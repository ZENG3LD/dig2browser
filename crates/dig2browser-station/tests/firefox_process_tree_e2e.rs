#![cfg(all(windows, feature = "geckodriver-test-hooks"))]

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use dig2browser_client::{
    ClientConfig, CollectionTask, RuntimeKind, RuntimeRequirements,
    RuntimeSelector, StationClient, TaskRuntimeContract, TaskStep,
};
use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE, STILL_ACTIVE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
    PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    GetExitCodeProcess, GetProcessTimes, OpenProcess, TerminateProcess,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
};

#[derive(Clone)]
struct ProcessEntry {
    pid: u32,
    parent_pid: u32,
    executable: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProcessIdentity {
    pid: u32,
    creation_filetime: u64,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires reviewed GECKODRIVER, installed Firefox, and an explicit live-process preannouncement"]
async fn station_owned_firefox_process_tree_exact_pid_lifecycle_e2e() {
    let geckodriver = std::env::var_os("GECKODRIVER")
        .map(PathBuf::from)
        .expect("GECKODRIVER is configured");
    assert!(geckodriver.is_file(), "GECKODRIVER is not a file");

    startup_timeout_case(&geckodriver).await;
    termination_case(&geckodriver, Termination::Clean).await;
    termination_case(&geckodriver, Termination::Emergency).await;
    termination_case(&geckodriver, Termination::HardStationKill).await;
}

async fn startup_timeout_case(geckodriver: &Path) {
    let mut case = Case::start(geckodriver, Some(1)).await;
    let task = firefox_probe_task();
    let (result, geckodriver) = tokio::join!(
        case.client.run_task("startup-timeout", task),
        case.capture_geckodriver_and_resume(),
    );
    assert!(result.is_err(), "1ms GeckoDriver readiness must time out");
    let _ = case.client.shutdown().await;
    let _ = case.daemon.wait().await.expect("wait for timeout station");
    wait_for_exact_exit(geckodriver, "startup-timeout geckodriver").await;
    case.cleanup("startup-timeout").await;
}

#[derive(Clone, Copy, Debug)]
enum Termination {
    Clean,
    Emergency,
    HardStationKill,
}

async fn termination_case(geckodriver: &Path, termination: Termination) {
    let mut case = Case::start(geckodriver, None).await;
    let task = firefox_probe_task();
    let (result, geckodriver) = tokio::join!(
        case.client.run_task("owned-firefox-tree", task),
        case.capture_geckodriver_and_resume(),
    );
    result.expect("start station-owned Firefox worker");
    let owned_tree = wait_for_owned_process_tree(geckodriver).await;

    match termination {
        Termination::Clean => {
            case.client.shutdown().await.expect("clean station shutdown");
        }
        Termination::Emergency => {
            terminate_exact_process(geckodriver);
            let _ = case.client.shutdown().await;
        }
        Termination::HardStationKill => {
            case.daemon.kill().await.expect("hard-kill station process");
        }
    }
    let _ = case.daemon.wait().await.expect("wait for station exit");
    let context = format!("{termination:?}");
    wait_for_exact_tree_exit(&owned_tree, &context).await;
    case.cleanup(&context).await;
}

struct Case {
    client: StationClient,
    daemon: tokio::process::Child,
    profiles: PathBuf,
    geckodriver_report: PathBuf,
    geckodriver_resume_barrier: PathBuf,
}

impl Case {
    async fn start(geckodriver: &Path, startup_timeout_millis: Option<u64>) -> Self {
        let unique = uuid::Uuid::new_v4();
        let pipe_name = format!("dig2browser-firefox-tree-{unique}");
        let profiles = std::env::temp_dir().join(format!(
            "dig2browser-firefox-tree-{unique}"
        ));
        std::fs::create_dir_all(&profiles).expect("create Firefox profiles root");
        let geckodriver_report = profiles.join("geckodriver-process.txt");
        let geckodriver_resume_barrier = profiles.join("resume-geckodriver");
        let mut command = tokio::process::Command::new(env!(
            "CARGO_BIN_EXE_dig2browser-stationd"
        ));
        command.env(
            "DIG2BROWSER_TEST_GECKODRIVER_REPORT_PATH",
            &geckodriver_report,
        );
        command.env(
            "DIG2BROWSER_TEST_GECKODRIVER_RESUME_BARRIER_PATH",
            &geckodriver_resume_barrier,
        );
        command.args([
            "--pipe-name",
            &pipe_name,
            "--profiles-root",
            profiles.to_str().expect("UTF-8 profiles path"),
            "--runtime",
            "firefox",
            "--geckodriver-path",
            geckodriver.to_str().expect("UTF-8 geckodriver path"),
            "--max-resident",
            "1",
            "--max-in-flight",
            "1",
            "--timeout-seconds",
            "20",
            "--drain-seconds",
            "5",
            "--allow-remote-shutdown",
            "--allow-scripted-tasks",
        ]);
        if let Some(timeout) = startup_timeout_millis {
            command.args([
                "--test-geckodriver-startup-timeout-millis",
                &timeout.to_string(),
            ]);
        }
        let daemon = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn Firefox station");
        let client = StationClient::connect(
            ClientConfig::new(
                &pipe_name,
                Duration::from_secs(10),
                Duration::from_secs(30),
            )
            .expect("valid Firefox client config"),
        )
        .await
        .expect("connect Firefox station");
        Self {
            client,
            daemon,
            profiles,
            geckodriver_report,
            geckodriver_resume_barrier,
        }
    }

    async fn capture_geckodriver_and_resume(&self) -> ProcessIdentity {
        for _ in 0..400 {
            match std::fs::read_to_string(&self.geckodriver_report) {
                Ok(report) => {
                    let identity = parse_process_identity(&report);
                    assert_eq!(
                        current_process_identity(identity.pid),
                        Some(identity),
                        "published geckodriver incarnation must still be suspended"
                    );
                    std::fs::write(&self.geckodriver_resume_barrier, b"resume\n")
                        .expect("release suspended geckodriver");
                    return identity;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => panic!("read geckodriver process report: {error}"),
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("station did not publish suspended geckodriver identity");
    }

    async fn cleanup(&self, context: &str) {
        for attempt in 0..20 {
            match std::fs::remove_dir_all(&self.profiles) {
                Ok(()) => return,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
                Err(_) if attempt + 1 < 20 => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(error) => {
                    panic!("{context}: remove Firefox profiles root: {error}")
                }
            }
        }
    }
}

fn firefox_probe_task() -> CollectionTask {
    let contract = TaskRuntimeContract::new(
        RuntimeSelector::Exact(RuntimeKind::Firefox),
        RuntimeRequirements::new(Vec::new(), false)
            .expect("valid Firefox requirements"),
    )
    .expect("valid Firefox contract");
    CollectionTask::new_with_runtime(
        vec![TaskStep::Evaluate {
            script: "navigator.userAgent".to_owned(),
        }],
        contract,
    )
    .expect("valid Firefox probe task")
}

async fn wait_for_owned_process_tree(
    root: ProcessIdentity,
) -> Vec<ProcessIdentity> {
    for _ in 0..400 {
        let snapshot = process_snapshot();
        let firefox_present = snapshot.iter().any(|process| {
            process.executable.eq_ignore_ascii_case("firefox.exe")
                && is_descendant(process.pid, root.pid, &snapshot)
                && current_process_identity(process.pid).is_some_and(|identity| {
                    identity.creation_filetime >= root.creation_filetime
                })
        });
        if firefox_present {
            let mut identities = snapshot
                .iter()
                .filter(|process| {
                    process.pid == root.pid
                        || is_descendant(process.pid, root.pid, &snapshot)
                })
                .filter_map(|process| current_process_identity(process.pid))
                .filter(|identity| {
                    identity.creation_filetime >= root.creation_filetime
                })
                .collect::<Vec<_>>();
            identities.sort_by_key(|identity| identity.pid);
            identities.dedup();
            assert!(
                identities.contains(&root),
                "owned process-tree snapshot lost the exact geckodriver root"
            );
            return identities;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!(
        "did not observe an exact Firefox descendant of geckodriver PID {}",
        root.pid
    );
}

async fn wait_for_exact_tree_exit(identities: &[ProcessIdentity], context: &str) {
    for _ in 0..400 {
        let survivors = identities
            .iter()
            .copied()
            .filter(|identity| current_process_identity(identity.pid) == Some(*identity))
            .collect::<Vec<_>>();
        if survivors.is_empty() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let survivors = identities
        .iter()
        .copied()
        .filter(|identity| current_process_identity(identity.pid) == Some(*identity))
        .collect::<Vec<_>>();
    panic!("{context}: exact owned process-tree survivors: {survivors:?}");
}

async fn wait_for_exact_exit(identity: ProcessIdentity, context: &str) {
    for _ in 0..400 {
        if current_process_identity(identity.pid) != Some(identity) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!(
        "{context}: exact process PID {} FILETIME {} survived lifecycle termination",
        identity.pid,
        identity.creation_filetime
    );
}

fn is_descendant(mut pid: u32, root_pid: u32, snapshot: &[ProcessEntry]) -> bool {
    for _ in 0..64 {
        let Some(process) = snapshot.iter().find(|process| process.pid == pid) else {
            return false;
        };
        if process.parent_pid == root_pid {
            return true;
        }
        if process.parent_pid == 0 || process.parent_pid == pid {
            return false;
        }
        pid = process.parent_pid;
    }
    false
}

fn process_snapshot() -> Vec<ProcessEntry> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
        .expect("create process snapshot");
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..PROCESSENTRY32W::default()
    };
    let mut processes = Vec::new();
    if unsafe { Process32FirstW(snapshot, &mut entry) }.is_ok() {
        loop {
            let end = entry
                .szExeFile
                .iter()
                .position(|unit| *unit == 0)
                .unwrap_or(entry.szExeFile.len());
            processes.push(ProcessEntry {
                pid: entry.th32ProcessID,
                parent_pid: entry.th32ParentProcessID,
                executable: String::from_utf16_lossy(&entry.szExeFile[..end]),
            });
            if unsafe { Process32NextW(snapshot, &mut entry) }.is_err() {
                break;
            }
        }
    }
    let _ = unsafe { CloseHandle(snapshot) };
    processes
}

fn terminate_exact_process(identity: ProcessIdentity) {
    let process = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,
            false,
            identity.pid,
        )
    }
        .expect("open exact geckodriver process");
    assert_eq!(
        process_identity_from_handle(process, identity.pid),
        Some(identity),
        "refusing to terminate a reused geckodriver PID"
    );
    unsafe { TerminateProcess(process, 70) }.expect("terminate exact geckodriver process");
    let _ = unsafe { CloseHandle(process) };
}

fn parse_process_identity(report: &str) -> ProcessIdentity {
    let mut fields = report.split_whitespace();
    let pid = fields
        .next()
        .expect("geckodriver report PID")
        .parse::<u32>()
        .expect("numeric geckodriver report PID");
    let creation_filetime = fields
        .next()
        .expect("geckodriver report creation FILETIME")
        .parse::<u64>()
        .expect("numeric geckodriver creation FILETIME");
    assert!(fields.next().is_none(), "unexpected geckodriver report data");
    assert_ne!(pid, 0, "geckodriver report PID must be non-zero");
    assert_ne!(
        creation_filetime, 0,
        "geckodriver creation FILETIME must be non-zero"
    );
    ProcessIdentity {
        pid,
        creation_filetime,
    }
}

fn current_process_identity(pid: u32) -> Option<ProcessIdentity> {
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let identity = process_identity_from_handle(process, pid);
    let _ = unsafe { CloseHandle(process) };
    identity
}

fn process_identity_from_handle(
    process: HANDLE,
    pid: u32,
) -> Option<ProcessIdentity> {
    let mut exit_code = 0u32;
    unsafe { GetExitCodeProcess(process, &mut exit_code) }.ok()?;
    if exit_code != STILL_ACTIVE.0 as u32 {
        return None;
    }
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    unsafe {
        GetProcessTimes(
            process,
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    }
    .ok()?;
    let creation_filetime =
        ((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64;
    (creation_filetime != 0).then_some(ProcessIdentity {
        pid,
        creation_filetime,
    })
}
