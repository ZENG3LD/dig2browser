#![cfg(windows)]

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use dig2browser::agentic::{BrowserWorker, BrowserWorkerConfig, CapabilitySet};
use dig2browser::identity::{
    BrowserBackend, DevicePersona, IdentityClass, IdentityProfile,
};
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
    TH32CS_SNAPPROCESS,
};

const CHILD_MODE: &str = "DIG2BROWSER_PROCESS_TREE_CHILD";
const READY_PATH: &str = "DIG2BROWSER_PROCESS_TREE_READY";
const PROFILES_PATH: &str = "DIG2BROWSER_PROCESS_TREE_PROFILES";

fn identity(root: &Path) -> IdentityProfile {
    IdentityProfile::new(
        root,
        "hard-kill-owner",
        IdentityClass::Public,
        BrowserBackend::Chromium,
        DevicePersona::DesktopNative,
    )
    .expect("create process-tree E2E identity")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn process_tree_child() {
    if std::env::var_os(CHILD_MODE).is_none() {
        return;
    }
    let ready = PathBuf::from(std::env::var_os(READY_PATH).expect("ready path"));
    let profiles = PathBuf::from(std::env::var_os(PROFILES_PATH).expect("profiles path"));
    let mut config = BrowserWorkerConfig::default();
    config.command_timeout = Duration::from_secs(60);
    let worker = BrowserWorker::spawn(identity(&profiles), CapabilitySet::all(), config)
        .expect("spawn child browser worker");
    worker.wait_until_settled().await.expect("start child Chromium");
    std::fs::write(&ready, std::process::id().to_string()).expect("publish ready marker");
    std::future::pending::<()>().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hard_kill_owner_reaps_chromium_tree_and_releases_profile_e2e() {
    let root = e2e_temp_base().join(format!(
        "dig2browser-process-tree-e2e-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let profiles = root.join("profiles");
    let ready = root.join("ready.txt");
    std::fs::create_dir_all(&profiles).expect("create E2E directories");

    let mut owner = tokio::process::Command::new(std::env::current_exe().expect("test binary"))
        .args([
            "--exact",
            "process_tree_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_MODE, "1")
        .env(READY_PATH, &ready)
        .env(PROFILES_PATH, &profiles)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn owner test process");
    let owner_pid = owner.id().expect("owner process ID");
    wait_for_file(&ready, Duration::from_secs(75)).await;

    let descendants = wait_for_browser_descendants(owner_pid, Duration::from_secs(15)).await;
    assert!(
        !descendants.is_empty(),
        "owner process has no Chromium descendants before hard kill"
    );

    owner.kill().await.expect("hard-kill owner process");
    owner.wait().await.expect("reap owner process");
    wait_for_processes_to_exit(&descendants, Duration::from_secs(15)).await;

    let mut successor_config = BrowserWorkerConfig::default();
    successor_config.command_timeout = Duration::from_secs(60);
    let successor = BrowserWorker::spawn(
        identity(&profiles),
        CapabilitySet::all(),
        successor_config,
    )
    .expect("spawn successor worker");
    successor
        .wait_until_settled()
        .await
        .expect("successor acquires released profile");
    successor.shutdown().await.expect("shutdown successor");
    drop(successor);

    remove_tree(&root).await;
}

fn e2e_temp_base() -> PathBuf {
    std::env::var_os("DIG2BROWSER_E2E_TMP")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\tmp"))
}

async fn wait_for_file(path: &Path, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.is_file() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("child did not publish ready marker: {}", path.display());
}

async fn wait_for_browser_descendants(owner_pid: u32, timeout: Duration) -> HashSet<u32> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let processes = process_snapshot().expect("read process snapshot");
        let descendants = descendants_of(owner_pid, &processes);
        let browsers = descendants
            .into_iter()
            .filter(|pid| {
                processes.get(pid).is_some_and(|(_, name)| {
                    name.eq_ignore_ascii_case("chrome.exe")
                        || name.eq_ignore_ascii_case("msedge.exe")
                })
            })
            .collect::<HashSet<_>>();
        if !browsers.is_empty() {
            return browsers;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    HashSet::new()
}

async fn wait_for_processes_to_exit(processes: &HashSet<u32>, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let snapshot = process_snapshot().expect("read process snapshot after hard kill");
        if processes.iter().all(|pid| !snapshot.contains_key(pid)) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let snapshot = process_snapshot().expect("read final process snapshot");
    let remaining = processes
        .iter()
        .filter(|pid| snapshot.contains_key(pid))
        .copied()
        .collect::<Vec<_>>();
    panic!("Chromium descendants survived owner hard kill: {remaining:?}");
}

fn descendants_of(owner_pid: u32, processes: &HashMap<u32, (u32, String)>) -> HashSet<u32> {
    let mut descendants = HashSet::new();
    let mut frontier = vec![owner_pid];
    while let Some(parent) = frontier.pop() {
        for (&pid, &(candidate_parent, _)) in processes {
            if candidate_parent == parent && descendants.insert(pid) {
                frontier.push(pid);
            }
        }
    }
    descendants
}

fn process_snapshot() -> std::io::Result<HashMap<u32, (u32, String)>> {
    // SAFETY: the snapshot handle is owned locally and closed before returning.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
        .map_err(windows_error)?;
    let mut entry = PROCESSENTRY32W::default();
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    let mut processes = HashMap::new();
    // SAFETY: `entry` has the required size and remains valid for each call.
    let mut next = unsafe { Process32FirstW(snapshot, &mut entry) }.is_ok();
    while next {
        let end = entry
            .szExeFile
            .iter()
            .position(|value| *value == 0)
            .unwrap_or(entry.szExeFile.len());
        let name = String::from_utf16_lossy(&entry.szExeFile[..end]);
        processes.insert(entry.th32ProcessID, (entry.th32ParentProcessID, name));
        // SAFETY: same initialized entry and valid snapshot handle.
        next = unsafe { Process32NextW(snapshot, &mut entry) }.is_ok();
    }
    // SAFETY: this function owns `snapshot` and closes it exactly once.
    let _ = unsafe { CloseHandle(snapshot) };
    Ok(processes)
}

fn windows_error(error: windows::core::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, error.to_string())
}

async fn remove_tree(path: &Path) {
    for _ in 0..30 {
        match std::fs::remove_dir_all(path) {
            Ok(()) => return,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    panic!("could not remove E2E directory: {}", path.display());
}
