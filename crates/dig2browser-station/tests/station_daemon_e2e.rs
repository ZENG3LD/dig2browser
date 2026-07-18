#![cfg(windows)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use dig2browser::identity::ProfileOwnershipGuard;
use dig2browser_client::{
    BrowserPersona, ClientConfig, ClientError, CollectionTask, FailureClass,
    MobilePersonaConfig, ResponseStatus, StationClient, StationStatus,
    TaskCapturePolicy, TaskReply, TaskStep,
};
use tokio::io::AsyncReadExt;

struct FixtureServer {
    address: SocketAddr,
    stopping: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl FixtureServer {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind daemon fixture");
        let address = listener.local_addr().expect("daemon fixture address");
        listener
            .set_nonblocking(true)
            .expect("make daemon fixture nonblocking");
        let stopping = Arc::new(AtomicBool::new(false));
        let thread_stopping = Arc::clone(&stopping);
        let thread = thread::spawn(move || {
            while !thread_stopping.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        thread::spawn(move || {
                            let _ = serve_connection(stream);
                        });
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("daemon fixture listener failed: {error}"),
                }
            }
        });
        Self {
            address,
            stopping,
            thread: Some(thread),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.address, path)
    }
}

impl Drop for FixtureServer {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        let _ = TcpStream::connect_timeout(&self.address, Duration::from_millis(100));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve_connection(mut stream: TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut request = [0_u8; 4096];
    let count = stream.read(&mut request)?;
    let request = String::from_utf8_lossy(&request[..count]);
    let path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/")
        .split('?')
        .next()
        .unwrap_or("/");
    let marker = path.trim_start_matches('/');
    if marker == "force-close" {
        return Ok(());
    }
    let body = format!(
        "<!doctype html><title>{marker}</title><main data-daemon-e2e=\"{marker}\">{marker}</main>"
    );
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stationd_serves_concurrent_clients_and_drains_real_chromium_e2e() {
    let _serial = e2e_serial_guard().await;
    let fixture = FixtureServer::start();
    let unique = uuid::Uuid::new_v4();
    let pipe_name = format!("dig2browser-stationd-e2e-{unique}");
    let profiles = e2e_temp_base().join(format!("dig2browser-stationd-e2e-{unique}"));
    std::fs::create_dir_all(&profiles).expect("create stationd E2E profiles root");
    let stationd = env!("CARGO_BIN_EXE_dig2browser-stationd");
    let mut daemon = spawn_stationd(stationd, &pipe_name, &profiles);

    let client_config = ClientConfig::new(
        &pipe_name,
        Duration::from_secs(15),
        Duration::from_secs(90),
    )
    .expect("valid station client config");
    let first = StationClient::connect(client_config.clone())
        .await
        .expect("connect first station client");
    let second = StationClient::connect(client_config.clone())
        .await
        .expect("connect second station client");
    let observer = StationClient::connect(client_config)
        .await
        .expect("connect observer station client");

    let baseline = observer.status().await.expect("read baseline status");
    assert_eq!(baseline.resident_identities, 0);
    assert_eq!(baseline.captures_started, 0);
    assert_eq!(baseline.captures_in_flight, 0);
    assert!(baseline.accepted_connections >= 3);
    assert!(baseline.active_connections >= 3);
    assert_eq!(baseline.command_limit, 4);
    assert!(baseline.command_available <= baseline.command_limit);

    let endpoint_conflict_profiles =
        e2e_temp_base().join(format!("dig2browser-stationd-conflict-e2e-{unique}"));
    let mut endpoint_conflict = spawn_stationd(
        stationd,
        &pipe_name,
        &endpoint_conflict_profiles,
    );
    let endpoint_status = tokio::time::timeout(Duration::from_secs(15), endpoint_conflict.wait())
        .await
        .expect("endpoint conflict exit timeout")
        .expect("wait for endpoint conflict");
    assert!(!endpoint_status.success());
    let (_, endpoint_stderr) = read_child_output(&mut endpoint_conflict).await;
    assert!(endpoint_stderr.contains("\"error_class\":\"station_endpoint_unavailable\""));
    remove_tree(&endpoint_conflict_profiles).await;

    let root_conflict_pipe = format!("dig2browser-stationd-root-conflict-e2e-{unique}");
    let mut root_conflict = spawn_stationd(stationd, &root_conflict_pipe, &profiles);
    let root_status = tokio::time::timeout(Duration::from_secs(15), root_conflict.wait())
        .await
        .expect("profiles root conflict exit timeout")
        .expect("wait for profiles root conflict");
    assert!(!root_status.success());
    let (_, root_stderr) = read_child_output(&mut root_conflict).await;
    assert!(root_stderr.contains("\"error_class\":\"profiles_root_owned\""));
    observer
        .health()
        .await
        .expect("primary station survives ownership conflicts");

    let first_url = fixture.url("/first-client");
    let second_url = fixture.url("/second-client");
    let first_task = tokio::spawn(async move {
        first
            .capture("shared-public-profile", &first_url)
            .await
    });
    let second_task = tokio::spawn(async move {
        second
            .capture("shared-public-profile", &second_url)
            .await
    });
    let during = wait_for_status(&observer, |status| status.captures_in_flight >= 2).await;
    assert_eq!(during.captures_started, 2);
    assert!(during.resident_identities >= 1);
    assert!(during.active_leases >= 1);
    assert!(during.command_available <= during.command_limit);

    let first_capture = first_task
        .await
        .expect("join first capture")
        .expect("capture through first client");
    let second_capture = second_task
        .await
        .expect("join second capture")
        .expect("capture through second client");
    assert_eq!(first_capture.title.as_deref(), Some("first-client"));
    assert!(
        String::from_utf8_lossy(&first_capture.html)
            .contains("data-daemon-e2e=\"first-client\"")
    );
    assert_eq!(second_capture.title.as_deref(), Some("second-client"));
    assert!(
        String::from_utf8_lossy(&second_capture.html)
            .contains("data-daemon-e2e=\"second-client\"")
    );
    assert_eq!(&first_capture.png[..8], b"\x89PNG\r\n\x1a\n");
    assert_eq!(&second_capture.png[..8], b"\x89PNG\r\n\x1a\n");

    let after_success = observer.status().await.expect("read successful status");
    assert_eq!(after_success.resident_identities, 1);
    assert_eq!(after_success.ready_workers, 1);
    assert_eq!(after_success.active_leases, 0);
    assert_eq!(after_success.captures_started, 2);
    assert_eq!(after_success.captures_in_flight, 0);
    assert_eq!(after_success.captures_succeeded, 2);
    assert_eq!(after_success.captures_failed, 0);
    assert_eq!(after_success.last_failure_class, FailureClass::None);

    let task_url = fixture.url("/typed-task");
    let task = CollectionTask::new(vec![
        TaskStep::Navigate {
            url: task_url.clone(),
        },
        TaskStep::Wait {
            duration: Duration::from_millis(50),
        },
        TaskStep::Evaluate {
            script: "({marker: 'task-script'})".to_owned(),
        },
        TaskStep::ReadSelectorText {
            selector: "main".to_owned(),
        },
        TaskStep::Wheel {
            x: 1.0,
            y: 1.0,
            delta_x: 0.0,
            delta_y: 10.0,
        },
        TaskStep::Capture {
            policy: TaskCapturePolicy::EvidenceViewport,
        },
    ])
    .expect("valid typed daemon task");
    let task_result = observer
        .run_task("typed-task-profile", task)
        .await
        .expect("run typed task through client and station daemon");
    assert_eq!(task_result.replies().len(), 6);
    assert_eq!(
        task_result.replies()[2],
        TaskReply::ScriptJson("{\"marker\":\"task-script\"}".to_owned())
    );
    assert_eq!(
        task_result.replies()[3],
        TaskReply::Text("typed-task".to_owned())
    );
    let TaskReply::Capture(task_capture) = &task_result.replies()[5] else {
        panic!("typed task did not return evidence capture");
    };
    assert_eq!(task_capture.requested_url, task_url);
    assert_eq!(task_capture.final_url, task_url);
    assert_eq!(task_capture.http_status, Some(200));
    assert_eq!(task_capture.title, "typed-task");
    assert_eq!(task_capture.ready_state, "complete");
    assert!(String::from_utf8_lossy(&task_capture.html)
        .contains("data-daemon-e2e=\"typed-task\""));
    assert_eq!(&task_capture.png[..8], b"\x89PNG\r\n\x1a\n");
    assert_eq!(
        task_capture.html_sha256,
        dig2browser::digest::sha256_bytes(&task_capture.html)
    );
    assert_eq!(
        task_capture.png_sha256,
        Some(dig2browser::digest::sha256_bytes(&task_capture.png))
    );
    assert_eq!(task_capture.protocol_version, dig2browser_protocol::PROTOCOL_VERSION);
    assert!(task_capture.collector_version.starts_with("dig2browser-station/"));

    assert!(
        observer
            .capture("failure-profile", fixture.url("/force-close"))
            .await
            .is_err(),
        "forced connection close unexpectedly produced a capture"
    );
    let after_failure = observer.status().await.expect("read failed status");
    assert_eq!(after_failure.captures_started, 4);
    assert_eq!(after_failure.captures_in_flight, 0);
    assert_eq!(after_failure.captures_succeeded, 3);
    assert_eq!(after_failure.captures_failed, 1);
    assert_eq!(after_failure.last_failure_class, FailureClass::CaptureFailed);
    assert!(after_failure.last_failure_unix_ms > 0);

    observer.shutdown().await.expect("request station drain");
    let status = tokio::time::timeout(Duration::from_secs(30), daemon.wait())
        .await
        .expect("station daemon exit timeout")
        .expect("wait for station daemon");
    assert!(status.success(), "station daemon failed: {status}");
    let (stdout, stderr) = read_child_output(&mut daemon).await;
    assert!(stderr.is_empty(), "clean station wrote stderr: {stderr}");
    assert!(stdout.contains("\"event\":\"station_exit\""));
    assert!(stdout.contains("\"outcome\":\"clean\""));
    assert!(stdout.contains("\"stop_reason\":\"remote_request\""));
    assert!(stdout.contains("\"drain_timed_out\":false"));
    remove_tree(&profiles).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stationd_denies_active_task_capabilities_by_default_e2e() {
    let _serial = e2e_serial_guard().await;
    let fixture = FixtureServer::start();
    let unique = uuid::Uuid::new_v4();
    let pipe_name = format!("dig2browser-stationd-restricted-e2e-{unique}");
    let profiles = e2e_temp_base().join(format!(
        "dig2browser-stationd-restricted-e2e-{unique}"
    ));
    std::fs::create_dir_all(&profiles).expect("create restricted E2E profiles root");
    let stationd = env!("CARGO_BIN_EXE_dig2browser-stationd");
    let mut daemon = spawn_stationd_with_task_permissions(
        stationd,
        &pipe_name,
        &profiles,
        false,
    );
    let client = StationClient::connect(
        ClientConfig::new(
            &pipe_name,
            Duration::from_secs(15),
            Duration::from_secs(90),
        )
        .expect("valid restricted client config"),
    )
    .await
    .expect("connect restricted task client");
    let interactive_task = CollectionTask::new(vec![
        TaskStep::Navigate {
            url: fixture.url("/restricted-interaction"),
        },
        TaskStep::ClickSelector {
            selector: "main".to_owned(),
        },
        TaskStep::Capture {
            policy: TaskCapturePolicy::EvidenceViewport,
        },
    ])
    .expect("valid restricted interaction task");
    assert!(matches!(
        client
            .run_task("restricted-profile", interactive_task)
            .await,
        Err(ClientError::Remote {
            status: ResponseStatus::Invalid,
            ..
        })
    ));
    let scripted_task = CollectionTask::new(vec![
        TaskStep::Navigate {
            url: fixture.url("/restricted-script"),
        },
        TaskStep::Evaluate {
            script: "document.title".to_owned(),
        },
        TaskStep::Capture {
            policy: TaskCapturePolicy::EvidenceViewport,
        },
    ])
    .expect("valid restricted script task");
    assert!(matches!(
        client.run_task("restricted-profile", scripted_task).await,
        Err(ClientError::Remote {
            status: ResponseStatus::Invalid,
            ..
        })
    ));
    let status = client.status().await.expect("restricted station status");
    assert_eq!(status.resident_identities, 0);
    client.shutdown().await.expect("shutdown restricted station");
    let exit = tokio::time::timeout(Duration::from_secs(30), daemon.wait())
        .await
        .expect("restricted daemon exit timeout")
        .expect("wait for restricted daemon");
    assert!(exit.success(), "restricted station failed: {exit}");
    let (_, stderr) = read_child_output(&mut daemon).await;
    assert!(stderr.is_empty(), "restricted station wrote stderr: {stderr}");
    remove_tree(&profiles).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stationd_persists_mobile_persona_and_profile_state_e2e() {
    let _serial = e2e_serial_guard().await;
    let fixture = FixtureServer::start();
    let unique = uuid::Uuid::new_v4();
    let pipe_name = format!("dig2browser-stationd-mobile-e2e-{unique}");
    let profiles = e2e_temp_base().join(format!("dig2browser-stationd-mobile-e2e-{unique}"));
    std::fs::create_dir_all(&profiles).expect("create mobile E2E profiles root");
    let stationd = env!("CARGO_BIN_EXE_dig2browser-stationd");
    let persona = BrowserPersona::mobile(MobilePersonaConfig {
        width: 412,
        height: 915,
        device_scale_milli: 2625,
        max_touch_points: 5,
        locale: "ru-RU".to_owned(),
        timezone: Some("Europe/Moscow".to_owned()),
        platform_version: "14.0.0".to_owned(),
        model: "Pixel 8".to_owned(),
    })
    .expect("valid mobile E2E persona");
    let client_config = ClientConfig::new(
        &pipe_name,
        Duration::from_secs(15),
        Duration::from_secs(90),
    )
    .expect("valid mobile client config");
    let mut daemon = spawn_stationd(stationd, &pipe_name, &profiles);
    let client = StationClient::connect(client_config.clone())
        .await
        .expect("connect mobile persona client");
    let first_task = CollectionTask::new(vec![
        TaskStep::Navigate {
            url: fixture.url("/mobile-first"),
        },
        TaskStep::Evaluate {
            script: "localStorage.setItem('dig2browser_e2e', 'persisted'); ({layoutWidth: innerWidth, layoutHeight: innerHeight, screenWidth: screen.width, screenHeight: screen.height, dpr: devicePixelRatio, touch: navigator.maxTouchPoints, ua: navigator.userAgent, uaMobile: navigator.userAgentData && navigator.userAgentData.mobile, uaPlatform: navigator.userAgentData && navigator.userAgentData.platform, platform: navigator.platform, language: navigator.language, timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, marker: localStorage.getItem('dig2browser_e2e')})".to_owned(),
        },
        TaskStep::Capture {
            policy: TaskCapturePolicy::EvidenceViewport,
        },
    ])
    .expect("valid first mobile task");
    let first_result = client
        .run_task_with_persona("mobile-durable-profile", persona.clone(), first_task)
        .await
        .expect("run first mobile persona task");
    let TaskReply::ScriptJson(first_fingerprint) = &first_result.replies()[1] else {
        panic!("first mobile task did not return fingerprint JSON");
    };
    assert_mobile_fingerprint(first_fingerprint, true);
    client.shutdown().await.expect("shutdown first mobile station");
    let first_exit = tokio::time::timeout(Duration::from_secs(30), daemon.wait())
        .await
        .expect("first mobile daemon exit timeout")
        .expect("wait for first mobile daemon");
    assert!(first_exit.success(), "first mobile station failed: {first_exit}");
    let (_, first_stderr) = read_child_output(&mut daemon).await;
    assert!(first_stderr.is_empty(), "mobile station wrote stderr: {first_stderr}");

    let mut successor = spawn_stationd(stationd, &pipe_name, &profiles);
    let successor_client = StationClient::connect(client_config)
        .await
        .expect("connect mobile successor client");
    let second_task = CollectionTask::new(vec![
        TaskStep::Navigate {
            url: fixture.url("/mobile-second"),
        },
        TaskStep::Evaluate {
            script: "({layoutWidth: innerWidth, layoutHeight: innerHeight, screenWidth: screen.width, screenHeight: screen.height, dpr: devicePixelRatio, touch: navigator.maxTouchPoints, ua: navigator.userAgent, uaMobile: navigator.userAgentData && navigator.userAgentData.mobile, uaPlatform: navigator.userAgentData && navigator.userAgentData.platform, platform: navigator.platform, language: navigator.language, timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, marker: localStorage.getItem('dig2browser_e2e')})".to_owned(),
        },
    ])
    .expect("valid second mobile task");
    let second_result = successor_client
        .run_task_with_persona("mobile-durable-profile", persona, second_task)
        .await
        .expect("run successor mobile persona task");
    let TaskReply::ScriptJson(second_fingerprint) = &second_result.replies()[1] else {
        panic!("second mobile task did not return fingerprint JSON");
    };
    assert_mobile_fingerprint(second_fingerprint, true);

    let mismatch_task = CollectionTask::new(vec![TaskStep::Navigate {
        url: fixture.url("/persona-mismatch"),
    }])
    .expect("valid persona mismatch task");
    assert!(matches!(
        successor_client
            .run_task_with_persona(
                "mobile-durable-profile",
                BrowserPersona::desktop_default(),
                mismatch_task,
            )
            .await,
        Err(ClientError::Remote {
            status: ResponseStatus::Invalid,
            ..
        })
    ));
    let manifest = profiles
        .join("mobile-durable-profile")
        .join(".dig2browser-persona-v1");
    let manifest_text = std::fs::read_to_string(manifest).expect("read persona manifest");
    assert!(manifest_text.contains("kind=Mobile"));
    assert!(!manifest_text.contains("persisted"));

    successor_client
        .shutdown()
        .await
        .expect("shutdown mobile successor");
    let successor_exit = tokio::time::timeout(Duration::from_secs(30), successor.wait())
        .await
        .expect("mobile successor exit timeout")
        .expect("wait for mobile successor");
    assert!(successor_exit.success(), "mobile successor failed: {successor_exit}");
    let (_, successor_stderr) = read_child_output(&mut successor).await;
    assert!(
        successor_stderr.is_empty(),
        "mobile successor wrote stderr: {successor_stderr}"
    );
    remove_tree(&profiles).await;
}

fn assert_mobile_fingerprint(fingerprint: &str, marker_expected: bool) {
    for expected in [
        "\"screenWidth\":412",
        "\"screenHeight\":915",
        "\"dpr\":2.625",
        "\"touch\":5",
        "\"uaMobile\":true",
        "\"uaPlatform\":\"Android\"",
        "\"platform\":\"Android\"",
        "\"language\":\"ru-RU\"",
        "\"timezone\":\"Europe/Moscow\"",
        "Android 14.0.0; Pixel 8",
    ] {
        assert!(
            fingerprint.contains(expected),
            "mobile fingerprint omitted {expected}: {fingerprint}"
        );
    }
    assert_eq!(
        fingerprint.contains("\"marker\":\"persisted\""),
        marker_expected,
        "unexpected durable marker state: {fingerprint}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stationd_hard_kill_releases_profile_and_client_reconnects_e2e() {
    let _serial = e2e_serial_guard().await;
    let fixture = FixtureServer::start();
    let unique = uuid::Uuid::new_v4();
    let pipe_name = format!("dig2browser-stationd-crash-e2e-{unique}");
    let profiles = e2e_temp_base().join(format!("dig2browser-stationd-crash-e2e-{unique}"));
    std::fs::create_dir_all(&profiles).expect("create crash E2E profiles root");
    let stationd = env!("CARGO_BIN_EXE_dig2browser-stationd");
    let mut daemon = spawn_stationd(stationd, &pipe_name, &profiles);
    let client_config = ClientConfig::new(
        &pipe_name,
        Duration::from_secs(15),
        Duration::from_secs(90),
    )
    .expect("valid crash E2E client config");
    let client = StationClient::connect(client_config)
        .await
        .expect("connect crash E2E client");
    let external_profile =
        ProfileOwnershipGuard::acquire(profiles.join("externally-locked-profile"))
            .expect("lock profile outside station");
    assert!(
        client
            .capture(
                "externally-locked-profile",
                fixture.url("/while-profile-locked"),
            )
            .await
            .is_err(),
        "station unexpectedly acquired an externally locked profile"
    );
    drop(external_profile);
    let released_capture = client
        .capture(
            "externally-locked-profile",
            fixture.url("/after-profile-release"),
        )
        .await
        .expect("station acquires profile after external owner releases it");
    assert_eq!(released_capture.title.as_deref(), Some("after-profile-release"));
    client
        .capture("crash-recovery-profile", fixture.url("/before-crash"))
        .await
        .expect("capture before stationd crash");

    daemon.kill().await.expect("hard-kill station daemon");
    daemon.wait().await.expect("reap killed station daemon");
    let mut successor = spawn_stationd(stationd, &pipe_name, &profiles);

    assert!(
        client.health().await.is_err(),
        "stale transport unexpectedly survived stationd hard kill"
    );
    client
        .health()
        .await
        .expect("client reconnects to successor stationd");
    let fresh = client.status().await.expect("read successor baseline status");
    assert_eq!(fresh.resident_identities, 0);
    assert_eq!(fresh.captures_started, 0);
    assert_eq!(fresh.captures_succeeded, 0);
    assert_eq!(fresh.captures_failed, 0);
    assert!(fresh.accepted_connections >= 1);
    let capture = client
        .capture("crash-recovery-profile", fixture.url("/after-crash"))
        .await
        .expect("successor acquires profile released by hard kill");
    assert_eq!(capture.title.as_deref(), Some("after-crash"));
    assert!(
        String::from_utf8_lossy(&capture.html)
            .contains("data-daemon-e2e=\"after-crash\"")
    );
    let recovered = client.status().await.expect("read successor capture status");
    assert_eq!(recovered.resident_identities, 1);
    assert_eq!(recovered.captures_started, 1);
    assert_eq!(recovered.captures_succeeded, 1);
    assert_eq!(recovered.captures_failed, 0);
    client.shutdown().await.expect("shutdown successor stationd");
    let status = tokio::time::timeout(Duration::from_secs(30), successor.wait())
        .await
        .expect("successor stationd exit timeout")
        .expect("wait for successor stationd");
    assert!(status.success(), "successor stationd failed: {status}");
    let (stdout, stderr) = read_child_output(&mut successor).await;
    assert!(stderr.is_empty(), "clean successor wrote stderr: {stderr}");
    assert!(stdout.contains("\"outcome\":\"clean\""));
    assert!(stdout.contains("\"stop_reason\":\"remote_request\""));
    remove_tree(&profiles).await;
}

async fn wait_for_status(
    client: &StationClient,
    predicate: impl Fn(&StationStatus) -> bool,
) -> StationStatus {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let status = client.status().await.expect("poll station status");
        if predicate(&status) {
            return status;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "station status predicate timed out: {status:?}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn e2e_serial_guard() -> tokio::sync::SemaphorePermit<'static> {
    static E2E_SERIAL: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);
    E2E_SERIAL
        .acquire()
        .await
        .expect("daemon E2E semaphore remains open")
}

async fn read_child_output(child: &mut tokio::process::Child) -> (String, String) {
    let mut stdout = String::new();
    if let Some(mut stream) = child.stdout.take() {
        stream
            .read_to_string(&mut stdout)
            .await
            .expect("read station stdout");
    }
    let mut stderr = String::new();
    if let Some(mut stream) = child.stderr.take() {
        stream
            .read_to_string(&mut stderr)
            .await
            .expect("read station stderr");
    }
    (stdout, stderr)
}

fn spawn_stationd(stationd: &str, pipe_name: &str, profiles: &Path) -> tokio::process::Child {
    spawn_stationd_with_task_permissions(stationd, pipe_name, profiles, true)
}

fn spawn_stationd_with_task_permissions(
    stationd: &str,
    pipe_name: &str,
    profiles: &Path,
    allow_active_tasks: bool,
) -> tokio::process::Child {
    let mut command = tokio::process::Command::new(stationd);
    command.args([
            "--pipe-name",
            pipe_name,
            "--profiles-root",
            profiles.to_str().expect("profiles path is UTF-8"),
            "--max-resident",
            "2",
            "--max-in-flight",
            "4",
            "--max-connections",
            "8",
            "--timeout-seconds",
            "60",
            "--drain-seconds",
            "15",
            "--allow-remote-shutdown",
        ]);
    if allow_active_tasks {
        command.args(["--allow-interactive-tasks", "--allow-scripted-tasks"]);
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn station daemon")
}

fn e2e_temp_base() -> PathBuf {
    std::env::var_os("DIG2BROWSER_E2E_TMP")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\tmp"))
}

async fn remove_tree(path: &Path) {
    for _ in 0..30 {
        match std::fs::remove_dir_all(path) {
            Ok(()) => return,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    panic!("could not remove stationd E2E profiles: {}", path.display());
}
