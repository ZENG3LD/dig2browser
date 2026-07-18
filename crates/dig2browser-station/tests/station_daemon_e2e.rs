#![cfg(windows)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use dig2browser_client::{ClientConfig, FailureClass, StationClient, StationStatus};

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

    assert!(
        observer
            .capture("failure-profile", fixture.url("/force-close"))
            .await
            .is_err(),
        "forced connection close unexpectedly produced a capture"
    );
    let after_failure = observer.status().await.expect("read failed status");
    assert_eq!(after_failure.captures_started, 3);
    assert_eq!(after_failure.captures_in_flight, 0);
    assert_eq!(after_failure.captures_succeeded, 2);
    assert_eq!(after_failure.captures_failed, 1);
    assert_eq!(after_failure.last_failure_class, FailureClass::CaptureFailed);
    assert!(after_failure.last_failure_unix_ms > 0);

    observer.shutdown().await.expect("request station drain");
    let status = tokio::time::timeout(Duration::from_secs(30), daemon.wait())
        .await
        .expect("station daemon exit timeout")
        .expect("wait for station daemon");
    assert!(status.success(), "station daemon failed: {status}");
    remove_tree(&profiles).await;
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

fn spawn_stationd(stationd: &str, pipe_name: &str, profiles: &Path) -> tokio::process::Child {
    tokio::process::Command::new(stationd)
        .args([
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
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
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
