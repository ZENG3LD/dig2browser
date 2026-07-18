#![cfg(windows)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use dig2browser_client::{ClientConfig, StationClient};

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
    let second = StationClient::connect(client_config)
        .await
        .expect("connect second station client");

    let first_url = fixture.url("/first-client");
    let second_url = fixture.url("/second-client");
    let (first_capture, second_capture) = tokio::join!(
        first.capture("shared-public-profile", &first_url),
        second.capture("shared-public-profile", &second_url),
    );
    let first_capture = first_capture.expect("capture through first client");
    let second_capture = second_capture.expect("capture through second client");
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

    first.shutdown().await.expect("request station drain");
    let status = tokio::time::timeout(Duration::from_secs(30), daemon.wait())
        .await
        .expect("station daemon exit timeout")
        .expect("wait for station daemon");
    assert!(status.success(), "station daemon failed: {status}");
    remove_tree(&profiles).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stationd_hard_kill_releases_profile_and_client_reconnects_e2e() {
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
    let capture = client
        .capture("crash-recovery-profile", fixture.url("/after-crash"))
        .await
        .expect("successor acquires profile released by hard kill");
    assert_eq!(capture.title.as_deref(), Some("after-crash"));
    assert!(
        String::from_utf8_lossy(&capture.html)
            .contains("data-daemon-e2e=\"after-crash\"")
    );
    client.shutdown().await.expect("shutdown successor stationd");
    let status = tokio::time::timeout(Duration::from_secs(30), successor.wait())
        .await
        .expect("successor stationd exit timeout")
        .expect("wait for successor stationd");
    assert!(status.success(), "successor stationd failed: {status}");
    remove_tree(&profiles).await;
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
