use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use dig2browser::agentic::{
    AgentCommand, AgentReply, BrowserWorkerConfig, CapabilitySet, CaptureArtifact,
    CapturePolicy,
};
use dig2browser_station::{
    BrowserStation, IdentityRequest, StationConfig, StationError,
};

struct FixtureServer {
    address: SocketAddr,
    stopping: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl FixtureServer {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind station fixture");
        let address = listener.local_addr().expect("fixture address");
        listener
            .set_nonblocking(true)
            .expect("make fixture nonblocking");
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
                    Err(error) => panic!("station fixture failed: {error}"),
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

fn serve_connection(mut stream: TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut request = [0_u8; 4096];
    let count = stream.read(&mut request)?;
    let request = String::from_utf8_lossy(&request[..count]);
    let path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");
    let title = if path.starts_with("/two") {
        "station two"
    } else {
        "station one"
    };
    let body = format!(
        "<!doctype html><title>{title}</title><main data-e2e=\"station\">{title}</main>"
    );
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes())
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn station_reuses_identity_enforces_ownership_and_drains_real_browser_e2e() {
    let fixture = FixtureServer::start();
    let profiles = e2e_temp_base().join(format!(
        "dig2browser-station-e2e-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let mut worker = BrowserWorkerConfig::default();
    worker.command_timeout = Duration::from_secs(60);
    worker.launch.restart_after_pages = 2;
    let config = StationConfig::new(&profiles, 1, 2)
        .expect("valid station config")
        .with_worker_config(worker);
    let station = BrowserStation::new(config);
    let identity = IdentityRequest::public_desktop("station-real-e2e");

    let first = station
        .lease(identity.clone(), CapabilitySet::monitoring())
        .await
        .expect("lease first identity");
    first
        .execute(AgentCommand::Navigate {
            url: fixture.url("/one"),
        })
        .await
        .expect("navigate first fixture");
    let capture = first
        .execute(AgentCommand::Capture {
            policy: CapturePolicy::HtmlOnly,
        })
        .await
        .expect("capture first fixture");
    match capture {
        AgentReply::Capture(CaptureArtifact::HtmlOnly { state, html }) => {
            assert_eq!(state.title, "station one");
            assert!(html.contains("data-e2e=\"station\""));
        }
        reply => panic!("unexpected station capture: {reply:?}"),
    }

    let second = station
        .lease(identity, CapabilitySet::monitoring())
        .await
        .expect("reuse station identity");
    let snapshot = station.snapshot().await;
    assert_eq!(snapshot.resident, 1);
    assert_eq!(snapshot.active_leases, 2);

    second
        .execute(AgentCommand::Navigate {
            url: fixture.url("/two"),
        })
        .await
        .expect("second navigation triggers runtime rotation");
    assert_eq!(second.snapshot().restart_count, 1);
    assert!(matches!(
        second.execute(AgentCommand::Shutdown).await,
        Err(StationError::DirectShutdownDenied)
    ));

    let report = station.shutdown().await.expect("drain station");
    assert_eq!(report.stopped, 1);
    assert!(matches!(
        first
            .execute(AgentCommand::Navigate {
                url: fixture.url("/one"),
            })
            .await,
        Err(StationError::ShuttingDown)
    ));
    drop(first);
    drop(second);
    remove_tree(&profiles).await;
}

fn e2e_temp_base() -> PathBuf {
    #[cfg(windows)]
    {
        std::env::var_os("DIG2BROWSER_E2E_TMP")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\tmp"))
    }
    #[cfg(not(windows))]
    {
        std::env::temp_dir()
    }
}

async fn remove_tree(path: &Path) {
    for _ in 0..30 {
        match std::fs::remove_dir_all(path) {
            Ok(()) => return,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    panic!("could not remove station E2E profiles: {}", path.display());
}
