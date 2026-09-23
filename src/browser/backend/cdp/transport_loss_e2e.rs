use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::*;
use crate::browser::backend::{BrowserBackend, PageBackend};
use crate::detect::args::BrowserProfile;

enum OriginMode {
    Allowed { blocked_origin: String },
    Blocked,
}

struct ControlledOrigin {
    address: SocketAddr,
    requests: Arc<AtomicUsize>,
    paths: Arc<Mutex<Vec<String>>>,
    stopping: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl ControlledOrigin {
    fn blocked() -> Self {
        Self::start(OriginMode::Blocked)
    }

    fn allowed(blocked_origin: String) -> Self {
        Self::start(OriginMode::Allowed { blocked_origin })
    }

    fn start(mode: OriginMode) -> Self {
        let listener =
            TcpListener::bind("127.0.0.1:0").expect("bind transport-loss origin");
        let address = listener.local_addr().expect("read transport-loss origin");
        listener
            .set_nonblocking(true)
            .expect("make transport-loss origin nonblocking");
        let requests = Arc::new(AtomicUsize::new(0));
        let paths = Arc::new(Mutex::new(Vec::new()));
        let stopping = Arc::new(AtomicBool::new(false));
        let thread_requests = Arc::clone(&requests);
        let thread_paths = Arc::clone(&paths);
        let thread_stopping = Arc::clone(&stopping);
        let thread = thread::spawn(move || {
            while !thread_stopping.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_nonblocking(false)
                            .expect("make transport-loss connection blocking");
                        thread_requests.fetch_add(1, Ordering::AcqRel);
                        let _ = serve_request(&mut stream, &mode, &thread_paths);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("transport-loss origin failed: {error}"),
                }
            }
        });
        Self {
            address,
            requests,
            paths,
            stopping,
            thread: Some(thread),
        }
    }

    fn origin(&self) -> String {
        format!("http://127.0.0.1:{}", self.address.port())
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.origin())
    }

    fn request_count(&self) -> usize {
        self.requests.load(Ordering::Acquire)
    }

    fn path_count(&self, expected: &str) -> usize {
        self.paths
            .lock()
            .expect("transport-loss paths remain available")
            .iter()
            .filter(|path| path.as_str() == expected)
            .count()
    }
}

impl Drop for ControlledOrigin {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        let _ = TcpStream::connect_timeout(&self.address, Duration::from_millis(100));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve_request(
    stream: &mut TcpStream,
    mode: &OriginMode,
    paths: &Mutex<Vec<String>>,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut request = Vec::with_capacity(4096);
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let mut chunk = [0_u8; 1024];
        let count = stream.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..count]);
        if request.len() >= 16 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "transport-loss request headers exceed bound",
            ));
        }
    }
    let request = String::from_utf8_lossy(&request);
    let path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");
    paths
        .lock()
        .expect("transport-loss paths remain available")
        .push(path.to_owned());
    let (status, content_type, body) = match mode {
        OriginMode::Allowed { blocked_origin } if path == "/document" => (
            "200 OK",
            "text/html; charset=utf-8",
            format!(
                "<!doctype html><title>transport loss</title><script>setTimeout(()=>fetch('/armed').catch(()=>{{}}),100);setTimeout(()=>fetch('{blocked_origin}/after-loss').catch(()=>{{}}),3000);</script>"
            ),
        ),
        OriginMode::Allowed { .. } if path == "/armed" => (
            "204 No Content",
            "text/plain; charset=utf-8",
            String::new(),
        ),
        OriginMode::Allowed { .. } => (
            "404 Not Found",
            "text/plain; charset=utf-8",
            String::new(),
        ),
        OriginMode::Blocked => (
            "204 No Content",
            "text/plain; charset=utf-8",
            String::new(),
        ),
    };
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body.as_bytes())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cdp_transport_loss_terminates_owned_chromium_before_scheduled_egress_e2e() {
    let _real_browser_guard = crate::test_support::REAL_BROWSER_E2E.lock().await;
    let blocked = ControlledOrigin::blocked();
    let allowed = ControlledOrigin::allowed(blocked.origin());
    let root = e2e_temp_base().join(format!(
        "dig2browser-cdp-loss-e2e-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let profile = root.join("profile");
    std::fs::create_dir_all(&root).expect("create transport-loss E2E root");

    let launch = LaunchConfig {
        profile: BrowserProfile::Persistent(profile.clone()),
        ..Default::default()
    };
    let browser = CdpBrowserBackend::launch(&launch, &StealthConfig::default())
        .await
        .expect("launch owned Chromium");
    let process_tree = Arc::clone(
        browser
            ._process_tree
            .as_ref()
            .expect("owned launch has process-tree containment"),
    );
    let client = Arc::clone(&browser.client);
    let page = browser
        .open_page(None)
        .await
        .expect("open controlled blank page");
    page.install_page_request_policy(
        NavigationPolicy::exact_origins([allowed.origin()])
            .expect("valid controlled exact origin"),
    )
    .await
    .expect("install exact page policy");
    page.goto(&allowed.url("/document"))
        .await
        .expect("navigate to controlled document");
    wait_for_path(&allowed, "/armed", Duration::from_secs(5)).await;
    assert_eq!(blocked.request_count(), 0);

    let inflight_session = page.session.clone();
    let inflight = tokio::spawn(async move {
        inflight_session
            .call(
                "Runtime.evaluate",
                Some(serde_json::json!({
                    "expression": "fetch('/inflight').then(()=>new Promise(()=>{}))",
                    "awaitPromise": true,
                    "returnByValue": true,
                })),
            )
            .await
    });
    wait_for_path(&allowed, "/inflight", Duration::from_secs(5)).await;
    let mut terminal = client.subscribe_terminal();
    client
        .close_transport()
        .await
        .expect("close only the CDP transport");
    tokio::time::timeout(Duration::from_secs(2), terminal.changed())
        .await
        .expect("CDP terminal signal timeout")
        .expect("CDP terminal sender remains available");
    assert!(*terminal.borrow(), "CDP transport did not become terminal");
    let inflight_result = tokio::time::timeout(Duration::from_secs(2), inflight)
        .await
        .expect("in-flight CDP call remained stuck after transport loss")
        .expect("in-flight CDP task panicked");
    assert!(
        matches!(inflight_result, Err(CdpError::ConnectionClosed)),
        "in-flight CDP call did not fail as connection-closed: {inflight_result:?}"
    );
    assert!(
        process_tree
            .wait_until_empty(Duration::from_secs(5))
            .await
            .expect("query owned process tree"),
        "owned Chromium survived terminal CDP transport"
    );
    assert!(
        !page.page_request_policy_healthy(),
        "page policy remained healthy after terminal CDP transport"
    );
    tokio::time::sleep(Duration::from_millis(3_200)).await;
    assert_eq!(
        blocked.request_count(),
        0,
        "scheduled page JS reached the blocked origin after CDP loss"
    );

    page.clear_page_request_policy()
        .await
        .expect("clear terminated page policy");
    drop(page);
    Box::new(browser)
        .close()
        .await
        .expect("close terminated browser backend");
    let successor =
        ProfileOwnershipGuard::acquire(&profile).expect("reacquire released profile");
    drop(successor);
    remove_tree(&root).await;
}

async fn wait_for_path(origin: &ControlledOrigin, path: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if origin.path_count(path) > 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("controlled page did not exercise {path}");
}

fn e2e_temp_base() -> PathBuf {
    std::env::var_os("DIG2BROWSER_E2E_TMP")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\tmp"))
}

async fn remove_tree(path: &Path) {
    // Windows can hold the just-closed Chromium's profile files locked for a
    // moment after process exit (antivirus scan, deferred handle release).
    // 15s matches the other owned-process teardown waits in this suite
    // (e.g. `ProcessTreeHandle::wait_until_empty`).
    for _ in 0..150 {
        match std::fs::remove_dir_all(path) {
            Ok(()) => return,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    panic!("could not remove transport-loss E2E root: {}", path.display());
}
