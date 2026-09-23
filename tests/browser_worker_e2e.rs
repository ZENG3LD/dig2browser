use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use dig2browser::agentic::{
    AgentCommand, AgentReply, BrowserWorker, BrowserWorkerConfig, CapabilitySet,
    CaptureArtifact, CapturePolicy, ElementRef, MobileLayout, WorkerError, WorkerLifecycle,
};
use dig2browser::identity::{
    BrowserBackend, DevicePersona, IdentityClass, IdentityProfile,
};

const FORM_PAGE: &str = r#"<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>dig2browser e2e fixture</title>
</head>
<body data-fixture="browser-worker-e2e">
  <label>Name <input id="name" autocomplete="off"></label>
  <button id="submit" type="button">Submit</button>
  <output id="result">pending</output>
  <output id="mobile"></output>
  <script>
    document.querySelector('#mobile').textContent = [
      window.innerWidth,
      window.innerHeight,
      window.devicePixelRatio,
      navigator.maxTouchPoints,
      window.screen.width,
      window.screen.height
    ].join('|');
    document.querySelector('#submit').addEventListener('click', () => {
      document.querySelector('#result').textContent =
        'submitted:' + document.querySelector('#name').value;
    });
  </script>
</body>
</html>"#;

const SECOND_PAGE: &str = r#"<!doctype html>
<html>
<head><meta charset="utf-8"><title>second epoch</title></head>
<body><p id="second">second-page-ready</p></body>
</html>"#;

struct FixtureServer {
    address: SocketAddr,
    stopping: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl FixtureServer {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture server");
        let address = listener.local_addr().expect("fixture address");
        listener
            .set_nonblocking(true)
            .expect("make fixture listener nonblocking");
        let stopping = Arc::new(AtomicBool::new(false));
        let thread_stopping = Arc::clone(&stopping);
        let thread = thread::spawn(move || {
            while !thread_stopping.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let _ = serve_connection(stream);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("fixture listener failed: {error}"),
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
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut request = [0_u8; 8192];
    let count = stream.read(&mut request)?;
    let first_line = String::from_utf8_lossy(&request[..count]);
    let path = first_line
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");
    let (status, content_type, body) = match path.split('?').next().unwrap_or(path) {
        "/form" => ("200 OK", "text/html; charset=utf-8", FORM_PAGE),
        "/second" => ("200 OK", "text/html; charset=utf-8", SECOND_PAGE),
        "/favicon.ico" => ("204 No Content", "image/x-icon", ""),
        _ => ("404 Not Found", "text/plain; charset=utf-8", "not found"),
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes())
}

fn temporary_profiles_root() -> PathBuf {
    e2e_temp_base().join(format!(
        "dig2browser-worker-e2e-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ))
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

fn mobile_identity(root: &PathBuf) -> IdentityProfile {
    IdentityProfile::new(
        root,
        "persistent-mobile-e2e",
        IdentityClass::Public,
        BrowserBackend::Chromium,
        DevicePersona::MobileLayout,
    )
    .expect("create E2E identity")
}

fn worker_config(layout: MobileLayout) -> BrowserWorkerConfig {
    BrowserWorkerConfig {
        command_timeout: Duration::from_secs(60),
        mobile_layout: Some(layout),
        ..Default::default()
    }
}

async fn resolve(worker: &BrowserWorker, selector: &str) -> ElementRef {
    match worker
        .execute(AgentCommand::ResolveElement {
            selector: selector.to_owned(),
        })
        .await
        .expect("resolve fixture element")
    {
        AgentReply::Element(element) => element,
        reply => panic!("unexpected resolve reply: {reply:?}"),
    }
}

async fn read_text(worker: &BrowserWorker, element: ElementRef) -> String {
    match worker
        .execute(AgentCommand::ReadElementText { element })
        .await
        .expect("read fixture element")
    {
        AgentReply::Text(text) => text,
        reply => panic!("unexpected text reply: {reply:?}"),
    }
}

async fn remove_profiles_root(path: &PathBuf) {
    let mut last_error = None;
    for _ in 0..30 {
        match std::fs::remove_dir_all(path) {
            Ok(()) => return,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) => {
                last_error = Some(error);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    panic!(
        "remove owned E2E profile tree: {}",
        last_error.expect("profile removal failed without an I/O error")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn browser_worker_real_chromium_persistent_mobile_e2e() {
    let fixture = FixtureServer::start();
    let profiles_root = temporary_profiles_root();
    let identity = mobile_identity(&profiles_root);
    let layout = MobileLayout::common_phone();

    let worker = BrowserWorker::spawn(
        identity.clone(),
        CapabilitySet::all(),
        worker_config(layout.clone()),
    )
    .expect("spawn production browser worker");
    let initial = worker.wait_until_settled().await.expect("start Chrome");
    assert_eq!(initial.lifecycle, WorkerLifecycle::Ready);

    worker
        .execute(AgentCommand::Navigate {
            url: fixture.url("/form"),
        })
        .await
        .expect("navigate to form fixture");
    let input = resolve(&worker, "#name").await;
    let submit = resolve(&worker, "#submit").await;
    let result = resolve(&worker, "#result").await;

    worker
        .execute(AgentCommand::TypeElement {
            element: input.clone(),
            text: "Foxhound E2E".to_owned(),
        })
        .await
        .expect("type through real CDP");
    worker
        .execute(AgentCommand::ClickElement { element: submit })
        .await
        .expect("click through real CDP");
    assert_eq!(read_text(&worker, result).await, "submitted:Foxhound E2E");

    let mobile = read_text(&worker, resolve(&worker, "#mobile").await).await;
    let metrics: Vec<&str> = mobile.split('|').collect();
    assert_eq!(metrics.len(), 6, "unexpected browser metrics: {mobile}");
    assert_eq!(metrics[0], layout.width().to_string());
    assert_eq!(metrics[1], layout.height().to_string());
    assert_eq!(metrics[2], layout.device_scale_factor().to_string());
    assert_eq!(metrics[3], layout.max_touch_points().to_string());
    assert_eq!(metrics[4], layout.width().to_string());
    assert_eq!(metrics[5], layout.height().to_string());

    let capture = worker
        .execute(AgentCommand::Capture {
            policy: CapturePolicy::EvidenceViewport,
        })
        .await
        .expect("capture production evidence");
    match capture {
        AgentReply::Capture(CaptureArtifact::EvidenceViewport { state, html, png }) => {
            assert_eq!(state.title, "dig2browser e2e fixture");
            assert_eq!(state.ready_state, "complete");
            assert!(html.contains("browser-worker-e2e"));
            assert!(html.contains("submitted:Foxhound E2E"));
            assert!(png.len() > 1_000, "viewport PNG is unexpectedly small");
            assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
        }
        reply => panic!("unexpected capture reply: {reply:?}"),
    }

    worker
        .execute(AgentCommand::Navigate {
            url: fixture.url("/second"),
        })
        .await
        .expect("navigate to a new page epoch");
    let stale_after_navigation = worker
        .execute(AgentCommand::ReadElementText {
            element: input.clone(),
        })
        .await;
    assert!(matches!(
        stale_after_navigation,
        Err(WorkerError::StaleElement { .. })
    ));

    let second = resolve(&worker, "#second").await;
    assert_eq!(read_text(&worker, second.clone()).await, "second-page-ready");
    worker
        .execute(AgentCommand::Restart)
        .await
        .expect("restart production browser runtime");
    let stale_after_restart = worker
        .execute(AgentCommand::ReadElementText { element: second })
        .await;
    assert!(matches!(
        stale_after_restart,
        Err(WorkerError::StaleElement { .. })
    ));
    assert_eq!(worker.snapshot().restart_count, 1);
    worker.shutdown().await.expect("shutdown first worker");
    assert_eq!(worker.snapshot().lifecycle, WorkerLifecycle::Stopped);
    drop(worker);

    let successor = BrowserWorker::spawn(
        identity,
        CapabilitySet::all(),
        worker_config(layout),
    )
    .expect("spawn successor on released persistent profile");
    let successor_state = successor
        .wait_until_settled()
        .await
        .expect("start successor Chrome");
    assert_eq!(successor_state.lifecycle, WorkerLifecycle::Ready);
    successor
        .execute(AgentCommand::Navigate {
            url: fixture.url("/second"),
        })
        .await
        .expect("navigate successor worker");
    let successor_element = resolve(&successor, "#second").await;
    assert_eq!(
        read_text(&successor, successor_element).await,
        "second-page-ready"
    );
    successor.shutdown().await.expect("shutdown successor worker");
    drop(successor);

    remove_profiles_root(&profiles_root).await;
}
