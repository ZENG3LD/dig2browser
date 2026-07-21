#![cfg(all(windows, feature = "crawler-test-hooks"))]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use dig2browser_client::{
    ArtifactMediaType, ArtifactRef, ClientConfig, ClientError, CollectionId,
    CollectionTask, ResponseStatus, RuntimeKind, RuntimeRequirements,
    RuntimeSelector, StationClient, TaskCapturePolicy, TaskRuntimeContract,
    TaskStep, TerminalOutcome, TraceCursor, TraceEvent, TraceEventKind,
};
use tokio::io::AsyncReadExt;

const COLLECTION_ID_BYTES: [u8; 16] = [0x5a; 16];
const RECEIPT_PATH: &str = "/receipt";

struct ControlledOrigin {
    address: SocketAddr,
    requests: Arc<Mutex<Vec<String>>>,
    stopping: Arc<AtomicBool>,
    listener_thread: Option<JoinHandle<()>>,
}

impl ControlledOrigin {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .expect("bind collection-receipt controlled origin");
        let address = listener
            .local_addr()
            .expect("read collection-receipt controlled origin address");
        listener
            .set_nonblocking(true)
            .expect("make collection-receipt origin nonblocking");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stopping = Arc::new(AtomicBool::new(false));
        let listener_requests = Arc::clone(&requests);
        let listener_stopping = Arc::clone(&stopping);
        let listener_thread = thread::spawn(move || {
            while !listener_stopping.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let requests = Arc::clone(&listener_requests);
                        thread::spawn(move || {
                            let _ = serve_origin_connection(stream, &requests);
                        });
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!(
                        "collection-receipt controlled origin failed: {error}"
                    ),
                }
            }
        });
        Self {
            address,
            requests,
            stopping,
            listener_thread: Some(listener_thread),
        }
    }

    fn origin(&self) -> String {
        format!("http://{}", self.address)
    }

    fn url(&self) -> String {
        format!("{}{RECEIPT_PATH}", self.origin())
    }

    fn requests(&self) -> Vec<String> {
        self.requests
            .lock()
            .expect("controlled-origin request log remains available")
            .clone()
    }
}

impl Drop for ControlledOrigin {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        let _ = TcpStream::connect_timeout(&self.address, Duration::from_millis(100));
        if let Some(listener_thread) = self.listener_thread.take() {
            let _ = listener_thread.join();
        }
    }
}

fn serve_origin_connection(
    mut stream: TcpStream,
    requests: &Mutex<Vec<String>>,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut request = Vec::with_capacity(4_096);
    loop {
        let mut chunk = [0u8; 1_024];
        let count = stream.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..count]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if request.len() >= 16 * 1_024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "controlled-origin request headers exceed limit",
            ));
        }
    }
    let request = String::from_utf8_lossy(&request);
    let Some(path) = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|target| target.split('?').next())
        .map(str::to_owned)
    else {
        return Ok(());
    };
    requests
        .lock()
        .expect("controlled-origin request log remains available")
        .push(path.clone());

    let (status, body) = if path == RECEIPT_PATH {
        (
            "200 OK",
            concat!(
                "<!doctype html><html><head>",
                "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
                "<link rel=\"icon\" href=\"data:,\">",
                "<title>receipt-e2e</title></head>",
                "<body><main data-collection-receipt=\"durable\">",
                "durable receipt before terminal</main></body></html>"
            ),
        )
    } else {
        (
            "404 Not Found",
            "<!doctype html><title>not-found</title>",
        )
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{body}",
        body.len(),
    );
    stream.write_all(response.as_bytes())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires installed Chrome and --features crawler-test-hooks"]
async fn stationd_recovers_public_collection_receipt_without_duplicate_outbound_e2e() {
    let _serial = e2e_serial_guard().await;
    let origin = ControlledOrigin::start();
    let unique = uuid::Uuid::new_v4();
    let pipe_name = format!("dig2browser-collection-receipt-e2e-{unique}");
    let root = e2e_temp_base().join(format!(
        "dig2browser-collection-receipt-e2e-{unique}"
    ));
    let profiles = root.join("profiles");
    let traces = root.join("traces");
    let pause_root = root.join("receipt-pause");
    for path in [&profiles, &traces, &pause_root] {
        std::fs::create_dir_all(path).expect("create collection-receipt E2E root");
    }

    let stationd = env!("CARGO_BIN_EXE_dig2browser-stationd");
    let mut daemon = spawn_stationd(
        stationd,
        &pipe_name,
        &profiles,
        &traces,
        &origin.origin(),
        DurablePermissions::ReadWrite,
        Some(&pause_root),
    );
    let client_config = ClientConfig::new(
        &pipe_name,
        Duration::from_secs(15),
        Duration::from_secs(120),
    )
    .expect("valid collection-receipt E2E client config");
    let client = StationClient::connect(client_config.clone())
        .await
        .expect("connect collection-receipt E2E client");

    let collection_id = CollectionId::new(COLLECTION_ID_BYTES)
        .expect("deterministic collection ID is nonzero");
    let task = evidence_viewport_task(origin.url());
    let handle = client
        .begin_collection_with_id("receipt-public", collection_id, task)
        .await
        .expect("begin public EvidenceViewport durable collection");
    assert_eq!(handle.collection_id(), collection_id);
    assert_eq!(handle.runtime().kind(), RuntimeKind::Chrome);

    wait_for_file(&pause_root.join("receipt-paused")).await;
    assert_eq!(
        origin.requests(),
        vec![RECEIPT_PATH.to_owned()],
        "first station made unexpected controlled-origin requests",
    );

    daemon
        .kill()
        .await
        .expect("hard-kill station after durable receipt");
    daemon
        .wait()
        .await
        .expect("reap hard-killed receipt station");
    let _ = read_child_output(&mut daemon).await;
    client
        .health()
        .await
        .expect_err("stale receipt transport unexpectedly survived hard kill");

    let mut successor = spawn_stationd(
        stationd,
        &pipe_name,
        &profiles,
        &traces,
        &origin.origin(),
        DurablePermissions::ReadWrite,
        None,
    );
    wait_for_health(&client).await;

    let receipt = client
        .read_collection_receipt(collection_id)
        .await
        .expect("read reconciled terminal collection receipt");
    assert_eq!(receipt.collection_id(), collection_id);
    assert_eq!(receipt.final_url(), origin.url());
    assert_eq!(receipt.http_status(), Some(200));
    assert_eq!(receipt.title(), Some("receipt-e2e"));
    assert!(receipt.completed_at_unix_ms() > 0);
    assert_eq!(receipt.ready_state(), "complete");
    assert!(receipt.capture_duration_ms() <= 120_000);
    assert!(receipt.collector_version().starts_with("dig2browser-station/"));
    assert_eq!(receipt.protocol_version(), 1);
    let html_artifact = receipt.html().clone();
    assert_eq!(html_artifact.media_type(), ArtifactMediaType::TextHtmlUtf8);
    let viewport_png = receipt
        .viewport_png()
        .cloned()
        .expect("EvidenceViewport receipt includes viewport PNG");
    assert_eq!(viewport_png.media_type(), ArtifactMediaType::ImagePng);

    let trace = read_complete_trace(&client, collection_id).await;
    let started = trace
        .iter()
        .find_map(|event| match event.kind() {
            TraceEventKind::Started(started) => Some(started),
            _ => None,
        })
        .expect("reconciled trace retains Started event");
    assert_eq!(receipt.task_sha256(), started.task_sha256());
    assert!(matches!(
        trace.last().map(TraceEvent::kind),
        Some(TraceEventKind::Terminal(terminal))
            if terminal.outcome() == TerminalOutcome::Succeeded
    ));

    let html = read_complete_artifact(&client, collection_id, &html_artifact).await;
    assert_eq!(
        dig2browser::digest::sha256_bytes(&html),
        *html_artifact.sha256(),
    );
    assert_eq!(u64::try_from(html.len()).unwrap(), html_artifact.len());
    assert!(String::from_utf8_lossy(&html)
        .contains("data-collection-receipt=\"durable\""));

    let png = read_complete_artifact(&client, collection_id, &viewport_png).await;
    assert_eq!(
        dig2browser::digest::sha256_bytes(&png),
        *viewport_png.sha256(),
    );
    assert_eq!(u64::try_from(png.len()).unwrap(), viewport_png.len());
    assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
    assert_eq!(
        origin.requests(),
        vec![RECEIPT_PATH.to_owned()],
        "successor repeated outbound instead of reconciling the receipt",
    );

    client
        .shutdown()
        .await
        .expect("shutdown receipt successor");
    assert_clean_exit(&mut successor).await;

    let mut denied = spawn_stationd(
        stationd,
        &pipe_name,
        &profiles,
        &traces,
        &origin.origin(),
        DurablePermissions::DefaultDeny,
        None,
    );
    let denied_client = StationClient::connect(client_config)
        .await
        .expect("connect default-deny receipt station");
    let denied_read = denied_client.read_collection_receipt(collection_id).await;
    assert!(matches!(
        denied_read,
        Err(ClientError::Remote {
            status: ResponseStatus::Invalid,
            ..
        })
    ));
    assert_eq!(
        origin.requests(),
        vec![RECEIPT_PATH.to_owned()],
        "default-denied receipt read caused outbound traffic",
    );
    denied_client
        .shutdown()
        .await
        .expect("shutdown default-deny receipt station");
    assert_clean_exit(&mut denied).await;
    remove_tree(&root).await;
}

fn evidence_viewport_task(url: String) -> CollectionTask {
    let runtime = TaskRuntimeContract::new(
        RuntimeSelector::Exact(RuntimeKind::Chrome),
        RuntimeRequirements::new(Vec::new(), false)
            .expect("valid receipt runtime requirements"),
    )
    .expect("valid exact-Chrome receipt runtime contract");
    CollectionTask::new_with_runtime(
        vec![
            TaskStep::Navigate { url },
            TaskStep::Capture {
                policy: TaskCapturePolicy::EvidenceViewport,
            },
        ],
        runtime,
    )
    .expect("valid EvidenceViewport receipt task")
}

async fn read_complete_trace(
    client: &StationClient,
    collection_id: CollectionId,
) -> Vec<TraceEvent> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let mut cursor = TraceCursor::START;
    let mut events = Vec::new();
    loop {
        let page = client
            .read_trace(collection_id, cursor, 64)
            .await
            .expect("read reconciled collection trace");
        events.extend_from_slice(page.events());
        if page.is_complete() {
            return events;
        }
        assert_ne!(page.next_cursor(), cursor, "trace cursor stopped advancing");
        cursor = page.next_cursor();
        assert!(
            tokio::time::Instant::now() < deadline,
            "receipt-backed trace did not become terminal"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn read_complete_artifact(
    client: &StationClient,
    collection_id: CollectionId,
    artifact: &ArtifactRef,
) -> Vec<u8> {
    let mut offset = 0u64;
    let mut bytes = Vec::new();
    loop {
        let chunk = client
            .read_artifact_chunk(
                collection_id,
                *artifact.sha256(),
                offset,
                64 * 1_024,
            )
            .await
            .expect("read receipt artifact chunk");
        assert_eq!(chunk.collection_id(), collection_id);
        assert_eq!(chunk.sha256(), artifact.sha256());
        assert_eq!(chunk.offset(), offset);
        assert_eq!(chunk.total_len(), artifact.len());
        bytes.extend_from_slice(chunk.bytes());
        offset = offset
            .checked_add(u64::try_from(chunk.bytes().len()).unwrap())
            .expect("receipt artifact offset remains bounded");
        if chunk.is_eof() {
            return bytes;
        }
    }
}

#[derive(Clone, Copy)]
enum DurablePermissions {
    ReadWrite,
    DefaultDeny,
}

fn spawn_stationd(
    stationd: &str,
    pipe_name: &str,
    profiles: &Path,
    traces: &Path,
    allowed_origin: &str,
    permissions: DurablePermissions,
    receipt_pause_root: Option<&Path>,
) -> tokio::process::Child {
    let mut command = tokio::process::Command::new(stationd);
    command.args([
        "--pipe-name",
        pipe_name,
        "--profiles-root",
        profiles.to_str().expect("profiles path is UTF-8"),
        "--trace-root",
        traces.to_str().expect("trace path is UTF-8"),
        "--runtime",
        "chrome",
        "--max-resident",
        "1",
        "--max-in-flight",
        "2",
        "--max-connections",
        "4",
        "--timeout-seconds",
        "120",
        "--drain-seconds",
        "15",
        "--allow-origin",
        allowed_origin,
        "--allow-private-peer",
        "127.0.0.1",
        "--allow-remote-shutdown",
    ]);
    if matches!(permissions, DurablePermissions::ReadWrite) {
        command.args(["--allow-durable-read", "--allow-durable-write"]);
    }
    if let Some(root) = receipt_pause_root {
        command.env("DIG2BROWSER_TEST_PAUSE_AFTER_CRAWL_RECEIPT", root);
    }
    command
        .env("HTTP_PROXY", "http://127.0.0.1:1")
        .env("HTTPS_PROXY", "http://127.0.0.1:1")
        .env("ALL_PROXY", "http://127.0.0.1:1")
        .env("NO_PROXY", "*")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn collection-receipt station daemon")
}

async fn wait_for_file(path: &Path) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    while !path.exists() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "station did not reach durable-receipt pause point"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn wait_for_health(client: &StationClient) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if client.health().await.is_ok() {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "client did not reconnect to collection-receipt successor"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn assert_clean_exit(daemon: &mut tokio::process::Child) {
    let status = tokio::time::timeout(Duration::from_secs(30), daemon.wait())
        .await
        .expect("collection-receipt station exit timeout")
        .expect("wait for collection-receipt station");
    assert!(status.success(), "collection-receipt station failed: {status}");
    let (stdout, stderr) = read_child_output(daemon).await;
    assert!(stderr.is_empty(), "receipt station wrote stderr: {stderr}");
    assert!(stdout.contains("\"event\":\"station_exit\""));
    assert!(stdout.contains("\"outcome\":\"clean\""));
    assert!(stdout.contains("\"drain_timed_out\":false"));
}

async fn read_child_output(child: &mut tokio::process::Child) -> (String, String) {
    let mut stdout = String::new();
    if let Some(mut stream) = child.stdout.take() {
        stream
            .read_to_string(&mut stdout)
            .await
            .expect("read collection-receipt station stdout");
    }
    let mut stderr = String::new();
    if let Some(mut stream) = child.stderr.take() {
        stream
            .read_to_string(&mut stderr)
            .await
            .expect("read collection-receipt station stderr");
    }
    (stdout, stderr)
}

async fn e2e_serial_guard() -> tokio::sync::SemaphorePermit<'static> {
    static E2E_SERIAL: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);
    E2E_SERIAL
        .acquire()
        .await
        .expect("receipt E2E semaphore remains open")
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
    panic!(
        "could not remove collection-receipt E2E root: {}",
        path.display()
    );
}
