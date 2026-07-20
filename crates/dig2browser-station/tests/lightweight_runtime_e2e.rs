#![cfg(windows)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use dig2browser::identity::ProfileOwnershipGuard;
use dig2browser_client::{
    CaptureCompleteness, ClientConfig, ClientError, CollectionTask,
    ControlTransport, EngineFamily, ResponseStatus, RuntimeFeature, RuntimeKind,
    RuntimeLimitation, RuntimeRequirements, RuntimeSelector, StationClient,
    SupportLevel, TaskCapturePolicy, TaskReply, TaskRuntimeContract, TaskStep,
};
use tokio::io::AsyncReadExt;

const PAGE: &str = "<!doctype html><html><head><title>lightweight fixture</title></head><body><main id=\"target\">original static value</main><script>document.querySelector('#target').textContent='script executed';document.title='script executed';</script></body></html>";

struct ControlledOrigin {
    address: SocketAddr,
    requests: Arc<AtomicUsize>,
    stopping: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl ControlledOrigin {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .expect("bind lightweight controlled origin");
        let address = listener
            .local_addr()
            .expect("read lightweight controlled origin address");
        listener
            .set_nonblocking(true)
            .expect("make lightweight controlled origin nonblocking");
        let stopping = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(AtomicUsize::new(0));
        let thread_stopping = Arc::clone(&stopping);
        let thread_requests = Arc::clone(&requests);
        let thread = thread::spawn(move || {
            while !thread_stopping.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_nonblocking(false)
                            .expect("make lightweight controlled connection blocking");
                        thread_requests.fetch_add(1, Ordering::AcqRel);
                        serve_request(&mut stream)
                            .expect("serve lightweight controlled-origin request");
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("lightweight controlled origin failed: {error}"),
                }
            }
        });
        Self {
            address,
            requests,
            stopping,
            thread: Some(thread),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.address.port())
    }

    fn request_count(&self) -> usize {
        self.requests.load(Ordering::Acquire)
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

fn serve_request(stream: &mut TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut request = Vec::with_capacity(4096);
    loop {
        let mut chunk = [0_u8; 1024];
        let count = stream.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..count]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if request.len() >= 16 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "controlled-origin request headers exceed bound",
            ));
        }
    }
    let request = String::from_utf8_lossy(&request);
    let path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");
    match path {
        "/start" => stream.write_all(
            b"HTTP/1.1 302 Found\r\nLocation: /document\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        ),
        "/document" => {
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",
                PAGE.len()
            );
            stream.write_all(headers.as_bytes())?;
            stream.write_all(PAGE.as_bytes())
        }
        _ => stream.write_all(
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        ),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stationd_lightweight_collects_static_dom_and_html_e2e() {
    let _serial = e2e_serial_guard().await;
    let origin = ControlledOrigin::start();
    let unique = uuid::Uuid::new_v4();
    let pipe_name = format!("dig2browser-lightweight-e2e-{unique}");
    let profiles = e2e_temp_base().join(format!("dig2browser-lightweight-e2e-{unique}"));
    std::fs::create_dir_all(&profiles).expect("create lightweight E2E profiles root");
    let mut daemon = spawn_lightweight_stationd(&pipe_name, &profiles);
    let client = connect(&pipe_name).await;
    let profile_id = "static-document-profile";
    let requested_url = origin.url("/start");
    let final_url = origin.url("/document");
    let requirements = RuntimeRequirements::new(
        vec![
            RuntimeFeature::Navigate,
            RuntimeFeature::DomInspect,
            RuntimeFeature::CaptureState,
            RuntimeFeature::CaptureHtml,
            RuntimeFeature::Lifecycle,
        ],
        false,
    )
    .expect("valid lightweight task requirements");
    let contract = TaskRuntimeContract::new(
        RuntimeSelector::Exact(RuntimeKind::Lightweight),
        requirements,
    )
    .expect("valid exact lightweight runtime contract");
    let task = CollectionTask::new_with_runtime(
        vec![
            TaskStep::Navigate {
                url: requested_url.clone(),
            },
            TaskStep::ReadSelectorText {
                selector: "#target".to_owned(),
            },
            TaskStep::Capture {
                policy: TaskCapturePolicy::HtmlOnly,
            },
        ],
        contract,
    )
    .expect("valid lightweight collection task");

    let result = client
        .run_task(profile_id, task)
        .await
        .expect("run task through stationd lightweight production path");
    assert_eq!(result.replies().len(), 3);
    assert_eq!(result.replies()[0], TaskReply::Acknowledged);
    assert_eq!(
        result.replies()[1],
        TaskReply::Text("original static value".to_owned()),
        "lightweight runtime unexpectedly executed page script"
    );
    let TaskReply::Capture(capture) = &result.replies()[2] else {
        panic!("lightweight task did not return HTML capture");
    };
    assert_eq!(capture.completeness, CaptureCompleteness::Complete);
    assert_eq!(capture.policy, TaskCapturePolicy::HtmlOnly);
    assert_eq!(capture.requested_url, requested_url);
    assert_eq!(capture.final_url, final_url);
    assert_eq!(capture.http_status, Some(200));
    assert_eq!(capture.title, "lightweight fixture");
    assert_eq!(capture.ready_state, "complete");
    assert_eq!(capture.html, PAGE.as_bytes());
    assert!(capture.png.is_empty());
    assert_eq!(capture.png_sha256, None);
    assert_eq!(
        digest_hex(capture.html_sha256),
        "6985babf2edcfeb7a05222710e1611994e9a873c17d1deefdda6736cf6f590ad"
    );
    assert_eq!(capture.collector_version, "dig2browser-station/0.1.0");
    assert_eq!(capture.protocol_version, dig2browser_protocol::PROTOCOL_VERSION);
    assert_eq!(origin.request_count(), 2, "redirect path was not exercised");

    let runtime = result
        .runtime()
        .expect("exact lightweight task records resolved runtime");
    assert_eq!(runtime.kind(), RuntimeKind::Lightweight);
    assert_eq!(runtime.engine(), EngineFamily::Dig2Lightweight);
    assert_eq!(runtime.control(), ControlTransport::Native);
    assert_eq!(runtime.version(), Some("0.1.0"));
    for feature in [
        RuntimeFeature::Navigate,
        RuntimeFeature::DomInspect,
        RuntimeFeature::CaptureState,
        RuntimeFeature::CaptureHtml,
        RuntimeFeature::Lifecycle,
    ] {
        assert_support(runtime, feature, SupportLevel::Native, &[]);
    }
    assert_support(
        runtime,
        RuntimeFeature::DesktopWeb,
        SupportLevel::Partial,
        &[
            RuntimeLimitation::NoScriptExecution,
            RuntimeLimitation::NoVisualRendering,
            RuntimeLimitation::NoInteractiveDom,
            RuntimeLimitation::NoSubresourceLoading,
            RuntimeLimitation::NoPersonaEmulation,
            RuntimeLimitation::Utf8HtmlOnly,
            RuntimeLimitation::NoBrowserSessionState,
        ],
    );
    for unsupported in [
        RuntimeFeature::ScriptEvaluate,
        RuntimeFeature::CaptureViewportPng,
        RuntimeFeature::PersistentProfile,
    ] {
        assert!(
            runtime
                .granted()
                .iter()
                .all(|support| support.feature() != unsupported),
            "unsupported feature was recorded as granted: {unsupported:?}"
        );
    }

    let profile_dir = profiles.join(profile_id);
    assert!(
        ProfileOwnershipGuard::acquire(&profile_dir).is_err(),
        "resident lightweight worker released profile ownership early"
    );
    client
        .shutdown()
        .await
        .expect("request clean lightweight station shutdown");
    assert_clean_exit(&mut daemon).await;
    let released = ProfileOwnershipGuard::acquire(&profile_dir)
        .expect("station shutdown releases lightweight profile ownership");
    drop(released);
    remove_tree(&profiles).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stationd_lightweight_rejects_script_before_profile_creation_e2e() {
    let _serial = e2e_serial_guard().await;
    let origin = ControlledOrigin::start();
    let unique = uuid::Uuid::new_v4();
    let pipe_name = format!("dig2browser-lightweight-reject-e2e-{unique}");
    let profiles =
        e2e_temp_base().join(format!("dig2browser-lightweight-reject-e2e-{unique}"));
    std::fs::create_dir_all(&profiles).expect("create lightweight rejection profiles root");
    let mut daemon = spawn_lightweight_stationd(&pipe_name, &profiles);
    let client = connect(&pipe_name).await;
    let profile_id = "script-must-not-spawn";
    let requirements = RuntimeRequirements::new(
        vec![RuntimeFeature::Navigate, RuntimeFeature::ScriptEvaluate],
        false,
    )
    .expect("valid unsupported lightweight requirements");
    let contract = TaskRuntimeContract::new(
        RuntimeSelector::Exact(RuntimeKind::Lightweight),
        requirements,
    )
    .expect("valid unsupported lightweight contract");
    let task = CollectionTask::new_with_runtime(
        vec![
            TaskStep::Navigate {
                url: origin.url("/document"),
            },
            TaskStep::Evaluate {
                script: "document.title".to_owned(),
            },
        ],
        contract,
    )
    .expect("valid unsupported lightweight task");

    let error = client
        .run_task(profile_id, task)
        .await
        .expect_err("lightweight ScriptEvaluate must fail closed");
    match error {
        ClientError::Remote { status, message } => {
            assert_eq!(status, ResponseStatus::Unsupported);
            assert_eq!(message, "runtime contract unsupported");
        }
        other => panic!("unexpected lightweight runtime rejection: {other}"),
    }
    assert!(
        !profiles.join(profile_id).exists(),
        "unsupported task created a profile before runtime admission"
    );
    assert_eq!(
        origin.request_count(),
        0,
        "unsupported task reached the controlled origin"
    );
    let status = client.status().await.expect("read lightweight rejection status");
    assert_eq!(status.resident_identities, 0);
    assert_eq!(status.active_leases, 0);

    client
        .shutdown()
        .await
        .expect("shutdown lightweight rejection station");
    assert_clean_exit(&mut daemon).await;
    remove_tree(&profiles).await;
}

fn assert_support(
    runtime: &dig2browser_client::ResolvedRuntimeRecord,
    feature: RuntimeFeature,
    level: SupportLevel,
    limitations: &[RuntimeLimitation],
) {
    let support = runtime
        .granted()
        .iter()
        .find(|support| support.feature() == feature)
        .unwrap_or_else(|| panic!("runtime did not record feature {feature:?}"));
    assert_eq!(support.level(), level, "wrong support level for {feature:?}");
    assert_eq!(
        support.limitations(),
        limitations,
        "wrong limitations for {feature:?}"
    );
}

fn digest_hex(bytes: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    output
}

async fn connect(pipe_name: &str) -> StationClient {
    StationClient::connect(
        ClientConfig::new(
            pipe_name,
            Duration::from_secs(15),
            Duration::from_secs(60),
        )
        .expect("valid lightweight E2E client config"),
    )
    .await
    .expect("connect lightweight station client")
}

fn spawn_lightweight_stationd(pipe_name: &str, profiles: &Path) -> tokio::process::Child {
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_dig2browser-stationd"));
    command.args([
        "--pipe-name",
        pipe_name,
        "--profiles-root",
        profiles.to_str().expect("profiles path is UTF-8"),
        "--runtime",
        "lightweight",
        "--max-resident",
        "1",
        "--max-in-flight",
        "2",
        "--max-connections",
        "2",
        "--timeout-seconds",
        "60",
        "--drain-seconds",
        "15",
        "--allow-remote-shutdown",
        "--allow-interactive-tasks",
        "--allow-scripted-tasks",
    ]);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn lightweight station daemon")
}

async fn assert_clean_exit(daemon: &mut tokio::process::Child) {
    let status = tokio::time::timeout(Duration::from_secs(30), daemon.wait())
        .await
        .expect("lightweight station exit timeout")
        .expect("wait for lightweight station daemon");
    assert!(status.success(), "lightweight station failed: {status}");
    let (stdout, stderr) = read_child_output(daemon).await;
    assert!(stderr.is_empty(), "clean lightweight station wrote stderr: {stderr}");
    assert!(stdout.contains("\"event\":\"station_exit\""));
    assert!(stdout.contains("\"outcome\":\"clean\""));
    assert!(stdout.contains("\"stop_reason\":\"remote_request\""));
    assert!(stdout.contains("\"drain_timed_out\":false"));
}

async fn read_child_output(child: &mut tokio::process::Child) -> (String, String) {
    let mut stdout = String::new();
    if let Some(mut stream) = child.stdout.take() {
        stream
            .read_to_string(&mut stdout)
            .await
            .expect("read lightweight station stdout");
    }
    let mut stderr = String::new();
    if let Some(mut stream) = child.stderr.take() {
        stream
            .read_to_string(&mut stderr)
            .await
            .expect("read lightweight station stderr");
    }
    (stdout, stderr)
}

async fn e2e_serial_guard() -> tokio::sync::SemaphorePermit<'static> {
    static E2E_SERIAL: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);
    E2E_SERIAL
        .acquire()
        .await
        .expect("lightweight E2E semaphore remains open")
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
    panic!("could not remove lightweight E2E profiles: {}", path.display());
}
