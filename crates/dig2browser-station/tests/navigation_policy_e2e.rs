#![cfg(windows)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use dig2browser_client::{
    BrowserPersona, ClientConfig, ClientError, CollectionTask, ResponseStatus,
    RuntimeFeature, RuntimeKind, RuntimeRequirements, RuntimeSelector, StationClient,
    TaskCapturePolicy, TaskReply, TaskRuntimeContract, TaskStep,
};
use tokio::io::AsyncReadExt;

type ControlledResponse = (&'static str, Vec<(String, String)>, String);
type Responder = Arc<dyn Fn(&str) -> ControlledResponse + Send + Sync>;

struct ControlledOrigin {
    address: SocketAddr,
    requests: Arc<AtomicUsize>,
    paths: Arc<Mutex<Vec<String>>>,
    stopping: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl ControlledOrigin {
    fn blocked() -> Self {
        Self::start(Arc::new(|_| {
            (
                "200 OK",
                Vec::new(),
                "<!doctype html><title>blocked origin</title>".to_owned(),
            )
        }))
    }

    fn allowed(blocked_origin: String) -> Self {
        Self::start(Arc::new(move |path| match path {
            "/document" => (
                "200 OK",
                Vec::new(),
                format!(
                    "<!doctype html><html><head><title>allowed origin</title></head><body><main id=\"ok\">allowed</main><img src=\"/allowed-pixel\"><img src=\"{blocked_origin}/pixel\"></body></html>"
                ),
            ),
            "/allowed-pixel" => ("200 OK", Vec::new(), "allowed pixel".to_owned()),
            "/popup" => (
                "200 OK",
                Vec::new(),
                "<!doctype html><title>popup</title><button id=\"popup\" onclick=\"window.open('/popup-child','_blank')\">open</button>".to_owned(),
            ),
            "/popup-child" => (
                "200 OK",
                Vec::new(),
                format!(
                    "<!doctype html><title>popup child</title><script>fetch('{blocked_origin}/popup-fetch').catch(()=>{{}});</script>"
                ),
            ),
            "/worker-page" => (
                "200 OK",
                Vec::new(),
                "<!doctype html><title>worker</title><main id=\"worker-state\">pending</main><script>const worker=new Worker('/worker.js');worker.onmessage=(event)=>{document.querySelector('#worker-state').textContent=event.data;};worker.onerror=()=>{document.querySelector('#worker-state').textContent='worker-error';};</script>".to_owned(),
            ),
            "/worker.js" => (
                "200 OK",
                vec![(
                    "Content-Type".to_owned(),
                    "text/javascript; charset=utf-8".to_owned(),
                )],
                format!(
                    "fetch('/worker-control').then(()=>fetch('{blocked_origin}/worker-fetch')).then(()=>postMessage('attempted'),()=>postMessage('attempted'));"
                ),
            ),
            "/worker-control" => ("200 OK", Vec::new(), "worker control".to_owned()),
            "/redirect-blocked" => (
                "302 Found",
                vec![("Location".to_owned(), format!("{blocked_origin}/redirect-target"))],
                String::new(),
            ),
            _ => ("404 Not Found", Vec::new(), String::new()),
        }))
    }

    fn start(response: Responder) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .expect("bind navigation-policy controlled origin");
        let address = listener.local_addr().expect("read controlled origin address");
        listener
            .set_nonblocking(true)
            .expect("make controlled origin nonblocking");
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
                            .expect("make controlled connection blocking");
                        thread_requests.fetch_add(1, Ordering::AcqRel);
                        let _ = serve_request(&mut stream, &response, &thread_paths);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("controlled origin failed: {error}"),
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
            .expect("controlled origin paths remain available")
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
    response: &Responder,
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
                "controlled-origin headers exceed bound",
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
        .expect("controlled origin paths remain available")
        .push(path.to_owned());
    let (status, headers, body) = response(path);
    write!(stream, "HTTP/1.1 {status}\r\n")?;
    let has_content_type = headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("content-type"));
    for (name, value) in headers {
        write!(stream, "{name}: {value}\r\n")?;
    }
    if !has_content_type {
        write!(stream, "Content-Type: text/html; charset=utf-8\r\n")?;
    }
    write!(
        stream,
        "Content-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body.as_bytes())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stationd_enforces_exact_origin_url_policy_across_runtime_targets_e2e() {
    let _serial = e2e_serial_guard().await;
    let blocked = ControlledOrigin::blocked();
    let allowed = ControlledOrigin::allowed(blocked.origin());

    for (runtime_name, runtime_kind) in [
        ("lightweight", RuntimeKind::Lightweight),
        ("chrome", RuntimeKind::Chrome),
    ] {
        let unique = uuid::Uuid::new_v4();
        let pipe_name = format!("dig2browser-policy-{runtime_name}-{unique}");
        let profiles = e2e_temp_base().join(format!(
            "dig2browser-policy-{runtime_name}-{unique}"
        ));
        let traces = e2e_temp_base().join(format!(
            "dig2browser-policy-trace-{runtime_name}-{unique}"
        ));
        std::fs::create_dir_all(&profiles).expect("create policy E2E profiles");
        std::fs::create_dir_all(&traces).expect("create policy E2E trace root");
        let mut daemon = spawn_stationd(
            &pipe_name,
            &profiles,
            &traces,
            runtime_name,
            &allowed.origin(),
        );
        let client = connect(&pipe_name).await;
        let profile_id = format!("policy-{runtime_name}");

        let legacy_profile_id = format!("policy-legacy-{runtime_name}");
        let legacy_error = client
            .capture(&legacy_profile_id, blocked.url("/legacy-capture"))
            .await
            .expect_err("legacy capture must reject a disallowed origin");
        assert_remote(
            legacy_error,
            ResponseStatus::Invalid,
            "navigation target rejected",
        );
        assert!(!profiles.join(&legacy_profile_id).exists());
        assert_eq!(blocked.request_count(), 0);

        let collection_profile_id = format!("policy-collection-{runtime_name}");
        let collection_error = client
            .begin_collection(
                &collection_profile_id,
                navigation_task(runtime_kind, blocked.url("/collection")),
            )
            .await
            .expect_err("durable collection must reject a disallowed origin");
        assert_remote(
            collection_error,
            ResponseStatus::Invalid,
            "collection request rejected",
        );
        assert!(!profiles.join(&collection_profile_id).exists());
        assert_eq!(blocked.request_count(), 0);

        let error = client
            .run_task(
                &profile_id,
                navigation_task(runtime_kind, blocked.url("/direct")),
            )
            .await
            .expect_err("station must reject an explicit disallowed origin");
        assert_remote(error, ResponseStatus::Invalid, "navigation target rejected");
        assert_eq!(blocked.request_count(), 0);
        assert!(!profiles.join(&profile_id).exists());
        let status = client.status().await.expect("read post-rejection status");
        assert_eq!(status.resident_identities, 0);

        if runtime_kind == RuntimeKind::Chrome {
            let auth_profile_id = "policy-auth-chrome";
            let auth_error = client
                .begin_auth_session(
                    auth_profile_id,
                    BrowserPersona::desktop_default(),
                    blocked.url("/auth"),
                )
                .await
                .expect_err("headful auth must reject a disallowed origin");
            assert_remote(
                auth_error,
                ResponseStatus::Invalid,
                "authentication identity rejected",
            );
            assert!(!profiles.join(auth_profile_id).exists());
            assert_eq!(blocked.request_count(), 0);
        }

        let redirect_error = client
            .run_task(
                &profile_id,
                navigation_task(runtime_kind, allowed.url("/redirect-blocked")),
            )
            .await
            .expect_err("runtime must block a redirect to a disallowed origin");
        assert_remote(
            redirect_error,
            ResponseStatus::CaptureFailed,
            "task failed at step 0",
        );
        assert_eq!(
            blocked.request_count(),
            0,
            "{runtime_name} contacted the blocked redirect origin"
        );

        let allowed_pixel_before = allowed.path_count("/allowed-pixel");
        let result = client
            .run_task(
                &profile_id,
                capture_task(runtime_kind, allowed.url("/document")),
            )
            .await
            .expect("allowed origin must remain collectable");
        assert_eq!(result.replies().len(), 2);
        let allowed_pixel_delta =
            allowed.path_count("/allowed-pixel") - allowed_pixel_before;
        if runtime_kind == RuntimeKind::Chrome {
            assert!(
                allowed_pixel_delta >= 1,
                "Chrome did not load the allowed same-page subresource"
            );
        } else {
            assert_eq!(
                allowed_pixel_delta, 0,
                "lightweight runtime unexpectedly loaded a subresource"
            );
        }
        assert_eq!(
            blocked.request_count(),
            0,
            "{runtime_name} contacted the blocked subresource origin"
        );

        if runtime_kind == RuntimeKind::Chrome {
            let popup_child_before = allowed.path_count("/popup-child");
            let blocked_popup_before = blocked.request_count();
            let popup_result = client
                .run_task(&profile_id, popup_task(allowed.url("/popup")))
                .await
                .expect("Chrome popup task must complete under the policy");
            assert_eq!(popup_result.replies().len(), 3);
            assert!(
                allowed.path_count("/popup-child") > popup_child_before,
                "Chrome did not load the controlled popup child"
            );
            assert_eq!(
                blocked.request_count(),
                blocked_popup_before,
                "Chrome popup contacted the blocked origin"
            );

            let worker_script_before = allowed.path_count("/worker.js");
            let worker_control_before = allowed.path_count("/worker-control");
            let blocked_worker_before = blocked.request_count();
            let worker_result = client
                .run_task(&profile_id, worker_task(allowed.url("/worker-page")))
                .await
                .expect("Chrome worker task must complete under the policy");
            assert!(
                allowed.path_count("/worker.js") > worker_script_before,
                "Chrome did not load the controlled worker script"
            );
            assert!(
                allowed.path_count("/worker-control") > worker_control_before,
                "Chrome worker did not execute its allowed control fetch"
            );
            assert_eq!(
                worker_result.replies()[2],
                TaskReply::Text("attempted".to_owned())
            );
            assert_eq!(
                blocked.request_count(),
                blocked_worker_before,
                "Chrome worker contacted the blocked origin"
            );
        }

        client.shutdown().await.expect("request clean station shutdown");
        assert_clean_exit(&mut daemon).await;
        remove_tree(&profiles).await;
        remove_tree(&traces).await;
    }
    assert!(allowed.request_count() >= 6, "shared corpus was not exercised");
}

fn navigation_task(runtime: RuntimeKind, url: String) -> CollectionTask {
    task(
        runtime,
        vec![TaskStep::Navigate { url }],
        vec![RuntimeFeature::Navigate, RuntimeFeature::Lifecycle],
    )
}

fn capture_task(runtime: RuntimeKind, url: String) -> CollectionTask {
    task(
        runtime,
        vec![
            TaskStep::Navigate { url },
            TaskStep::Capture {
                policy: TaskCapturePolicy::HtmlOnly,
            },
        ],
        vec![
            RuntimeFeature::Navigate,
            RuntimeFeature::CaptureState,
            RuntimeFeature::CaptureHtml,
            RuntimeFeature::Lifecycle,
        ],
    )
}

fn popup_task(url: String) -> CollectionTask {
    task(
        RuntimeKind::Chrome,
        vec![
            TaskStep::Navigate { url },
            TaskStep::ClickSelector {
                selector: "#popup".to_owned(),
            },
            TaskStep::Wait {
                duration: Duration::from_millis(750),
            },
        ],
        vec![
            RuntimeFeature::Navigate,
            RuntimeFeature::DomInspect,
            RuntimeFeature::DomInteract,
            RuntimeFeature::Lifecycle,
        ],
    )
}

fn worker_task(url: String) -> CollectionTask {
    task(
        RuntimeKind::Chrome,
        vec![
            TaskStep::Navigate { url },
            TaskStep::Wait {
                duration: Duration::from_millis(1_500),
            },
            TaskStep::ReadSelectorText {
                selector: "#worker-state".to_owned(),
            },
        ],
        vec![
            RuntimeFeature::Navigate,
            RuntimeFeature::DomInspect,
            RuntimeFeature::Lifecycle,
        ],
    )
}

fn task(
    runtime: RuntimeKind,
    steps: Vec<TaskStep>,
    features: Vec<RuntimeFeature>,
) -> CollectionTask {
    let requirements =
        RuntimeRequirements::new(features, false).expect("valid policy requirements");
    let contract = TaskRuntimeContract::new(
        RuntimeSelector::Exact(runtime),
        requirements,
    )
    .expect("valid exact runtime contract");
    CollectionTask::new_with_runtime(steps, contract).expect("valid policy task")
}

fn assert_remote(error: ClientError, status: ResponseStatus, message: &str) {
    match error {
        ClientError::Remote {
            status: actual,
            message: actual_message,
        } => {
            assert_eq!(actual, status);
            assert_eq!(actual_message, message);
        }
        other => panic!("unexpected policy error: {other}"),
    }
}

fn spawn_stationd(
    pipe_name: &str,
    profiles: &Path,
    traces: &Path,
    runtime: &str,
    allowed_origin: &str,
) -> tokio::process::Child {
    let mut command = tokio::process::Command::new(
        env!("CARGO_BIN_EXE_dig2browser-stationd"),
    );
    command.args([
        "--pipe-name",
        pipe_name,
        "--profiles-root",
        profiles.to_str().expect("profiles path is UTF-8"),
        "--trace-root",
        traces.to_str().expect("trace path is UTF-8"),
        "--runtime",
        runtime,
        "--allow-origin",
        allowed_origin,
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
        "--allow-headful-auth",
        "--allow-durable-read",
        "--allow-durable-write",
    ]);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn navigation-policy station")
}

async fn connect(pipe_name: &str) -> StationClient {
    StationClient::connect(
        ClientConfig::new(
            pipe_name,
            Duration::from_secs(15),
            Duration::from_secs(60),
        )
        .expect("valid policy client config"),
    )
    .await
    .expect("connect navigation-policy station")
}

async fn assert_clean_exit(daemon: &mut tokio::process::Child) {
    let status = tokio::time::timeout(Duration::from_secs(30), daemon.wait())
        .await
        .expect("policy station exit timeout")
        .expect("wait for policy station");
    assert!(status.success(), "policy station failed: {status}");
    let (stdout, stderr) = read_child_output(daemon).await;
    assert!(stderr.is_empty(), "policy station wrote stderr: {stderr}");
    assert!(stdout.contains("\"outcome\":\"clean\""));
}

async fn read_child_output(child: &mut tokio::process::Child) -> (String, String) {
    let mut stdout = String::new();
    if let Some(mut stream) = child.stdout.take() {
        stream.read_to_string(&mut stdout).await.expect("read stdout");
    }
    let mut stderr = String::new();
    if let Some(mut stream) = child.stderr.take() {
        stream.read_to_string(&mut stderr).await.expect("read stderr");
    }
    (stdout, stderr)
}

async fn e2e_serial_guard() -> tokio::sync::SemaphorePermit<'static> {
    static E2E_SERIAL: tokio::sync::Semaphore =
        tokio::sync::Semaphore::const_new(1);
    E2E_SERIAL.acquire().await.expect("E2E semaphore remains open")
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
    panic!("could not remove policy E2E profiles: {}", path.display());
}
