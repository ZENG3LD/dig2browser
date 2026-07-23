#![cfg(windows)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dig2browser::identity::ProfileOwnershipGuard;
use dig2browser_client::{
    ArtifactMediaType, ArtifactRef, ArtifactRole, BrowserPersona, ClientConfig,
    ClientError, CollectionId, CollectionTask, ControlTransport, CrawlCursor,
    CrawlEvent, CrawlEventKind, CrawlJobId, CrawlPhase, CrawlSpec, EngineFamily, FailureClass,
    IdentitySessionStatus, InterruptedReason, LiveCursor, LiveEventKind, LiveFilter,
    LiveTarget, MobilePersonaConfig, MonitorCursor, MonitorEvent, MonitorEventKind,
    MonitorFrame, MonitorStopReason, PersonaPreset,
    ProfileClass, ResponseStatus, RouteRef, RuntimeFeature, RuntimeKind,
    RuntimeRequirements, RuntimeSelector, SessionHealthProbe, SessionPhase,
    SessionStateUpdate, StationClient, StationStatus, SupportLevel,
    TaskCapturePolicy, TaskReply, TaskRuntimeContract, TaskStep,
    TerminalOutcome, TraceCursor, TraceEvent, TraceEventKind,
    WebSocketDirection, WebSocketOpcode, PROTOCOL_VERSION,
};
use dig2browser_probe::ProbeTranscriptV1;
use dig2browser_station::{
    BrowserStation, DurableMonitorManager, IdentityRequest as StationIdentityRequest,
    ProfilesRootOwnership, StationConfig,
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
        format!("http://localhost:{}{}", self.address.port(), path)
    }

    fn origin(&self) -> String {
        format!("http://localhost:{}", self.address.port())
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

/// An async WebSocket fixture for the live-capture E2E. It completes the
/// RFC 6455 handshake via tokio-tungstenite, pushes a text frame to each
/// connecting browser (surfacing as `Network.webSocketFrameReceived`), and
/// reads the page's own frame (surfacing as `Network.webSocketFrameSent`),
/// keeping the socket open with periodic pushes until the page/browser goes
/// away. Bound to an ephemeral port; the page script dials it by port.
struct WebSocketFixture {
    port: u16,
    handle: tokio::task::JoinHandle<()>,
}

impl WebSocketFixture {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind websocket fixture");
        let port = listener
            .local_addr()
            .expect("websocket fixture address")
            .port();
        let handle = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let _ = serve_websocket(stream).await;
                });
            }
        });
        Self { port, handle }
    }
}

impl Drop for WebSocketFixture {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

async fn serve_websocket(
    stream: tokio::net::TcpStream,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use futures::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let mut ws = tokio_tungstenite::accept_async(stream).await?;
    // Push once immediately so a `Received` frame is available promptly, then
    // keep pushing so the station's reader reliably catches one after its
    // devtools subscription attaches.
    ws.send(Message::Text("{\"tick\":0}".to_owned().into())).await?;
    let mut tick: u64 = 0;
    loop {
        tokio::select! {
            incoming = ws.next() => match incoming {
                Some(Ok(message)) if message.is_close() => break,
                Some(Ok(_)) => {}
                Some(Err(_)) | None => break,
            },
            _ = tokio::time::sleep(Duration::from_millis(300)) => {
                tick += 1;
                if ws
                    .send(Message::Text(format!("{{\"tick\":{tick}}}").into()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    }
    Ok(())
}

fn serve_connection(mut stream: TcpStream) -> std::io::Result<()> {
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
                "fixture request headers exceed limit",
            ));
        }
    }
    let request = String::from_utf8_lossy(&request);
    let path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/")
        .split('?')
        .next()
        .unwrap_or("/");
    let requested_marker = path.trim_start_matches('/');
    let marker = if requested_marker == "auth-check" {
        if request.lines().any(|line| {
            line.to_ascii_lowercase().starts_with("cookie:")
                && line.contains("dig2browser_auth_e2e=cookie-secret")
        }) {
            "auth-check-ok".to_owned()
        } else {
            "auth-check-missing".to_owned()
        }
    } else if requested_marker == "matrix-cookie-check" {
        match request_cookie_value(&request, "dig2browser_matrix_e2e") {
            Some(value) => format!("matrix-cookie-present-{value}"),
            None => "matrix-cookie-empty".to_owned(),
        }
    } else if let Some(value) = requested_marker.strip_prefix("matrix-cookie-set-") {
        format!("matrix-cookie-set-{value}")
    } else {
        requested_marker.to_owned()
    };
    if marker == "force-close" {
        return Ok(());
    }
    let script = if requested_marker == "auth-bootstrap" {
        "<script>localStorage.setItem('dig2browser_auth_e2e','present');document.cookie='dig2browser_auth_e2e=cookie-secret; Path=/; Max-Age=3600';setTimeout(()=>location.href='/auth-check',50)</script>".to_owned()
    } else if requested_marker == "auth-check" {
        format!(
            "<script>if(localStorage.getItem('dig2browser_auth_roundtrip')===null){{localStorage.setItem('dig2browser_auth_roundtrip',{})}}</script>",
            if marker == "auth-check-ok" { "'ok'" } else { "'missing'" }
        )
    } else if requested_marker == "persona-probe" {
        persona_probe_script(&request)
    } else if let Some(ws_port) = requested_marker.strip_prefix("live-ws-page-") {
        // Open a WebSocket to the live-capture fixture after a short delay so
        // the station's devtools subscription (attached right after Navigate
        // returns) is guaranteed active before any frame is exchanged — the
        // page sends one frame on open (recorded as webSocketFrameSent) and
        // the server pushes frames back (webSocketFrameReceived).
        format!(
            "<script>setTimeout(()=>{{\
const ws=new WebSocket('ws://localhost:{ws_port}/');\
ws.onopen=()=>ws.send('hello-from-page');\
ws.onmessage=(event)=>{{document.title='ws-recv';}};\
}},400)</script>"
        )
    } else {
        String::new()
    };
    let links = requested_marker
        .strip_prefix("matrix-crawl-seed-")
        .map(|runtime| {
            format!(
                "<a href=\"/matrix-crawl-page-2-{runtime}\" data-crawl-next>next</a>"
            )
        })
        .unwrap_or_default();
    let body = format!(
        "<!doctype html><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>{marker}</title><main data-daemon-e2e=\"{marker}\">{marker}</main>{}{links}{script}",
        match requested_marker {
            "session-ready" => "<section data-session-ready></section>",
            "session-reauth" => "<form data-session-reauth></form>",
            "persona-probe" => "<pre id=\"persona-probe-output\"></pre>",
            _ => "",
        }
    );
    let cookie = if requested_marker == "auth-bootstrap" {
        "Set-Cookie: dig2browser_auth_e2e=cookie-secret; Path=/; Max-Age=3600; HttpOnly; SameSite=Lax\r\n".to_owned()
    } else if let Some(value) = requested_marker.strip_prefix("matrix-cookie-set-") {
        format!(
            "Set-Cookie: dig2browser_matrix_e2e={value}; Path=/; Max-Age=3600; HttpOnly; SameSite=Lax\r\n"
        )
    } else {
        String::new()
    };
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n{cookie}Content-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes())
}

fn request_cookie_value(request: &str, expected_name: &str) -> Option<String> {
    let cookie_header = request_header(request, "cookie");
    cookie_header.split(';').find_map(|pair| {
        let (name, value) = pair.trim().split_once('=')?;
        (name == expected_name).then(|| value.to_owned())
    })
}

fn persona_probe_script(request: &str) -> String {
    let server_user_agent = json_script_string(&request_header(request, "user-agent"));
    let accept_language = json_script_string(&request_header(request, "accept-language"));
    let sec_ch_ua_mobile = json_script_string(&request_header(request, "sec-ch-ua-mobile"));
    let sec_ch_ua_platform = json_script_string(&request_header(request, "sec-ch-ua-platform"));
    format!(
        r#"<script>(() => {{
const output = document.getElementById('persona-probe-output');
const uaData = navigator.userAgentData || null;
let webglVendor = '';
let webglRenderer = '';
try {{
  const canvas = document.createElement('canvas');
  const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
  if (gl) {{
    const dbg = gl.getExtension('WEBGL_debug_renderer_info');
    if (dbg) {{
      webglVendor = gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL);
      webglRenderer = gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL);
    }}
  }}
}} catch (_) {{}}
const observation = {{
  browser: {{
    userAgent: navigator.userAgent,
    platform: navigator.platform,
    language: navigator.language,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    uaMobile: uaData ? uaData.mobile : null,
    uaPlatform: uaData ? uaData.platform : null,
    innerWidth: innerWidth,
    innerHeight: innerHeight,
    screenWidth: screen.width,
    screenHeight: screen.height,
    dprMilli: Math.round(devicePixelRatio * 1000),
    maxTouchPoints: navigator.maxTouchPoints,
    coarsePointer: matchMedia('(pointer: coarse)').matches,
    hover: matchMedia('(hover: hover)').matches,
    webdriver: navigator.webdriver === true,
    colorDepth: screen.colorDepth,
    hardwareConcurrency: navigator.hardwareConcurrency,
    deviceMemory: Math.round(navigator.deviceMemory),
    webglVendor: webglVendor,
    webglRenderer: webglRenderer
  }},
  server: {{
    userAgent: {server_user_agent},
    acceptLanguage: {accept_language},
    secChUaMobile: {sec_ch_ua_mobile},
    secChUaPlatform: {sec_ch_ua_platform}
  }}
}};
output.textContent = JSON.stringify(observation);
output.dataset.ready = 'true';
}})()</script>"#,
    )
}

fn request_header(request: &str, expected_name: &str) -> String {
    request
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case(expected_name))
        .map(|(_, value)| value.trim().to_owned())
        .unwrap_or_default()
}

fn json_script_string(value: &str) -> String {
    serde_json::to_string(value).expect("serialize bounded fixture header")
}

fn persona_probe_task(url: String) -> CollectionTask {
    let runtime_contract = TaskRuntimeContract::new(
        RuntimeSelector::Exact(RuntimeKind::Chrome),
        RuntimeRequirements::new(Vec::new(), false)
            .expect("valid persona probe runtime requirements"),
    )
    .expect("valid persona probe runtime contract");
    CollectionTask::new_with_runtime(
        vec![
            TaskStep::Navigate { url },
            TaskStep::ReadSelectorText {
                selector: "#persona-probe-output".to_owned(),
            },
        ],
        runtime_contract,
    )
    .expect("valid persona probe task")
}

async fn collect_persona_probe(
    client: &StationClient,
    profile_id: &str,
    profile_class: ProfileClass,
    persona: &BrowserPersona,
    url: String,
) -> ProbeTranscriptV1 {
    let result = client
        .run_task_with_identity(
            profile_id,
            profile_class,
            persona.clone(),
            persona_probe_task(url),
        )
        .await
        .expect("collect controlled-origin persona probe");
    let runtime = result
        .runtime()
        .expect("persona probe records resolved runtime");
    assert_eq!(runtime.kind(), RuntimeKind::Chrome);
    assert_eq!(result.replies().len(), 2);
    let TaskReply::Text(observation) = &result.replies()[1] else {
        panic!("persona probe did not return selector text");
    };
    ProbeTranscriptV1::from_observation(persona, runtime, observation)
        .expect("validate controlled-origin persona transcript")
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
async fn stationd_explicit_chrome_and_edge_runtime_selection_e2e() {
    let _serial = e2e_serial_guard().await;
    let fixture = FixtureServer::start();
    let stationd = env!("CARGO_BIN_EXE_dig2browser-stationd");

    for (runtime, expects_edge_brand) in [("chrome", false), ("edge", true)] {
        let runtime_kind = if expects_edge_brand {
            RuntimeKind::Edge
        } else {
            RuntimeKind::Chrome
        };
        let unique = uuid::Uuid::new_v4();
        let pipe_name = format!("dig2browser-stationd-{runtime}-e2e-{unique}");
        let profiles = e2e_temp_base().join(format!(
            "dig2browser-stationd-{runtime}-e2e-{unique}"
        ));
        std::fs::create_dir_all(&profiles).expect("create explicit-runtime profiles root");
        let mut daemon = spawn_stationd_for_runtime(
            stationd,
            &pipe_name,
            &profiles,
            runtime,
        );
        let daemon_pid = daemon.id().expect("explicit-runtime stationd PID");

        let client = StationClient::connect(
            ClientConfig::new(
                &pipe_name,
                Duration::from_secs(15),
                Duration::from_secs(90),
            )
            .expect("valid explicit-runtime client config"),
        )
        .await
        .expect("connect explicit-runtime station client");
        let marker = format!("explicit-{runtime}-runtime");
        let url = fixture.url(&format!("/{marker}"));
        let runtime_contract = TaskRuntimeContract::new(
            RuntimeSelector::Exact(runtime_kind),
            RuntimeRequirements::new(Vec::new(), false)
                .expect("valid evidence-only runtime requirements"),
        )
        .expect("valid explicit runtime contract");
        let task = CollectionTask::new_with_runtime(
            vec![
                TaskStep::Navigate { url: url.clone() },
                TaskStep::Evaluate {
                    script: "navigator.userAgent".to_owned(),
                },
                TaskStep::Capture {
                    policy: TaskCapturePolicy::EvidenceViewport,
                },
            ],
            runtime_contract,
        )
        .expect("valid explicit-runtime typed task");
        let result = client
            .run_task(&format!("explicit-{runtime}-profile"), task)
            .await
            .expect("run task through explicit browser runtime");

        let resolved = result
            .runtime()
            .expect("opt-in task returns resolved runtime evidence");
        assert_eq!(resolved.kind(), runtime_kind);
        assert_eq!(resolved.engine(), EngineFamily::Chromium);
        assert_eq!(resolved.control(), ControlTransport::Cdp);
        assert!(resolved.version().is_some_and(|version| !version.is_empty()));
        for feature in [
            RuntimeFeature::ScriptEvaluate,
            RuntimeFeature::Navigate,
            RuntimeFeature::CaptureState,
            RuntimeFeature::CaptureHtml,
            RuntimeFeature::CaptureViewportPng,
            RuntimeFeature::Lifecycle,
            RuntimeFeature::PersistentProfile,
            RuntimeFeature::DesktopWeb,
        ] {
            assert!(
                resolved.granted().iter().any(|support| {
                    support.feature() == feature
                        && support.level() == SupportLevel::Native
                }),
                "{runtime} did not record granted feature {feature:?}"
            );
        }
        assert_eq!(result.replies().len(), 3);
        let TaskReply::ScriptJson(user_agent_json) = &result.replies()[1] else {
            panic!("explicit {runtime} task did not return user agent JSON");
        };
        let user_agent = user_agent_json
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .expect("user agent is a JSON string");
        assert!(
            user_agent.contains("Chrome/"),
            "{runtime} user agent lacks Chromium brand: {user_agent}"
        );
        assert_eq!(
            user_agent.contains("Edg/"),
            expects_edge_brand,
            "{runtime} user agent did not match selected runtime: {user_agent}"
        );

        let TaskReply::Capture(capture) = &result.replies()[2] else {
            panic!("explicit {runtime} task did not return evidence capture");
        };
        assert_eq!(capture.requested_url, url);
        assert_eq!(capture.final_url, url);
        assert_eq!(capture.http_status, Some(200));
        assert_eq!(capture.title, marker);
        assert_eq!(capture.ready_state, "complete");
        assert!(
            String::from_utf8_lossy(&capture.html)
                .contains(&format!("data-daemon-e2e=\"{marker}\""))
        );
        assert_eq!(&capture.png[..8], b"\x89PNG\r\n\x1a\n");
        assert_eq!(
            capture.html_sha256,
            dig2browser::digest::sha256_bytes(&capture.html)
        );
        assert_eq!(
            capture.png_sha256,
            Some(dig2browser::digest::sha256_bytes(&capture.png))
        );

        let legacy_url = fixture.url(&format!("/legacy-{runtime}-runtime"));
        let legacy = client
            .run_task(
                &format!("explicit-{runtime}-profile"),
                CollectionTask::new(vec![
                    TaskStep::Navigate {
                        url: legacy_url.clone(),
                    },
                    TaskStep::Capture {
                        policy: TaskCapturePolicy::HtmlOnly,
                    },
                ])
                .expect("valid legacy typed task"),
            )
            .await
            .expect("legacy D2TK v1 remains supported");
        assert!(legacy.runtime().is_none());
        let TaskReply::Capture(legacy_capture) = &legacy.replies()[1] else {
            panic!("legacy {runtime} task did not return capture");
        };
        assert_eq!(legacy_capture.final_url, legacy_url);

        client
            .shutdown()
            .await
            .expect("request explicit-runtime station drain");
        let status = tokio::time::timeout(Duration::from_secs(30), daemon.wait())
            .await
            .expect("explicit-runtime station daemon exit timeout")
            .expect("wait for explicit-runtime station daemon");
        assert!(
            status.success(),
            "{runtime} station daemon {daemon_pid} failed: {status}"
        );
        assert_eq!(
            daemon.try_wait().expect("recheck station daemon exit"),
            Some(status),
            "{runtime} station daemon {daemon_pid} remained alive"
        );
        let (stdout, stderr) = read_child_output(&mut daemon).await;
        assert!(
            stderr.is_empty(),
            "clean {runtime} station wrote stderr: {stderr}"
        );
        assert!(stdout.contains("\"event\":\"station_exit\""));
        assert!(stdout.contains("\"outcome\":\"clean\""));
        assert!(stdout.contains("\"stop_reason\":\"remote_request\""));
        assert!(stdout.contains("\"drain_timed_out\":false"));
        remove_tree(&profiles).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires GECKODRIVER pointing to the reviewed geckodriver executable"]
async fn stationd_explicit_firefox_runtime_selection_e2e() {
    let _serial = e2e_serial_guard().await;
    let fixture = FixtureServer::start();
    let stationd = env!("CARGO_BIN_EXE_dig2browser-stationd");
    let geckodriver = std::env::var_os("GECKODRIVER")
        .map(PathBuf::from)
        .expect("GECKODRIVER is configured");
    assert!(geckodriver.is_file(), "GECKODRIVER is not a file");

    let unique = uuid::Uuid::new_v4();
    let pipe_name = format!("dig2browser-stationd-firefox-e2e-{unique}");
    let profiles = e2e_temp_base().join(format!(
        "dig2browser-stationd-firefox-e2e-{unique}"
    ));
    std::fs::create_dir_all(&profiles).expect("create Firefox profiles root");
    let mut daemon = spawn_stationd_for_firefox(
        stationd,
        &pipe_name,
        &profiles,
        &geckodriver,
    );

    let client = StationClient::connect(
        ClientConfig::new(
            &pipe_name,
            Duration::from_secs(15),
            Duration::from_secs(90),
        )
        .expect("valid Firefox client config"),
    )
    .await
    .expect("connect Firefox station client");
    let marker = "explicit-firefox-runtime";
    let url = fixture.url(&format!("/{marker}"));
    let runtime_contract = TaskRuntimeContract::new(
        RuntimeSelector::Exact(RuntimeKind::Firefox),
        RuntimeRequirements::new(Vec::new(), false)
            .expect("valid Firefox runtime requirements"),
    )
    .expect("valid Firefox runtime contract");
    let task = CollectionTask::new_with_runtime(
        vec![
            TaskStep::Navigate { url: url.clone() },
            TaskStep::Evaluate {
                script: "navigator.userAgent".to_owned(),
            },
            TaskStep::Capture {
                policy: TaskCapturePolicy::EvidenceViewport,
            },
        ],
        runtime_contract,
    )
    .expect("valid Firefox task");
    let result = client
        .run_task("explicit-firefox-profile", task)
        .await
        .expect("run task through Firefox runtime");

    let resolved = result.runtime().expect("Firefox runtime evidence");
    assert_eq!(resolved.kind(), RuntimeKind::Firefox);
    assert_eq!(resolved.engine(), EngineFamily::Gecko);
    assert_eq!(resolved.control(), ControlTransport::WebDriverBidi);
    for feature in [
        RuntimeFeature::ScriptEvaluate,
        RuntimeFeature::Navigate,
        RuntimeFeature::CaptureState,
        RuntimeFeature::CaptureHtml,
        RuntimeFeature::CaptureViewportPng,
        RuntimeFeature::Lifecycle,
        RuntimeFeature::PersistentProfile,
        RuntimeFeature::DesktopWeb,
    ] {
        assert!(
            resolved.granted().iter().any(|support| {
                support.feature() == feature
                    && support.level() == SupportLevel::Native
            }),
            "Firefox did not record granted feature {feature:?}"
        );
    }
    let TaskReply::ScriptJson(user_agent_json) = &result.replies()[1] else {
        panic!("Firefox task did not return user agent JSON");
    };
    assert!(user_agent_json.contains("Firefox/"));
    assert!(!user_agent_json.contains("Chrome/"));
    let TaskReply::Capture(capture) = &result.replies()[2] else {
        panic!("Firefox task did not return evidence capture");
    };
    assert_eq!(capture.requested_url, url);
    assert_eq!(capture.final_url, url);
    assert_eq!(capture.http_status, Some(200));
    assert_eq!(capture.title, marker);
    assert_eq!(&capture.png[..8], b"\x89PNG\r\n\x1a\n");

    client.shutdown().await.expect("request Firefox station drain");
    let status = tokio::time::timeout(Duration::from_secs(30), daemon.wait())
        .await
        .expect("Firefox station exit timeout")
        .expect("wait for Firefox station");
    assert!(status.success(), "Firefox station failed: {status}");
    let (_, stderr) = read_child_output(&mut daemon).await;
    assert!(stderr.is_empty(), "Firefox station wrote stderr: {stderr}");
    remove_tree(&profiles).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires installed Chrome"]
async fn stationd_chrome_product_matrix_cookie_auth_restart_e2e() {
    let _serial = e2e_serial_guard().await;
    run_stationd_browser_product_matrix("chrome", RuntimeKind::Chrome, None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires installed Edge"]
async fn stationd_edge_product_matrix_cookie_auth_restart_e2e() {
    let _serial = e2e_serial_guard().await;
    run_stationd_browser_product_matrix("edge", RuntimeKind::Edge, None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires GECKODRIVER and installed Firefox"]
async fn stationd_firefox_product_matrix_cookie_auth_restart_e2e() {
    let _serial = e2e_serial_guard().await;
    let geckodriver = std::env::var_os("GECKODRIVER")
        .map(PathBuf::from)
        .expect("GECKODRIVER is configured");
    assert!(geckodriver.is_file(), "GECKODRIVER is not a file");
    run_stationd_browser_product_matrix(
        "firefox",
        RuntimeKind::Firefox,
        Some(&geckodriver),
    )
    .await;
}

async fn run_stationd_browser_product_matrix(
    runtime: &str,
    runtime_kind: RuntimeKind,
    geckodriver: Option<&Path>,
) {
        let fixture = FixtureServer::start();
        let stationd = env!("CARGO_BIN_EXE_dig2browser-stationd");
        let unique = uuid::Uuid::new_v4();
        let pipe_name = format!("dig2browser-product-matrix-{runtime}-{unique}");
        let root = e2e_temp_base().join(format!(
            "dig2browser-product-matrix-{runtime}-{unique}"
        ));
        let profiles = root.join("profiles");
        let traces = root.join("traces");
        let crawls = root.join("crawls");
        for path in [&profiles, &traces, &crawls] {
            std::fs::create_dir_all(path).expect("create product matrix durable root");
        }
        let mut daemon = spawn_stationd_for_product_matrix(
            stationd,
            &pipe_name,
            &profiles,
            &traces,
            &crawls,
            runtime,
            geckodriver,
        );
        let client = StationClient::connect(
            ClientConfig::new(
                &pipe_name,
                Duration::from_secs(15),
                Duration::from_secs(90),
            )
            .expect("valid product matrix client config"),
        )
        .await
        .unwrap_or_else(|error| panic!("connect {runtime} product matrix: {error}"));

        let profile_a = format!("matrix-{runtime}-a");
        let set_url = fixture.url(&format!("/matrix-cookie-set-{runtime}"));
        let first = client
            .run_task(
                &profile_a,
                matrix_task(
                    runtime_kind,
                    vec![
                        TaskStep::Navigate {
                            url: set_url.clone(),
                        },
                        TaskStep::Evaluate {
                            script: "document.title".to_owned(),
                        },
                        TaskStep::Evaluate {
                            script: "performance.timeOrigin".to_owned(),
                        },
                        TaskStep::Capture {
                            policy: TaskCapturePolicy::EvidenceViewport,
                        },
                    ],
                ),
            )
            .await
            .unwrap_or_else(|error| panic!("{runtime} cookie seed task failed: {error}"));
        assert_eq!(
            first.runtime().expect("matrix runtime evidence").kind(),
            runtime_kind
        );
        assert_eq!(
            first.replies()[1],
            TaskReply::ScriptJson(format!("\"matrix-cookie-set-{runtime}\""))
        );
        let first_time_origin = script_json_number(&first.replies()[2]);
        let TaskReply::Capture(first_capture) = &first.replies()[3] else {
            panic!("{runtime} seed task did not capture evidence");
        };
        assert_eq!(first_capture.title, format!("matrix-cookie-set-{runtime}"));
        assert_eq!(&first_capture.png[..8], b"\x89PNG\r\n\x1a\n");
        tokio::time::sleep(Duration::from_secs(2)).await;

        let check_url = fixture.url("/matrix-cookie-check");
        let successor = client
            .run_task(
                &profile_a,
                matrix_task(
                    runtime_kind,
                    vec![
                        TaskStep::Navigate {
                            url: check_url.clone(),
                        },
                        TaskStep::Evaluate {
                            script: "performance.timeOrigin".to_owned(),
                        },
                        TaskStep::Capture {
                            policy: TaskCapturePolicy::EvidenceViewport,
                        },
                    ],
                ),
            )
            .await
            .unwrap_or_else(|error| panic!("{runtime} restart cookie task failed: {error}"));
        let successor_time_origin = script_json_number(&successor.replies()[1]);
        assert_ne!(
            first_time_origin, successor_time_origin,
            "{runtime} did not rotate the browser before the successor navigation"
        );
        let TaskReply::Capture(successor_capture) = &successor.replies()[2] else {
            panic!("{runtime} successor task did not capture evidence");
        };
        assert_eq!(
            successor_capture.title,
            format!("matrix-cookie-present-{runtime}")
        );

        let isolated = client
            .run_task(
                &format!("matrix-{runtime}-b"),
                matrix_task(
                    runtime_kind,
                    vec![
                        TaskStep::Navigate {
                            url: check_url.clone(),
                        },
                        TaskStep::Capture {
                            policy: TaskCapturePolicy::EvidenceViewport,
                        },
                    ],
                ),
            )
            .await
            .unwrap_or_else(|error| panic!("{runtime} isolation task failed: {error}"));
        let TaskReply::Capture(isolated_capture) = &isolated.replies()[1] else {
            panic!("{runtime} isolation task did not capture evidence");
        };
        assert_eq!(isolated_capture.title, "matrix-cookie-empty");

        let auth_profile = format!("matrix-{runtime}-auth");
        let persona = BrowserPersona::desktop_default();
        client
            .begin_auth_session(
                &auth_profile,
                persona.clone(),
                fixture.url("/auth-bootstrap"),
            )
            .await
            .unwrap_or_else(|error| panic!("{runtime} auth begin failed: {error}"));
        tokio::time::sleep(Duration::from_secs(2)).await;
        client
            .finish_auth_session(&auth_profile)
            .await
            .unwrap_or_else(|error| panic!("{runtime} auth finish failed: {error}"));
        tokio::time::sleep(Duration::from_secs(2)).await;
        let authenticated = client
            .run_task_with_identity(
                &auth_profile,
                ProfileClass::Authenticated,
                persona,
                matrix_task(
                    runtime_kind,
                    vec![
                        TaskStep::Navigate {
                            url: fixture.url("/auth-check"),
                        },
                        TaskStep::Evaluate {
                            script: "localStorage.getItem('dig2browser_auth_e2e')"
                                .to_owned(),
                        },
                        TaskStep::Evaluate {
                            script: "localStorage.getItem('dig2browser_auth_roundtrip')"
                                .to_owned(),
                        },
                        TaskStep::Capture {
                            policy: TaskCapturePolicy::EvidenceViewport,
                        },
                    ],
                ),
            )
            .await
            .unwrap_or_else(|error| panic!("{runtime} authenticated reuse failed: {error}"));
        assert_eq!(
            authenticated.replies()[1],
            TaskReply::ScriptJson("\"present\"".to_owned())
        );
        assert_eq!(
            authenticated.replies()[2],
            TaskReply::ScriptJson("\"ok\"".to_owned())
        );
        let TaskReply::Capture(auth_capture) = &authenticated.replies()[3] else {
            panic!("{runtime} authenticated task did not capture evidence");
        };
        assert_eq!(auth_capture.title, "auth-check-ok");
        assert!(!format!("{:?}", authenticated.replies()).contains("cookie-secret"));

        let crawl_url = fixture.url(&format!("/matrix-crawl-seed-{runtime}"));
        let crawl_page_2_url = fixture.url(&format!("/matrix-crawl-page-2-{runtime}"));
        let crawl_id = client
            .begin_crawl(
                &profile_a,
                CrawlSpec::new(
                    vec![crawl_url.clone()],
                    vec![fixture.origin()],
                    2,
                    1,
                    0,
                )
                .expect("valid product matrix crawl spec"),
            )
            .await
            .unwrap_or_else(|error| panic!("{runtime} crawl begin failed: {error}"));
        let crawl_events = wait_for_complete_product_crawl(&client, crawl_id).await;
        assert_eq!(
            client
                .crawl_status(crawl_id)
                .await
                .expect("read product matrix crawl status")
                .phase(),
            CrawlPhase::Succeeded,
        );
        let crawl_pages = crawl_events
            .iter()
            .filter(|event| event.kind() == CrawlEventKind::PageSucceeded)
            .collect::<Vec<_>>();
        assert_eq!(crawl_pages.len(), 2, "{runtime} crawl did not follow its link");
        assert_eq!(
            crawl_events
                .iter()
                .filter(|event| event.kind() == CrawlEventKind::JobSucceeded)
                .count(),
            1,
        );
        for (url, marker) in [
            (&crawl_url, format!("matrix-crawl-seed-{runtime}")),
            (&crawl_page_2_url, format!("matrix-crawl-page-2-{runtime}")),
        ] {
            let crawl_page = crawl_pages
                .iter()
                .find(|event| event.canonical_url() == Some(url.as_str()))
                .unwrap_or_else(|| panic!("{runtime} crawl omitted {url}"));
            assert_eq!(crawl_page.http_status(), Some(200));
            assert_eq!(crawl_page.attempt(), 1);
            let page = crawl_page
                .page()
                .expect("successful product matrix crawl page artifact");
            let html = read_complete_artifact(&client, page.collection_id(), page.html()).await;
            assert!(
                String::from_utf8_lossy(&html)
                    .contains(&format!("data-daemon-e2e=\"{marker}\"")),
                "{runtime} crawl artifact did not contain controlled fixture evidence",
            );
            let trace = wait_for_complete_trace(&client, page.collection_id()).await;
            let started = trace
                .iter()
                .find_map(|event| match event.kind() {
                    TraceEventKind::Started(started) => Some(started),
                    _ => None,
                })
                .expect("crawler collection trace includes runtime evidence");
            assert_eq!(started.runtime().kind(), runtime_kind);
        }

        client
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown {runtime} product matrix: {error}"));
        let status = tokio::time::timeout(Duration::from_secs(30), daemon.wait())
            .await
            .unwrap_or_else(|_| panic!("{runtime} product matrix exit timeout"))
            .expect("wait for product matrix station");
        assert!(status.success(), "{runtime} product matrix station failed: {status}");
        let (_, stderr) = read_child_output(&mut daemon).await;
        assert!(stderr.is_empty(), "{runtime} product matrix stderr: {stderr}");
        remove_tree(&root).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn in_process_station_chrome_auth_cookie_reuse_e2e() {
    let _serial = e2e_serial_guard().await;
    let fixture = FixtureServer::start();
    let unique = uuid::Uuid::new_v4();
    let profiles = e2e_temp_base().join(format!(
        "dig2browser-in-process-auth-e2e-{unique}"
    ));
    let profiles_owner = ProfilesRootOwnership::acquire(&profiles)
        .expect("own in-process auth profiles root");
    let config = StationConfig::new(profiles_owner.root(), 2, 2)
        .expect("valid in-process auth station config")
        .with_runtime_selector(RuntimeSelector::Exact(RuntimeKind::Chrome));
    let station = BrowserStation::new(config);
    let identity = StationIdentityRequest::authenticated_persona(
        "in-process-auth-profile",
        BrowserPersona::desktop_default(),
    );
    station
        .begin_auth_session(identity.clone(), fixture.url("/auth-bootstrap"))
        .await
        .expect("begin in-process auth session");
    tokio::time::sleep(Duration::from_secs(2)).await;
    station
        .finish_auth_session(identity.id())
        .await
        .expect("finish in-process auth session");
    tokio::time::sleep(Duration::from_secs(2)).await;
    let status = station
        .check_auth_session(
            identity,
            SessionHealthProbe {
                url: fixture.url("/auth-check"),
                ready_selector: "[data-daemon-e2e='auth-check-ok']".to_owned(),
                reauth_selector: "[data-daemon-e2e='auth-check-missing']".to_owned(),
                ready_ttl_seconds: 60,
            },
        )
        .await
        .expect("check in-process auth session");
    assert_eq!(status.phase, SessionPhase::Ready);
    station.shutdown().await.expect("shutdown in-process auth station");
    drop(profiles_owner);
    remove_tree(&profiles).await;
}

// Phase B.1c acceptance: a prepared session imported from cookie material is
// installed durably into the profile and transmitted by the browser on a later
// authenticated navigation — without any headful login. import_session restarts
// the browser internally (flush to disk + reload), so a passing check proves the
// cookie survived a disk round-trip, i.e. it is durable, not merely RAM-resident.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn in_process_station_chrome_session_import_reuse_e2e() {
    let _serial = e2e_serial_guard().await;
    let fixture = FixtureServer::start();
    let unique = uuid::Uuid::new_v4();
    let profiles = e2e_temp_base().join(format!(
        "dig2browser-in-process-import-e2e-{unique}"
    ));
    let profiles_owner = ProfilesRootOwnership::acquire(&profiles)
        .expect("own in-process import profiles root");
    let config = StationConfig::new(profiles_owner.root(), 2, 2)
        .expect("valid in-process import station config")
        .with_runtime_selector(RuntimeSelector::Exact(RuntimeKind::Chrome));
    let station = BrowserStation::new(config);
    let identity = StationIdentityRequest::authenticated_persona(
        "in-process-import-profile",
        BrowserPersona::desktop_default(),
    );

    // The prepared session: the same marker cookie the fixture's /auth-check
    // looks for, host-only for the fixture host (localhost). Built directly as a
    // CookieSpec — the portable file parser is unit-tested separately.
    let cookies = vec![dig2browser::agentic::CookieSpec {
        name: "dig2browser_auth_e2e".to_owned(),
        value: "cookie-secret".to_owned(),
        domain: "localhost".to_owned(),
        path: "/".to_owned(),
        secure: false,
        http_only: false,
        expires_unix: None,
    }];

    let imported = station
        .import_session(identity.clone(), cookies, 60)
        .await
        .expect("import prepared session");
    assert_eq!(imported, 1);

    // Reuse proof: the fixture only renders auth-check-ok when the request
    // carried the cookie, so a Ready phase means the imported cookie was both
    // installed and transmitted by the browser.
    let status = station
        .check_auth_session(
            identity,
            SessionHealthProbe {
                url: fixture.url("/auth-check"),
                ready_selector: "[data-daemon-e2e='auth-check-ok']".to_owned(),
                reauth_selector: "[data-daemon-e2e='auth-check-missing']".to_owned(),
                ready_ttl_seconds: 60,
            },
        )
        .await
        .expect("check imported session");
    assert_eq!(status.phase, SessionPhase::Ready);

    station.shutdown().await.expect("shutdown in-process import station");
    drop(profiles_owner);
    remove_tree(&profiles).await;
}

// P1.1 acceptance: an agent starts a live monitor over the pipe and reads a
// page's real WebSocket traffic — both directions, typed, with the endpoint
// url correlated — without hand-rolling any browser plumbing. This is the
// exact "consumer had to hand-write a WebSocket monitor" crutch the live
// capability exists to remove, proven against real Chrome and a real WS peer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stationd_live_websocket_capture_streams_typed_frames_e2e() {
    let _serial = e2e_serial_guard().await;
    let fixture = FixtureServer::start();
    let ws_fixture = WebSocketFixture::start().await;
    let unique = uuid::Uuid::new_v4();
    let pipe_name = format!("dig2browser-stationd-live-ws-e2e-{unique}");
    let profiles = e2e_temp_base().join(format!(
        "dig2browser-stationd-live-ws-e2e-{unique}"
    ));
    std::fs::create_dir_all(&profiles).expect("create live-ws profiles root");
    let stationd = env!("CARGO_BIN_EXE_dig2browser-stationd");
    let mut daemon = spawn_stationd_for_live_events(stationd, &pipe_name, &profiles);

    let client = StationClient::connect(
        ClientConfig::new(
            &pipe_name,
            Duration::from_secs(15),
            Duration::from_secs(90),
        )
        .expect("valid live-ws client config"),
    )
    .await
    .expect("connect live-ws station client");

    let page_url = fixture.url(&format!("/live-ws-page-{}", ws_fixture.port));
    // websocket_only: frame traffic without the full HTTP/XHR firehose.
    // A cold browser launch can occasionally fail the initial navigation
    // (RuntimeError::Navigation), surfaced as an Unavailable begin — the same
    // transient any station navigation can hit — so retry a few times here,
    // as a real client would.
    let mut session = None;
    for attempt in 0..8 {
        match client
            .begin_live_capture(
                "live-ws-profile",
                LiveTarget::Navigate {
                    url: page_url.clone(),
                },
                LiveFilter::new(true, true, false),
            )
            .await
        {
            Ok(id) => {
                session = Some(id);
                break;
            }
            Err(ClientError::Remote {
                status: ResponseStatus::Unavailable,
                ..
            }) if attempt < 7 => {
                tokio::time::sleep(Duration::from_millis(400)).await;
            }
            Err(error) => panic!("begin live websocket capture: {error:?}"),
        }
    }
    let session = session.expect("begin live websocket capture after retries");

    // Drain the cursored feed until both frame directions are observed.
    let mut cursor = LiveCursor::START;
    let mut received_frame: Option<(WebSocketOpcode, Vec<u8>, Option<String>)> = None;
    let mut sent_frame: Option<(WebSocketOpcode, Vec<u8>)> = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while tokio::time::Instant::now() < deadline
        && (received_frame.is_none() || sent_frame.is_none())
    {
        let page = client
            .read_live_events(session, cursor, 64)
            .await
            .expect("read live events");
        assert!(
            page.is_active(),
            "live session ended before both frames were captured"
        );
        for event in page.events() {
            if let LiveEventKind::WebSocketFrame(frame) = event.kind() {
                match frame.direction() {
                    WebSocketDirection::Received => {
                        received_frame.get_or_insert_with(|| {
                            (
                                frame.opcode(),
                                frame.payload().to_vec(),
                                frame.url().map(str::to_owned),
                            )
                        });
                    }
                    WebSocketDirection::Sent => {
                        sent_frame.get_or_insert_with(|| {
                            (frame.opcode(), frame.payload().to_vec())
                        });
                    }
                }
            }
        }
        cursor = page.next_cursor();
        if received_frame.is_none() || sent_frame.is_none() {
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
    }

    let (recv_opcode, recv_payload, recv_url) =
        received_frame.expect("server->page WebSocket frame captured over the pipe");
    assert_eq!(recv_opcode, WebSocketOpcode::Text);
    assert!(
        String::from_utf8_lossy(&recv_payload).contains("\"tick\""),
        "unexpected received payload: {}",
        String::from_utf8_lossy(&recv_payload)
    );
    // The url backfill (via webSocketCreated's top-level url) resolves the
    // frame endpoint even though CDP omits the url on the frame events.
    let recv_url = recv_url.expect("received frame carries the correlated ws endpoint url");
    assert!(
        recv_url.contains(&format!("localhost:{}", ws_fixture.port)),
        "unexpected frame endpoint url: {recv_url}"
    );

    let (sent_opcode, sent_payload) =
        sent_frame.expect("page->server WebSocket frame captured over the pipe");
    assert_eq!(sent_opcode, WebSocketOpcode::Text);
    assert_eq!(sent_payload, b"hello-from-page");

    client
        .stop_live_capture(session)
        .await
        .expect("stop live capture");
    // After Stop the session is removed, so a further Read is rejected.
    assert!(client.read_live_events(session, cursor, 64).await.is_err());

    client.shutdown().await.expect("request live-ws station drain");
    let status = tokio::time::timeout(Duration::from_secs(30), daemon.wait())
        .await
        .expect("live-ws station daemon exit timeout")
        .expect("wait for live-ws station daemon");
    assert!(status.success(), "live-ws station daemon failed: {status}");
    let (_, stderr) = read_child_output(&mut daemon).await;
    assert!(stderr.is_empty(), "clean live-ws station wrote stderr: {stderr}");
    drop(ws_fixture);
    remove_tree(&profiles).await;
}

// P1.2 Part B slice 6 acceptance: a durable monitor's captured WebSocket frames
// survive a station restart. Station A begins a durable monitor and captures real
// frames (payloads to the CAS, metadata to the journal, fsync per frame), then is
// abandoned (the crash end state: locks released, journal non-terminal). A fresh
// Station B reconciles the crash-left-open journal, replays the durable records
// from a cursor, and reads the frame payloads back from the CAS byte-exact — the
// durability the live RAM ring cannot provide.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn durable_monitor_survives_station_restart_and_resumes_e2e() {
    let _serial = e2e_serial_guard().await;
    let fixture = FixtureServer::start();
    let ws_fixture = WebSocketFixture::start().await;
    let unique = uuid::Uuid::new_v4();
    let base = e2e_temp_base().join(format!("dig2browser-durable-monitor-e2e-{unique}"));
    let profiles = base.join("profiles");
    let monitor_root = base.join("monitors");
    std::fs::create_dir_all(&monitor_root).expect("create monitor root");
    let profiles_owner =
        ProfilesRootOwnership::acquire(&profiles).expect("own durable-monitor profiles root");
    let config = StationConfig::new(profiles_owner.root(), 2, 2)
        .expect("valid durable-monitor station config")
        .with_runtime_selector(RuntimeSelector::Exact(RuntimeKind::Chrome));
    let page_url = fixture.url(&format!("/live-ws-page-{}", ws_fixture.port));
    let persona = BrowserPersona::desktop_default();

    // --- Station A: begin a durable monitor and capture frames in both directions ---
    let monitor_id = {
        let station = BrowserStation::new(config.clone());
        let manager =
            DurableMonitorManager::open(station, &monitor_root).expect("open durable manager A");

        // A cold browser launch can transiently fail the initial navigation; retry
        // begin a few times, as a real caller would.
        let mut monitor_id = None;
        for attempt in 0..8 {
            match manager
                .begin(
                    "durable-monitor-profile",
                    ProfileClass::Public,
                    persona.clone(),
                    page_url.clone(),
                    LiveFilter::new(true, true, false),
                )
                .await
            {
                Ok(id) => {
                    monitor_id = Some(id);
                    break;
                }
                Err(_) if attempt < 7 => {
                    tokio::time::sleep(Duration::from_millis(400)).await;
                }
                Err(error) => panic!("begin durable monitor: {error:?}"),
            }
        }
        let monitor_id = monitor_id.expect("begin durable monitor after retries");

        // Wait until both a Received (server push) and a Sent (page send) frame
        // have been captured durably.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        let mut saw_received = false;
        let mut saw_sent = false;
        while tokio::time::Instant::now() < deadline && !(saw_received && saw_sent) {
            let records = manager
                .read(&monitor_id, MonitorCursor::START, 64)
                .expect("read resident durable monitor");
            for frame in frame_records(&records) {
                match frame.direction() {
                    WebSocketDirection::Received => saw_received = true,
                    WebSocketDirection::Sent => saw_sent = true,
                }
            }
            if !(saw_received && saw_sent) {
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        }
        assert!(
            saw_received && saw_sent,
            "durable monitor did not capture both frame directions before restart"
        );

        // Simulate a crash: release the monitor without a clean stop (journal left
        // non-terminal, locks released), then drop the manager + station.
        manager
            .abandon(Duration::from_secs(5))
            .await
            .expect("abandon durable monitor");
        drop(manager);
        monitor_id
    };

    // --- Station B (restart): reconcile + resume from the durable journal + CAS ---
    let station_b = BrowserStation::new(config.clone());
    let manager_b =
        DurableMonitorManager::open(station_b, &monitor_root).expect("open durable manager B");

    // The crash-left-open journal was reconciled on open — it is now terminal.
    assert!(
        manager_b
            .is_terminal(&monitor_id)
            .expect("query terminal after restart"),
        "durable monitor journal was not reconciled on restart"
    );

    let records = manager_b
        .read(&monitor_id, MonitorCursor::START, 64)
        .expect("read durable monitor after restart");
    assert!(records[0].is_start(), "first record is not Started");
    assert!(
        matches!(
            records.last().map(MonitorEvent::kind),
            Some(MonitorEventKind::Stopped(MonitorStopReason::Interrupted(
                InterruptedReason::SuccessorReconciliation
            )))
        ),
        "last record is not the reconciliation Stopped"
    );

    let frames = frame_records(&records);
    assert!(!frames.is_empty(), "no durable frames survived the restart");

    // Read frame payloads back from the CAS byte-exact — the durability proof.
    let received = frames
        .iter()
        .find(|frame| frame.direction() == WebSocketDirection::Received)
        .expect("a received frame survived");
    let received_payload = manager_b
        .frame_payload(received)
        .expect("received payload from CAS");
    assert!(
        String::from_utf8_lossy(&received_payload).contains("\"tick\""),
        "unexpected durable received payload: {}",
        String::from_utf8_lossy(&received_payload)
    );
    let sent = frames
        .iter()
        .find(|frame| frame.direction() == WebSocketDirection::Sent)
        .expect("a sent frame survived");
    assert_eq!(
        manager_b.frame_payload(sent).expect("sent payload from CAS"),
        b"hello-from-page"
    );

    // Resume from a cursor: reading after the first frame's cursor omits it.
    let first_frame_cursor = records
        .iter()
        .find(|event| matches!(event.kind(), MonitorEventKind::FrameCommitted(_)))
        .map(MonitorEvent::cursor)
        .expect("a frame cursor");
    let tail = manager_b
        .read(&monitor_id, first_frame_cursor, 64)
        .expect("cursored read after restart");
    assert!(
        tail.iter().all(|event| event.cursor().value() > first_frame_cursor.value()),
        "cursored read returned records at or before the cursor"
    );

    drop(manager_b);
    drop(ws_fixture);
    drop(profiles_owner);
    remove_tree(&base).await;
}

fn frame_records(records: &[MonitorEvent]) -> Vec<&MonitorFrame> {
    records
        .iter()
        .filter_map(|event| match event.kind() {
            MonitorEventKind::FrameCommitted(frame) => Some(frame),
            _ => None,
        })
        .collect()
}

// P1.2 Part B slice 4 acceptance: the durable-monitor IPC wire family, driven by
// a real out-of-process client through the named pipe. Begin a durable monitor,
// page its records, read a frame payload back from the CAS, and stop — all over
// D2MQ/D2MP — proving the codec + dispatch + `--allow-durable-*` gates end to end.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stationd_durable_monitor_wire_e2e() {
    let _serial = e2e_serial_guard().await;
    let fixture = FixtureServer::start();
    let ws_fixture = WebSocketFixture::start().await;
    let unique = uuid::Uuid::new_v4();
    let pipe_name = format!("dig2browser-stationd-durable-wire-e2e-{unique}");
    let base = e2e_temp_base().join(format!("dig2browser-stationd-durable-wire-e2e-{unique}"));
    let profiles = base.join("profiles");
    let monitor_root = base.join("monitors");
    std::fs::create_dir_all(&profiles).expect("create durable-wire profiles");
    std::fs::create_dir_all(&monitor_root).expect("create durable-wire monitor root");
    let stationd = env!("CARGO_BIN_EXE_dig2browser-stationd");
    let mut daemon =
        spawn_stationd_for_durable_monitor(stationd, &pipe_name, &profiles, &monitor_root);

    let client = StationClient::connect(
        ClientConfig::new(&pipe_name, Duration::from_secs(15), Duration::from_secs(90))
            .expect("valid durable-wire client config"),
    )
    .await
    .expect("connect durable-wire station client");

    let page_url = fixture.url(&format!("/live-ws-page-{}", ws_fixture.port));
    let mut monitor_id = None;
    for attempt in 0..8 {
        match client
            .begin_durable_monitor(
                "durable-wire-profile",
                ProfileClass::Public,
                BrowserPersona::desktop_default(),
                page_url.clone(),
                LiveFilter::new(true, true, false),
            )
            .await
        {
            Ok(id) => {
                monitor_id = Some(id);
                break;
            }
            Err(ClientError::Remote {
                status: ResponseStatus::Unavailable,
                ..
            }) if attempt < 7 => {
                tokio::time::sleep(Duration::from_millis(400)).await;
            }
            Err(error) => panic!("begin durable monitor over wire: {error:?}"),
        }
    }
    let monitor_id = monitor_id.expect("begin durable monitor over wire after retries");

    // Page records until both directions are captured; keep a received frame's ref.
    let mut received_artifact = None;
    let mut saw_sent = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while tokio::time::Instant::now() < deadline && (received_artifact.is_none() || !saw_sent) {
        let page = client
            .read_durable_monitor(&monitor_id, MonitorCursor::START, 64)
            .await
            .expect("read durable monitor over wire");
        for frame in frame_records(page.events()) {
            match frame.direction() {
                WebSocketDirection::Received => {
                    if received_artifact.is_none() {
                        received_artifact = frame.artifact().cloned();
                    }
                }
                WebSocketDirection::Sent => saw_sent = true,
            }
        }
        if received_artifact.is_none() || !saw_sent {
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
    }
    let received_artifact =
        received_artifact.expect("a received frame with a CAS reference over the wire");
    assert!(saw_sent, "page-send frame not captured over the wire");

    // Fetch the frame payload back from the CAS over the wire.
    let payload = client
        .read_durable_frame(&monitor_id, received_artifact)
        .await
        .expect("read durable frame payload over wire");
    assert!(
        String::from_utf8_lossy(&payload).contains("\"tick\""),
        "unexpected durable frame payload over wire: {}",
        String::from_utf8_lossy(&payload)
    );

    // Stop over the wire; a subsequent read shows the terminal page.
    client
        .stop_durable_monitor(&monitor_id)
        .await
        .expect("stop durable monitor over wire");
    let after = client
        .read_durable_monitor(&monitor_id, MonitorCursor::START, 64)
        .await
        .expect("read stopped durable monitor over wire");
    assert!(after.is_terminal(), "monitor not terminal after stop");
    assert!(
        matches!(
            after.events().last().map(MonitorEvent::kind),
            Some(MonitorEventKind::Stopped(MonitorStopReason::Requested))
        ),
        "last record after stop is not Stopped(Requested)"
    );

    client.shutdown().await.expect("request durable-wire station drain");
    let status = tokio::time::timeout(Duration::from_secs(30), daemon.wait())
        .await
        .expect("durable-wire station exit timeout")
        .expect("wait for durable-wire station");
    assert!(status.success(), "durable-wire station failed: {status}");
    let (_, stderr) = read_child_output(&mut daemon).await;
    assert!(stderr.is_empty(), "clean durable-wire station wrote stderr: {stderr}");
    drop(ws_fixture);
    remove_tree(&base).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stationd_compiles_personas_binds_routes_and_validates_probe_e2e() {
    let _serial = e2e_serial_guard().await;
    let fixture = FixtureServer::start();
    let unique = uuid::Uuid::new_v4();
    let pipe_name = format!("dig2browser-stationd-persona-probe-e2e-{unique}");
    let profiles = e2e_temp_base().join(format!(
        "dig2browser-stationd-persona-probe-e2e-{unique}"
    ));
    std::fs::create_dir_all(&profiles).expect("create persona probe profiles root");
    let stationd = env!("CARGO_BIN_EXE_dig2browser-stationd");
    let client_config = ClientConfig::new(
        &pipe_name,
        Duration::from_secs(15),
        Duration::from_secs(90),
    )
    .expect("valid persona probe client config");
    let direct_route = RouteRef::new("host.direct").expect("valid direct route");
    let alternate_route =
        RouteRef::new("host.direct-alt").expect("valid alternate direct route");
    let desktop = BrowserPersona::compiled(
        PersonaPreset::ChromeWindowsDesktopV1,
        direct_route.clone(),
    )
    .expect("compile desktop persona");
    let mobile = BrowserPersona::compiled(
        PersonaPreset::ChromeAndroidPixel7MobileWebV1,
        direct_route,
    )
    .expect("compile mobile persona");

    let mut daemon = spawn_stationd_for_runtime_with_routes(
        stationd,
        &pipe_name,
        &profiles,
        "chrome",
        &["host.direct", "host.direct-alt"],
        true,
    );
    let client = StationClient::connect(client_config.clone())
        .await
        .expect("connect persona probe client");
    let first_desktop = collect_persona_probe(
        &client,
        "compiled-desktop-profile",
        ProfileClass::Authenticated,
        &desktop,
        fixture.url("/persona-probe"),
    )
    .await;
    let first_desktop_hash = first_desktop.sha256();
    assert_ne!(first_desktop_hash, [0_u8; 32]);
    let first_mobile = collect_persona_probe(
        &client,
        "compiled-mobile-profile",
        ProfileClass::Public,
        &mobile,
        fixture.url("/persona-probe"),
    )
    .await;
    assert_ne!(first_mobile.sha256(), [0_u8; 32]);
    assert!(first_mobile.observation().browser.ua_mobile);

    let ready_expiry = unix_time_ms().saturating_add(60_000);
    client
        .update_identity_state(
            "compiled-desktop-profile",
            SessionStateUpdate {
                phase: SessionPhase::Ready,
                expires_at_unix_ms: Some(ready_expiry),
            },
        )
        .await
        .expect("mark compiled authenticated profile ready");
    client.shutdown().await.expect("shutdown first persona probe station");
    let first_exit = tokio::time::timeout(Duration::from_secs(30), daemon.wait())
        .await
        .expect("first persona probe daemon exit timeout")
        .expect("wait for first persona probe daemon");
    assert!(first_exit.success(), "first persona probe daemon failed: {first_exit}");
    let (_, first_stderr) = read_child_output(&mut daemon).await;
    assert!(first_stderr.is_empty(), "persona probe daemon wrote stderr: {first_stderr}");

    let desktop_profile = profiles.join("compiled-desktop-profile");
    let binding_path = desktop_profile.join(".dig2browser-profile-binding-v2");
    let binding = std::fs::read_to_string(&binding_path)
        .expect("read compiled profile binding");
    assert!(binding.contains("preset=chrome-windows-desktop-v1"));
    assert!(binding.contains("runtime=Chrome"));
    assert!(binding.contains("route=11:host.direct"));
    assert!(!binding.contains("Mozilla/"));
    assert!(!binding.contains(&fixture.url("/persona-probe")));

    let mut successor = spawn_stationd_for_runtime_with_routes(
        stationd,
        &pipe_name,
        &profiles,
        "chrome",
        &["host.direct", "host.direct-alt"],
        true,
    );
    let successor_client = StationClient::connect(client_config.clone())
        .await
        .expect("connect persona probe successor");
    let alternate_persona = BrowserPersona::compiled(
        PersonaPreset::ChromeWindowsDesktopV1,
        alternate_route,
    )
    .expect("compile alternate-route persona");
    let alternate_task = persona_probe_task(fixture.url("/persona-probe"));
    assert!(matches!(
        successor_client
            .run_task_with_identity(
                "compiled-desktop-profile",
                ProfileClass::Authenticated,
                alternate_persona,
                alternate_task,
            )
            .await,
        Err(ClientError::Remote {
            status: ResponseStatus::Invalid,
            ..
        })
    ));
    assert_eq!(
        std::fs::read_to_string(&binding_path).expect("reread immutable binding"),
        binding,
    );

    let edge_persona = BrowserPersona::compiled(
        PersonaPreset::EdgeWindowsDesktopV1,
        RouteRef::new("host.direct").expect("valid direct route"),
    )
    .expect("compile incompatible Edge persona");
    assert!(matches!(
        successor_client
            .run_task_with_persona(
                "compiled-edge-rejected-profile",
                edge_persona,
                persona_probe_task(fixture.url("/persona-probe")),
            )
            .await,
        Err(ClientError::Remote {
            status: ResponseStatus::Unsupported,
            ..
        })
    ));
    assert!(!profiles.join("compiled-edge-rejected-profile").exists());

    let second_desktop = collect_persona_probe(
        &successor_client,
        "compiled-desktop-profile",
        ProfileClass::Authenticated,
        &desktop,
        fixture.url("/persona-probe"),
    )
    .await;
    assert_eq!(second_desktop.sha256(), first_desktop_hash);
    let persisted = successor_client
        .identity_status("compiled-desktop-profile")
        .await
        .expect("read compiled identity state after restart");
    assert_eq!(persisted.phase, SessionPhase::Ready);
    assert_eq!(persisted.expires_at_unix_ms, Some(ready_expiry));
    successor_client
        .shutdown()
        .await
        .expect("shutdown persona probe successor");
    let successor_exit = tokio::time::timeout(Duration::from_secs(30), successor.wait())
        .await
        .expect("persona probe successor exit timeout")
        .expect("wait for persona probe successor");
    assert!(successor_exit.success(), "persona probe successor failed: {successor_exit}");
    let (_, successor_stderr) = read_child_output(&mut successor).await;
    assert!(
        successor_stderr.is_empty(),
        "persona probe successor wrote stderr: {successor_stderr}"
    );

    std::fs::remove_file(&binding_path).expect("remove binding to exercise fail-closed status");
    let mut corrupt = spawn_stationd_for_runtime_with_routes(
        stationd,
        &pipe_name,
        &profiles,
        "chrome",
        &["host.direct", "host.direct-alt"],
        true,
    );
    let corrupt_client = StationClient::connect(client_config)
        .await
        .expect("connect corrupt-binding station");
    assert!(matches!(
        corrupt_client.identity_status("compiled-desktop-profile").await,
        Err(ClientError::Remote {
            status: ResponseStatus::Protocol,
            ..
        })
    ));
    assert!(matches!(
        corrupt_client
            .update_identity_state(
                "compiled-desktop-profile",
                SessionStateUpdate {
                    phase: SessionPhase::ReauthRequired,
                    expires_at_unix_ms: None,
                },
            )
            .await,
        Err(ClientError::Remote {
            status: ResponseStatus::Protocol,
            ..
        })
    ));
    corrupt_client
        .shutdown()
        .await
        .expect("shutdown corrupt-binding station");
    let corrupt_exit = tokio::time::timeout(Duration::from_secs(30), corrupt.wait())
        .await
        .expect("corrupt-binding daemon exit timeout")
        .expect("wait for corrupt-binding daemon");
    assert!(corrupt_exit.success(), "corrupt-binding daemon failed: {corrupt_exit}");
    let (_, corrupt_stderr) = read_child_output(&mut corrupt).await;
    assert!(corrupt_stderr.is_empty(), "corrupt-binding daemon wrote stderr: {corrupt_stderr}");
    remove_tree(&profiles).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stationd_rejects_native_mobile_before_profile_or_runtime_spawn_e2e() {
    let _serial = e2e_serial_guard().await;
    let unique = uuid::Uuid::new_v4();
    let pipe_name = format!("dig2browser-stationd-runtime-reject-e2e-{unique}");
    let profiles = e2e_temp_base().join(format!(
        "dig2browser-stationd-runtime-reject-e2e-{unique}"
    ));
    std::fs::create_dir_all(&profiles).expect("create runtime-reject profiles root");
    let stationd = env!("CARGO_BIN_EXE_dig2browser-stationd");
    let mut daemon = spawn_stationd_for_runtime(
        stationd,
        &pipe_name,
        &profiles,
        "chrome",
    );
    let client = StationClient::connect(
        ClientConfig::new(
            &pipe_name,
            Duration::from_secs(15),
            Duration::from_secs(30),
        )
        .expect("valid runtime-reject client config"),
    )
    .await
    .expect("connect runtime-reject station client");
    let profile_id = "native-mobile-rejected";
    let contract = TaskRuntimeContract::new(
        RuntimeSelector::Exact(RuntimeKind::Chrome),
        RuntimeRequirements::new(
            vec![RuntimeFeature::NativeMobileDevice],
            false,
        )
        .expect("valid unsupported runtime requirement"),
    )
    .expect("valid runtime-reject contract");
    let task = CollectionTask::new_with_runtime(
        vec![TaskStep::Wait {
            duration: Duration::from_millis(1),
        }],
        contract,
    )
    .expect("valid runtime-reject task");

    let error = client
        .run_task(profile_id, task)
        .await
        .expect_err("native mobile must fail closed on Chrome");
    match error {
        ClientError::Remote { status, message } => {
            assert_eq!(status, ResponseStatus::Unsupported);
            assert_eq!(message, "runtime contract unsupported");
        }
        other => panic!("unexpected runtime rejection: {other}"),
    }
    assert!(
        !profiles.join(profile_id).exists(),
        "runtime rejection created a profile"
    );
    let status = client.status().await.expect("read runtime-reject status");
    assert_eq!(status.resident_identities, 0);
    assert_eq!(status.active_leases, 0);

    client
        .shutdown()
        .await
        .expect("shutdown runtime-reject station");
    let status = tokio::time::timeout(Duration::from_secs(30), daemon.wait())
        .await
        .expect("runtime-reject station exit timeout")
        .expect("wait for runtime-reject station");
    assert!(status.success(), "runtime-reject station failed: {status}");
    let (stdout, stderr) = read_child_output(&mut daemon).await;
    assert!(stderr.is_empty(), "runtime-reject station wrote stderr: {stderr}");
    assert!(stdout.contains("\"outcome\":\"clean\""));
    assert!(stdout.contains("\"stopped_workers\":0"));
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
    assert!(matches!(
        client
            .update_identity_state(
                "restricted-profile",
                SessionStateUpdate {
                    phase: SessionPhase::ReauthRequired,
                    expires_at_unix_ms: None,
                },
            )
            .await,
        Err(ClientError::Remote {
            status: ResponseStatus::Invalid,
            ..
        })
    ));
    assert!(matches!(
        client.identity_status("restricted-profile").await,
        Err(ClientError::Remote {
            status: ResponseStatus::Invalid,
            ..
        })
    ));
    assert!(matches!(
        client
            .begin_auth_session(
                "restricted-auth-profile",
                BrowserPersona::desktop_default(),
                fixture.url("/restricted-auth"),
            )
            .await,
        Err(ClientError::Remote {
            status: ResponseStatus::Invalid,
            ..
        })
    ));
    assert!(matches!(
        client
            .check_auth_session(
                "restricted-auth-profile",
                BrowserPersona::desktop_default(),
                SessionHealthProbe {
                    url: fixture.url("/restricted-health"),
                    ready_selector: "[data-session-ready]".to_owned(),
                    reauth_selector: "[data-session-reauth]".to_owned(),
                    ready_ttl_seconds: 60,
                },
            )
            .await,
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
async fn stationd_headful_auth_reuses_profile_without_exporting_secrets_e2e() {
    let _serial = e2e_serial_guard().await;
    let fixture = FixtureServer::start();
    let unique = uuid::Uuid::new_v4();
    let pipe_name = format!("dig2browser-stationd-auth-e2e-{unique}");
    let profiles = e2e_temp_base().join(format!(
        "dig2browser-stationd-auth-e2e-{unique}"
    ));
    std::fs::create_dir_all(&profiles).expect("create headful auth E2E profiles root");
    let stationd = env!("CARGO_BIN_EXE_dig2browser-stationd");
    let auth_cli = env!("CARGO_BIN_EXE_dig2browser-auth");
    let mut daemon = spawn_stationd_with_runtime_permissions(
        stationd,
        &pipe_name,
        &profiles,
        Some("chrome"),
        true,
        true,
        true,
    );
    let client = StationClient::connect(
        ClientConfig::new(
            &pipe_name,
            Duration::from_secs(15),
            Duration::from_secs(90),
        )
        .expect("valid headful auth client config"),
    )
    .await
    .expect("connect headful auth client");
    let profile_id = "headful-auth-profile";
    let persona = BrowserPersona::desktop_default();

    let auth_url = fixture.url("/auth-bootstrap");
    let begin = run_auth_cli(
        auth_cli,
        &pipe_name,
        &["begin", "--profile-id", profile_id, "--url", &auth_url],
    )
    .await;
    assert!(begin.status.success(), "auth CLI begin failed: {begin:?}");
    assert!(String::from_utf8_lossy(&begin.stdout).contains("\"state\":\"open\""));
    let during = client.status().await.expect("read auth session status");
    assert_eq!(during.resident_identities, 1);
    assert_eq!(during.ready_workers, 1);
    let reauth = client
        .identity_status(profile_id)
        .await
        .expect("read session state after auth start");
    assert_eq!(reauth.phase, SessionPhase::ReauthRequired);
    assert_eq!(reauth.profile_class, Some(ProfileClass::Authenticated));

    let busy_task = CollectionTask::new(vec![TaskStep::Navigate {
        url: fixture.url("/auth-busy"),
    }])
    .expect("valid busy task");
    assert!(matches!(
        client
            .run_task_with_identity(
                profile_id,
                ProfileClass::Authenticated,
                persona.clone(),
                busy_task,
            )
            .await,
        Err(ClientError::Remote {
            status: ResponseStatus::Unavailable,
            ..
        })
    ));
    assert!(matches!(
        client
            .begin_auth_session(
                profile_id,
                persona.clone(),
                fixture.url("/auth-duplicate"),
            )
            .await,
        Err(ClientError::Remote {
            status: ResponseStatus::Unavailable,
            ..
        })
    ));

    tokio::time::sleep(Duration::from_secs(2)).await;

    let finish = run_auth_cli(
        auth_cli,
        &pipe_name,
        &["finish", "--profile-id", profile_id],
    )
    .await;
    assert!(finish.status.success(), "auth CLI finish failed: {finish:?}");
    assert!(String::from_utf8_lossy(&finish.stdout).contains("\"state\":\"closed\""));
    assert!(matches!(
        client.finish_auth_session(profile_id).await,
        Err(ClientError::Remote {
            status: ResponseStatus::Invalid,
            ..
        })
    ));

    let verification = CollectionTask::new(vec![
        TaskStep::Navigate {
            url: fixture.url("/auth-check"),
        },
        TaskStep::Evaluate {
            script: "localStorage.getItem('dig2browser_auth_e2e')".to_owned(),
        },
        TaskStep::Capture {
            policy: TaskCapturePolicy::EvidenceViewport,
        },
    ])
    .expect("valid post-auth verification task");
    let result = client
        .run_task_with_identity(
            profile_id,
            ProfileClass::Authenticated,
            persona,
            verification,
        )
        .await
        .expect("reuse authenticated profile in headless worker");
    assert_eq!(
        result.replies()[1],
        TaskReply::ScriptJson("\"present\"".to_owned())
    );
    let TaskReply::Capture(capture) = &result.replies()[2] else {
        panic!("post-auth task did not return evidence capture");
    };
    assert_eq!(capture.requested_url, fixture.url("/auth-check"));
    assert_eq!(capture.final_url, fixture.url("/auth-check"));
    assert_eq!(capture.title, "auth-check-ok");
    assert!(!format!("{:?}", result.replies()).contains("cookie-secret"));

    let ready_url = fixture.url("/session-ready");
    let health_ready = run_auth_cli(
        auth_cli,
        &pipe_name,
        &[
            "check",
            "--profile-id",
            profile_id,
            "--url",
            &ready_url,
            "--ready-selector",
            "[data-session-ready]",
            "--reauth-selector",
            "[data-session-reauth]",
            "--ready-ttl-seconds",
            "60",
        ],
    )
    .await;
    assert!(health_ready.status.success(), "ready probe failed: {health_ready:?}");
    assert!(String::from_utf8_lossy(&health_ready.stdout).contains("\"phase\":\"ready\""));
    let ready_status = client
        .identity_status(profile_id)
        .await
        .expect("read health-ready state");
    assert_eq!(ready_status.phase, SessionPhase::Ready);
    assert!(ready_status.expires_at_unix_ms.is_some());

    let reauth_url = fixture.url("/session-reauth");
    let health_reauth = run_auth_cli(
        auth_cli,
        &pipe_name,
        &[
            "check",
            "--profile-id",
            profile_id,
            "--url",
            &reauth_url,
            "--ready-selector",
            "[data-session-ready]",
            "--reauth-selector",
            "[data-session-reauth]",
            "--ready-ttl-seconds",
            "60",
        ],
    )
    .await;
    assert!(health_reauth.status.success(), "reauth probe failed: {health_reauth:?}");
    assert!(String::from_utf8_lossy(&health_reauth.stdout)
        .contains("\"phase\":\"reauth_required\""));
    let reauth_status = client
        .identity_status(profile_id)
        .await
        .expect("read health-reauth state");
    assert_eq!(reauth_status.phase, SessionPhase::ReauthRequired);
    assert_eq!(reauth_status.expires_at_unix_ms, None);

    let ready_command = run_auth_cli(
        auth_cli,
        &pipe_name,
        &["ready", "--profile-id", profile_id, "--ttl-seconds", "60"],
    )
    .await;
    assert!(
        ready_command.status.success(),
        "auth CLI ready failed: {ready_command:?}"
    );
    let ready = client
        .identity_status(profile_id)
        .await
        .expect("read ready state after operator confirmation");
    assert_eq!(ready.phase, SessionPhase::Ready);
    assert!(ready.expires_at_unix_ms.is_some_and(|expiry| expiry > unix_time_ms()));
    let status_command = run_auth_cli(
        auth_cli,
        &pipe_name,
        &["status", "--profile-id", profile_id],
    )
    .await;
    assert!(status_command.status.success(), "auth CLI status failed: {status_command:?}");
    assert!(String::from_utf8_lossy(&status_command.stdout).contains("\"phase\":\"ready\""));

    client.shutdown().await.expect("shutdown headful auth station");
    let exit = tokio::time::timeout(Duration::from_secs(30), daemon.wait())
        .await
        .expect("headful auth daemon exit timeout")
        .expect("wait for headful auth daemon");
    assert!(exit.success(), "headful auth station failed: {exit}");
    let (_, stderr) = read_child_output(&mut daemon).await;
    assert!(stderr.is_empty(), "headful auth station wrote stderr: {stderr}");
    remove_tree(&profiles).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stationd_persists_authenticated_session_lifecycle_e2e() {
    let _serial = e2e_serial_guard().await;
    let fixture = FixtureServer::start();
    let unique = uuid::Uuid::new_v4();
    let pipe_name = format!("dig2browser-stationd-session-e2e-{unique}");
    let profiles = e2e_temp_base().join(format!(
        "dig2browser-stationd-session-e2e-{unique}"
    ));
    std::fs::create_dir_all(&profiles).expect("create session E2E profiles root");
    let stationd = env!("CARGO_BIN_EXE_dig2browser-stationd");
    let client_config = ClientConfig::new(
        &pipe_name,
        Duration::from_secs(15),
        Duration::from_secs(90),
    )
    .expect("valid session client config");
    let mut daemon = spawn_stationd(stationd, &pipe_name, &profiles);
    let client = StationClient::connect(client_config.clone())
        .await
        .expect("connect authenticated session client");
    let task = CollectionTask::new(vec![
        TaskStep::Navigate {
            url: fixture.url("/authenticated-profile"),
        },
        TaskStep::Capture {
            policy: TaskCapturePolicy::EvidenceViewport,
        },
    ])
    .expect("valid authenticated identity task");
    let result = client
        .run_task_with_identity(
            "authenticated-durable-profile",
            ProfileClass::Authenticated,
            BrowserPersona::desktop_default(),
            task,
        )
        .await
        .expect("create authenticated browser identity");
    assert!(matches!(result.replies()[1], TaskReply::Capture(_)));

    let unknown = client
        .identity_status("authenticated-durable-profile")
        .await
        .expect("read initial authenticated state");
    assert_eq!(unknown.profile_class, Some(ProfileClass::Authenticated));
    assert_eq!(unknown.phase, SessionPhase::Unknown);
    assert!(unknown.profile_exists);
    assert!(unknown.persona_bound);
    let expiry = unix_time_ms().saturating_add(1_500);
    client
        .update_identity_state(
            "authenticated-durable-profile",
            SessionStateUpdate {
                phase: SessionPhase::Ready,
                expires_at_unix_ms: Some(expiry),
            },
        )
        .await
        .expect("mark authenticated session ready");
    let ready = client
        .identity_status("authenticated-durable-profile")
        .await
        .expect("read ready authenticated state");
    assert_eq!(ready.phase, SessionPhase::Ready);
    assert_eq!(ready.expires_at_unix_ms, Some(expiry));
    assert!(ready.updated_at_unix_ms > 0);

    client.shutdown().await.expect("shutdown first session station");
    let first_exit = tokio::time::timeout(Duration::from_secs(30), daemon.wait())
        .await
        .expect("first session daemon exit timeout")
        .expect("wait for first session daemon");
    assert!(first_exit.success(), "first session station failed: {first_exit}");
    let (_, first_stderr) = read_child_output(&mut daemon).await;
    assert!(first_stderr.is_empty(), "session station wrote stderr: {first_stderr}");

    let mut successor = spawn_stationd(stationd, &pipe_name, &profiles);
    let successor_client = StationClient::connect(client_config)
        .await
        .expect("connect session successor client");
    let now = unix_time_ms();
    if expiry >= now {
        tokio::time::sleep(Duration::from_millis(
            expiry.saturating_sub(now).saturating_add(25),
        ))
        .await;
    }
    let expired = successor_client
        .identity_status("authenticated-durable-profile")
        .await
        .expect("read expired state after restart");
    assert_eq!(expired.phase, SessionPhase::Expired);
    assert_eq!(expired.expires_at_unix_ms, Some(expiry));

    successor_client
        .update_identity_state(
            "authenticated-durable-profile",
            SessionStateUpdate {
                phase: SessionPhase::ReauthRequired,
                expires_at_unix_ms: None,
            },
        )
        .await
        .expect("mark authenticated session for reauthentication");
    let reauth = successor_client
        .identity_status("authenticated-durable-profile")
        .await
        .expect("read reauthentication state");
    assert_eq!(reauth.phase, SessionPhase::ReauthRequired);
    assert_eq!(reauth.expires_at_unix_ms, None);

    let renewed_expiry = unix_time_ms().saturating_add(60_000);
    successor_client
        .update_identity_state(
            "authenticated-durable-profile",
            SessionStateUpdate {
                phase: SessionPhase::Ready,
                expires_at_unix_ms: Some(renewed_expiry),
            },
        )
        .await
        .expect("mark reauthenticated session ready");
    let renewed = successor_client
        .identity_status("authenticated-durable-profile")
        .await
        .expect("read renewed session state");
    assert_eq!(renewed.phase, SessionPhase::Ready);
    assert_eq!(renewed.expires_at_unix_ms, Some(renewed_expiry));

    let public_task = CollectionTask::new(vec![TaskStep::Navigate {
        url: fixture.url("/public-profile"),
    }])
    .expect("valid public identity task");
    successor_client
        .run_task("public-session-profile", public_task)
        .await
        .expect("create public browser identity");
    assert!(matches!(
        successor_client
            .update_identity_state(
                "public-session-profile",
                SessionStateUpdate {
                    phase: SessionPhase::Ready,
                    expires_at_unix_ms: Some(renewed_expiry),
                },
            )
            .await,
        Err(ClientError::Remote {
            status: ResponseStatus::Invalid,
            ..
        })
    ));

    let journal = std::fs::read(
        profiles
            .join("authenticated-durable-profile")
            .join(".dig2browser-session-state-v1"),
    )
    .expect("read non-secret session journal");
    assert_eq!(journal.len() % IdentitySessionStatus::ENCODED_LEN, 0);
    assert_eq!(journal.len(), IdentitySessionStatus::ENCODED_LEN * 3);
    let class = std::fs::read_to_string(
        profiles
            .join("authenticated-durable-profile")
            .join(".dig2browser-profile-class-v1"),
    )
    .expect("read identity class binding");
    assert_eq!(class, "Authenticated");

    successor_client
        .shutdown()
        .await
        .expect("shutdown session successor");
    let successor_exit = tokio::time::timeout(Duration::from_secs(30), successor.wait())
        .await
        .expect("session successor exit timeout")
        .expect("wait for session successor");
    assert!(successor_exit.success(), "session successor failed: {successor_exit}");
    let (_, successor_stderr) = read_child_output(&mut successor).await;
    assert!(
        successor_stderr.is_empty(),
        "session successor wrote stderr: {successor_stderr}"
    );
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
async fn stationd_resumes_trace_and_reconciles_hard_kill_e2e() {
    let _serial = e2e_serial_guard().await;
    let fixture = FixtureServer::start();
    let unique = uuid::Uuid::new_v4();
    let pipe_name = format!("dig2browser-stationd-trace-e2e-{unique}");
    let profiles = e2e_temp_base().join(format!(
        "dig2browser-stationd-trace-profiles-e2e-{unique}"
    ));
    let traces = e2e_temp_base().join(format!(
        "dig2browser-stationd-trace-ledger-e2e-{unique}"
    ));
    std::fs::create_dir_all(&profiles).expect("create trace E2E profiles root");
    std::fs::create_dir_all(&traces).expect("create trace E2E ledger root");
    let stationd = env!("CARGO_BIN_EXE_dig2browser-stationd");
    let mut daemon = spawn_stationd_with_trace(
        stationd,
        &pipe_name,
        &profiles,
        &traces,
    );
    let client_config = ClientConfig::new(
        &pipe_name,
        Duration::from_secs(15),
        Duration::from_secs(90),
    )
    .expect("valid trace E2E client config");
    let client = StationClient::connect(client_config)
        .await
        .expect("connect trace E2E client");

    let denied_profile = "authenticated-trace-denied";
    let denied_id = CollectionId::new(*uuid::Uuid::new_v4().as_bytes())
        .expect("nonzero denied collection ID");
    let denied = client
        .begin_collection_with_identity(
            denied_profile,
            denied_id,
            ProfileClass::Authenticated,
            BrowserPersona::desktop_default(),
            CollectionTask::new(vec![TaskStep::Navigate {
                url: fixture.url("/authenticated-trace-denied"),
            }])
            .expect("valid denied authenticated task"),
        )
        .await;
    assert!(matches!(
        denied,
        Err(ClientError::Remote {
            status: ResponseStatus::Unsupported,
            ..
        })
    ));
    assert!(
        !profiles.join(denied_profile).exists(),
        "authenticated durable denial created a profile"
    );

    let collection_id = CollectionId::new(*uuid::Uuid::new_v4().as_bytes())
        .expect("nonzero collection ID");
    let secret_query = "trace-query-secret";
    let secret_profile = "trace-profile-secret";
    let secret_script = "trace-script-secret";
    let secret_selector = "main[data-daemon-e2e=\"durable-trace\"]";
    let runtime_contract = TaskRuntimeContract::new(
        RuntimeSelector::Exact(RuntimeKind::Chrome),
        RuntimeRequirements::new(Vec::new(), false)
            .expect("valid trace runtime requirements"),
    )
    .expect("valid trace runtime contract");
    let task = CollectionTask::new_with_runtime(
        vec![
            TaskStep::Navigate {
                url: format!("{}?token={secret_query}", fixture.url("/durable-trace")),
            },
            TaskStep::Evaluate {
                script: format!("({{marker: '{secret_script}'}})"),
            },
            TaskStep::ReadSelectorText {
                selector: secret_selector.to_owned(),
            },
            TaskStep::Capture {
                policy: TaskCapturePolicy::EvidenceViewport,
            },
        ],
        runtime_contract,
    )
    .expect("valid durable trace task");
    let retry_task = task.clone();
    let handle = client
        .begin_collection_with_id(secret_profile, collection_id, task)
        .await
        .expect("begin durable trace collection");
    assert_eq!(handle.collection_id(), collection_id);
    assert_eq!(handle.cursor(), TraceCursor::new(1));
    assert_eq!(handle.runtime().kind(), RuntimeKind::Chrome);

    client.disconnect().await;
    let events = wait_for_complete_trace(&client, collection_id).await;
    assert_eq!(events.first().map(TraceEvent::cursor), Some(TraceCursor::new(1)));
    for (index, event) in events.iter().enumerate() {
        assert_eq!(event.cursor().value(), u32::try_from(index + 1).unwrap());
    }
    let mut artifacts = Vec::new();
    let mut terminal = None;
    for event in &events {
        match event.kind() {
            TraceEventKind::ArtifactCommitted(committed) => {
                artifacts.push((committed.role(), committed.artifact().clone()));
            }
            TraceEventKind::Terminal(trace) => terminal = Some(trace.outcome()),
            _ => {}
        }
    }
    assert_eq!(terminal, Some(TerminalOutcome::Succeeded));
    assert_eq!(artifacts.len(), 2);
    let receipt = client
        .read_collection_receipt(collection_id)
        .await
        .expect("read terminal collection receipt");
    let TraceEventKind::Started(started) = events[0].kind() else {
        panic!("collection trace did not start with task digest");
    };
    assert_eq!(receipt.collection_id(), collection_id);
    assert_eq!(receipt.task_sha256(), started.task_sha256());
    assert!(receipt.final_url().starts_with(&fixture.url("/durable-trace")));
    assert_eq!(receipt.http_status(), Some(200));
    assert_eq!(receipt.title(), Some("durable-trace"));
    assert_eq!(receipt.ready_state(), "complete");
    assert!(receipt.completed_at_unix_ms() > 0);
    assert_eq!(receipt.protocol_version(), PROTOCOL_VERSION);
    assert!(receipt.collector_version().starts_with("dig2browser-station/"));
    for (role, artifact) in &artifacts {
        let bytes = read_complete_artifact(&client, collection_id, artifact).await;
        assert_eq!(u64::try_from(bytes.len()).unwrap(), artifact.len());
        assert_eq!(
            dig2browser::digest::sha256_bytes(&bytes),
            *artifact.sha256()
        );
        match role {
            ArtifactRole::Html => {
                assert_eq!(receipt.html(), artifact);
                assert_eq!(artifact.media_type(), ArtifactMediaType::TextHtmlUtf8);
                assert!(String::from_utf8_lossy(&bytes)
                    .contains("data-daemon-e2e=\"durable-trace\""));
            }
            ArtifactRole::ViewportPng => {
                assert_eq!(receipt.viewport_png(), Some(artifact));
                assert_eq!(artifact.media_type(), ArtifactMediaType::ImagePng);
                assert_eq!(&bytes[..8], b"\x89PNG\r\n\x1a\n");
            }
        }
    }
    let retry = client
        .begin_collection_with_id(secret_profile, collection_id, retry_task)
        .await
        .expect("retry durable collection idempotently");
    assert_eq!(retry.collection_id(), collection_id);
    let retried_events = wait_for_complete_trace(&client, collection_id).await;
    assert_eq!(retried_events, events);
    let durable_events = read_trace_event_bytes(&traces);
    let durable_text = String::from_utf8_lossy(&durable_events);
    for secret in [secret_query, secret_profile, secret_script, secret_selector] {
        assert!(
            !durable_text.contains(secret),
            "trace event files leaked task input: {secret}"
        );
    }

    let cancelled_id = CollectionId::new(*uuid::Uuid::new_v4().as_bytes())
        .expect("nonzero cancelled collection ID");
    let cancelled_task = CollectionTask::new(vec![
        TaskStep::Navigate {
            url: fixture.url("/durable-cancelled"),
        },
        TaskStep::Wait {
            duration: Duration::from_secs(60),
        },
    ])
    .expect("valid cancellable collection task");
    client
        .begin_collection_with_id(
            "trace-cancel-profile",
            cancelled_id,
            cancelled_task,
        )
        .await
        .expect("begin cancellable collection");
    client
        .cancel_collection(cancelled_id)
        .await
        .expect("request collection cancellation");
    let cancelled = wait_for_complete_trace(&client, cancelled_id).await;
    assert!(matches!(
        cancelled.last().map(TraceEvent::kind),
        Some(TraceEventKind::Terminal(trace))
            if trace.outcome() == TerminalOutcome::Cancelled
    ));
    assert!(matches!(
        client.read_collection_receipt(cancelled_id).await,
        Err(ClientError::Remote {
            status: ResponseStatus::Invalid,
            ..
        })
    ));

    let interrupted_id = CollectionId::new(*uuid::Uuid::new_v4().as_bytes())
        .expect("nonzero interrupted collection ID");
    let interrupted_task = CollectionTask::new_with_runtime(
        vec![
            TaskStep::Navigate {
                url: fixture.url("/durable-interrupted"),
            },
            TaskStep::Wait {
                duration: Duration::from_secs(60),
            },
            TaskStep::Capture {
                policy: TaskCapturePolicy::HtmlOnly,
            },
        ],
        TaskRuntimeContract::new(
            RuntimeSelector::Exact(RuntimeKind::Chrome),
            RuntimeRequirements::new(Vec::new(), false)
                .expect("valid interrupted runtime requirements"),
        )
        .expect("valid interrupted runtime contract"),
    )
    .expect("valid interrupted collection task");
    client
        .begin_collection_with_id(
            "trace-crash-profile",
            interrupted_id,
            interrupted_task,
        )
        .await
        .expect("persist interrupted collection start");

    daemon.kill().await.expect("hard-kill trace station daemon");
    daemon.wait().await.expect("reap killed trace station daemon");
    let _ = read_child_output(&mut daemon).await;
    let mut successor = spawn_stationd_with_trace(
        stationd,
        &pipe_name,
        &profiles,
        &traces,
    );
    assert!(
        client.health().await.is_err(),
        "stale trace transport unexpectedly survived hard kill"
    );
    client
        .health()
        .await
        .expect("trace client reconnects to successor");
    let interrupted = wait_for_complete_trace(&client, interrupted_id).await;
    assert_eq!(interrupted.len(), 2);
    assert!(matches!(
        interrupted[0].kind(),
        TraceEventKind::Started(_)
    ));
    assert!(matches!(
        interrupted[1].kind(),
        TraceEventKind::Interrupted(InterruptedReason::SuccessorReconciliation)
    ));

    let legacy = client
        .run_task(
            "trace-crash-profile",
            CollectionTask::new(vec![
                TaskStep::Navigate {
                    url: fixture.url("/after-trace-reconciliation"),
                },
                TaskStep::Capture {
                    policy: TaskCapturePolicy::HtmlOnly,
                },
            ])
            .expect("valid legacy task after trace reconciliation"),
        )
        .await
        .expect("successor reuses profile after trace reconciliation");
    assert!(legacy.runtime().is_none());
    let TaskReply::Capture(capture) = &legacy.replies()[1] else {
        panic!("legacy task omitted capture after reconciliation");
    };
    assert!(String::from_utf8_lossy(&capture.html)
        .contains("data-daemon-e2e=\"after-trace-reconciliation\""));

    client.shutdown().await.expect("shutdown trace successor");
    let status = tokio::time::timeout(Duration::from_secs(30), successor.wait())
        .await
        .expect("trace successor exit timeout")
        .expect("wait for trace successor");
    assert!(status.success(), "trace successor failed: {status}");
    let (stdout, stderr) = read_child_output(&mut successor).await;
    assert!(stderr.is_empty(), "clean trace successor wrote stderr: {stderr}");
    assert!(stdout.contains("\"outcome\":\"clean\""));
    assert!(stdout.contains("\"drain_timed_out\":false"));
    remove_tree(&profiles).await;
    remove_tree(&traces).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stationd_surfaces_terminal_persistence_failure_e2e() {
    let _serial = e2e_serial_guard().await;
    let fixture = FixtureServer::start();
    let unique = uuid::Uuid::new_v4();
    let pipe_name = format!("dig2browser-stationd-trace-fault-e2e-{unique}");
    let profiles = e2e_temp_base().join(format!(
        "dig2browser-stationd-trace-fault-profiles-e2e-{unique}"
    ));
    let traces = e2e_temp_base().join(format!(
        "dig2browser-stationd-trace-fault-ledger-e2e-{unique}"
    ));
    std::fs::create_dir_all(&profiles).expect("create trace-fault profiles root");
    std::fs::create_dir_all(&traces).expect("create trace-fault ledger root");
    let stationd = env!("CARGO_BIN_EXE_dig2browser-stationd");
    let mut daemon = spawn_stationd_with_trace(
        stationd,
        &pipe_name,
        &profiles,
        &traces,
    );
    let client_config = ClientConfig::new(
        &pipe_name,
        Duration::from_secs(15),
        Duration::from_secs(90),
    )
    .expect("valid trace-fault client config");
    let client = StationClient::connect(client_config.clone())
        .await
        .expect("connect trace-fault client");
    let collection_id = CollectionId::new(*uuid::Uuid::new_v4().as_bytes())
        .expect("nonzero trace-fault collection ID");
    let task = CollectionTask::new(vec![
        TaskStep::Navigate {
            url: fixture.url("/terminal-persistence-fault"),
        },
        TaskStep::Wait {
            duration: Duration::from_secs(60),
        },
    ])
    .expect("valid trace-fault task");
    client
        .begin_collection_with_id("trace-fault-profile", collection_id, task.clone())
        .await
        .expect("persist trace-fault start");

    let blocked_terminal = trace_collection_dir(&traces, collection_id)
        .join("00000002.event");
    std::fs::create_dir(&blocked_terminal).expect("inject terminal append fault");
    client
        .cancel_collection(collection_id)
        .await
        .expect("request trace-fault cancellation");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        match client
            .read_trace(collection_id, TraceCursor::START, 64)
            .await
        {
            Err(ClientError::Remote {
                status: ResponseStatus::Unavailable,
                ..
            }) => break,
            Err(ClientError::Remote {
                status: ResponseStatus::Protocol,
                ..
            }) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Ok(_) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            other => panic!("terminal persistence fault was not surfaced: {other:?}"),
        }
    }
    assert!(matches!(
        client
            .begin_collection_with_id("trace-fault-profile", collection_id, task)
            .await,
        Err(ClientError::Remote {
            status: ResponseStatus::Unavailable,
            ..
        })
    ));

    client
        .shutdown()
        .await
        .expect("request trace-fault daemon shutdown");
    let status = tokio::time::timeout(Duration::from_secs(30), daemon.wait())
        .await
        .expect("trace-fault daemon exit timeout")
        .expect("wait for trace-fault daemon");
    assert!(!status.success(), "trace-fault daemon reported clean exit");
    let (_, stderr) = read_child_output(&mut daemon).await;
    assert!(stderr.contains("\"error_class\":\"trace_root_unavailable\""));

    std::fs::remove_dir(&blocked_terminal).expect("remove terminal append fault");
    let mut successor = spawn_stationd_with_trace(
        stationd,
        &pipe_name,
        &profiles,
        &traces,
    );
    let successor_client = StationClient::connect(client_config)
        .await
        .expect("connect trace-fault successor");
    let recovered = wait_for_complete_trace(&successor_client, collection_id).await;
    assert_eq!(recovered.len(), 2);
    assert!(matches!(
        recovered[1].kind(),
        TraceEventKind::Interrupted(InterruptedReason::SuccessorReconciliation)
    ));
    successor_client
        .shutdown()
        .await
        .expect("shutdown trace-fault successor");
    let successor_status = tokio::time::timeout(Duration::from_secs(30), successor.wait())
        .await
        .expect("trace-fault successor exit timeout")
        .expect("wait for trace-fault successor");
    assert!(successor_status.success());
    let (stdout, successor_stderr) = read_child_output(&mut successor).await;
    assert!(successor_stderr.is_empty());
    assert!(stdout.contains("\"outcome\":\"clean\""));
    remove_tree(&profiles).await;
    remove_tree(&traces).await;
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

async fn wait_for_complete_trace(
    client: &StationClient,
    collection_id: CollectionId,
) -> Vec<TraceEvent> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    let mut cursor = TraceCursor::START;
    let mut events = Vec::new();
    loop {
        let page = client
            .read_trace(collection_id, cursor, 64)
            .await
            .expect("poll durable trace");
        events.extend_from_slice(page.events());
        cursor = page.next_cursor();
        if page.is_complete() {
            return events;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "durable trace did not reach a terminal event"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn wait_for_complete_product_crawl(
    client: &StationClient,
    job_id: CrawlJobId,
) -> Vec<CrawlEvent> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    let mut cursor = CrawlCursor::START;
    let mut events = Vec::new();
    loop {
        let page = client
            .read_crawl_events(job_id, cursor, 64)
            .await
            .expect("poll product matrix crawl events");
        events.extend_from_slice(page.events());
        cursor = page.next_cursor();
        if page.is_complete() {
            return events;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "product matrix crawl did not reach terminal state: {events:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn read_complete_artifact(
    client: &StationClient,
    collection_id: CollectionId,
    artifact: &ArtifactRef,
) -> Vec<u8> {
    let mut offset = 0_u64;
    let mut bytes = Vec::new();
    loop {
        let chunk = client
            .read_artifact_chunk(
                collection_id,
                *artifact.sha256(),
                offset,
                1024,
            )
            .await
            .expect("read durable artifact chunk");
        assert_eq!(chunk.total_len(), artifact.len());
        bytes.extend_from_slice(chunk.bytes());
        offset = offset
            .checked_add(u64::try_from(chunk.bytes().len()).unwrap())
            .expect("artifact offset remains bounded");
        if chunk.is_eof() {
            return bytes;
        }
    }
}

fn read_trace_event_bytes(trace_root: &Path) -> Vec<u8> {
    let mut output = Vec::new();
    let collections = trace_root.join("collections");
    for collection in std::fs::read_dir(collections).expect("read trace collections") {
        let collection = collection.expect("read trace collection entry");
        if !collection.file_type().expect("trace collection type").is_dir() {
            continue;
        }
        for event in std::fs::read_dir(collection.path()).expect("read trace events") {
            let event = event.expect("read trace event entry");
            if event
                .path()
                .extension()
                .is_some_and(|extension| extension == "event")
            {
                output.extend_from_slice(
                    &std::fs::read(event.path()).expect("read trace event file"),
                );
            }
        }
    }
    output
}

fn trace_collection_dir(trace_root: &Path, collection_id: CollectionId) -> PathBuf {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut name = String::with_capacity(32);
    for byte in collection_id.as_bytes() {
        name.push(HEX[usize::from(byte >> 4)] as char);
        name.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    trace_root.join("collections").join(name)
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

async fn run_auth_cli(
    auth_cli: &str,
    pipe_name: &str,
    args: &[&str],
) -> std::process::Output {
    let mut command = tokio::process::Command::new(auth_cli);
    command.args(["--pipe-name", pipe_name]);
    command.args(args);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .expect("run dig2browser-auth CLI")
}

fn spawn_stationd(stationd: &str, pipe_name: &str, profiles: &Path) -> tokio::process::Child {
    spawn_stationd_with_permissions(stationd, pipe_name, profiles, true, true, false)
}

fn spawn_stationd_with_trace(
    stationd: &str,
    pipe_name: &str,
    profiles: &Path,
    traces: &Path,
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
        "4",
        "--max-connections",
        "8",
        "--timeout-seconds",
        "90",
        "--drain-seconds",
        "15",
        "--allow-remote-shutdown",
        "--allow-interactive-tasks",
        "--allow-scripted-tasks",
        "--allow-durable-read",
        "--allow-durable-write",
    ]);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn trace station daemon")
}

fn spawn_stationd_for_runtime(
    stationd: &str,
    pipe_name: &str,
    profiles: &Path,
    runtime: &str,
) -> tokio::process::Child {
    spawn_stationd_with_runtime_permissions(
        stationd,
        pipe_name,
        profiles,
        Some(runtime),
        true,
        true,
        false,
    )
}

fn spawn_stationd_for_durable_monitor(
    stationd: &str,
    pipe_name: &str,
    profiles: &Path,
    monitor_root: &Path,
) -> tokio::process::Child {
    let mut command = tokio::process::Command::new(stationd);
    command.args([
        "--pipe-name",
        pipe_name,
        "--profiles-root",
        profiles.to_str().expect("profiles path is UTF-8"),
        "--monitor-root",
        monitor_root.to_str().expect("monitor root is UTF-8"),
        "--runtime",
        "chrome",
        "--max-resident",
        "2",
        "--max-in-flight",
        "4",
        "--max-connections",
        "8",
        "--timeout-seconds",
        "90",
        "--drain-seconds",
        "15",
        "--allow-remote-shutdown",
        "--allow-durable-read",
        "--allow-durable-write",
    ]);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn durable-monitor station daemon")
}

fn spawn_stationd_for_live_events(
    stationd: &str,
    pipe_name: &str,
    profiles: &Path,
) -> tokio::process::Child {
    let mut command = tokio::process::Command::new(stationd);
    command.args([
        "--pipe-name",
        pipe_name,
        "--profiles-root",
        profiles.to_str().expect("profiles path is UTF-8"),
        "--runtime",
        "chrome",
        "--max-resident",
        "2",
        "--max-in-flight",
        "4",
        "--max-connections",
        "8",
        "--timeout-seconds",
        "90",
        "--drain-seconds",
        "15",
        "--allow-remote-shutdown",
        "--allow-live-events",
    ]);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn live-events station daemon")
}

fn spawn_stationd_for_firefox(
    stationd: &str,
    pipe_name: &str,
    profiles: &Path,
    geckodriver: &Path,
) -> tokio::process::Child {
    let mut command = tokio::process::Command::new(stationd);
    command.env_remove("GECKODRIVER");
    command.args([
        "--pipe-name",
        pipe_name,
        "--profiles-root",
        profiles.to_str().expect("profiles path is UTF-8"),
        "--runtime",
        "firefox",
        "--geckodriver-path",
        geckodriver.to_str().expect("geckodriver path is UTF-8"),
        "--max-resident",
        "2",
        "--max-in-flight",
        "4",
        "--max-connections",
        "8",
        "--timeout-seconds",
        "90",
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
        .expect("spawn Firefox station daemon")
}

fn spawn_stationd_for_product_matrix(
    stationd: &str,
    pipe_name: &str,
    profiles: &Path,
    traces: &Path,
    crawls: &Path,
    runtime: &str,
    geckodriver: Option<&Path>,
) -> tokio::process::Child {
    let mut command = tokio::process::Command::new(stationd);
    #[cfg(feature = "runtime-test-hooks")]
    command.env("DIG2BROWSER_TEST_CAPTURE_DIAGNOSTICS", "1");
    let max_resident = if runtime == "firefox" { "1" } else { "4" };
    command.args([
        "--pipe-name",
        pipe_name,
        "--profiles-root",
        profiles.to_str().expect("profiles path is UTF-8"),
        "--trace-root",
        traces.to_str().expect("trace path is UTF-8"),
        "--crawl-root",
        crawls.to_str().expect("crawl path is UTF-8"),
        "--runtime",
        runtime,
        "--restart-after-pages",
        "1",
        "--max-resident",
        max_resident,
        "--max-in-flight",
        "4",
        "--max-connections",
        "8",
        "--timeout-seconds",
        "90",
        "--drain-seconds",
        "15",
        "--allow-remote-shutdown",
        "--allow-interactive-tasks",
        "--allow-scripted-tasks",
        "--allow-headful-auth",
        "--allow-session-health",
        "--allow-identity-status",
        "--allow-session-state-updates",
        "--allow-durable-read",
        "--allow-durable-write",
        "--allow-crawl-read",
        "--allow-crawl-write",
    ]);
    if let Some(geckodriver) = geckodriver {
        command.env_remove("GECKODRIVER");
        command.args([
            "--geckodriver-path",
            geckodriver.to_str().expect("geckodriver path is UTF-8"),
        ]);
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr({
            #[cfg(feature = "runtime-test-hooks")]
            {
                Stdio::inherit()
            }
            #[cfg(not(feature = "runtime-test-hooks"))]
            {
                Stdio::piped()
            }
        })
        .kill_on_drop(true)
        .spawn()
        .expect("spawn product matrix station daemon")
}

fn matrix_task(runtime: RuntimeKind, steps: Vec<TaskStep>) -> CollectionTask {
    let contract = TaskRuntimeContract::new(
        RuntimeSelector::Exact(runtime),
        RuntimeRequirements::new(Vec::new(), false)
            .expect("valid matrix runtime requirements"),
    )
    .expect("valid matrix runtime contract");
    CollectionTask::new_with_runtime(steps, contract)
        .expect("valid matrix collection task")
}

fn script_json_number(reply: &TaskReply) -> f64 {
    let TaskReply::ScriptJson(value) = reply else {
        panic!("matrix task did not return script JSON: {reply:?}");
    };
    serde_json::from_str(value).expect("matrix script JSON is numeric")
}

fn spawn_stationd_for_runtime_with_routes(
    stationd: &str,
    pipe_name: &str,
    profiles: &Path,
    runtime: &str,
    direct_route_refs: &[&str],
    allow_session_state_updates: bool,
) -> tokio::process::Child {
    spawn_stationd_with_runtime_routes_permissions(
        stationd,
        pipe_name,
        profiles,
        StationSpawnOptions {
            runtime: Some(runtime),
            direct_route_refs,
            allow_active_tasks: true,
            allow_session_state_updates,
            allow_headful_auth: false,
        },
    )
}

fn spawn_stationd_with_task_permissions(
    stationd: &str,
    pipe_name: &str,
    profiles: &Path,
    allow_active_tasks: bool,
) -> tokio::process::Child {
    spawn_stationd_with_permissions(
        stationd,
        pipe_name,
        profiles,
        allow_active_tasks,
        false,
        false,
    )
}

fn spawn_stationd_with_permissions(
    stationd: &str,
    pipe_name: &str,
    profiles: &Path,
    allow_active_tasks: bool,
    allow_session_state_updates: bool,
    allow_headful_auth: bool,
) -> tokio::process::Child {
    spawn_stationd_with_runtime_permissions(
        stationd,
        pipe_name,
        profiles,
        None,
        allow_active_tasks,
        allow_session_state_updates,
        allow_headful_auth,
    )
}

fn spawn_stationd_with_runtime_permissions(
    stationd: &str,
    pipe_name: &str,
    profiles: &Path,
    runtime: Option<&str>,
    allow_active_tasks: bool,
    allow_session_state_updates: bool,
    allow_headful_auth: bool,
) -> tokio::process::Child {
    spawn_stationd_with_runtime_routes_permissions(
        stationd,
        pipe_name,
        profiles,
        StationSpawnOptions {
            runtime,
            direct_route_refs: &[],
            allow_active_tasks,
            allow_session_state_updates,
            allow_headful_auth,
        },
    )
}

struct StationSpawnOptions<'a> {
    runtime: Option<&'a str>,
    direct_route_refs: &'a [&'a str],
    allow_active_tasks: bool,
    allow_session_state_updates: bool,
    allow_headful_auth: bool,
}

fn spawn_stationd_with_runtime_routes_permissions(
    stationd: &str,
    pipe_name: &str,
    profiles: &Path,
    options: StationSpawnOptions<'_>,
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
    if let Some(runtime) = options.runtime {
        command.args(["--runtime", runtime]);
    }
    for direct_route_ref in options.direct_route_refs {
        command.args(["--direct-route-ref", direct_route_ref]);
    }
    if options.allow_active_tasks {
        command.args(["--allow-interactive-tasks", "--allow-scripted-tasks"]);
    }
    if options.allow_session_state_updates {
        command.args([
            "--allow-identity-status",
            "--allow-session-state-updates",
        ]);
    }
    if options.allow_headful_auth {
        command.args(["--allow-headful-auth", "--allow-session-health"]);
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn station daemon")
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or_default()
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
