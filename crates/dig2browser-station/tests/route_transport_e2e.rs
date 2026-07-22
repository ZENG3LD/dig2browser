#![cfg(windows)]

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use dig2browser_client::{
    BrowserPersona, ClientConfig, CollectionTask, CollectionTaskResult, PersonaPreset, ProfileClass, RouteRef,
    RuntimeFeature, RuntimeKind, RuntimeRequirements, RuntimeSelector, StationClient,
    TaskCapturePolicy, TaskReply, TaskRuntimeContract, TaskStep,
};
use tokio::io::AsyncReadExt;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires installed Chrome"]
async fn stationd_chrome_direct_http_connect_socks5_route_matrix_e2e() {
    let _serial = route_e2e_serial_guard().await;
    run_route_matrix("chrome", RuntimeKind::Chrome, None, RouteMatrixScope::All).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires installed Edge"]
async fn stationd_edge_direct_http_connect_socks5_route_matrix_e2e() {
    let _serial = route_e2e_serial_guard().await;
    run_route_matrix("edge", RuntimeKind::Edge, None, RouteMatrixScope::All).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires GECKODRIVER and installed Firefox"]
async fn stationd_firefox_direct_http_connect_socks5_route_matrix_e2e() {
    let _serial = route_e2e_serial_guard().await;
    let geckodriver = std::env::var_os("GECKODRIVER")
        .map(PathBuf::from)
        .expect("GECKODRIVER is configured");
    assert!(geckodriver.is_file(), "GECKODRIVER is not a file");
    for scope in [
        RouteMatrixScope::Direct,
        RouteMatrixScope::Socks5,
        RouteMatrixScope::HttpConnect,
    ] {
        run_firefox_route_scope(&geckodriver, scope).await;
    }
}

async fn run_firefox_route_scope(geckodriver: &Path, scope: RouteMatrixScope) {
    run_route_matrix(
        "firefox",
        RuntimeKind::Firefox,
        Some(geckodriver),
        scope,
    )
    .await;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteMatrixScope {
    All,
    Direct,
    Socks5,
    HttpConnect,
}

impl RouteMatrixScope {
    fn includes_direct(self) -> bool {
        matches!(self, Self::All | Self::Direct)
    }

    fn includes_socks5(self) -> bool {
        matches!(self, Self::All | Self::Socks5)
    }

    fn includes_http_connect(self) -> bool {
        matches!(self, Self::All | Self::HttpConnect)
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Direct => "direct",
            Self::Socks5 => "socks5",
            Self::HttpConnect => "http-connect",
        }
    }
}

async fn run_route_matrix(
    runtime_name: &str,
    runtime_kind: RuntimeKind,
    geckodriver: Option<&Path>,
    scope: RouteMatrixScope,
) {
    let direct = ControlledOrigin::start();
    let tripwire = DirectTripwire::start();
    let http_proxy = ControlledHttpProxy::start();
    let socks5_proxy = ControlledSocks5Proxy::start();
    let unique = uuid::Uuid::new_v4();
    let root = e2e_temp_base().join(format!(
        "dig2browser-route-matrix-{runtime_name}-{}-{unique}",
        scope.as_str(),
    ));
    let profiles = root.join("profiles");
    std::fs::create_dir_all(&profiles).expect("create route-matrix profiles root");
    let pipe_name = format!("dig2browser-route-matrix-{runtime_name}-{unique}");
    let mut daemon = spawn_route_stationd(
        &pipe_name,
        &profiles,
        runtime_name,
        geckodriver,
        http_proxy.address(),
        socks5_proxy.address(),
    );
    let client = StationClient::connect(
        ClientConfig::new(
            &pipe_name,
            Duration::from_secs(15),
            Duration::from_secs(90),
        )
        .expect("valid route-matrix client config"),
    )
    .await
    .unwrap_or_else(|error| panic!("connect {runtime_name} route matrix: {error}"));

    if scope.includes_direct() {
        let direct_route = RouteRef::host_direct();
        let direct_result = client
            .run_task_with_identity(
                &format!("route-{runtime_name}-direct"),
                ProfileClass::Public,
                compiled_persona(runtime_kind, direct_route),
                route_task(runtime_kind, direct.url("/route-direct")),
            )
            .await
            .unwrap_or_else(|error| panic!("{runtime_name} direct route failed: {error}"));
        assert_route_capture(
            runtime_name,
            runtime_kind,
            &direct_result,
            "direct-route-ok",
        );
        assert_eq!(direct.path_count("/route-direct"), 1);
    }

    let target = tripwire.address();
    if scope.includes_socks5() {
        let socks_url = format!("http://{target}/route-socks5");
        let socks_result = client
            .run_task_with_identity(
                &format!("route-{runtime_name}-socks5"),
                ProfileClass::Public,
                compiled_persona(
                    runtime_kind,
                    RouteRef::new("matrix.socks5").expect("SOCKS5 route reference"),
                ),
                route_task(runtime_kind, socks_url),
            )
            .await
            .unwrap_or_else(|error| {
                panic!(
                    "{runtime_name} SOCKS5 route failed: {error}; targets={:?}; errors={:?}; tripwire={}",
                    socks5_proxy.observed_targets(),
                    socks5_proxy.observed_errors(),
                    tripwire.accepted(),
                )
            });
        assert_route_capture(
            runtime_name,
            runtime_kind,
            &socks_result,
            "socks5-route-ok",
        );
        assert!(
            socks5_proxy.saw_target(target),
            "{runtime_name} SOCKS5 proxy did not observe the exact target"
        );
    }

    if scope.includes_http_connect() {
        let http_profile = format!("route-{runtime_name}-http");
        let http_persona = compiled_persona(
            runtime_kind,
            RouteRef::new("matrix.http").expect("HTTP route reference"),
        );
        let http_url = format!("http://{target}/route-http");
        let http_result = client
            .run_task_with_identity(
                &http_profile,
                ProfileClass::Public,
                http_persona.clone(),
                route_task(runtime_kind, http_url.clone()),
            )
            .await
            .unwrap_or_else(|error| panic!("{runtime_name} HTTP proxy route failed: {error}"));
        assert_route_capture(
            runtime_name,
            runtime_kind,
            &http_result,
            "http-proxy-route-ok",
        );
        assert!(
            http_proxy.saw_request_target(&http_url),
            "{runtime_name} HTTP proxy did not observe the exact absolute target"
        );

        let connect_authority = target.to_string();
        let connect_result = client
            .run_task_with_identity(
                &http_profile,
                ProfileClass::Public,
                http_persona,
                route_task(runtime_kind, format!("https://{target}/route-connect")),
            )
            .await;
        assert!(
            connect_result.is_err(),
            "controlled CONNECT rejection unexpectedly produced a successful page"
        );
        assert!(
            http_proxy.saw_tls_tunnel_authority(&connect_authority),
            "{runtime_name} did not carry a TLS ClientHello through HTTP CONNECT for the exact HTTPS authority"
        );
    }

    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        tripwire.accepted(),
        0,
        "{runtime_name} bypassed the selected proxy and opened a direct target socket"
    );

    client
        .shutdown()
        .await
        .unwrap_or_else(|error| panic!("shutdown {runtime_name} route matrix: {error}"));
    let status = tokio::time::timeout(Duration::from_secs(30), daemon.wait())
        .await
        .unwrap_or_else(|_| panic!("{runtime_name} route matrix exit timeout"))
        .expect("wait for route-matrix station");
    let (stdout, stderr) = read_child_output(&mut daemon).await;
    assert!(
        status.success(),
        "{runtime_name} route matrix station failed: {status}; stdout={stdout}; stderr={stderr}"
    );
    assert!(stderr.is_empty(), "{runtime_name} route matrix stderr: {stderr}");
    remove_tree(&root).await;
}

fn compiled_persona(runtime: RuntimeKind, route: RouteRef) -> BrowserPersona {
    let preset = match runtime {
        RuntimeKind::Chrome => PersonaPreset::ChromeWindowsDesktopV1,
        RuntimeKind::Edge => PersonaPreset::EdgeWindowsDesktopV1,
        RuntimeKind::Firefox => PersonaPreset::FirefoxWindowsDesktopV1,
        other => panic!("unsupported route-matrix runtime: {other:?}"),
    };
    BrowserPersona::compiled(preset, route).expect("compile route-bound persona")
}

fn route_task(runtime: RuntimeKind, url: String) -> CollectionTask {
    let contract = TaskRuntimeContract::new(
        RuntimeSelector::Exact(runtime),
        RuntimeRequirements::new(
            vec![
                RuntimeFeature::Navigate,
                RuntimeFeature::CaptureState,
                RuntimeFeature::CaptureHtml,
                RuntimeFeature::Lifecycle,
            ],
            false,
        )
        .expect("valid route-matrix requirements"),
    )
    .expect("valid route-matrix runtime contract");
    CollectionTask::new_with_runtime(
        vec![
            TaskStep::Navigate { url },
            TaskStep::Capture {
                policy: TaskCapturePolicy::HtmlOnly,
            },
        ],
        contract,
    )
    .expect("valid route-matrix task")
}

fn assert_route_capture(
    runtime_name: &str,
    runtime_kind: RuntimeKind,
    result: &CollectionTaskResult,
    expected_title: &str,
) {
    assert_eq!(
        result.runtime().expect("route runtime evidence").kind(),
        runtime_kind
    );
    let TaskReply::Capture(capture) = &result.replies()[1] else {
        panic!("{runtime_name} route task did not return an evidence capture");
    };
    assert_eq!(capture.http_status, Some(200));
    assert_eq!(capture.title, expected_title);
    assert!(
        String::from_utf8_lossy(&capture.html).contains("data-route-e2e"),
        "{runtime_name} route capture omitted controlled evidence"
    );
}

struct ControlledOrigin {
    address: SocketAddr,
    paths: Arc<Mutex<Vec<String>>>,
    stopping: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl ControlledOrigin {
    fn start() -> Self {
        let listener = bound_nonblocking_listener();
        let address = listener.local_addr().expect("controlled origin address");
        let paths = Arc::new(Mutex::new(Vec::new()));
        let stopping = Arc::new(AtomicBool::new(false));
        let thread_paths = Arc::clone(&paths);
        let thread_stopping = Arc::clone(&stopping);
        let thread = thread::spawn(move || {
            accept_loop(listener, thread_stopping, move |mut stream| {
                let request = read_http_headers(&mut stream)?;
                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("/")
                    .to_owned();
                thread_paths
                    .lock()
                    .expect("controlled origin paths remain available")
                    .push(path);
                write_html(&mut stream, "direct-route-ok")
            });
        });
        Self {
            address,
            paths,
            stopping,
            thread: Some(thread),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.address, path)
    }

    fn path_count(&self, path: &str) -> usize {
        self.paths
            .lock()
            .expect("controlled origin paths remain available")
            .iter()
            .filter(|seen| seen.as_str() == path)
            .count()
    }
}

impl Drop for ControlledOrigin {
    fn drop(&mut self) {
        stop_listener(self.address, &self.stopping, &mut self.thread);
    }
}

struct DirectTripwire {
    address: SocketAddr,
    accepted: Arc<AtomicUsize>,
    stopping: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl DirectTripwire {
    fn start() -> Self {
        let listener = bound_nonblocking_listener();
        let address = listener.local_addr().expect("tripwire address");
        let accepted = Arc::new(AtomicUsize::new(0));
        let stopping = Arc::new(AtomicBool::new(false));
        let thread_accepted = Arc::clone(&accepted);
        let thread_stopping = Arc::clone(&stopping);
        let thread = thread::spawn(move || {
            while !thread_stopping.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        thread_accepted.fetch_add(1, Ordering::AcqRel);
                        drop(stream);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("tripwire listener failed: {error}"),
                }
            }
        });
        Self {
            address,
            accepted,
            stopping,
            thread: Some(thread),
        }
    }

    fn address(&self) -> SocketAddr {
        self.address
    }

    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::Acquire)
    }
}

impl Drop for DirectTripwire {
    fn drop(&mut self) {
        stop_listener(self.address, &self.stopping, &mut self.thread);
    }
}

struct ControlledHttpProxy {
    address: SocketAddr,
    request_lines: Arc<Mutex<Vec<String>>>,
    tls_tunnels: Arc<Mutex<Vec<String>>>,
    stopping: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl ControlledHttpProxy {
    fn start() -> Self {
        let listener = bound_nonblocking_listener();
        let address = listener.local_addr().expect("HTTP proxy address");
        let request_lines = Arc::new(Mutex::new(Vec::new()));
        let tls_tunnels = Arc::new(Mutex::new(Vec::new()));
        let stopping = Arc::new(AtomicBool::new(false));
        let thread_lines = Arc::clone(&request_lines);
        let thread_tls_tunnels = Arc::clone(&tls_tunnels);
        let thread_stopping = Arc::clone(&stopping);
        let thread = thread::spawn(move || {
            accept_loop(listener, thread_stopping, move |mut stream| {
                let request = read_http_headers(&mut stream)?;
                let request_line = request.lines().next().unwrap_or_default().to_owned();
                thread_lines
                    .lock()
                    .expect("HTTP proxy log remains available")
                    .push(request_line.clone());
                if request_line.starts_with("CONNECT ") {
                    stream.write_all(
                        b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: dig2browser-e2e\r\n\r\n",
                    )?;
                    let mut tls_header = [0_u8; 5];
                    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
                    if stream.read_exact(&mut tls_header).is_ok() && tls_header[0] == 0x16 {
                        if let Some(authority) = request_line
                            .strip_prefix("CONNECT ")
                            .and_then(|line| line.strip_suffix(" HTTP/1.1"))
                        {
                            thread_tls_tunnels
                                .lock()
                                .expect("HTTP CONNECT log remains available")
                                .push(authority.to_owned());
                        }
                    }
                    Ok(())
                } else {
                    write_html(&mut stream, "http-proxy-route-ok")
                }
            });
        });
        Self {
            address,
            request_lines,
            tls_tunnels,
            stopping,
            thread: Some(thread),
        }
    }

    fn address(&self) -> SocketAddr {
        self.address
    }

    fn saw_request_target(&self, target: &str) -> bool {
        self.request_lines
            .lock()
            .expect("HTTP proxy log remains available")
            .iter()
            .any(|line| line.starts_with("GET ") && line.contains(target))
    }

    fn saw_tls_tunnel_authority(&self, authority: &str) -> bool {
        self.tls_tunnels
            .lock()
            .expect("HTTP CONNECT log remains available")
            .iter()
            .any(|seen| seen == authority)
    }
}

impl Drop for ControlledHttpProxy {
    fn drop(&mut self) {
        stop_listener(self.address, &self.stopping, &mut self.thread);
    }
}

struct ControlledSocks5Proxy {
    address: SocketAddr,
    targets: Arc<Mutex<Vec<SocketAddr>>>,
    errors: Arc<Mutex<Vec<String>>>,
    stopping: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl ControlledSocks5Proxy {
    fn start() -> Self {
        let listener = bound_nonblocking_listener();
        let address = listener.local_addr().expect("SOCKS5 proxy address");
        let targets = Arc::new(Mutex::new(Vec::new()));
        let errors = Arc::new(Mutex::new(Vec::new()));
        let stopping = Arc::new(AtomicBool::new(false));
        let thread_targets = Arc::clone(&targets);
        let thread_errors = Arc::clone(&errors);
        let thread_stopping = Arc::clone(&stopping);
        let thread = thread::spawn(move || {
            accept_loop(listener, thread_stopping, move |mut stream| {
                let target = match accept_socks5_connect(&mut stream) {
                    Ok(target) => target,
                    Err(error) => {
                        thread_errors
                            .lock()
                            .expect("SOCKS5 error log remains available")
                            .push(format!("handshake: {error}"));
                        return Err(error);
                    }
                };
                if let Some(target) = target {
                    thread_targets
                        .lock()
                        .expect("SOCKS5 target log remains available")
                        .push(target);
                }
                let request = match read_http_headers(&mut stream) {
                    Ok(request) => request,
                    Err(error) => {
                        thread_errors
                            .lock()
                            .expect("SOCKS5 error log remains available")
                            .push(format!("payload: {error}"));
                        return Err(error);
                    }
                };
                if request.starts_with("GET ") {
                    write_html(&mut stream, "socks5-route-ok")?;
                }
                Ok(())
            });
        });
        Self {
            address,
            targets,
            errors,
            stopping,
            thread: Some(thread),
        }
    }

    fn address(&self) -> SocketAddr {
        self.address
    }

    fn saw_target(&self, target: SocketAddr) -> bool {
        self.targets
            .lock()
            .expect("SOCKS5 target log remains available")
            .contains(&target)
    }

    fn observed_targets(&self) -> Vec<SocketAddr> {
        self.targets
            .lock()
            .expect("SOCKS5 target log remains available")
            .clone()
    }

    fn observed_errors(&self) -> Vec<String> {
        self.errors
            .lock()
            .expect("SOCKS5 error log remains available")
            .clone()
    }
}

impl Drop for ControlledSocks5Proxy {
    fn drop(&mut self) {
        stop_listener(self.address, &self.stopping, &mut self.thread);
    }
}

fn accept_socks5_connect(stream: &mut TcpStream) -> std::io::Result<Option<SocketAddr>> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut greeting = [0_u8; 2];
    stream.read_exact(&mut greeting)?;
    if greeting[0] != 5 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid SOCKS version",
        ));
    }
    let mut methods = vec![0_u8; usize::from(greeting[1])];
    stream.read_exact(&mut methods)?;
    stream.write_all(&[5, 0])?;

    let mut header = [0_u8; 4];
    stream.read_exact(&mut header)?;
    if header[..3] != [5, 1, 0] {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "SOCKS request is not CONNECT",
        ));
    }
    let ip = match header[3] {
        1 => {
            let mut octets = [0_u8; 4];
            stream.read_exact(&mut octets)?;
            Some(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        3 => {
            let mut length = [0_u8; 1];
            stream.read_exact(&mut length)?;
            let mut host = vec![0_u8; usize::from(length[0])];
            stream.read_exact(&mut host)?;
            std::str::from_utf8(&host).ok().and_then(|host| host.parse().ok())
        }
        4 => {
            let mut octets = [0_u8; 16];
            stream.read_exact(&mut octets)?;
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    };
    let mut port = [0_u8; 2];
    stream.read_exact(&mut port)?;
    stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])?;
    Ok(ip.map(|ip| SocketAddr::new(ip, u16::from_be_bytes(port))))
}

fn bound_nonblocking_listener() -> TcpListener {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind controlled listener");
    listener
        .set_nonblocking(true)
        .expect("make controlled listener nonblocking");
    listener
}

fn accept_loop(
    listener: TcpListener,
    stopping: Arc<AtomicBool>,
    serve: impl Fn(TcpStream) -> std::io::Result<()> + Send + Sync + 'static,
) {
    let serve = Arc::new(serve);
    while !stopping.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_nonblocking(false)
                    .expect("make accepted controlled stream blocking");
                let connection = Arc::clone(&serve);
                thread::spawn(move || {
                    let _ = connection(stream);
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("controlled listener failed: {error}"),
        }
    }
}

fn read_http_headers(stream: &mut TcpStream) -> std::io::Result<String> {
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
                "controlled request headers exceed bound",
            ));
        }
    }
    Ok(String::from_utf8_lossy(&request).into_owned())
}

fn write_html(stream: &mut TcpStream, title: &str) -> std::io::Result<()> {
    let body = format!(
        "<!doctype html><title>{title}</title><main data-route-e2e=\"{title}\">{title}</main>"
    );
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{}",
        body.len(),
        body
    )
}

fn stop_listener(
    address: SocketAddr,
    stopping: &AtomicBool,
    thread: &mut Option<JoinHandle<()>>,
) {
    stopping.store(true, Ordering::Release);
    let _ = TcpStream::connect_timeout(&address, Duration::from_millis(100));
    if let Some(thread) = thread.take() {
        let _ = thread.join();
    }
}

fn spawn_route_stationd(
    pipe_name: &str,
    profiles: &Path,
    runtime: &str,
    geckodriver: Option<&Path>,
    http_proxy: SocketAddr,
    socks5_proxy: SocketAddr,
) -> tokio::process::Child {
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_dig2browser-stationd"));
    command.args([
        "--pipe-name",
        pipe_name,
        "--profiles-root",
        profiles.to_str().expect("profiles path is UTF-8"),
        "--runtime",
        runtime,
        "--direct-route-ref",
        "host.direct",
        "--http-proxy-route",
        &format!("matrix.http={http_proxy}"),
        "--socks5-proxy-route",
        &format!("matrix.socks5={socks5_proxy}"),
        "--restart-after-pages",
        "0",
        "--max-resident",
        "1",
        "--max-in-flight",
        "2",
        "--max-connections",
        "4",
        "--timeout-seconds",
        "90",
        "--drain-seconds",
        "15",
        "--allow-remote-shutdown",
        "--allow-interactive-tasks",
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
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn route-matrix station")
}

async fn read_child_output(child: &mut tokio::process::Child) -> (String, String) {
    let mut stdout = String::new();
    if let Some(mut stream) = child.stdout.take() {
        stream.read_to_string(&mut stdout).await.expect("read station stdout");
    }
    let mut stderr = String::new();
    if let Some(mut stream) = child.stderr.take() {
        stream.read_to_string(&mut stderr).await.expect("read station stderr");
    }
    (stdout, stderr)
}

async fn route_e2e_serial_guard() -> tokio::sync::SemaphorePermit<'static> {
    static E2E_SERIAL: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);
    E2E_SERIAL
        .acquire()
        .await
        .expect("route E2E semaphore remains open")
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
    panic!("could not remove route E2E root: {}", path.display());
}
