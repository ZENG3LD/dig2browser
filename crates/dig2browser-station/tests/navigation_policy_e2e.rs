#![cfg(windows)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Stdio;
#[cfg(feature = "tls-test-hooks")]
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;
#[cfg(feature = "tls-test-hooks")]
use std::time::Instant;

use dig2browser::identity::ProfileOwnershipGuard;
use dig2browser_client::{
    BrowserPersona, ClientConfig, ClientError, CollectionTask, ResponseStatus,
    RuntimeFeature, RuntimeKind, RuntimeRequirements, RuntimeSelector, StationClient,
    TaskCapturePolicy, TaskReply, TaskRuntimeContract, TaskStep,
};
use dig2browser_station::ProfilesRootOwnership;
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
        Self::start_on("127.0.0.1", Arc::new(|_| {
            (
                "200 OK",
                Vec::new(),
                "<!doctype html><title>blocked origin</title>".to_owned(),
            )
        }))
    }

    fn peer_denied() -> Self {
        Self::start_on("127.0.0.2", Arc::new(|_| {
            (
                "200 OK",
                Vec::new(),
                "<!doctype html><title>peer denied</title>".to_owned(),
            )
        }))
    }

    fn allowed(blocked_origin: String) -> Self {
        Self::start_on("127.0.0.1", Arc::new(move |path| match path {
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

    fn webrtc_probe(stun_address: SocketAddr) -> Self {
        let page = r#"<!doctype html><html><head><title>WebRTC containment fixture</title><link rel="icon" href="data:,"></head><body><main id="webrtc-state">pending</main><script>(async()=>{const state=document.querySelector('#webrtc-state');if(typeof RTCPeerConnection!=='function'){state.textContent='api-missing';return;}const peer=new RTCPeerConnection({iceServers:[{urls:'stun:__STUN_ADDRESS__'}]});window.__dig2browserWebRtcProbe=peer;peer.createDataChannel('probe');try{const offer=await peer.createOffer();await peer.setLocalDescription(offer);state.textContent='ice-attempted:'+peer.iceGatheringState;}catch(error){state.textContent='ice-error:'+error.name;}})();</script></body></html>"#
            .replace("__STUN_ADDRESS__", &stun_address.to_string());
        Self::start_on("127.0.0.1", Arc::new(move |path| match path {
            "/webrtc-probe" => ("200 OK", Vec::new(), page.clone()),
            _ => ("404 Not Found", Vec::new(), String::new()),
        }))
    }

    fn start_on(bind_ip: &str, response: Responder) -> Self {
        let listener = TcpListener::bind((bind_ip, 0))
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
        format!("http://{}", self.address)
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

struct ControlledUdpReceiver {
    address: SocketAddr,
    datagrams: Arc<AtomicUsize>,
    stun_datagrams: Arc<AtomicUsize>,
    stopping: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl ControlledUdpReceiver {
    fn start() -> Self {
        let route_probe = UdpSocket::bind("0.0.0.0:0")
            .expect("bind local-interface route probe");
        route_probe
            .connect("192.0.2.1:9")
            .expect("select a local IPv4 interface for the STUN receiver");
        let local_ip = route_probe
            .local_addr()
            .expect("read selected local interface")
            .ip();
        assert!(
            !local_ip.is_loopback() && !local_ip.is_unspecified(),
            "WebRTC egress E2E requires a non-loopback local interface"
        );
        let socket = UdpSocket::bind((local_ip, 0))
            .expect("bind controlled WebRTC STUN receiver");
        let address = socket.local_addr().expect("read STUN receiver address");
        socket
            .set_nonblocking(true)
            .expect("make STUN receiver nonblocking");
        let datagrams = Arc::new(AtomicUsize::new(0));
        let stun_datagrams = Arc::new(AtomicUsize::new(0));
        let stopping = Arc::new(AtomicBool::new(false));
        let thread_datagrams = Arc::clone(&datagrams);
        let thread_stun_datagrams = Arc::clone(&stun_datagrams);
        let thread_stopping = Arc::clone(&stopping);
        let thread = thread::spawn(move || {
            let mut buffer = [0_u8; 2048];
            while !thread_stopping.load(Ordering::Acquire) {
                match socket.recv_from(&mut buffer) {
                    Ok((count, _peer)) => {
                        thread_datagrams.fetch_add(1, Ordering::AcqRel);
                        let declared_length = if count >= 4 {
                            usize::from(u16::from_be_bytes([buffer[2], buffer[3]]))
                        } else {
                            0
                        };
                        if count >= 20
                            && u16::from_be_bytes([buffer[0], buffer[1]]) == 0x0001
                            && declared_length % 4 == 0
                            && count == 20 + declared_length
                            && buffer[4..8] == [0x21, 0x12, 0xa4, 0x42]
                        {
                            thread_stun_datagrams.fetch_add(1, Ordering::AcqRel);
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("controlled STUN receiver failed: {error}"),
                }
            }
        });
        Self {
            address,
            datagrams,
            stun_datagrams,
            stopping,
            thread: Some(thread),
        }
    }

    fn address(&self) -> SocketAddr {
        self.address
    }

    fn datagram_count(&self) -> usize {
        self.datagrams.load(Ordering::Acquire)
    }

    fn stun_datagram_count(&self) -> usize {
        self.stun_datagrams.load(Ordering::Acquire)
    }

    fn prove_ready(&self) {
        let baseline = self.datagram_count();
        let sender = UdpSocket::bind((self.address.ip(), 0))
            .expect("bind controlled STUN receiver readiness sender");
        sender
            .send_to(b"dig2browser-udp-readiness", self.address)
            .expect("send STUN receiver readiness datagram");
        for _ in 0..100 {
            if self.datagram_count() > baseline {
                return;
            }
            thread::sleep(Duration::from_millis(5));
        }
        panic!("controlled STUN receiver did not observe its readiness datagram");
    }

    async fn wait_for_stun(&self, timeout: Duration) -> usize {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let count = self.stun_datagram_count();
            if count > 0 || tokio::time::Instant::now() >= deadline {
                return count;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
}

impl Drop for ControlledUdpReceiver {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
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

#[cfg(feature = "tls-test-hooks")]
const HTTPS_PAGE: &str = "<!doctype html><html><head><title>secure fixture</title><link rel=\"icon\" href=\"data:,\"></head><body><main id=\"secure\">pinned transport</main></body></html>";

#[cfg(feature = "tls-test-hooks")]
struct ControlledHttpsOrigin {
    address: SocketAddr,
    directory: PathBuf,
    certificate_spki: String,
    child: Child,
}

#[cfg(feature = "tls-test-hooks")]
impl ControlledHttpsOrigin {
    fn start(base: &Path) -> Self {
        let directory = base.join("https-fixture");
        std::fs::create_dir_all(&directory).expect("create HTTPS fixture directory");
        let openssl = openssl_executable();
        let key = directory.join("key.pem");
        let certificate = directory.join("certificate.pem");
        let public_key = directory.join("public-key.pem");
        let public_key_der = directory.join("public-key.der");
        let public_key_sha256 = directory.join("public-key.sha256");
        let public_key_sha256_base64 = directory.join("public-key.sha256.base64");
        run_openssl(
            &openssl,
            &[
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-sha256",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=127.0.0.1",
                "-addext",
                "subjectAltName=IP:127.0.0.1",
                "-keyout",
                key.to_str().expect("UTF-8 HTTPS key path"),
                "-out",
                certificate.to_str().expect("UTF-8 HTTPS certificate path"),
            ],
        );
        run_openssl(
            &openssl,
            &[
                "x509",
                "-in",
                certificate.to_str().expect("UTF-8 HTTPS certificate path"),
                "-pubkey",
                "-noout",
                "-out",
                public_key.to_str().expect("UTF-8 HTTPS public-key path"),
            ],
        );
        run_openssl(
            &openssl,
            &[
                "pkey",
                "-pubin",
                "-in",
                public_key.to_str().expect("UTF-8 HTTPS public-key path"),
                "-outform",
                "DER",
                "-out",
                public_key_der.to_str().expect("UTF-8 HTTPS DER path"),
            ],
        );
        run_openssl(
            &openssl,
            &[
                "dgst",
                "-sha256",
                "-binary",
                "-out",
                public_key_sha256.to_str().expect("UTF-8 HTTPS digest path"),
                public_key_der.to_str().expect("UTF-8 HTTPS DER path"),
            ],
        );
        run_openssl(
            &openssl,
            &[
                "base64",
                "-A",
                "-in",
                public_key_sha256.to_str().expect("UTF-8 HTTPS digest path"),
                "-out",
                public_key_sha256_base64
                    .to_str()
                    .expect("UTF-8 HTTPS base64 path"),
            ],
        );
        let certificate_spki = std::fs::read_to_string(&public_key_sha256_base64)
            .expect("read HTTPS SPKI SHA-256 base64");
        assert_eq!(certificate_spki.len(), 44, "canonical SHA-256 base64 length");
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{}",
            HTTPS_PAGE.len(),
            HTTPS_PAGE
        );
        std::fs::write(directory.join("secure"), response)
            .expect("write controlled HTTPS response");

        let listener = TcpListener::bind("127.0.0.1:0").expect("reserve HTTPS fixture port");
        let address = listener.local_addr().expect("HTTPS fixture address");
        drop(listener);
        let child = Command::new(&openssl)
            .args([
                "s_server",
                "-4",
                "-accept",
                &format!("127.0.0.1:{}", address.port()),
                "-cert",
                certificate.to_str().expect("UTF-8 HTTPS certificate path"),
                "-key",
                key.to_str().expect("UTF-8 HTTPS key path"),
                "-HTTP",
                "-quiet",
            ])
            .current_dir(&directory)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start controlled OpenSSL HTTPS fixture");
        let mut fixture = Self {
            address,
            directory,
            certificate_spki,
            child,
        };
        fixture.wait_until_ready();
        fixture
    }

    fn origin(&self) -> String {
        format!("https://{}", self.address)
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.origin())
    }

    fn certificate_spki(&self) -> &str {
        &self.certificate_spki
    }

    fn wait_until_ready(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if self.child.try_wait().expect("poll HTTPS fixture").is_some() {
                panic!("OpenSSL HTTPS fixture exited before accepting connections");
            }
            if let Ok(stream) = TcpStream::connect_timeout(
                &self.address,
                Duration::from_millis(100),
            ) {
                drop(stream);
                return;
            }
            assert!(
                Instant::now() < deadline,
                "OpenSSL HTTPS fixture did not bind its controlled listener"
            );
            thread::sleep(Duration::from_millis(25));
        }
    }
}

#[cfg(feature = "tls-test-hooks")]
impl Drop for ControlledHttpsOrigin {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

#[cfg(feature = "tls-test-hooks")]
fn openssl_executable() -> PathBuf {
    if let Some(path) = std::env::var_os("DIG2BROWSER_OPENSSL") {
        return PathBuf::from(path);
    }
    let git_openssl = PathBuf::from(r"C:\Program Files\Git\mingw64\bin\openssl.exe");
    if git_openssl.is_file() {
        return git_openssl;
    }
    PathBuf::from("openssl")
}

#[cfg(feature = "tls-test-hooks")]
fn run_openssl(executable: &Path, arguments: &[&str]) {
    let output = Command::new(executable)
        .args(arguments)
        .stdin(Stdio::null())
        .output()
        .expect("run OpenSSL fixture command");
    assert!(
        output.status.success(),
        "OpenSSL fixture command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stationd_remote_shutdown_at_connection_capacity_exits_e2e() {
    let unique = uuid::Uuid::new_v4();
    let pipe_name = format!("dig2browser-capacity-shutdown-{unique}");
    let profiles = e2e_temp_base().join(format!("dig2browser-capacity-shutdown-{unique}"));
    std::fs::create_dir_all(&profiles).expect("create capacity-shutdown profiles root");
    let mut daemon = spawn_capacity_shutdown_stationd(&pipe_name, &profiles);
    let client = connect(&pipe_name).await;

    client
        .shutdown()
        .await
        .expect("request shutdown while the only connection slot is occupied");
    let status = tokio::time::timeout(Duration::from_secs(15), daemon.wait())
        .await
        .expect("station did not exit after capacity-bound remote shutdown")
        .expect("wait for capacity-shutdown station");
    assert!(status.success(), "capacity-shutdown station failed: {status}");
    let (stdout, stderr) = read_child_output(&mut daemon).await;
    assert!(stderr.is_empty(), "capacity-shutdown station wrote stderr: {stderr}");
    let report: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("parse capacity-shutdown station report");
    assert_eq!(report["outcome"], "clean", "unclean station report: {stdout}");
    assert_eq!(report["stop_reason"], "remote_request");
    assert_eq!(report["accepted_connections"], 1);
    assert_eq!(report["completed_connections"], 1);
    assert_eq!(report["aborted_connections"], 0);

    let released_profiles = ProfilesRootOwnership::acquire(&profiles)
        .expect("capacity-shutdown station releases profiles-root ownership");
    drop(released_profiles);
    remove_tree(&profiles).await;
}

#[cfg(feature = "tls-test-hooks")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stationd_rejects_malformed_test_certificate_error_spki_before_profile_acquisition() {
    let unique = uuid::Uuid::new_v4();
    let pipe_name = format!("dig2browser-invalid-spki-{unique}");
    let profiles = e2e_temp_base().join(format!("dig2browser-invalid-spki-{unique}"));
    assert!(!profiles.exists(), "invalid-config profile fixture must start absent");
    let mut daemon = spawn_https_stationd(
        &pipe_name,
        &profiles,
        "https://127.0.0.1:443",
        Some("AA=="),
    );
    let status = tokio::time::timeout(Duration::from_secs(15), daemon.wait())
        .await
        .expect("invalid SPKI station exit timeout")
        .expect("wait for invalid SPKI station");
    assert!(!status.success(), "invalid SPKI station unexpectedly started");
    let (stdout, stderr) = read_child_output(&mut daemon).await;
    assert!(stdout.is_empty(), "invalid SPKI station wrote stdout: {stdout}");
    assert!(
        stderr.contains("\"error_class\":\"invalid_config\""),
        "invalid SPKI station returned wrong error: {stderr}"
    );
    assert!(
        !profiles.exists(),
        "invalid SPKI configuration acquired or created the profiles root"
    );
}

#[cfg(feature = "tls-test-hooks")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires installed Chrome, OpenSSL, and --features tls-test-hooks"]
async fn stationd_chrome_spki_certificate_exception_reaches_https_through_owned_connect_e2e() {
    let _serial = e2e_serial_guard().await;
    let unique = uuid::Uuid::new_v4();
    let base = e2e_temp_base().join(format!("dig2browser-https-spki-{unique}"));
    std::fs::create_dir_all(&base).expect("create HTTPS SPKI E2E root");
    let https = ControlledHttpsOrigin::start(&base);

    let pinned_pipe = format!("dig2browser-https-pinned-{unique}");
    let pinned_profiles = base.join("profiles-pinned");
    std::fs::create_dir_all(&pinned_profiles).expect("create pinned profiles root");
    let mut pinned_daemon = spawn_https_stationd(
        &pinned_pipe,
        &pinned_profiles,
        &https.origin(),
        Some(https.certificate_spki()),
    );
    let pinned_client = connect(&pinned_pipe).await;
    let requested_url = https.url("/secure");
    let result = pinned_client
        .run_task("https-pinned", https_task(requested_url.clone()))
        .await
        .expect("exact SPKI certificate exception must allow the controlled HTTPS document");
    assert_eq!(result.replies().len(), 3);
    assert_eq!(result.replies()[0], TaskReply::Acknowledged);
    assert_eq!(
        result.replies()[1],
        TaskReply::Text("pinned transport".to_owned())
    );
    let TaskReply::Capture(capture) = &result.replies()[2] else {
        panic!("pinned HTTPS task did not return an HTML capture");
    };
    assert_eq!(capture.requested_url, requested_url);
    assert_eq!(capture.final_url, requested_url);
    assert_eq!(capture.http_status, Some(200));
    assert_eq!(capture.title, "secure fixture");
    assert!(
        String::from_utf8_lossy(&capture.html).contains("pinned transport"),
        "HTML capture did not contain the controlled HTTPS marker"
    );
    pinned_client
        .shutdown()
        .await
        .expect("request clean pinned station shutdown");
    drop(pinned_client);
    assert_https_clean_exit(&mut pinned_daemon).await;
    let released_profiles = ProfilesRootOwnership::acquire(&pinned_profiles)
        .expect("clean HTTPS station shutdown releases profiles-root ownership");
    let released_profile = ProfileOwnershipGuard::acquire(pinned_profiles.join("https-pinned"))
        .expect("clean HTTPS station shutdown releases the browser profile");
    drop(released_profile);
    drop(released_profiles);
    drop(https);

    remove_tree(&base).await;
}

// This is a truth regression for the current browser-only mitigation. It must
// be replaced by a zero-datagram acceptance test when OS-level isolation lands.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires installed Chrome; proves the known browser-only WebRTC UDP gap"]
async fn stationd_chrome_exact_route_detects_direct_webrtc_stun_udp_gap_e2e() {
    let _serial = e2e_serial_guard().await;
    let unique = uuid::Uuid::new_v4();
    let profiles = e2e_temp_base().join(format!("dig2browser-webrtc-{unique}"));
    let traces = e2e_temp_base().join(format!("dig2browser-webrtc-trace-{unique}"));
    std::fs::create_dir_all(&profiles).expect("create WebRTC profiles root");
    std::fs::create_dir_all(&traces).expect("create WebRTC trace root");
    let udp = ControlledUdpReceiver::start();
    udp.prove_ready();
    let origin = ControlledOrigin::webrtc_probe(udp.address());
    let pipe_name = format!("dig2browser-webrtc-{unique}");
    let allowed_origin = origin.origin();
    let mut daemon = spawn_stationd(
        &pipe_name,
        &profiles,
        &traces,
        "chrome",
        &[&allowed_origin],
    );
    let client = connect(&pipe_name).await;
    let profile_id = "webrtc-browser-containment";
    let requested_url = origin.url("/webrtc-probe");

    let result = client
        .run_task(profile_id, webrtc_probe_task(requested_url.clone()))
        .await
        .expect("exact Chrome route must complete the controlled WebRTC page task");
    assert_eq!(result.replies().len(), 4);
    assert_eq!(result.replies()[0], TaskReply::Acknowledged);
    assert_eq!(result.replies()[1], TaskReply::Acknowledged);
    let TaskReply::Text(ice_state) = &result.replies()[2] else {
        panic!("WebRTC page did not return its ICE state");
    };
    assert!(
        ice_state.starts_with("ice-attempted:"),
        "WebRTC API/ICE attempt did not actually run: {ice_state}"
    );
    let TaskReply::Capture(capture) = &result.replies()[3] else {
        panic!("WebRTC task did not return an HTML capture");
    };
    assert_eq!(capture.requested_url, requested_url);
    assert_eq!(capture.final_url, requested_url);
    assert_eq!(capture.http_status, Some(200));
    assert_eq!(capture.title, "WebRTC containment fixture");
    assert!(
        String::from_utf8_lossy(&capture.html).contains("webrtc-state"),
        "WebRTC capture did not contain the controlled page marker"
    );

    let stun_datagrams = udp.wait_for_stun(Duration::from_secs(5)).await;
    assert!(
        stun_datagrams >= 1,
        "Chrome no longer emitted direct STUN; replace this gap regression with a zero-datagram containment acceptance test"
    );

    client.shutdown().await.expect("request clean WebRTC station shutdown");
    drop(client);
    assert_webrtc_clean_exit(&mut daemon).await;
    let released_profiles = ProfilesRootOwnership::acquire(&profiles)
        .expect("clean WebRTC station shutdown releases profiles-root ownership");
    let released_profile = ProfileOwnershipGuard::acquire(profiles.join(profile_id))
        .expect("clean WebRTC station shutdown releases the browser profile");
    drop(released_profile);
    drop(released_profiles);
    drop(origin);
    drop(udp);

    remove_tree(&profiles).await;
    remove_tree(&traces).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stationd_enforces_exact_origin_url_policy_across_runtime_targets_e2e() {
    let _serial = e2e_serial_guard().await;
    let blocked = ControlledOrigin::blocked();
    let peer_denied = ControlledOrigin::peer_denied();
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
        let allowed_origin = allowed.origin();
        let peer_denied_origin = peer_denied.origin();
        let mut daemon = spawn_stationd(
            &pipe_name,
            &profiles,
            &traces,
            runtime_name,
            &[&allowed_origin, &peer_denied_origin],
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

        let peer_denied_before = peer_denied.request_count();
        let peer_error = client
            .run_task(
                &profile_id,
                navigation_task(runtime_kind, peer_denied.url("/peer-policy")),
            )
            .await
            .expect_err("station proxy must reject an origin-allowed peer");
        assert_remote(
            peer_error,
            ResponseStatus::CaptureFailed,
            "task failed at step 0",
        );
        assert_eq!(
            peer_denied.request_count(),
            peer_denied_before,
            "{runtime_name} bypassed the station proxy for a denied loopback peer"
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

#[cfg(feature = "tls-test-hooks")]
fn https_task(url: String) -> CollectionTask {
    task(
        RuntimeKind::Chrome,
        vec![
            TaskStep::Navigate { url },
            TaskStep::ReadSelectorText {
                selector: "#secure".to_owned(),
            },
            TaskStep::Capture {
                policy: TaskCapturePolicy::HtmlOnly,
            },
        ],
        vec![
            RuntimeFeature::Navigate,
            RuntimeFeature::DomInspect,
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

fn webrtc_probe_task(url: String) -> CollectionTask {
    task(
        RuntimeKind::Chrome,
        vec![
            TaskStep::Navigate { url },
            TaskStep::Wait {
                duration: Duration::from_millis(1_500),
            },
            TaskStep::ReadSelectorText {
                selector: "#webrtc-state".to_owned(),
            },
            TaskStep::Capture {
                policy: TaskCapturePolicy::HtmlOnly,
            },
        ],
        vec![
            RuntimeFeature::Navigate,
            RuntimeFeature::DomInspect,
            RuntimeFeature::CaptureState,
            RuntimeFeature::CaptureHtml,
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
    allowed_origins: &[&str],
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
    for origin in allowed_origins {
        command.args(["--allow-origin", origin]);
    }
    command.args(["--allow-private-peer", "127.0.0.1"]);
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
        .expect("spawn navigation-policy station")
}

fn spawn_capacity_shutdown_stationd(
    pipe_name: &str,
    profiles: &Path,
) -> tokio::process::Child {
    let mut command = tokio::process::Command::new(
        env!("CARGO_BIN_EXE_dig2browser-stationd"),
    );
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
        "1",
        "--max-connections",
        "1",
        "--timeout-seconds",
        "10",
        "--drain-seconds",
        "2",
        "--allow-remote-shutdown",
    ]);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn capacity-shutdown station")
}

#[cfg(feature = "tls-test-hooks")]
fn spawn_https_stationd(
    pipe_name: &str,
    profiles: &Path,
    allowed_origin: &str,
    certificate_spki: Option<&str>,
) -> tokio::process::Child {
    let mut command = tokio::process::Command::new(
        env!("CARGO_BIN_EXE_dig2browser-stationd"),
    );
    command.args([
        "--pipe-name",
        pipe_name,
        "--profiles-root",
        profiles.to_str().expect("profiles path is UTF-8"),
        "--runtime",
        "chrome",
        "--allow-origin",
        allowed_origin,
        "--allow-private-peer",
        "127.0.0.1",
        "--max-resident",
        "1",
        "--max-in-flight",
        "1",
        "--max-connections",
        "1",
        "--timeout-seconds",
        "10",
        "--drain-seconds",
        "2",
        "--allow-remote-shutdown",
        "--allow-interactive-tasks",
    ]);
    if let Some(certificate_spki) = certificate_spki {
        command.args([
            "--test-chrome-certificate-error-spki-sha256",
            certificate_spki,
        ]);
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
        .expect("spawn HTTPS policy station")
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
    let report: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("parse policy station exit report");
    assert!(
        report["egress_completed_connections"]
            .as_u64()
            .is_some_and(|count| count >= 1),
        "policy station did not report a completed egress connection: {stdout}"
    );
    assert!(
        report["egress_denied_connections"]
            .as_u64()
            .is_some_and(|count| count >= 1),
        "policy station did not report a denied egress connection: {stdout}"
    );
}

async fn assert_webrtc_clean_exit(daemon: &mut tokio::process::Child) {
    let status = tokio::time::timeout(Duration::from_secs(30), daemon.wait())
        .await
        .expect("WebRTC policy station exit timeout")
        .expect("wait for WebRTC policy station");
    assert!(status.success(), "WebRTC policy station failed: {status}");
    let (stdout, stderr) = read_child_output(daemon).await;
    assert!(stderr.is_empty(), "WebRTC policy station wrote stderr: {stderr}");
    let report: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("parse WebRTC station exit report");
    assert_eq!(report["outcome"], "clean", "unclean station report: {stdout}");
    assert_eq!(report["stop_reason"], "remote_request");
    assert_eq!(report["stopped_workers"], 1);
    let accepted = report["egress_accepted_connections"]
        .as_u64()
        .expect("accepted WebRTC egress count");
    assert!(accepted >= 1, "WebRTC station accepted no egress connections: {stdout}");
    let classified: u64 = [
        "egress_completed_connections",
        "egress_denied_connections",
        "egress_invalid_connections",
        "egress_failed_connections",
        "egress_timed_out_connections",
        "egress_aborted_connections",
    ]
    .iter()
    .map(|counter| report[*counter].as_u64().expect("classified WebRTC egress count"))
    .sum();
    assert_eq!(accepted, classified, "unaccounted WebRTC egress connection: {stdout}");
    assert!(
        report["egress_completed_connections"]
            .as_u64()
            .is_some_and(|count| count >= 1),
        "WebRTC station did not complete the controlled HTTP request: {stdout}"
    );
    assert_eq!(report["egress_failed_connections"], 0);
    assert_eq!(report["egress_timed_out_connections"], 0);
    assert_eq!(report["egress_drain_timed_out"], false);
}

#[cfg(feature = "tls-test-hooks")]
async fn assert_https_clean_exit(daemon: &mut tokio::process::Child) {
    let status = tokio::time::timeout(Duration::from_secs(30), daemon.wait())
        .await
        .expect("HTTPS policy station exit timeout")
        .expect("wait for HTTPS policy station");
    assert!(status.success(), "HTTPS policy station failed: {status}");
    let (stdout, stderr) = read_child_output(daemon).await;
    assert!(stderr.is_empty(), "HTTPS policy station wrote stderr: {stderr}");
    let report: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("parse HTTPS station exit report");
    assert_eq!(report["outcome"], "clean", "unclean station report: {stdout}");
    assert_eq!(report["stop_reason"], "remote_request");
    assert_eq!(report["stopped_workers"], 1);
    assert!(
        report["egress_accepted_connections"]
            .as_u64()
            .is_some_and(|count| count >= 1),
        "HTTPS station did not own a CONNECT tunnel: {stdout}"
    );
    assert!(
        report["egress_completed_connections"]
            .as_u64()
            .is_some_and(|count| count >= 1),
        "HTTPS station did not complete a CONNECT tunnel: {stdout}"
    );
    let accepted = report["egress_accepted_connections"]
        .as_u64()
        .expect("accepted egress count");
    let classified = [
        "egress_completed_connections",
        "egress_denied_connections",
        "egress_invalid_connections",
        "egress_failed_connections",
        "egress_timed_out_connections",
        "egress_aborted_connections",
    ]
    .iter()
    .map(|counter| report[*counter].as_u64().expect("classified egress count"))
    .sum::<u64>();
    assert_eq!(accepted, classified, "unaccounted egress connection: {stdout}");
    for counter in ["egress_failed_connections", "egress_timed_out_connections"] {
        assert_eq!(report[counter], 0, "dirty {counter} counter: {stdout}");
    }
    assert_eq!(report["egress_drain_timed_out"], false);
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
