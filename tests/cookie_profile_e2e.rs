#![cfg(windows)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dig2browser::browser::{Cookie, CookieJar, StealthBrowser, StealthPage};
use dig2browser::detect::{BrowserProfile, LaunchConfig};
use dig2browser::stealth::StealthConfig;
use base64::Engine;
use sha2::{Digest, Sha256};

const SERVER_COOKIE_NAME: &str = "dig2browser_server_cookie_e2e";
const SERVER_COOKIE_VALUE: &str = "server-synthetic-secret";
const CDP_COOKIE_NAME: &str = "dig2browser_cdp_cookie_e2e";
const CDP_COOKIE_VALUE: &str = "cdp-synthetic-secret";
const SECURE_COOKIE_NAME: &str = "dig2browser_secure_cookie_e2e";
const SECURE_COOKIE_VALUE: &str = "secure-synthetic-secret";

struct FixtureServer {
    address: SocketAddr,
    requests_with_both_cookies: Arc<AtomicUsize>,
    issue_server_cookie: Arc<AtomicBool>,
    stopping: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl FixtureServer {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind cookie fixture");
        let address = listener.local_addr().expect("cookie fixture address");
        listener
            .set_nonblocking(true)
            .expect("make cookie fixture nonblocking");
        let requests_with_both_cookies = Arc::new(AtomicUsize::new(0));
        let issue_server_cookie = Arc::new(AtomicBool::new(true));
        let stopping = Arc::new(AtomicBool::new(false));
        let thread_cookie_requests = Arc::clone(&requests_with_both_cookies);
        let thread_issue_server_cookie = Arc::clone(&issue_server_cookie);
        let thread_stopping = Arc::clone(&stopping);
        let thread = thread::spawn(move || {
            while !thread_stopping.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let cookie_requests = Arc::clone(&thread_cookie_requests);
                        let issue_server_cookie = Arc::clone(&thread_issue_server_cookie);
                        thread::spawn(move || {
                            let _ = serve_connection(
                                stream,
                                &cookie_requests,
                                issue_server_cookie.load(Ordering::Acquire),
                            );
                        });
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("cookie fixture listener failed: {error}"),
                }
            }
        });
        Self {
            address,
            requests_with_both_cookies,
            issue_server_cookie,
            stopping,
            thread: Some(thread),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://localhost:{}{path}", self.address.port())
    }

    fn requests_with_both_cookies(&self) -> usize {
        self.requests_with_both_cookies.load(Ordering::Acquire)
    }

    fn stop_issuing_server_cookie(&self) {
        self.issue_server_cookie.store(false, Ordering::Release);
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

struct HttpsFixture {
    address: SocketAddr,
    directory: PathBuf,
    response_path: PathBuf,
    certificate_spki: String,
    child: Child,
}

impl HttpsFixture {
    fn start(base: &Path) -> Self {
        let directory = base.join("https-fixture");
        std::fs::create_dir_all(&directory).expect("create HTTPS fixture directory");
        let openssl = openssl_executable();
        let key = directory.join("key.pem");
        let certificate = directory.join("certificate.pem");
        let public_key = directory.join("public-key.pem");
        let public_key_der = directory.join("public-key.der");
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
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost,IP:127.0.0.1",
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
        let certificate_spki = base64::engine::general_purpose::STANDARD.encode(
            Sha256::digest(std::fs::read(&public_key_der).expect("read HTTPS SPKI")),
        );
        let listener = TcpListener::bind("127.0.0.1:0").expect("reserve HTTPS fixture port");
        let address = listener.local_addr().expect("HTTPS fixture address");
        drop(listener);
        let response_path = directory.join("account");
        write_https_response(&response_path, true);
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
            .expect("start OpenSSL HTTPS fixture");
        let mut fixture = Self {
            address,
            directory,
            response_path,
            certificate_spki,
            child,
        };
        fixture.wait_until_ready();
        fixture
    }

    fn url(&self) -> String {
        format!("https://localhost:{}/account", self.address.port())
    }

    fn browser_argument(&self) -> String {
        format!(
            "--ignore-certificate-errors-spki-list={}",
            self.certificate_spki
        )
    }

    fn stop_issuing_cookie(&self) {
        write_https_response(&self.response_path, false);
    }

    fn wait_until_ready(&mut self) {
        for _ in 0..100 {
            if self.child.try_wait().expect("poll HTTPS fixture").is_some() {
                panic!("OpenSSL HTTPS fixture exited before accepting connections");
            }
            if TcpStream::connect_timeout(&self.address, Duration::from_millis(50)).is_ok() {
                return;
            }
            thread::sleep(Duration::from_millis(25));
        }
        panic!("OpenSSL HTTPS fixture did not accept connections");
    }
}

impl Drop for HttpsFixture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

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

fn run_openssl(executable: &Path, arguments: &[&str]) {
    let output = Command::new(executable)
        .args(arguments)
        .stdin(Stdio::null())
        .output()
        .expect("run OpenSSL HTTPS fixture command");
    assert!(
        output.status.success(),
        "OpenSSL HTTPS fixture command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn write_https_response(path: &Path, issue_cookie: bool) {
    let body = "<!doctype html><title>secure-cookie-e2e</title><main data-ready>ready</main>";
    let set_cookie = if issue_cookie {
        format!(
            "Set-Cookie: {SECURE_COOKIE_NAME}={SECURE_COOKIE_VALUE}; Path=/; Max-Age=3600; Secure; HttpOnly; SameSite=Lax\r\n"
        )
    } else {
        String::new()
    };
    std::fs::write(
        path,
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n{set_cookie}Content-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{body}",
            body.len()
        ),
    )
    .expect("write HTTPS fixture response");
}

fn serve_connection(
    mut stream: TcpStream,
    requests_with_both_cookies: &AtomicUsize,
    issue_server_cookie: bool,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut request = Vec::with_capacity(4_096);
    loop {
        let mut chunk = [0_u8; 1_024];
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
                "cookie fixture request headers exceed limit",
            ));
        }
    }
    let request = String::from_utf8_lossy(&request);
    let has_server_cookie = request.contains(&format!(
        "{SERVER_COOKIE_NAME}={SERVER_COOKIE_VALUE}"
    ));
    let has_cdp_cookie = request.contains(&format!("{CDP_COOKIE_NAME}={CDP_COOKIE_VALUE}"));
    if has_server_cookie && has_cdp_cookie {
        requests_with_both_cookies.fetch_add(1, Ordering::AcqRel);
    }
    let body = "<!doctype html><title>cookie-profile-e2e</title><main data-ready>ready</main>";
    let set_cookie = if issue_server_cookie {
        format!(
            "Set-Cookie: {SERVER_COOKIE_NAME}={SERVER_COOKIE_VALUE}; Path=/; Max-Age=3600; HttpOnly; SameSite=Lax\r\n"
        )
    } else {
        String::new()
    };
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n{set_cookie}Content-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes())
}

fn launch_config(profile: &Path, headless: bool) -> LaunchConfig {
    LaunchConfig {
        headless,
        profile: BrowserProfile::Persistent(profile.to_path_buf()),
        ..LaunchConfig::default()
    }
}

fn assert_cookie(
    jar: &CookieJar,
    name: &str,
    expected_value: &str,
    expected_secure: bool,
    expected_http_only: bool,
) {
    let cookie = jar
        .iter()
        .find(|cookie| cookie.name == name)
        .unwrap_or_else(|| panic!("missing synthetic cookie {name}: {jar:?}"));
    assert_eq!(cookie.value, expected_value);
    assert_eq!(cookie.domain, "localhost");
    assert_eq!(cookie.path, "/");
    assert_eq!(cookie.is_secure, expected_secure);
    assert_eq!(cookie.is_httponly, expected_http_only);
    assert!(cookie.expires_utc.is_some());
}

fn e2e_profile() -> PathBuf {
    let base = std::env::var_os("DIG2BROWSER_E2E_TMP")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\tmp"));
    base.join(format!(
        "dig2browser-cookie-profile-e2e-{}",
        uuid::Uuid::new_v4()
    ))
}

async fn remove_profile(path: &Path) {
    for _ in 0..30 {
        match std::fs::remove_dir_all(path) {
            Ok(()) => return,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    panic!("could not remove cookie E2E profile: {}", path.display());
}

async fn goto_ready(page: &StealthPage, url: &str) {
    let first = page
        .goto_and_wait(url, "[data-ready]", Duration::from_secs(15))
        .await;
    if first.is_err() {
        tokio::time::sleep(Duration::from_millis(100)).await;
        page.goto_and_wait(url, "[data-ready]", Duration::from_secs(15))
            .await
            .expect("load cookie fixture after one idempotent retry");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn visible_to_headless_profile_preserves_exact_cookie_values_e2e() {
    let fixture = FixtureServer::start();
    let profile = e2e_profile();
    std::fs::create_dir_all(&profile).expect("create cookie E2E profile");
    let url = fixture.url("/account");

    let visible = StealthBrowser::launch_with(
        launch_config(&profile, false),
        StealthConfig::default(),
    )
    .await
    .expect("launch visible Chromium");
    let page = visible
        .new_blank_page()
        .await
        .expect("create visible cookie page");
    goto_ready(&page, &url).await;
    assert_cookie(
        &page.get_cookies().await.expect("read live server cookie"),
        SERVER_COOKIE_NAME,
        SERVER_COOKIE_VALUE,
        false,
        true,
    );

    let expires = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs()
        .saturating_add(3_600);
    page.set_cookies(&CookieJar(vec![Cookie {
        name: CDP_COOKIE_NAME.to_owned(),
        value: CDP_COOKIE_VALUE.to_owned(),
        domain: "localhost".to_owned(),
        path: "/".to_owned(),
        is_secure: false,
        is_httponly: true,
        expires_utc: Some(i64::try_from(expires).expect("cookie expiry fits i64")),
    }]))
    .await
    .expect("set synthetic CDP cookie");
    let live = page.get_cookies().await.expect("read both live cookies");
    assert_cookie(&live, SERVER_COOKIE_NAME, SERVER_COOKIE_VALUE, false, true);
    assert_cookie(&live, CDP_COOKIE_NAME, CDP_COOKIE_VALUE, false, true);
    goto_ready(&page, &url).await;
    assert!(fixture.requests_with_both_cookies() >= 1);
    drop(page);
    visible.close().await.expect("close visible Chromium");
    fixture.stop_issuing_server_cookie();
    tokio::time::sleep(Duration::from_secs(2)).await;

    let cookie_db = profile.join("Default").join("Network").join("Cookies");
    assert!(cookie_db.is_file(), "persistent cookie DB was not created");

    let headless = StealthBrowser::launch_with(
        launch_config(&profile, true),
        StealthConfig::default(),
    )
    .await
    .expect("launch headless successor Chromium");
    let successor_page = headless
        .new_blank_page()
        .await
        .expect("create successor cookie page");
    goto_ready(&successor_page, &url).await;
    let persisted = successor_page
        .get_cookies()
        .await
        .expect("read persisted cookies through CDP");
    assert_cookie(
        &persisted,
        SERVER_COOKIE_NAME,
        SERVER_COOKIE_VALUE,
        false,
        true,
    );
    assert_cookie(
        &persisted,
        CDP_COOKIE_NAME,
        CDP_COOKIE_VALUE,
        false,
        true,
    );
    assert!(fixture.requests_with_both_cookies() >= 2);
    drop(successor_page);
    headless.close().await.expect("close headless successor");

    remove_profile(&profile).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn visible_to_headless_profile_preserves_secure_https_cookie_e2e() {
    let profile = e2e_profile();
    std::fs::create_dir_all(&profile).expect("create secure-cookie E2E profile");
    let fixture = HttpsFixture::start(&profile);
    let mut visible_config = launch_config(&profile, false);
    visible_config.extra_args.push(fixture.browser_argument());

    let visible = StealthBrowser::launch_with(visible_config, StealthConfig::default())
        .await
        .expect("launch visible Chromium for HTTPS cookie");
    let page = visible
        .new_blank_page()
        .await
        .expect("create visible HTTPS cookie page");
    goto_ready(&page, &fixture.url()).await;
    assert_cookie(
        &page
            .get_cookies()
            .await
            .expect("read live Secure HTTPS cookie"),
        SECURE_COOKIE_NAME,
        SECURE_COOKIE_VALUE,
        true,
        true,
    );
    drop(page);
    visible
        .close()
        .await
        .expect("close visible HTTPS Chromium");
    fixture.stop_issuing_cookie();

    let cookie_db = profile.join("Default").join("Network").join("Cookies");
    assert!(cookie_db.is_file(), "persistent HTTPS cookie DB was not created");

    let mut successor_config = launch_config(&profile, true);
    successor_config.extra_args.push(fixture.browser_argument());
    let headless = StealthBrowser::launch_with(successor_config, StealthConfig::default())
        .await
        .expect("launch headless HTTPS successor");
    let successor_page = headless
        .new_blank_page()
        .await
        .expect("create successor HTTPS page");
    goto_ready(&successor_page, &fixture.url()).await;
    assert_cookie(
        &successor_page
            .get_cookies()
            .await
            .expect("read persisted Secure HTTPS cookie"),
        SECURE_COOKIE_NAME,
        SECURE_COOKIE_VALUE,
        true,
        true,
    );
    drop(successor_page);
    headless
        .close()
        .await
        .expect("close headless HTTPS successor");

    drop(fixture);
    remove_profile(&profile).await;
}
