#![cfg(windows)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dig2browser::browser::{Cookie, CookieJar, StealthBrowser, StealthPage};
use dig2browser::detect::{BrowserProfile, LaunchConfig};
use dig2browser::stealth::StealthConfig;

const SERVER_COOKIE_NAME: &str = "dig2browser_server_cookie_e2e";
const SERVER_COOKIE_VALUE: &str = "server-synthetic-secret";
const CDP_COOKIE_NAME: &str = "dig2browser_cdp_cookie_e2e";
const CDP_COOKIE_VALUE: &str = "cdp-synthetic-secret";

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
    expected_http_only: bool,
) {
    let cookie = jar
        .iter()
        .find(|cookie| cookie.name == name)
        .unwrap_or_else(|| panic!("missing synthetic cookie {name}: {jar:?}"));
    assert_eq!(cookie.value, expected_value);
    assert_eq!(cookie.domain, "localhost");
    assert_eq!(cookie.path, "/");
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
    assert_cookie(&live, SERVER_COOKIE_NAME, SERVER_COOKIE_VALUE, true);
    assert_cookie(&live, CDP_COOKIE_NAME, CDP_COOKIE_VALUE, true);
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
        true,
    );
    assert_cookie(&persisted, CDP_COOKIE_NAME, CDP_COOKIE_VALUE, true);
    assert!(fixture.requests_with_both_cookies() >= 2);
    drop(successor_page);
    headless.close().await.expect("close headless successor");

    remove_profile(&profile).await;
}
