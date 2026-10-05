//! Two-way browser stream machine.
//!
//! This process owns Chrome. Frame bytes leave as native CDP screenshots.
//! Mouse and keyboard bytes come back and are applied on that same Chrome
//! with `Input.dispatchMouseEvent` / `Input.dispatchKeyEvent`. The profile
//! (cookies included) stays on the node. The peer is always C2: this module
//! has no HQ address and does not accept a dial from HQ.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use tokio::sync::mpsc;

use crate::browser::{
    BrowserError, BrowserPreference, BrowserProfile, LaunchConfig, StealthBrowser, StealthConfig,
    StealthPage,
};
use crate::detect::args::RendererSandboxMode;

/// Local page the node itself serves. Chrome paints this. It is not a
/// third-party login page.
pub const LOCAL_PAGE_HTML: &str = r#"<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>DIG2BROWSER LOCAL STREAM PAGE</title>
<style>
  html, body { margin: 0; height: 100%; background: #0b3d2e; color: #f4f1de;
    font-family: sans-serif; }
  h1 { margin: 24px; font-size: 42px; }
  #count { margin-left: 24px; font-size: 28px; }
</style>
</head>
<body>
<h1>DIG2BROWSER LOCAL STREAM PAGE</h1>
<p id="count">clicks: 0</p>
<script>
document.addEventListener('click', function (e) {
  var n = (window.__clicks || 0) + 1;
  window.__clicks = n;
  document.getElementById('count').textContent =
    'clicks: ' + n + ' at ' + e.clientX + ',' + e.clientY + ' button ' + e.button;
  document.title = 'clicks=' + n;
}, true);
</script>
</body>
</html>
"#;


/// Local login form the node serves when a remote login page does not paint
/// a usable email + password form. The banner says this is not claude.ai.
pub const LOGIN_PAGE_HTML: &str = r#"<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>LOCAL LOGIN FORM</title>
<style>
  html, body { margin: 0; height: 100%; background: #10243a; color: #f4f1de;
    font-family: sans-serif; }
  .banner { background: #f2c14e; color: #1a1a1a; font-size: 28px; font-weight: 700;
    padding: 16px 24px; }
  .sub { margin: 8px 24px 0; font-size: 16px; }
  form { margin: 28px 24px; width: 480px; }
  label { display: block; font-size: 18px; margin: 14px 0 6px; }
  input { display: block; width: 460px; height: 48px; font-size: 20px; padding: 0 12px;
    box-sizing: border-box; border: 2px solid #8aa; background: #fff; color: #111; }
  input:focus { outline: 6px solid #ffe600; background: #fff3a0; border-color: #111; }
  button { margin-top: 18px; height: 52px; min-width: 200px; font-size: 22px;
    background: #e85d04; color: white; border: 0; cursor: pointer; }
  button:focus { outline: 6px solid #ffe600; }
  #error { min-height: 56px; margin: 18px 24px; font-size: 32px; font-weight: 700;
    color: #ff5a5a; }
  #status { margin: 0 24px; font-size: 20px; }
</style>
</head>
<body data-kind="local-login-form">
<div class="banner">LOCAL LOGIN FORM — not claude.ai</div>
<p class="sub">Served by the node on this machine. This page never sends credentials.</p>
<form id="login">
  <label for="email">Email</label>
  <input id="email" name="email" type="email" autocomplete="username">
  <label for="password">Password</label>
  <input id="password" name="password" type="password" autocomplete="current-password">
  <button id="signin" type="submit">Sign in</button>
</form>
<div id="error"></div>
<div id="status">submits: 0</div>
<script>
document.getElementById('login').addEventListener('submit', function (e) {
  e.preventDefault();
  var email = document.getElementById('email');
  var password = document.getElementById('password');
  var err = document.getElementById('error');
  var n = (window.__submits || 0) + 1;
  window.__submits = n;
  if (!email.value) err.textContent = 'Enter an email address';
  else if (!password.value) err.textContent = 'Enter a password';
  else err.textContent = 'Refusing to submit: fields are not empty';
  document.getElementById('status').textContent = 'submits: ' + n + ' (no credentials sent)';
  document.title = 'local-login submits=' + n;
});
</script>
</body>
</html>
"#;

const WIRE_VERSION: u8 = 1;
const KIND_MOUSE: u8 = 1;
const KIND_KEY: u8 = 2;

const MOUSE_MOVE: u8 = 1;
const MOUSE_DOWN: u8 = 2;
const MOUSE_UP: u8 = 3;
const MOUSE_CLICK: u8 = 4;

const BUTTON_LEFT: u8 = 0;
const BUTTON_MIDDLE: u8 = 1;
const BUTTON_RIGHT: u8 = 2;

const KEY_DOWN: u8 = 1;
const KEY_UP: u8 = 2;
const KEY_PRESS: u8 = 3;

const MAX_KEY_LEN: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseButton {
    Left,
    Middle,
    Right,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseAction {
    Move,
    Down,
    Up,
    Click,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAction {
    Down,
    Up,
    Press,
}

/// Input the node applies. C2 never sees this enum; it only forwards bytes.
#[derive(Debug, Clone, PartialEq)]
pub enum InputEvent {
    Mouse {
        action: MouseAction,
        button: MouseButton,
        x: f64,
        y: f64,
    },
    Key {
        action: KeyAction,
        key: String,
    },
}

#[derive(Debug)]
pub struct StreamError(pub String);

impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for StreamError {}

pub fn encode_input(event: &InputEvent) -> Result<Vec<u8>, StreamError> {
    let mut out = Vec::with_capacity(20);
    out.push(WIRE_VERSION);
    match event {
        InputEvent::Mouse {
            action,
            button,
            x,
            y,
        } => {
            out.push(KIND_MOUSE);
            out.push(mouse_action_byte(*action));
            out.push(mouse_button_byte(*button));
            out.extend_from_slice(&x.to_le_bytes());
            out.extend_from_slice(&y.to_le_bytes());
        }
        InputEvent::Key { action, key } => {
            let bytes = key.as_bytes();
            if bytes.is_empty() || bytes.len() > MAX_KEY_LEN {
                return Err(StreamError(format!(
                    "key length {} is outside 1..={MAX_KEY_LEN}",
                    bytes.len()
                )));
            }
            out.push(KIND_KEY);
            out.push(key_action_byte(*action));
            out.push(u8::try_from(bytes.len()).unwrap_or(0));
            out.extend_from_slice(bytes);
        }
    }
    Ok(out)
}

pub fn decode_input(bytes: &[u8]) -> Result<InputEvent, StreamError> {
    if bytes.len() < 4 {
        return Err(StreamError(format!(
            "input too short: {} bytes",
            bytes.len()
        )));
    }
    if bytes[0] != WIRE_VERSION {
        return Err(StreamError(format!("unsupported input version {}", bytes[0])));
    }
    match bytes[1] {
        KIND_MOUSE => {
            if bytes.len() != 20 {
                return Err(StreamError(format!(
                    "mouse input must be 20 bytes, got {}",
                    bytes.len()
                )));
            }
            let action = mouse_action_from(bytes[2])?;
            let button = mouse_button_from(bytes[3])?;
            let mut x_buf = [0u8; 8];
            let mut y_buf = [0u8; 8];
            x_buf.copy_from_slice(&bytes[4..12]);
            y_buf.copy_from_slice(&bytes[12..20]);
            Ok(InputEvent::Mouse {
                action,
                button,
                x: f64::from_le_bytes(x_buf),
                y: f64::from_le_bytes(y_buf),
            })
        }
        KIND_KEY => {
            let action = key_action_from(bytes[2])?;
            let len = usize::from(bytes[3]);
            if len == 0 || len > MAX_KEY_LEN || bytes.len() != 4 + len {
                return Err(StreamError(format!(
                    "key input length mismatch: header {len}, bytes {}",
                    bytes.len()
                )));
            }
            let key = std::str::from_utf8(&bytes[4..4 + len])
                .map_err(|_| StreamError("key is not utf-8".into()))?
                .to_owned();
            Ok(InputEvent::Key { action, key })
        }
        other => Err(StreamError(format!("unknown input kind {other}"))),
    }
}

/// CDP calls `apply_input` will make. Tested without Chrome.
pub fn plan_cdp(event: &InputEvent) -> Result<Vec<String>, StreamError> {
    match event {
        InputEvent::Mouse {
            action: MouseAction::Move,
            x,
            y,
            ..
        } => Ok(vec![format!(
            "Input.dispatchMouseEvent type=mouseMoved x={x} y={y} button=none clickCount=0"
        )]),
        InputEvent::Mouse {
            action: MouseAction::Down,
            button: MouseButton::Left,
            x,
            y,
        } => Ok(vec![format!(
            "Input.dispatchMouseEvent type=mousePressed x={x} y={y} button=left clickCount=1"
        )]),
        InputEvent::Mouse {
            action: MouseAction::Up,
            button: MouseButton::Left,
            x,
            y,
        } => Ok(vec![format!(
            "Input.dispatchMouseEvent type=mouseReleased x={x} y={y} button=left clickCount=1"
        )]),
        InputEvent::Mouse {
            action: MouseAction::Click,
            button: MouseButton::Left,
            x,
            y,
        } => Ok(vec![
            format!(
                "Input.dispatchMouseEvent type=mousePressed x={x} y={y} button=left clickCount=1"
            ),
            format!(
                "Input.dispatchMouseEvent type=mouseReleased x={x} y={y} button=left clickCount=1"
            ),
        ]),
        InputEvent::Mouse {
            action: MouseAction::Click,
            button: MouseButton::Right,
            x,
            y,
        } => Ok(vec![
            format!(
                "Input.dispatchMouseEvent type=mousePressed x={x} y={y} button=right clickCount=1"
            ),
            format!(
                "Input.dispatchMouseEvent type=mouseReleased x={x} y={y} button=right clickCount=1"
            ),
        ]),
        InputEvent::Mouse {
            action,
            button,
            ..
        } => Err(StreamError(format!(
            "no CDP mapping for {action:?} {button:?}"
        ))),
        InputEvent::Key { key, .. } => Ok(vec![
            format!("Input.dispatchKeyEvent type=keyDown key={key}"),
            format!("Input.dispatchKeyEvent type=keyUp key={key}"),
        ]),
    }
}

/// Apply one decoded input event to the live page. Returns the CDP lines that ran.
pub async fn apply_input(page: &StealthPage, event: &InputEvent) -> Result<Vec<String>, StreamError> {
    let planned = plan_cdp(event)?;
    match event {
        InputEvent::Mouse {
            action: MouseAction::Move,
            x,
            y,
            ..
        } => page.mouse_move(*x, *y).await.map_err(browser_err)?,
        InputEvent::Mouse {
            action: MouseAction::Down,
            button: MouseButton::Left,
            x,
            y,
        } => page.mouse_down(*x, *y).await.map_err(browser_err)?,
        InputEvent::Mouse {
            action: MouseAction::Up,
            button: MouseButton::Left,
            x,
            y,
        } => page.mouse_up(*x, *y).await.map_err(browser_err)?,
        InputEvent::Mouse {
            action: MouseAction::Click,
            button: MouseButton::Left,
            x,
            y,
        } => page.click_at(*x, *y).await.map_err(browser_err)?,
        InputEvent::Mouse {
            action: MouseAction::Click,
            button: MouseButton::Right,
            x,
            y,
        } => page.right_click_at(*x, *y).await.map_err(browser_err)?,
        InputEvent::Mouse { .. } => {
            return Err(StreamError("unreachable after plan_cdp".into()));
        }
        InputEvent::Key { key, .. } => page.key_press(key).await.map_err(browser_err)?,
    }
    Ok(planned)
}

fn browser_err(err: BrowserError) -> StreamError {
    StreamError(err.to_string())
}

pub struct Endpoints {
    pub post_url: String,
    pub ws_url: String,
}

/// URLs on the C2 origin only. There is no node or HQ address in this builder.
pub fn c2_endpoints(c2_http: &str, session: &str, role: &str) -> Result<Endpoints, StreamError> {
    let (http_base, ws_base) = split_origin(c2_http)?;
    validate_session(session)?;
    if role != "node" && role != "hq" {
        return Err(StreamError(format!("role must be node or hq, got {role}")));
    }
    Ok(Endpoints {
        post_url: format!("{http_base}/session/{session}"),
        ws_url: format!("{ws_base}/session/{session}/{role}"),
    })
}

pub fn split_origin(c2_http: &str) -> Result<(String, String), StreamError> {
    let (scheme, rest) = c2_http
        .split_once("://")
        .ok_or_else(|| StreamError("c2 url needs a scheme".into()))?;
    let ws_scheme = match scheme {
        "http" => "ws",
        "https" => "wss",
        other => {
            return Err(StreamError(format!(
                "c2 scheme must be http or https, got {other}"
            )))
        }
    };
    if rest.is_empty() || rest.contains('/') || rest.contains('@') || rest.contains(' ') {
        return Err(StreamError(
            "c2 url must be scheme://host:port with no path, user, or space".into(),
        ));
    }
    Ok((format!("{scheme}://{rest}"), format!("{ws_scheme}://{rest}")))
}

pub fn validate_session(session: &str) -> Result<(), StreamError> {
    if session.is_empty() || session.len() > 64 {
        return Err(StreamError("session id length must be 1..=64".into()));
    }
    if !session
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(StreamError(
            "session id must be ASCII alphanumeric, '_' or '-'".into(),
        ));
    }
    Ok(())
}

/// Serve the local HTML on 127.0.0.1 and return the port. Chrome in this
/// network namespace is the only client that needs to reach it.
pub fn spawn_local_page() -> std::io::Result<u16> {
    spawn_local_html(LOCAL_PAGE_HTML)
}

pub fn spawn_local_html(html: &'static str) -> std::io::Result<u16> {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))?;
    let port = listener.local_addr()?.port();
    std::thread::Builder::new()
        .name("dig2-local-page".into())
        .spawn(move || serve_loop(listener, html))?;
    Ok(port)
}

fn serve_loop(listener: TcpListener, html: &'static str) {
    for conn in listener.incoming() {
        let mut stream = match conn {
            Ok(stream) => stream,
            Err(_) => continue,
        };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let mut buf = [0u8; 2048];
        let _ = stream.read(&mut buf);
        let body = html.as_bytes();
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(header.as_bytes());
        let _ = stream.write_all(body);
        let _ = stream.flush();
    }
}

pub struct NodeOptions {
    pub c2: String,
    pub session: String,
    pub profile: PathBuf,
    pub evidence: PathBuf,
    pub click_wait: Duration,
}

pub struct NodeProof {
    pub page_url: String,
    pub profile: PathBuf,
    pub cdp_lines: Vec<String>,
    pub dom: String,
    pub title: String,
    pub href: String,
    pub frames_sent: u64,
    pub last_frame_bytes: u64,
}

/// Launch Chrome in `options.profile`, paint the local page, push PNG frames
/// to C2, and apply the first input event that comes back.
pub async fn run_node(options: NodeOptions) -> Result<NodeProof, StreamError> {
    if let Some(parent) = options.evidence.parent() {
        std::fs::create_dir_all(parent).map_err(|e| StreamError(e.to_string()))?;
    }
    std::fs::create_dir_all(&options.profile).map_err(|e| StreamError(e.to_string()))?;

    let endpoints = c2_endpoints(&options.c2, &options.session, "node")?;
    open_session(&endpoints.post_url).await?;

    let port = spawn_local_page().map_err(|e| StreamError(e.to_string()))?;
    let page_url = format!("http://127.0.0.1:{port}/");
    eprintln!("[stream-node] local page {page_url}");

    let launch = LaunchConfig {
        headless: true,
        window_size: (1280, 720),
        profile: BrowserProfile::Persistent(options.profile.clone()),
        browser_pref: BrowserPreference::ChromeOnly,
        renderer_sandbox: RendererSandboxMode::CompatibilityDisabled,
        ..LaunchConfig::default()
    };
    let mut stealth = StealthConfig::default();
    stealth.transparent = true;

    eprintln!("[stream-node] launching Chrome profile {}", options.profile.display());
    let browser = StealthBrowser::launch_with(launch, stealth)
        .await
        .map_err(browser_err)?;
    let page = browser
        .new_page(&page_url)
        .await
        .map_err(browser_err)?;
    page.goto_and_wait(&page_url, "#count", Duration::from_secs(15))
        .await
        .map_err(browser_err)?;
    let ready = page
        .eval("document.body && document.body.innerText.indexOf('DIG2BROWSER LOCAL STREAM PAGE') !== -1")
        .await
        .map_err(browser_err)?;
    if ready.as_bool() != Some(true) {
        let _ = browser.close().await;
        return Err(StreamError(
            "Chrome did not paint the local stream page".into(),
        ));
    }
    eprintln!("[stream-node] Chrome painted the local page");

    let ws = connect_ws(&endpoints.ws_url).await?;
    let (mut ws_write, mut ws_read) = ws.split();

    let (frame_tx, mut frame_rx) = mpsc::channel::<Vec<u8>>(1);
    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<InputEvent>();
    let frames_sent = Arc::new(AtomicU64::new(0));
    let last_frame_bytes = Arc::new(AtomicU64::new(0));
    let frames_sent_w = Arc::clone(&frames_sent);
    let last_frame_bytes_w = Arc::clone(&last_frame_bytes);

    let writer = tokio::spawn(async move {
        while let Some(png) = frame_rx.recv().await {
            let n = u64::try_from(png.len()).unwrap_or(0);
            if ws_write
                .send(tokio_tungstenite::tungstenite::Message::binary(png))
                .await
                .is_err()
            {
                break;
            }
            frames_sent_w.fetch_add(1, Ordering::Relaxed);
            last_frame_bytes_w.store(n, Ordering::Relaxed);
            eprintln!("[stream-node] frame bytes={n}");
        }
    });

    let reader = tokio::spawn(async move {
        use futures::StreamExt;
        while let Some(msg) = ws_read.next().await {
            match msg {
                Ok(tokio_tungstenite::tungstenite::Message::Binary(data)) => {
                    let n = data.len();
                    match decode_input(&data) {
                        Ok(event) => {
                            eprintln!("[stream-node] input bytes={n}");
                            if event_tx.send(event).is_err() {
                                break;
                            }
                        }
                        Err(err) => {
                            eprintln!("[stream-node] input decode failed bytes={n}: {err}");
                        }
                    }
                }
                Ok(tokio_tungstenite::tungstenite::Message::Ping(_))
                | Ok(tokio_tungstenite::tungstenite::Message::Pong(_)) => {}
                Ok(tokio_tungstenite::tungstenite::Message::Close(_)) | Err(_) => break,
                Ok(_) => {
                    eprintln!("[stream-node] ignored non-binary input");
                }
            }
        }
    });

    let mut tick = tokio::time::interval(Duration::from_millis(400));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let deadline = tokio::time::Instant::now() + options.click_wait;
    let mut proof: Option<NodeProof> = None;

    while tokio::time::Instant::now() < deadline {
        tokio::select! {
            _ = tick.tick() => {
                match page.screenshot().await {
                    Ok(png) if png.len() >= 32 && png.starts_with(&[0x89, b'P', b'N', b'G']) => {
                        if frame_tx.try_send(png).is_err() {
                            // Writer is busy or gone. Drop this frame; keep reading input.
                        }
                    }
                    Ok(png) => eprintln!("[stream-node] skipped non-png frame bytes={}", png.len()),
                    Err(err) => eprintln!("[stream-node] screenshot failed: {err}"),
                }
            }
            event = event_rx.recv() => {
                let Some(event) = event else { break };
                let cdp_lines = apply_input(&page, &event).await?;
                for line in &cdp_lines {
                    eprintln!("[stream-node] cdp {line}");
                }
                tokio::time::sleep(Duration::from_millis(150)).await;
                let dom = eval_string(&page, "document.getElementById('count').textContent").await?;
                let title = eval_string(&page, "document.title").await?;
                let href = eval_string(&page, "location.href").await?;
                eprintln!("[stream-node] dom {dom}");
                proof = Some(NodeProof {
                    page_url: page_url.clone(),
                    profile: options.profile.clone(),
                    cdp_lines,
                    dom,
                    title,
                    href,
                    frames_sent: frames_sent.load(Ordering::Relaxed),
                    last_frame_bytes: last_frame_bytes.load(Ordering::Relaxed),
                });
                break;
            }
        }
    }

    drop(frame_tx);
    writer.abort();
    reader.abort();
    let _ = browser.close().await;

    let proof = proof.ok_or_else(|| StreamError("timed out waiting for one input event".into()))?;
    write_evidence(&options.evidence, &proof)?;
    Ok(proof)
}

async fn eval_string(page: &StealthPage, js: &str) -> Result<String, StreamError> {
    let value = page.eval(js).await.map_err(browser_err)?;
    Ok(value.as_str().unwrap_or("").to_owned())
}

fn write_evidence(path: &std::path::Path, proof: &NodeProof) -> Result<(), StreamError> {
    let mut body = String::new();
    body.push_str(&format!("page={}\n", proof.page_url));
    body.push_str(&format!("profile={}\n", proof.profile.display()));
    body.push_str(&format!("href={}\n", proof.href));
    body.push_str(&format!("title={}\n", proof.title));
    body.push_str(&format!("frames_sent={}\n", proof.frames_sent));
    body.push_str(&format!("last_frame_bytes={}\n", proof.last_frame_bytes));
    body.push_str(&format!("dom={}\n", proof.dom));
    for line in &proof.cdp_lines {
        body.push_str("cdp=");
        body.push_str(line);
        body.push('\n');
    }
    std::fs::write(path, body).map_err(|e| StreamError(e.to_string()))
}

async fn open_session(post_url: &str) -> Result<(), StreamError> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| StreamError(e.to_string()))?;
    let response = client
        .post(post_url)
        .body("")
        .send()
        .await
        .map_err(|e| StreamError(format!("session open failed: {e}")))?;
    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|e| StreamError(e.to_string()))?;
    if !status.is_success() {
        return Err(StreamError(format!("session open status {status}: {text}")));
    }
    eprintln!("[stream-node] session open {post_url} status={status}");
    Ok(())
}

async fn connect_ws(
    ws_url: &str,
) -> Result<
    tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    StreamError,
> {
    let mut last = String::from("not attempted");
    for attempt in 1..=40 {
        match tokio_tungstenite::connect_async(ws_url).await {
            Ok((ws, _)) => {
                eprintln!("[stream-node] websocket ready {ws_url} attempt={attempt}");
                return Ok(ws);
            }
            Err(err) => {
                last = err.to_string();
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    }
    Err(StreamError(format!(
        "websocket {ws_url} failed: {last}"
    )))
}

fn mouse_action_byte(action: MouseAction) -> u8 {
    match action {
        MouseAction::Move => MOUSE_MOVE,
        MouseAction::Down => MOUSE_DOWN,
        MouseAction::Up => MOUSE_UP,
        MouseAction::Click => MOUSE_CLICK,
    }
}

fn mouse_button_byte(button: MouseButton) -> u8 {
    match button {
        MouseButton::Left => BUTTON_LEFT,
        MouseButton::Middle => BUTTON_MIDDLE,
        MouseButton::Right => BUTTON_RIGHT,
    }
}

fn key_action_byte(action: KeyAction) -> u8 {
    match action {
        KeyAction::Down => KEY_DOWN,
        KeyAction::Up => KEY_UP,
        KeyAction::Press => KEY_PRESS,
    }
}

fn mouse_action_from(byte: u8) -> Result<MouseAction, StreamError> {
    match byte {
        MOUSE_MOVE => Ok(MouseAction::Move),
        MOUSE_DOWN => Ok(MouseAction::Down),
        MOUSE_UP => Ok(MouseAction::Up),
        MOUSE_CLICK => Ok(MouseAction::Click),
        other => Err(StreamError(format!("unknown mouse action {other}"))),
    }
}

fn mouse_button_from(byte: u8) -> Result<MouseButton, StreamError> {
    match byte {
        BUTTON_LEFT => Ok(MouseButton::Left),
        BUTTON_MIDDLE => Ok(MouseButton::Middle),
        BUTTON_RIGHT => Ok(MouseButton::Right),
        other => Err(StreamError(format!("unknown mouse button {other}"))),
    }
}

fn key_action_from(byte: u8) -> Result<KeyAction, StreamError> {
    match byte {
        KEY_DOWN => Ok(KeyAction::Down),
        KEY_UP => Ok(KeyAction::Up),
        KEY_PRESS => Ok(KeyAction::Press),
        other => Err(StreamError(format!("unknown key action {other}"))),
    }
}

/// 12-byte prefix sent immediately before a PNG. C2 forwards it as opaque
/// bytes and does not log the timestamp. Layout: b"FRME" + capture_ns le.
pub fn frame_timing_header(capture_ns: u64) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[..4].copy_from_slice(b"FRME");
    out[4..].copy_from_slice(&capture_ns.to_le_bytes());
    out
}

/// Monotonic nanoseconds. On Unix this is `CLOCK_MONOTONIC`. Windows has
/// no `clock_gettime`; a process-local `Instant` is the same kind of clock
/// for frame deltas. C2 forwards the bytes and does not interpret them.
pub fn mono_ns() -> u64 {
    #[cfg(unix)]
    {
        #[repr(C)]
        struct Timespec {
            tv_sec: i64,
            tv_nsec: i64,
        }
        extern "C" {
            fn clock_gettime(clk_id: i32, tp: *mut Timespec) -> i32;
        }
        const CLOCK_MONOTONIC: i32 = 1;
        let mut ts = Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let rc = unsafe { clock_gettime(CLOCK_MONOTONIC, &mut ts) };
        if rc != 0 {
            return 0;
        }
        return (ts.tv_sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(ts.tv_nsec as u64);
    }
    #[cfg(not(unix))]
    {
        use std::sync::OnceLock;
        static BASE: OnceLock<std::time::Instant> = OnceLock::new();
        let base = BASE.get_or_init(std::time::Instant::now);
        u64::try_from(base.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }
}

fn append_clock(path: &std::path::Path, line: &str) {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "{line}");
        let _ = file.flush();
    }
}

const PROBE_JS: &str = r#"(function(){
  function box(el){
    if(!el) return null;
    var r = el.getBoundingClientRect();
    var s = window.getComputedStyle(el);
    if(r.width < 20 || r.height < 16) return null;
    if(s.visibility === 'hidden' || s.display === 'none') return null;
    return {id: el.id || '', x: r.left + r.width/2, y: r.top + r.height/2};
  }
  function first(sel){
    var nodes = document.querySelectorAll(sel);
    for (var i=0;i<nodes.length;i++){
      var b = box(nodes[i]);
      if(b) return b;
    }
    return null;
  }
  var email = first('input[type="email"], input[name="email"], input[autocomplete="username"], input[autocomplete="email"]');
  var password = first('input[type="password"]');
  var button = first('#signin, button[type="submit"], input[type="submit"], button');
  var text = (document.body && document.body.innerText) ? document.body.innerText.slice(0, 240) : '';
  return JSON.stringify({
    href: String(location.href),
    title: String(document.title),
    kind: document.body ? (document.body.getAttribute('data-kind') || '') : '',
    email: email, password: password, button: button, text: text
  });
})()"#;

const DOM_JS: &str = r#"(function(){
  var ae = document.activeElement;
  var err = document.getElementById('error');
  var st = document.getElementById('status');
  return JSON.stringify({
    activeId: ae ? (ae.id || ae.tagName || '') : '',
    error: err ? err.textContent : '',
    status: st ? st.textContent : '',
    title: document.title,
    href: location.href,
    kind: document.body ? (document.body.getAttribute('data-kind') || '') : ''
  });
})()"#;

pub struct LoginNodeOptions {
    pub c2: String,
    pub session: String,
    pub profile: PathBuf,
    pub evidence: PathBuf,
    pub targets: PathBuf,
    pub clock: PathBuf,
    pub ready_file: PathBuf,
    pub try_url: String,
    pub expect_clicks: u64,
    pub click_wait: Duration,
}

fn field_present(value: &serde_json::Value, key: &str) -> bool {
    value.get(key).map(|item| item.is_object()).unwrap_or(false)
}

fn login_usable(value: &serde_json::Value) -> bool {
    if !field_present(value, "email")
        || !field_present(value, "password")
        || !field_present(value, "button")
    {
        return false;
    }
    let text = value
        .get("text")
        .and_then(|item| item.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let blocked = [
        "just a moment",
        "cloudflare",
        "verify you are human",
        "checking your browser",
    ]
    .iter()
    .any(|needle| text.contains(needle));
    !blocked
}

fn xy_of(value: &serde_json::Value, key: &str) -> Result<(f64, f64), StreamError> {
    let obj = value
        .get(key)
        .and_then(|item| item.as_object())
        .ok_or_else(|| StreamError(format!("login probe missing {key}")))?;
    let x = obj
        .get("x")
        .and_then(|item| item.as_f64())
        .ok_or_else(|| StreamError(format!("{key} missing x")))?;
    let y = obj
        .get("y")
        .and_then(|item| item.as_f64())
        .ok_or_else(|| StreamError(format!("{key} missing y")))?;
    Ok((x, y))
}

async fn probe_page(page: &StealthPage) -> Result<serde_json::Value, StreamError> {
    let value = page.eval(PROBE_JS).await.map_err(browser_err)?;
    let text = value
        .as_str()
        .ok_or_else(|| StreamError(format!("login probe was not a string: {value}")))?;
    serde_json::from_str(text).map_err(|err| StreamError(format!("login probe json: {err}")))
}

async fn dom_state(page: &StealthPage) -> Result<String, StreamError> {
    let value = page.eval(DOM_JS).await.map_err(browser_err)?;
    Ok(value.as_str().unwrap_or("").to_owned())
}

async fn open_session_retry(post_url: &str) -> Result<(), StreamError> {
    let mut last = String::from("not attempted");
    for _ in 0..40 {
        match open_session(post_url).await {
            Ok(()) => return Ok(()),
            Err(err) => last = err.to_string(),
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    Err(StreamError(format!("session open failed: {last}")))
}

async fn wait_ready(path: &std::path::Path, deadline: tokio::time::Instant) -> Result<(), StreamError> {
    while tokio::time::Instant::now() < deadline {
        if path.exists() {
            eprintln!("[stream-node] hq ready file {}", path.display());
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(StreamError(format!(
        "timed out waiting for hq ready file {}",
        path.display()
    )))
}

fn write_targets(
    path: &std::path::Path,
    kind: &str,
    href: &str,
    title: &str,
    fallback: &str,
    email: (f64, f64),
    password: (f64, f64),
    signin: (f64, f64),
) -> Result<(), StreamError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| StreamError(err.to_string()))?;
    }
    let body = format!(
        "kind={kind}\nhref={href}\ntitle={title}\nfallback={fallback}\nemail_x={ex:.3}\nemail_y={ey:.3}\npassword_x={px:.3}\npassword_y={py:.3}\nsignin_x={sx:.3}\nsignin_y={sy:.3}\n",
        ex = email.0,
        ey = email.1,
        px = password.0,
        py = password.1,
        sx = signin.0,
        sy = signin.1
    );
    let mut file = std::fs::File::create(path).map_err(|err| StreamError(err.to_string()))?;
    use std::io::Write;
    file.write_all(body.as_bytes())
        .map_err(|err| StreamError(err.to_string()))?;
    file.sync_all().map_err(|err| StreamError(err.to_string()))?;
    Ok(())
}


/// Paint a login page, stream PNG frames to C2, apply N left clicks.
///
/// Tries `try_url` first. A usable page has a visible email field, password
/// field, and button, and is not a Cloudflare interstitial. Otherwise Chrome
/// is pointed at the node-served local login form.
pub async fn run_login_node(options: LoginNodeOptions) -> Result<NodeProof, StreamError> {
    if let Some(parent) = options.evidence.parent() {
        std::fs::create_dir_all(parent).map_err(|err| StreamError(err.to_string()))?;
    }
    std::fs::create_dir_all(&options.profile).map_err(|err| StreamError(err.to_string()))?;
    let _ = std::fs::remove_file(&options.clock);

    let endpoints = c2_endpoints(&options.c2, &options.session, "node")?;
    open_session_retry(&endpoints.post_url).await?;

    let port = spawn_local_html(LOGIN_PAGE_HTML).map_err(|err| StreamError(err.to_string()))?;
    let local_url = format!("http://127.0.0.1:{port}/");
    eprintln!("[stream-node] local login form {local_url}");

    let launch = LaunchConfig {
        headless: true,
        window_size: (1280, 720),
        profile: BrowserProfile::Persistent(options.profile.clone()),
        browser_pref: BrowserPreference::ChromeOnly,
        renderer_sandbox: RendererSandboxMode::CompatibilityDisabled,
        extra_args: vec!["--force-device-scale-factor=1".into()],
        ..LaunchConfig::default()
    };
    let mut stealth = StealthConfig::default();
    stealth.transparent = true;

    eprintln!(
        "[stream-node] launching Chrome profile {}",
        options.profile.display()
    );
    let browser = StealthBrowser::launch_with(launch, stealth)
        .await
        .map_err(browser_err)?;
    let page = browser.new_page("about:blank").await.map_err(browser_err)?;

    let mut kind = String::from("local-login-form");
    let mut fallback = String::new();
    let mut painted_remote = false;
    if !options.try_url.is_empty() {
        eprintln!("[stream-node] trying login url {}", options.try_url);
        let attempt = tokio::time::timeout(Duration::from_secs(25), async {
            page.goto(&options.try_url).await.map_err(browser_err)?;
            let deadline = tokio::time::Instant::now() + Duration::from_secs(12);
            loop {
                let probed = probe_page(&page).await?;
                if login_usable(&probed) {
                    return Ok::<_, StreamError>(probed);
                }
                if tokio::time::Instant::now() >= deadline {
                    let title = probed.get("title").and_then(|item| item.as_str()).unwrap_or("");
                    let href = probed.get("href").and_then(|item| item.as_str()).unwrap_or("");
                    return Err(StreamError(format!(
                        "no usable email+password form title={title} href={href}"
                    )));
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        })
        .await;
        match attempt {
            Ok(Ok(_)) => {
                painted_remote = true;
                eprintln!("[stream-node] remote login form painted");
            }
            Ok(Err(err)) => {
                fallback = err.to_string();
                eprintln!("[stream-node] remote login not usable: {fallback}");
            }
            Err(_) => {
                fallback = format!("timed out waiting for {}", options.try_url);
                eprintln!("[stream-node] {fallback}");
            }
        }
    }
    if !painted_remote {
        if fallback.is_empty() {
            fallback = "remote login url not requested".into();
        }
        page.goto_and_wait(&local_url, "#email", Duration::from_secs(15))
            .await
            .map_err(browser_err)?;
        kind = "local-login-form".into();
        eprintln!("[stream-node] Chrome painted the local login form");
    }

    let probed = probe_page(&page).await?;
    if !login_usable(&probed) {
        let _ = browser.close().await;
        return Err(StreamError(format!(
            "login form is not usable after paint: {probed}"
        )));
    }
    if painted_remote {
        let href_now = probed.get("href").and_then(|item| item.as_str()).unwrap_or("");
        if href_now.contains("claude.ai") {
            kind = "claude-login".into();
        } else {
            let body_kind = probed.get("kind").and_then(|item| item.as_str()).unwrap_or("");
            kind = if body_kind.is_empty() {
                "remote-login".into()
            } else {
                body_kind.to_owned()
            };
        }
    }
    let email = xy_of(&probed, "email")?;
    let password = xy_of(&probed, "password")?;
    let signin = xy_of(&probed, "button")?;
    let href = probed
        .get("href")
        .and_then(|item| item.as_str())
        .unwrap_or("")
        .to_owned();
    let title = probed
        .get("title")
        .and_then(|item| item.as_str())
        .unwrap_or("")
        .to_owned();
    write_targets(
        &options.targets,
        &kind,
        &href,
        &title,
        &fallback,
        email,
        password,
        signin,
    )?;
    eprintln!(
        "[stream-node] targets kind={kind} email={:.1},{:.1} password={:.1},{:.1} signin={:.1},{:.1}",
        email.0, email.1, password.0, password.1, signin.0, signin.1
    );

    let dom_before = dom_state(&page).await?;
    let deadline = tokio::time::Instant::now() + options.click_wait;
    wait_ready(&options.ready_file, deadline).await?;

    let ws = connect_ws(&endpoints.ws_url).await?;
    let (mut ws_write, mut ws_read) = ws.split();
    let (frame_tx, mut frame_rx) = mpsc::channel::<(u64, Vec<u8>)>(2);
    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<InputEvent>();
    let frames_sent = Arc::new(AtomicU64::new(0));
    let last_frame_bytes = Arc::new(AtomicU64::new(0));
    let frames_sent_w = Arc::clone(&frames_sent);
    let last_frame_bytes_w = Arc::clone(&last_frame_bytes);

    let writer = tokio::spawn(async move {
        while let Some((capture_ns, png)) = frame_rx.recv().await {
            let header = frame_timing_header(capture_ns);
            if ws_write
                .send(tokio_tungstenite::tungstenite::Message::binary(header.to_vec()))
                .await
                .is_err()
            {
                break;
            }
            let n = u64::try_from(png.len()).unwrap_or(0);
            if ws_write
                .send(tokio_tungstenite::tungstenite::Message::binary(png))
                .await
                .is_err()
            {
                break;
            }
            frames_sent_w.fetch_add(1, Ordering::Relaxed);
            last_frame_bytes_w.store(n, Ordering::Relaxed);
            eprintln!("[stream-node] frame bytes={n}");
        }
    });

    let reader = tokio::spawn(async move {
        use futures::StreamExt;
        while let Some(msg) = ws_read.next().await {
            match msg {
                Ok(tokio_tungstenite::tungstenite::Message::Binary(data)) => {
                    let n = data.len();
                    match decode_input(&data) {
                        Ok(event) => {
                            eprintln!("[stream-node] input bytes={n}");
                            if event_tx.send(event).is_err() {
                                break;
                            }
                        }
                        Err(err) => {
                            eprintln!("[stream-node] input decode failed bytes={n}: {err}");
                        }
                    }
                }
                Ok(tokio_tungstenite::tungstenite::Message::Ping(_))
                | Ok(tokio_tungstenite::tungstenite::Message::Pong(_)) => {}
                Ok(tokio_tungstenite::tungstenite::Message::Close(_)) | Err(_) => break,
                Ok(_) => {
                    eprintln!("[stream-node] ignored non-binary input");
                }
            }
        }
    });

    let mut tick = tokio::time::interval(Duration::from_millis(400));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut clicks_done = 0u64;
    let mut cdp_lines = Vec::new();
    let mut tail_until: Option<tokio::time::Instant> = None;

    loop {
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        if let Some(until) = tail_until {
            if tokio::time::Instant::now() >= until {
                break;
            }
        }
        tokio::select! {
            _ = tick.tick() => {
                match page.screenshot().await {
                    Ok(png) if png.len() >= 32 && png.starts_with(&[0x89, b'P', b'N', b'G']) => {
                        let capture_ns = mono_ns();
                        if frame_tx.try_send((capture_ns, png)).is_err() {
                            // Writer is busy. Drop this frame.
                        }
                    }
                    Ok(png) => eprintln!("[stream-node] skipped non-png frame bytes={}", png.len()),
                    Err(err) => eprintln!("[stream-node] screenshot failed: {err}"),
                }
            }
            event = event_rx.recv(), if tail_until.is_none() || clicks_done < options.expect_clicks => {
                let Some(event) = event else { break };
                match &event {
                    InputEvent::Mouse { action: MouseAction::Click, button: MouseButton::Left, x, y } => {
                        clicks_done += 1;
                        let pressed_ns = mono_ns();
                        page.mouse_down(*x, *y).await.map_err(browser_err)?;
                        let line = format!(
                            "Input.dispatchMouseEvent type=mousePressed x={x} y={y} button=left clickCount=1"
                        );
                        eprintln!("[stream-node] cdp {line}");
                        cdp_lines.push(line);
                        page.mouse_up(*x, *y).await.map_err(browser_err)?;
                        let line = format!(
                            "Input.dispatchMouseEvent type=mouseReleased x={x} y={y} button=left clickCount=1"
                        );
                        eprintln!("[stream-node] cdp {line}");
                        cdp_lines.push(line);
                        append_clock(
                            &options.clock,
                            &format!("click seq={clicks_done} pressed_ns={pressed_ns}"),
                        );
                        eprintln!("[stream-node] click seq={clicks_done} pressed_ns={pressed_ns}");
                        if clicks_done >= options.expect_clicks && tail_until.is_none() {
                            tail_until = Some(tokio::time::Instant::now() + Duration::from_secs(4));
                        }
                    }
                    other => {
                        let lines = apply_input(&page, other).await?;
                        for line in lines {
                            eprintln!("[stream-node] cdp {line}");
                            cdp_lines.push(line);
                        }
                    }
                }
            }
        }
    }

    let dom_after = dom_state(&page).await.unwrap_or_else(|err| format!("dom error: {err}"));
    drop(frame_tx);
    writer.abort();
    reader.abort();
    let _ = browser.close().await;

    if clicks_done == 0 {
        return Err(StreamError("timed out waiting for login clicks".into()));
    }
    let proof = NodeProof {
        page_url: if painted_remote { options.try_url.clone() } else { local_url },
        profile: options.profile.clone(),
        cdp_lines,
        dom: dom_after.clone(),
        title: title.clone(),
        href: href.clone(),
        frames_sent: frames_sent.load(Ordering::Relaxed),
        last_frame_bytes: last_frame_bytes.load(Ordering::Relaxed),
    };
    let mut body = String::new();
    body.push_str(&format!("page={}\n", proof.page_url));
    body.push_str(&format!("kind={kind}\n"));
    body.push_str(&format!("fallback={fallback}\n"));
    body.push_str(&format!("profile={}\n", proof.profile.display()));
    body.push_str(&format!("href={}\n", proof.href));
    body.push_str(&format!("title={}\n", proof.title));
    body.push_str(&format!("frames_sent={}\n", proof.frames_sent));
    body.push_str(&format!("last_frame_bytes={}\n", proof.last_frame_bytes));
    body.push_str(&format!("clicks_applied={clicks_done}\n"));
    body.push_str(&format!("dom_before={dom_before}\n"));
    body.push_str(&format!("dom_after={dom_after}\n"));
    for line in &proof.cdp_lines {
        body.push_str("cdp=");
        body.push_str(line);
        body.push('\n');
    }
    std::fs::write(&options.evidence, body).map_err(|err| StreamError(err.to_string()))?;
    Ok(proof)
}


#[cfg(test)]
mod tests {
    use super::*;

    fn click(x: f64, y: f64, button: MouseButton) -> InputEvent {
        InputEvent::Mouse {
            action: MouseAction::Click,
            button,
            x,
            y,
        }
    }

    #[test]
    fn click_bytes_match_the_shared_vector() {
        let bytes = encode_input(&click(120.0, 90.0, MouseButton::Left)).unwrap();
        assert_eq!(
            bytes,
            hex_decode("010104000000000000005e400000000000805640")
        );
        assert_eq!(decode_input(&bytes).unwrap(), click(120.0, 90.0, MouseButton::Left));
    }

    #[test]
    fn key_press_bytes_match_the_shared_vector() {
        let event = InputEvent::Key {
            action: KeyAction::Press,
            key: "Enter".into(),
        };
        let bytes = encode_input(&event).unwrap();
        assert_eq!(bytes, hex_decode("01020305456e746572"));
        assert_eq!(decode_input(&bytes).unwrap(), event);
    }

    #[test]
    fn truncated_and_bad_version_fail() {
        assert!(decode_input(&[1, 1, 4]).is_err());
        assert!(decode_input(&[9, 1, 4, 0]).is_err());
    }

    #[test]
    fn left_click_plan_is_press_then_release() {
        let lines = plan_cdp(&click(120.0, 90.0, MouseButton::Left)).unwrap();
        assert_eq!(
            lines,
            vec![
                "Input.dispatchMouseEvent type=mousePressed x=120 y=90 button=left clickCount=1",
                "Input.dispatchMouseEvent type=mouseReleased x=120 y=90 button=left clickCount=1",
            ]
        );
    }

    #[test]
    fn middle_click_has_no_cdp_mapping() {
        let err = plan_cdp(&click(1.0, 2.0, MouseButton::Middle)).unwrap_err();
        assert!(err.to_string().contains("no CDP mapping"));
    }

    #[test]
    fn c2_endpoints_stay_on_the_c2_origin() {
        let ends = c2_endpoints("http://10.88.1.2:18443", "proof1", "node").unwrap();
        assert_eq!(ends.post_url, "http://10.88.1.2:18443/session/proof1");
        assert_eq!(ends.ws_url, "ws://10.88.1.2:18443/session/proof1/node");
        assert!(c2_endpoints("http://10.88.1.2:18443/extra", "proof1", "node").is_err());
    }

    #[test]
    fn local_page_is_ours_and_serves() {
        assert!(LOCAL_PAGE_HTML.contains("DIG2BROWSER LOCAL STREAM PAGE"));
        assert!(LOCAL_PAGE_HTML.contains("id=\"count\""));
        assert!(!LOCAL_PAGE_HTML.to_ascii_lowercase().contains("claude"));
        let port = spawn_local_page().unwrap();
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .unwrap();
        let mut body = Vec::new();
        stream.read_to_end(&mut body).unwrap();
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("DIG2BROWSER LOCAL STREAM PAGE"));
    }


    #[test]
    fn local_login_form_is_labeled_and_serves() {
        assert!(LOGIN_PAGE_HTML.contains("LOCAL LOGIN FORM"));
        assert!(LOGIN_PAGE_HTML.contains("not claude.ai"));
        assert!(LOGIN_PAGE_HTML.contains("id=\"email\""));
        assert!(LOGIN_PAGE_HTML.contains("type=\"password\""));
        assert!(LOGIN_PAGE_HTML.contains(">Sign in<"));
        assert!(LOGIN_PAGE_HTML.contains("data-kind=\"local-login-form\""));
        let header = frame_timing_header(1000);
        assert_eq!(&header[..4], b"FRME");
        assert_eq!(&header[4..], &1000u64.to_le_bytes());
        let port = spawn_local_html(LOGIN_PAGE_HTML).unwrap();
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .unwrap();
        let mut body = Vec::new();
        stream.read_to_end(&mut body).unwrap();
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("LOCAL LOGIN FORM"));
        assert!(text.contains("not claude.ai"));
    }

    fn hex_decode(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }
}
