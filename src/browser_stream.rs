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
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))?;
    let port = listener.local_addr()?.port();
    std::thread::Builder::new()
        .name("dig2-local-page".into())
        .spawn(move || serve_loop(listener))?;
    Ok(port)
}

fn serve_loop(listener: TcpListener) {
    for conn in listener.incoming() {
        let mut stream = match conn {
            Ok(stream) => stream,
            Err(_) => continue,
        };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let mut buf = [0u8; 2048];
        let _ = stream.read(&mut buf);
        let body = LOCAL_PAGE_HTML.as_bytes();
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

    fn hex_decode(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }
}
