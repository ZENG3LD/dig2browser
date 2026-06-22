//! dev-attach — attach to an existing Chrome/Edge and debug it live.
//!
//! # Basic usage
//!
//!   dev-attach --port 9222 --target http://127.0.0.1:17499 --watch-console
//!   dev-attach --port 9222 --eval "JSON.stringify({frames: window.MLC_FRAMES})"
//!   dev-attach --port 9222 --screenshot ./snap.png --interval 5
//!
//! # Input / interaction
//!
//!   dev-attach --port 9222 --click 500,300
//!   dev-attach --port 9222 --right-click 500,300
//!   dev-attach --port 9222 --move 200,400
//!   dev-attach --port 9222 --drag 100,200,400,200
//!   dev-attach --port 9222 --wheel 500,300,0,300
//!   dev-attach --port 9222 --key Enter
//!   dev-attach --port 9222 --key-chord "Control+r"
//!
//! # Viewport
//!
//!   dev-attach --port 9222 --viewport 1280x800
//!   dev-attach --port 9222 --viewport 1280x800 --viewport-scale 2.0
//!
//! # DOM inspection
//!
//!   dev-attach --port 9222 --dom "body"
//!   dev-attach --port 9222 --rect "#canvas"
//!
//! # Performance
//!
//!   dev-attach --port 9222 --perf
//!   dev-attach --port 9222 --frames-count 2
//!
//! # Raw CDP
//!
//!   dev-attach --port 9222 --cdp "Page.reload"
//!   dev-attach --port 9222 --cdp "Browser.getVersion"
//!   dev-attach --port 9222 --cdp "Input.dispatchMouseEvent" --cdp-params '{"type":"mouseMoved","x":100,"y":100}'
//!
//! # Network
//!
//!   dev-attach --port 9222 --network-poll
//!
//! The browser must have been launched with `--remote-debugging-port=<PORT>`.
//! Use `--watch-console` to enter the poll loop. Ctrl-C to quit.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use clap::Parser;
use dig2browser::{DevToolsEvent, StealthBrowser, discover_ws_url};

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "dev-attach",
    about = "Attach to an existing headed Chrome/Edge and debug it live via CDP"
)]
struct Cli {
    /// Chrome/Edge remote-debugging port (default: 9222)
    #[arg(long, default_value = "9222")]
    port: u16,

    /// Attach to the first tab whose URL starts with this prefix.
    /// If omitted, picks the first non-about:blank page.
    #[arg(long)]
    target: Option<String>,

    /// Execute this JS expression once, print the result, and exit.
    #[arg(long)]
    eval: Option<String>,

    /// Watch console messages forever (poll every 2 s). Ctrl-C to quit.
    #[arg(long)]
    watch_console: bool,

    /// Save a screenshot PNG to this path (one-shot unless --interval is set).
    #[arg(long)]
    screenshot: Option<PathBuf>,

    /// Repeat --screenshot every N seconds.
    #[arg(long, value_name = "SECONDS")]
    interval: Option<u64>,

    // ── Input / interaction ───────────────────────────────────────────────────

    /// Left-click at coordinates, e.g. --click 500,300
    #[arg(long, value_name = "X,Y")]
    click: Option<String>,

    /// Right-click at coordinates, e.g. --right-click 500,300
    #[arg(long = "right-click", value_name = "X,Y")]
    right_click: Option<String>,

    /// Move mouse to coordinates (hover), e.g. --move 200,400
    #[arg(long, value_name = "X,Y")]
    r#move: Option<String>,

    /// Drag between two points, e.g. --drag 100,200,400,200
    #[arg(long, value_name = "X1,Y1,X2,Y2")]
    drag: Option<String>,

    /// Wheel scroll, e.g. --wheel 500,300,0,300 (X,Y,DX,DY)
    #[arg(long, value_name = "X,Y,DX,DY")]
    wheel: Option<String>,

    /// Press a key by name, e.g. --key Enter  or  --key a
    #[arg(long, value_name = "KEY")]
    key: Option<String>,

    /// Key chord, modifiers separated by +, e.g. --key-chord "Control+r"
    #[arg(long = "key-chord", value_name = "CHORD")]
    key_chord: Option<String>,

    // ── Viewport ─────────────────────────────────────────────────────────────

    /// Set viewport size, e.g. --viewport 1280x800
    #[arg(long, value_name = "WxH")]
    viewport: Option<String>,

    /// Device scale factor for --viewport (default: 1.0)
    #[arg(long = "viewport-scale", default_value = "1.0")]
    viewport_scale: f64,

    // ── DOM inspection ────────────────────────────────────────────────────────

    /// Dump DOM tree starting at selector (use "body" for full page)
    #[arg(long, value_name = "SELECTOR")]
    dom: Option<String>,

    /// Maximum depth for --dom (default: 3)
    #[arg(long = "dom-depth", default_value = "3")]
    dom_depth: u32,

    /// Print bounding rect of the first matching element
    #[arg(long, value_name = "SELECTOR")]
    rect: Option<String>,

    // ── Raw CDP escape hatch ──────────────────────────────────────────────────

    /// Raw CDP method to call, e.g. --cdp "Page.reload"
    #[arg(long, value_name = "METHOD")]
    cdp: Option<String>,

    /// JSON params for --cdp, e.g. --cdp-params '{"ignoreCache":true}'
    #[arg(long = "cdp-params", value_name = "JSON")]
    cdp_params: Option<String>,

    // ── Network log ───────────────────────────────────────────────────────────

    /// Drain and print queued network events, then exit.
    #[arg(long = "network-poll")]
    network_poll: bool,

    // ── Performance / frames ─────────────────────────────────────────────────

    /// Dump Navigation Timing + Resource Timing entries.
    #[arg(long)]
    perf: bool,

    /// Count requestAnimationFrame callbacks over N seconds.
    #[arg(long = "frames-count", value_name = "SECONDS")]
    frames_count: Option<u64>,

    /// Poll window.MLC_FRAMES every 2 s indefinitely. Ctrl-C to quit.
    #[arg(long = "watch-frames")]
    watch_frames: bool,

    // ── Repetition ───────────────────────────────────────────────────────────

    /// Suppress progress chatter — only print final results.
    #[arg(long)]
    quiet: bool,
}

// ── Coordinate parsers ────────────────────────────────────────────────────────

fn parse_xy(s: &str) -> Result<(f64, f64), String> {
    let parts: Vec<&str> = s.split(',').collect();
    if parts.len() != 2 {
        return Err(format!("expected X,Y — got {s:?}"));
    }
    let x = parts[0].trim().parse::<f64>().map_err(|e| format!("bad X: {e}"))?;
    let y = parts[1].trim().parse::<f64>().map_err(|e| format!("bad Y: {e}"))?;
    Ok((x, y))
}

fn parse_xy_dx_dy(s: &str) -> Result<(f64, f64, f64, f64), String> {
    let parts: Vec<&str> = s.split(',').collect();
    if parts.len() != 4 {
        return Err(format!("expected X,Y,DX,DY — got {s:?}"));
    }
    let x = parts[0].trim().parse::<f64>().map_err(|e| format!("bad X: {e}"))?;
    let y = parts[1].trim().parse::<f64>().map_err(|e| format!("bad Y: {e}"))?;
    let dx = parts[2].trim().parse::<f64>().map_err(|e| format!("bad DX: {e}"))?;
    let dy = parts[3].trim().parse::<f64>().map_err(|e| format!("bad DY: {e}"))?;
    Ok((x, y, dx, dy))
}

fn parse_drag_coords(s: &str) -> Result<(f64, f64, f64, f64), String> {
    let parts: Vec<&str> = s.split(',').collect();
    if parts.len() != 4 {
        return Err(format!("expected X1,Y1,X2,Y2 — got {s:?}"));
    }
    let x1 = parts[0].trim().parse::<f64>().map_err(|e| format!("bad X1: {e}"))?;
    let y1 = parts[1].trim().parse::<f64>().map_err(|e| format!("bad Y1: {e}"))?;
    let x2 = parts[2].trim().parse::<f64>().map_err(|e| format!("bad X2: {e}"))?;
    let y2 = parts[3].trim().parse::<f64>().map_err(|e| format!("bad Y2: {e}"))?;
    Ok((x1, y1, x2, y2))
}

fn parse_viewport(s: &str) -> Result<(u32, u32), String> {
    let parts: Vec<&str> = s.split('x').collect();
    if parts.len() != 2 {
        return Err(format!("expected WxH — got {s:?}"));
    }
    let w = parts[0].trim().parse::<u32>().map_err(|e| format!("bad W: {e}"))?;
    let h = parts[1].trim().parse::<u32>().map_err(|e| format!("bad H: {e}"))?;
    Ok((w, h))
}

/// Parse a key-chord string like "Control+r" into (modifiers, key).
fn parse_chord(s: &str) -> (Vec<String>, String) {
    let parts: Vec<&str> = s.split('+').collect();
    let key = parts.last().copied().unwrap_or("").to_owned();
    let modifiers: Vec<String> = parts[..parts.len().saturating_sub(1)]
        .iter()
        .map(|m| m.to_string())
        .collect();
    (modifiers, key)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn drain_events(dt: &mut dig2browser::PageDevTools) -> (Vec<String>, Vec<String>) {
    let mut console = Vec::new();
    let mut network = Vec::new();
    while let Some(event) = dt.try_next() {
        match event {
            DevToolsEvent::Console(c) => {
                console.push(format!("[{}] {}", c.level, c.text));
            }
            DevToolsEvent::Network(n) => {
                let status = n.status.map(|s| s.to_string()).unwrap_or_else(|| "-".into());
                let url = n.url.as_deref().unwrap_or("-");
                network.push(format!("{} {} {}", n.method, status, url));
            }
        }
    }
    (console, network)
}

async fn eval_dims(page: &dig2browser::StealthPage) -> String {
    let js = r#"
        (function() {
            var mlc = window.MLC_FRAMES !== undefined ? window.MLC_FRAMES : '?';
            var cw = window.innerWidth || 0;
            var ch = window.innerHeight || 0;
            var sw = window.screen ? window.screen.width : 0;
            var sh = window.screen ? window.screen.height : 0;
            var canvas = document.querySelector('canvas');
            var cvs = canvas ? (canvas.width + 'x' + canvas.height) : 'no-canvas';
            return JSON.stringify({mlc: mlc, client: cw+'x'+ch, screen: sw+'x'+sh, canvas: cvs});
        })()
    "#;
    match page.eval(js).await {
        Ok(v) => {
            let s = v.as_str().unwrap_or("");
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(s) {
                format!(
                    "frames={} | client={} | screen={} | canvas={}",
                    parsed["mlc"].as_str().unwrap_or(&parsed["mlc"].to_string()),
                    parsed["client"].as_str().unwrap_or("?"),
                    parsed["screen"].as_str().unwrap_or("?"),
                    parsed["canvas"].as_str().unwrap_or("?"),
                )
            } else {
                format!("raw={s}")
            }
        }
        Err(e) => format!("eval-err: {e}"),
    }
}

fn log(quiet: bool, msg: &str) {
    if !quiet {
        eprintln!("{msg}");
    }
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    log(cli.quiet, &format!("[dev-attach] querying debug port {}...", cli.port));
    let ws_url = discover_ws_url(cli.port).await?;
    log(cli.quiet, &format!("[dev-attach] browser ws: {ws_url}"));

    let browser = StealthBrowser::attach(ws_url).await?;

    let pages = browser.pages().await?;
    if pages.is_empty() {
        eprintln!("[dev-attach] no page targets found in the browser");
        return Ok(());
    }

    let target_id = if let Some(prefix) = &cli.target {
        pages
            .iter()
            .find(|(_, url)| url.starts_with(prefix.as_str()))
            .map(|(id, _)| id.clone())
            .ok_or_else(|| {
                format!(
                    "no tab with URL starting with '{}'. Available:\n{}",
                    prefix,
                    pages
                        .iter()
                        .map(|(id, url)| format!("  {id}  {url}"))
                        .collect::<Vec<_>>()
                        .join("\n")
                )
            })?
    } else {
        pages
            .iter()
            .find(|(_, url)| url != "about:blank" && !url.is_empty())
            .or_else(|| pages.first())
            .map(|(id, _)| id.clone())
            .ok_or("no tabs found")?
    };

    log(cli.quiet, &format!("[dev-attach] attaching to tab: {target_id}"));
    let page = browser.attach_page(&target_id).await?;

    // ── One-shot actions ──────────────────────────────────────────────────────

    // --eval
    if let Some(js) = &cli.eval {
        let result = page.eval(js).await?;
        match &result {
            serde_json::Value::String(s) => println!("{s}"),
            other => println!("{}", serde_json::to_string_pretty(other)?),
        }
        return Ok(());
    }

    // --click
    if let Some(s) = &cli.click {
        let (x, y) = parse_xy(s).map_err(|e| format!("--click: {e}"))?;
        log(cli.quiet, &format!("[dev-attach] click at ({x},{y})"));
        page.click_at(x, y).await?;
    }

    // --right-click
    if let Some(s) = &cli.right_click {
        let (x, y) = parse_xy(s).map_err(|e| format!("--right-click: {e}"))?;
        log(cli.quiet, &format!("[dev-attach] right-click at ({x},{y})"));
        page.right_click_at(x, y).await?;
    }

    // --move
    if let Some(s) = &cli.r#move {
        let (x, y) = parse_xy(s).map_err(|e| format!("--move: {e}"))?;
        log(cli.quiet, &format!("[dev-attach] mouse move to ({x},{y})"));
        page.mouse_move(x, y).await?;
    }

    // --drag
    if let Some(s) = &cli.drag {
        let (x1, y1, x2, y2) = parse_drag_coords(s).map_err(|e| format!("--drag: {e}"))?;
        log(cli.quiet, &format!("[dev-attach] drag ({x1},{y1}) → ({x2},{y2})"));
        page.drag(x1, y1, x2, y2).await?;
    }

    // --wheel
    if let Some(s) = &cli.wheel {
        let (x, y, dx, dy) = parse_xy_dx_dy(s).map_err(|e| format!("--wheel: {e}"))?;
        log(cli.quiet, &format!("[dev-attach] wheel at ({x},{y}) delta=({dx},{dy})"));
        page.wheel(x, y, dx, dy).await?;
    }

    // --key
    if let Some(key) = &cli.key {
        log(cli.quiet, &format!("[dev-attach] key press: {key}"));
        page.key_press(key).await?;
    }

    // --key-chord
    if let Some(chord) = &cli.key_chord {
        let (modifiers, key) = parse_chord(chord);
        log(cli.quiet, &format!("[dev-attach] key chord: {chord}"));
        let mod_refs: Vec<&str> = modifiers.iter().map(|s| s.as_str()).collect();
        page.key_chord(&mod_refs, &key).await?;
    }

    // --viewport
    if let Some(vp) = &cli.viewport {
        let (w, h) = parse_viewport(vp).map_err(|e| format!("--viewport: {e}"))?;
        log(cli.quiet, &format!("[dev-attach] set viewport {w}x{h} scale={}", cli.viewport_scale));
        page.set_viewport(w, h, cli.viewport_scale).await?;
    }

    // --dom
    if let Some(selector) = &cli.dom {
        let sel = if selector.is_empty() { "body" } else { selector.as_str() };
        log(cli.quiet, &format!("[dev-attach] dom tree: {sel} (depth {})", cli.dom_depth));
        let tree = page.dom_tree(sel, cli.dom_depth).await?;
        println!("{}", serde_json::to_string_pretty(&tree)?);
        return Ok(());
    }

    // --rect
    if let Some(selector) = &cli.rect {
        match page.element_rect(selector).await? {
            Some((x, y, w, h)) => {
                println!("x={x} y={y} w={w} h={h}");
            }
            None => {
                println!("null (element not found: {selector})");
            }
        }
        return Ok(());
    }

    // --cdp
    if let Some(method) = &cli.cdp {
        let params: Option<serde_json::Value> = cli
            .cdp_params
            .as_deref()
            .map(|s| serde_json::from_str(s))
            .transpose()
            .map_err(|e| format!("--cdp-params JSON parse error: {e}"))?;
        log(cli.quiet, &format!("[dev-attach] cdp call: {method}"));
        let result = page.cdp_call(method, params).await?;
        println!("{}", serde_json::to_string_pretty(&result)?);
        return Ok(());
    }

    // --network-poll
    if cli.network_poll {
        let net = page.drain_network().await?;
        if net.is_empty() {
            println!("(no network events queued)");
        } else {
            for entry in &net {
                println!("{}", serde_json::to_string(entry)?);
            }
        }
        return Ok(());
    }

    // --perf
    if cli.perf {
        let entries = page.performance_entries().await?;
        println!("{}", serde_json::to_string_pretty(&entries)?);
        return Ok(());
    }

    // --frames-count N
    if let Some(secs) = cli.frames_count {
        log(cli.quiet, &format!("[dev-attach] counting frames for {secs}s…"));
        let count = page.count_frames(secs * 1000).await?;
        println!("{count}");
        return Ok(());
    }

    // --screenshot one-shot (no --interval)
    if let Some(ref path) = cli.screenshot {
        if cli.interval.is_none() {
            let bytes = page.screenshot().await?;
            std::fs::write(path, &bytes)?;
            log(cli.quiet, &format!("[dev-attach] screenshot saved: {}", path.display()));
            return Ok(());
        }
    }

    // ── Poll loop ────────────────────────────────────────────────────────────
    // Entered when --watch-console, --watch-frames, or --screenshot --interval.

    let mut events = page.devtools().await?;
    let t_start = Instant::now();
    let poll_ms = 2_000u64;
    let screenshot_interval = cli.interval.unwrap_or(0);
    let mut last_shot_at = Instant::now() - Duration::from_secs(screenshot_interval + 1);

    log(cli.quiet, "[dev-attach] entering poll loop — Ctrl-C to quit");
    log(
        cli.quiet,
        &format!(
            "[dev-attach] (--watch-console={}, --watch-frames={}, --screenshot={:?}, --interval={}s)",
            cli.watch_console,
            cli.watch_frames,
            cli.screenshot,
            screenshot_interval,
        ),
    );

    loop {
        tokio::time::sleep(Duration::from_millis(poll_ms)).await;

        let t = t_start.elapsed().as_secs();
        let dims = eval_dims(&page).await;

        if cli.watch_frames {
            println!("[t={t}s] {dims}");
        } else {
            println!("[t={t}s] {dims}");
        }

        let (console_msgs, _net) = drain_events(&mut events);
        if cli.watch_console {
            for msg in &console_msgs {
                println!("  console: {msg}");
            }
        }

        if let Some(ref path) = cli.screenshot {
            if screenshot_interval > 0 && last_shot_at.elapsed().as_secs() >= screenshot_interval {
                match page.screenshot().await {
                    Ok(bytes) => {
                        if let Err(e) = std::fs::write(path, &bytes) {
                            eprintln!("[dev-attach] screenshot write error: {e}");
                        } else {
                            log(
                                cli.quiet,
                                &format!(
                                    "[dev-attach] screenshot saved: {} ({} bytes)",
                                    path.display(),
                                    bytes.len()
                                ),
                            );
                        }
                    }
                    Err(e) => eprintln!("[dev-attach] screenshot error: {e}"),
                }
                last_shot_at = Instant::now();
            }
        }
    }
}
