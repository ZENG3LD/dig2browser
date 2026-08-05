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
//! # Hang forensics
//!
//!   dev-attach --port 9222 --hang-report
//!   dev-attach --port 9222 --hang-report --recover
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

    /// Press the left button WITHOUT releasing (mid-drag inspection:
    /// --down, then --move steps, screenshot the frozen frame, --up)
    #[arg(long, value_name = "X,Y")]
    down: Option<String>,

    /// Release the left button (closes a prior --down)
    #[arg(long, value_name = "X,Y")]
    up: Option<String>,

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

    /// Clear any device-metrics override stuck on the tab (undo a persona /
    /// --viewport pin) — the page returns to the browser's native size.
    #[arg(long = "clear-viewport")]
    clear_viewport: bool,

    /// Heal a stale renderer viewport (innerWidth disagreeing with the real
    /// window, e.g. after mixed-DPI monitor moves or a leftover persona
    /// pin): forces a device-metrics set→clear cycle — the CDP equivalent
    /// of grabbing the window border — then prints the resulting metrics.
    #[arg(long = "fix-viewport")]
    fix_viewport: bool,

    // ── Persona ──────────────────────────────────────────────────────────────

    /// Persona SOURCE — which of the three identity modes to use:
    ///   user                      the browser's own identity (DEFAULT)
    ///   random[:SEED]             coherent generated persona
    ///   catalog:<path>[#id]       record from a .json / .sqlite catalog
    /// Default `user` applies no overrides at all, so the page keeps
    /// following the real window.
    #[arg(long, value_name = "SPEC", default_value = "user")]
    persona: String,

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

    // ── Hang forensics ────────────────────────────────────────────────────────

    /// Diagnose a page whose main thread has stopped answering: probe it, then
    /// CPU-profile the stuck isolate and print what it is spinning in.
    ///
    /// Console and app logs go silent when the main thread blocks — no events
    /// are emitted at all — so the log is empty exactly when it matters. The V8
    /// profiler is served off that thread and keeps sampling, which makes it
    /// the one channel that still talks.
    #[arg(long = "hang-report")]
    hang_report: bool,

    /// Seconds to sample for --hang-report (default 3).
    #[arg(long = "hang-seconds", value_name = "SECONDS", default_value_t = 3)]
    hang_seconds: u64,

    /// After reporting, take the thread back: Runtime.terminateExecution, then
    /// Page.reload if that was not enough. Off by default — evidence first.
    #[arg(long)]
    recover: bool,

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

    // Hang forensics run BEFORE the attach and never touch it. Attaching
    // negotiates with the page, and a page whose main thread is blocked cannot
    // answer that negotiation — the tool meant for a wedged tab must not need
    // the tab to be well.
    if cli.hang_report {
        return hang_report(
            cli.port,
            cli.target.as_deref(),
            cli.hang_seconds,
            cli.recover,
            cli.quiet,
        )
        .await;
    }

    log(cli.quiet, &format!("[dev-attach] querying debug port {}...", cli.port));
    let ws_url = discover_ws_url(cli.port).await?;
    log(cli.quiet, &format!("[dev-attach] browser ws: {ws_url}"));

    // Persona source — three modes, default `user` (the browser's own
    // identity, zero overrides, so the page keeps following the real
    // window). `random` / `catalog` are explicit opt-ins.
    let persona_source = dig2browser::stealth::PersonaSource::parse(&cli.persona)
        .map_err(|e| format!("--persona: {e}"))?;
    log(
        cli.quiet,
        &format!("[dev-attach] persona mode: {}", persona_source.mode_name()),
    );
    let browser = StealthBrowser::attach_with_persona(ws_url, &persona_source).await?;

    let pages = browser.pages().await?;
    if pages.is_empty() {
        eprintln!("[dev-attach] no page targets found in the browser");
        return Ok(());
    }

    let target_id = if let Some(prefix) = &cli.target {
        pages
            .iter()
            .find(|(_, url, _)| url.starts_with(prefix.as_str()))
            .map(|(id, _, _)| id.clone())
            .ok_or_else(|| {
                format!(
                    "no tab with URL starting with '{}'. Available:\n{}",
                    prefix,
                    pages
                        .iter()
                        .map(|(id, url, _)| format!("  {id}  {url}"))
                        .collect::<Vec<_>>()
                        .join("\n")
                )
            })?
    } else {
        pages
            .iter()
            .find(|(_, url, _)| url != "about:blank" && !url.is_empty())
            .or_else(|| pages.first())
            .map(|(id, _, _)| id.clone())
            .ok_or("no tabs found")?
    };

    log(cli.quiet, &format!("[dev-attach] attaching to tab: {target_id}"));
    let page = browser.attach_page(&target_id).await?;

    // ── One-shot actions ──────────────────────────────────────────────────────
    // Input actions run FIRST, --eval runs after them (it used to early-return
    // before the input block, silently swallowing every `--click … --eval` /
    // `--move … --eval` combo — the clicks never fired).

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

    // --down (button press held across process exits — CDP state lives in
    // the browser, so a later --move / --up invocation continues the drag)
    if let Some(s) = &cli.down {
        let (x, y) = parse_xy(s).map_err(|e| format!("--down: {e}"))?;
        log(cli.quiet, &format!("[dev-attach] mouse down at ({x},{y})"));
        page.mouse_down(x, y).await?;
    }

    // --up
    if let Some(s) = &cli.up {
        let (x, y) = parse_xy(s).map_err(|e| format!("--up: {e}"))?;
        log(cli.quiet, &format!("[dev-attach] mouse up at ({x},{y})"));
        page.mouse_up(x, y).await?;
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

    // --eval — runs AFTER the input actions above so combos like
    // `--move … --eval 1` actually move first.
    if let Some(js) = &cli.eval {
        let result = page.eval(js).await?;
        match &result {
            serde_json::Value::String(s) => println!("{s}"),
            other => println!("{}", serde_json::to_string_pretty(other)?),
        }
        return Ok(());
    }

    // Pure input invocations are one-shot: exit unless another action
    // (screenshot / watch / viewport / dom / rect / network) still needs
    // the connection — otherwise main falls through into the poll loop.
    let did_input = cli.click.is_some()
        || cli.right_click.is_some()
        || cli.r#move.is_some()
        || cli.drag.is_some()
        || cli.down.is_some()
        || cli.up.is_some()
        || cli.wheel.is_some()
        || cli.key.is_some()
        || cli.key_chord.is_some();
    if did_input
        && cli.screenshot.is_none()
        && !cli.watch_console
        && !cli.clear_viewport
        && !cli.fix_viewport
        && cli.viewport.is_none()
        && cli.dom.is_none()
        && cli.rect.is_none()
        && !cli.network_poll
    {
        return Ok(());
    }

    // --clear-viewport — strip a stuck device-metrics override (persona or
    // --viewport residue) so the page follows the real window again.
    // One-shot: exits unless another action (eval/screenshot/watch) is also
    // requested — otherwise main would fall through into the poll loop.
    if cli.clear_viewport {
        page.clear_viewport_override().await?;
        log(cli.quiet, "[dev-attach] device-metrics override cleared");
        if cli.eval.is_none() && cli.screenshot.is_none() && !cli.watch_console && !cli.fix_viewport {
            return Ok(());
        }
    }

    // --fix-viewport — set→clear metrics cycle: flushes a stale renderer
    // size the way a manual window-border drag does. The set value is
    // irrelevant (clear discards it); the CYCLE forces Chrome to recompute
    // native metrics from the real window. Proven live 2026-07-29 against
    // a page whose innerWidth was stuck at 1920 in a 960px window.
    if cli.fix_viewport {
        page.set_viewport(100, 100, 0.0).await?;
        page.clear_viewport_override().await?;
        let v = page
            .eval("JSON.stringify({inner:[window.innerWidth,window.innerHeight],outer:[window.outerWidth,window.outerHeight],dpr:window.devicePixelRatio})")
            .await?;
        let v_str = match &v {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        log(cli.quiet, &format!("[dev-attach] viewport cycle done: {v_str}"));
        if cli.eval.is_none() && cli.screenshot.is_none() && !cli.watch_console {
            return Ok(());
        }
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

// ── Hang forensics ───────────────────────────────────────────────────────────
//
// Everything below speaks raw CDP over the PAGE's own websocket. Nothing here
// goes through the library's attach path: that path negotiates with the page,
// and a page whose main thread is blocked cannot answer.

/// How long a liveness probe may take before the page counts as wedged.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
/// A wedged page cannot answer, so every CDP call needs its own ceiling.
const CDP_TIMEOUT: Duration = Duration::from_secs(5);

type Ws = tokio_tungstenite::WebSocketStream<
    tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
>;

/// Diagnose — and optionally revive — a page whose main thread has stopped.
///
/// The order is deliberate: EVIDENCE first, recovery second, and recovery only
/// when asked. A wedged renderer is the only place the stack that caused it
/// still exists; reloading the tab destroys it, and the bug becomes a story
/// instead of a stack trace.
async fn hang_report(
    port: u16,
    target: Option<&str>,
    seconds: u64,
    recover: bool,
    quiet: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (title, url, target_id) = pick_target(port, target).await?;
    log(quiet, &format!("[dev-attach] page: {title} — {url}"));

    // The BROWSER endpoint, not the page's own socket. A session opened
    // straight onto a page is a legacy session and every command on it queues
    // behind the main thread — which is precisely the thread that is stuck. A
    // flat session attached from the browser endpoint is what DevTools itself
    // uses, and it is the one that routes `Debugger.pause` and
    // `Runtime.terminateExecution` out of band.
    let browser_ws = browser_ws_url(port).await?;
    let (mut ws, _) = tokio_tungstenite::connect_async(&browser_ws).await?;
    let mut next_id = 1_u64;
    let session = attach_flat(&mut ws, &mut next_id, &target_id)
        .await
        .ok_or("could not attach a flat session to the page")?;
    let session = Some(session);

    let alive = probe_alive(&mut ws, &mut next_id, &session).await;
    println!("main thread: {}", if alive { "responding" } else { "BLOCKED" });

    if alive {
        // A live page answers the profiler, which is the useful question here:
        // not "is it stuck" but "what is it spending itself on".
        log(quiet, "[dev-attach] sampling the isolate...");
        match cpu_profile(&mut ws, &mut next_id, &session, seconds).await {
            Ok(frames) if !frames.is_empty() => {
                println!("\nhottest frames ({seconds}s sample, self time):");
                for (name, url, line, hits, pct) in frames.iter().take(15) {
                    let where_ = if url.is_empty() {
                        String::new()
                    } else {
                        format!("  {url}:{line}")
                    };
                    println!("  {pct:>5.1}%  {hits:>6} samples  {name}{where_}");
                }
            }
            Ok(_) => println!("\nprofiler returned no samples — the isolate never ran in the window"),
            Err(e) => println!("\nprofiler unavailable: {e}"),
        }
        return Ok(());
    }

    // BLOCKED. The profiler is served BY the stuck thread, so it answers
    // nothing — measured, not assumed. What still lands is the debugger's
    // interrupt: `Debugger.pause` is delivered out of band, exactly as the
    // DevTools stop button does it during a runaway script, and the resulting
    // `Debugger.paused` event carries the stack that is spinning.
    log(quiet, "[dev-attach] interrupting the stuck thread...");
    match pause_stack(&mut ws, &mut next_id, &session).await {
        Some(frames) if !frames.is_empty() => {
            println!("\nstack at the moment of the interrupt (innermost first):");
            for (i, (name, url, line, col)) in frames.iter().enumerate().take(20) {
                let where_ = if url.is_empty() {
                    String::new()
                } else {
                    format!("  {url}:{line}:{col}")
                };
                println!("  #{i:<2} {name}{where_}");
            }
        }
        Some(_) => println!("\nthe interrupt landed but the stack came back empty"),
        None => println!("\nthe debugger interrupt did not land either — the renderer is beyond CDP"),
    }

    if !recover {
        println!("\nnot recovering (pass --recover). The tab is still stopped, and the stack above dies with it.");
        return Ok(());
    }

    println!("\nrecovering: Runtime.terminateExecution");
    let _ = call(&mut ws, &mut next_id, &session, "Runtime.terminateExecution", serde_json::json!({})).await;
    if probe_alive(&mut ws, &mut next_id, &session).await {
        println!("recovered: the thread came back without a reload");
        return Ok(());
    }
    println!("still blocked: Page.reload");
    let _ = call(&mut ws, &mut next_id, &session, "Page.reload", serde_json::json!({})).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    if probe_alive(&mut ws, &mut next_id, &session).await {
        println!("after reload: responding");
        return Ok(());
    }

    // Last resort: the renderer is past every in-page command, so replace the
    // TAB. This is the one recovery that always works and the one that costs
    // the most — the old renderer, and any evidence still inside it, goes with
    // it. It runs last for that reason.
    println!("after reload: STILL BLOCKED — recycling the tab");
    let fresh = call(
        &mut ws,
        &mut next_id,
        &None,
        "Target.createTarget",
        serde_json::json!({ "url": url }),
    )
    .await
    .and_then(|r| r.get("targetId").and_then(|v| v.as_str()).map(str::to_string));
    match fresh {
        Some(new_id) => {
            let _ = call(
                &mut ws,
                &mut next_id,
                &None,
                "Target.closeTarget",
                serde_json::json!({ "targetId": target_id }),
            )
            .await;
            println!("recycled: {url} is open again on target {new_id}; the wedged tab is closed");
        }
        None => println!("could not open a replacement tab — the browser itself may be in trouble"),
    }
    Ok(())
}

/// Pick the page to look at. The browser process serves this list whatever
/// the renderer is doing.
async fn pick_target(
    port: u16,
    target: Option<&str>,
) -> Result<(String, String, String), Box<dyn std::error::Error>> {
    let list: serde_json::Value = reqwest::get(format!("http://127.0.0.1:{port}/json/list"))
        .await?
        .json()
        .await?;
    let pages = list.as_array().ok_or("/json/list did not return an array")?;
    let pick = pages
        .iter()
        .filter(|t| t.get("type").and_then(|v| v.as_str()) == Some("page"))
        .find(|t| match target {
            Some(prefix) => t
                .get("url")
                .and_then(|v| v.as_str())
                .is_some_and(|u| u.starts_with(prefix)),
            None => t.get("url").and_then(|v| v.as_str()) != Some("about:blank"),
        })
        .ok_or("no matching page target")?;
    Ok((
        pick.get("title").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        pick.get("url").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        pick.get("id").and_then(|v| v.as_str()).ok_or("target has no id")?.to_string(),
    ))
}

async fn browser_ws_url(port: u16) -> Result<String, Box<dyn std::error::Error>> {
    let v: serde_json::Value = reqwest::get(format!("http://127.0.0.1:{port}/json/version"))
        .await?
        .json()
        .await?;
    Ok(v.get("webSocketDebuggerUrl")
        .and_then(|u| u.as_str())
        .ok_or("browser endpoint exposes no webSocketDebuggerUrl")?
        .to_string())
}

/// Attach a FLAT session to the target and return its id.
async fn attach_flat(ws: &mut Ws, next_id: &mut u64, target_id: &str) -> Option<String> {
    let r = call(
        ws,
        next_id,
        &None,
        "Target.attachToTarget",
        serde_json::json!({ "targetId": target_id, "flatten": true }),
    )
    .await?;
    r.get("sessionId").and_then(|v| v.as_str()).map(str::to_string)
}

/// One CDP round-trip: send, then read until the reply with our id arrives,
/// dropping the events that stream past in the meantime.
async fn call(
    ws: &mut Ws,
    next_id: &mut u64,
    session: &Option<String>,
    method: &str,
    params: serde_json::Value,
) -> Option<serde_json::Value> {
    call_within(ws, next_id, session, method, params, CDP_TIMEOUT).await
}

async fn call_within(
    ws: &mut Ws,
    next_id: &mut u64,
    session: &Option<String>,
    method: &str,
    params: serde_json::Value,
    limit: Duration,
) -> Option<serde_json::Value> {
    use futures::{SinkExt, StreamExt};
    let id = *next_id;
    *next_id += 1;
    let mut envelope = serde_json::json!({ "id": id, "method": method, "params": params });
    if let Some(sid) = session {
        envelope["sessionId"] = serde_json::Value::String(sid.clone());
    }
    let msg = envelope.to_string();
    ws.send(tokio_tungstenite::tungstenite::Message::Text(msg.into()))
        .await
        .ok()?;

    let deadline = tokio::time::Instant::now() + limit;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        let next = tokio::time::timeout(remaining, ws.next()).await.ok()??.ok()?;
        let text = match next {
            tokio_tungstenite::tungstenite::Message::Text(t) => t,
            _ => continue,
        };
        let v: serde_json::Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if v.get("id").and_then(|x| x.as_u64()) == Some(id) {
            return v.get("result").cloned().or(Some(serde_json::Value::Null));
        }
    }
}

/// One bounded round-trip through the renderer's JS thread.
async fn probe_alive(ws: &mut Ws, next_id: &mut u64, session: &Option<String>) -> bool {
    call_within(
        ws,
        next_id,
        session,
        "Runtime.evaluate",
        serde_json::json!({ "expression": "1", "returnByValue": true }),
        PROBE_TIMEOUT,
    )
    .await
    .is_some()
}

/// Sample the isolate and fold the flat profile into self-time per function.
///
/// `Profiler.*` is served off the main thread, so it answers while JS is
/// spinning — including inside wasm, where the frames come back with the Rust
/// symbol names a dev build carries in its name section.
async fn cpu_profile(
    ws: &mut Ws,
    next_id: &mut u64,
    session: &Option<String>,
    seconds: u64,
) -> Result<Vec<(String, String, i64, u64, f64)>, String> {
    call(ws, next_id, session, "Profiler.enable", serde_json::json!({}))
        .await
        .ok_or("Profiler.enable did not answer")?;
    call(
        ws,
        next_id,
        session,
        "Profiler.setSamplingInterval",
        serde_json::json!({ "interval": 200 }),
    )
    .await;
    call(ws, next_id, session, "Profiler.start", serde_json::json!({}))
        .await
        .ok_or("Profiler.start did not answer")?;

    tokio::time::sleep(Duration::from_secs(seconds.max(1))).await;

    let stopped = call(ws, next_id, session, "Profiler.stop", serde_json::json!({}))
        .await
        .ok_or("Profiler.stop did not answer")?;
    let nodes = stopped
        .get("profile")
        .and_then(|p| p.get("nodes"))
        .and_then(|n| n.as_array())
        .ok_or("profile carried no nodes")?;

    let total: u64 = nodes
        .iter()
        .map(|n| n.get("hitCount").and_then(|h| h.as_u64()).unwrap_or(0))
        .sum();
    let mut rows: Vec<(String, String, i64, u64, f64)> = nodes
        .iter()
        .filter_map(|n| {
            let hits = n.get("hitCount").and_then(|h| h.as_u64()).unwrap_or(0);
            if hits == 0 {
                return None;
            }
            let f = n.get("callFrame")?;
            let name = f
                .get("functionName")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .unwrap_or("(anonymous)")
                .to_string();
            let url = f.get("url").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let line = f.get("lineNumber").and_then(|v| v.as_i64()).unwrap_or(-1) + 1;
            let pct = if total > 0 {
                hits as f64 * 100.0 / total as f64
            } else {
                0.0
            };
            Some((name, url, line, hits, pct))
        })
        .collect();
    rows.sort_by(|a, b| b.3.cmp(&a.3));
    Ok(rows)
}

/// Interrupt a spinning isolate and read the stack it was in.
///
/// `Debugger.pause` is the one command that reaches a blocked main thread —
/// V8 takes it as an interrupt rather than as a queued message, which is why
/// the DevTools stop button works on a runaway loop while everything else in
/// the panel is frozen. `Debugger.enable` is sent first WITHOUT waiting for
/// its reply: that reply is queued behind the loop and will never come, but
/// the domain is armed by the time the interrupt fires.
async fn pause_stack(
    ws: &mut Ws,
    next_id: &mut u64,
    session: &Option<String>,
) -> Option<Vec<(String, String, i64, i64)>> {
    use futures::SinkExt;
    for method in ["Debugger.enable", "Debugger.pause"] {
        let id = *next_id;
        *next_id += 1;
        let mut envelope = serde_json::json!({ "id": id, "method": method, "params": {} });
        if let Some(sid) = session {
            envelope["sessionId"] = serde_json::Value::String(sid.clone());
        }
        let msg = envelope.to_string();
        ws.send(tokio_tungstenite::tungstenite::Message::Text(msg.into()))
            .await
            .ok()?;
    }
    let paused = wait_for_event(ws, "Debugger.paused", Duration::from_secs(5)).await?;
    let frames = paused.get("params")?.get("callFrames")?.as_array()?;
    Some(
        frames
            .iter()
            .filter_map(|f| {
                let name = f
                    .get("functionName")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .unwrap_or("(anonymous)")
                    .to_string();
                let loc = f.get("location")?;
                let url = f
                    .get("url")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let line = loc.get("lineNumber").and_then(|v| v.as_i64()).unwrap_or(-1) + 1;
                let col = loc.get("columnNumber").and_then(|v| v.as_i64()).unwrap_or(0);
                Some((name, url, line, col))
            })
            .collect(),
    )
}

/// Read messages until the named event shows up, or the window closes.
async fn wait_for_event(
    ws: &mut Ws,
    method: &str,
    limit: Duration,
) -> Option<serde_json::Value> {
    use futures::StreamExt;
    let deadline = tokio::time::Instant::now() + limit;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        let next = tokio::time::timeout(remaining, ws.next()).await.ok()??.ok()?;
        let text = match next {
            tokio_tungstenite::tungstenite::Message::Text(t) => t,
            _ => continue,
        };
        let v: serde_json::Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if v.get("method").and_then(|m| m.as_str()) == Some(method) {
            return Some(v);
        }
    }
}
