//! dev-launch-debug — launch Chrome/Edge with --remote-debugging-port and an
//! isolated user-data-dir, then print the DevTools WebSocket URL on stdout.
//!
//! # Usage
//!
//!   dev-launch-debug --port 9222
//!   dev-launch-debug --port 9222 --url http://127.0.0.1:17499/index.html
//!   dev-launch-debug --port 9222 --profile /tmp/myprofile
//!
//! On Ctrl-C the launched browser process is killed.
//! The discovered DevTools ws:// URL is printed on stdout so it can be
//! consumed by scripts:
//!
//!   WS=$(dev-launch-debug --port 9222)
//!   dev-attach --port 9222 --target http://127.0.0.1:17499 --watch-console

use std::path::PathBuf;

use clap::Parser;
use dig2browser::discover_ws_url;

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "dev-launch-debug",
    about = "Launch Chrome/Edge with --remote-debugging-port and an isolated profile"
)]
struct Cli {
    /// Remote debugging port (default: 9222)
    #[arg(long, default_value = "9222")]
    port: u16,

    /// User-data-dir for the isolated profile.
    /// Default: $TEMP/dig2browser-debug-<PORT>
    #[arg(long, value_name = "DIR")]
    profile: Option<PathBuf>,

    /// URL to open after launch (optional).
    #[arg(long)]
    url: Option<String>,
}

// ── Browser detection (lightweight re-use of dig2browser::detect) ─────────────

fn find_browser() -> Result<PathBuf, String> {
    // Env-var overrides first.
    for env in &["CHROME_PATH", "EDGE_PATH"] {
        if let Ok(v) = std::env::var(env) {
            let p = PathBuf::from(&v);
            if p.exists() {
                return Ok(p);
            }
        }
    }

    let mut candidates: Vec<String> = Vec::new();
    if cfg!(target_os = "windows") {
        candidates.push(r"C:\Program Files\Google\Chrome\Application\chrome.exe".into());
        candidates.push(r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe".into());
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            candidates.push(format!(r"{}\Google\Chrome\Application\chrome.exe", local));
        }
        candidates.push(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe".into());
        candidates.push(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe".into());
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            candidates.push(format!(r"{}\Microsoft\Edge\Application\msedge.exe", local));
        }
    } else if cfg!(target_os = "macos") {
        candidates.push("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome".into());
        candidates.push("/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge".into());
        candidates.push("/Applications/Chromium.app/Contents/MacOS/Chromium".into());
    } else {
        candidates.push("/usr/bin/google-chrome".into());
        candidates.push("/usr/bin/chromium-browser".into());
        candidates.push("/usr/bin/chromium".into());
        candidates.push("/usr/bin/microsoft-edge".into());
    }

    for path in &candidates {
        if std::path::Path::new(path).exists() {
            return Ok(PathBuf::from(path));
        }
    }

    Err(format!(
        "no Chrome/Edge binary found. Tried: {}. Set CHROME_PATH or EDGE_PATH env var.",
        candidates.join(", ")
    ))
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Resolve profile directory.
    let profile_dir = match cli.profile {
        Some(p) => p,
        None => {
            let mut tmp = std::env::temp_dir();
            tmp.push(format!("dig2browser-debug-{}", cli.port));
            tmp
        }
    };

    // Create profile dir if it doesn't exist.
    std::fs::create_dir_all(&profile_dir)?;

    let browser = find_browser()
        .map_err(|e| format!("browser not found: {e}"))?;

    eprintln!(
        "[dev-launch-debug] launching: {}",
        browser.display()
    );
    eprintln!(
        "[dev-launch-debug] profile:   {}",
        profile_dir.display()
    );
    eprintln!("[dev-launch-debug] port:      {}", cli.port);

    let mut args = vec![
        format!("--remote-debugging-port={}", cli.port),
        format!("--user-data-dir={}", profile_dir.display()),
        "--no-first-run".to_owned(),
        "--no-default-browser-check".to_owned(),
        "--disable-background-networking".to_owned(),
        "--disable-sync".to_owned(),
        "--disable-translate".to_owned(),
        "--safebrowsing-disable-auto-update".to_owned(),
        "--metrics-recording-only".to_owned(),
        "--disable-extensions".to_owned(),
    ];

    if let Some(url) = cli.url {
        args.push(url);
    }

    let mut child = tokio::process::Command::new(&browser)
        .args(&args)
        .stderr(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("failed to spawn browser: {e}"))?;

    eprintln!("[dev-launch-debug] browser spawned (pid {:?}), waiting for DevTools URL…", child.id());

    // Poll discover_ws_url until the browser is ready (up to 30 s).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let ws_url = loop {
        if std::time::Instant::now() >= deadline {
            return Err("timed out waiting for Chrome DevTools to become available".into());
        }
        match discover_ws_url(cli.port).await {
            Ok(url) => break url,
            Err(_) => {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        }
    };

    // Print the URL on stdout (for script consumption).
    println!("{ws_url}");
    eprintln!("[dev-launch-debug] ready — DevTools ws URL printed on stdout");
    eprintln!("[dev-launch-debug] Ctrl-C to quit and kill the browser");

    // Stay alive until Ctrl-C.
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            eprintln!("[dev-launch-debug] shutting down…");
            let _ = child.kill().await;
        }
        status = child.wait() => {
            match status {
                Ok(s) => eprintln!("[dev-launch-debug] browser exited: {s}"),
                Err(e) => eprintln!("[dev-launch-debug] browser wait error: {e}"),
            }
        }
    }

    Ok(())
}
