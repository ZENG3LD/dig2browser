//! dev-fetch — quick CLI for testing stealth browser fetches.
//!
//! Usage:
//!   dev-fetch <URL> [--fingerprint path.json] [--headed] [--wait-selector "#id"]
//!              [--save-html out.html] [--save-screenshot out.png] [--profile ./profile]
//!              [--network-log] [--cookies] [--console] [--eval "JS"] [--dom "selector"]
//!              [--keep-open SECONDS]
//!
//! Prints a summary to stderr and writes HTML to stdout (unless --save-html is used).

use std::path::PathBuf;
use std::time::{Duration, Instant};

use clap::Parser;
use dig2browser::{
    BrowserPreference, BrowserProfile, LaunchConfig, LocaleProfile, StealthBrowser, StealthConfig,
    StealthLevel,
};
use dig2browser::DevToolsEvent;

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "dev-fetch", about = "Fetch a URL in the stealth browser and inspect the result")]
struct Cli {
    /// URL to fetch
    url: String,

    /// Path to a JSON fingerprint config file
    #[arg(long)]
    fingerprint: Option<PathBuf>,

    /// Launch a visible browser window instead of headless
    #[arg(long)]
    headed: bool,

    /// CSS selector to wait for before capturing HTML/screenshot
    #[arg(long)]
    wait_selector: Option<String>,

    /// Save HTML output to this file path
    #[arg(long)]
    save_html: Option<PathBuf>,

    /// Save screenshot PNG to this file path
    #[arg(long)]
    save_screenshot: Option<PathBuf>,

    /// Persistent browser profile directory
    #[arg(long)]
    profile: Option<PathBuf>,

    /// Show network request/response log after page load
    #[arg(long)]
    network_log: bool,

    /// Dump all cookies after page load
    #[arg(long)]
    cookies: bool,

    /// Show console messages (log/warn/error) captured during load
    #[arg(long)]
    console: bool,

    /// Execute JavaScript and print the result
    #[arg(long)]
    eval: Option<String>,

    /// Find elements matching a CSS selector and print their outer HTML
    #[arg(long)]
    dom: Option<String>,

    /// Keep the browser open for N seconds (useful with --headed for manual inspection)
    #[arg(long, value_name = "SECONDS")]
    keep_open: Option<u64>,
}

// ── Fingerprint config ────────────────────────────────────────────────────────

#[derive(serde::Deserialize, Default)]
struct FingerprintConfig {
    browser: Option<String>,
    level: Option<String>,
    locale: Option<String>,
    timezone: Option<String>,
    viewport: Option<[u32; 2]>,
    hardware_concurrency: Option<u32>,
    device_memory_gb: Option<u32>,
    user_agent: Option<String>,
}

impl FingerprintConfig {
    fn into_configs(self) -> (StealthConfig, BrowserPreference) {
        let level = match self.level.as_deref() {
            Some("basic") => StealthLevel::Basic,
            Some("standard_no_webgl") => StealthLevel::StandardNoWebGL,
            Some("full") => StealthLevel::Full,
            _ => StealthLevel::Standard,
        };

        let locale_tag = self.locale.clone().unwrap_or_else(|| "en-US".to_owned());
        let locale = LocaleProfile {
            locale: locale_tag,
            timezone: self.timezone.clone(),
        };

        let mut stealth = StealthConfig {
            level,
            locale,
            ..StealthConfig::default()
        };

        if let Some([w, h]) = self.viewport {
            stealth.viewport = (w, h);
        }
        if let Some(hc) = self.hardware_concurrency {
            stealth.hardware_concurrency = hc;
        }
        if let Some(dm) = self.device_memory_gb {
            stealth.device_memory_gb = dm;
        }
        if let Some(ua) = self.user_agent {
            stealth.user_agent = ua;
        }

        let pref = match self.browser.as_deref() {
            Some("firefox") => BrowserPreference::Firefox,
            Some("chrome") => BrowserPreference::ChromeOnly,
            Some("edge") => BrowserPreference::EdgeOnly,
            _ => BrowserPreference::Auto,
        };

        (stealth, pref)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn extract_title(html: &str) -> Option<String> {
    let lower = html.to_lowercase();
    let start = lower.find("<title>")? + 7;
    let end = lower[start..].find("</title>")?;
    Some(html[start..start + end].trim().to_string())
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Build stealth + browser preference from fingerprint (or defaults).
    let (stealth, browser_pref) = if let Some(fp_path) = &cli.fingerprint {
        let raw = std::fs::read_to_string(fp_path)?;
        let fp: FingerprintConfig = serde_json::from_str(&raw)?;
        fp.into_configs()
    } else {
        (StealthConfig::default(), BrowserPreference::Auto)
    };

    // --headed overrides headless regardless of fingerprint.
    let headless = !cli.headed;

    // --profile sets a persistent profile directory.
    let profile = match &cli.profile {
        Some(dir) => BrowserProfile::Persistent(dir.clone()),
        None => BrowserProfile::Ephemeral,
    };

    // Viewport from stealth config feeds into LaunchConfig window size.
    let window_size = stealth.viewport;

    let launch = LaunchConfig {
        headless,
        window_size,
        profile,
        browser_pref,
        ..LaunchConfig::default()
    };

    // Launch browser.
    let t0 = Instant::now();
    let browser = StealthBrowser::launch_with(launch, stealth).await?;

    // Always use new_blank_page so we can subscribe to devtools before navigation.
    let page = browser.new_blank_page().await?;

    // Subscribe to devtools events before navigation to capture everything.
    let need_devtools = cli.network_log || cli.console;
    let mut devtools = if need_devtools {
        Some(page.devtools().await?)
    } else {
        None
    };

    // Navigate.
    if let Some(selector) = &cli.wait_selector {
        page.goto_and_wait(&cli.url, selector, Duration::from_secs(30))
            .await?;
    } else {
        page.goto(&cli.url).await?;
    }

    let fetch_ms = t0.elapsed().as_millis();

    // Capture HTML and screenshot.
    let html = page.html().await?;
    let screenshot = page.screenshot().await?;

    // Summary to stderr.
    let title = extract_title(&html).unwrap_or_else(|| "(no title)".to_owned());
    eprintln!("URL:        {}", cli.url);
    eprintln!("Title:      {}", title);
    eprintln!("HTML size:  {} bytes", html.len());
    eprintln!("PNG size:   {} bytes", screenshot.len());
    eprintln!("Fetch time: {} ms", fetch_ms);

    // Drain all captured devtools events once into typed vecs.
    let mut network_events = Vec::new();
    let mut console_events = Vec::new();
    if let Some(ref mut dt) = devtools {
        while let Some(event) = dt.try_next() {
            match event {
                DevToolsEvent::Network(net) => network_events.push(net),
                DevToolsEvent::Console(con) => console_events.push(con),
            }
        }
    }

    // Network log.
    if cli.network_log {
        eprintln!("\n=== Network Log ({} requests) ===", network_events.len());
        for net in &network_events {
            let status = net
                .status
                .map(|s: u16| s.to_string())
                .unwrap_or_else(|| "-".to_string());
            let url = net.url.as_deref().unwrap_or("-");
            eprintln!("  {} {} {}", net.method, status, url);
        }
    }

    // Console messages.
    if cli.console {
        eprintln!("\n=== Console ({} messages) ===", console_events.len());
        for con in &console_events {
            eprintln!("  [{}] {}", con.level, con.text);
        }
    }

    // Cookies.
    if cli.cookies {
        let jar = page.get_cookies().await?;
        eprintln!("\n=== Cookies ({}) ===", jar.len());
        for c in jar.iter() {
            let secure = if c.is_secure { " secure" } else { "" };
            let httponly = if c.is_httponly { " httponly" } else { "" };
            eprintln!(
                "  {}={} [domain={} path={}{}{}]",
                c.name, c.value, c.domain, c.path, secure, httponly
            );
        }
    }

    // Eval.
    if let Some(js) = &cli.eval {
        let result = page.eval(js).await?;
        eprintln!("\n=== Eval Result ===");
        eprintln!("{}", serde_json::to_string_pretty(&result)?);
    }

    // DOM query.
    if let Some(selector) = &cli.dom {
        let elements = page.find_all(selector).await?;
        eprintln!(
            "\n=== DOM: {} ({} matches) ===",
            selector,
            elements.len()
        );
        for (i, el) in elements.iter().enumerate() {
            let el_html = el.html().await?;
            eprintln!("[{}] {}", i, el_html);
        }
    }

    // Keep open.
    if let Some(seconds) = cli.keep_open {
        eprintln!("\nKeeping browser open for {} seconds...", seconds);
        tokio::time::sleep(Duration::from_secs(seconds)).await;
    }

    // Persist outputs.
    if let Some(html_path) = &cli.save_html {
        std::fs::write(html_path, html.as_bytes())?;
        eprintln!("HTML saved: {}", html_path.display());
    }

    if let Some(ss_path) = &cli.save_screenshot {
        std::fs::write(ss_path, &screenshot)?;
        eprintln!("PNG saved:  {}", ss_path.display());
    }

    // If neither save flag was given, print HTML to stdout.
    if cli.save_html.is_none() && cli.save_screenshot.is_none() {
        print!("{}", html);
    }

    browser.close().await?;

    Ok(())
}
