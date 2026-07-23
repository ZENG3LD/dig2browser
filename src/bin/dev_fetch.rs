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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::Parser;
use dig2browser::DevToolsEvent;
use dig2browser::NetworkEvent;
use dig2browser::{
    BrowserPreference, BrowserProfile, BrowserProxy, LaunchConfig, LocaleProfile, StealthBrowser,
    StealthConfig, StealthLevel,
};

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "dev-fetch",
    about = "Fetch a URL in the stealth browser and inspect the result"
)]
struct Cli {
    /// URL to fetch
    url: String,

    /// Path to a JSON fingerprint config file
    #[arg(long)]
    fingerprint: Option<PathBuf>,

    /// Route the browser through a proxy, e.g. socks5://127.0.0.1:18080 or http://host:port
    #[arg(long)]
    proxy: Option<String>,

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

    /// Save deterministic capture metadata JSON to this file path
    #[arg(long)]
    save_metadata: Option<PathBuf>,

    /// Persistent browser profile directory
    #[arg(long)]
    profile: Option<PathBuf>,

    /// Show network request/response log after page load
    #[arg(long)]
    network_log: bool,

    /// Dump all cookies after page load
    #[arg(long)]
    cookies: bool,

    /// Include secret cookie values in --cookies output
    #[arg(long, requires = "cookies")]
    show_cookie_values: bool,

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

#[derive(serde::Serialize)]
struct CaptureMetadata<'a> {
    requested_url: &'a str,
    final_url: &'a str,
    http_status: Option<u16>,
    captured_at_unix_ms: u64,
    fetch_duration_ms: u64,
    title: Option<&'a str>,
    html_bytes: u64,
    screenshot_bytes: u64,
}

fn main_document_http_status(events: &[NetworkEvent], final_url: &str) -> Option<u16> {
    events.iter().rev().find_map(|event| {
        let status = event.status.filter(|status| (100..=599).contains(status))?;
        let event_url = event.url.as_deref()?;
        if !document_urls_match(event_url, final_url) {
            return None;
        }

        let is_main_document = match event.method.as_str() {
            "Network.responseReceived" => event.params["type"] == "Document",
            "network.responseCompleted" => event.params["navigation"].is_string(),
            _ => false,
        };
        is_main_document.then_some(status)
    })
}

fn document_urls_match(event_url: &str, final_url: &str) -> bool {
    event_url.split('#').next() == final_url.split('#').next()
}

fn unix_time_ms() -> Result<u64, Box<dyn std::error::Error>> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
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

    // --proxy socks5://host:port | http://host:port  (default scheme = socks5)
    let browser_proxy = cli.proxy.as_deref().map(|p| {
        let addr = p.split_once("://").map(|(_, a)| a).unwrap_or(p);
        let sa: std::net::SocketAddr = addr.parse().expect("invalid --proxy address (want host:port)");
        if p.starts_with("http") {
            BrowserProxy::Http(sa)
        } else {
            BrowserProxy::Socks5(sa)
        }
    });

    let launch = LaunchConfig {
        headless,
        window_size,
        profile,
        browser_pref,
        browser_proxy,
        ..LaunchConfig::default()
    };

    // Launch browser.
    let browser = StealthBrowser::launch_with(launch, stealth).await?;

    // Always use new_blank_page so we can subscribe to devtools before navigation.
    let page = browser.new_blank_page().await?;

    // Subscribe to devtools events before navigation to capture everything.
    let need_devtools = cli.network_log || cli.console || cli.save_metadata.is_some();
    let mut devtools = if need_devtools {
        Some(page.devtools().await?)
    } else {
        None
    };

    // Navigate.
    let fetch_started = Instant::now();
    if let Some(selector) = &cli.wait_selector {
        page.goto_and_wait(&cli.url, selector, Duration::from_secs(30))
            .await?;
    } else {
        page.goto(&cli.url).await?;
    }

    let fetch_ms = u64::try_from(fetch_started.elapsed().as_millis())?;

    // Capture HTML and screenshot.
    let html = page.html().await?;
    let screenshot = page.screenshot().await?;

    // Summary to stderr.
    let title = page
        .eval("document.title")
        .await?
        .as_str()
        .map(str::to_owned)
        .filter(|title| !title.trim().is_empty())
        .or_else(|| extract_title(&html));
    eprintln!("URL:        {}", cli.url);
    eprintln!("Title:      {}", title.as_deref().unwrap_or("(no title)"));
    eprintln!("HTML size:  {} bytes", html.len());
    eprintln!("PNG size:   {} bytes", screenshot.len());
    eprintln!("Fetch time: {} ms", fetch_ms);

    // Give late async events (SPA XHR, lazy resources) time to arrive.
    if need_devtools {
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

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
            let value = if cli.show_cookie_values {
                c.value.as_str()
            } else {
                "<redacted>"
            };
            eprintln!(
                "  {}={} [domain={} path={}{}{}]",
                c.name, value, c.domain, c.path, secure, httponly
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
        eprintln!("\n=== DOM: {} ({} matches) ===", selector, elements.len());
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

    if let Some(metadata_path) = &cli.save_metadata {
        let final_url = page
            .eval("window.location.href")
            .await?
            .as_str()
            .ok_or("window.location.href did not evaluate to a string")?
            .to_owned();
        let metadata = CaptureMetadata {
            requested_url: &cli.url,
            final_url: &final_url,
            http_status: main_document_http_status(&network_events, &final_url),
            captured_at_unix_ms: unix_time_ms()?,
            fetch_duration_ms: fetch_ms,
            title: title.as_deref(),
            html_bytes: u64::try_from(html.len())?,
            screenshot_bytes: u64::try_from(screenshot.len())?,
        };
        let mut json = serde_json::to_vec_pretty(&metadata)?;
        json.push(b'\n');
        std::fs::write(metadata_path, json)?;
        eprintln!("Metadata saved: {}", metadata_path.display());
    }

    // If neither save flag was given, print HTML to stdout.
    if cli.save_html.is_none() && cli.save_screenshot.is_none() {
        print!("{}", html);
    }

    browser.close().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn network_event(
        method: &str,
        url: &str,
        status: u16,
        params: serde_json::Value,
    ) -> NetworkEvent {
        NetworkEvent {
            method: method.to_owned(),
            url: Some(url.to_owned()),
            status: Some(status),
            params,
        }
    }

    #[test]
    fn derives_only_matching_main_document_status() {
        let events = vec![
            network_event(
                "Network.responseReceived",
                "https://example.com/app.js",
                404,
                json!({"type": "Script"}),
            ),
            network_event(
                "Network.responseReceived",
                "https://example.com/missing",
                404,
                json!({"type": "Document"}),
            ),
        ];
        assert_eq!(
            main_document_http_status(&events, "https://example.com/missing#details"),
            Some(404)
        );
    }

    #[test]
    fn bidi_status_requires_navigation_evidence() {
        let resource = network_event(
            "network.responseCompleted",
            "https://example.com/gone",
            410,
            json!({"navigation": null}),
        );
        assert_eq!(
            main_document_http_status(&[resource], "https://example.com/gone"),
            None
        );

        let document = network_event(
            "network.responseCompleted",
            "https://example.com/gone",
            410,
            json!({"navigation": "navigation-id"}),
        );
        assert_eq!(
            main_document_http_status(&[document], "https://example.com/gone"),
            Some(410)
        );
    }
}
