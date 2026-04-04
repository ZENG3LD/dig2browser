//! Smoke test: stealth injection, cookies, and DevTools events against real Chrome.
//!
//! Run with: `cargo run --example smoke_stealth`
//!
//! Tests:
//!   1. Launch Chrome with default (Standard) stealth config
//!   2. Navigate to bot.sannysoft.com — a public bot-detection test page
//!   3. Eval JS to verify stealth patches: navigator.webdriver, window.chrome, plugins
//!   4. Screenshot the bot-detection results page
//!   5. Navigate to httpbin.org and read cookies
//!   6. Subscribe to DevTools network events, navigate, collect events
//!   7. Close browser

use std::time::Duration;

use dig2browser::{DevToolsEvent, StealthBrowser};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== SMOKE TEST: Stealth + Cookies + DevTools ===\n");

    // ── 1. Launch Chrome ──────────────────────────────────────────────────────
    println!("[1] Launching Chrome with default stealth (Standard level)...");
    let browser = StealthBrowser::launch().await?;
    println!("    OK: Browser launched");

    // ── 2. Bot-detection page ─────────────────────────────────────────────────
    println!("[2] Navigating to https://bot.sannysoft.com/ ...");
    let page = browser.new_page("https://bot.sannysoft.com/").await?;
    // Give the page a moment to fully execute its detection scripts.
    tokio::time::sleep(Duration::from_secs(3)).await;
    println!("    OK: Page loaded");

    // ── 3. Stealth checks via JS eval ─────────────────────────────────────────
    println!("[3] Checking stealth indicators via JS eval...");

    // navigator.webdriver must be false (or undefined)
    let webdriver = page.eval("navigator.webdriver").await?;
    println!(
        "    navigator.webdriver = {} (want false/null)",
        webdriver
    );
    let wd_ok = webdriver.as_bool() == Some(false) || webdriver.is_null();
    println!(
        "    webdriver check: {}",
        if wd_ok { "PASS" } else { "FAIL (exposed!)" }
    );

    // window.chrome must exist
    let chrome_exists = page.eval("typeof window.chrome !== 'undefined'").await?;
    println!("    window.chrome exists: {} (want true)", chrome_exists);
    let chrome_ok = chrome_exists.as_bool() == Some(true);
    println!(
        "    chrome check: {}",
        if chrome_ok { "PASS" } else { "FAIL (missing!)" }
    );

    // chrome.csi must be a function
    let csi_type = page.eval("typeof window.chrome?.csi").await?;
    println!("    typeof window.chrome.csi = {} (want 'function')", csi_type);

    // navigator.plugins must be non-empty (we inject 3)
    let plugin_count = page
        .eval("navigator.plugins.length")
        .await?;
    println!("    navigator.plugins.length = {} (want >= 3)", plugin_count);
    let plugins_ok = plugin_count.as_u64().unwrap_or(0) >= 3;
    println!(
        "    plugins check: {}",
        if plugins_ok { "PASS" } else { "FAIL (no plugins!)" }
    );

    // navigator.languages must be non-empty
    let lang = page.eval("navigator.languages[0]").await?;
    println!("    navigator.languages[0] = {}", lang);

    // hardwareConcurrency should be 8
    let hw = page.eval("navigator.hardwareConcurrency").await?;
    println!("    navigator.hardwareConcurrency = {} (want 8)", hw);

    // deviceMemory should be 8
    let mem = page.eval("navigator.deviceMemory").await?;
    println!("    navigator.deviceMemory = {} (want 8)", mem);

    // Check if the bot-detection page itself thinks we passed the webdriver test
    // bot.sannysoft.com puts results in a table with id="table"
    let result_html = page
        .eval(
            r#"
            (function() {
                const rows = document.querySelectorAll('table tr');
                const results = [];
                rows.forEach(row => {
                    const cells = row.querySelectorAll('td');
                    if (cells.length >= 2) {
                        const label = cells[0].innerText.trim();
                        const value = cells[1].innerText.trim();
                        if (label && value) {
                            results.push(label + ': ' + value);
                        }
                    }
                });
                return results.join('\n');
            })()
        "#,
        )
        .await?;
    println!("\n    Bot-detection page results:");
    if let Some(text) = result_html.as_str() {
        for line in text.lines().take(20) {
            println!("      {}", line);
        }
    } else {
        println!("      (could not read table — page may have different structure)");
    }

    // ── 4. Screenshot ─────────────────────────────────────────────────────────
    println!("\n[4] Taking screenshot of bot-detection page...");
    let png = page.screenshot_full().await?;
    println!("    OK: Screenshot = {} bytes", png.len());
    std::fs::write("smoke_stealth_botcheck.png", &png)?;
    println!("    OK: Saved to smoke_stealth_botcheck.png");

    // ── 5. Cookies ────────────────────────────────────────────────────────────
    println!("[5] Testing cookies...");
    println!("    Navigating to https://httpbin.org/cookies/set?smoke=1&stealth=ok ...");
    let cookie_page = browser
        .new_page("https://httpbin.org/cookies/set?smoke=1&stealth=ok")
        .await?;
    tokio::time::sleep(Duration::from_secs(1)).await;

    let jar = cookie_page.get_cookies().await?;
    println!("    Cookie count: {}", jar.len());
    if jar.is_empty() {
        println!("    WARN: No cookies — httpbin.org may have redirected or blocked.");
    } else {
        for cookie in jar.iter() {
            println!(
                "      name={:?}  value={:?}  domain={:?}  secure={}",
                cookie.name, cookie.value, cookie.domain, cookie.is_secure
            );
        }
        println!("    PASS: Got {} cookie(s)", jar.len());
    }

    // ── 6. DevTools network events ────────────────────────────────────────────
    println!("[6] Testing DevTools network events...");

    // Open a fresh page, subscribe to DevTools, then navigate.
    // After navigation completes we drain pending events via try_next.
    let dt_page = browser.new_blank_page().await?;
    let mut devtools = dt_page.devtools().await?;

    // Navigate — events are buffered in the broadcast channel while we wait.
    dt_page.goto("https://example.com").await?;

    // Give the backend a moment to flush buffered events.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Drain all pending events without blocking.
    let mut network_count = 0usize;
    let mut console_count = 0usize;

    while let Some(event) = devtools.try_next() {
        match event {
            DevToolsEvent::Network(ev) => {
                network_count += 1;
                if network_count <= 5 {
                    println!(
                        "    Network event: method={:?}  url={:?}  status={:?}",
                        ev.method,
                        ev.url.as_deref().unwrap_or("(none)"),
                        ev.status,
                    );
                }
            }
            DevToolsEvent::Console(ev) => {
                console_count += 1;
                if console_count <= 3 {
                    println!("    Console [{}]: {}", ev.level, ev.text);
                }
            }
        }
    }

    // Also try a short blocking wait in case events arrive slightly late.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, devtools.next_event()).await {
            Ok(Some(DevToolsEvent::Network(ev))) => {
                network_count += 1;
                if network_count <= 5 {
                    println!(
                        "    Network event: method={:?}  url={:?}  status={:?}",
                        ev.method,
                        ev.url.as_deref().unwrap_or("(none)"),
                        ev.status,
                    );
                }
            }
            Ok(Some(DevToolsEvent::Console(ev))) => {
                console_count += 1;
                if console_count <= 3 {
                    println!("    Console [{}]: {}", ev.level, ev.text);
                }
            }
            Ok(None) => {
                println!("    DevTools channel closed");
                break;
            }
            Err(_) => break, // timeout — no more events
        }
    }

    println!(
        "    DevTools: {} network event(s), {} console event(s) collected",
        network_count, console_count
    );
    if network_count > 0 {
        println!("    PASS: DevTools network events are firing");
    } else {
        println!("    WARN: No network events received — backend may not support subscriptions");
    }

    // ── 7. Close ──────────────────────────────────────────────────────────────
    println!("[7] Closing browser...");
    browser.close().await?;
    println!("    OK: Browser closed");

    // ── Summary ───────────────────────────────────────────────────────────────
    println!("\n=== SMOKE TEST COMPLETE ===");
    println!("  Stealth: webdriver={} chrome={} plugins={}", wd_ok, chrome_ok, plugins_ok);
    println!("  Screenshot: smoke_stealth_botcheck.png");
    println!("  Cookies:  {} found", jar.len());
    println!("  DevTools: {} network events", network_count);

    Ok(())
}
