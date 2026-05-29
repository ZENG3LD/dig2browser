//! Native `cargo test --target wasm32-unknown-unknown` runner.
//!
//! Runs a compiled wasm-bindgen test binary inside a real browser via
//! WebDriver, collecting pass/fail counts and returning them as an exit code.
//!
//! ## Exit codes
//!
//! | Code | Meaning |
//! |------|---------|
//! | 0 | All tests passed |
//! | 1 | Test failures, parse error, driver / browser error |
//! | 124 | Global timeout elapsed without a `test result:` line |
//!
//! ## Supported `filter_args`
//!
//! Positional arguments (not starting with `--`) are test-name filters (substring
//! match by default).  Known flags:
//!
//! | Flag | Effect |
//! |------|--------|
//! | `--exact` | Exact name match instead of substring |
//! | `--nocapture` | Route `console.log` output to `#output` (visible in runner stdout) |
//! | `--include-ignored` | Include `#[ignore]`d tests |
//! | `--ignored` | Same as `--include-ignored` |
//!
//! ## Environment variables
//!
//! | Variable | Effect |
//! |----------|--------|
//! | `DIG2_WASM_BROWSER` | Force `chrome` / `firefox` / `edge` instead of auto-detect |
//! | `WASM_BINDGEN_TEST_TIMEOUT` | Per-run global timeout in seconds (default 20) |
//! | `DIG2_WASM_PER_TEST_TIMEOUT` | Stall watchdog: seconds of no `#output` progress before exit 124 (0 or unset = disabled) |
//! | `DIG2_WASM_HEADLESS` | Set to `0` or `false` to run browser in headed mode (debug) |
//! | `DIG2_WASM_ESTABLISH_TIMEOUT` | Seconds allowed for browser/driver establishment (`new_session` + `goto`). Default 60. Exceeding returns exit code 124. |
//! | `DIG2_WASM_BROWSER_ARGS` | Space-separated extra browser flags appended after built-in flags (e.g. `--js-flags=--max-old-space-size=4096`). Args must not contain spaces. |
//! | `CHROMEDRIVER` | Path to a pre-installed chromedriver binary (skip download) |
//! | `MSEDGEDRIVER` | Path to a pre-installed msedgedriver binary (skip download) |
//! | `GECKODRIVER` | Path to a pre-installed geckodriver binary (skip download) |

pub mod download;
pub mod driver;
pub mod filter;
pub mod harness;
pub mod server;
pub mod shim;

pub use driver::DriverKind;
pub use harness::TestResult;
pub use server::StaticServer;
pub use shim::ShimOutput;

use std::path::Path;
use thiserror::Error;

/// Errors produced by the wasm test runner.
#[derive(Debug, Error)]
pub enum WasmTestError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("schema version mismatch — expected {expected}, found {found}")]
    SchemaMismatch { expected: String, found: String },

    #[error("browser binary not found")]
    BrowserNotFound,

    #[error("driver download failed: {0}")]
    DriverDownload(String),

    #[error("driver process error: {0}")]
    Driver(String),

    #[error("WebDriver error: {0}")]
    WebDriver(String),

    #[error("wasm-bindgen shim generation failed: {0}")]
    Bindgen(String),

    #[error("test run timed out after {0}s")]
    Timeout(u64),

    #[error("tests failed: {passed} passed, {failed} failed")]
    TestsFailed { passed: usize, failed: usize },

    #[error("static server error: {0}")]
    Server(String),
}

/// Run a wasm-bindgen test binary inside a real browser.
///
/// `wasm_path` — path to the `.wasm` file produced by
/// `cargo test --target wasm32-unknown-unknown`.
///
/// `filter_args` — slice of arguments forwarded from cargo (everything after
/// the `--` separator on the `cargo test` command line).  Positional
/// arguments are test-name substring filters; recognised flags are
/// `--exact`, `--nocapture`, `--include-ignored`, `--ignored`.
///
/// ## Exit codes
///
/// | Code | Meaning |
/// |------|---------|
/// | 0 | All tests passed |
/// | 1 | Test failures, parse error, driver / browser error |
/// | 124 | Global timeout elapsed without a `test result:` line |
pub async fn run(wasm_path: &Path, filter_args: &[String]) -> Result<i32, WasmTestError> {
    // 1. Read wasm bytes.
    let wasm_bytes = std::fs::read(wasm_path)?;

    // 2. Create unique temp dir for shim + harness files.
    let tmp = std::env::temp_dir().join(format!("dig2wasm-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&tmp)?;

    // 3. Create a unique browser profile dir to prevent profile-lock collisions
    //    when the runner is invoked back-to-back or in parallel.  Chrome and
    //    Edge hold an exclusive lock on the user-data-dir; sharing the default
    //    profile with a still-exiting prior instance causes the new launch to
    //    fail immediately after "resolving driver…".
    let profile = std::env::temp_dir().join(format!("dig2wasm-profile-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&profile)?;

    // 4. Run inner logic; always clean up both dirs on exit (best-effort).
    let result = run_inner(wasm_path, &wasm_bytes, &tmp, &profile, filter_args).await;
    let _ = std::fs::remove_dir_all(&tmp);
    let _ = std::fs::remove_dir_all(&profile);
    result
}

async fn run_inner(
    wasm_path: &Path,
    wasm_bytes: &[u8],
    tmp: &std::path::Path,
    profile: &std::path::Path,
    filter_args: &[String],
) -> Result<i32, WasmTestError> {
    use crate::detect::{detect_browser, BrowserPreference};

    // 4. Parse filter spec from filter_args (GAP-1).
    let spec = filter::FilterSpec::parse(filter_args);

    // 5. Collect test exports.  A wasm with no `__wbgt_*` exports is not a
    //    wasm-bindgen test binary (e.g. an empty `--lib` unittest target that
    //    cargo still runs).  Report 0 tests and skip the browser entirely — this
    //    also avoids running Bindgen on a module that lacks wasm-bindgen
    //    intrinsics, which fails with "failed to find intrinsics".
    let all_tests = shim::test_exports(wasm_bytes)?;
    if all_tests.is_empty() {
        println!(
            "\nrunning 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 filtered out; finished in 0.00s\n"
        );
        return Ok(0);
    }

    // 6. Apply name filters (GAP-1).
    let (included_refs, filtered_count) = spec.apply(&all_tests);
    let included: Vec<String> = included_refs.into_iter().cloned().collect();

    if included.is_empty() {
        // All tests were filtered out — report this cleanly.
        println!(
            "\nrunning 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; {} filtered out; finished in 0.00s\n",
            all_tests.len()
        );
        return Ok(0);
    }

    // 7. Generate shim.
    let shim = shim::generate_shim(wasm_path, tmp)?;
    let stem = shim.js_filename.trim_end_matches(".js").to_string();

    // 8. Read per-test stall watchdog env.
    //    When > 0, the runner-side poll loop will exit 124 if #output stops
    //    advancing for this many seconds without a "test result:" line
    //    appearing (i.e. a single test is hung).  No JS-level wrapper is
    //    emitted; wrapping exported fns breaks WasmBindgenTestContext accounting.
    let per_test_stall_secs: Option<u64> = std::env::var("DIG2_WASM_PER_TEST_TIMEOUT")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&n| n > 0);

    // 9. Read headless toggle (GAP-5).
    let headless = match std::env::var("DIG2_WASM_HEADLESS").ok().as_deref() {
        Some(v) if v.eq_ignore_ascii_case("0") || v.eq_ignore_ascii_case("false") => false,
        _ => true,
    };

    // 9b. Read establishment timeout (FEATURE 1).
    //     Applies to the new_session + goto phase.  Default 60s.
    let establish_secs: u64 = std::env::var("DIG2_WASM_ESTABLISH_TIMEOUT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);

    // 9c. Read extra browser args (FEATURE 3).
    //     Space-separated; args must not contain spaces themselves.
    let extra_browser_args: Vec<String> = std::env::var("DIG2_WASM_BROWSER_ARGS")
        .ok()
        .map(|s| s.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default();

    // 10. Write harness files.
    std::fs::write(tmp.join("index.html"), harness::render_html(spec.nocapture))?;
    std::fs::write(
        tmp.join("run.js"),
        harness::render_run_js(&stem, &included, spec.include_ignored, filtered_count),
    )?;

    // 11. Start static server (kept alive until end of scope).
    let server = server::serve(tmp.to_path_buf())?;

    // 12. Detect browser.
    let browser = match std::env::var("DIG2_WASM_BROWSER").ok().as_deref() {
        Some(v) if v.eq_ignore_ascii_case("chrome") => {
            detect_browser(BrowserPreference::ChromeOnly)
        }
        Some(v) if v.eq_ignore_ascii_case("firefox") => {
            detect_browser(BrowserPreference::Firefox)
        }
        Some(v) if v.eq_ignore_ascii_case("edge") => {
            detect_browser(BrowserPreference::EdgeOnly)
        }
        _ => detect_browser(BrowserPreference::ChromeOnly)
            .or_else(|_| detect_browser(BrowserPreference::Firefox))
            .or_else(|_| detect_browser(BrowserPreference::EdgeOnly)),
    }
    .map_err(|_| WasmTestError::BrowserNotFound)?;

    eprintln!(
        "dig2-wasm-test: using {:?} at {}",
        browser.kind,
        browser.path.display()
    );

    // 13. Get browser version.
    let version = crate::detect::version::browser_version(&browser);

    // 14. Select driver kind.
    let kind = driver::DriverKind::for_browser(browser.kind);

    // 15. Resolve driver (GAP-4a: env var short-circuit is inside ensure_driver).
    eprintln!("dig2-wasm-test: resolving driver…");
    let driver_path = download::ensure_driver(kind, version.as_deref()).await?;

    // 16. Spawn driver with retry (GAP-4b: retry loop is inside spawn).
    let mut drv = driver::spawn(&driver_path, kind).await?;

    // 17. Build capabilities — pass the unique profile dir so Chrome/Edge don't
    //     collide on the default profile when runs overlap (FIX-1).
    //     Also forward any extra browser args (FEATURE 3).
    let caps = driver::headless_caps(kind, &browser.path, headless, profile, &extra_browser_args);

    // 18. Open WebDriver session + navigate — wrapped in an establishment timeout
    //     (FEATURE 1).  If the browser or driver wedges during new_session or
    //     goto, the overall establishment phase is capped at `establish_secs`.
    //     On timeout: kill the driver first, then return exit code 124.
    //
    // FEATURE 2 — robust teardown: all paths that return after the driver is
    // spawned must kill the driver.  We use a `DriverGuard` that kills on Drop,
    // so early-return paths (establishment timeout, session errors, poll errors)
    // are all covered without explicit kill calls on every branch.
    // Capture the URL before the mutable borrow in the guard.
    let drv_url = drv.url();

    struct DriverGuard<'a>(&'a mut driver::SpawnedDriver);
    impl Drop for DriverGuard<'_> {
        fn drop(&mut self) {
            self.0.kill();
        }
    }
    let _drv_guard = DriverGuard(&mut drv);

    let client = crate::webdriver::WdClient::new(&drv_url);
    let establish_dur = std::time::Duration::from_secs(establish_secs);

    // 18a. new_session with establishment timeout.
    let session = match tokio::time::timeout(establish_dur, client.new_session(caps)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(WasmTestError::WebDriver(e.to_string())),
        Err(_) => {
            eprintln!(
                "dig2-wasm-test: browser/driver establishment timed out after {establish_secs}s"
            );
            // _drv_guard Drop will kill the driver.
            return Ok(124);
        }
    };

    // 18b. goto with establishment timeout.
    match tokio::time::timeout(establish_dur, session.goto(&server.url())).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            // FEATURE 2: close session before driver guard kills the driver.
            let _ = session.close().await;
            return Err(WasmTestError::WebDriver(e.to_string()));
        }
        Err(_) => {
            let _ = session.close().await;
            eprintln!(
                "dig2-wasm-test: browser/driver establishment timed out after {establish_secs}s"
            );
            return Ok(124);
        }
    }

    // 19. Poll for test result.
    //
    //     Two independent timeout mechanisms run concurrently:
    //
    //     a) Global timeout (`WASM_BINDGEN_TEST_TIMEOUT`, default 20s) — the
    //        whole run must complete within this wall-clock budget.
    //
    //     b) Stall watchdog (`DIG2_WASM_PER_TEST_TIMEOUT`, opt-in) — if the
    //        `#output` text stops advancing (no new characters) for this many
    //        seconds AND `test result:` has not appeared, the runner treats the
    //        session as stalled and exits 124.  Because wasm runs single-
    //        threaded there is no way to skip the stuck test; the watchdog
    //        surfaces the hang quickly with a clear diagnostic instead of
    //        letting the global timeout swallow it silently.
    let timeout_secs: u64 = std::env::var("WASM_BINDGEN_TEST_TIMEOUT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20);

    let start = std::time::Instant::now();
    let poll_interval = std::time::Duration::from_millis(100);
    let timeout_dur = std::time::Duration::from_secs(timeout_secs);

    // Stall watchdog state: track the last time #output content changed.
    let stall_dur = per_test_stall_secs.map(std::time::Duration::from_secs);
    let mut last_output_change = std::time::Instant::now();
    let mut last_output_len: usize = 0;

    // exit_reason: None = completed, Some(true) = global timeout, Some(false) = stall
    let (output_text, exit_reason) = loop {
        tokio::time::sleep(poll_interval).await;

        // Null-tolerant: the page may not have parsed the harness DOM yet on the
        // first polls (navigation commits before load completes). Return "" instead
        // of throwing "Cannot read properties of null" — keep polling until #output
        // appears with the test-result line.
        let val = session
            .execute_sync(
                "var o = document.getElementById('output'); return o ? o.textContent : '';",
                vec![],
            )
            .await
            .map_err(|e| WasmTestError::WebDriver(e.to_string()))?;

        let text = val.as_str().unwrap_or_default().to_string();

        // Track progress for stall watchdog.
        if text.len() != last_output_len {
            last_output_len = text.len();
            last_output_change = std::time::Instant::now();
        }

        if text.contains("test result:") {
            break (text, None);
        }

        // Global timeout.
        if start.elapsed() >= timeout_dur {
            break (text, Some(true));
        }

        // Stall watchdog: no progress for stall_dur and still no result.
        if let Some(sd) = stall_dur {
            if last_output_change.elapsed() >= sd {
                break (text, Some(false));
            }
        }
    };

    // 20. FEATURE 2: close session before driver guard kills the driver, so
    //     the browser receives a clean shutdown signal first.
    let _ = session.close().await;

    // Keep server alive until output is printed; driver guard kills driver on
    // drop at end of scope (or already killed on early return above).
    drop(server);

    // 21. Print output to stdout.
    if !output_text.ends_with('\n') {
        println!("{output_text}");
    } else {
        print!("{output_text}");
    }

    // 22. Determine exit code.
    match exit_reason {
        Some(true) => {
            // Global timeout.
            eprintln!(
                "dig2-wasm-test: timed out after {timeout_secs}s waiting for test result"
            );
            // Exit code 124 = conventional timeout code (GAP-6).
            return Ok(124);
        }
        Some(false) => {
            // Stall watchdog fired.
            let stall_n = per_test_stall_secs.unwrap_or(0);
            eprintln!(
                "dig2-wasm-test: stalled — no test progress for {stall_n}s (last output above)"
            );
            return Ok(124);
        }
        None => {}
    }

    match harness::parse_output(&output_text) {
        Some(r) => Ok(if r.failed > 0 { 1 } else { 0 }),
        None => Ok(1),
    }
}
