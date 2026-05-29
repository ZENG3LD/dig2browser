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
//! | `WASM_BINDGEN_TEST_TIMEOUT` | Per-run timeout in seconds (default 20) |
//! | `DIG2_WASM_PER_TEST_TIMEOUT` | Per-test timeout in seconds (opt-in; 0 = disabled) |
//! | `DIG2_WASM_HEADLESS` | Set to `0` or `false` to run browser in headed mode (debug) |
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

    // 2. Create unique temp dir.
    let tmp = std::env::temp_dir().join(format!("dig2wasm-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&tmp)?;

    // 3. Run inner logic; always clean up tmp on exit.
    let result = run_inner(wasm_path, &wasm_bytes, &tmp, filter_args).await;
    let _ = std::fs::remove_dir_all(&tmp);
    result
}

async fn run_inner(
    wasm_path: &Path,
    wasm_bytes: &[u8],
    tmp: &std::path::Path,
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

    // 8. Read per-test timeout env (GAP-3).
    let per_test_timeout_secs: Option<u64> = std::env::var("DIG2_WASM_PER_TEST_TIMEOUT")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&n| n > 0);

    // 9. Read headless toggle (GAP-5).
    let headless = match std::env::var("DIG2_WASM_HEADLESS").ok().as_deref() {
        Some(v) if v.eq_ignore_ascii_case("0") || v.eq_ignore_ascii_case("false") => false,
        _ => true,
    };

    // 10. Write harness files.
    std::fs::write(tmp.join("index.html"), harness::render_html(spec.nocapture))?;
    std::fs::write(
        tmp.join("run.js"),
        harness::render_run_js(
            &stem,
            &included,
            spec.include_ignored,
            filtered_count,
            per_test_timeout_secs,
        ),
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

    // 17. Build capabilities (GAP-5: headless param).
    let caps = driver::headless_caps(kind, &browser.path, headless);

    // 18. Open WebDriver session.
    let client = crate::webdriver::WdClient::new(&drv.url());
    let session = client
        .new_session(caps)
        .await
        .map_err(|e| WasmTestError::WebDriver(e.to_string()))?;

    // 19. Navigate to the harness page.
    session
        .goto(&server.url())
        .await
        .map_err(|e| WasmTestError::WebDriver(e.to_string()))?;

    // 20. Poll for test result.
    let timeout_secs: u64 = std::env::var("WASM_BINDGEN_TEST_TIMEOUT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20);

    let start = std::time::Instant::now();
    let poll_interval = std::time::Duration::from_millis(100);
    let timeout_dur = std::time::Duration::from_secs(timeout_secs);

    let (output_text, timed_out) = loop {
        tokio::time::sleep(poll_interval).await;

        let val = session
            .execute_sync(
                "return document.getElementById('output').textContent",
                vec![],
            )
            .await
            .map_err(|e| WasmTestError::WebDriver(e.to_string()))?;

        let text = val.as_str().unwrap_or_default().to_string();

        if text.contains("test result:") {
            break (text, false);
        }

        if start.elapsed() >= timeout_dur {
            break (text, true);
        }
    };

    // 21. Best-effort session close.
    let _ = session.close().await;

    // Keep server and driver alive until here.
    drop(server);
    drv.kill();

    // 22. Print output to stdout.
    if !output_text.ends_with('\n') {
        println!("{output_text}");
    } else {
        print!("{output_text}");
    }

    // 23. Determine exit code.
    if timed_out && !output_text.contains("test result:") {
        eprintln!(
            "dig2-wasm-test: timed out after {timeout_secs}s waiting for test result"
        );
        // Exit code 124 = conventional timeout code (GAP-6).
        return Ok(124);
    }

    match harness::parse_output(&output_text) {
        Some(r) => Ok(if r.failed > 0 { 1 } else { 0 }),
        None => Ok(1),
    }
}
