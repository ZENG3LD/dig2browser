//! Native `cargo test --target wasm32-unknown-unknown` runner.
//!
//! Runs a compiled wasm-bindgen test binary inside a real browser via
//! WebDriver, collecting pass/fail counts and returning them as an exit code.

pub mod download;
pub mod driver;
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
/// `filter_args` — optional test-name filters forwarded to the runner page.
///
/// Returns the process exit code: 0 = all passed, non-zero = failures or error.
pub async fn run(wasm_path: &Path, filter_args: &[String]) -> Result<i32, WasmTestError> {
    if !filter_args.is_empty() {
        eprintln!("dig2-wasm-test: note: test filters not yet supported, running all tests");
    }

    // 1. Read wasm bytes.
    let wasm_bytes = std::fs::read(wasm_path)?;

    // 2. Create unique temp dir.
    let tmp = std::env::temp_dir().join(format!("dig2wasm-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&tmp)?;

    // 3. Run inner logic; always clean up tmp on exit.
    let result = run_inner(wasm_path, &wasm_bytes, &tmp).await;
    let _ = std::fs::remove_dir_all(&tmp);
    result
}

async fn run_inner(
    wasm_path: &Path,
    wasm_bytes: &[u8],
    tmp: &std::path::Path,
) -> Result<i32, WasmTestError> {
    use crate::detect::{detect_browser, BrowserPreference};

    // 4. Collect test exports FIRST. A wasm with no `__wbgt_*` exports is not a
    //    wasm-bindgen test binary (e.g. an empty `--lib` unittest target that
    //    cargo still runs). Report 0 tests and skip the browser entirely — this
    //    also avoids running Bindgen on a module that lacks wasm-bindgen
    //    intrinsics, which fails with "failed to find intrinsics".
    let tests = shim::test_exports(wasm_bytes)?;
    if tests.is_empty() {
        println!(
            "\nrunning 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 filtered out; finished in 0.00s\n"
        );
        return Ok(0);
    }

    // 5. Generate shim.
    let shim = shim::generate_shim(wasm_path, tmp)?;
    let stem = shim.js_filename.trim_end_matches(".js").to_string();

    // 6. Write harness files.
    std::fs::write(tmp.join("index.html"), harness::render_html())?;
    std::fs::write(
        tmp.join("run.js"),
        harness::render_run_js(&stem, &tests, false, 0),
    )?;

    // 7. Start static server (kept alive until end of scope).
    let server = server::serve(tmp.to_path_buf())?;

    // 8. Detect browser.
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

    // 9. Get browser version.
    let version = crate::detect::version::browser_version(&browser);

    // 10. Select driver kind.
    let kind = driver::DriverKind::for_browser(browser.kind);

    // 11. Resolve driver.
    eprintln!("dig2-wasm-test: resolving driver…");
    let driver_path = download::ensure_driver(kind, version.as_deref()).await?;

    // 12. Spawn driver (kept alive until end of scope).
    let mut driver = driver::spawn(&driver_path, kind).await?;

    // 13. Build capabilities.
    let caps = driver::headless_caps(kind, &browser.path);

    // 14. Open WebDriver session.
    let client = crate::webdriver::WdClient::new(&driver.url());
    let session = client
        .new_session(caps)
        .await
        .map_err(|e| WasmTestError::WebDriver(e.to_string()))?;

    // 15. Navigate to the harness page.
    session
        .goto(&server.url())
        .await
        .map_err(|e| WasmTestError::WebDriver(e.to_string()))?;

    // 16. Poll for test result.
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

    // 17. Best-effort session close.
    let _ = session.close().await;

    // Keep server and driver alive until here.
    drop(server);
    driver.kill();

    // 18. Print output to stdout.
    if !output_text.ends_with('\n') {
        println!("{output_text}");
    } else {
        print!("{output_text}");
    }

    // 19. Determine exit code.
    if timed_out && !output_text.contains("test result:") {
        eprintln!(
            "dig2-wasm-test: timed out after {timeout_secs}s waiting for test result"
        );
        return Ok(1);
    }

    match harness::parse_output(&output_text) {
        Some(r) => Ok(if r.failed > 0 { 1 } else { 0 }),
        None => Ok(1),
    }
}
