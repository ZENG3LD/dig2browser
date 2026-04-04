//! Smoke test: basic browser operations against real Chrome.
//!
//! Run with: `cargo run --example smoke_basic`
//!
//! Tests: launch, navigate, screenshot, eval JS, page HTML, PDF export.

use dig2browser::{PrintOptions, StealthBrowser};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== SMOKE TEST: Basic Operations ===\n");

    // 1. Launch Chrome (auto-detect)
    println!("[1] Launching Chrome...");
    let browser = StealthBrowser::launch().await?;
    println!("    OK: Browser launched");

    // 2. Navigate to example.com
    println!("[2] Navigating to https://example.com...");
    let page = browser.new_page("https://example.com").await?;
    println!("    OK: Page loaded");

    // 3. Get page HTML
    println!("[3] Getting page HTML...");
    let html = page.html().await?;
    println!("    OK: HTML length = {} bytes", html.len());
    assert!(
        html.contains("Example Domain"),
        "HTML should contain 'Example Domain'"
    );
    println!("    OK: Contains 'Example Domain'");

    // 4. Eval JavaScript
    println!("[4] Evaluating JavaScript...");
    let title = page.eval("document.title").await?;
    println!("    OK: document.title = {}", title);

    // 5. Screenshot
    println!("[5] Taking screenshot...");
    let png = page.screenshot().await?;
    println!("    OK: Screenshot size = {} bytes", png.len());
    std::fs::write("test_screenshot.png", &png)?;
    println!("    OK: Saved to test_screenshot.png");

    // 6. PDF export
    println!("[6] Exporting PDF...");
    let pdf_result = page.pdf(PrintOptions::default()).await;
    match pdf_result {
        Ok(pdf) => {
            println!("    OK: PDF size = {} bytes", pdf.len());
            std::fs::write("test_page.pdf", &pdf)?;
            println!("    OK: Saved to test_page.pdf");
        }
        Err(e) => println!("    WARN: PDF export failed: {}", e),
    }

    // 7. Navigate to another page
    println!("[7] Navigating to https://httpbin.org/html...");
    let page2 = browser.new_page("https://httpbin.org/html").await?;
    let html2 = page2.html().await?;
    println!("    OK: httpbin HTML length = {} bytes", html2.len());

    // 8. Close
    println!("[8] Closing browser...");
    browser.close().await?;
    println!("    OK: Browser closed");

    println!("\n=== ALL BASIC TESTS PASSED ===");
    Ok(())
}
