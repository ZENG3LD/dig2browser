/// Smoke test — real Chrome DOM interaction.
///
/// Run with: cargo run --example smoke_dom

use std::time::Duration;

use dig2browser::{LaunchConfig, StealthBrowser, StealthConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ── Step 1: Launch Chrome ────────────────────────────────────────────────
    println!("[1] Launching Chrome (headless)...");
    let launch = LaunchConfig {
        headless: true,
        ..LaunchConfig::default()
    };
    let browser = StealthBrowser::launch_with(launch, StealthConfig::default()).await?;
    println!("    OK — browser launched");

    // ── Step 2: Navigate to example.com ─────────────────────────────────────
    println!("[2] Navigating to https://example.com ...");
    let page = browser.new_page("https://example.com").await?;
    println!("    OK — page loaded");

    // ── Step 3: Find <h1>, verify text ──────────────────────────────────────
    println!("[3] Finding <h1> ...");
    let h1 = page.find("h1").await?;
    let h1_text = h1.text().await?;
    println!("    h1 text: {:?}", h1_text);
    assert_eq!(
        h1_text.trim(),
        "Example Domain",
        "Expected 'Example Domain', got {:?}",
        h1_text
    );

    // ── Step 3b: Bounding box while h1 node is still fresh ──────────────────
    // Note: each call to page.find() triggers DOM.getDocument which invalidates
    // prior nodeIds, so bounding_box must be called before any subsequent find().
    println!("[3b] Getting bounding box of <h1> ...");
    let bbox = h1.bounding_box().await?;
    println!(
        "    bbox: x={:.1} y={:.1} w={:.1} h={:.1}",
        bbox.x, bbox.y, bbox.width, bbox.height
    );
    assert!(bbox.width > 0.0, "Expected positive width");
    assert!(bbox.height > 0.0, "Expected positive height");
    println!("    OK — h1 verified with bounding box");

    // ── Step 4: Find <p>, get text ───────────────────────────────────────────
    println!("[4] Finding first <p> ...");
    let p = page.find("p").await?;
    let p_text = p.text().await?;
    println!("    p text: {:?}", p_text);
    println!("    OK — p found");

    // ── Step 5: Find the "More information" link and click it ────────────────
    // example.com has exactly one <a> tag linking to iana.org.
    println!("[5] Finding link on example.com ...");
    let link = page.find("a").await?;
    let href = link.attribute("href").await?;
    println!("    link href: {:?}", href);
    link.click().await?;
    println!("    OK — link clicked");

    // ── Step 6: Navigate to a page with inputs ───────────────────────────────
    println!("[6] Navigating to https://httpbin.org/forms/post ...");
    page.goto("https://httpbin.org/forms/post").await?;
    println!("    OK — forms page loaded");

    // ── Step 7: Find input, type text ────────────────────────────────────────
    println!("[7] Finding custname input and typing ...");
    let input = page
        .wait()
        .at_most(Duration::from_secs(15))
        .for_element("input[name='custname']")
        .await?;
    input.type_text("John Smoke Test").await?;
    let typed_val = page
        .eval("document.querySelector(\"input[name='custname']\").value")
        .await?;
    println!("    input value after typing: {:?}", typed_val);
    println!("    OK — text typed");

    // ── Step 8: Click submit button via JS eval (avoids comma-selector issue) ─
    println!("[8] Clicking submit button via JS ...");
    let submit_exists = page
        .eval("document.querySelector('button') !== null || document.querySelector('input[type=submit]') !== null")
        .await?;
    println!("    submit exists: {:?}", submit_exists);
    // Click via JavaScript — works regardless of node handle staleness.
    page.eval("(document.querySelector('button') || document.querySelector('input[type=submit]')).click()").await?;
    println!("    OK — submit clicked via JS");

    tokio::time::sleep(Duration::from_millis(800)).await;

    // ── Step 9: WaitBuilder ──────────────────────────────────────────────────
    println!("[9] Using WaitBuilder.for_element(\"body\") ...");
    let body = page
        .wait()
        .at_most(Duration::from_secs(10))
        .every(Duration::from_millis(300))
        .for_element("body")
        .await?;
    let body_text = body.text().await?;
    println!(
        "    body text snippet: {:?}",
        &body_text[..body_text.len().min(100)]
    );
    println!("    OK — WaitBuilder works");

    // ── Step 10: Close browser ───────────────────────────────────────────────
    println!("[10] Closing browser ...");
    browser.close().await?;
    println!("     OK — browser closed");

    println!("\nAll smoke tests passed.");
    Ok(())
}
