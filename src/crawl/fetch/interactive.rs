//! Action executor — runs [`BrowserAction`] sequences against a live
//! [`StealthPage`](crate::StealthPage).
//!
//! Each action is executed in order. Failures are recorded in
//! [`ActionOutcome::failed_actions`] and execution continues. The function
//! never panics and always returns an [`ActionOutcome`] even when individual
//! steps fail.

use std::time::Duration;

use crate::StealthPage;
use tracing::warn;

use super::FetchError;
use crate::crawl::agent::actions::{ActionOutcome, BrowserAction};

/// Execute a sequence of [`BrowserAction`]s against `page`.
///
/// Actions are run in order. On failure the action index and error message are
/// appended to [`ActionOutcome::failed_actions`] and the next action proceeds.
/// After all actions finish the current page HTML and a viewport screenshot are
/// captured for the caller.
pub async fn execute_actions(
    page: &StealthPage,
    actions: &[BrowserAction],
) -> Result<ActionOutcome, FetchError> {
    let total_actions = actions.len();
    let mut failed_actions: Vec<(usize, String)> = Vec::new();
    let mut last_screenshot: Option<Vec<u8>> = None;

    for (idx, action) in actions.iter().enumerate() {
        match action {
            BrowserAction::Click { selector } => match page.find(selector).await {
                Ok(el) => {
                    if let Err(e) = el.click().await {
                        let msg = format!("Click({selector:?}): {e}");
                        warn!(action = idx, %e, "click failed");
                        failed_actions.push((idx, msg));
                    }
                }
                Err(e) => {
                    let msg = format!("Click({selector:?}) find: {e}");
                    warn!(action = idx, %e, "element not found for Click");
                    failed_actions.push((idx, msg));
                }
            },

            BrowserAction::ClickAt { x, y } => {
                let js = format!("document.elementFromPoint({x}, {y})?.click()");
                if let Err(e) = page.eval(&js).await {
                    let msg = format!("ClickAt({x},{y}): {e}");
                    warn!(action = idx, %e, "ClickAt eval failed");
                    failed_actions.push((idx, msg));
                }
            }

            BrowserAction::Type { selector, text } => match page.find(selector).await {
                Ok(el) => {
                    if let Err(e) = el.type_text(text).await {
                        let msg = format!("Type({selector:?}): {e}");
                        warn!(action = idx, %e, "type_text failed");
                        failed_actions.push((idx, msg));
                    }
                }
                Err(e) => {
                    let msg = format!("Type({selector:?}) find: {e}");
                    warn!(action = idx, %e, "element not found for Type");
                    failed_actions.push((idx, msg));
                }
            },

            BrowserAction::ScrollTo { selector } => {
                let js = format!(
                    "document.querySelector({selector:?})?.scrollIntoView({{behavior:'smooth',block:'center'}})"
                );
                if let Err(e) = page.eval(&js).await {
                    let msg = format!("ScrollTo({selector:?}): {e}");
                    warn!(action = idx, %e, "ScrollTo eval failed");
                    failed_actions.push((idx, msg));
                }
            }

            BrowserAction::ScrollToY { y } => {
                let js = format!("window.scrollTo(0, {y})");
                if let Err(e) = page.eval(&js).await {
                    let msg = format!("ScrollToY({y}): {e}");
                    warn!(action = idx, %e, "ScrollToY eval failed");
                    failed_actions.push((idx, msg));
                }
            }

            BrowserAction::ScrollBottom => {
                if let Err(e) = page.human_scroll().await {
                    let msg = format!("ScrollBottom: {e}");
                    warn!(action = idx, %e, "ScrollBottom failed");
                    failed_actions.push((idx, msg));
                }
            }

            BrowserAction::WaitForElement {
                selector,
                timeout_ms,
            } => {
                let timeout = Duration::from_millis(*timeout_ms as u64);
                if let Err(e) = page.wait().at_most(timeout).for_element(selector).await {
                    let msg = format!("WaitForElement({selector:?}, {timeout_ms}ms): {e}");
                    warn!(action = idx, %e, "WaitForElement timed out");
                    failed_actions.push((idx, msg));
                }
            }

            BrowserAction::WaitMs { ms } => {
                let clamped = (*ms).min(10_000);
                tokio::time::sleep(Duration::from_millis(clamped as u64)).await;
            }

            BrowserAction::ScreenshotAndAnalyze => match page.screenshot().await {
                Ok(bytes) => {
                    last_screenshot = Some(bytes);
                }
                Err(e) => {
                    let msg = format!("ScreenshotAndAnalyze: {e}");
                    warn!(action = idx, %e, "screenshot failed");
                    failed_actions.push((idx, msg));
                }
            },

            // Silently tolerates element-not-found — overlays may already be gone.
            BrowserAction::DismissOverlay { selector } => match page.find(selector).await {
                Ok(el) => {
                    if let Err(e) = el.click().await {
                        warn!(action = idx, %e, selector, "DismissOverlay click failed (ignored)");
                    }
                }
                Err(e) => {
                    warn!(action = idx, %e, selector, "DismissOverlay element not found (ignored)");
                }
            },

            BrowserAction::PressKey { key } => {
                let js = format!(
                    "document.activeElement?.dispatchEvent(\
                     new KeyboardEvent('keydown', {{key:{key:?}, bubbles:true}}))"
                );
                if let Err(e) = page.eval(&js).await {
                    let msg = format!("PressKey({key:?}): {e}");
                    warn!(action = idx, %e, "PressKey eval failed");
                    failed_actions.push((idx, msg));
                }
            }

            BrowserAction::SelectOption { selector, value } => {
                let js = format!(
                    "{{let e=document.querySelector({selector:?});\
                     if(e){{e.value={value:?};\
                     e.dispatchEvent(new Event('change',{{bubbles:true}}))}}}}"
                );
                if let Err(e) = page.eval(&js).await {
                    let msg = format!("SelectOption({selector:?}, {value:?}): {e}");
                    warn!(action = idx, %e, "SelectOption eval failed");
                    failed_actions.push((idx, msg));
                }
            }
        }
    }

    let html = page
        .html()
        .await
        .map_err(|e| FetchError::Fetch(e.to_string()))?;

    let screenshot = match page.screenshot().await {
        Ok(bytes) => Some(bytes),
        Err(e) => {
            warn!(%e, "final screenshot failed; using last intermediate if available");
            last_screenshot
        }
    };

    Ok(ActionOutcome {
        html,
        screenshot,
        failed_actions,
        total_actions,
    })
}
