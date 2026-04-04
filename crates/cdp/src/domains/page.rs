//! CDP Page domain helpers.

use base64::Engine;
use serde_json::json;
use tokio::time::{timeout, Duration};

use crate::error::CdpError;
use crate::session::CdpSession;
use crate::types::CdpEvent;

impl CdpSession {
    /// Navigate the page to the given URL.
    pub async fn navigate(&self, url: &str) -> Result<(), CdpError> {
        self.call("Page.navigate", Some(json!({ "url": url }))).await?;
        Ok(())
    }

    /// Return the full outer HTML of the document via `Runtime.evaluate`.
    pub async fn get_content(&self) -> Result<String, CdpError> {
        let result = self
            .evaluate("document.documentElement.outerHTML")
            .await?;
        let html = result["value"]
            .as_str()
            .unwrap_or("")
            .to_owned();
        Ok(html)
    }

    /// Inject a script that will run on every new document.
    /// Returns the script identifier.
    pub async fn add_script_on_new_document(&self, source: &str) -> Result<String, CdpError> {
        let result = self
            .call(
                "Page.addScriptToEvaluateOnNewDocument",
                Some(json!({ "source": source })),
            )
            .await?;
        let identifier = result["identifier"]
            .as_str()
            .ok_or_else(|| CdpError::Protocol {
                code: -1,
                message: "missing identifier in Page.addScriptToEvaluateOnNewDocument response"
                    .to_owned(),
            })?
            .to_owned();
        Ok(identifier)
    }

    /// Capture a screenshot and return the raw image bytes.
    ///
    /// `format` should be `"png"` or `"jpeg"`.
    /// `quality` is only used for JPEG (0-100).
    pub async fn capture_screenshot(
        &self,
        format: &str,
        quality: Option<u32>,
    ) -> Result<Vec<u8>, CdpError> {
        let params = match quality {
            Some(q) => json!({ "format": format, "quality": q }),
            None => json!({ "format": format }),
        };
        let result = self
            .call("Page.captureScreenshot", Some(params))
            .await?;
        let encoded = result["data"]
            .as_str()
            .ok_or_else(|| CdpError::Protocol {
                code: -1,
                message: "missing data in Page.captureScreenshot response".to_owned(),
            })?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|e| CdpError::WebSocket(format!("base64 decode error: {e}")))?;
        Ok(bytes)
    }

    /// Wait for the `Page.loadEventFired` event up to `timeout_ms` milliseconds.
    pub async fn wait_for_load(&self, timeout_ms: u64) -> Result<(), CdpError> {
        let mut events = self.client().subscribe();
        let duration = Duration::from_millis(timeout_ms);

        let result = timeout(duration, async move {
            loop {
                match events.recv().await {
                    Ok(CdpEvent { method, .. }) if method == "Page.loadEventFired" => {
                        return Ok(());
                    }
                    Ok(_) => continue,
                    Err(_) => return Err(CdpError::ConnectionClosed),
                }
            }
        })
        .await;

        match result {
            Ok(inner) => inner,
            Err(_elapsed) => Err(CdpError::Timeout),
        }
    }
}
