//! CDP Page domain helpers.

use base64::Engine;
use serde::Serialize;
use serde_json::json;
use tokio::time::{timeout, Duration};

use crate::cdp::error::CdpError;
use crate::cdp::session::CdpSession;
use crate::cdp::types::CdpEvent;

/// Options for `Page.printToPDF`.
#[derive(Debug, Clone, Serialize, Default)]
pub struct PrintToPdfOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub landscape: Option<bool>,
    #[serde(rename = "paperWidth", skip_serializing_if = "Option::is_none")]
    pub paper_width: Option<f64>,
    #[serde(rename = "paperHeight", skip_serializing_if = "Option::is_none")]
    pub paper_height: Option<f64>,
    #[serde(rename = "marginTop", skip_serializing_if = "Option::is_none")]
    pub margin_top: Option<f64>,
    #[serde(rename = "marginBottom", skip_serializing_if = "Option::is_none")]
    pub margin_bottom: Option<f64>,
    #[serde(rename = "marginLeft", skip_serializing_if = "Option::is_none")]
    pub margin_left: Option<f64>,
    #[serde(rename = "marginRight", skip_serializing_if = "Option::is_none")]
    pub margin_right: Option<f64>,
    #[serde(rename = "printBackground", skip_serializing_if = "Option::is_none")]
    pub print_background: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scale: Option<f64>,
}

/// A rectangular viewport clip region for screenshots.
#[derive(Debug, Clone, Serialize)]
pub struct Viewport {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
    pub scale: f64,
}

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

    /// Print the page to PDF and return the raw bytes.
    pub async fn print_to_pdf(&self, options: PrintToPdfOptions) -> Result<Vec<u8>, CdpError> {
        let params = serde_json::to_value(&options)?;
        let result = self.call("Page.printToPDF", Some(params)).await?;
        let encoded = result["data"]
            .as_str()
            .ok_or_else(|| CdpError::Protocol {
                code: -1,
                message: "missing data in Page.printToPDF response".to_owned(),
            })?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|e| CdpError::WebSocket(format!("base64 decode error: {e}")))?;
        Ok(bytes)
    }

    /// Capture a screenshot with full options, including optional clip viewport
    /// and full-page mode.
    pub async fn capture_screenshot_with(
        &self,
        format: &str,
        quality: Option<u32>,
        clip: Option<Viewport>,
        full_page: bool,
    ) -> Result<Vec<u8>, CdpError> {
        let mut params = json!({ "format": format });
        if let Some(q) = quality {
            params["quality"] = serde_json::Value::Number(q.into());
        }
        if let Some(c) = clip {
            params["clip"] = serde_json::to_value(&c)?;
        }
        if full_page {
            params["captureBeyondViewport"] = serde_json::Value::Bool(true);
        }
        let result = self.call("Page.captureScreenshot", Some(params)).await?;
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

    /// Enable the Page domain (required before receiving Page events).
    pub async fn enable_page(&self) -> Result<(), CdpError> {
        self.call("Page.enable", None).await?;
        Ok(())
    }

    /// Return the current frame tree.
    pub async fn get_frame_tree(&self) -> Result<serde_json::Value, CdpError> {
        let result = self.call("Page.getFrameTree", None).await?;
        Ok(result["frameTree"].clone())
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
