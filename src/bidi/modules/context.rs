use std::sync::Arc;

use base64::Engine;
use serde::Deserialize;

use crate::bidi::{error::BiDiError, transport::BiDiClient};

/// A node in the browsing context tree returned by `browsingContext.getTree`.
#[derive(Debug, Clone, Deserialize)]
pub struct BrowsingContext {
    pub context: String,
    pub url: String,
    #[serde(default)]
    pub children: Vec<BrowsingContext>,
}

/// Result returned by `browsingContext.navigate`.
#[derive(Debug, Clone, Deserialize)]
pub struct NavigateResult {
    pub navigation: Option<String>,
    pub url: String,
}

impl BiDiClient {
    /// Retrieve the browsing context tree, optionally rooted at `root`.
    pub async fn get_tree(
        self: &Arc<Self>,
        root: Option<&str>,
    ) -> Result<Vec<BrowsingContext>, BiDiError> {
        let mut params = serde_json::json!({});
        if let Some(r) = root {
            params["root"] = r.into();
        }
        let result = self.call("browsingContext.getTree", params).await?;
        let contexts: Vec<BrowsingContext> = serde_json::from_value(
            result
                .get("contexts")
                .cloned()
                .unwrap_or(serde_json::Value::Array(vec![])),
        )?;
        Ok(contexts)
    }

    /// Navigate the given browsing context to `url`.
    pub async fn navigate(
        self: &Arc<Self>,
        context: &str,
        url: &str,
    ) -> Result<NavigateResult, BiDiError> {
        let result = self
            .call(
                "browsingContext.navigate",
                serde_json::json!({ "context": context, "url": url }),
            )
            .await?;
        let nav: NavigateResult = serde_json::from_value(result)?;
        Ok(nav)
    }

    /// Create a new browsing context of the given type (`"tab"` or `"window"`).
    ///
    /// `reference_context` is an optional existing context to use as a hint.
    /// Returns the new context id.
    pub async fn create_context(
        self: &Arc<Self>,
        context_type: &str,
        reference_context: Option<&str>,
    ) -> Result<String, BiDiError> {
        let mut params = serde_json::json!({ "type": context_type });
        if let Some(r) = reference_context {
            params["referenceContext"] = r.into();
        }
        let result = self.call("browsingContext.create", params).await?;
        let id = result
            .get("context")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        Ok(id)
    }

    /// Close and destroy the specified browsing context.
    pub async fn close_context(self: &Arc<Self>, context: &str) -> Result<(), BiDiError> {
        self.call(
            "browsingContext.close",
            serde_json::json!({ "context": context }),
        )
        .await?;
        Ok(())
    }

    /// Capture a screenshot of the specified browsing context and return PNG bytes.
    pub async fn capture_screenshot(
        self: &Arc<Self>,
        context: &str,
    ) -> Result<Vec<u8>, BiDiError> {
        let result = self
            .call(
                "browsingContext.captureScreenshot",
                serde_json::json!({ "context": context }),
            )
            .await?;
        let b64 = result
            .get("data")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| BiDiError::Protocol {
                error: "base64".to_string(),
                message: e.to_string(),
            })?;
        Ok(bytes)
    }

    /// Print the specified browsing context to PDF and return the raw bytes.
    pub async fn print(
        self: &Arc<Self>,
        context: &str,
        options: serde_json::Value,
    ) -> Result<Vec<u8>, BiDiError> {
        let mut params = options;
        params["context"] = context.into();
        let result = self.call("browsingContext.print", params).await?;
        let b64 = result
            .get("data")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| BiDiError::Protocol {
                error: "base64".to_string(),
                message: e.to_string(),
            })?;
        Ok(bytes)
    }
}
