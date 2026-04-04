use std::sync::Arc;

use crate::{
    error::WdError,
    session::WdSession,
    types::Capabilities,
};

/// Low-level HTTP client that speaks to a WebDriver server.
#[derive(Debug, Clone)]
pub struct WdClient {
    pub(crate) http: reqwest::Client,
    pub(crate) base_url: String,
}

impl WdClient {
    /// Create a new client targeting `base_url` (e.g. `"http://localhost:4444"`).
    pub fn new(base_url: &str) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    /// POST `/session` — create a new WebDriver session.
    pub async fn new_session(
        self,
        caps: Capabilities,
    ) -> Result<WdSession, WdError> {
        let body = serde_json::json!({ "capabilities": caps });
        let url = format!("{}/session", self.base_url);

        tracing::debug!("POST {url}");

        let resp: serde_json::Value = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await?
            .json()
            .await?;

        let value = extract_value(&resp)?;

        let session_id = value
            .get("sessionId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| WdError::SessionNotCreated("missing sessionId".to_string()))?
            .to_string();

        let capabilities = value
            .get("capabilities")
            .cloned()
            .unwrap_or(serde_json::Value::Null);

        tracing::debug!("session created: {session_id}");

        Ok(WdSession {
            client: Arc::new(self),
            session_id,
            capabilities,
        })
    }
}

/// Extract the `value` field from a W3C WebDriver response, returning a
/// `WdError::Protocol` if the value contains an `error` key.
pub(crate) fn extract_value(resp: &serde_json::Value) -> Result<&serde_json::Value, WdError> {
    let value = resp.get("value").unwrap_or(resp);

    if let Some(error) = value.get("error").and_then(|v| v.as_str()) {
        let message = value
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        return Err(WdError::Protocol {
            error: error.to_string(),
            message,
        });
    }

    Ok(value)
}
