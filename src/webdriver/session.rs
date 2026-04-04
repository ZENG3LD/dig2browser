use std::sync::Arc;

use crate::webdriver::{client::{extract_value, WdClient}, error::WdError};

/// An active WebDriver session.
pub struct WdSession {
    pub(crate) client: Arc<WdClient>,
    /// The session identifier returned by the driver.
    pub session_id: String,
    /// The negotiated capabilities for this session.
    pub capabilities: serde_json::Value,
}

impl WdSession {
    /// Build the full URL for a session-scoped endpoint path.
    pub(crate) fn url(&self, path: &str) -> String {
        let path = path.trim_start_matches('/');
        if path.is_empty() {
            format!("{}/session/{}", self.client.base_url, self.session_id)
        } else {
            format!("{}/session/{}/{path}", self.client.base_url, self.session_id)
        }
    }

    /// GET a session-scoped endpoint and return the `value` field.
    pub(crate) async fn get(&self, path: &str) -> Result<serde_json::Value, WdError> {
        let url = self.url(path);
        tracing::debug!("GET {url}");
        let resp: serde_json::Value = self.client.http.get(&url).send().await?.json().await?;
        extract_value(&resp).cloned()
    }

    /// POST a session-scoped endpoint with a JSON body and return the `value` field.
    pub(crate) async fn post(
        &self,
        path: &str,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, WdError> {
        let url = self.url(path);
        tracing::debug!("POST {url}");
        let resp: serde_json::Value = self
            .client
            .http
            .post(&url)
            .json(&body)
            .send()
            .await?
            .json()
            .await?;
        extract_value(&resp).cloned()
    }

    /// DELETE a session-scoped endpoint and return the `value` field.
    pub(crate) async fn delete(&self, path: &str) -> Result<serde_json::Value, WdError> {
        let url = self.url(path);
        tracing::debug!("DELETE {url}");
        let resp: serde_json::Value =
            self.client.http.delete(&url).send().await?.json().await?;
        extract_value(&resp).cloned()
    }

    /// Delete the session (calls `DELETE /session/{id}`).
    pub async fn close(self) -> Result<(), WdError> {
        self.delete("").await?;
        tracing::debug!("session {} closed", self.session_id);
        Ok(())
    }
}
