//! CDP Fetch domain helpers (request interception).

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::error::CdpError;
use crate::session::CdpSession;

/// Pattern used to enable request interception.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestPattern {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url_pattern: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_stage: Option<String>,
}

impl CdpSession {
    /// Enable request interception with the provided patterns.
    pub async fn enable_fetch(&self, patterns: Vec<RequestPattern>) -> Result<(), CdpError> {
        let params = json!({ "patterns": patterns });
        self.call("Fetch.enable", Some(params)).await?;
        Ok(())
    }

    /// Disable request interception.
    pub async fn disable_fetch(&self) -> Result<(), CdpError> {
        self.call("Fetch.disable", None).await?;
        Ok(())
    }

    /// Allow an intercepted request to continue unmodified.
    pub async fn continue_request(&self, request_id: &str) -> Result<(), CdpError> {
        self.call(
            "Fetch.continueRequest",
            Some(json!({ "requestId": request_id })),
        )
        .await?;
        Ok(())
    }

    /// Abort an intercepted request with the given network error reason.
    pub async fn fail_request(&self, request_id: &str, reason: &str) -> Result<(), CdpError> {
        self.call(
            "Fetch.failRequest",
            Some(json!({ "requestId": request_id, "errorReason": reason })),
        )
        .await?;
        Ok(())
    }

    /// Fulfill an intercepted request with a mock response.
    pub async fn fulfill_request(
        &self,
        request_id: &str,
        status: u32,
        headers: Vec<(String, String)>,
        body: Option<&[u8]>,
    ) -> Result<(), CdpError> {
        let response_headers: Vec<serde_json::Value> = headers
            .into_iter()
            .map(|(name, value)| json!({ "name": name, "value": value }))
            .collect();

        let mut params = json!({
            "requestId": request_id,
            "responseCode": status,
            "responseHeaders": response_headers,
        });

        if let Some(b) = body {
            let encoded = base64::engine::general_purpose::STANDARD.encode(b);
            params["body"] = serde_json::Value::String(encoded);
        }

        self.call("Fetch.fulfillRequest", Some(params)).await?;
        Ok(())
    }
}
