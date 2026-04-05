use std::sync::Arc;

use crate::bidi::{error::BiDiError, transport::BiDiClient};

impl BiDiClient {
    /// Subscribe to network events, optionally scoped to specific browsing
    /// contexts.
    ///
    /// After calling this, `network.beforeRequestSent`, `network.responseStarted`,
    /// and `network.responseCompleted` events will flow through
    /// [`BiDiClient::subscribe`].
    pub async fn subscribe_network(
        self: &Arc<Self>,
        contexts: Option<Vec<String>>,
    ) -> Result<(), BiDiError> {
        let mut params = serde_json::json!({
            "events": [
                "network.beforeRequestSent",
                "network.responseStarted",
                "network.responseCompleted",
            ],
        });

        if let Some(ctxs) = contexts {
            params["contexts"] = serde_json::json!(ctxs);
        }

        self.call("session.subscribe", params).await?;
        Ok(())
    }

    /// Register a network intercept for the given phases and URL patterns.
    ///
    /// Returns the opaque intercept id.
    ///
    /// Common phase strings: `"beforeRequestSent"`, `"responseStarted"`,
    /// `"authRequired"`.
    pub async fn add_intercept(
        self: &Arc<Self>,
        phases: Vec<&str>,
        url_patterns: Vec<serde_json::Value>,
    ) -> Result<String, BiDiError> {
        let result = self
            .call(
                "network.addIntercept",
                serde_json::json!({
                    "phases": phases,
                    "urlPatterns": url_patterns,
                }),
            )
            .await?;

        let intercept_id = result
            .get("intercept")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        Ok(intercept_id)
    }

    /// Remove a previously registered intercept.
    pub async fn remove_intercept(
        self: &Arc<Self>,
        intercept_id: &str,
    ) -> Result<(), BiDiError> {
        self.call(
            "network.removeIntercept",
            serde_json::json!({ "intercept": intercept_id }),
        )
        .await?;
        Ok(())
    }

    /// Allow an intercepted request to continue unmodified.
    pub async fn continue_request(
        self: &Arc<Self>,
        request_id: &str,
    ) -> Result<(), BiDiError> {
        self.call(
            "network.continueRequest",
            serde_json::json!({ "request": request_id }),
        )
        .await?;
        Ok(())
    }

    /// Respond to an intercepted request with a custom response.
    ///
    /// `headers` is a list of `(name, value)` pairs. `body` is an optional
    /// base64-encoded or plain string body.
    pub async fn provide_response(
        self: &Arc<Self>,
        request_id: &str,
        status: u32,
        headers: Vec<(String, String)>,
        body: Option<&str>,
    ) -> Result<(), BiDiError> {
        let header_list: Vec<serde_json::Value> = headers
            .into_iter()
            .map(|(name, value)| serde_json::json!({ "name": name, "value": { "type": "string", "value": value } }))
            .collect();

        let mut params = serde_json::json!({
            "request": request_id,
            "statusCode": status,
            "headers": header_list,
        });

        if let Some(b) = body {
            params["body"] = serde_json::json!({ "type": "string", "value": b });
        }

        self.call("network.provideResponse", params).await?;
        Ok(())
    }

    /// Fail an intercepted request, causing it to produce a network error.
    pub async fn fail_request(self: &Arc<Self>, request_id: &str) -> Result<(), BiDiError> {
        self.call(
            "network.failRequest",
            serde_json::json!({ "request": request_id }),
        )
        .await?;
        Ok(())
    }
}
