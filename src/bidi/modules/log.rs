use std::sync::Arc;

use crate::bidi::{error::BiDiError, transport::BiDiClient};

impl BiDiClient {
    /// Subscribe to `log.entryAdded` events, optionally scoped to specific
    /// browsing contexts.
    ///
    /// After calling this, listen for events via [`BiDiClient::subscribe`].
    pub async fn subscribe_log(
        self: &Arc<Self>,
        contexts: Option<Vec<String>>,
    ) -> Result<(), BiDiError> {
        let mut params = serde_json::json!({
            "events": ["log.entryAdded"],
        });

        if let Some(ctxs) = contexts {
            params["contexts"] = serde_json::json!(ctxs);
        }

        self.call("session.subscribe", params).await?;
        Ok(())
    }
}
