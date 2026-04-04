use std::sync::Arc;

use crate::bidi::{error::BiDiError, transport::BiDiClient};

impl BiDiClient {
    /// Perform a sequence of input actions in the specified browsing context.
    ///
    /// `actions` is a list of action source objects as defined by the BiDi spec.
    /// Use the same structure as the W3C Actions API (pointer/key/wheel sources).
    pub async fn perform_actions(
        self: &Arc<Self>,
        context: &str,
        actions: Vec<serde_json::Value>,
    ) -> Result<(), BiDiError> {
        self.call(
            "input.performActions",
            serde_json::json!({ "context": context, "actions": actions }),
        )
        .await?;
        Ok(())
    }

    /// Release all currently-held input state in the specified browsing context.
    pub async fn release_actions(
        self: &Arc<Self>,
        context: &str,
    ) -> Result<(), BiDiError> {
        self.call(
            "input.releaseActions",
            serde_json::json!({ "context": context }),
        )
        .await?;
        Ok(())
    }
}
