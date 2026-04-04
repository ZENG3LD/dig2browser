use crate::{error::WdError, session::WdSession};

impl WdSession {
    /// Accept the currently-open alert, confirm, or prompt dialog.
    pub async fn accept_alert(&self) -> Result<(), WdError> {
        self.post("alert/accept", serde_json::json!({})).await?;
        Ok(())
    }

    /// Dismiss the currently-open alert, confirm, or prompt dialog.
    pub async fn dismiss_alert(&self) -> Result<(), WdError> {
        self.post("alert/dismiss", serde_json::json!({})).await?;
        Ok(())
    }

    /// Return the text shown in the currently-open dialog.
    pub async fn get_alert_text(&self) -> Result<String, WdError> {
        let val = self.get("alert/text").await?;
        Ok(val.as_str().unwrap_or_default().to_string())
    }

    /// Type `text` into the currently-open prompt dialog.
    pub async fn send_alert_text(&self, text: &str) -> Result<(), WdError> {
        self.post("alert/text", serde_json::json!({ "text": text }))
            .await?;
        Ok(())
    }
}
