use crate::{error::WdError, session::WdSession};

impl WdSession {
    /// Navigate to the given URL.
    pub async fn goto(&self, url: &str) -> Result<(), WdError> {
        self.post("url", serde_json::json!({ "url": url })).await?;
        Ok(())
    }

    /// Return the page source of the current document.
    pub async fn source(&self) -> Result<String, WdError> {
        let val = self.get("source").await?;
        Ok(val.as_str().unwrap_or_default().to_string())
    }

    /// Return the title of the current page.
    pub async fn title(&self) -> Result<String, WdError> {
        let val = self.get("title").await?;
        Ok(val.as_str().unwrap_or_default().to_string())
    }

    /// Return the URL of the current page.
    pub async fn current_url(&self) -> Result<String, WdError> {
        let val = self.get("url").await?;
        Ok(val.as_str().unwrap_or_default().to_string())
    }

    /// Navigate back.
    pub async fn back(&self) -> Result<(), WdError> {
        self.post("back", serde_json::json!({})).await?;
        Ok(())
    }

    /// Navigate forward.
    pub async fn forward(&self) -> Result<(), WdError> {
        self.post("forward", serde_json::json!({})).await?;
        Ok(())
    }

    /// Reload the current page.
    pub async fn refresh(&self) -> Result<(), WdError> {
        self.post("refresh", serde_json::json!({})).await?;
        Ok(())
    }
}
