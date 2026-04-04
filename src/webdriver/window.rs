use crate::webdriver::{error::WdError, session::WdSession};

impl WdSession {
    /// Open a new browser window/tab and return its handle.
    pub async fn new_window(&self) -> Result<String, WdError> {
        let val = self
            .post("window/new", serde_json::json!({ "type": "tab" }))
            .await?;
        let handle = val
            .get("handle")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        Ok(handle)
    }

    /// Close the current window/tab.
    pub async fn close_window(&self) -> Result<(), WdError> {
        self.delete("window").await?;
        Ok(())
    }

    /// Switch focus to the window identified by `handle`.
    pub async fn switch_to_window(&self, handle: &str) -> Result<(), WdError> {
        self.post("window", serde_json::json!({ "handle": handle }))
            .await?;
        Ok(())
    }

    /// Return all current window handles.
    pub async fn window_handles(&self) -> Result<Vec<String>, WdError> {
        let val = self.get("window/handles").await?;
        let handles: Vec<String> = serde_json::from_value(val)?;
        Ok(handles)
    }

    /// Set the position and size of the current window.
    pub async fn set_window_rect(&self, x: i32, y: i32, w: u32, h: u32) -> Result<(), WdError> {
        self.post(
            "window/rect",
            serde_json::json!({ "x": x, "y": y, "width": w, "height": h }),
        )
        .await?;
        Ok(())
    }
}
