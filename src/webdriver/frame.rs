use crate::webdriver::{error::WdError, session::WdSession, types::WdElement};

/// Identifies the target frame when switching context.
pub enum FrameId {
    /// Switch to the frame at this zero-based index in the current context.
    Index(u32),
    /// Switch to the frame represented by the given element reference.
    Element(WdElement),
    /// Switch to the top-level browsing context.
    Null,
}

impl WdSession {
    /// Switch the active browsing context to the specified frame.
    ///
    /// Use [`FrameId::Null`] to return to the top-level document.
    pub async fn switch_to_frame(&self, id: FrameId) -> Result<(), WdError> {
        let body = match id {
            FrameId::Index(n) => serde_json::json!({ "id": n }),
            FrameId::Element(el) => serde_json::json!({ "id": el }),
            FrameId::Null => serde_json::json!({ "id": null }),
        };
        self.post("frame", body).await?;
        Ok(())
    }

    /// Switch the active browsing context back to the immediate parent frame.
    pub async fn switch_to_parent_frame(&self) -> Result<(), WdError> {
        self.post("frame/parent", serde_json::json!({})).await?;
        Ok(())
    }
}
