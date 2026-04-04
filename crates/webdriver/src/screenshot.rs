use base64::Engine;

use crate::{error::WdError, session::WdSession};

impl WdSession {
    /// Take a full-page screenshot and return the raw PNG bytes.
    pub async fn screenshot(&self) -> Result<Vec<u8>, WdError> {
        let val = self.get("screenshot").await?;
        let b64 = val.as_str().unwrap_or_default();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| WdError::Protocol {
                error: "base64".to_string(),
                message: e.to_string(),
            })?;
        Ok(bytes)
    }
}
