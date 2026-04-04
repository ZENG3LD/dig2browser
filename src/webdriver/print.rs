use base64::Engine;
use serde::Serialize;

use crate::webdriver::{error::WdError, session::WdSession};

/// Page dimensions for PDF printing.
#[derive(Debug, Clone, Serialize)]
pub struct PrintPage {
    pub width: f64,
    pub height: f64,
}

/// Page margin settings for PDF printing.
#[derive(Debug, Clone, Serialize)]
pub struct PrintMargin {
    pub top: f64,
    pub bottom: f64,
    pub left: f64,
    pub right: f64,
}

/// Options for `POST /session/{id}/print`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct PrintOptions {
    /// `"portrait"` or `"landscape"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orientation: Option<String>,
    /// Scaling factor (1.0 = 100 %).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scale: Option<f64>,
    /// Whether to print background graphics.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub background: Option<bool>,
    /// Paper size.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page: Option<PrintPage>,
    /// Page margins.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub margin: Option<PrintMargin>,
}

impl WdSession {
    /// Render the current page to a PDF and return the raw bytes.
    ///
    /// Calls `POST /session/{id}/print` and base64-decodes the result.
    pub async fn print_pdf(&self, options: PrintOptions) -> Result<Vec<u8>, WdError> {
        let body = serde_json::to_value(&options)?;
        let val = self.post("print", body).await?;
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
