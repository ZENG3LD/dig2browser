//! CDP Security domain helpers.

use serde_json::json;

use crate::cdp::error::CdpError;
use crate::cdp::session::CdpSession;

impl CdpSession {
    /// Instruct the browser to ignore all certificate errors.
    pub async fn ignore_certificate_errors(&self) -> Result<(), CdpError> {
        self.call(
            "Security.setIgnoreCertificateErrors",
            Some(json!({ "ignore": true })),
        )
        .await?;
        Ok(())
    }
}
