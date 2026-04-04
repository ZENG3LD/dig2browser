//! CDP Log domain helpers.
//!
//! Enabling the Log domain causes the browser to stream `Log.entryAdded`
//! events through the broadcast channel provided by `CdpClient::subscribe`.

use crate::cdp::error::CdpError;
use crate::cdp::session::CdpSession;

impl CdpSession {
    /// Enable the Log domain so that `Log.entryAdded` events are broadcast.
    pub async fn enable_log(&self) -> Result<(), CdpError> {
        self.call("Log.enable", None).await?;
        Ok(())
    }
}
