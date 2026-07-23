//! CDP Browser domain helpers.

use serde_json::json;

use crate::cdp::error::CdpError;
use crate::cdp::session::CdpSession;

impl CdpSession {
    /// Configure how downloads triggered by this page's browser context are
    /// handled (`Browser.setDownloadBehavior`). `behavior: "allowAndName"`
    /// saves each download under `download_path`, named by its GUID (no
    /// filename collisions); `events_enabled` makes the browser emit
    /// `Browser.downloadWillBegin`/`Browser.downloadProgress` on this
    /// session.
    pub async fn set_download_behavior(
        &self,
        behavior: &str,
        download_path: &str,
        events_enabled: bool,
    ) -> Result<(), CdpError> {
        self.call(
            "Browser.setDownloadBehavior",
            Some(json!({
                "behavior": behavior,
                "downloadPath": download_path,
                "eventsEnabled": events_enabled,
            })),
        )
        .await?;
        Ok(())
    }
}
