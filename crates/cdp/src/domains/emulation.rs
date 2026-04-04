//! CDP Emulation domain helpers.

use serde_json::json;

use crate::error::CdpError;
use crate::session::CdpSession;

impl CdpSession {
    /// Override the browser timezone.
    pub async fn set_timezone(&self, timezone_id: &str) -> Result<(), CdpError> {
        self.call(
            "Emulation.setTimezoneOverride",
            Some(json!({ "timezoneId": timezone_id })),
        )
        .await?;
        Ok(())
    }

    /// Override the User-Agent string.
    pub async fn set_user_agent(&self, user_agent: &str) -> Result<(), CdpError> {
        self.call(
            "Emulation.setUserAgentOverride",
            Some(json!({ "userAgent": user_agent })),
        )
        .await?;
        Ok(())
    }

    /// Override the device screen metrics.
    pub async fn set_device_metrics(
        &self,
        width: u32,
        height: u32,
        scale: f64,
    ) -> Result<(), CdpError> {
        self.call(
            "Emulation.setDeviceMetricsOverride",
            Some(json!({
                "width": width,
                "height": height,
                "deviceScaleFactor": scale,
                "mobile": false,
            })),
        )
        .await?;
        Ok(())
    }
}
