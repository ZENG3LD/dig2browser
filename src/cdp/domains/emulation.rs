//! CDP Emulation domain helpers.

use serde::Serialize;
use serde_json::json;

use crate::cdp::error::CdpError;
use crate::cdp::session::CdpSession;

/// A CSS media feature override (e.g. `prefers-color-scheme`).
#[derive(Debug, Clone, Serialize)]
pub struct MediaFeature {
    pub name: String,
    pub value: String,
}

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

    /// Override the geolocation.
    ///
    /// `accuracy` defaults to `1.0` when `None`.
    pub async fn set_geolocation(
        &self,
        lat: f64,
        lng: f64,
        accuracy: Option<f64>,
    ) -> Result<(), CdpError> {
        self.call(
            "Emulation.setGeolocationOverride",
            Some(json!({
                "latitude": lat,
                "longitude": lng,
                "accuracy": accuracy.unwrap_or(1.0),
            })),
        )
        .await?;
        Ok(())
    }

    /// Clear the geolocation override.
    pub async fn clear_geolocation(&self) -> Result<(), CdpError> {
        self.call("Emulation.clearGeolocationOverride", None).await?;
        Ok(())
    }

    /// Override the browser locale (e.g. `"en-US"`, `"ru-RU"`).
    pub async fn set_locale(&self, locale: &str) -> Result<(), CdpError> {
        self.call(
            "Emulation.setLocaleOverride",
            Some(json!({ "locale": locale })),
        )
        .await?;
        Ok(())
    }

    /// Override CSS media features (e.g. `prefers-color-scheme: dark`).
    pub async fn set_emulated_media(
        &self,
        features: Vec<MediaFeature>,
    ) -> Result<(), CdpError> {
        self.call(
            "Emulation.setEmulatedMedia",
            Some(json!({ "features": features })),
        )
        .await?;
        Ok(())
    }
}
