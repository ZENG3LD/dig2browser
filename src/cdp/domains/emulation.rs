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

    /// Override the User-Agent string together with full UA Client Hints metadata.
    ///
    /// Passing `userAgentMetadata` causes Chrome to also rewrite the
    /// `Sec-CH-UA`, `Sec-CH-UA-Platform`, `Sec-CH-UA-Mobile`, and related
    /// HTTP request headers — something that JS-only patching cannot achieve.
    ///
    /// `brands` should be `[("Google Chrome", "131"), ("Chromium", "131"), ("Not_A Brand", "24")]`.
    pub async fn set_user_agent_with_metadata(
        &self,
        user_agent: &str,
        platform: &str,
        platform_version: &str,
        architecture: &str,
        model: &str,
        mobile: bool,
        brands: &[(&str, &str)],
        full_version_list: &[(&str, &str)],
    ) -> Result<(), CdpError> {
        let brands_json: Vec<serde_json::Value> = brands
            .iter()
            .map(|(brand, version)| json!({ "brand": brand, "version": version }))
            .collect();
        let full_version_list_json: Vec<serde_json::Value> = full_version_list
            .iter()
            .map(|(brand, version)| json!({ "brand": brand, "version": version }))
            .collect();
        self.call(
            "Emulation.setUserAgentOverride",
            Some(json!({
                "userAgent": user_agent,
                "userAgentMetadata": {
                    "brands": brands_json,
                    "fullVersionList": full_version_list_json,
                    "platform": platform,
                    "platformVersion": platform_version,
                    "architecture": architecture,
                    "model": model,
                    "mobile": mobile,
                }
            })),
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
