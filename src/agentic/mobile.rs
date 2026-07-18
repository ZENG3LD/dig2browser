use serde_json::{json, Value};

/// Validated parameters for Chromium mobile-layout emulation.
///
/// This changes viewport, DPR, orientation, and touch input only. It does not turn a
/// desktop browser into Android, reproduce a mobile TLS stack, or satisfy device
/// attestation.
#[derive(Debug, Clone, PartialEq)]
pub struct MobileLayout {
    width: u32,
    height: u32,
    device_scale_factor: f64,
    max_touch_points: u8,
}

impl MobileLayout {
    pub fn new(
        width: u32,
        height: u32,
        device_scale_factor: f64,
        max_touch_points: u8,
    ) -> Result<Self, MobileLayoutError> {
        if !(240..=1440).contains(&width) || !(320..=3200).contains(&height) {
            return Err(MobileLayoutError::InvalidViewport);
        }
        if !device_scale_factor.is_finite() || !(1.0..=4.0).contains(&device_scale_factor) {
            return Err(MobileLayoutError::InvalidDeviceScaleFactor);
        }
        if !(1..=10).contains(&max_touch_points) {
            return Err(MobileLayoutError::InvalidTouchPoints);
        }
        Ok(Self {
            width,
            height,
            device_scale_factor,
            max_touch_points,
        })
    }

    pub fn common_phone() -> Self {
        Self::new(393, 852, 3.0, 5).expect("built-in mobile layout is valid")
    }

    pub fn width(&self) -> u32 {
        self.width
    }

    pub fn height(&self) -> u32 {
        self.height
    }

    pub fn device_scale_factor(&self) -> f64 {
        self.device_scale_factor
    }

    pub fn max_touch_points(&self) -> u8 {
        self.max_touch_points
    }

    /// Parameters for `Emulation.setDeviceMetricsOverride`.
    pub fn device_metrics_params(&self) -> Value {
        json!({
            "width": self.width,
            "height": self.height,
            "deviceScaleFactor": self.device_scale_factor,
            "mobile": true,
            "screenWidth": self.width,
            "screenHeight": self.height,
            "screenOrientation": {
                "type": "portraitPrimary",
                "angle": 0
            }
        })
    }

    /// Parameters for `Emulation.setTouchEmulationEnabled`.
    pub fn touch_emulation_params(&self) -> Value {
        json!({
            "enabled": true,
            "maxTouchPoints": self.max_touch_points
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MobileLayoutError {
    InvalidViewport,
    InvalidDeviceScaleFactor,
    InvalidTouchPoints,
}

impl std::fmt::Display for MobileLayoutError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidViewport => write!(formatter, "mobile viewport is outside safe bounds"),
            Self::InvalidDeviceScaleFactor => {
                write!(
                    formatter,
                    "device scale factor must be finite and between 1 and 4"
                )
            }
            Self::InvalidTouchPoints => write!(formatter, "touch point count must be 1 to 10"),
        }
    }
}

impl std::error::Error for MobileLayoutError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_layout_only_cdp_parameters() {
        let layout = MobileLayout::common_phone();
        let metrics = layout.device_metrics_params();
        let touch = layout.touch_emulation_params();

        assert_eq!(metrics["mobile"], true);
        assert_eq!(metrics["width"], 393);
        assert_eq!(touch["maxTouchPoints"], 5);
        assert!(metrics.get("userAgent").is_none());
    }
}
