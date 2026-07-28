//! Stealth configuration types.

use crate::detect::BrowserKind;

/// How aggressively to apply anti-detection overrides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StealthLevel {
    /// Only webdriver + chrome_runtime patches.
    Basic,
    /// Basic + canvas, plugins, languages, permissions, hardware, memory,
    /// max touch points, WebRTC (per `webrtc_policy`), connection.
    StandardNoWebGL,
    /// StandardNoWebGL + WebGL + screen resolution.
    #[default]
    Standard,
    /// Standard + timezone, media devices, performance timing, battery,
    /// outer size, UA data.
    Full,
}

/// Locale/timezone profile for navigator and Intl overrides.
#[derive(Debug, Clone)]
pub struct LocaleProfile {
    pub locale: String,
    pub timezone: Option<String>,
}

impl LocaleProfile {
    pub fn russian() -> Self {
        Self {
            locale: "ru-RU".into(),
            timezone: Some("Europe/Moscow".into()),
        }
    }
    pub fn english() -> Self {
        Self {
            locale: "en-GB".into(),
            timezone: None,
        }
    }
    pub fn english_us() -> Self {
        Self {
            locale: "en-US".into(),
            timezone: None,
        }
    }
}

/// An empty value selects an automatic User-Agent derived from the browser
/// binary actually launched. A non-empty value remains an explicit override.
pub const DEFAULT_USER_AGENT: &str = "";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHintsProfile {
    platform: String,
    platform_version: String,
    architecture: String,
    model: String,
    mobile: bool,
}

impl ClientHintsProfile {
    pub fn windows_desktop() -> Self {
        Self {
            platform: "Windows".to_owned(),
            platform_version: "15.0.0".to_owned(),
            architecture: "x86".to_owned(),
            model: String::new(),
            mobile: false,
        }
    }

    pub fn android_mobile(
        platform_version: impl Into<String>,
        model: impl Into<String>,
    ) -> Self {
        Self {
            platform: "Android".to_owned(),
            platform_version: platform_version.into(),
            architecture: String::new(),
            model: model.into(),
            mobile: true,
        }
    }

    pub fn platform(&self) -> &str {
        &self.platform
    }

    pub fn platform_version(&self) -> &str {
        &self.platform_version
    }

    pub fn architecture(&self) -> &str {
        &self.architecture
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    pub fn mobile(&self) -> bool {
        self.mobile
    }
}

/// Validated CSS-to-physical-pixel scale used by browser emulation.
///
/// The bounded range covers normal desktop scaling and Chromium's supported
/// mobile-layout presets without allowing non-finite protocol values.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DeviceScaleFactor(f64);

impl DeviceScaleFactor {
    pub fn new(value: f64) -> Result<Self, InvalidDeviceScaleFactor> {
        if value.is_finite() && (1.0..=4.0).contains(&value) {
            Ok(Self(value))
        } else {
            Err(InvalidDeviceScaleFactor)
        }
    }

    pub const fn get(self) -> f64 {
        self.0
    }
}

impl Default for DeviceScaleFactor {
    fn default() -> Self {
        Self(1.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidDeviceScaleFactor;

impl std::fmt::Display for InvalidDeviceScaleFactor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "device scale factor must be finite and between 1 and 4")
    }
}

impl std::error::Error for InvalidDeviceScaleFactor {}

#[derive(Debug, Clone)]
pub(crate) struct UserAgentProfile {
    pub user_agent: String,
    pub browser_brand: &'static str,
    pub full_version: Option<String>,
}

impl UserAgentProfile {
    pub fn major_version(&self) -> Option<&str> {
        self.full_version
            .as_deref()
            .and_then(|version| version.split('.').next())
    }

    pub fn brands(&self) -> Option<Vec<(&str, &str)>> {
        let major = self.major_version()?;
        let mut brands = vec![(self.browser_brand, major)];
        if self.browser_brand != "Chromium" {
            brands.push(("Chromium", major));
        }
        brands.push(("Not_A Brand", "24"));
        Some(brands)
    }

    pub fn full_version_list(&self) -> Option<Vec<(&str, &str)>> {
        let full = self.full_version.as_deref()?;
        let mut brands = vec![(self.browser_brand, full)];
        if self.browser_brand != "Chromium" {
            brands.push(("Chromium", full));
        }
        brands.push(("Not_A Brand", "24.0.0.0"));
        Some(brands)
    }
}

/// WebRTC handling policy.
///
/// The default is `Retain`: the no-persona / library-direct default keeps
/// `RTCPeerConnection` present, matching a real browser. This also matches
/// today's *effective* prior behavior, since removal used to be wired only
/// under `StealthLevel::Full` and so never actually ran at the `Standard`
/// level a caller gets by default. Removal is now opt-in via
/// `webrtc_policy = Remove` — set by a persona whose real browser
/// authentically lacks WebRTC (the privacy-cohort persona). IP-leak
/// containment for a retained `RTCPeerConnection` (real ICE candidates) is
/// the isolation engine's job (WFP kernel egress containment), not this
/// policy's — this only decides realism, never leak prevention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WebrtcPolicy {
    /// Delete `RTCPeerConnection`.
    Remove,
    /// Keep `RTCPeerConnection` present and unpatched (default).
    #[default]
    Retain,
}

/// Full stealth configuration passed to script generators and injection strategies.
#[derive(Debug, Clone)]
pub struct StealthConfig {
    /// Transparent mode: apply NO identity overrides at all (no UA, no
    /// timezone, no device metrics). For dev tooling that ATTACHES to a
    /// developer's own headed browser to observe/drive it (`dev-attach`) —
    /// repainting the identity of a browser we did not launch pins its
    /// viewport to the persona size (live incident 2026-07-29: every
    /// `dev-attach` call silently forced 1920×1080 metrics onto the dev
    /// stand tab, so real window resizes were ignored).
    pub transparent: bool,
    pub level: StealthLevel,
    pub locale: LocaleProfile,
    pub viewport: (u32, u32),
    pub device_scale_factor: DeviceScaleFactor,
    pub hardware_concurrency: u32,
    pub device_memory_gb: u32,
    pub max_touch_points: u8,
    /// `WEBGL_debug_renderer_info` `UNMASKED_VENDOR_WEBGL` override.
    pub webgl_vendor: String,
    /// `WEBGL_debug_renderer_info` `UNMASKED_RENDERER_WEBGL` override.
    pub webgl_renderer: String,
    pub webrtc_policy: WebrtcPolicy,
    /// User-Agent string to report via both HTTP headers and JS `navigator.userAgent`.
    /// CDP backend uses this with `Emulation.setUserAgentOverride`.
    pub user_agent: String,
    pub client_hints: ClientHintsProfile,
}

impl Default for StealthConfig {
    fn default() -> Self {
        Self {
            transparent: false,
            level: StealthLevel::Standard,
            locale: LocaleProfile::english_us(),
            viewport: (1920, 1080),
            device_scale_factor: DeviceScaleFactor::default(),
            hardware_concurrency: 8,
            device_memory_gb: 8,
            max_touch_points: 0,
            webgl_vendor: "Google Inc. (NVIDIA)".to_owned(),
            webgl_renderer:
                "ANGLE (NVIDIA, NVIDIA GeForce GTX 1080 Direct3D11 vs_5_0 ps_5_0, D3D11)"
                    .to_owned(),
            webrtc_policy: WebrtcPolicy::default(),
            user_agent: DEFAULT_USER_AGENT.to_owned(),
            client_hints: ClientHintsProfile::windows_desktop(),
        }
    }
}

impl StealthConfig {
    pub fn russian() -> Self {
        Self {
            level: StealthLevel::Full,
            locale: LocaleProfile::russian(),
            ..Default::default()
        }
    }
    pub fn english() -> Self {
        Self::default()
    }

    pub fn set_device_scale_factor(
        &mut self,
        value: f64,
    ) -> Result<(), InvalidDeviceScaleFactor> {
        self.device_scale_factor = DeviceScaleFactor::new(value)?;
        Ok(())
    }

    pub(crate) fn resolve_user_agent(
        &self,
        kind: BrowserKind,
        detected_version: Option<&str>,
    ) -> UserAgentProfile {
        let browser_brand = match kind {
            BrowserKind::Edge => "Microsoft Edge",
            BrowserKind::Chrome => "Google Chrome",
            BrowserKind::Chromium | BrowserKind::Firefox => "Chromium",
        };

        if !self.user_agent.trim().is_empty() {
            let full_version = extract_browser_version(&self.user_agent).map(str::to_owned);
            let explicit_brand = if self.user_agent.contains("Edg/") {
                "Microsoft Edge"
            } else if self.user_agent.contains("Chrome/") {
                "Google Chrome"
            } else {
                browser_brand
            };
            return UserAgentProfile {
                user_agent: self.user_agent.clone(),
                browser_brand: explicit_brand,
                full_version,
            };
        }

        let full_version = detected_version.map(str::to_owned);
        let user_agent = full_version
            .as_deref()
            .map(|version| automatic_user_agent(kind, version, &self.client_hints))
            .unwrap_or_default();
        UserAgentProfile {
            user_agent,
            browser_brand,
            full_version,
        }
    }

    pub(crate) fn resolved_profile_from_user_agent(&self) -> Option<UserAgentProfile> {
        if self.user_agent.trim().is_empty() {
            return None;
        }
        let browser_brand = if self.user_agent.contains("Edg/") {
            "Microsoft Edge"
        } else if self.user_agent.contains("Chrome/") {
            "Google Chrome"
        } else {
            "Chromium"
        };
        Some(UserAgentProfile {
            user_agent: self.user_agent.clone(),
            browser_brand,
            full_version: extract_browser_version(&self.user_agent).map(str::to_owned),
        })
    }
}

fn automatic_user_agent(
    kind: BrowserKind,
    version: &str,
    client_hints: &ClientHintsProfile,
) -> String {
    let base = if client_hints.mobile() {
        format!(
            "Mozilla/5.0 (Linux; Android {}; {}) \
             AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version} Mobile Safari/537.36",
            client_hints.platform_version(),
            client_hints.model(),
        )
    } else {
        format!(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
             AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version} Safari/537.36"
        )
    };
    match kind {
        BrowserKind::Edge => format!("{base} Edg/{version}"),
        _ => base,
    }
}

fn extract_browser_version(user_agent: &str) -> Option<&str> {
    ["Edg/", "Chrome/", "Chromium/"]
        .into_iter()
        .find_map(|marker| {
            let start = user_agent.find(marker)? + marker.len();
            let version = user_agent[start..].split_whitespace().next()?;
            version
                .chars()
                .all(|character| character.is_ascii_digit() || character == '.')
                .then_some(version)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn automatic_chrome_profile_uses_detected_version() {
        let profile = StealthConfig::default()
            .resolve_user_agent(BrowserKind::Chrome, Some("150.0.7871.125"));

        assert!(profile.user_agent.contains("Chrome/150.0.7871.125"));
        assert_eq!(profile.major_version(), Some("150"));
        assert_eq!(profile.browser_brand, "Google Chrome");
    }

    #[test]
    fn automatic_edge_profile_keeps_edge_and_chromium_tokens_coherent() {
        let profile = StealthConfig::default()
            .resolve_user_agent(BrowserKind::Edge, Some("150.0.7871.125"));

        assert!(profile.user_agent.contains("Chrome/150.0.7871.125"));
        assert!(profile.user_agent.contains("Edg/150.0.7871.125"));
        assert_eq!(profile.browser_brand, "Microsoft Edge");
    }

    #[test]
    fn explicit_user_agent_is_preserved() {
        let config = StealthConfig {
            user_agent: "custom-agent/7".into(),
            ..StealthConfig::default()
        };
        let profile = config.resolve_user_agent(BrowserKind::Chrome, Some("150.0.7871.125"));

        assert_eq!(profile.user_agent, "custom-agent/7");
    }

    #[test]
    fn device_scale_factor_is_bounded_and_finite() {
        let mut config = StealthConfig::default();

        config.set_device_scale_factor(3.0).unwrap();
        assert_eq!(config.device_scale_factor.get(), 3.0);

        for invalid in [0.0, 4.1, f64::NAN, f64::INFINITY] {
            assert!(config.set_device_scale_factor(invalid).is_err());
        }
        assert_eq!(config.device_scale_factor.get(), 3.0);
    }
}
