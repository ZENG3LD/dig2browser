//! Stealth configuration types.

/// How aggressively to apply anti-detection overrides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StealthLevel {
    /// Only webdriver + chrome_runtime patches.
    Basic,
    /// Basic + canvas, plugins, languages, permissions, hardware, memory, connection.
    StandardNoWebGL,
    /// StandardNoWebGL + WebGL + screen resolution.
    #[default]
    Standard,
    /// Standard + WebRTC, timezone, media devices, performance timing, battery, outer size, UA data.
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

/// Full stealth configuration passed to script generators and injection strategies.
#[derive(Debug, Clone)]
pub struct StealthConfig {
    pub level: StealthLevel,
    pub locale: LocaleProfile,
    pub viewport: (u32, u32),
    pub hardware_concurrency: u32,
    pub device_memory_gb: u32,
}

impl Default for StealthConfig {
    fn default() -> Self {
        Self {
            level: StealthLevel::Standard,
            locale: LocaleProfile::english_us(),
            viewport: (1920, 1080),
            hardware_concurrency: 8,
            device_memory_gb: 8,
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
}
