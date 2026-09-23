//! Anti-bot / CAPTCHA challenge page detector.
//!
//! [`AntiBotDetector`] scans raw HTML for patterns emitted by well-known
//! bot-management systems and returns a structured [`AntiBotResult`].
//!
//! Detection is done with simple substring search — no Aho-Corasick
//! dependency so the crate stays light. For the pattern counts used here
//! (< 100) the linear scan is fast enough and avoids an extra dependency.

/// The result of running anti-bot detection over a page.
#[derive(Debug, Clone)]
pub struct AntiBotResult {
    /// `true` when at least one known anti-bot pattern was found.
    pub detected: bool,
    /// Name of the first (highest-confidence) provider detected, if any.
    pub provider: Option<String>,
    /// Type of challenge detected (e.g. `"js_challenge"`, `"captcha"`).
    pub challenge_type: Option<String>,
}

/// Known anti-bot / captcha providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Provider {
    Cloudflare,
    ReCaptcha,
    HCaptcha,
    Turnstile,
    Akamai,
    DataDome,
    Imperva,
    PerimeterX,
    Kasada,
}

impl Provider {
    fn name(self) -> &'static str {
        match self {
            Self::Cloudflare => "Cloudflare",
            Self::ReCaptcha => "Google reCAPTCHA",
            Self::HCaptcha => "hCaptcha",
            Self::Turnstile => "Cloudflare Turnstile",
            Self::Akamai => "Akamai",
            Self::DataDome => "DataDome",
            Self::Imperva => "Imperva/Incapsula",
            Self::PerimeterX => "PerimeterX",
            Self::Kasada => "Kasada",
        }
    }

    fn challenge_type(self) -> &'static str {
        match self {
            Self::Cloudflare
            | Self::Akamai
            | Self::DataDome
            | Self::Imperva
            | Self::PerimeterX
            | Self::Kasada => "js_challenge",
            Self::ReCaptcha | Self::HCaptcha | Self::Turnstile => "captcha",
        }
    }
}

/// (needle, provider, is_high_confidence)
const PATTERNS: &[(&str, Provider, bool)] = &[
    // Cloudflare
    ("Just a moment", Provider::Cloudflare, true),
    ("cf-browser-verification", Provider::Cloudflare, true),
    ("cf_chl_opt", Provider::Cloudflare, true),
    ("cf_clearance", Provider::Cloudflare, true),
    ("__cf_bm", Provider::Cloudflare, false),
    // reCAPTCHA
    ("g-recaptcha", Provider::ReCaptcha, true),
    ("grecaptcha", Provider::ReCaptcha, true),
    ("recaptcha/api.js", Provider::ReCaptcha, true),
    // hCaptcha
    ("h-captcha", Provider::HCaptcha, true),
    ("hcaptcha.com", Provider::HCaptcha, true),
    // Turnstile
    ("cf-turnstile", Provider::Turnstile, true),
    (
        "challenges.cloudflare.com/turnstile",
        Provider::Turnstile,
        true,
    ),
    // Akamai
    ("akamaized.net", Provider::Akamai, true),
    ("ak_bmsc", Provider::Akamai, true),
    ("_abck", Provider::Akamai, true),
    // DataDome
    ("datadome.co", Provider::DataDome, true),
    ("DataDome", Provider::DataDome, true),
    // Imperva / Incapsula
    ("_Incapsula_Resource", Provider::Imperva, true),
    ("incapsula.com", Provider::Imperva, true),
    ("incap_ses", Provider::Imperva, false),
    // PerimeterX
    ("perimeterx.com", Provider::PerimeterX, true),
    ("_pxhd", Provider::PerimeterX, true),
    ("_px3", Provider::PerimeterX, true),
    // Kasada
    ("kasada.io", Provider::Kasada, true),
    ("kpsdk", Provider::Kasada, true),
];

/// Stateless anti-bot detector. Create once, call [`detect`](Self::detect) many times.
#[derive(Debug, Default)]
pub struct AntiBotDetector;

impl AntiBotDetector {
    pub fn new() -> Self {
        Self
    }

    /// Scan `html` for anti-bot patterns and return a result.
    ///
    /// High-confidence patterns take precedence over low-confidence ones.
    pub fn detect(&self, html: &str) -> AntiBotResult {
        let mut seen = std::collections::HashMap::<Provider, bool>::new();

        for (needle, provider, high_conf) in PATTERNS {
            if html.contains(needle) {
                let entry = seen.entry(*provider).or_insert(false);
                if *high_conf {
                    *entry = true;
                }
            }
        }

        if seen.is_empty() {
            return AntiBotResult {
                detected: false,
                provider: None,
                challenge_type: None,
            };
        }

        let best = seen
            .iter()
            .max_by_key(|(_, &high)| high as u8)
            .map(|(p, _)| *p)
            .expect("seen is non-empty");

        AntiBotResult {
            detected: true,
            provider: Some(best.name().to_owned()),
            challenge_type: Some(best.challenge_type().to_owned()),
        }
    }

    /// Quick check: returns `true` if any known pattern is found.
    pub fn is_protected(&self, html: &str) -> bool {
        PATTERNS.iter().any(|(needle, _, _)| html.contains(needle))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cloudflare_just_a_moment() {
        let html = "<title>Just a moment...</title><div id=\"cf-browser-verification\"></div>";
        let result = AntiBotDetector::new().detect(html);
        assert!(result.detected);
        assert_eq!(result.provider.as_deref(), Some("Cloudflare"));
        assert_eq!(result.challenge_type.as_deref(), Some("js_challenge"));
    }

    #[test]
    fn test_recaptcha() {
        let html = r#"<div class="g-recaptcha" data-sitekey="xxx"></div>"#;
        let result = AntiBotDetector::new().detect(html);
        assert!(result.detected);
        assert_eq!(result.provider.as_deref(), Some("Google reCAPTCHA"));
        assert_eq!(result.challenge_type.as_deref(), Some("captcha"));
    }

    #[test]
    fn test_hcaptcha() {
        let html = r#"<div class="h-captcha" data-sitekey="xxx"></div>"#;
        let result = AntiBotDetector::new().detect(html);
        assert!(result.detected);
        assert_eq!(result.provider.as_deref(), Some("hCaptcha"));
    }

    #[test]
    fn test_datadome() {
        let html = r#"<script src="https://js.datadome.co/tags.js"></script>"#;
        let result = AntiBotDetector::new().detect(html);
        assert!(result.detected);
        assert!(result.provider.as_deref().unwrap().contains("DataDome"));
    }

    #[test]
    fn test_clean_page() {
        let html = "<html><body><h1>Welcome</h1></body></html>";
        let result = AntiBotDetector::new().detect(html);
        assert!(!result.detected);
        assert!(result.provider.is_none());
        assert!(result.challenge_type.is_none());
    }

    #[test]
    fn test_is_protected() {
        let det = AntiBotDetector::new();
        assert!(det.is_protected("some text grecaptcha more text"));
        assert!(!det.is_protected("<html><body>normal page</body></html>"));
    }

    #[test]
    fn test_turnstile() {
        let html = r#"<div class="cf-turnstile" data-sitekey="xxx"></div>"#;
        let result = AntiBotDetector::new().detect(html);
        assert!(result.detected);
        assert_eq!(result.provider.as_deref(), Some("Cloudflare Turnstile"));
        assert_eq!(result.challenge_type.as_deref(), Some("captcha"));
    }
}
