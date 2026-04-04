use serde::{Deserialize, Serialize};

/// W3C WebDriver capabilities for session creation.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Capabilities {
    #[serde(rename = "alwaysMatch", skip_serializing_if = "Option::is_none")]
    pub always_match: Option<serde_json::Value>,

    #[serde(rename = "firstMatch", skip_serializing_if = "Option::is_none")]
    pub first_match: Option<Vec<serde_json::Value>>,
}

impl Capabilities {
    /// Chrome capabilities via `goog:chromeOptions`.
    pub fn chrome() -> Self {
        Self {
            always_match: Some(serde_json::json!({
                "browserName": "chrome",
                "goog:chromeOptions": {}
            })),
            first_match: None,
        }
    }

    /// Firefox capabilities via `moz:firefoxOptions`.
    pub fn firefox() -> Self {
        Self {
            always_match: Some(serde_json::json!({
                "browserName": "firefox",
                "moz:firefoxOptions": {}
            })),
            first_match: None,
        }
    }

    /// Edge capabilities via `ms:edgeOptions`.
    pub fn edge() -> Self {
        Self {
            always_match: Some(serde_json::json!({
                "browserName": "MicrosoftEdge",
                "ms:edgeOptions": {}
            })),
            first_match: None,
        }
    }

    /// Add `--headless` argument to the browser.
    pub fn headless(mut self) -> Self {
        let am = self.always_match.get_or_insert_with(|| serde_json::json!({}));
        push_arg(am, "--headless");
        self
    }

    /// Set the initial window size via `--window-size`.
    pub fn window_size(mut self, w: u32, h: u32) -> Self {
        let am = self.always_match.get_or_insert_with(|| serde_json::json!({}));
        push_arg(am, &format!("--window-size={w},{h}"));
        self
    }

    /// Override the user-agent string.
    pub fn user_agent(mut self, ua: &str) -> Self {
        let am = self.always_match.get_or_insert_with(|| serde_json::json!({}));
        push_arg(am, &format!("--user-agent={ua}"));
        self
    }

    /// Enable WebDriver BiDi by requesting `"webSocketUrl": true`.
    pub fn with_bidi(mut self) -> Self {
        let am = self.always_match.get_or_insert_with(|| serde_json::json!({}));
        am["webSocketUrl"] = serde_json::Value::Bool(true);
        self
    }

    /// Apply Firefox anti-detection preferences via `moz:firefoxOptions.prefs`.
    ///
    /// These operate at the browser-engine level (not via JS injection), so they
    /// are more robust than JS overrides:
    ///
    /// - `dom.webdriver.enabled = false` — hides `navigator.webdriver = true`
    /// - `media.peerconnection.enabled = false` — disables WebRTC (prevents IP leaks)
    /// - `media.navigator.enabled = false` — disables `navigator.mediaDevices` enumeration
    /// - `geo.enabled = false` — disables geolocation API
    /// - `network.dns.disablePrefetch = true` — stops DNS prefetch leaks
    /// - `fission.autostart = true` — modern WAFs detect its absence as automation
    ///
    /// Only has effect when the capabilities target Firefox (`moz:firefoxOptions`).
    /// Silently no-ops for Chrome/Edge.
    pub fn with_firefox_stealth_prefs(mut self) -> Self {
        let am = self.always_match.get_or_insert_with(|| serde_json::json!({}));
        if let Some(opts) = am.get_mut("moz:firefoxOptions") {
            if let Some(obj) = opts.as_object_mut() {
                obj.insert(
                    "prefs".to_string(),
                    serde_json::json!({
                        "dom.webdriver.enabled": false,
                        "media.peerconnection.enabled": false,
                        "media.peerconnection.ice.no_host": true,
                        "media.navigator.enabled": false,
                        "geo.enabled": false,
                        "network.dns.disablePrefetch": true,
                        "network.dns.disablePrefetchFromHTTPS": true,
                        "network.prefetch-next": false,
                        "fission.autostart": true,
                        "toolkit.telemetry.enabled": false,
                        "datareporting.healthreport.uploadEnabled": false,
                    }),
                );
            }
        }
        self
    }
}

/// Push a command-line argument into the vendor-specific options args array.
fn push_arg(cap: &mut serde_json::Value, arg: &str) {
    // Try goog:chromeOptions first, then moz:firefoxOptions, then ms:edgeOptions.
    for key in &["goog:chromeOptions", "moz:firefoxOptions", "ms:edgeOptions"] {
        if let Some(opts) = cap.get_mut(key) {
            let args = opts
                .as_object_mut()
                .and_then(|o| {
                    if !o.contains_key("args") {
                        o.insert("args".to_string(), serde_json::json!([]));
                    }
                    o.get_mut("args")
                });
            if let Some(arr) = args.and_then(|v| v.as_array_mut()) {
                arr.push(serde_json::Value::String(arg.to_string()));
                return;
            }
        }
    }
}

/// A cookie as returned or sent by the WebDriver protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WdCookie {
    pub name: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure: Option<bool>,
    #[serde(rename = "httpOnly", skip_serializing_if = "Option::is_none")]
    pub http_only: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiry: Option<u64>,
}

/// A reference to a DOM element, identified by the W3C element reference UUID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WdElement {
    /// The opaque element reference string returned by the driver.
    #[serde(
        rename = "element-6066-11e4-a52e-4f735466cecf",
        alias = "ELEMENT"
    )]
    pub element_id: String,
}
