use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::detect::args::BrowserProxy;

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

    /// Select the exact Firefox binary owned by the runtime detector.
    pub fn firefox_binary(mut self, binary: &Path) -> Self {
        let am = self.always_match.get_or_insert_with(|| serde_json::json!({}));
        if let Some(options) = am
            .get_mut("moz:firefoxOptions")
            .and_then(serde_json::Value::as_object_mut)
        {
            options.insert(
                "binary".to_owned(),
                serde_json::Value::String(binary.to_string_lossy().into_owned()),
            );
        }
        self
    }

    /// Bind Firefox to the station-owned persistent profile directory.
    pub fn firefox_profile(mut self, profile: &Path) -> Self {
        let am = self.always_match.get_or_insert_with(|| serde_json::json!({}));
        push_arg(am, "-profile");
        push_arg(am, &profile.to_string_lossy());
        self
    }

    /// Configure the standard top-level W3C proxy capability.
    pub fn browser_proxy(mut self, proxy: BrowserProxy) -> Self {
        let am = self.always_match.get_or_insert_with(|| serde_json::json!({}));
        am["proxy"] = match proxy {
            BrowserProxy::Direct => serde_json::json!({
                "proxyType": "direct"
            }),
            BrowserProxy::Http(endpoint) => {
                let endpoint = endpoint.to_string();
                serde_json::json!({
                    "proxyType": "manual",
                    "httpProxy": endpoint,
                    "sslProxy": endpoint,
                    "noProxy": []
                })
            }
            BrowserProxy::Socks5(endpoint) => serde_json::json!({
                "proxyType": "manual",
                "socksProxy": endpoint.to_string(),
                "socksVersion": 5,
                "noProxy": []
            }),
        };
        if matches!(proxy, BrowserProxy::Http(_) | BrowserProxy::Socks5(_)) {
            set_firefox_pref(am, "network.proxy.allow_hijacking_localhost", true);
        }
        if matches!(proxy, BrowserProxy::Socks5(_)) {
            set_firefox_pref(am, "network.proxy.socks_remote_dns", true);
        }
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

fn set_firefox_pref(
    cap: &mut serde_json::Value,
    name: &str,
    value: impl Into<serde_json::Value>,
) {
    let Some(options) = cap
        .get_mut("moz:firefoxOptions")
        .and_then(serde_json::Value::as_object_mut)
    else {
        return;
    };
    let prefs = options
        .entry("prefs")
        .or_insert_with(|| serde_json::json!({}));
    if let Some(prefs) = prefs.as_object_mut() {
        prefs.insert(name.to_owned(), value.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firefox_proxy_capability_serializes_direct_http_and_socks5() {
        let direct = serde_json::to_value(
            Capabilities::firefox().browser_proxy(BrowserProxy::Direct),
        )
        .unwrap();
        assert_eq!(
            direct["alwaysMatch"]["proxy"],
            serde_json::json!({"proxyType": "direct"})
        );

        let http = serde_json::to_value(Capabilities::firefox().browser_proxy(
            BrowserProxy::Http("127.0.0.1:28080".parse().unwrap()),
        ))
        .unwrap();
        assert_eq!(
            http["alwaysMatch"]["proxy"],
            serde_json::json!({
                "proxyType": "manual",
                "httpProxy": "127.0.0.1:28080",
                "sslProxy": "127.0.0.1:28080",
                "noProxy": []
            })
        );
        assert_eq!(
            http["alwaysMatch"]["moz:firefoxOptions"]["prefs"]
                ["network.proxy.allow_hijacking_localhost"],
            true,
        );

        let socks = serde_json::to_value(Capabilities::firefox().browser_proxy(
            BrowserProxy::Socks5("127.0.0.1:19050".parse().unwrap()),
        ))
        .unwrap();
        assert_eq!(
            socks["alwaysMatch"]["proxy"],
            serde_json::json!({
                "proxyType": "manual",
                "socksProxy": "127.0.0.1:19050",
                "socksVersion": 5,
                "noProxy": []
            })
        );
        assert_eq!(
            socks["alwaysMatch"]["moz:firefoxOptions"]["prefs"]
                ["network.proxy.allow_hijacking_localhost"],
            true,
        );
        assert_eq!(
            socks["alwaysMatch"]["moz:firefoxOptions"]["prefs"]
                ["network.proxy.socks_remote_dns"],
            true,
        );
    }
}
