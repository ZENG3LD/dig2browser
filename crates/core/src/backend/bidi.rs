//! WebDriver BiDi backend for StealthBrowser.
//!
//! Launches Firefox, creates a WebDriver session with BiDi enabled,
//! then connects a BiDiClient to the returned WebSocket URL.

use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc,
};

use futures::future::BoxFuture;
use tracing::debug;

use dig2browser_bidi::BiDiClient;
use dig2browser_cookie::Cookie;
use dig2browser_detect::{LaunchConfig, BrowserPreference, detect_browser};
use dig2browser_stealth::{StealthConfig, get_scripts};
use dig2browser_webdriver::{Capabilities, WdClient, WdSession};

use crate::error::BrowserError;
use super::{BrowserBackend, PageBackend};

// ── Browser backend ────────────────────────────────────────────────────────

/// BiDi (Firefox) browser backend.
pub(crate) struct BiDiBrowserBackend {
    bidi: Arc<BiDiClient>,
    wd_session: Arc<WdSession>,
    launch: LaunchConfig,
    page_count: AtomicU32,
    /// Spawned Firefox process, if we launched it ourselves.
    _child: Option<tokio::process::Child>,
}

impl BiDiBrowserBackend {
    /// Launch Firefox, create a WebDriver session with BiDi, connect the BiDi client.
    pub(crate) async fn launch(
        launch: &LaunchConfig,
        stealth: &StealthConfig,
    ) -> Result<Self, BrowserError> {
        let binary = detect_browser(BrowserPreference::Firefox)?;
        debug!("Launching Firefox: {}", binary.path.display());

        // Spawn Firefox with remote debugging + geckodriver compatibility.
        // Firefox requires geckodriver as the WebDriver intermediary.
        // We connect to the geckodriver URL configured in launch.geckodriver_url.
        //
        // For BiDi we don't spawn Firefox directly here; geckodriver handles
        // Firefox spawning when we create a session. We just talk to geckodriver.

        let client = WdClient::new(&launch.geckodriver_url);

        let mut caps = Capabilities::firefox().with_bidi();
        if launch.headless {
            caps = caps.headless();
        }

        let session = client
            .new_session(caps)
            .await
            .map_err(|e| BrowserError::Connect(e.to_string()))?;

        // Extract the BiDi WebSocket URL from capabilities.
        let ws_url = session
            .capabilities
            .get("webSocketUrl")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                BrowserError::Connect(
                    "WebDriver session did not return webSocketUrl — BiDi not supported".into(),
                )
            })?
            .to_owned();

        debug!("BiDi WebSocket URL: {ws_url}");

        let bidi = BiDiClient::connect(&ws_url)
            .await
            .map_err(|e| BrowserError::Connect(e.to_string()))?;

        // Pre-register stealth scripts as preload scripts so they fire on every
        // navigation in any browsing context.
        let scripts = get_scripts(stealth);
        for script in &scripts {
            // Wrap as IIFE for preload compatibility.
            let wrapped = format!("(function() {{ {} }})();", script);
            bidi.add_preload_script(&wrapped, None)
                .await
                .map_err(|e| BrowserError::StealthInject(e.to_string()))?;
        }

        Ok(Self {
            bidi,
            wd_session: Arc::new(session),
            launch: launch.clone(),
            page_count: AtomicU32::new(0),
            _child: None,
        })
    }
}

impl BrowserBackend for BiDiBrowserBackend {
    fn new_page<'a>(
        &'a self,
        url: &'a str,
    ) -> BoxFuture<'a, Result<Box<dyn PageBackend>, BrowserError>> {
        Box::pin(async move {
            let handle = self
                .wd_session
                .new_window()
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            // Switch WebDriver focus to the new window.
            self.wd_session
                .switch_to_window(&handle)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            // Navigate to the requested URL.
            self.wd_session
                .goto(url)
                .await
                .map_err(|e| BrowserError::Navigate(e.to_string()))?;

            self.page_count.fetch_add(1, Ordering::Relaxed);

            let page = BiDiPageBackend {
                wd_session: Arc::clone(&self.wd_session),
                _bidi: Arc::clone(&self.bidi),
                window_handle: handle,
            };

            Ok(Box::new(page) as Box<dyn PageBackend>)
        })
    }

    fn new_blank_page<'a>(&'a self) -> BoxFuture<'a, Result<Box<dyn PageBackend>, BrowserError>> {
        Box::pin(async move {
            let handle = self
                .wd_session
                .new_window()
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            self.wd_session
                .switch_to_window(&handle)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            self.page_count.fetch_add(1, Ordering::Relaxed);

            let page = BiDiPageBackend {
                wd_session: Arc::clone(&self.wd_session),
                _bidi: Arc::clone(&self.bidi),
                window_handle: handle,
            };

            Ok(Box::new(page) as Box<dyn PageBackend>)
        })
    }

    fn close<'a>(self: Box<Self>) -> BoxFuture<'a, Result<(), BrowserError>> {
        Box::pin(async move {
            // Close the WebDriver session (geckodriver will terminate Firefox).
            // WdSession::close() consumes the session; we have it behind Arc.
            // If there are no other Arc holders, unwrap and close properly.
            match Arc::try_unwrap(self.wd_session) {
                Ok(session) => {
                    let _ = session.close().await;
                }
                Err(_arc) => {
                    // Session still referenced elsewhere — best effort log.
                    tracing::warn!("BiDi WdSession still referenced; cannot close cleanly");
                }
            }
            Ok(())
        })
    }

    fn page_count(&self) -> u32 {
        self.page_count.load(Ordering::Relaxed)
    }

    fn needs_restart(&self) -> bool {
        let limit = self.launch.restart_after_pages;
        limit > 0 && self.page_count() >= limit
    }
}

// ── Page backend ────────────────────────────────────────────────────────────

/// BiDi-backed page handle.
pub(crate) struct BiDiPageBackend {
    wd_session: Arc<WdSession>,
    /// Kept alive so the underlying WebSocket connection stays open.
    _bidi: Arc<BiDiClient>,
    window_handle: String,
}

impl PageBackend for BiDiPageBackend {
    fn goto<'a>(&'a self, url: &'a str) -> BoxFuture<'a, Result<(), BrowserError>> {
        Box::pin(async move {
            // Ensure the WebDriver focus is on our window.
            self.wd_session
                .switch_to_window(&self.window_handle)
                .await
                .map_err(|e| BrowserError::Navigate(e.to_string()))?;

            self.wd_session
                .goto(url)
                .await
                .map_err(|e| BrowserError::Navigate(e.to_string()))
        })
    }

    fn html<'a>(&'a self) -> BoxFuture<'a, Result<String, BrowserError>> {
        Box::pin(async move {
            self.wd_session
                .switch_to_window(&self.window_handle)
                .await
                .map_err(|e| BrowserError::JsEval(e.to_string()))?;

            self.wd_session
                .source()
                .await
                .map_err(|e| BrowserError::JsEval(e.to_string()))
        })
    }

    fn eval<'a>(&'a self, js: &'a str) -> BoxFuture<'a, Result<serde_json::Value, BrowserError>> {
        Box::pin(async move {
            self.wd_session
                .switch_to_window(&self.window_handle)
                .await
                .map_err(|e| BrowserError::JsEval(e.to_string()))?;

            self.wd_session
                .execute_sync(js, vec![])
                .await
                .map_err(|e| BrowserError::JsEval(e.to_string()))
        })
    }

    fn screenshot<'a>(&'a self) -> BoxFuture<'a, Result<Vec<u8>, BrowserError>> {
        Box::pin(async move {
            self.wd_session
                .switch_to_window(&self.window_handle)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            self.wd_session
                .screenshot()
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))
        })
    }

    fn get_cookies<'a>(
        &'a self,
    ) -> BoxFuture<'a, Result<Vec<Cookie>, BrowserError>> {
        Box::pin(async move {
            self.wd_session
                .switch_to_window(&self.window_handle)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            let wd_cookies = self
                .wd_session
                .get_cookies()
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            let cookies = wd_cookies
                .into_iter()
                .map(|c| Cookie {
                    name: c.name,
                    value: c.value,
                    domain: c.domain.unwrap_or_default(),
                    path: c.path.unwrap_or_else(|| "/".into()),
                    is_secure: c.secure.unwrap_or(false),
                    is_httponly: c.http_only.unwrap_or(false),
                    expires_utc: c.expiry.map(|e| e as i64),
                })
                .collect();
            Ok(cookies)
        })
    }

    fn set_cookies<'a>(
        &'a self,
        cookies: &'a [Cookie],
    ) -> BoxFuture<'a, Result<(), BrowserError>> {
        Box::pin(async move {
            self.wd_session
                .switch_to_window(&self.window_handle)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            for cookie in cookies {
                let wd_cookie = dig2browser_webdriver::WdCookie {
                    name: cookie.name.clone(),
                    value: cookie.value.clone(),
                    domain: Some(cookie.domain.clone()),
                    path: Some(cookie.path.clone()),
                    secure: Some(cookie.is_secure),
                    http_only: Some(cookie.is_httponly),
                    expiry: cookie.expires_utc.map(|t| t as u64),
                };
                self.wd_session
                    .add_cookie(wd_cookie)
                    .await
                    .map_err(|e| BrowserError::Other(e.to_string()))?;
            }
            Ok(())
        })
    }
}
