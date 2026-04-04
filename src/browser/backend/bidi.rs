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

use crate::bidi::BiDiClient;
use crate::cookies::Cookie;
use crate::detect::{LaunchConfig, BrowserPreference, detect_browser};
use crate::stealth::{StealthConfig, get_scripts};
use crate::webdriver::{Capabilities, WdClient, WdSession, WdElement};

use crate::browser::devtools::DevToolsEvent;
use crate::browser::error::BrowserError;
use super::{BrowserBackend, BoundingBox, ElementHandle, ElementInner, PageBackend, PrintOptions};

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
        let _binary = detect_browser(BrowserPreference::Firefox)?;
        debug!("Launching Firefox: {}", _binary.path.display());

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
                let wd_cookie = crate::webdriver::WdCookie {
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

    // ── Element interaction ────────────────────────────────────────────────

    fn find_element<'a>(
        &'a self,
        selector: &'a str,
    ) -> BoxFuture<'a, Result<ElementHandle, BrowserError>> {
        Box::pin(async move {
            self.wd_session
                .switch_to_window(&self.window_handle)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            let el = self
                .wd_session
                .find_element("css selector", selector)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            Ok(ElementHandle {
                inner: ElementInner::WebDriver {
                    element_id: el.element_id,
                },
            })
        })
    }

    fn find_elements<'a>(
        &'a self,
        selector: &'a str,
    ) -> BoxFuture<'a, Result<Vec<ElementHandle>, BrowserError>> {
        Box::pin(async move {
            self.wd_session
                .switch_to_window(&self.window_handle)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            let els = self
                .wd_session
                .find_elements("css selector", selector)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            Ok(els
                .into_iter()
                .map(|el| ElementHandle {
                    inner: ElementInner::WebDriver {
                        element_id: el.element_id,
                    },
                })
                .collect())
        })
    }

    fn click_element<'a>(
        &'a self,
        element: &'a ElementHandle,
    ) -> BoxFuture<'a, Result<(), BrowserError>> {
        Box::pin(async move {
            let wd_el = wd_element(element)?;
            self.wd_session
                .switch_to_window(&self.window_handle)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            self.wd_session
                .click(&wd_el)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))
        })
    }

    fn type_into_element<'a>(
        &'a self,
        element: &'a ElementHandle,
        text: &'a str,
    ) -> BoxFuture<'a, Result<(), BrowserError>> {
        Box::pin(async move {
            let wd_el = wd_element(element)?;
            self.wd_session
                .switch_to_window(&self.window_handle)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            self.wd_session
                .send_keys(&wd_el, text)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))
        })
    }

    fn element_text<'a>(
        &'a self,
        element: &'a ElementHandle,
    ) -> BoxFuture<'a, Result<String, BrowserError>> {
        Box::pin(async move {
            let wd_el = wd_element(element)?;
            self.wd_session
                .switch_to_window(&self.window_handle)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            self.wd_session
                .element_text(&wd_el)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))
        })
    }

    fn element_attribute<'a>(
        &'a self,
        element: &'a ElementHandle,
        name: &'a str,
    ) -> BoxFuture<'a, Result<Option<String>, BrowserError>> {
        Box::pin(async move {
            let wd_el = wd_element(element)?;
            self.wd_session
                .switch_to_window(&self.window_handle)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            self.wd_session
                .element_attribute(&wd_el, name)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))
        })
    }

    fn element_html<'a>(
        &'a self,
        element: &'a ElementHandle,
    ) -> BoxFuture<'a, Result<String, BrowserError>> {
        Box::pin(async move {
            let wd_el = wd_element(element)?;
            self.wd_session
                .switch_to_window(&self.window_handle)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            // Use execute_sync to get outerHTML via the element reference.
            let el_json = serde_json::json!({
                "element-6066-11e4-a52e-4f735466cecf": wd_el.element_id
            });
            let result = self
                .wd_session
                .execute_sync("return arguments[0].outerHTML", vec![el_json])
                .await
                .map_err(|e| BrowserError::JsEval(e.to_string()))?;

            Ok(result.as_str().unwrap_or("").to_owned())
        })
    }

    fn element_bounding_box<'a>(
        &'a self,
        element: &'a ElementHandle,
    ) -> BoxFuture<'a, Result<BoundingBox, BrowserError>> {
        Box::pin(async move {
            let wd_el = wd_element(element)?;
            self.wd_session
                .switch_to_window(&self.window_handle)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            let rect = self
                .wd_session
                .element_rect(&wd_el)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            Ok(BoundingBox {
                x: rect.x,
                y: rect.y,
                width: rect.width,
                height: rect.height,
            })
        })
    }

    // ── PDF ───────────────────────────────────────────────────────────────

    fn print_pdf<'a>(
        &'a self,
        options: &'a PrintOptions,
    ) -> BoxFuture<'a, Result<Vec<u8>, BrowserError>> {
        Box::pin(async move {
            self.wd_session
                .switch_to_window(&self.window_handle)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            let wd_opts = crate::webdriver::PrintOptions {
                orientation: if options.landscape {
                    Some("landscape".to_owned())
                } else {
                    Some("portrait".to_owned())
                },
                scale: options.scale,
                background: if options.print_background { Some(true) } else { None },
                page: options.paper_width.zip(options.paper_height).map(|(w, h)| {
                    crate::webdriver::PrintPage { width: w, height: h }
                }),
                margin: None,
            };

            let result = self
                .wd_session
                .print_pdf(wd_opts)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            Ok(result)
        })
    }

    // ── Enhanced screenshots ───────────────────────────────────────────────

    fn screenshot_full_page<'a>(&'a self) -> BoxFuture<'a, Result<Vec<u8>, BrowserError>> {
        Box::pin(async move {
            self.wd_session
                .switch_to_window(&self.window_handle)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            // Scroll to max to trigger lazy loading, then take screenshot.
            // WebDriver screenshot already returns full-page in Firefox.
            let _ = self
                .wd_session
                .execute_sync(
                    "window.scrollTo(0, document.body.scrollHeight)",
                    vec![],
                )
                .await;

            // Brief yield so the browser processes the scroll.
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;

            self.wd_session
                .screenshot()
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))
        })
    }

    fn screenshot_element<'a>(
        &'a self,
        element: &'a ElementHandle,
    ) -> BoxFuture<'a, Result<Vec<u8>, BrowserError>> {
        Box::pin(async move {
            let wd_el = wd_element(element)?;
            self.wd_session
                .switch_to_window(&self.window_handle)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            let bytes = self
                .wd_session
                .element_screenshot(&wd_el)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            Ok(bytes)
        })
    }

    // ── DevTools events ───────────────────────────────────────────────────

    fn subscribe_events<'a>(
        &'a self,
    ) -> BoxFuture<'a, Result<tokio::sync::broadcast::Receiver<DevToolsEvent>, BrowserError>> {
        Box::pin(async move {
            // Subscribe to BiDi events and bridge to DevToolsEvent.
            let (tx, rx) = tokio::sync::broadcast::channel::<DevToolsEvent>(256);
            let mut bidi_rx = self._bidi.subscribe();

            tokio::spawn(async move {
                loop {
                    match bidi_rx.recv().await {
                        Ok(event) => {
                            let dt_event = bridge_bidi_event(event);
                            if let Some(e) = dt_event {
                                if tx.send(e).is_err() {
                                    break;
                                }
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    }
                }
            });

            Ok(rx)
        })
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Extract a `WdElement` from an `ElementHandle`, returning an error if it's
/// a CDP handle.
fn wd_element(element: &ElementHandle) -> Result<WdElement, BrowserError> {
    match &element.inner {
        ElementInner::WebDriver { element_id } => Ok(WdElement {
            element_id: element_id.clone(),
        }),
        ElementInner::Cdp { .. } => Err(BrowserError::Other(
            "ElementHandle is a CDP handle, not a WebDriver handle".into(),
        )),
    }
}

/// Map a raw BiDi event into a `DevToolsEvent` if it's relevant.
fn bridge_bidi_event(event: crate::bidi::BiDiEvent) -> Option<DevToolsEvent> {
    use crate::browser::devtools::{ConsoleEvent, NetworkEvent};

    match event.method.as_str() {
        m if m.starts_with("network.") => {
            let params = event.params.clone();
            let url = params["request"]["url"].as_str().map(|s| s.to_owned());
            let status = params["response"]["status"].as_u64().map(|s| s as u16);
            Some(DevToolsEvent::Network(NetworkEvent {
                method: event.method,
                url,
                status,
                params,
            }))
        }
        "log.entryAdded" => {
            let params = event.params.clone();
            let level = params["level"].as_str().unwrap_or("log").to_owned();
            let text = params["text"].as_str().unwrap_or("").to_owned();
            Some(DevToolsEvent::Console(ConsoleEvent { level, text }))
        }
        _ => None,
    }
}

