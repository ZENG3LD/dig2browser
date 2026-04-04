//! CDP (Chrome DevTools Protocol) backend for StealthBrowser.
//!
//! Spawns a Chrome/Edge process, connects via WebSocket, and provides
//! BrowserBackend + PageBackend implementations using dig2browser-cdp.

use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc,
};

use base64::Engine;
use futures::future::BoxFuture;
use tokio::io::{AsyncBufReadExt, BufReader};
use tracing::debug;

use crate::cdp::{CdpClient, CdpSession};
use crate::cookies::Cookie;
use crate::detect::{LaunchConfig, detect_browser};
use crate::stealth::{StealthConfig, get_scripts};

use crate::browser::devtools::DevToolsEvent;
use crate::browser::error::BrowserError;
use super::{BrowserBackend, BoundingBox, ElementHandle, ElementInner, PageBackend, PrintOptions};

// ── Process handle ─────────────────────────────────────────────────────────

/// Internal state for a running CDP browser process.
pub(crate) struct CdpBrowserBackend {
    client: Arc<CdpClient>,
    root: CdpSession,
    launch: LaunchConfig,
    stealth: StealthConfig,
    page_count: AtomicU32,
    /// Child process — kept alive for the lifetime of this backend.
    _child: tokio::process::Child,
    /// Profile dir path, deleted on drop if ephemeral.
    profile_dir: std::path::PathBuf,
    profile_ephemeral: bool,
}

impl Drop for CdpBrowserBackend {
    fn drop(&mut self) {
        if self.profile_ephemeral {
            let _ = std::fs::remove_dir_all(&self.profile_dir);
        }
    }
}

impl CdpBrowserBackend {
    /// Spawn a Chrome/Edge process and connect via CDP WebSocket.
    pub(crate) async fn launch(
        launch: &LaunchConfig,
        stealth: &StealthConfig,
    ) -> Result<Self, BrowserError> {
        let binary = detect_browser(launch.browser_pref)?;
        let port = launch.debug_port.unwrap_or_else(LaunchConfig::find_free_port);
        let (profile_dir, profile_ephemeral) = launch.profile.resolve()?;
        let locale = Some(stealth.locale.locale.as_str());
        let args = launch.build_args(&profile_dir, port, locale);

        debug!(
            "Launching CDP browser: {} with {} args on port {}",
            binary.path.display(),
            args.len(),
            port
        );

        let mut child = tokio::process::Command::new(&binary.path)
            .args(&args)
            .stderr(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stdin(std::process::Stdio::null())
            .spawn()
            .map_err(|e| BrowserError::Launch(e.to_string()))?;

        // Read stderr looking for "DevTools listening on ws://"
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| BrowserError::Launch("could not capture stderr".into()))?;

        let ws_url = Self::find_ws_url(stderr).await?;
        debug!("CDP WebSocket URL: {ws_url}");

        let client = CdpClient::connect(&ws_url)
            .await
            .map_err(|e| BrowserError::Connect(e.to_string()))?;

        let root = client.root_session();

        Ok(Self {
            client,
            root,
            launch: launch.clone(),
            stealth: stealth.clone(),
            page_count: AtomicU32::new(0),
            _child: child,
            profile_dir,
            profile_ephemeral,
        })
    }

    /// Scan stderr lines until we see the DevTools WS URL.
    async fn find_ws_url(
        stderr: impl tokio::io::AsyncRead + Unpin,
    ) -> Result<String, BrowserError> {
        let reader = BufReader::new(stderr);
        let mut lines = reader.lines();

        let timeout = std::time::Duration::from_secs(30);
        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(BrowserError::Connect(
                    "timed out waiting for DevTools WebSocket URL on stderr".into(),
                ));
            }

            let line_future = lines.next_line();
            match tokio::time::timeout(remaining, line_future).await {
                Ok(Ok(Some(line))) => {
                    debug!("browser stderr: {line}");
                    if let Some(pos) = line.find("ws://") {
                        return Ok(line[pos..].trim().to_owned());
                    }
                }
                Ok(Ok(None)) => {
                    return Err(BrowserError::Connect(
                        "browser stderr closed before DevTools URL appeared".into(),
                    ));
                }
                Ok(Err(e)) => {
                    return Err(BrowserError::Io(e));
                }
                Err(_) => {
                    return Err(BrowserError::Connect(
                        "timed out waiting for DevTools WebSocket URL".into(),
                    ));
                }
            }
        }
    }

    /// Create and attach to a new page target, inject stealth scripts, optionally navigate.
    async fn open_page(&self, url: Option<&str>) -> Result<CdpPageBackend, BrowserError> {
        // Always start as about:blank so we attach before any real navigation begins.
        let target_id = self
            .root
            .create_target("about:blank")
            .await
            .map_err(|e| BrowserError::Navigate(e.to_string()))?;

        // Attach to the target to get a session.
        let session_id = self
            .root
            .attach_to_target(&target_id)
            .await
            .map_err(|e| BrowserError::Connect(e.to_string()))?;

        let session = CdpSession::with_session_id(session_id, Arc::clone(&self.client));

        // Enable required domains on this session.
        session
            .call("Page.enable", None)
            .await
            .map_err(|e| BrowserError::Connect(e.to_string()))?;
        session
            .call("Network.enable", None)
            .await
            .map_err(|e| BrowserError::Connect(e.to_string()))?;

        // ── CDP-native stealth overrides ──────────────────────────────────────
        // These run at the protocol level and are more reliable than JS patching:
        // they survive property-descriptor inspection and also affect HTTP headers.

        // User-Agent + Client Hints: sets Sec-CH-UA* HTTP headers automatically.
        session
            .set_user_agent_with_metadata(
                &self.stealth.user_agent,
                "Windows",
                "15.0.0",
                "x86",
                "",   // model — empty for desktops
                false, // mobile
                &[
                    ("Google Chrome", "131"),
                    ("Chromium", "131"),
                    ("Not_A Brand", "24"),
                ],
                &[
                    ("Google Chrome", "131.0.6778.140"),
                    ("Chromium", "131.0.6778.140"),
                    ("Not_A Brand", "24.0.0.0"),
                ],
            )
            .await
            .map_err(|e| BrowserError::StealthInject(e.to_string()))?;

        // Timezone: fixes both Intl.DateTimeFormat AND new Date().toString().
        // The JS override_timezone script only fixes Intl, missing Date.toString().
        if let Some(tz) = &self.stealth.locale.timezone {
            session
                .set_timezone(tz)
                .await
                .map_err(|e| BrowserError::StealthInject(e.to_string()))?;
        }

        // Device metrics: screen dimensions + devicePixelRatio at browser level.
        // Also affects CSS media queries and visual viewport, unlike JS patching.
        let (vp_w, vp_h) = self.stealth.viewport;
        session
            .set_device_metrics(vp_w, vp_h, 1.0)
            .await
            .map_err(|e| BrowserError::StealthInject(e.to_string()))?;

        // ── JS stealth scripts ────────────────────────────────────────────────
        // Injected after native overrides. Some overlap with the CDP calls above
        // but JS scripts cover properties that have no CDP equivalent (plugins,
        // permissions, WebGL, etc.) and serve as safety nets for the ones that do.
        let scripts = get_scripts(&self.stealth);
        for script in &scripts {
            session
                .add_script_on_new_document(script)
                .await
                .map_err(|e| BrowserError::StealthInject(e.to_string()))?;
        }

        // Navigate to the target URL and wait for the page to fully load.
        if let Some(nav_url) = url {
            session
                .navigate(nav_url)
                .await
                .map_err(|e| BrowserError::Navigate(e.to_string()))?;
        }

        self.page_count.fetch_add(1, Ordering::Relaxed);

        Ok(CdpPageBackend {
            session,
            target_id,
        })
    }
}

impl BrowserBackend for CdpBrowserBackend {
    fn new_page<'a>(
        &'a self,
        url: &'a str,
    ) -> BoxFuture<'a, Result<Box<dyn PageBackend>, BrowserError>> {
        Box::pin(async move {
            let page = self.open_page(Some(url)).await?;
            Ok(Box::new(page) as Box<dyn PageBackend>)
        })
    }

    fn new_blank_page<'a>(&'a self) -> BoxFuture<'a, Result<Box<dyn PageBackend>, BrowserError>> {
        Box::pin(async move {
            let page = self.open_page(None).await?;
            Ok(Box::new(page) as Box<dyn PageBackend>)
        })
    }

    fn close<'a>(mut self: Box<Self>) -> BoxFuture<'a, Result<(), BrowserError>> {
        Box::pin(async move {
            // Ask the browser to close gracefully via CDP.
            let _ = self.root.call("Browser.close", None).await;
            // Then kill the process if still running.
            let _ = self._child.kill().await;
            if self.profile_ephemeral {
                let _ = std::fs::remove_dir_all(&self.profile_dir);
                self.profile_ephemeral = false; // prevent double-cleanup in Drop
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

// ── Page backend ───────────────────────────────────────────────────────────

/// CDP-backed page handle.
pub(crate) struct CdpPageBackend {
    session: CdpSession,
    /// Kept so callers can close the target explicitly if needed.
    target_id: String,
}

impl PageBackend for CdpPageBackend {
    fn goto<'a>(&'a self, url: &'a str) -> BoxFuture<'a, Result<(), BrowserError>> {
        Box::pin(async move {
            self.session
                .navigate(url)
                .await
                .map_err(|e| BrowserError::Navigate(e.to_string()))
        })
    }

    fn html<'a>(&'a self) -> BoxFuture<'a, Result<String, BrowserError>> {
        Box::pin(async move {
            self.session
                .get_content()
                .await
                .map_err(|e| BrowserError::JsEval(e.to_string()))
        })
    }

    fn eval<'a>(&'a self, js: &'a str) -> BoxFuture<'a, Result<serde_json::Value, BrowserError>> {
        Box::pin(async move {
            let result = self
                .session
                .evaluate(js)
                .await
                .map_err(|e| BrowserError::JsEval(e.to_string()))?;
            // result is {"type": "...", "value": ...} — return the value field.
            Ok(result
                .get("value")
                .cloned()
                .unwrap_or(serde_json::Value::Null))
        })
    }

    fn screenshot<'a>(&'a self) -> BoxFuture<'a, Result<Vec<u8>, BrowserError>> {
        Box::pin(async move {
            self.session
                .capture_screenshot("png", None)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))
        })
    }

    fn get_cookies<'a>(
        &'a self,
    ) -> BoxFuture<'a, Result<Vec<Cookie>, BrowserError>> {
        Box::pin(async move {
            let cdp_cookies = self
                .session
                .get_cookies()
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            let cookies = cdp_cookies
                .into_iter()
                .map(|c| Cookie {
                    name: c.name,
                    value: c.value,
                    domain: c.domain,
                    path: c.path,
                    is_secure: c.secure,
                    is_httponly: c.http_only,
                    expires_utc: c.expires.map(|f| f as i64),
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
            for cookie in cookies {
                let cdp_cookie = crate::cdp::CdpCookie {
                    name: cookie.name.clone(),
                    value: cookie.value.clone(),
                    domain: cookie.domain.clone(),
                    path: cookie.path.clone(),
                    secure: cookie.is_secure,
                    http_only: cookie.is_httponly,
                    expires: cookie.expires_utc.map(|t| t as f64),
                };
                self.session
                    .set_cookie(cdp_cookie)
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
            self.session
                .enable_dom()
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            let doc = self
                .session
                .get_document()
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            let node_id = self
                .session
                .query_selector(doc.node_id, selector)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?
                .ok_or_else(|| {
                    BrowserError::Other(format!("element not found: {selector}"))
                })?;

            Ok(ElementHandle {
                inner: ElementInner::Cdp { node_id },
            })
        })
    }

    fn find_elements<'a>(
        &'a self,
        selector: &'a str,
    ) -> BoxFuture<'a, Result<Vec<ElementHandle>, BrowserError>> {
        Box::pin(async move {
            self.session
                .enable_dom()
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            let doc = self
                .session
                .get_document()
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            let node_ids = self
                .session
                .query_selector_all(doc.node_id, selector)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            let handles = node_ids
                .into_iter()
                .map(|node_id| ElementHandle {
                    inner: ElementInner::Cdp { node_id },
                })
                .collect();

            Ok(handles)
        })
    }

    fn click_element<'a>(
        &'a self,
        element: &'a ElementHandle,
    ) -> BoxFuture<'a, Result<(), BrowserError>> {
        Box::pin(async move {
            let node_id = cdp_node_id(element)?;

            // Scroll the element into view first.
            self.session
                .scroll_into_view(node_id)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            // Get the bounding box to compute the center.
            let bbox = self
                .session
                .get_box_model(node_id)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            // content quad is [x1,y1, x2,y2, x3,y3, x4,y4].
            let (cx, cy) = quad_center(&bbox.content);

            self.session
                .mouse_click(cx, cy)
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
            let node_id = cdp_node_id(element)?;

            self.session
                .focus(node_id)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            self.session
                .type_text(text)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))
        })
    }

    fn element_text<'a>(
        &'a self,
        element: &'a ElementHandle,
    ) -> BoxFuture<'a, Result<String, BrowserError>> {
        Box::pin(async move {
            let node_id = cdp_node_id(element)?;

            // Resolve to a JS remote object so we can call functions on it.
            let object_id = self
                .session
                .resolve_node(node_id)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            let result = self
                .session
                .call(
                    "Runtime.callFunctionOn",
                    Some(serde_json::json!({
                        "objectId": object_id,
                        "functionDeclaration": "function() { return this.textContent; }",
                        "returnByValue": true,
                    })),
                )
                .await
                .map_err(|e| BrowserError::JsEval(e.to_string()))?;

            Ok(result["result"]["value"]
                .as_str()
                .unwrap_or("")
                .to_owned())
        })
    }

    fn element_attribute<'a>(
        &'a self,
        element: &'a ElementHandle,
        name: &'a str,
    ) -> BoxFuture<'a, Result<Option<String>, BrowserError>> {
        Box::pin(async move {
            let node_id = cdp_node_id(element)?;

            let object_id = self
                .session
                .resolve_node(node_id)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            let attr_name = name.to_owned();
            let result = self
                .session
                .call(
                    "Runtime.callFunctionOn",
                    Some(serde_json::json!({
                        "objectId": object_id,
                        "functionDeclaration": "function(n) { return this.getAttribute(n); }",
                        "arguments": [{ "value": attr_name }],
                        "returnByValue": true,
                    })),
                )
                .await
                .map_err(|e| BrowserError::JsEval(e.to_string()))?;

            let val = &result["result"]["value"];
            if val.is_null() || val.is_string() && val.as_str() == Some("null") {
                Ok(None)
            } else {
                Ok(val.as_str().map(|s| s.to_owned()))
            }
        })
    }

    fn element_html<'a>(
        &'a self,
        element: &'a ElementHandle,
    ) -> BoxFuture<'a, Result<String, BrowserError>> {
        Box::pin(async move {
            let node_id = cdp_node_id(element)?;

            self.session
                .get_outer_html(node_id)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))
        })
    }

    fn element_bounding_box<'a>(
        &'a self,
        element: &'a ElementHandle,
    ) -> BoxFuture<'a, Result<BoundingBox, BrowserError>> {
        Box::pin(async move {
            let node_id = cdp_node_id(element)?;

            let model = self
                .session
                .get_box_model(node_id)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            // border quad: x1,y1, x2,y2, x3,y3, x4,y4
            let b = &model.border;
            if b.len() < 8 {
                return Err(BrowserError::Other(
                    "invalid box model: border quad has fewer than 8 values".into(),
                ));
            }
            // top-left corner = (b[0], b[1]), width and height from CDP model.
            Ok(BoundingBox {
                x: b[0],
                y: b[1],
                width: model.width as f64,
                height: model.height as f64,
            })
        })
    }

    // ── PDF ───────────────────────────────────────────────────────────────

    fn print_pdf<'a>(
        &'a self,
        options: &'a PrintOptions,
    ) -> BoxFuture<'a, Result<Vec<u8>, BrowserError>> {
        Box::pin(async move {
            let mut params = serde_json::json!({
                "landscape": options.landscape,
                "printBackground": options.print_background,
            });

            if let Some(scale) = options.scale {
                params["scale"] = serde_json::Value::from(scale);
            }
            if let Some(w) = options.paper_width {
                params["paperWidth"] = serde_json::Value::from(w);
            }
            if let Some(h) = options.paper_height {
                params["paperHeight"] = serde_json::Value::from(h);
            }

            let result = self
                .session
                .call("Page.printToPDF", Some(params))
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            let encoded = result["data"]
                .as_str()
                .ok_or_else(|| BrowserError::Other("missing data in Page.printToPDF response".into()))?;

            let bytes = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|e| BrowserError::Other(format!("base64 decode error: {e}")))?;

            Ok(bytes)
        })
    }

    // ── Enhanced screenshots ───────────────────────────────────────────────

    fn screenshot_full_page<'a>(&'a self) -> BoxFuture<'a, Result<Vec<u8>, BrowserError>> {
        Box::pin(async move {
            // Get the full page dimensions via JS.
            let dims = self
                .session
                .evaluate("JSON.stringify({ w: document.documentElement.scrollWidth, h: document.documentElement.scrollHeight })")
                .await
                .map_err(|e| BrowserError::JsEval(e.to_string()))?;

            let dims_str = dims["value"].as_str().unwrap_or(r#"{"w":1280,"h":800}"#);
            let dims_val: serde_json::Value =
                serde_json::from_str(dims_str).unwrap_or(serde_json::json!({"w":1280,"h":800}));
            let w = dims_val["w"].as_f64().unwrap_or(1280.0);
            let h = dims_val["h"].as_f64().unwrap_or(800.0);

            let result = self
                .session
                .call(
                    "Page.captureScreenshot",
                    Some(serde_json::json!({
                        "format": "png",
                        "clip": {
                            "x": 0,
                            "y": 0,
                            "width": w,
                            "height": h,
                            "scale": 1,
                        },
                        "captureBeyondViewport": true,
                    })),
                )
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            let encoded = result["data"]
                .as_str()
                .ok_or_else(|| BrowserError::Other("missing data in captureScreenshot response".into()))?;

            base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|e| BrowserError::Other(format!("base64 decode error: {e}")))
        })
    }

    fn screenshot_element<'a>(
        &'a self,
        element: &'a ElementHandle,
    ) -> BoxFuture<'a, Result<Vec<u8>, BrowserError>> {
        Box::pin(async move {
            let node_id = cdp_node_id(element)?;

            self.session
                .scroll_into_view(node_id)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            let model = self
                .session
                .get_box_model(node_id)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            let b = &model.border;
            if b.len() < 8 {
                return Err(BrowserError::Other(
                    "invalid box model: border quad has fewer than 8 values".into(),
                ));
            }

            let x = b[0];
            let y = b[1];
            let w = model.width as f64;
            let h = model.height as f64;

            let result = self
                .session
                .call(
                    "Page.captureScreenshot",
                    Some(serde_json::json!({
                        "format": "png",
                        "clip": {
                            "x": x,
                            "y": y,
                            "width": w,
                            "height": h,
                            "scale": 1,
                        },
                    })),
                )
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            let encoded = result["data"]
                .as_str()
                .ok_or_else(|| BrowserError::Other("missing data in captureScreenshot response".into()))?;

            base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|e| BrowserError::Other(format!("base64 decode error: {e}")))
        })
    }

    // ── DevTools events ───────────────────────────────────────────────────

    fn subscribe_events<'a>(
        &'a self,
    ) -> BoxFuture<'a, Result<tokio::sync::broadcast::Receiver<DevToolsEvent>, BrowserError>> {
        Box::pin(async move {
            // CDP events flow through the client's broadcast channel.
            // We bridge CdpEvent → DevToolsEvent in a background task and
            // provide the caller with a broadcast::Receiver<DevToolsEvent>.
            let (tx, rx) = tokio::sync::broadcast::channel(256);
            let mut cdp_rx = self.session.client().subscribe();

            tokio::spawn(async move {
                loop {
                    match cdp_rx.recv().await {
                        Ok(event) => {
                            let dt_event = bridge_cdp_event(event);
                            if let Some(e) = dt_event {
                                // If all receivers dropped, stop the bridge.
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

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Extract the CDP node_id from an ElementHandle, returning an error if the
/// handle is for a different backend.
fn cdp_node_id(element: &ElementHandle) -> Result<i64, BrowserError> {
    match &element.inner {
        ElementInner::Cdp { node_id } => Ok(*node_id),
        ElementInner::WebDriver { .. } => Err(BrowserError::Other(
            "ElementHandle is a WebDriver handle, not a CDP handle".into(),
        )),
    }
}

/// Compute the center of a content/border/etc. quad (8-element slice).
fn quad_center(quad: &[f64]) -> (f64, f64) {
    if quad.len() < 8 {
        return (0.0, 0.0);
    }
    let cx = (quad[0] + quad[2] + quad[4] + quad[6]) / 4.0;
    let cy = (quad[1] + quad[3] + quad[5] + quad[7]) / 4.0;
    (cx, cy)
}

/// Map a raw CDP event into a `DevToolsEvent` if it's relevant.
fn bridge_cdp_event(event: crate::cdp::CdpEvent) -> Option<DevToolsEvent> {
    use crate::browser::devtools::{ConsoleEvent, NetworkEvent};

    match event.method.as_str() {
        m if m.starts_with("Network.") => {
            let params = event.params.unwrap_or(serde_json::Value::Null);
            let url = params["response"]["url"]
                .as_str()
                .or_else(|| params["request"]["url"].as_str())
                .map(|s| s.to_owned());
            let status = params["response"]["status"].as_u64().map(|s| s as u16);
            Some(DevToolsEvent::Network(NetworkEvent {
                method: event.method,
                url,
                status,
                params,
            }))
        }
        "Runtime.consoleAPICalled" => {
            let params = event.params.unwrap_or(serde_json::Value::Null);
            let level = params["type"].as_str().unwrap_or("log").to_owned();
            let text = params["args"]
                .as_array()
                .and_then(|arr| arr.first())
                .and_then(|v| v["value"].as_str())
                .unwrap_or("")
                .to_owned();
            Some(DevToolsEvent::Console(ConsoleEvent { level, text }))
        }
        _ => None,
    }
}

// Suppress lint: target_id is kept for future use (explicit target close).
impl Drop for CdpPageBackend {
    fn drop(&mut self) {
        let _target_id = &self.target_id;
        // Could send Target.closeTarget here, but it requires an async context.
        // The browser will GC detached targets automatically.
    }
}
