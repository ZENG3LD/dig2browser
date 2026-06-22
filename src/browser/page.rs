//! StealthPage — the primary public page API.

use std::sync::Arc;
use std::time::Duration;

use crate::cookies::CookieJar;

use crate::browser::backend::{BoundingBox, ElementHandle, PageBackend, PrintOptions};
use crate::browser::devtools::{DevToolsEvent, PageDevTools};
use crate::browser::error::BrowserError;
use crate::browser::wait::WaitBuilder;

/// A browser page (tab) with stealth capabilities.
///
/// Obtained via [`StealthBrowser::new_page`] or [`StealthBrowser::new_blank_page`].
pub struct StealthPage {
    pub(crate) backend: Arc<dyn PageBackend>,
}

impl StealthPage {
    /// Navigate to `url`.
    pub async fn goto(&self, url: &str) -> Result<(), BrowserError> {
        self.backend.goto(url).await
    }

    /// Navigate to `url`, then poll for `selector` until found or `timeout` elapses.
    ///
    /// Uses `document.querySelector(selector)` via JS eval. Returns `Timeout` if
    /// the element is never found within the given duration.
    pub async fn goto_and_wait(
        &self,
        url: &str,
        selector: &str,
        timeout: Duration,
    ) -> Result<(), BrowserError> {
        self.backend.goto(url).await?;

        let deadline = tokio::time::Instant::now() + timeout;
        let poll_interval = Duration::from_millis(200);

        loop {
            let js = format!(
                "document.querySelector({:?}) !== null",
                selector
            );
            let result = self.backend.eval(&js).await?;
            if result.as_bool() == Some(true) {
                return Ok(());
            }

            if tokio::time::Instant::now() >= deadline {
                return Err(BrowserError::Timeout(timeout));
            }

            tokio::time::sleep(poll_interval).await;
        }
    }

    /// Return the full outer HTML of the current document.
    pub async fn html(&self) -> Result<String, BrowserError> {
        self.backend.html().await
    }

    /// Evaluate a JavaScript expression in the page context.
    pub async fn eval(&self, js: &str) -> Result<serde_json::Value, BrowserError> {
        self.backend.eval(js).await
    }

    /// Capture a PNG screenshot of the current viewport.
    pub async fn screenshot(&self) -> Result<Vec<u8>, BrowserError> {
        self.backend.screenshot().await
    }

    /// Capture a PNG screenshot of the full page (not just the viewport).
    pub async fn screenshot_full(&self) -> Result<Vec<u8>, BrowserError> {
        self.backend.screenshot_full_page().await
    }

    /// Print the page as a PDF and return the raw bytes.
    pub async fn pdf(&self, options: PrintOptions) -> Result<Vec<u8>, BrowserError> {
        self.backend.print_pdf(&options).await
    }

    /// Sleep a human-like random delay (50–300 ms).
    pub async fn human_delay(&self) {
        use rand::Rng;
        let ms = rand::thread_rng().gen_range(50u64..=300);
        tokio::time::sleep(Duration::from_millis(ms)).await;
    }

    /// Perform a simulated smooth scroll to the bottom of the page.
    pub async fn human_scroll(&self) -> Result<(), BrowserError> {
        let js = r#"
            window.scrollTo({
                top: document.body.scrollHeight,
                behavior: 'smooth'
            });
        "#;
        self.backend.eval(js).await?;
        Ok(())
    }

    /// Return all cookies visible to the current page, wrapped in a [`CookieJar`].
    pub async fn get_cookies(&self) -> Result<CookieJar, BrowserError> {
        let cookies = self.backend.get_cookies().await?;
        Ok(CookieJar(cookies))
    }

    /// Set the page's cookies from a [`CookieJar`].
    pub async fn set_cookies(&self, jar: &CookieJar) -> Result<(), BrowserError> {
        self.backend.set_cookies(&jar.0).await
    }

    /// Set extra HTTP headers that will be sent with every request from this page.
    ///
    /// On the CDP backend (Chrome/Edge) this calls `Network.setExtraHTTPHeaders`.
    /// On the BiDi backend (Firefox) this is a no-op — BiDi has no direct
    /// equivalent, so the call succeeds silently.
    pub async fn set_extra_http_headers(
        &self,
        headers: std::collections::HashMap<String, String>,
    ) -> Result<(), BrowserError> {
        self.backend.set_extra_http_headers(headers).await
    }

    /// Disable Content Security Policy enforcement on this page.
    ///
    /// On the CDP backend (Chrome/Edge) this calls `Page.setBypassCSP`.
    /// This allows `Runtime.evaluate` to inject scripts on CSP-locked sites.
    /// On the BiDi backend (Firefox) this is a no-op.
    ///
    /// Call this before navigating to the target URL so the bypass is active
    /// for the initial document load.
    pub async fn set_bypass_csp(&self, enabled: bool) -> Result<(), BrowserError> {
        self.backend.set_bypass_csp(enabled).await
    }

    /// Register a script to run on every new document before any page JS.
    ///
    /// On the CDP backend (Chrome/Edge) this calls
    /// `Page.addScriptToEvaluateOnNewDocument` and returns the `identifier`
    /// from the response (needed to remove the script later).
    /// On the BiDi backend (Firefox) this is a no-op returning an empty string.
    ///
    /// This is the correct way to make injected scripts survive navigation:
    /// combine with `eval` for the current page (idempotent script guard ensures
    /// no double-injection).
    pub async fn add_script_to_evaluate_on_new_document(
        &self,
        source: &str,
    ) -> Result<String, BrowserError> {
        self.backend
            .add_script_to_evaluate_on_new_document(source)
            .await
    }

    /// Find the first element matching the CSS `selector`.
    pub async fn find(&self, selector: &str) -> Result<Element, BrowserError> {
        let handle = self.backend.find_element(selector).await?;
        Ok(Element {
            handle,
            backend: Arc::clone(&self.backend),
        })
    }

    /// Find all elements matching the CSS `selector`.
    pub async fn find_all(&self, selector: &str) -> Result<Vec<Element>, BrowserError> {
        let handles = self.backend.find_elements(selector).await?;
        Ok(handles
            .into_iter()
            .map(|handle| Element {
                handle,
                backend: Arc::clone(&self.backend),
            })
            .collect())
    }

    /// Create a wait builder for polling-based waiting.
    ///
    /// # Example
    /// ```no_run
    /// # use std::time::Duration;
    /// # async fn example(page: &crate::browser::StealthPage) -> Result<(), crate::browser::BrowserError> {
    /// let el = page.wait().at_most(Duration::from_secs(10)).for_element("#submit").await?;
    /// # Ok(()) }
    /// ```
    pub fn wait(&self) -> WaitBuilder<'_> {
        WaitBuilder::new(self)
    }

    /// Subscribe to DevTools events for this page.
    pub async fn devtools(&self) -> Result<PageDevTools, BrowserError> {
        let rx = self.backend.subscribe_events().await?;
        Ok(PageDevTools::new(rx))
    }

    // ── Task 1: Raw input by coordinates ─────────────────────────────────────

    /// Click at viewport coordinates (CSS pixels).
    ///
    /// Synthesizes `mousePressed` + `mouseReleased` for the left button.
    pub async fn click_at(&self, x: f64, y: f64) -> Result<(), BrowserError> {
        self.backend.click_at(x, y).await
    }

    /// Right-click at viewport coordinates.
    ///
    /// Synthesizes `mousePressed` + `mouseReleased` for the right button.
    pub async fn right_click_at(&self, x: f64, y: f64) -> Result<(), BrowserError> {
        self.backend.right_click_at(x, y).await
    }

    /// Move the mouse to viewport coordinates without clicking.
    ///
    /// Fires a `mouseMoved` event for hover/tooltip testing.
    pub async fn mouse_move(&self, x: f64, y: f64) -> Result<(), BrowserError> {
        self.backend.mouse_move_to(x, y).await
    }

    /// Press-drag-release from `(x1, y1)` to `(x2, y2)`.
    ///
    /// Synthesizes `mousePressed` → several `mouseMoved` steps → `mouseReleased`
    /// so drag-handlers fire correctly.
    pub async fn drag(&self, x1: f64, y1: f64, x2: f64, y2: f64) -> Result<(), BrowserError> {
        self.backend.drag(x1, y1, x2, y2).await
    }

    /// Dispatch a scroll-wheel event at `(x, y)` with CSS-pixel deltas.
    pub async fn wheel(&self, x: f64, y: f64, dx: f64, dy: f64) -> Result<(), BrowserError> {
        self.backend.wheel(x, y, dx, dy).await
    }

    /// Press a key by name.
    ///
    /// Accepts standard DOM key names (`"Enter"`, `"Escape"`, `"ArrowLeft"`,
    /// `"Tab"`, `"Backspace"`) or a single printable character (`"a"`, `"A"`, …).
    /// Synthesizes `keyDown` + `keyUp`.
    pub async fn key_press(&self, key: &str) -> Result<(), BrowserError> {
        self.backend.key_press(key).await
    }

    /// Hold modifiers and press a key — e.g. `(&["Control"], "r")` for Ctrl+R.
    ///
    /// Modifier names: `"Alt"`, `"Control"`, `"Meta"`, `"Shift"`.
    pub async fn key_chord(&self, modifiers: &[&str], key: &str) -> Result<(), BrowserError> {
        self.backend.key_chord(modifiers, key).await
    }

    // ── Task 2: Viewport / device emulation ──────────────────────────────────

    /// Override the viewport dimensions and device pixel ratio.
    ///
    /// Calls `Emulation.setDeviceMetricsOverride`. Affects CSS media queries,
    /// `window.innerWidth/Height`, and screenshot dimensions.
    pub async fn set_viewport(
        &self,
        width: u32,
        height: u32,
        device_scale_factor: f64,
    ) -> Result<(), BrowserError> {
        self.backend
            .set_viewport(width, height, device_scale_factor)
            .await
    }

    /// Clear a previous `set_viewport` override.
    ///
    /// Calls `Emulation.clearDeviceMetricsOverride`.
    pub async fn clear_viewport_override(&self) -> Result<(), BrowserError> {
        self.backend.clear_viewport_override().await
    }

    // ── Task 3: DOM inspection ────────────────────────────────────────────────

    /// Walk the DOM below `selector` (up to `max_depth` levels) and return a
    /// JSON tree of `{tag, id, classes, rect:[x,y,w,h], children:[…]}` nodes.
    ///
    /// Useful for layout debugging without screenshots.
    pub async fn dom_tree(
        &self,
        selector: &str,
        max_depth: u32,
    ) -> Result<serde_json::Value, BrowserError> {
        let js = format!(
            r#"
(function() {{
    function walk(el, depth) {{
        if (!el || depth < 0) return null;
        var r = el.getBoundingClientRect();
        var node = {{
            tag: el.tagName ? el.tagName.toLowerCase() : '',
            id: el.id || '',
            classes: el.className ? el.className.split(' ').filter(Boolean) : [],
            rect: [r.left, r.top, r.width, r.height],
            children: []
        }};
        if (depth > 0) {{
            for (var i = 0; i < el.children.length; i++) {{
                var child = walk(el.children[i], depth - 1);
                if (child) node.children.push(child);
            }}
        }}
        return node;
    }}
    var root = document.querySelector({selector_json});
    if (!root) return null;
    return walk(root, {max_depth});
}})()
"#,
            selector_json = serde_json::to_string(selector)
                .map_err(|e| BrowserError::JsEval(e.to_string()))?,
            max_depth = max_depth
        );
        let val = self.backend.eval(&js).await?;
        Ok(val)
    }

    /// Get the bounding rect `(x, y, width, height)` of the first element
    /// matching `selector`, or `None` if the element was not found.
    pub async fn element_rect(
        &self,
        selector: &str,
    ) -> Result<Option<(f64, f64, f64, f64)>, BrowserError> {
        let js = format!(
            r#"
(function() {{
    var el = document.querySelector({selector_json});
    if (!el) return null;
    var r = el.getBoundingClientRect();
    return JSON.stringify([r.left, r.top, r.width, r.height]);
}})()
"#,
            selector_json = serde_json::to_string(selector)
                .map_err(|e| BrowserError::JsEval(e.to_string()))?,
        );
        let val = self.backend.eval(&js).await?;
        if val.is_null() {
            return Ok(None);
        }
        // The value is a JSON-encoded array string.
        let arr_str = val.as_str().unwrap_or("null");
        let arr: Vec<f64> = serde_json::from_str(arr_str)
            .map_err(|e| BrowserError::JsEval(format!("element_rect parse error: {e}")))?;
        if arr.len() < 4 {
            return Ok(None);
        }
        Ok(Some((arr[0], arr[1], arr[2], arr[3])))
    }

    // ── Task 4: Performance + paint timing ────────────────────────────────────

    /// Return Navigation Timing and Resource Timing entries as JSON.
    pub async fn performance_entries(&self) -> Result<serde_json::Value, BrowserError> {
        let js = r#"
(function() {
    var nav = performance.getEntriesByType('navigation');
    var res = performance.getEntriesByType('resource');
    return JSON.stringify({ navigation: nav, resources: res });
})()
"#;
        let val = self.backend.eval(js).await?;
        let s = val.as_str().unwrap_or("{}");
        serde_json::from_str(s).map_err(|e| BrowserError::JsEval(format!("performance_entries parse error: {e}")))
    }

    /// Return the current `performance.now()` reading in milliseconds.
    pub async fn now_ms(&self) -> Result<f64, BrowserError> {
        let val = self.backend.eval("performance.now()").await?;
        val.as_f64()
            .ok_or_else(|| BrowserError::JsEval("performance.now() did not return a number".into()))
    }

    /// Count `requestAnimationFrame` callbacks fired over `duration_ms` milliseconds.
    ///
    /// Resolves once the timer expires and returns the frame count.
    pub async fn count_frames(&self, duration_ms: u64) -> Result<u64, BrowserError> {
        // Kick off the counter in the page, then poll for the result.
        let start_js = format!(
            r#"
(function() {{
    window.__d2b_frame_count = 0;
    window.__d2b_frame_done = false;
    function tick() {{
        window.__d2b_frame_count++;
        if (!window.__d2b_frame_done) requestAnimationFrame(tick);
    }}
    requestAnimationFrame(tick);
    setTimeout(function() {{ window.__d2b_frame_done = true; }}, {duration_ms});
}})()
"#
        );
        self.backend.eval(&start_js).await?;
        // Wait for duration + a bit of padding.
        tokio::time::sleep(Duration::from_millis(duration_ms + 200)).await;
        let val = self.backend.eval("window.__d2b_frame_count || 0").await?;
        Ok(val.as_u64().unwrap_or(0))
    }

    // ── Task 5: Raw CDP escape hatch ─────────────────────────────────────────

    /// Send a raw CDP method on this page's session and return the `result` object.
    ///
    /// Use this for anything not yet wrapped by the typed API.
    pub async fn cdp_call(
        &self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, BrowserError> {
        self.backend.cdp_call(method, params).await
    }

    // ── Task 6: Network log streaming ────────────────────────────────────────

    /// Drain queued network events since the last call.
    ///
    /// Returns a `Vec` of `{method, url, status?, mime?, timestamp}` objects.
    /// Requires that `devtools()` has been called first (events are produced by
    /// the same background bridge).
    pub async fn drain_network(&self) -> Result<Vec<serde_json::Value>, BrowserError> {
        let mut dt = self.devtools().await?;
        let mut events = Vec::new();
        while let Some(ev) = dt.try_next() {
            if let DevToolsEvent::Network(n) = ev {
                let status = n.status.map(|s| serde_json::Value::Number(s.into()));
                let mime = n.params["response"]["mimeType"]
                    .as_str()
                    .map(|s| serde_json::Value::String(s.to_owned()));
                let ts = n.params["timestamp"].clone();
                let mut obj = serde_json::json!({
                    "method": n.method,
                    "url": n.url,
                });
                if let Some(s) = status {
                    obj["status"] = s;
                }
                if let Some(m) = mime {
                    obj["mime"] = m;
                }
                if !ts.is_null() {
                    obj["timestamp"] = ts;
                }
                events.push(obj);
            }
        }
        Ok(events)
    }
}

// ── Element ──────────────────────────────────────────────────────────────────

/// An element obtained from [`StealthPage::find`] or [`StealthPage::find_all`].
///
/// `Element` borrows the page's backend via `Arc`, so it can outlive the
/// `StealthPage` reference but not the underlying browser session.
pub struct Element {
    pub(crate) handle: ElementHandle,
    pub(crate) backend: Arc<dyn PageBackend>,
}

impl Element {
    /// Click this element.
    pub async fn click(&self) -> Result<(), BrowserError> {
        self.backend.click_element(&self.handle).await
    }

    /// Type `text` into this element.
    pub async fn type_text(&self, text: &str) -> Result<(), BrowserError> {
        self.backend.type_into_element(&self.handle, text).await
    }

    /// Get the visible text content of this element.
    pub async fn text(&self) -> Result<String, BrowserError> {
        self.backend.element_text(&self.handle).await
    }

    /// Get the value of a named attribute, or `None` if absent.
    pub async fn attribute(&self, name: &str) -> Result<Option<String>, BrowserError> {
        self.backend.element_attribute(&self.handle, name).await
    }

    /// Get the outer HTML of this element.
    pub async fn html(&self) -> Result<String, BrowserError> {
        self.backend.element_html(&self.handle).await
    }

    /// Get the bounding box of this element.
    pub async fn bounding_box(&self) -> Result<BoundingBox, BrowserError> {
        self.backend.element_bounding_box(&self.handle).await
    }

    /// Capture a screenshot cropped to this element.
    pub async fn screenshot(&self) -> Result<Vec<u8>, BrowserError> {
        self.backend.screenshot_element(&self.handle).await
    }
}
