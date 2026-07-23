use futures::future::BoxFuture;

use crate::browser::{
    Cookie, CookieJar, DevToolsEvent, NetworkEvent, PageDevTools, StealthBrowser, StealthPage,
};
use crate::detect::{BrowserPreference, BrowserProfile, LaunchConfig};
use crate::identity::{BrowserBackend, DevicePersona, IdentityProfile};
use crate::process_isolation::BrowserProcessIsolation;
use crate::stealth::StealthConfig;

use super::contract::{
    CaptureArtifact, CapturePolicy, CookieSpec, DocumentState, RuntimeFailureKind,
};
use super::mobile::MobileLayout;
use super::navigation::NavigationPolicy;

pub type RuntimeResult<T> = Result<T, RuntimeError>;

/// Browser operations required by the single-owner worker actor.
pub trait BrowserRuntime: Send + 'static {
    fn start(&mut self) -> BoxFuture<'_, RuntimeResult<()>>;
    fn restart(&mut self) -> BoxFuture<'_, RuntimeResult<()>>;
    fn close(&mut self) -> BoxFuture<'_, RuntimeResult<()>>;
    fn needs_restart(&self) -> bool;
    fn navigation_policy_healthy(&self) -> bool {
        true
    }

    fn navigate<'a>(&'a mut self, url: &'a str) -> BoxFuture<'a, RuntimeResult<DocumentState>>;
    fn click_at(&mut self, x: f64, y: f64) -> BoxFuture<'_, RuntimeResult<()>>;
    fn wheel(
        &mut self,
        x: f64,
        y: f64,
        delta_x: f64,
        delta_y: f64,
    ) -> BoxFuture<'_, RuntimeResult<()>>;
    fn key_press<'a>(&'a mut self, key: &'a str) -> BoxFuture<'a, RuntimeResult<()>>;
    fn resolve_element<'a>(&'a mut self, selector: &'a str) -> BoxFuture<'a, RuntimeResult<()>>;
    fn click_element<'a>(&'a mut self, selector: &'a str) -> BoxFuture<'a, RuntimeResult<()>>;
    fn type_element<'a>(
        &'a mut self,
        selector: &'a str,
        text: &'a str,
    ) -> BoxFuture<'a, RuntimeResult<()>>;
    fn read_element_text<'a>(
        &'a mut self,
        selector: &'a str,
    ) -> BoxFuture<'a, RuntimeResult<String>>;
    fn evaluate<'a>(
        &'a mut self,
        script: &'a str,
    ) -> BoxFuture<'a, RuntimeResult<serde_json::Value>>;
    fn capture(&mut self, policy: CapturePolicy) -> BoxFuture<'_, RuntimeResult<CaptureArtifact>>;

    /// Subscribe to this runtime's live DevTools event stream (`Network.*`
    /// incl. WebSocket/SSE frames, and console messages). Default
    /// implementation reports the surface as unsupported; only
    /// [`RealBrowserRuntime`] (CDP/BiDi-backed) overrides it. Each call
    /// returns an independent subscription — it does not disturb the
    /// runtime's own internal DevTools use (HTTP-status tracking).
    fn subscribe_devtools(&mut self) -> BoxFuture<'_, RuntimeResult<PageDevTools>> {
        Box::pin(async { Err(RuntimeError::new(RuntimeFailureKind::Protocol)) })
    }

    /// Install cookies into the running session (CDP `Network.setCookie`).
    /// Default reports the surface as unsupported; only [`RealBrowserRuntime`]
    /// overrides it.
    fn set_cookies(&mut self, cookies: Vec<CookieSpec>) -> BoxFuture<'_, RuntimeResult<()>> {
        let _ = cookies;
        Box::pin(async { Err(RuntimeError::new(RuntimeFailureKind::Protocol)) })
    }

    /// Observe the document's load state (`document.readyState`, plus url/title)
    /// via a fixed internal evaluation — no consumer script. Default reports the
    /// surface as unsupported; only [`RealBrowserRuntime`] overrides it. Backs
    /// the inspect-only `WaitForLoadState` task step.
    fn observe_document(&mut self) -> BoxFuture<'_, RuntimeResult<DocumentState>> {
        Box::pin(async { Err(RuntimeError::new(RuntimeFailureKind::Protocol)) })
    }

    /// Enumerate the page's interactive elements via a fixed internal DOM read
    /// (no consumer script), returning raw JSON `[{role, name, selector}, …]`.
    /// Default reports the surface as unsupported; only [`RealBrowserRuntime`]
    /// overrides it. Backs the inspect-only `ReadInteractiveElements` task step.
    fn read_interactive_elements(
        &mut self,
    ) -> BoxFuture<'_, RuntimeResult<serde_json::Value>> {
        Box::pin(async { Err(RuntimeError::new(RuntimeFailureKind::Protocol)) })
    }

    /// Choose an `<option>` of the `<select>` at `selector` by value/label/text
    /// via a fixed internal script parameterized only by `value` (no consumer
    /// script). Default reports the surface as unsupported; only
    /// [`RealBrowserRuntime`] overrides it. Backs the `SelectOption` step.
    fn select_option<'a>(
        &'a mut self,
        selector: &'a str,
        value: &'a str,
    ) -> BoxFuture<'a, RuntimeResult<()>> {
        let _ = (selector, value);
        Box::pin(async { Err(RuntimeError::new(RuntimeFailureKind::Protocol)) })
    }

    /// Set the files selected by the file `<input>` at `selector` to the local
    /// `path` (CDP `DOM.setFileInputFiles`). Default reports the surface as
    /// unsupported; only [`RealBrowserRuntime`] overrides it. Backs the gated
    /// `UploadFile` step.
    fn set_file_input<'a>(
        &'a mut self,
        selector: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, RuntimeResult<()>> {
        let _ = (selector, path);
        Box::pin(async { Err(RuntimeError::new(RuntimeFailureKind::Protocol)) })
    }

    /// Block until a download triggered by the current page completes, or
    /// `timeout` elapses, and return its suggested filename and raw bytes.
    /// Default reports the surface as unsupported; only
    /// [`RealBrowserRuntime`] overrides it. Backs the gated `WaitForDownload`
    /// step.
    fn wait_for_download(
        &mut self,
        timeout: std::time::Duration,
    ) -> BoxFuture<'_, RuntimeResult<(String, Vec<u8>)>> {
        let _ = timeout;
        Box::pin(async { Err(RuntimeError::new(RuntimeFailureKind::Protocol)) })
    }
}

/// Production runtime owning exactly one browser and one page for an identity.
pub struct RealBrowserRuntime {
    identity: IdentityProfile,
    launch: LaunchConfig,
    stealth: StealthConfig,
    mobile_layout: Option<MobileLayout>,
    navigation_policy: NavigationPolicy,
    process_isolation: BrowserProcessIsolation,
    browser: Option<StealthBrowser>,
    page: Option<StealthPage>,
    devtools: Option<PageDevTools>,
    document_http_status: Option<u16>,
    navigation_count: u32,
}

impl RealBrowserRuntime {
    pub fn new(
        identity: IdentityProfile,
        launch: LaunchConfig,
        stealth: StealthConfig,
        mobile_layout: Option<MobileLayout>,
    ) -> RuntimeResult<Self> {
        Self::new_with_navigation_policy(
            identity,
            launch,
            stealth,
            mobile_layout,
            NavigationPolicy::default(),
        )
    }

    pub fn new_with_navigation_policy(
        identity: IdentityProfile,
        launch: LaunchConfig,
        stealth: StealthConfig,
        mobile_layout: Option<MobileLayout>,
        navigation_policy: NavigationPolicy,
    ) -> RuntimeResult<Self> {
        Self::new_with_navigation_policy_and_process_isolation(
            identity,
            launch,
            stealth,
            mobile_layout,
            navigation_policy,
            BrowserProcessIsolation::Native,
        )
    }

    pub fn new_with_navigation_policy_and_process_isolation(
        identity: IdentityProfile,
        mut launch: LaunchConfig,
        mut stealth: StealthConfig,
        mobile_layout: Option<MobileLayout>,
        navigation_policy: NavigationPolicy,
        process_isolation: BrowserProcessIsolation,
    ) -> RuntimeResult<Self> {
        let backend_matches = match launch.browser_pref {
            BrowserPreference::Firefox => identity.backend() == BrowserBackend::Firefox,
            BrowserPreference::Auto
            | BrowserPreference::ChromeOnly
            | BrowserPreference::EdgeOnly => identity.backend() == BrowserBackend::Chromium,
        };
        if !backend_matches {
            return Err(RuntimeError::new(RuntimeFailureKind::Launch));
        }
        match (identity.device(), mobile_layout.is_some()) {
            (DevicePersona::DesktopNative, true) | (DevicePersona::MobileLayout, false) => {
                return Err(RuntimeError::new(RuntimeFailureKind::Protocol));
            }
            _ => {}
        }

        if let Some(layout) = &mobile_layout {
            launch.window_size = (layout.width(), layout.height());
            stealth.viewport = (layout.width(), layout.height());
            stealth
                .set_device_scale_factor(layout.device_scale_factor())
                .map_err(|_| RuntimeError::new(RuntimeFailureKind::Protocol))?;
        }

        Ok(Self {
            identity,
            launch,
            stealth,
            mobile_layout,
            navigation_policy,
            process_isolation,
            browser: None,
            page: None,
            devtools: None,
            document_http_status: None,
            navigation_count: 0,
        })
    }

    async fn start_inner(&mut self) -> RuntimeResult<()> {
        if self.browser.is_some() || self.page.is_some() {
            return Ok(());
        }
        self.launch.profile = BrowserProfile::Persistent(self.identity.profile_dir().to_path_buf());

        let browser = StealthBrowser::launch_with_process_isolation(
            self.launch.clone(),
            self.stealth.clone(),
            self.process_isolation.clone(),
        )
        .await
        .map_err(|error| {
            tracing::debug!(%error, "browser runtime launch failed");
            report_containment_start_failure("launch", &error);
            RuntimeError::new(RuntimeFailureKind::Launch)
        })?;
        let page = match browser.new_blank_page().await {
            Ok(page) => page,
            Err(error) => {
                tracing::debug!(%error, "browser runtime blank page failed");
                report_containment_start_failure("blank_page", &error);
                let _ = browser.close().await;
                return Err(RuntimeError::new(RuntimeFailureKind::Launch));
            }
        };
        let devtools = match page.devtools().await {
            Ok(devtools) => devtools,
            Err(error) => {
                tracing::debug!(%error, "browser runtime devtools setup failed");
                report_containment_start_failure("devtools", &error);
                let _ = browser.close().await;
                return Err(RuntimeError::new(RuntimeFailureKind::Protocol));
            }
        };

        if let Some(layout) = &self.mobile_layout {
            if page
                .cdp_call(
                    "Emulation.setDeviceMetricsOverride",
                    Some(layout.device_metrics_params()),
                )
                .await
                .is_err()
                || page
                    .cdp_call(
                        "Emulation.setTouchEmulationEnabled",
                        Some(layout.touch_emulation_params()),
                    )
                    .await
                    .is_err()
            {
                let _ = browser.close().await;
                return Err(RuntimeError::new(RuntimeFailureKind::Protocol));
            }
        }
        if page
            .install_page_request_policy(self.navigation_policy.clone())
            .await
            .is_err()
        {
            let _ = browser.close().await;
            return Err(RuntimeError::new(RuntimeFailureKind::Protocol));
        }

        self.page = Some(page);
        self.devtools = Some(devtools);
        self.document_http_status = None;
        self.navigation_count = 0;
        self.browser = Some(browser);
        Ok(())
    }

    async fn restart_inner(&mut self) -> RuntimeResult<()> {
        self.devtools.take();
        self.document_http_status = None;
        self.navigation_count = 0;
        self.release_current_browser().await?;
        self.start_inner().await
    }

    async fn release_current_browser(&mut self) -> RuntimeResult<()> {
        let policy_result = match &self.page {
            Some(page) => page
                .clear_page_request_policy()
                .await
                .map_err(|_| RuntimeError::new(RuntimeFailureKind::Shutdown)),
            None => Ok(()),
        };
        self.page.take();
        let close_result = if let Some(browser) = self.browser.take() {
            browser
                .close()
                .await
                .map_err(|_| RuntimeError::new(RuntimeFailureKind::Shutdown))
        } else {
            Ok(())
        };
        policy_result.and(close_result)
    }

    async fn close_inner(&mut self) -> RuntimeResult<()> {
        self.devtools.take();
        self.document_http_status = None;
        self.release_current_browser().await
    }

    fn page(&self) -> RuntimeResult<&StealthPage> {
        self.page
            .as_ref()
            .ok_or_else(|| RuntimeError::new(RuntimeFailureKind::Protocol))
    }

    async fn document_state(&self) -> RuntimeResult<DocumentState> {
        let value = self
            .page()?
            .eval(
                r#"JSON.stringify({url:String(location.href),title:String(document.title),readyState:String(document.readyState)})"#,
            )
            .await
            .map_err(|_| RuntimeError::new(RuntimeFailureKind::Capture))?;
        let encoded = value
            .as_str()
            .ok_or_else(|| RuntimeError::new(RuntimeFailureKind::Protocol))?;
        let value: serde_json::Value = serde_json::from_str(encoded)
            .map_err(|_| RuntimeError::new(RuntimeFailureKind::Protocol))?;
        Ok(DocumentState {
            url: value["url"].as_str().unwrap_or_default().to_owned(),
            title: value["title"].as_str().unwrap_or_default().to_owned(),
            ready_state: value["readyState"].as_str().unwrap_or_default().to_owned(),
            http_status: self.document_http_status,
        })
    }

    async fn interactive_elements(&self) -> RuntimeResult<serde_json::Value> {
        let value = self
            .page()?
            .eval(INTERACTIVE_ELEMENTS_SCRIPT)
            .await
            .map_err(|_| RuntimeError::new(RuntimeFailureKind::Capture))?;
        let encoded = value
            .as_str()
            .ok_or_else(|| RuntimeError::new(RuntimeFailureKind::Protocol))?;
        let parsed: serde_json::Value = serde_json::from_str(encoded)
            .map_err(|_| RuntimeError::new(RuntimeFailureKind::Protocol))?;
        if !parsed.is_array() {
            return Err(RuntimeError::new(RuntimeFailureKind::Protocol));
        }
        Ok(parsed)
    }

    async fn select_option_inner(
        &self,
        selector: &str,
        value: &str,
    ) -> RuntimeResult<()> {
        // Embed the caller's selector and value as JSON-escaped JS string
        // literals; the surrounding script is fixed (station-authored), so this
        // is parameterization, not a consumer script.
        let selector_lit = serde_json::to_string(selector)
            .map_err(|_| RuntimeError::new(RuntimeFailureKind::Protocol))?;
        let value_lit = serde_json::to_string(value)
            .map_err(|_| RuntimeError::new(RuntimeFailureKind::Protocol))?;
        let script = format!(
            "JSON.stringify((function(){{\
var sel={selector_lit}, target={value_lit}, el;\
try{{ el=document.querySelector(sel); }}catch(e){{ return false; }}\
if(!el||String(el.tagName).toLowerCase()!=='select') return false;\
var opts=el.options, idx=-1;\
for(var i=0;i<opts.length;i++){{ var o=opts[i]; if(o.value===target||o.label===target||(o.text||'').trim()===target){{ idx=i; break; }} }}\
if(idx===-1) return false;\
el.selectedIndex=idx;\
el.dispatchEvent(new Event('input',{{bubbles:true}}));\
el.dispatchEvent(new Event('change',{{bubbles:true}}));\
return true;\
}})())"
        );
        let result = self
            .page()?
            .eval(&script)
            .await
            .map_err(|_| RuntimeError::new(RuntimeFailureKind::Interaction))?;
        if result.as_str() == Some("true") {
            Ok(())
        } else {
            Err(RuntimeError::new(RuntimeFailureKind::Interaction))
        }
    }

    fn clear_devtools_events(&mut self) {
        if let Some(devtools) = &mut self.devtools {
            while devtools.try_next().is_some() {}
        }
    }

    fn update_document_http_status(&mut self, final_url: &str) {
        let mut status = None;
        if let Some(devtools) = &mut self.devtools {
            while let Some(event) = devtools.try_next() {
                if let DevToolsEvent::Network(event) = event {
                    if let Some(candidate) = main_document_http_status(&event, final_url) {
                        status = Some(candidate);
                    }
                }
            }
        }
        self.document_http_status = status;
    }
}

fn main_document_http_status(event: &NetworkEvent, final_url: &str) -> Option<u16> {
    let status = event.status.filter(|status| (100..=599).contains(status))?;
    let event_url = event.url.as_deref()?;
    if event_url.split('#').next() != final_url.split('#').next() {
        return None;
    }

    let is_main_document = match event.method.as_str() {
        "Network.responseReceived" => event.params["type"] == "Document",
        "network.responseCompleted" => event.params["navigation"].is_string(),
        _ => false,
    };
    is_main_document.then_some(status)
}

impl BrowserRuntime for RealBrowserRuntime {
    fn start(&mut self) -> BoxFuture<'_, RuntimeResult<()>> {
        Box::pin(self.start_inner())
    }

    fn restart(&mut self) -> BoxFuture<'_, RuntimeResult<()>> {
        Box::pin(self.restart_inner())
    }

    fn close(&mut self) -> BoxFuture<'_, RuntimeResult<()>> {
        Box::pin(self.close_inner())
    }

    fn needs_restart(&self) -> bool {
        let limit = self.launch.restart_after_pages;
        limit > 0 && self.navigation_count >= limit
    }

    fn navigation_policy_healthy(&self) -> bool {
        self.page
            .as_ref()
            .is_some_and(StealthPage::page_request_policy_healthy)
    }

    fn navigate<'a>(&'a mut self, url: &'a str) -> BoxFuture<'a, RuntimeResult<DocumentState>> {
        Box::pin(async move {
            if !self.navigation_policy.allows(url)
                || !self.page()?.page_request_policy_healthy()
            {
                return Err(RuntimeError::new(RuntimeFailureKind::Navigation));
            }
            self.clear_devtools_events();
            self.document_http_status = None;
            self.page()?
                .goto(url)
                .await
                .map_err(|_| RuntimeError::new(RuntimeFailureKind::Navigation))?;
            self.navigation_count = self.navigation_count.saturating_add(1);
            let mut state = self.document_state().await?;
            self.update_document_http_status(&state.url);
            state.http_status = self.document_http_status;
            Ok(state)
        })
    }

    fn click_at(&mut self, x: f64, y: f64) -> BoxFuture<'_, RuntimeResult<()>> {
        Box::pin(async move {
            self.page()?
                .click_at(x, y)
                .await
                .map_err(|_| RuntimeError::new(RuntimeFailureKind::Interaction))
        })
    }

    fn wheel(
        &mut self,
        x: f64,
        y: f64,
        delta_x: f64,
        delta_y: f64,
    ) -> BoxFuture<'_, RuntimeResult<()>> {
        Box::pin(async move {
            self.page()?
                .wheel(x, y, delta_x, delta_y)
                .await
                .map_err(|_| RuntimeError::new(RuntimeFailureKind::Interaction))
        })
    }

    fn key_press<'a>(&'a mut self, key: &'a str) -> BoxFuture<'a, RuntimeResult<()>> {
        Box::pin(async move {
            self.page()?
                .key_press(key)
                .await
                .map_err(|_| RuntimeError::new(RuntimeFailureKind::Interaction))
        })
    }

    fn resolve_element<'a>(&'a mut self, selector: &'a str) -> BoxFuture<'a, RuntimeResult<()>> {
        Box::pin(async move {
            self.page()?
                .find(selector)
                .await
                .map(|_| ())
                .map_err(|_| RuntimeError::new(RuntimeFailureKind::Interaction))
        })
    }

    fn click_element<'a>(&'a mut self, selector: &'a str) -> BoxFuture<'a, RuntimeResult<()>> {
        Box::pin(async move {
            let element = self
                .page()?
                .find(selector)
                .await
                .map_err(|_| RuntimeError::new(RuntimeFailureKind::Interaction))?;
            element
                .click()
                .await
                .map_err(|_| RuntimeError::new(RuntimeFailureKind::Interaction))
        })
    }

    fn type_element<'a>(
        &'a mut self,
        selector: &'a str,
        text: &'a str,
    ) -> BoxFuture<'a, RuntimeResult<()>> {
        Box::pin(async move {
            let element = self
                .page()?
                .find(selector)
                .await
                .map_err(|_| RuntimeError::new(RuntimeFailureKind::Interaction))?;
            element
                .type_text(text)
                .await
                .map_err(|_| RuntimeError::new(RuntimeFailureKind::Interaction))
        })
    }

    fn read_element_text<'a>(
        &'a mut self,
        selector: &'a str,
    ) -> BoxFuture<'a, RuntimeResult<String>> {
        Box::pin(async move {
            let element = self
                .page()?
                .find(selector)
                .await
                .map_err(|_| RuntimeError::new(RuntimeFailureKind::Interaction))?;
            element
                .text()
                .await
                .map_err(|_| RuntimeError::new(RuntimeFailureKind::Interaction))
        })
    }

    fn evaluate<'a>(
        &'a mut self,
        script: &'a str,
    ) -> BoxFuture<'a, RuntimeResult<serde_json::Value>> {
        Box::pin(async move {
            self.page()?
                .eval(script)
                .await
                .map_err(|_| RuntimeError::new(RuntimeFailureKind::Interaction))
        })
    }

    fn capture(&mut self, policy: CapturePolicy) -> BoxFuture<'_, RuntimeResult<CaptureArtifact>> {
        Box::pin(async move {
            let state = self.document_state().await?;
            match policy {
                CapturePolicy::StateOnly => Ok(CaptureArtifact::StateOnly(state)),
                CapturePolicy::HtmlOnly => {
                    let html = self
                        .page()?
                        .html()
                        .await
                        .map_err(|error| {
                            report_test_capture_failure("html", &error);
                            RuntimeError::new(RuntimeFailureKind::Capture)
                        })?;
                    Ok(CaptureArtifact::HtmlOnly { state, html })
                }
                CapturePolicy::EvidenceViewport => {
                    let html = self
                        .page()?
                        .html()
                        .await
                        .map_err(|error| {
                            report_test_capture_failure("html", &error);
                            RuntimeError::new(RuntimeFailureKind::Capture)
                        })?;
                    let png = self
                        .page()?
                        .screenshot()
                        .await
                        .map_err(|error| {
                            report_test_capture_failure("screenshot", &error);
                            RuntimeError::new(RuntimeFailureKind::Capture)
                        })?;
                    Ok(CaptureArtifact::EvidenceViewport { state, html, png })
                }
            }
        })
    }

    fn subscribe_devtools(&mut self) -> BoxFuture<'_, RuntimeResult<PageDevTools>> {
        Box::pin(async move {
            self.page()?
                .devtools()
                .await
                .map_err(|_| RuntimeError::new(RuntimeFailureKind::Protocol))
        })
    }

    fn set_cookies(&mut self, cookies: Vec<CookieSpec>) -> BoxFuture<'_, RuntimeResult<()>> {
        Box::pin(async move {
            let jar = CookieJar(
                cookies
                    .into_iter()
                    .map(|cookie| Cookie {
                        name: cookie.name,
                        value: cookie.value,
                        domain: cookie.domain,
                        path: cookie.path,
                        is_secure: cookie.secure,
                        is_httponly: cookie.http_only,
                        expires_utc: cookie.expires_unix,
                    })
                    .collect(),
            );
            self.page()?
                .set_cookies(&jar)
                .await
                .map_err(|_| RuntimeError::new(RuntimeFailureKind::Interaction))
        })
    }

    fn observe_document(&mut self) -> BoxFuture<'_, RuntimeResult<DocumentState>> {
        Box::pin(async move { self.document_state().await })
    }

    fn read_interactive_elements(
        &mut self,
    ) -> BoxFuture<'_, RuntimeResult<serde_json::Value>> {
        Box::pin(async move { self.interactive_elements().await })
    }

    fn select_option<'a>(
        &'a mut self,
        selector: &'a str,
        value: &'a str,
    ) -> BoxFuture<'a, RuntimeResult<()>> {
        Box::pin(async move { self.select_option_inner(selector, value).await })
    }

    fn set_file_input<'a>(
        &'a mut self,
        selector: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, RuntimeResult<()>> {
        Box::pin(async move {
            let paths = [path.to_owned()];
            self.page()?
                .set_input_files(selector, &paths)
                .await
                .map_err(|_| RuntimeError::new(RuntimeFailureKind::Interaction))
        })
    }

    fn wait_for_download(
        &mut self,
        timeout: std::time::Duration,
    ) -> BoxFuture<'_, RuntimeResult<(String, Vec<u8>)>> {
        Box::pin(async move {
            self.page()?
                .wait_for_download(timeout)
                .await
                .map_err(|_| RuntimeError::new(RuntimeFailureKind::Capture))
        })
    }
}

/// Fixed, station-authored DOM read backing `ReadInteractiveElements`. It
/// enumerates interactive elements and, for each, derives an ARIA/tag `role`,
/// a best-effort accessible `name`, and a stable CSS `selector` (an `#id` when
/// uniquely resolvable, else an `nth-of-type` path anchored at the nearest
/// uniquely-id'd ancestor). Bounded to `MAX_INTERACTIVE_ELEMENTS` (256) and
/// returns a `JSON.stringify`'d array, mirroring `document_state`'s marshalling.
/// This is not a consumer script — its text is compiled in, never caller-supplied.
const INTERACTIVE_ELEMENTS_SCRIPT: &str = r#"JSON.stringify((function(){
  var MAX=256, NAME_MAX=512;
  function uniqueId(el){
    if(!el.id) return null;
    try{ if(document.querySelectorAll('#'+CSS.escape(el.id)).length===1) return '#'+CSS.escape(el.id); }catch(e){}
    return null;
  }
  function cssPath(el){
    var uid=uniqueId(el); if(uid) return uid;
    var parts=[], node=el;
    while(node && node.nodeType===1 && node!==document.documentElement){
      var uidn=uniqueId(node);
      if(uidn){ parts.unshift(uidn); break; }
      var sel=node.tagName.toLowerCase();
      var parent=node.parentNode;
      if(parent && parent.children){
        var sibs=[];
        for(var i=0;i<parent.children.length;i++){ if(parent.children[i].tagName===node.tagName) sibs.push(parent.children[i]); }
        if(sibs.length>1) sel+=':nth-of-type('+(sibs.indexOf(node)+1)+')';
      }
      parts.unshift(sel);
      node=node.parentNode;
    }
    return parts.join(' > ');
  }
  function role(el){
    var r=el.getAttribute&&el.getAttribute('role');
    if(r&&r.trim()) return r.trim().toLowerCase();
    return el.tagName.toLowerCase();
  }
  function name(el){
    var a=el.getAttribute&&el.getAttribute('aria-label');
    if(a&&a.trim()) return a.trim();
    var t=(el.innerText||el.textContent||'').replace(/\s+/g,' ').trim();
    if(t) return t;
    if('value' in el && el.value) return String(el.value);
    var ph=el.getAttribute&&el.getAttribute('placeholder'); if(ph&&ph.trim()) return ph.trim();
    var nm=el.getAttribute&&el.getAttribute('name'); if(nm&&nm.trim()) return nm.trim();
    var ti=el.getAttribute&&el.getAttribute('title'); if(ti&&ti.trim()) return ti.trim();
    return '';
  }
  var nodes=document.querySelectorAll('a,button,input,select,textarea,[role]');
  var seen=[], out=[];
  for(var i=0;i<nodes.length && out.length<MAX;i++){
    var el=nodes[i];
    if(seen.indexOf(el)!==-1) continue;
    seen.push(el);
    var sel=cssPath(el);
    if(!sel) continue;
    var nm=name(el); if(nm.length>NAME_MAX) nm=nm.slice(0,NAME_MAX);
    out.push({role:role(el), name:nm, selector:sel});
  }
  return out;
})())"#;

#[cfg(feature = "containment-test-hooks")]
fn report_containment_start_failure(stage: &str, error: &dyn std::fmt::Display) {
    use std::io::Write as _;

    let Some(path) = std::env::var_os("DIG2BROWSER_RUNTIME_DIAGNOSTIC_LOG") else {
        return;
    };
    if path.is_empty() {
        return;
    }
    if let Ok(mut log) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = writeln!(log, "stage={stage} error={error}");
    }
}

#[cfg(not(feature = "containment-test-hooks"))]
fn report_containment_start_failure(_stage: &str, _error: &dyn std::fmt::Display) {}

#[cfg(feature = "runtime-test-hooks")]
fn report_test_capture_failure(stage: &str, error: &dyn std::fmt::Display) {
    if std::env::var_os("DIG2BROWSER_TEST_CAPTURE_DIAGNOSTICS").is_some() {
        eprintln!("dig2browser_test_capture_failure stage={stage} error={error}");
    }
}

#[cfg(not(feature = "runtime-test-hooks"))]
fn report_test_capture_failure(_stage: &str, _error: &dyn std::fmt::Display) {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeError {
    kind: RuntimeFailureKind,
}

impl RuntimeError {
    pub fn new(kind: RuntimeFailureKind) -> Self {
        Self { kind }
    }

    pub fn kind(self) -> RuntimeFailureKind {
        self.kind
    }
}

impl std::fmt::Display for RuntimeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "browser runtime {:?} failure", self.kind)
    }
}

impl std::error::Error for RuntimeError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{DevicePersona, IdentityClass};

    #[test]
    fn cdp_backend_is_the_only_persistent_profile_lock_owner() {
        let source = include_str!("runtime.rs");
        let guard_type = ["ProfileOwnership", "Guard"].concat();
        let owner_field = ["profile", "_owner"].concat();

        assert!(!source.contains(&guard_type));
        assert!(!source.contains(&owner_field));
    }

    #[test]
    fn mobile_layout_aligns_launch_and_stealth_device_metrics() {
        let identity = IdentityProfile::new(
            "profiles",
            "mobile-public",
            IdentityClass::Public,
            BrowserBackend::Chromium,
            DevicePersona::MobileLayout,
        )
        .unwrap();
        let layout = MobileLayout::new(393, 852, 3.0, 5).unwrap();
        let mut stealth = StealthConfig::default();
        stealth.user_agent = "desktop-sentinel".into();

        let runtime = RealBrowserRuntime::new(
            identity,
            LaunchConfig::default(),
            stealth,
            Some(layout),
        )
        .unwrap();

        assert_eq!(runtime.launch.window_size, (393, 852));
        assert_eq!(runtime.stealth.viewport, (393, 852));
        assert_eq!(runtime.stealth.device_scale_factor.get(), 3.0);
        assert_eq!(runtime.stealth.user_agent, "desktop-sentinel");
    }

    #[test]
    fn main_document_status_uses_final_document_response() {
        let subresource = NetworkEvent {
            method: "Network.responseReceived".into(),
            url: Some("https://example.test/app.js".into()),
            status: Some(200),
            params: serde_json::json!({"type": "Script"}),
        };
        let document = NetworkEvent {
            method: "Network.responseReceived".into(),
            url: Some("https://example.test/final#fragment".into()),
            status: Some(204),
            params: serde_json::json!({"type": "Document"}),
        };

        assert_eq!(
            main_document_http_status(&subresource, "https://example.test/final"),
            None
        );
        assert_eq!(
            main_document_http_status(&document, "https://example.test/final"),
            Some(204)
        );
    }
}
