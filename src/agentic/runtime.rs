use futures::future::BoxFuture;

use crate::browser::{StealthBrowser, StealthPage};
use crate::detect::{BrowserPreference, BrowserProfile, LaunchConfig};
use crate::identity::{BrowserBackend, DevicePersona, IdentityProfile};
use crate::stealth::StealthConfig;

use super::contract::{CaptureArtifact, CapturePolicy, DocumentState, RuntimeFailureKind};
use super::mobile::MobileLayout;

pub type RuntimeResult<T> = Result<T, RuntimeError>;

/// Browser operations required by the single-owner worker actor.
pub trait BrowserRuntime: Send + 'static {
    fn start(&mut self) -> BoxFuture<'_, RuntimeResult<()>>;
    fn restart(&mut self) -> BoxFuture<'_, RuntimeResult<()>>;
    fn close(&mut self) -> BoxFuture<'_, RuntimeResult<()>>;
    fn needs_restart(&self) -> bool;

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
    fn capture(&mut self, policy: CapturePolicy) -> BoxFuture<'_, RuntimeResult<CaptureArtifact>>;
}

/// Production runtime owning exactly one browser and one page for an identity.
pub struct RealBrowserRuntime {
    identity: IdentityProfile,
    launch: LaunchConfig,
    stealth: StealthConfig,
    mobile_layout: Option<MobileLayout>,
    browser: Option<StealthBrowser>,
    page: Option<StealthPage>,
}

impl RealBrowserRuntime {
    pub fn new(
        identity: IdentityProfile,
        mut launch: LaunchConfig,
        mut stealth: StealthConfig,
        mobile_layout: Option<MobileLayout>,
    ) -> RuntimeResult<Self> {
        if identity.backend() != BrowserBackend::Chromium
            || launch.browser_pref == BrowserPreference::Firefox
        {
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
            browser: None,
            page: None,
        })
    }

    async fn start_inner(&mut self) -> RuntimeResult<()> {
        if self.browser.is_some() || self.page.is_some() {
            return Ok(());
        }
        self.launch.profile = BrowserProfile::Persistent(self.identity.profile_dir().to_path_buf());

        let browser = StealthBrowser::launch_with(self.launch.clone(), self.stealth.clone())
            .await
            .map_err(|_| RuntimeError::new(RuntimeFailureKind::Launch))?;
        let page = match browser.new_blank_page().await {
            Ok(page) => page,
            Err(_) => {
                let _ = browser.close().await;
                return Err(RuntimeError::new(RuntimeFailureKind::Launch));
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

        self.page = Some(page);
        self.browser = Some(browser);
        Ok(())
    }

    async fn restart_inner(&mut self) -> RuntimeResult<()> {
        self.page.take();
        if let Some(browser) = self.browser.take() {
            browser
                .close()
                .await
                .map_err(|_| RuntimeError::new(RuntimeFailureKind::Shutdown))?;
        }
        self.start_inner().await
    }

    async fn close_inner(&mut self) -> RuntimeResult<()> {
        self.page.take();
        let close_result = if let Some(browser) = self.browser.take() {
            browser
                .close()
                .await
                .map_err(|_| RuntimeError::new(RuntimeFailureKind::Shutdown))
        } else {
            Ok(())
        };
        close_result
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
        })
    }
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
        self.browser
            .as_ref()
            .is_some_and(StealthBrowser::needs_restart)
    }

    fn navigate<'a>(&'a mut self, url: &'a str) -> BoxFuture<'a, RuntimeResult<DocumentState>> {
        Box::pin(async move {
            self.page()?
                .goto(url)
                .await
                .map_err(|_| RuntimeError::new(RuntimeFailureKind::Navigation))?;
            self.document_state().await
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
                        .map_err(|_| RuntimeError::new(RuntimeFailureKind::Capture))?;
                    Ok(CaptureArtifact::HtmlOnly { state, html })
                }
                CapturePolicy::EvidenceViewport => {
                    let html = self
                        .page()?
                        .html()
                        .await
                        .map_err(|_| RuntimeError::new(RuntimeFailureKind::Capture))?;
                    let png = self
                        .page()?
                        .screenshot()
                        .await
                        .map_err(|_| RuntimeError::new(RuntimeFailureKind::Capture))?;
                    Ok(CaptureArtifact::EvidenceViewport { state, html, png })
                }
            }
        })
    }
}

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
}
