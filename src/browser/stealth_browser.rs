//! StealthBrowser — the primary public browser API.

use std::sync::Arc;

use crate::detect::{BrowserPreference, LaunchConfig};
use crate::process_isolation::BrowserProcessIsolation;
use crate::stealth::StealthConfig;

use crate::browser::backend::{BrowserBackend, cdp::CdpBrowserBackend, bidi::BiDiBrowserBackend};
use crate::browser::error::BrowserError;
use crate::browser::page::StealthPage;

/// Query `http://127.0.0.1:{port}/json/version` and return the browser-level
/// `webSocketDebuggerUrl`. The browser must have been launched with
/// `--remote-debugging-port=<port>`.
pub async fn discover_ws_url(port: u16) -> Result<String, BrowserError> {
    let url = format!("http://127.0.0.1:{port}/json/version");
    let resp = reqwest::get(&url)
        .await
        .map_err(|e| BrowserError::Connect(format!("GET {url}: {e}")))?;
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| BrowserError::Connect(format!("parse json: {e}")))?;
    body.get("webSocketDebuggerUrl")
        .and_then(|v| v.as_str())
        .map(|s| s.to_owned())
        .ok_or_else(|| BrowserError::Connect("no webSocketDebuggerUrl in /json/version".into()))
}

/// A running browser instance with anti-detection stealth applied.
///
/// # Example
/// ```no_run
/// # async fn run() -> Result<(), crate::browser::BrowserError> {
/// let browser = crate::browser::StealthBrowser::launch().await?;
/// let page = browser.new_page("https://example.com").await?;
/// let html = page.html().await?;
/// browser.close().await?;
/// # Ok(())
/// # }
/// ```
pub struct StealthBrowser {
    pub(crate) backend: Box<dyn BrowserBackend>,
    /// Stored for future restart support.
    pub(crate) _launch: LaunchConfig,
    /// Stored for future restart support.
    pub(crate) _stealth: StealthConfig,
}

impl StealthBrowser {
    /// Launch a browser with default configuration.
    ///
    /// Auto-detects Chrome/Edge. Stealth level: Standard. Headless.
    pub async fn launch() -> Result<Self, BrowserError> {
        Self::launch_with(LaunchConfig::default(), StealthConfig::default()).await
    }

    /// Launch a browser with explicit launch and stealth configuration.
    ///
    /// - `Firefox` preference → BiDi backend (geckodriver required)
    /// - All other preferences → CDP backend (Chrome/Edge)
    pub async fn launch_with(
        launch: LaunchConfig,
        stealth: StealthConfig,
    ) -> Result<Self, BrowserError> {
        Self::launch_with_process_isolation(
            launch,
            stealth,
            BrowserProcessIsolation::Native,
        )
        .await
    }

    /// Launch with an explicit outer process-isolation policy.
    pub async fn launch_with_process_isolation(
        launch: LaunchConfig,
        stealth: StealthConfig,
        process_isolation: BrowserProcessIsolation,
    ) -> Result<Self, BrowserError> {
        let backend: Box<dyn BrowserBackend> = match launch.browser_pref {
            BrowserPreference::Firefox => {
                if !process_isolation.is_native() {
                    return Err(BrowserError::Launch(
                        "outer process isolation is unavailable for Firefox".into(),
                    ));
                }
                let b = BiDiBrowserBackend::launch(&launch, &stealth).await?;
                Box::new(b)
            }
            _ => {
                let b = CdpBrowserBackend::launch_with_process_isolation(
                    &launch,
                    &stealth,
                    &process_isolation,
                )
                .await?;
                Box::new(b)
            }
        };

        Ok(Self {
            backend,
            _launch: launch,
            _stealth: stealth,
        })
    }

    /// Attach to an already-running Chrome/Edge instance — TRANSPARENT by
    /// default: no persona is applied to attached tabs (no UA / timezone /
    /// device-metrics overrides). Attaching to a browser this library did
    /// not launch means observing and driving it, not repainting its
    /// identity (live incident 2026-07-29: the persona default silently
    /// pinned a dev stand tab to 1920×1080). Persona-on-attach is an
    /// explicit opt-in via [`StealthBrowser::attach_with`].
    ///
    /// Obtain `ws_url` via [`discover_ws_url`] or the browser's own stderr
    /// ("DevTools listening on ws://…"). The browser is NOT killed when this
    /// instance is dropped or closed.
    pub async fn attach(ws_url: String) -> Result<Self, BrowserError> {
        let stealth = StealthConfig {
            transparent: true,
            ..StealthConfig::default()
        };
        Self::attach_with(ws_url, stealth).await
    }

    /// Attach with an explicit persona SOURCE — the three-mode selector
    /// (`user` / `random` / `catalog`, see
    /// [`crate::stealth::PersonaSource`]). `PersonaSource::User` (the
    /// default) resolves to no overrides at all and is identical to
    /// [`StealthBrowser::attach`]; the other two modes resolve to a full
    /// identity that is pushed onto every attached tab.
    pub async fn attach_with_persona(
        ws_url: String,
        source: &crate::stealth::PersonaSource,
    ) -> Result<Self, BrowserError> {
        let stealth = match source
            .resolve()
            .map_err(|e| BrowserError::Connect(e.to_string()))?
        {
            Some(cfg) => cfg,
            None => StealthConfig {
                transparent: true,
                ..StealthConfig::default()
            },
        };
        Self::attach_with(ws_url, stealth).await
    }

    /// Attach to an already-running Chrome/Edge instance with an explicit
    /// stealth config — the persona IS applied to every tab attached via
    /// [`StealthBrowser::attach_page`] (UA / timezone / device metrics),
    /// exactly like a launched-browser page. For flows that own the target
    /// browser's identity (crawler personas); dev tooling uses the
    /// transparent [`StealthBrowser::attach`] instead.
    pub async fn attach_with(
        ws_url: String,
        stealth: StealthConfig,
    ) -> Result<Self, BrowserError> {
        let launch = LaunchConfig::default();
        let b = CdpBrowserBackend::attach(ws_url, launch.clone(), stealth.clone()).await?;
        Ok(Self {
            backend: Box::new(b),
            _launch: launch,
            _stealth: stealth,
        })
    }

    /// List all open page targets (tabs) in an attached/launched browser.
    /// Returns `(target_id, url, title)` triples. Only works on the CDP backend.
    pub async fn pages(&self) -> Result<Vec<(String, String, String)>, BrowserError> {
        let cdp = self
            .backend
            .as_any_cdp()
            .ok_or_else(|| BrowserError::Connect("pages() is only available on the CDP backend".into()))?;
        cdp.list_pages().await
    }

    /// Attach to an existing open tab by `target_id` (from [`StealthBrowser::pages`]).
    /// Returns a `StealthPage` connected to that tab without creating a new one.
    /// Applies the same CDP-native stealth overrides as a freshly opened page
    /// (UA/Client Hints, timezone, device metrics), but does NOT inject the
    /// JS stealth scripts — those cannot retroactively patch a document this
    /// tab already loaded before it was attached.
    pub async fn attach_page(&self, target_id: &str) -> Result<StealthPage, BrowserError> {
        let cdp = self
            .backend
            .as_any_cdp()
            .ok_or_else(|| BrowserError::Connect("attach_page() is only available on the CDP backend".into()))?;
        let page = cdp.attach_to_existing_page(target_id).await?;
        Ok(StealthPage {
            backend: Arc::from(Box::new(page) as Box<dyn crate::browser::backend::PageBackend>),
        })
    }

    /// Open a new page and navigate to `url`.
    pub async fn new_page(&self, url: &str) -> Result<StealthPage, BrowserError> {
        let backend = self.backend.new_page(url).await?;
        Ok(StealthPage {
            backend: Arc::from(backend),
        })
    }

    /// Open a new blank page (about:blank) without navigating.
    pub async fn new_blank_page(&self) -> Result<StealthPage, BrowserError> {
        let backend = self.backend.new_blank_page().await?;
        Ok(StealthPage {
            backend: Arc::from(backend),
        })
    }

    /// Number of pages opened since the last restart.
    pub fn page_count(&self) -> u32 {
        self.backend.page_count()
    }

    /// Whether the browser should be restarted due to page count threshold.
    pub fn needs_restart(&self) -> bool {
        self.backend.needs_restart()
    }

    /// Close the browser and release all resources.
    pub async fn close(self) -> Result<(), BrowserError> {
        self.backend.close().await
    }
}
