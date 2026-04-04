//! Firefox WebDriver backend using fantoccini.
//!
//! `WebDriverBrowser` connects to an already-running geckodriver process.
//! It does NOT spawn geckodriver — the user must start it separately:
//!
//!   geckodriver --port 4444 &
//!
//! Compatible: geckodriver 0.35.x with Firefox 124+.
//! Download: <https://github.com/mozilla/geckodriver/releases>

use std::sync::atomic::{AtomicU32, Ordering};

use fantoccini::ClientBuilder;
use serde_json::json;

use crate::browser_args::LaunchConfig;
use crate::error::BrowserError;
use crate::stealth::StealthConfig;

/// Firefox browser backend managed via W3C WebDriver (geckodriver).
///
/// Does not own the geckodriver process. Lifecycle: connect on creation,
/// `close()` ends the WebDriver session. `restart()` is a no-op because
/// WebDriver sessions are stateless per navigation.
pub(crate) struct WebDriverBrowser {
    pub(crate) stealth: StealthConfig,
    pub(crate) launch: LaunchConfig,
    pub(crate) page_count: AtomicU32,
    /// The geckodriver URL, e.g. `"http://localhost:4444"`.
    pub(crate) geckodriver_url: String,
}

impl WebDriverBrowser {
    /// Connect to an already-running geckodriver at `launch.geckodriver_url`.
    ///
    /// Builds Firefox capabilities (headless flag) and creates a WebDriver
    /// session. Returns `BrowserError::GeckoDriver` if geckodriver is not
    /// reachable or session creation fails.
    pub(crate) async fn connect(
        launch: &LaunchConfig,
        stealth: &StealthConfig,
    ) -> Result<Self, BrowserError> {
        let geckodriver_url = launch.geckodriver_url.clone();

        // Build Firefox capabilities.
        let mut caps = serde_json::Map::new();
        if launch.headless {
            let mut ff_opts = serde_json::Map::new();
            ff_opts.insert("args".into(), json!(["-headless"]));
            caps.insert(
                "moz:firefoxOptions".into(),
                serde_json::Value::Object(ff_opts),
            );
        }

        // Attempt connection — surface any errors as GeckoDriver variant.
        ClientBuilder::native()
            .capabilities(caps)
            .connect(&geckodriver_url)
            .await
            .map_err(|e| BrowserError::GeckoDriver(e.to_string()))?
            // Connection succeeded; we don't need to hold the client here —
            // new_page() creates a fresh client per tab.
            .close()
            .await
            .map_err(|e| BrowserError::WebDriver(e.to_string()))?;

        tracing::info!(
            "[dig2browser/webdriver] Connected to geckodriver at {}",
            geckodriver_url
        );

        Ok(Self {
            stealth: stealth.clone(),
            launch: launch.clone(),
            page_count: AtomicU32::new(0),
            geckodriver_url,
        })
    }

    /// Open a new WebDriver session, navigate to `url`, and inject stealth scripts.
    ///
    /// Stealth scripts must be injected AFTER navigation because WebDriver has
    /// no `AddScriptToEvaluateOnNewDocument` equivalent. The brief window
    /// between page load and injection is acceptable for scraping use cases.
    pub(crate) async fn new_page(
        &self,
        url: &str,
    ) -> Result<fantoccini::Client, BrowserError> {
        let client = self.new_client().await?;

        client
            .goto(url)
            .await
            .map_err(|e| BrowserError::Navigate {
                url: url.into(),
                detail: e.to_string(),
            })?;

        crate::stealth::inject_stealth_webdriver(&client, &self.stealth).await?;

        Ok(client)
    }

    /// No-op restart — WebDriver sessions are created fresh per page.
    pub(crate) async fn restart(&mut self) -> Result<(), BrowserError> {
        tracing::debug!("[dig2browser/webdriver] restart() is a no-op for WebDriver backend");
        self.page_count.store(0, Ordering::Relaxed);
        Ok(())
    }

    /// No cleanup needed — geckodriver is an external process not owned here.
    pub(crate) async fn close(self) -> Result<(), BrowserError> {
        tracing::info!("[dig2browser/webdriver] WebDriver backend closed");
        Ok(())
    }

    pub(crate) fn page_count(&self) -> u32 {
        self.page_count.load(Ordering::Relaxed)
    }

    pub(crate) fn increment_page_count(&self) {
        self.page_count.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn needs_restart(&self) -> bool {
        let threshold = self.launch.restart_after_pages;
        threshold > 0 && self.page_count.load(Ordering::Relaxed) >= threshold
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Create a new fantoccini::Client connected to geckodriver.
    pub(crate) async fn new_client(&self) -> Result<fantoccini::Client, BrowserError> {
        let mut caps = serde_json::Map::new();
        if self.launch.headless {
            let mut ff_opts = serde_json::Map::new();
            ff_opts.insert("args".into(), json!(["-headless"]));
            caps.insert(
                "moz:firefoxOptions".into(),
                serde_json::Value::Object(ff_opts),
            );
        }

        ClientBuilder::native()
            .capabilities(caps)
            .connect(&self.geckodriver_url)
            .await
            .map_err(|e| BrowserError::GeckoDriver(e.to_string()))
    }
}
