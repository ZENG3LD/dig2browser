use crate::backend::CdpBrowser;
use crate::backend::BrowserInner;
#[cfg(feature = "firefox")]
use crate::backend::WebDriverBrowser;
#[cfg(feature = "firefox")]
use crate::browser_detect::BrowserPreference;
use crate::browser_args::LaunchConfig;
use crate::error::BrowserError;
use crate::page::StealthPage;
use crate::stealth::StealthConfig;

// ---------------------------------------------------------------------------
// StealthBrowser
// ---------------------------------------------------------------------------

/// Multi-backend browser handle.
///
/// Dispatches all operations to the correct backend via `BrowserInner`:
/// - Without the `firefox` feature: always a CDP (Chrome/Edge) backend.
/// - With `firefox` feature: CDP for Chrome/Edge or WebDriver for Firefox
///   depending on `LaunchConfig::browser_pref`.
pub struct StealthBrowser {
    inner: BrowserInner,
}

impl StealthBrowser {
    /// Launch with default config.
    pub async fn launch() -> Result<Self, BrowserError> {
        Self::launch_with(LaunchConfig::default(), StealthConfig::default()).await
    }

    /// Launch with explicit config.
    ///
    /// For Chrome/Edge: spawns the browser process and connects via CDP.
    /// For Firefox: connects to an already-running geckodriver.
    pub async fn launch_with(
        launch: LaunchConfig,
        stealth: StealthConfig,
    ) -> Result<Self, BrowserError> {
        #[cfg(feature = "firefox")]
        let inner = if launch.browser_pref == BrowserPreference::Firefox {
            let b = WebDriverBrowser::connect(&launch, &stealth).await?;
            BrowserInner::WebDriver(b)
        } else {
            let b = CdpBrowser::launch(&launch, &stealth).await?;
            BrowserInner::Cdp(b)
        };

        #[cfg(not(feature = "firefox"))]
        let inner = {
            let b = CdpBrowser::launch(&launch, &stealth).await?;
            BrowserInner::Cdp(b)
        };

        Ok(Self { inner })
    }

    // -----------------------------------------------------------------------
    // Page creation
    // -----------------------------------------------------------------------

    /// Open a new page with stealth scripts injected and navigate to `url`.
    pub async fn new_page(&self, url: &str) -> Result<StealthPage, BrowserError> {
        self.increment_page_count();
        match &self.inner {
            BrowserInner::Cdp(b) => {
                let page = b.new_page(url).await?;
                Ok(StealthPage::from_cdp(page))
            }
            #[cfg(feature = "firefox")]
            BrowserInner::WebDriver(b) => {
                let client = b.new_page(url).await?;
                Ok(StealthPage::from_webdriver(client))
            }
        }
    }

    /// Open a new blank page with stealth scripts injected (no navigation).
    pub async fn new_blank_page(&self) -> Result<StealthPage, BrowserError> {
        self.increment_page_count();
        match &self.inner {
            BrowserInner::Cdp(b) => {
                let page = b.new_blank_page().await?;
                Ok(StealthPage::from_cdp(page))
            }
            #[cfg(feature = "firefox")]
            BrowserInner::WebDriver(b) => {
                // WebDriver has no blank page concept separate from navigation;
                // open about:blank and inject stealth scripts.
                let client = b.new_client().await?;
                client
                    .goto("about:blank")
                    .await
                    .map_err(|e| BrowserError::Navigate {
                        url: "about:blank".into(),
                        detail: e.to_string(),
                    })?;
                crate::stealth::inject_stealth_webdriver(&client, &b.stealth).await?;
                Ok(StealthPage::from_webdriver(client))
            }
        }
    }

    // -----------------------------------------------------------------------
    // Page counter
    // -----------------------------------------------------------------------

    /// Increment the internal page counter by one.
    pub fn increment_page_count(&self) {
        match &self.inner {
            BrowserInner::Cdp(b) => b.increment_page_count(),
            #[cfg(feature = "firefox")]
            BrowserInner::WebDriver(b) => b.increment_page_count(),
        }
    }

    /// Current page navigation count since the last launch or restart.
    pub fn page_count(&self) -> u32 {
        match &self.inner {
            BrowserInner::Cdp(b) => b.page_count(),
            #[cfg(feature = "firefox")]
            BrowserInner::WebDriver(b) => b.page_count(),
        }
    }

    /// Returns `true` when the page counter has exceeded `restart_after_pages`.
    pub fn needs_restart(&self) -> bool {
        match &self.inner {
            BrowserInner::Cdp(b) => b.needs_restart(),
            #[cfg(feature = "firefox")]
            BrowserInner::WebDriver(b) => b.needs_restart(),
        }
    }

    // -----------------------------------------------------------------------
    // Restart
    // -----------------------------------------------------------------------

    /// Restart the browser.
    ///
    /// For CDP: kills and re-launches the Chrome/Edge process.
    /// For WebDriver: resets the page counter (sessions are stateless).
    pub async fn restart(&mut self) -> Result<(), BrowserError> {
        tracing::info!(
            "[dig2browser] Restarting browser after {} pages",
            self.page_count()
        );
        match &mut self.inner {
            BrowserInner::Cdp(b) => b.restart().await,
            #[cfg(feature = "firefox")]
            BrowserInner::WebDriver(b) => b.restart().await,
        }?;
        tracing::info!("[dig2browser] Browser restarted successfully");
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Close
    // -----------------------------------------------------------------------

    /// Close the browser and clean up resources.
    pub async fn close(self) -> Result<(), BrowserError> {
        match self.inner {
            BrowserInner::Cdp(b) => b.close().await,
            #[cfg(feature = "firefox")]
            BrowserInner::WebDriver(b) => b.close().await,
        }
    }

    // -----------------------------------------------------------------------
    // Raw access (CDP-only)
    // -----------------------------------------------------------------------

    /// Access the underlying chromiumoxide `Browser` for advanced CDP operations.
    ///
    /// Only available when the `firefox` feature is disabled (Chrome-only builds).
    #[cfg(not(feature = "firefox"))]
    pub fn raw(&self) -> &chromiumoxide::Browser {
        match &self.inner {
            BrowserInner::Cdp(b) => &b.browser,
        }
    }
}
