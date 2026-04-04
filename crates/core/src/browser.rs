//! StealthBrowser — the primary public browser API.

use dig2browser_detect::{BrowserPreference, LaunchConfig};
use dig2browser_stealth::StealthConfig;

use crate::backend::{BrowserBackend, cdp::CdpBrowserBackend, bidi::BiDiBrowserBackend};
use crate::error::BrowserError;
use crate::page::StealthPage;

/// A running browser instance with anti-detection stealth applied.
///
/// # Example
/// ```no_run
/// # async fn run() -> Result<(), dig2browser_core::BrowserError> {
/// let browser = dig2browser_core::StealthBrowser::launch().await?;
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
        let backend: Box<dyn BrowserBackend> = match launch.browser_pref {
            BrowserPreference::Firefox => {
                let b = BiDiBrowserBackend::launch(&launch, &stealth).await?;
                Box::new(b)
            }
            _ => {
                let b = CdpBrowserBackend::launch(&launch, &stealth).await?;
                Box::new(b)
            }
        };

        Ok(Self {
            backend,
            _launch: launch,
            _stealth: stealth,
        })
    }

    /// Open a new page and navigate to `url`.
    pub async fn new_page(&self, url: &str) -> Result<StealthPage, BrowserError> {
        let backend = self.backend.new_page(url).await?;
        Ok(StealthPage { backend })
    }

    /// Open a new blank page (about:blank) without navigating.
    pub async fn new_blank_page(&self) -> Result<StealthPage, BrowserError> {
        let backend = self.backend.new_blank_page().await?;
        Ok(StealthPage { backend })
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
