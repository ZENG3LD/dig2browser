//! StealthPage — the primary public page API.

use std::sync::Arc;
use std::time::Duration;

use crate::cookies::CookieJar;

use crate::browser::backend::{BoundingBox, ElementHandle, PageBackend, PrintOptions};
use crate::browser::devtools::PageDevTools;
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
