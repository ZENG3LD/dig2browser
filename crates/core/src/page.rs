//! StealthPage — the primary public page API.

use std::time::Duration;

use dig2browser_cookie::CookieJar;

use crate::backend::PageBackend;
use crate::error::BrowserError;

/// A browser page (tab) with stealth capabilities.
///
/// Obtained via [`StealthBrowser::new_page`] or [`StealthBrowser::new_blank_page`].
pub struct StealthPage {
    pub(crate) backend: Box<dyn PageBackend>,
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
}
