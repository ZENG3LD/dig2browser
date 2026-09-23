use super::retry::RetryConfig;
use super::{FetchError, FetchedPage, Fetcher};
use crate::bot_auth::RequestSigner;
use crate::{LaunchConfig, StealthBrowser, StealthConfig};
use dig2browser_crawler::profile::FetchMethod;
use futures::future::BoxFuture;
use std::sync::Arc;
use std::time::Instant;
use url::Url;

/// Browser fetcher backed by a [`StealthBrowser`].
///
/// Uses `StealthBrowser` directly (not the station daemon) — same pattern as
/// `daemon4russian-parser`'s Yandex Maps enrichment daemon.
///
/// Optionally retries failed navigations with exponential backoff when a
/// [`RetryConfig`] is supplied.
///
/// Optionally injects Web Bot Auth headers via a [`RequestSigner`].
pub struct BrowserFetcher {
    browser: StealthBrowser,
    /// Optional CSS selector to wait for before capturing HTML.
    wait_selector: Option<String>,
    /// Optional retry configuration.
    retry: Option<RetryConfig>,
    /// Optional Web Bot Auth signer.
    signer: Option<Arc<RequestSigner>>,
}

impl BrowserFetcher {
    /// Launch a stealth browser with the given config.
    pub async fn new(
        launch: LaunchConfig,
        stealth: StealthConfig,
        wait_selector: Option<String>,
        signer: Option<Arc<RequestSigner>>,
    ) -> Result<Self, FetchError> {
        let browser = StealthBrowser::launch_with(launch, stealth)
            .await
            .map_err(|e| FetchError::Fetch(format!("browser launch: {e}")))?;
        Ok(Self {
            browser,
            wait_selector,
            retry: None,
            signer,
        })
    }

    /// Enable exponential-backoff retry for failed browser navigations.
    pub fn with_retry(mut self, config: RetryConfig) -> Self {
        self.retry = Some(config);
        self
    }

    /// Shut down the browser.
    pub async fn shutdown(self) -> Result<(), FetchError> {
        self.browser
            .close()
            .await
            .map_err(|e| FetchError::Fetch(format!("browser shutdown: {e}")))
    }

    /// Perform a single browser navigation without retry.
    async fn navigate_once(&self, url: &Url) -> Result<FetchedPage, FetchError> {
        let start = Instant::now();

        let page = self
            .browser
            .new_blank_page()
            .await
            .map_err(|e| FetchError::Fetch(format!("browser new page: {e}")))?;

        if let Some(signer) = &self.signer {
            if let Ok(headers) = signer.sign_request("GET", url.as_str()) {
                let mut extra_headers = std::collections::HashMap::new();
                extra_headers.insert("Signature-Agent".to_string(), headers.signature_agent);
                extra_headers.insert("Signature-Input".to_string(), headers.signature_input);
                extra_headers.insert("Signature".to_string(), headers.signature);
                page.set_extra_http_headers(extra_headers)
                    .await
                    .map_err(|e| FetchError::Fetch(format!("browser set headers: {e}")))?;
            }
        }

        page.goto(url.as_str())
            .await
            .map_err(|e| FetchError::Fetch(format!("browser goto: {e}")))?;

        if let Some(selector) = &self.wait_selector {
            page.wait()
                .for_element(selector.as_str())
                .await
                .map_err(|e| FetchError::Fetch(format!("browser wait for element: {e}")))?;
        }

        let body = page
            .html()
            .await
            .map_err(|e| FetchError::Fetch(format!("browser html: {e}")))?;

        let screenshot = page
            .screenshot()
            .await
            .map_err(|e| FetchError::Fetch(format!("browser screenshot: {e}")))?;

        Ok(FetchedPage {
            url: url.clone(),
            status_code: Some(200),
            body,
            fetched_at: chrono::Utc::now(),
            fetch_ms: start.elapsed().as_millis() as u64,
            method: FetchMethod::Browser {
                wait_selector: self.wait_selector.clone(),
            },
            screenshot: Some(screenshot),
        })
    }

    /// Navigate to `url` and return the live `StealthPage` handle without
    /// capturing HTML. Caller owns the page and is responsible for closing
    /// it.
    pub async fn open_page(&self, url: &Url) -> Result<crate::StealthPage, FetchError> {
        let page = self
            .browser
            .new_blank_page()
            .await
            .map_err(|e| FetchError::Fetch(format!("browser new page: {e}")))?;

        if let Some(signer) = &self.signer {
            if let Ok(headers) = signer.sign_request("GET", url.as_str()) {
                let mut extra_headers = std::collections::HashMap::new();
                extra_headers.insert("Signature-Agent".to_string(), headers.signature_agent);
                extra_headers.insert("Signature-Input".to_string(), headers.signature_input);
                extra_headers.insert("Signature".to_string(), headers.signature);
                page.set_extra_http_headers(extra_headers)
                    .await
                    .map_err(|e| FetchError::Fetch(format!("browser set headers: {e}")))?;
            }
        }

        page.goto(url.as_str())
            .await
            .map_err(|e| FetchError::Fetch(format!("browser goto: {e}")))?;

        if let Some(selector) = &self.wait_selector {
            page.wait()
                .for_element(selector.as_str())
                .await
                .map_err(|e| FetchError::Fetch(format!("browser wait for element: {e}")))?;
        }

        Ok(page)
    }

    /// Fetch a page, execute browser actions, then capture the result.
    pub async fn fetch_with_actions(
        &self,
        url: &Url,
        actions: &[crate::crawl::agent::actions::BrowserAction],
    ) -> Result<FetchedPage, FetchError> {
        let start = Instant::now();
        let page = self.open_page(url).await?;

        let outcome = super::interactive::execute_actions(&page, actions).await?;

        Ok(FetchedPage {
            url: url.clone(),
            status_code: Some(200),
            body: outcome.html,
            fetched_at: chrono::Utc::now(),
            fetch_ms: start.elapsed().as_millis() as u64,
            method: FetchMethod::Browser {
                wait_selector: self.wait_selector.clone(),
            },
            screenshot: outcome.screenshot,
        })
    }
}

impl Fetcher for BrowserFetcher {
    fn fetch<'a>(&'a self, url: &'a Url) -> BoxFuture<'a, Result<FetchedPage, FetchError>> {
        Box::pin(async move {
            if let Some(retry_cfg) = &self.retry {
                use super::retry::retry_with_backoff;
                retry_with_backoff(retry_cfg, |_attempt| async move { self.navigate_once(url).await }).await
            } else {
                self.navigate_once(url).await
            }
        })
    }
}
