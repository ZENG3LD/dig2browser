use super::cache::ResponseCache;
use super::proxy::{ProxyConfig, ProxyPool};
use super::retry::RetryConfig;
use super::{FetchError, FetchedPage, Fetcher};
use crate::bot_auth::RequestSigner;
use dig2browser_crawler::profile::FetchMethod;
use futures::future::BoxFuture;
use reqwest::Client;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use url::Url;

/// Builder for [`HttpFetcher`].
///
/// Allows progressive configuration of retry, caching, and proxy options
/// before constructing the fetcher.
pub struct HttpFetcherBuilder {
    user_agent: String,
    timeout: Duration,
    retry: Option<RetryConfig>,
    cache: Option<ResponseCache>,
    proxy: Option<ProxyPool>,
}

impl HttpFetcherBuilder {
    /// Start building an `HttpFetcher` with the given `User-Agent` string.
    pub fn new(user_agent: impl Into<String>) -> Self {
        Self {
            user_agent: user_agent.into(),
            timeout: Duration::from_secs(30),
            retry: None,
            cache: None,
            proxy: None,
        }
    }

    /// Override the request timeout (default: 30 s).
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Enable retry with the given configuration.
    pub fn retry(mut self, config: RetryConfig) -> Self {
        self.retry = Some(config);
        self
    }

    /// Enable response caching with the given TTL and capacity.
    pub fn cache(mut self, ttl: Duration, max_size: usize) -> Self {
        self.cache = Some(ResponseCache::new(ttl, max_size));
        self
    }

    /// Enable proxy rotation from the given configuration.
    ///
    /// If `config.urls` is empty the proxy pool is silently omitted.
    pub fn proxy(mut self, config: ProxyConfig) -> Self {
        self.proxy = ProxyPool::from_config(config);
        self
    }

    /// Construct the `HttpFetcher`, building a `reqwest::Client` internally.
    pub fn build(self) -> Result<HttpFetcher, FetchError> {
        let mut builder = Client::builder()
            .user_agent(&self.user_agent)
            .timeout(self.timeout);

        if let Some(ref pool) = self.proxy {
            if let Some(url) = pool.next() {
                let proxy = reqwest::Proxy::all(url)
                    .map_err(|e| FetchError::Fetch(format!("invalid proxy URL {url}: {e}")))?;
                builder = builder.proxy(proxy);
            }
        }

        let client = builder
            .build()
            .map_err(|e| FetchError::Fetch(e.to_string()))?;

        Ok(HttpFetcher {
            client,
            retry: self.retry,
            cache: self.cache.map(|c| Arc::new(Mutex::new(c))),
            proxy: self.proxy,
            signer: None,
        })
    }
}

/// HTTP fetcher backed by `reqwest::Client`.
///
/// Performs a plain GET request and returns the response body as a string.
/// Suitable for static pages that do not require JavaScript rendering.
///
/// Optionally supports:
/// - Exponential-backoff **retry** on transient errors (429, 5xx, network failures).
/// - Simple TTL-based **response cache** (no external deps).
/// - **Proxy rotation** via a `ProxyPool`.
/// - **Web Bot Auth signing** via an optional [`RequestSigner`].
pub struct HttpFetcher {
    client: Client,
    retry: Option<RetryConfig>,
    cache: Option<Arc<Mutex<ResponseCache>>>,
    proxy: Option<ProxyPool>,
    signer: Option<Arc<RequestSigner>>,
}

impl HttpFetcher {
    /// Build a new `HttpFetcher` with the given `User-Agent` string and a
    /// 30-second request timeout. No retry, cache, or proxy is configured.
    ///
    /// Pass `signer = Some(arc)` to attach Web Bot Auth headers to every request.
    pub fn new(user_agent: &str, signer: Option<Arc<RequestSigner>>) -> Result<Self, FetchError> {
        let mut fetcher = HttpFetcherBuilder::new(user_agent).build()?;
        fetcher.signer = signer;
        Ok(fetcher)
    }

    /// Build an `HttpFetcher` from an existing `reqwest::Client`.
    ///
    /// No retry, cache, proxy, or signer is configured.
    pub fn with_client(client: Client) -> Self {
        Self {
            client,
            retry: None,
            cache: None,
            proxy: None,
            signer: None,
        }
    }

    /// Return a [`HttpFetcherBuilder`] for full configuration.
    pub fn builder(user_agent: impl Into<String>) -> HttpFetcherBuilder {
        HttpFetcherBuilder::new(user_agent)
    }

    /// Apply Web Bot Auth headers to a request builder if a signer is configured.
    fn apply_bot_auth(&self, mut req: reqwest::RequestBuilder, url: &Url) -> reqwest::RequestBuilder {
        if let Some(signer) = &self.signer {
            if let Ok(headers) = signer.sign_request("GET", url.as_str()) {
                req = req
                    .header("Signature-Agent", &headers.signature_agent)
                    .header("Signature-Input", &headers.signature_input)
                    .header("Signature", &headers.signature);
            }
        }
        req
    }

    /// Perform a single GET request without retry.
    async fn fetch_once(&self, url: &Url) -> Result<FetchedPage, FetchError> {
        let start = Instant::now();

        let resp = if let Some(pool) = &self.proxy {
            if let Some(proxy_url) = pool.next() {
                let proxy = reqwest::Proxy::all(proxy_url).map_err(|e| {
                    FetchError::Fetch(format!("invalid proxy URL {proxy_url}: {e}"))
                })?;
                let tmp = Client::builder()
                    .proxy(proxy)
                    .build()
                    .map_err(|e| FetchError::Fetch(e.to_string()))?;
                let req = self.apply_bot_auth(tmp.get(url.as_str()), url);
                req.send()
                    .await
                    .map_err(|e| FetchError::Fetch(format!("{url}: {e}")))?
            } else {
                let req = self.apply_bot_auth(self.client.get(url.as_str()), url);
                req.send()
                    .await
                    .map_err(|e| FetchError::Fetch(format!("{url}: {e}")))?
            }
        } else {
            let req = self.apply_bot_auth(self.client.get(url.as_str()), url);
            req.send()
                .await
                .map_err(|e| FetchError::Fetch(format!("{url}: {e}")))?
        };

        let status = resp.status().as_u16();
        let body = resp
            .text()
            .await
            .map_err(|e| FetchError::Fetch(format!("{url}: body read: {e}")))?;

        Ok(FetchedPage {
            url: url.clone(),
            status_code: Some(status),
            body,
            fetched_at: chrono::Utc::now(),
            fetch_ms: start.elapsed().as_millis() as u64,
            method: FetchMethod::Http,
            screenshot: None,
        })
    }
}

impl Fetcher for HttpFetcher {
    fn fetch<'a>(&'a self, url: &'a Url) -> BoxFuture<'a, Result<FetchedPage, FetchError>> {
        Box::pin(async move {
            if let Some(cache) = &self.cache {
                if let Ok(mut guard) = cache.lock() {
                    if let Some(cached) = guard.get(url.as_str()) {
                        tracing::debug!(url = %url, "cache hit");
                        return Ok(cached.page);
                    }
                }
            }

            let page = if let Some(retry_cfg) = &self.retry {
                let config = retry_cfg.clone();
                retry_with_backoff_fetch(self, url, &config).await?
            } else {
                self.fetch_once(url).await?
            };

            if let Some(cache) = &self.cache {
                if page.status_code.is_some_and(|s| s < 400) {
                    if let Ok(mut guard) = cache.lock() {
                        guard.put(url.as_str(), page.clone());
                    }
                }
            }

            Ok(page)
        })
    }
}

/// Helper to call `HttpFetcher::fetch_once` through the retry machinery.
///
/// This is a free function rather than a method so that the borrow checker
/// is satisfied when we move `config` into the closure.
async fn retry_with_backoff_fetch(
    fetcher: &HttpFetcher,
    url: &Url,
    config: &RetryConfig,
) -> Result<FetchedPage, FetchError> {
    use super::retry::retry_with_backoff;

    retry_with_backoff(config, |_attempt| async move {
        fetcher.fetch_once(url).await.and_then(|page| {
            if let Some(status) = page.status_code {
                if super::retry::is_retryable_status(status) {
                    return Err(FetchError::Fetch(format!("{url}: status {status}")));
                }
            }
            Ok(page)
        })
    })
    .await
}
