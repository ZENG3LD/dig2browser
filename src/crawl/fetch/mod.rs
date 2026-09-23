//! Page fetching for the `crawler` feature: a plain-HTTP fetcher
//! ([`http::HttpFetcher`]) and a browser-driven fetcher
//! ([`browser::BrowserFetcher`], wrapping [`crate::StealthBrowser`]) behind
//! a common [`Fetcher`] trait, plus retry/cache/proxy helpers and the L2/L3
//! interactive-action executor.

pub mod browser;
pub mod cache;
pub mod http;
pub mod interactive;
pub mod proxy;
pub mod retry;

use dig2browser_crawler::profile::FetchMethod;
use futures::future::BoxFuture;
use url::Url;

/// A page fetch failed. Trimmed to the one variant every fetch path in this
/// module actually produces — earlier iterations of this type (see
/// `dig2crawl`'s `core::error::CrawlError`) carried queue/budget/robots
/// variants that only the (dropped) in-process crawl engine ever
/// constructed.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("fetch error: {0}")]
    Fetch(String),
}

/// One fetched page: final URL, status, body, timing, and (browser mode
/// only) an optional screenshot.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FetchedPage {
    pub url: Url,
    pub status_code: Option<u16>,
    pub body: String,
    pub fetched_at: chrono::DateTime<chrono::Utc>,
    pub fetch_ms: u64,
    pub method: FetchMethod,
    /// Screenshot bytes (PNG), set only in browser mode when captured.
    #[serde(skip)]
    pub screenshot: Option<Vec<u8>>,
}

/// Fetches a single URL. Implementations: [`http::HttpFetcher`],
/// [`browser::BrowserFetcher`].
pub trait Fetcher: Send + Sync {
    fn fetch<'a>(&'a self, url: &'a Url) -> BoxFuture<'a, Result<FetchedPage, FetchError>>;
}
