use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::browser::StealthBrowser;
use crate::browser_args::LaunchConfig;
use crate::error::BrowserError;
use crate::page::StealthPage;
use crate::stealth::StealthConfig;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct PoolConfig {
    pub size: usize,
    pub launch: LaunchConfig,
    pub stealth: StealthConfig,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            size: 3,
            launch: LaunchConfig::default(),
            stealth: StealthConfig::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// BrowserPool
// ---------------------------------------------------------------------------

pub struct BrowserPool {
    browsers: Vec<Arc<StealthBrowser>>,
    semaphore: Arc<tokio::sync::Semaphore>,
    counter: Arc<AtomicUsize>,
}

pub struct PoolPage {
    pub page: StealthPage,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl std::ops::Deref for PoolPage {
    type Target = StealthPage;
    fn deref(&self) -> &StealthPage {
        &self.page
    }
}

impl BrowserPool {
    /// Launch `config.size` browsers in parallel and build the pool.
    ///
    /// Each browser gets a unique debug port starting from the port found for
    /// the first browser and incrementing by one for each subsequent instance.
    pub async fn new(config: PoolConfig) -> Result<Self, BrowserError> {
        let size = config.size.max(1);

        // Pre-allocate a base port and hand out sequential ports so browsers
        // don't collide with each other.
        let base_port = config
            .launch
            .debug_port
            .unwrap_or_else(LaunchConfig::find_free_port);

        let launch_futures: Vec<_> = (0..size)
            .map(|i| {
                let mut launch = config.launch.clone();
                // Assign a unique port per browser slot.
                launch.debug_port = Some(base_port.saturating_add(i as u16));
                let stealth = config.stealth.clone();
                async move { StealthBrowser::launch_with(launch, stealth).await }
            })
            .collect();

        let browsers_vec = futures::future::try_join_all(launch_futures).await?;
        let browsers: Vec<Arc<StealthBrowser>> =
            browsers_vec.into_iter().map(Arc::new).collect();

        Ok(Self {
            semaphore: Arc::new(tokio::sync::Semaphore::new(size)),
            counter: Arc::new(AtomicUsize::new(0)),
            browsers,
        })
    }

    /// Acquire a page from the pool.
    ///
    /// Blocks until a slot is available (semaphore), then opens a new page on
    /// the next browser in round-robin order and navigates to `url`.
    ///
    /// The returned `PoolPage` holds the semaphore permit — the slot is
    /// released back to the pool when `PoolPage` is dropped.
    pub async fn acquire(&self, url: &str) -> Result<PoolPage, BrowserError> {
        let permit = Arc::clone(&self.semaphore)
            .acquire_owned()
            .await
            .map_err(|e| BrowserError::Other(format!("Semaphore closed: {e}")))?;

        let idx = self.counter.fetch_add(1, Ordering::Relaxed) % self.browsers.len();
        let page = self.browsers[idx].new_page(url).await?;

        Ok(PoolPage {
            page,
            _permit: permit,
        })
    }

    /// Shut down all browsers in the pool.
    ///
    /// Each browser is closed in sequence; errors are logged but do not abort
    /// the shutdown.
    pub async fn shutdown(self) -> Result<(), BrowserError> {
        for browser in self.browsers {
            // Try to unwrap the Arc — only succeeds when we're the sole owner,
            // which is guaranteed because pool holds all refs after shutdown.
            match Arc::try_unwrap(browser) {
                Ok(b) => {
                    if let Err(e) = b.close().await {
                        tracing::warn!("[dig2browser] pool shutdown error: {e}");
                    }
                }
                Err(_arc) => {
                    // A PoolPage is still holding a reference; the browser
                    // will be dropped when that last Arc ref goes away.
                    tracing::warn!("[dig2browser] pool shutdown: browser still referenced, skipping close");
                }
            }
        }
        Ok(())
    }
}
