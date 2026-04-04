//! BrowserPool — a fixed-size pool of StealthBrowser instances.
//!
//! Callers `acquire()` a page from the pool; the RAII guard returns the
//! semaphore permit on drop so the next waiter can proceed.

use std::ops::Deref;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;

use dig2browser_detect::LaunchConfig;
use dig2browser_stealth::StealthConfig;
use tracing::warn;

use crate::browser::StealthBrowser;
use crate::error::BrowserError;
use crate::page::StealthPage;

/// Configuration for the browser pool.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Number of browser processes to launch.
    pub size: usize,
    /// How long to wait for a slot before returning `PoolExhausted`.
    pub acquire_timeout: Duration,
    /// Launch configuration applied to every browser in the pool.
    pub launch: LaunchConfig,
    /// Stealth configuration applied to every browser in the pool.
    pub stealth: StealthConfig,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            size: 3,
            acquire_timeout: Duration::from_secs(30),
            launch: LaunchConfig::default(),
            stealth: StealthConfig::default(),
        }
    }
}

/// A fixed-size pool of browser instances.
///
/// `acquire()` blocks until a slot is free (up to `PoolConfig::acquire_timeout`),
/// then opens a new page on a browser selected by round-robin.
pub struct BrowserPool {
    browsers: Vec<Arc<StealthBrowser>>,
    semaphore: Arc<tokio::sync::Semaphore>,
    counter: Arc<AtomicUsize>,
    acquire_timeout: Duration,
}

impl BrowserPool {
    /// Launch `config.size` browser instances and build the pool.
    pub async fn new(config: PoolConfig) -> Result<Self, BrowserError> {
        let size = config.size.max(1);
        let mut browsers = Vec::with_capacity(size);

        // Launch browsers in parallel.
        let mut handles = Vec::with_capacity(size);
        for i in 0..size {
            let mut launch = config.launch.clone();
            let stealth = config.stealth.clone();

            // Assign a unique debug port to each browser so they don't conflict.
            if launch.debug_port.is_none() {
                // Find a free port, offset by index just in case two calls race.
                let base = LaunchConfig::find_free_port();
                launch.debug_port = Some(base.saturating_add(i as u16));
            }

            handles.push(tokio::spawn(async move {
                StealthBrowser::launch_with(launch, stealth).await
            }));
        }

        for handle in handles {
            let browser = handle
                .await
                .map_err(|e| BrowserError::Launch(e.to_string()))??;
            browsers.push(Arc::new(browser));
        }

        Ok(Self {
            semaphore: Arc::new(tokio::sync::Semaphore::new(size)),
            browsers,
            counter: Arc::new(AtomicUsize::new(0)),
            acquire_timeout: config.acquire_timeout,
        })
    }

    /// Acquire a page from the pool, waiting up to `acquire_timeout`.
    ///
    /// Returns a [`PoolPage`] RAII guard that releases the semaphore slot on drop.
    pub async fn acquire(&self) -> Result<PoolPage, BrowserError> {
        let permit = tokio::time::timeout(
            self.acquire_timeout,
            Arc::clone(&self.semaphore).acquire_owned(),
        )
        .await
        .map_err(|_| BrowserError::PoolExhausted(self.acquire_timeout))?
        .map_err(|_| BrowserError::Other("semaphore closed".into()))?;

        // Round-robin selection.
        let idx = self.counter.fetch_add(1, Ordering::Relaxed) % self.browsers.len();
        let browser = Arc::clone(&self.browsers[idx]);

        let page = browser
            .new_blank_page()
            .await?;

        Ok(PoolPage {
            page,
            _permit: permit,
        })
    }

    /// Close all browsers in the pool.
    ///
    /// Logs a warning for any browser that is still referenced elsewhere.
    pub async fn shutdown(self) -> Result<(), BrowserError> {
        for browser_arc in self.browsers {
            match Arc::try_unwrap(browser_arc) {
                Ok(browser) => {
                    let _ = browser.close().await;
                }
                Err(_) => {
                    warn!("BrowserPool::shutdown — browser still referenced, skipping");
                }
            }
        }
        Ok(())
    }
}

/// RAII guard that holds a semaphore permit for the duration of a pool interaction.
///
/// The inner [`StealthPage`] is accessible via `Deref` or `.page()`.
pub struct PoolPage {
    page: StealthPage,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl PoolPage {
    /// Borrow the inner page.
    pub fn page(&self) -> &StealthPage {
        &self.page
    }
}

impl Deref for PoolPage {
    type Target = StealthPage;

    fn deref(&self) -> &Self::Target {
        &self.page
    }
}
