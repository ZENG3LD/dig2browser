use super::FetchError;
use rand::Rng;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Strategy used to select the next proxy from the pool.
#[derive(Debug, Clone, Copy)]
pub enum RotationStrategy {
    /// Proxies are used in sequence, wrapping around when the end is reached.
    RoundRobin,
    /// Each call picks a proxy at random.
    Random,
}

/// Configuration for a proxy pool.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// List of proxy URLs.
    ///
    /// Supported formats: `http://host:port`, `https://host:port`,
    /// `socks5://host:port`, and `http://user:pass@host:port`.
    pub urls: Vec<String>,
    /// How the next proxy is selected on each call to [`ProxyPool::next`].
    pub rotation: RotationStrategy,
}

/// A pool of proxy URLs that can be iterated according to a
/// [`RotationStrategy`].
///
/// The pool is cheaply `Clone`able — all clones share the same round-robin
/// counter.
#[derive(Clone)]
pub struct ProxyPool {
    urls: Arc<Vec<String>>,
    strategy: RotationStrategy,
    /// Monotonically increasing counter used for round-robin selection.
    index: Arc<AtomicUsize>,
}

impl ProxyPool {
    /// Build a `ProxyPool` from a [`ProxyConfig`].
    ///
    /// Returns `None` when the `urls` list is empty so callers can easily
    /// skip proxy setup.
    pub fn from_config(config: ProxyConfig) -> Option<Self> {
        if config.urls.is_empty() {
            return None;
        }
        Some(Self {
            urls: Arc::new(config.urls),
            strategy: config.rotation,
            index: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// Return the next proxy URL according to the rotation strategy.
    ///
    /// Returns `None` only when the pool is empty (which cannot happen when
    /// constructed via [`ProxyPool::from_config`] — it guarantees at least one
    /// URL).
    pub fn next(&self) -> Option<&str> {
        if self.urls.is_empty() {
            return None;
        }

        let idx = match self.strategy {
            RotationStrategy::RoundRobin => {
                let raw = self.index.fetch_add(1, Ordering::Relaxed);
                raw % self.urls.len()
            }
            RotationStrategy::Random => {
                let mut rng = rand::thread_rng();
                rng.gen_range(0..self.urls.len())
            }
        };

        Some(&self.urls[idx])
    }

    /// Apply the next proxy from the pool to a `reqwest::ClientBuilder`.
    ///
    /// When the pool is empty this is a no-op and the builder is returned
    /// unchanged.
    pub fn apply_to_builder(
        &self,
        builder: reqwest::ClientBuilder,
    ) -> Result<reqwest::ClientBuilder, FetchError> {
        match self.next() {
            None => Ok(builder),
            Some(url) => {
                let proxy = reqwest::Proxy::all(url)
                    .map_err(|e| FetchError::Fetch(format!("invalid proxy URL {url}: {e}")))?;
                Ok(builder.proxy(proxy))
            }
        }
    }

    /// Return the number of proxy URLs in the pool.
    pub fn len(&self) -> usize {
        self.urls.len()
    }

    /// Returns `true` when the pool contains no URLs.
    pub fn is_empty(&self) -> bool {
        self.urls.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(urls: &[&str], strategy: RotationStrategy) -> ProxyPool {
        ProxyPool::from_config(ProxyConfig {
            urls: urls.iter().map(|s| s.to_string()).collect(),
            rotation: strategy,
        })
        .unwrap()
    }

    #[test]
    fn empty_config_returns_none() {
        let result = ProxyPool::from_config(ProxyConfig {
            urls: vec![],
            rotation: RotationStrategy::RoundRobin,
        });
        assert!(result.is_none());
    }

    #[test]
    fn round_robin_cycles() {
        let p = pool(
            &["http://a:8080", "http://b:8080", "http://c:8080"],
            RotationStrategy::RoundRobin,
        );
        assert_eq!(p.next(), Some("http://a:8080"));
        assert_eq!(p.next(), Some("http://b:8080"));
        assert_eq!(p.next(), Some("http://c:8080"));
        assert_eq!(p.next(), Some("http://a:8080"));
    }

    #[test]
    fn random_always_returns_valid_url() {
        let p = pool(
            &["http://a:8080", "http://b:8080"],
            RotationStrategy::Random,
        );
        for _ in 0..20 {
            let url = p.next().expect("should return a url");
            assert!(url == "http://a:8080" || url == "http://b:8080");
        }
    }

    #[test]
    fn single_proxy_always_returned() {
        let p = pool(&["http://only:8080"], RotationStrategy::RoundRobin);
        for _ in 0..5 {
            assert_eq!(p.next(), Some("http://only:8080"));
        }
    }

    #[test]
    fn cloned_pool_shares_counter() {
        let p1 = pool(
            &["http://a:8080", "http://b:8080"],
            RotationStrategy::RoundRobin,
        );
        let p2 = p1.clone();
        assert_eq!(p1.next(), Some("http://a:8080"));
        assert_eq!(p2.next(), Some("http://b:8080"));
    }
}
