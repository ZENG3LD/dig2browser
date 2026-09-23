use super::FetchedPage;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// A cached HTTP response with an expiry timestamp.
#[derive(Clone, Debug)]
pub struct CachedResponse {
    /// The fetched page stored in the cache.
    pub page: FetchedPage,
    /// Wall-clock time when this entry expires.
    expires_at: Instant,
}

/// Simple in-process response cache backed by a `HashMap`.
///
/// Entries are TTL-evicted lazily on `get()`. There is no background task —
/// stale entries are removed only when they are looked up or when `clear()` is
/// called. When `max_size` entries are already stored, `put()` is a no-op
/// (the cache is full).
pub struct ResponseCache {
    entries: HashMap<String, CachedResponse>,
    ttl: Duration,
    max_size: usize,
}

impl ResponseCache {
    /// Create a new cache with the given TTL and capacity limit.
    pub fn new(ttl: Duration, max_size: usize) -> Self {
        Self {
            entries: HashMap::new(),
            ttl,
            max_size,
        }
    }

    /// Look up a response by URL.
    ///
    /// Returns `Some` only when the entry exists and has not yet expired.
    /// Expired entries are removed from the map before returning `None`.
    pub fn get(&mut self, url: &str) -> Option<CachedResponse> {
        let now = Instant::now();
        match self.entries.get(url) {
            Some(entry) if entry.expires_at > now => Some(entry.clone()),
            Some(_) => {
                self.entries.remove(url);
                None
            }
            None => None,
        }
    }

    /// Store a response.
    ///
    /// If the cache is already at `max_size` capacity the call is silently
    /// ignored. Overwrites any existing entry for the same URL.
    pub fn put(&mut self, url: impl Into<String>, page: FetchedPage) {
        let key = url.into();
        if !self.entries.contains_key(&key) && self.entries.len() >= self.max_size {
            tracing::debug!(max = self.max_size, "response cache full, skipping put");
            return;
        }
        let expires_at = Instant::now() + self.ttl;
        self.entries.insert(key, CachedResponse { page, expires_at });
    }

    /// Remove all entries from the cache.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Return the number of entries currently stored (including stale ones that
    /// have not yet been evicted).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` when the cache contains no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Evict all entries whose TTL has elapsed. Useful for periodic
    /// housekeeping when the cache is large.
    pub fn evict_expired(&mut self) {
        let now = Instant::now();
        self.entries.retain(|_, v| v.expires_at > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig2browser_crawler::profile::FetchMethod;
    use url::Url;

    fn make_page(url: &str) -> FetchedPage {
        FetchedPage {
            url: Url::parse(url).unwrap(),
            status_code: Some(200),
            body: "hello".to_string(),
            fetched_at: chrono::Utc::now(),
            fetch_ms: 10,
            method: FetchMethod::Http,
            screenshot: None,
        }
    }

    #[test]
    fn put_and_get() {
        let mut cache = ResponseCache::new(Duration::from_secs(60), 100);
        let page = make_page("https://example.com/");
        cache.put("https://example.com/", page);
        assert!(cache.get("https://example.com/").is_some());
    }

    #[test]
    fn miss_for_unknown_url() {
        let mut cache = ResponseCache::new(Duration::from_secs(60), 100);
        assert!(cache.get("https://example.com/missing").is_none());
    }

    #[test]
    fn expired_entry_returns_none() {
        let mut cache = ResponseCache::new(Duration::from_millis(1), 100);
        cache.put("https://example.com/", make_page("https://example.com/"));
        std::thread::sleep(Duration::from_millis(5));
        assert!(cache.get("https://example.com/").is_none());
        assert!(cache.is_empty());
    }

    #[test]
    fn clear_removes_all() {
        let mut cache = ResponseCache::new(Duration::from_secs(60), 100);
        cache.put("https://a.com/", make_page("https://a.com/"));
        cache.put("https://b.com/", make_page("https://b.com/"));
        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn max_size_respected() {
        let mut cache = ResponseCache::new(Duration::from_secs(60), 2);
        cache.put("https://a.com/", make_page("https://a.com/"));
        cache.put("https://b.com/", make_page("https://b.com/"));
        cache.put("https://c.com/", make_page("https://c.com/"));
        assert_eq!(cache.len(), 2);
        assert!(cache.get("https://c.com/").is_none());
    }

    #[test]
    fn overwrite_same_key_when_full() {
        let mut cache = ResponseCache::new(Duration::from_secs(60), 2);
        cache.put("https://a.com/", make_page("https://a.com/"));
        cache.put("https://b.com/", make_page("https://b.com/"));
        cache.put("https://a.com/", make_page("https://a.com/"));
        assert_eq!(cache.len(), 2);
        assert!(cache.get("https://a.com/").is_some());
    }

    #[test]
    fn evict_expired_removes_stale() {
        let mut cache = ResponseCache::new(Duration::from_millis(1), 100);
        cache.put("https://a.com/", make_page("https://a.com/"));
        std::thread::sleep(Duration::from_millis(5));
        cache.evict_expired();
        assert!(cache.is_empty());
    }
}
