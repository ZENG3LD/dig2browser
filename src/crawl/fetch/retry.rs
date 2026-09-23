use super::FetchError;
use std::future::Future;
use std::time::Duration;
use tokio::time::sleep;

/// Configuration for exponential-backoff retry logic.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts (not counting the initial attempt).
    pub max_retries: u32,
    /// Delay before the first retry, in milliseconds.
    pub initial_delay_ms: u64,
    /// Upper bound on retry delay, in milliseconds.
    pub max_delay_ms: u64,
    /// Multiplicative factor applied to the delay after each attempt.
    pub backoff_factor: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay_ms: 500,
            max_delay_ms: 30_000,
            backoff_factor: 2.0,
        }
    }
}

/// HTTP status codes that warrant a retry.
pub fn is_retryable_status(status: u16) -> bool {
    matches!(status, 429 | 500 | 502 | 503 | 504)
}

/// HTTP status codes that should never be retried.
pub fn is_non_retryable_status(status: u16) -> bool {
    matches!(status, 400 | 401 | 403 | 404)
}

/// Returns `true` when the `reqwest` error is a network-level failure that may
/// succeed on a subsequent attempt (timeout, connection reset, etc.).
pub fn is_retryable_reqwest_error(err: &reqwest::Error) -> bool {
    err.is_timeout() || err.is_connect()
}

/// Compute the delay for the given attempt index using exponential backoff.
///
/// `attempt` is zero-based: 0 -> `initial_delay_ms`, 1 -> `initial * factor`, …
/// The result is clamped to `max_delay_ms`.
fn backoff_delay(attempt: u32, config: &RetryConfig) -> Duration {
    let ms = (config.initial_delay_ms as f64 * config.backoff_factor.powi(attempt as i32)) as u64;
    Duration::from_millis(ms.min(config.max_delay_ms))
}

/// Run an async closure, retrying on retryable [`FetchError`] variants with
/// exponential backoff.
///
/// The closure receives the current attempt index (0-based) so callers can log
/// progress if needed. On permanent failure the last error is returned.
pub async fn retry_with_backoff<F, Fut, T>(config: &RetryConfig, mut f: F) -> Result<T, FetchError>
where
    F: FnMut(u32) -> Fut,
    Fut: Future<Output = Result<T, FetchError>>,
{
    let mut attempt = 0u32;

    loop {
        match f(attempt).await {
            Ok(value) => return Ok(value),
            Err(err) => {
                let should_retry = match &err {
                    FetchError::Fetch(msg) => {
                        let retryable_status = [429u16, 500, 502, 503, 504]
                            .iter()
                            .any(|s| msg.contains(&s.to_string()));
                        let non_retryable_status = [400u16, 401, 403, 404]
                            .iter()
                            .any(|s| msg.contains(&s.to_string()));
                        retryable_status || (!non_retryable_status && !msg.contains("status "))
                    }
                };

                if should_retry && attempt < config.max_retries {
                    let delay = backoff_delay(attempt, config);
                    tracing::warn!(
                        attempt = attempt + 1,
                        max = config.max_retries,
                        delay_ms = delay.as_millis(),
                        error = %err,
                        "fetch failed, retrying"
                    );
                    sleep(delay).await;
                    attempt += 1;
                } else {
                    return Err(err);
                }
            }
        }
    }
}

/// Convenience wrapper: retry an async closure that returns a `reqwest::Response`.
///
/// This variant inspects the response status directly, making it simpler to use
/// from `HttpFetcher` where you have access to the raw response before reading
/// the body.
pub async fn retry_reqwest<F, Fut>(config: &RetryConfig, mut f: F) -> Result<reqwest::Response, FetchError>
where
    F: FnMut(u32) -> Fut,
    Fut: Future<Output = Result<reqwest::Response, reqwest::Error>>,
{
    let mut attempt = 0u32;

    loop {
        match f(attempt).await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                if is_retryable_status(status) && attempt < config.max_retries {
                    let delay = backoff_delay(attempt, config);
                    tracing::warn!(
                        status,
                        attempt = attempt + 1,
                        max = config.max_retries,
                        delay_ms = delay.as_millis(),
                        "retryable HTTP status, retrying"
                    );
                    sleep(delay).await;
                    attempt += 1;
                    continue;
                }
                return Ok(resp);
            }
            Err(err) => {
                if is_retryable_reqwest_error(&err) && attempt < config.max_retries {
                    let delay = backoff_delay(attempt, config);
                    tracing::warn!(
                        attempt = attempt + 1,
                        max = config.max_retries,
                        delay_ms = delay.as_millis(),
                        error = %err,
                        "network error, retrying"
                    );
                    sleep(delay).await;
                    attempt += 1;
                } else {
                    return Err(FetchError::Fetch(err.to_string()));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retryable_statuses() {
        for s in [429, 500, 502, 503, 504] {
            assert!(is_retryable_status(s), "expected {s} to be retryable");
        }
    }

    #[test]
    fn non_retryable_statuses() {
        for s in [400, 401, 403, 404] {
            assert!(is_non_retryable_status(s), "expected {s} to be non-retryable");
            assert!(!is_retryable_status(s), "expected {s} NOT to be retryable");
        }
    }

    #[test]
    fn backoff_clamped_at_max() {
        let config = RetryConfig {
            max_retries: 5,
            initial_delay_ms: 100,
            max_delay_ms: 1_000,
            backoff_factor: 2.0,
        };
        let delay = backoff_delay(10, &config);
        assert_eq!(delay, Duration::from_millis(1_000));
    }

    #[test]
    fn backoff_grows_exponentially() {
        let config = RetryConfig {
            max_retries: 5,
            initial_delay_ms: 100,
            max_delay_ms: 100_000,
            backoff_factor: 2.0,
        };
        assert_eq!(backoff_delay(0, &config), Duration::from_millis(100));
        assert_eq!(backoff_delay(1, &config), Duration::from_millis(200));
        assert_eq!(backoff_delay(2, &config), Duration::from_millis(400));
    }

    #[tokio::test]
    async fn retry_succeeds_on_second_attempt() {
        let config = RetryConfig {
            max_retries: 3,
            initial_delay_ms: 1,
            max_delay_ms: 10,
            backoff_factor: 2.0,
        };

        let counter = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let counter2 = counter.clone();

        let result = retry_with_backoff(&config, move |_| {
            let c = counter2.clone();
            async move {
                let n = c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if n == 0 {
                    Err(FetchError::Fetch("connection reset".to_string()))
                } else {
                    Ok(42u32)
                }
            }
        })
        .await;

        assert_eq!(result.unwrap(), 42);
        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 2);
    }
}
