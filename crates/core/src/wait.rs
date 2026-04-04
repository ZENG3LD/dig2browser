//! WaitBuilder — fluent polling API for page conditions.

use std::time::{Duration, Instant};

use crate::error::BrowserError;
use crate::page::{Element, StealthPage};

/// A builder for waiting on page conditions before proceeding.
///
/// Obtained via [`StealthPage::wait`]. Configure the timeout and polling
/// interval, then call one of the terminal `for_*` methods.
///
/// # Example
/// ```no_run
/// # async fn run(page: &dig2browser_core::StealthPage) -> Result<(), dig2browser_core::BrowserError> {
/// use std::time::Duration;
/// let el = page.wait()
///     .at_most(Duration::from_secs(10))
///     .for_element("button#submit")
///     .await?;
/// el.click().await?;
/// # Ok(())
/// # }
/// ```
pub struct WaitBuilder<'a> {
    pub(crate) page: &'a StealthPage,
    pub(crate) timeout: Duration,
    pub(crate) interval: Duration,
}

impl<'a> WaitBuilder<'a> {
    pub(crate) fn new(page: &'a StealthPage) -> Self {
        Self {
            page,
            timeout: Duration::from_secs(30),
            interval: Duration::from_millis(500),
        }
    }

    /// Set the maximum time to wait.
    pub fn at_most(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the polling interval.
    pub fn every(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// Wait until an element matching `selector` exists in the DOM.
    ///
    /// Returns the element handle once found, or `BrowserError::Timeout` if
    /// the deadline elapses.
    pub async fn for_element(self, selector: &str) -> Result<Element, BrowserError> {
        let deadline = Instant::now() + self.timeout;

        loop {
            if let Ok(el) = self.page.find(selector).await { return Ok(el) }

            if Instant::now() >= deadline {
                return Err(BrowserError::Timeout(self.timeout));
            }

            tokio::time::sleep(self.interval).await;
        }
    }

    /// Wait until the current page URL contains `url_part`.
    ///
    /// Returns `()` when the condition is met, or `BrowserError::Timeout`.
    pub async fn for_url(self, url_part: &str) -> Result<(), BrowserError> {
        let deadline = Instant::now() + self.timeout;
        let js = format!("window.location.href.includes({url_part:?})");

        loop {
            match self.page.eval(&js).await {
                Ok(v) if v.as_bool() == Some(true) => return Ok(()),
                _ => {}
            }

            if Instant::now() >= deadline {
                return Err(BrowserError::Timeout(self.timeout));
            }

            tokio::time::sleep(self.interval).await;
        }
    }

    /// Wait until a JavaScript expression returns a truthy value.
    ///
    /// Returns `()` when truthy, or `BrowserError::Timeout`.
    pub async fn for_condition(self, js: &str) -> Result<(), BrowserError> {
        let deadline = Instant::now() + self.timeout;

        loop {
            match self.page.eval(js).await {
                Ok(v) if is_truthy(&v) => return Ok(()),
                _ => {}
            }

            if Instant::now() >= deadline {
                return Err(BrowserError::Timeout(self.timeout));
            }

            tokio::time::sleep(self.interval).await;
        }
    }

    /// Wait until `document.readyState === "complete"`.
    ///
    /// Returns `()` when navigation is complete, or `BrowserError::Timeout`.
    pub async fn for_navigation(self) -> Result<(), BrowserError> {
        self.for_condition("document.readyState === 'complete'").await
    }
}

/// Return whether a JSON value should be considered truthy.
fn is_truthy(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::Null => false,
        serde_json::Value::Bool(b) => *b,
        serde_json::Value::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(false),
        serde_json::Value::String(s) => !s.is_empty(),
        serde_json::Value::Array(a) => !a.is_empty(),
        serde_json::Value::Object(o) => !o.is_empty(),
    }
}
