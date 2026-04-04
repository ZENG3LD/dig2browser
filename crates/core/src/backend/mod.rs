//! Backend abstraction layer — protocol-agnostic traits for browser and page handles.
//!
//! All trait methods use `BoxFuture` so the traits are object-safe and can be
//! stored as `Box<dyn BrowserBackend>` / `Box<dyn PageBackend>`.

pub mod bidi;
pub mod cdp;

use futures::future::BoxFuture;

use crate::error::BrowserError;

/// A running browser instance capable of creating new pages.
pub trait BrowserBackend: Send + Sync {
    /// Open a new page/tab, navigate to `url`, and return a page handle.
    fn new_page<'a>(&'a self, url: &'a str) -> BoxFuture<'a, Result<Box<dyn PageBackend>, BrowserError>>;

    /// Open a blank page (about:blank) without navigating.
    fn new_blank_page<'a>(&'a self) -> BoxFuture<'a, Result<Box<dyn PageBackend>, BrowserError>>;

    /// Close the browser and release all associated resources.
    fn close<'a>(self: Box<Self>) -> BoxFuture<'a, Result<(), BrowserError>>;

    /// Number of pages opened since the last restart.
    fn page_count(&self) -> u32;

    /// Whether the browser should be restarted (page count exceeded threshold).
    fn needs_restart(&self) -> bool;
}

/// A single browser page (tab) that can be navigated and queried.
pub trait PageBackend: Send + Sync {
    /// Navigate to `url`.
    fn goto<'a>(&'a self, url: &'a str) -> BoxFuture<'a, Result<(), BrowserError>>;

    /// Return the full outer HTML of the current document.
    fn html<'a>(&'a self) -> BoxFuture<'a, Result<String, BrowserError>>;

    /// Evaluate a JavaScript expression and return its result as JSON.
    fn eval<'a>(&'a self, js: &'a str) -> BoxFuture<'a, Result<serde_json::Value, BrowserError>>;

    /// Capture a PNG screenshot and return the raw bytes.
    fn screenshot<'a>(&'a self) -> BoxFuture<'a, Result<Vec<u8>, BrowserError>>;

    /// Return all cookies visible to the current page.
    fn get_cookies<'a>(
        &'a self,
    ) -> BoxFuture<'a, Result<Vec<dig2browser_cookie::Cookie>, BrowserError>>;

    /// Replace the page's cookie jar with the provided cookies.
    fn set_cookies<'a>(
        &'a self,
        cookies: &'a [dig2browser_cookie::Cookie],
    ) -> BoxFuture<'a, Result<(), BrowserError>>;
}
