//! Backend abstraction layer — protocol-agnostic traits for browser and page handles.
//!
//! All trait methods use `BoxFuture` so the traits are object-safe and can be
//! stored as `Arc<dyn PageBackend>`.

pub mod bidi;
pub mod cdp;

use futures::future::BoxFuture;

use crate::browser::devtools::DevToolsEvent;
use crate::browser::error::BrowserError;

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
    ) -> BoxFuture<'a, Result<Vec<crate::cookies::Cookie>, BrowserError>>;

    /// Replace the page's cookie jar with the provided cookies.
    fn set_cookies<'a>(
        &'a self,
        cookies: &'a [crate::cookies::Cookie],
    ) -> BoxFuture<'a, Result<(), BrowserError>>;

    // ── Element interaction ────────────────────────────────────────────────

    /// Find the first element matching `selector`.
    fn find_element<'a>(
        &'a self,
        selector: &'a str,
    ) -> BoxFuture<'a, Result<ElementHandle, BrowserError>>;

    /// Find all elements matching `selector`.
    fn find_elements<'a>(
        &'a self,
        selector: &'a str,
    ) -> BoxFuture<'a, Result<Vec<ElementHandle>, BrowserError>>;

    /// Click an element at its center.
    fn click_element<'a>(
        &'a self,
        element: &'a ElementHandle,
    ) -> BoxFuture<'a, Result<(), BrowserError>>;

    /// Type `text` into an element (focus first).
    fn type_into_element<'a>(
        &'a self,
        element: &'a ElementHandle,
        text: &'a str,
    ) -> BoxFuture<'a, Result<(), BrowserError>>;

    /// Get the visible text content of an element.
    fn element_text<'a>(
        &'a self,
        element: &'a ElementHandle,
    ) -> BoxFuture<'a, Result<String, BrowserError>>;

    /// Get the value of a named attribute, or `None` if the attribute is absent.
    fn element_attribute<'a>(
        &'a self,
        element: &'a ElementHandle,
        name: &'a str,
    ) -> BoxFuture<'a, Result<Option<String>, BrowserError>>;

    /// Get the outer HTML of an element.
    fn element_html<'a>(
        &'a self,
        element: &'a ElementHandle,
    ) -> BoxFuture<'a, Result<String, BrowserError>>;

    /// Get the bounding box (position + size) of an element.
    fn element_bounding_box<'a>(
        &'a self,
        element: &'a ElementHandle,
    ) -> BoxFuture<'a, Result<BoundingBox, BrowserError>>;

    // ── PDF ───────────────────────────────────────────────────────────────

    /// Print the page as a PDF and return the raw bytes.
    fn print_pdf<'a>(
        &'a self,
        options: &'a PrintOptions,
    ) -> BoxFuture<'a, Result<Vec<u8>, BrowserError>>;

    // ── Enhanced screenshots ───────────────────────────────────────────────

    /// Capture a screenshot of the full page (not just the viewport).
    fn screenshot_full_page<'a>(&'a self) -> BoxFuture<'a, Result<Vec<u8>, BrowserError>>;

    /// Capture a screenshot cropped to a specific element.
    fn screenshot_element<'a>(
        &'a self,
        element: &'a ElementHandle,
    ) -> BoxFuture<'a, Result<Vec<u8>, BrowserError>>;

    /// Set extra HTTP headers sent with every request issued by this page.
    ///
    /// Merges with any previously set headers. Pass an empty map to clear.
    fn set_extra_http_headers<'a>(
        &'a self,
        headers: std::collections::HashMap<String, String>,
    ) -> BoxFuture<'a, Result<(), BrowserError>>;

    /// Disable Content Security Policy enforcement so that injected scripts
    /// work on CSP-locked pages.
    ///
    /// On the CDP backend calls `Page.setBypassCSP`. On the BiDi backend
    /// this is a no-op (returns `Ok(())`).
    fn set_bypass_csp<'a>(&'a self, enabled: bool) -> BoxFuture<'a, Result<(), BrowserError>>;

    /// Register a script to run on every new document before any page JS runs.
    ///
    /// On the CDP backend calls `Page.addScriptToEvaluateOnNewDocument` and
    /// returns the `identifier` string from the response.
    /// On the BiDi backend this is a no-op (returns an empty string).
    fn add_script_to_evaluate_on_new_document<'a>(
        &'a self,
        source: &'a str,
    ) -> BoxFuture<'a, Result<String, BrowserError>>;

    // ── DevTools events ───────────────────────────────────────────────────

    /// Subscribe to DevTools events for this page.
    fn subscribe_events<'a>(
        &'a self,
    ) -> BoxFuture<'a, Result<tokio::sync::broadcast::Receiver<DevToolsEvent>, BrowserError>>;
}

// ── Shared types ────────────────────────────────────────────────────────────

/// Opaque handle to a DOM element.
///
/// The internals are backend-specific: CDP stores a node_id + optional
/// remote objectId; WebDriver stores an element UUID.
#[derive(Debug, Clone)]
pub struct ElementHandle {
    pub(crate) inner: ElementInner,
}

#[derive(Debug, Clone)]
pub(crate) enum ElementInner {
    Cdp {
        node_id: i64,
    },
    WebDriver {
        element_id: String,
    },
}

/// Bounding box of a DOM element in page-space pixels.
#[derive(Debug, Clone)]
pub struct BoundingBox {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

/// Options for PDF printing via [`PageBackend::print_pdf`].
#[derive(Debug, Clone, Default)]
pub struct PrintOptions {
    pub landscape: bool,
    pub print_background: bool,
    pub scale: Option<f64>,
    pub paper_width: Option<f64>,
    pub paper_height: Option<f64>,
}
