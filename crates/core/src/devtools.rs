//! DevTools event types for agent-facing inspection.
//!
//! These types define the surface for network and console event observation.
//! Actual wiring to CDP/BiDi event streams is a future extension.

/// A DevTools event emitted by the browser.
#[derive(Debug, Clone)]
pub enum DevToolsEvent {
    /// A network request/response event.
    Network(NetworkEvent),
    /// A console message.
    Console(ConsoleEvent),
}

/// A network-level event (request sent, response received, etc.).
#[derive(Debug, Clone)]
pub struct NetworkEvent {
    /// The CDP/BiDi method name, e.g. `"Network.responseReceived"`.
    pub method: String,
    /// The URL involved in this event, if applicable.
    pub url: Option<String>,
    /// HTTP status code, if this event carries a response.
    pub status: Option<u16>,
    /// Full event parameters as JSON.
    pub params: serde_json::Value,
}

/// A console message emitted by the page.
#[derive(Debug, Clone)]
pub struct ConsoleEvent {
    /// Severity level: `"log"`, `"warn"`, `"error"`, `"debug"`, `"info"`.
    pub level: String,
    /// The text content of the console message.
    pub text: String,
}

/// DevTools inspection handle for a page.
///
/// Currently a type-only placeholder. Actual event subscription (via CDP
/// broadcast receiver or BiDi event stream) will be wired in a future iteration.
pub struct PageDevTools {
    _private: (),
}

impl PageDevTools {
    /// Create a new (currently inert) DevTools handle.
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for PageDevTools {
    fn default() -> Self {
        Self::new()
    }
}
