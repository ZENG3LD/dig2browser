//! DevTools event types and the PageDevTools inspection handle.
//!
//! Callers use [`PageDevTools`] — obtained via [`StealthPage::devtools`] — to
//! receive a stream of CDP/BiDi events translated into the unified
//! [`DevToolsEvent`] type.

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
/// Obtained via [`StealthPage::devtools`]. Wraps a broadcast receiver that
/// delivers CDP/BiDi events translated into [`DevToolsEvent`] values.
pub struct PageDevTools {
    events_rx: tokio::sync::broadcast::Receiver<DevToolsEvent>,
}

impl PageDevTools {
    /// Create a new DevTools handle backed by the given broadcast receiver.
    pub(crate) fn new(rx: tokio::sync::broadcast::Receiver<DevToolsEvent>) -> Self {
        Self { events_rx: rx }
    }

    /// Wait for the next event.
    ///
    /// Returns `None` if the event channel has been closed (browser gone).
    pub async fn next_event(&mut self) -> Option<DevToolsEvent> {
        loop {
            match self.events_rx.recv().await {
                Ok(event) => return Some(event),
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    // We fell behind — skip missed events and continue.
                    continue;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
            }
        }
    }

    /// Try to get an event without blocking.
    ///
    /// Returns `None` if no event is currently available or the channel is
    /// closed.
    pub fn try_next(&mut self) -> Option<DevToolsEvent> {
        match self.events_rx.try_recv() {
            Ok(event) => Some(event),
            Err(_) => None,
        }
    }
}
