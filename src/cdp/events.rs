//! Typed CDP event stream.
//!
//! Wraps the raw `broadcast::Receiver<CdpEvent>` and filters + deserializes
//! only the events whose `method` matches a specific CDP domain method.

use std::marker::PhantomData;

use serde::Deserialize;
use tokio::sync::broadcast;

use crate::cdp::session::CdpSession;
use crate::cdp::types::CdpEvent;

// ── Core trait + stream ──────────────────────────────────────────────────────

/// A CDP event type that knows its protocol method string.
pub trait CdpEventType: for<'de> Deserialize<'de> + Send + Clone + 'static {
    const METHOD: &'static str;
}

/// A typed event stream that receives only events matching `T::METHOD`.
pub struct EventStream<T> {
    rx: broadcast::Receiver<CdpEvent>,
    session_filter: Option<String>,
    _phantom: PhantomData<T>,
}

impl<T: CdpEventType> EventStream<T> {
    /// Create a new typed stream with an optional session-id filter.
    pub fn new(rx: broadcast::Receiver<CdpEvent>, session_id: Option<String>) -> Self {
        Self {
            rx,
            session_filter: session_id,
            _phantom: PhantomData,
        }
    }

    /// Wait for the next event that matches `T::METHOD` (and the session filter).
    ///
    /// Returns `None` when the underlying broadcast channel is closed.
    pub async fn next(&mut self) -> Option<T> {
        loop {
            match self.rx.recv().await {
                Ok(event) => {
                    if event.method != T::METHOD {
                        continue;
                    }
                    if let Some(ref sid) = self.session_filter {
                        if event.session_id.as_deref() != Some(sid.as_str()) {
                            continue;
                        }
                    }
                    let params = event.params.unwrap_or(serde_json::Value::Null);
                    match serde_json::from_value::<T>(params) {
                        Ok(typed) => return Some(typed),
                        Err(_) => continue,
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }
}

impl CdpSession {
    /// Create a typed event stream for the given event type `T`.
    pub fn event_stream<T: CdpEventType>(&self) -> EventStream<T> {
        let rx = self.client().subscribe();
        EventStream::new(rx, self.session_id().map(str::to_owned))
    }
}

// ── Page events ──────────────────────────────────────────────────────────────

/// `Page.loadEventFired` — fired when the page load event completes.
#[derive(Debug, Clone, Deserialize)]
pub struct PageLoadEventFired {
    pub timestamp: f64,
}
impl CdpEventType for PageLoadEventFired {
    const METHOD: &'static str = "Page.loadEventFired";
}

/// `Page.frameNavigated` — fired when a frame has navigated to a new URL.
#[derive(Debug, Clone, Deserialize)]
pub struct PageFrameNavigated {
    pub frame: serde_json::Value,
}
impl CdpEventType for PageFrameNavigated {
    const METHOD: &'static str = "Page.frameNavigated";
}

// ── Network events ───────────────────────────────────────────────────────────

/// Minimal representation of a network request from CDP.
#[derive(Debug, Clone, Deserialize)]
pub struct NetworkRequest {
    pub url: String,
    pub method: String,
    pub headers: serde_json::Value,
}

/// `Network.requestWillBeSent` — fired just before a request is sent.
#[derive(Debug, Clone, Deserialize)]
pub struct NetworkRequestWillBeSent {
    #[serde(rename = "requestId")]
    pub request_id: String,
    pub request: NetworkRequest,
    pub timestamp: f64,
    #[serde(rename = "wallTime")]
    pub wall_time: Option<f64>,
    #[serde(rename = "type")]
    pub resource_type: Option<String>,
}
impl CdpEventType for NetworkRequestWillBeSent {
    const METHOD: &'static str = "Network.requestWillBeSent";
}

/// Minimal representation of a network response from CDP.
#[derive(Debug, Clone, Deserialize)]
pub struct NetworkResponse {
    pub url: String,
    pub status: u32,
    pub headers: serde_json::Value,
    #[serde(rename = "mimeType")]
    pub mime_type: String,
}

/// `Network.responseReceived` — fired when a response is received.
#[derive(Debug, Clone, Deserialize)]
pub struct NetworkResponseReceived {
    #[serde(rename = "requestId")]
    pub request_id: String,
    pub response: NetworkResponse,
    #[serde(rename = "type")]
    pub resource_type: Option<String>,
}
impl CdpEventType for NetworkResponseReceived {
    const METHOD: &'static str = "Network.responseReceived";
}

// ── Fetch events ─────────────────────────────────────────────────────────────

/// `Fetch.requestPaused` — fired when a request is intercepted by the Fetch
/// domain.
#[derive(Debug, Clone, Deserialize)]
pub struct FetchRequestPaused {
    #[serde(rename = "requestId")]
    pub request_id: String,
    pub request: NetworkRequest,
    #[serde(rename = "responseStatusCode")]
    pub response_status_code: Option<u32>,
    #[serde(rename = "resourceType")]
    pub resource_type: String,
}
impl CdpEventType for FetchRequestPaused {
    const METHOD: &'static str = "Fetch.requestPaused";
}

// ── Runtime events ───────────────────────────────────────────────────────────

/// `Runtime.consoleAPICalled` — fired when a console method is called.
#[derive(Debug, Clone, Deserialize)]
pub struct RuntimeConsoleApiCalled {
    #[serde(rename = "type")]
    pub call_type: String,
    pub args: Vec<serde_json::Value>,
    pub timestamp: f64,
}
impl CdpEventType for RuntimeConsoleApiCalled {
    const METHOD: &'static str = "Runtime.consoleAPICalled";
}

// ── Log events ───────────────────────────────────────────────────────────────

/// A single log entry from the Log domain.
#[derive(Debug, Clone, Deserialize)]
pub struct LogEntry {
    pub source: String,
    pub level: String,
    pub text: String,
    pub timestamp: f64,
    pub url: Option<String>,
}

/// `Log.entryAdded` — fired when the Log domain emits a new entry.
#[derive(Debug, Clone, Deserialize)]
pub struct LogEntryAdded {
    pub entry: LogEntry,
}
impl CdpEventType for LogEntryAdded {
    const METHOD: &'static str = "Log.entryAdded";
}
