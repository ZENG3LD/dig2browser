use std::marker::PhantomData;

use serde::Deserialize;
use tokio::sync::broadcast;

use crate::{transport::BiDiClient, types::BiDiEvent};

/// Implemented by types that correspond to a specific BiDi event method.
pub trait BiDiEventType: for<'de> Deserialize<'de> + Send + Clone + 'static {
    /// The fully-qualified event method name, e.g. `"network.beforeRequestSent"`.
    const METHOD: &'static str;
}

/// A filtered stream that only yields events matching `T::METHOD`.
pub struct BiDiEventStream<T> {
    rx: broadcast::Receiver<BiDiEvent>,
    _phantom: PhantomData<T>,
}

impl<T: BiDiEventType> BiDiEventStream<T> {
    /// Return the next event of type `T`, skipping unrelated events.
    ///
    /// Returns `None` when the broadcast channel is closed.
    pub async fn next(&mut self) -> Option<T> {
        loop {
            match self.rx.recv().await {
                Ok(event) if event.method == T::METHOD => {
                    match serde_json::from_value::<T>(event.params.clone()) {
                        Ok(typed) => return Some(typed),
                        Err(e) => {
                            tracing::warn!(
                                "BiDiEventStream: failed to deserialize {}: {e}",
                                T::METHOD
                            );
                            continue;
                        }
                    }
                }
                Ok(_) => continue,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }
}

impl BiDiClient {
    /// Subscribe to a specific typed BiDi event stream.
    ///
    /// Only events whose `method` matches `T::METHOD` will be yielded.
    pub fn event_stream<T: BiDiEventType>(&self) -> BiDiEventStream<T> {
        BiDiEventStream {
            rx: self.subscribe(),
            _phantom: PhantomData,
        }
    }
}

// ---------------------------------------------------------------------------
// Concrete event types
// ---------------------------------------------------------------------------

/// Payload carried by `"network.beforeRequestSent"` events.
#[derive(Debug, Clone, Deserialize)]
pub struct NetworkBeforeRequestSent {
    pub request: BiDiRequest,
    pub context: String,
}

impl BiDiEventType for NetworkBeforeRequestSent {
    const METHOD: &'static str = "network.beforeRequestSent";
}

/// Payload carried by `"network.responseCompleted"` events.
#[derive(Debug, Clone, Deserialize)]
pub struct NetworkResponseCompleted {
    pub request: BiDiRequest,
    pub response: BiDiResponse,
    pub context: String,
}

impl BiDiEventType for NetworkResponseCompleted {
    const METHOD: &'static str = "network.responseCompleted";
}

/// Minimal network request descriptor shared by several event types.
#[derive(Debug, Clone, Deserialize)]
pub struct BiDiRequest {
    pub request: String,
    pub url: String,
    pub method: String,
}

/// Minimal network response descriptor.
#[derive(Debug, Clone, Deserialize)]
pub struct BiDiResponse {
    pub url: String,
    pub status: u32,
}

/// Payload carried by `"log.entryAdded"` events.
#[derive(Debug, Clone, Deserialize)]
pub struct LogEntryAdded {
    pub level: String,
    pub text: String,
    pub source: LogSource,
}

impl BiDiEventType for LogEntryAdded {
    const METHOD: &'static str = "log.entryAdded";
}

/// Source information attached to a log entry.
#[derive(Debug, Clone, Deserialize)]
pub struct LogSource {
    #[serde(rename = "type")]
    pub source_type: String,
}
