use serde::Deserialize;

/// A BiDi event pushed by the browser without a corresponding command id.
#[derive(Debug, Clone, Deserialize)]
pub struct BiDiEvent {
    /// The fully-qualified event name, e.g. `"network.responseStarted"`.
    pub method: String,
    /// The event payload, structure depends on `method`.
    pub params: serde_json::Value,
}

/// An outbound command message queued for the WebSocket sender task.
#[derive(Debug)]
pub(crate) struct BiDiOutbound {
    pub id: u64,
    pub method: String,
    pub params: serde_json::Value,
}
