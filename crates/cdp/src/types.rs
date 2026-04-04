//! CDP wire types — outbound commands and inbound events.

use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

use crate::error::CdpError;

/// An outbound CDP command sent over the WebSocket.
///
/// The `response_tx` channel is excluded from serialization; it is stored in
/// the pending-requests map while the frame is in-flight.
pub struct CdpOutbound {
    pub id: u64,
    pub method: String,
    pub params: Option<serde_json::Value>,
    pub session_id: Option<String>,
    /// Oneshot sender that resolves when the browser replies.
    pub response_tx: oneshot::Sender<Result<serde_json::Value, CdpError>>,
}

/// Serializable wire frame for an outbound CDP command.
#[derive(Serialize)]
pub(crate) struct CdpOutboundFrame<'a> {
    pub id: u64,
    pub method: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<&'a serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<&'a str>,
}

impl<'a> From<&'a CdpOutbound> for CdpOutboundFrame<'a> {
    fn from(cmd: &'a CdpOutbound) -> Self {
        Self {
            id: cmd.id,
            method: &cmd.method,
            params: cmd.params.as_ref(),
            session_id: cmd.session_id.as_deref(),
        }
    }
}

/// An inbound CDP event (message without an `id` field).
#[derive(Debug, Clone, Deserialize)]
pub struct CdpEvent {
    pub method: String,
    pub params: Option<serde_json::Value>,
    #[serde(rename = "sessionId")]
    pub session_id: Option<String>,
}

/// A raw inbound CDP message. May be a response (has `id`) or an event.
#[derive(Debug, Deserialize)]
pub(crate) struct CdpInbound {
    pub id: Option<u64>,
    pub method: Option<String>,
    pub params: Option<serde_json::Value>,
    pub result: Option<serde_json::Value>,
    pub error: Option<CdpErrorPayload>,
    #[serde(rename = "sessionId")]
    pub session_id: Option<String>,
}

/// The `error` object returned by the browser on CDP command failure.
#[derive(Debug, Deserialize)]
pub(crate) struct CdpErrorPayload {
    pub code: i64,
    pub message: String,
}
