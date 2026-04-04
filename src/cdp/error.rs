//! CDP error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CdpError {
    #[error("WebSocket error: {0}")]
    WebSocket(String),
    #[error("protocol error {code}: {message}")]
    Protocol { code: i64, message: String },
    #[error("response timeout")]
    Timeout,
    #[error("connection closed")]
    ConnectionClosed,
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}
