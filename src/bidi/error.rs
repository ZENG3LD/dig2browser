use thiserror::Error;

/// Errors returned by the WebDriver BiDi client.
#[derive(Debug, Error)]
pub enum BiDiError {
    #[error("WebSocket error: {0}")]
    WebSocket(String),

    #[error("protocol error: {error}: {message}")]
    Protocol { error: String, message: String },

    #[error("timeout")]
    Timeout,

    #[error("connection closed")]
    ConnectionClosed,

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}
