use thiserror::Error;

/// Errors returned by the WebDriver client.
#[derive(Debug, Error)]
pub enum WdError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("WebDriver error {error}: {message}")]
    Protocol { error: String, message: String },

    #[error("no session")]
    NoSession,

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("element not found")]
    ElementNotFound,

    #[error("session not created: {0}")]
    SessionNotCreated(String),
}
