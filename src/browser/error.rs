//! Unified browser error type for dig2browser-core.

use thiserror::Error;

/// Top-level error type for all browser operations.
#[derive(Debug, Error)]
pub enum BrowserError {
    #[error("binary not found: {0}")]
    BinaryNotFound(String),

    #[error("launch failed: {0}")]
    Launch(String),

    #[error("connection: {0}")]
    Connect(String),

    #[error("CDP: {0}")]
    Cdp(#[from] crate::cdp::CdpError),

    #[error("WebDriver: {0}")]
    WebDriver(#[from] crate::webdriver::WdError),

    #[error("BiDi: {0}")]
    BiDi(#[from] crate::bidi::BiDiError),

    #[error("navigate: {0}")]
    Navigate(String),

    #[error("JS eval: {0}")]
    JsEval(String),

    #[error("stealth inject: {0}")]
    StealthInject(String),

    #[error("pool exhausted (waited {0:?})")]
    PoolExhausted(std::time::Duration),

    #[error("timeout after {0:?}")]
    Timeout(std::time::Duration),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

impl From<crate::detect::DetectError> for BrowserError {
    fn from(e: crate::detect::DetectError) -> Self {
        BrowserError::BinaryNotFound(e.to_string())
    }
}
