use thiserror::Error;

#[derive(Debug, Error)]
pub enum BrowserError {
    #[error("Browser binary not found; tried: {tried:?}")]
    BinaryNotFound { tried: Vec<String> },

    #[error("Failed to launch browser process: {0}")]
    Launch(#[source] std::io::Error),

    #[error("Timed out waiting for DevTools WebSocket URL ({secs}s)")]
    WsUrlTimeout { secs: u64 },

    #[error("Failed to connect chromiumoxide: {0}")]
    Connect(String),

    #[error("CDP operation failed: {0}")]
    Cdp(String),

    #[error("Page navigation failed for '{url}': {detail}")]
    Navigate { url: String, detail: String },

    #[error("JavaScript evaluation error: {0}")]
    JsEval(String),

    #[error("Stealth injection failed: {0}")]
    StealthInject(String),

    #[error("Pool exhausted — all {size} browser slots in use")]
    PoolExhausted { size: usize },

    #[error("Timeout")]
    Timeout,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

#[derive(Debug, Error)]
pub enum CookieError {
    #[error("Browser error: {0}")]
    Browser(#[from] BrowserError),

    #[error("Cookie DB not found at {path}")]
    DbMissing { path: String },

    #[error("SQLite error: {0}")]
    Sqlite(String),

    #[error("Local State file not found at {path}")]
    LocalStateMissing { path: String },

    #[error("Local State JSON malformed: {0}")]
    LocalStateJson(String),

    #[error("DPAPI decryption failed (OS error {code})")]
    DpapiDecrypt { code: u32 },

    #[error("AES-GCM decryption failed")]
    AesGcm,

    #[error("No cookies found for domain '{domain}'")]
    NoCookies { domain: String },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
