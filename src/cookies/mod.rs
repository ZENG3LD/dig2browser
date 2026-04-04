//! Cookie reading and interception for Chrome and Firefox profiles.
//!
//! Handles AES-256-GCM + DPAPI decryption (Chrome) and plaintext reading (Firefox).

pub mod decrypt;
pub mod firefox;
pub mod interceptor;
pub mod sqlite;
pub mod types;

pub use interceptor::{intercept_cookies, open_auth_session, InterceptConfig};
pub use types::{Cookie, CookieJar};

use crate::detect::DetectError;
use thiserror::Error;

/// Errors produced by cookie operations.
#[derive(Debug, Error)]
pub enum CookieError {
    #[error("Browser detection failed: {0}")]
    Detect(#[from] DetectError),

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
