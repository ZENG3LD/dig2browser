//! Browser binary detection and launch argument builder.
//!
//! Zero protocol dependencies — safe to compile on any platform.

pub mod args;
pub mod binary;

pub use args::{BrowserProfile, LaunchConfig};
pub use binary::{BrowserBinary, BrowserKind, BrowserPreference, detect_browser, get_firefox_paths};

use thiserror::Error;

/// Errors produced by the detect crate.
#[derive(Debug, Error)]
pub enum DetectError {
    #[error("Browser binary not found; tried: {tried:?}")]
    BinaryNotFound { tried: Vec<String> },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
