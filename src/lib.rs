pub mod bot_auth;
pub mod cdp;
pub mod webdriver;
pub mod bidi;
pub mod stealth;
pub mod cookies;
pub mod detect;
pub mod browser;
pub mod wasmtest;
pub mod identity;
pub mod agentic;

// Re-export main types at crate root
pub use browser::*;
