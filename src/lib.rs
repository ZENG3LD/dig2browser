pub mod cdp;
pub mod webdriver;
pub mod bidi;
pub mod stealth;
pub mod cookies;
pub mod detect;
pub mod browser;

// Re-export main types at crate root
pub use browser::*;
