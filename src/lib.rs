pub mod bot_auth;
pub mod cdp;
pub mod webdriver;
pub mod bidi;
pub mod stealth;
pub mod cookies;
pub mod detect;
pub mod browser;
pub mod browser_stream;
pub mod wasmtest;
pub mod identity;
pub mod agentic;
pub mod worker_ipc;
pub mod digest;
pub mod process_isolation;
#[cfg(feature = "crawler")]
pub mod crawl;
#[cfg(windows)]
mod windows_runtime_mirror;
mod browser_process;
mod process_tree;
#[cfg(all(test, windows))]
pub(crate) mod test_support;

// Re-export main types at crate root
pub use browser::*;
pub use detect::args::BrowserProxy;
pub use process_isolation::BrowserProcessIsolation;
#[cfg(windows)]
pub use windows_runtime_mirror::{
    WindowsBrowserRuntimeMirror, WindowsRuntimeMirrorError, WindowsRuntimeMirrorRemovalReport,
    WindowsRuntimeMirrorScope, WindowsRuntimeMirrorScopeParseError,
};
