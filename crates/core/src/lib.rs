//! dig2browser-core — unified StealthBrowser / StealthPage API.
//!
//! This crate ties together the CDP, WebDriver BiDi, stealth, cookie, and
//! detect crates behind a single ergonomic surface. Most users should import
//! from the top-level `dig2browser` facade crate rather than this one directly.

pub(crate) mod backend;

mod browser;
mod devtools;
mod error;
mod page;
mod pool;
mod wait;

pub use browser::StealthBrowser;
pub use backend::{BoundingBox, ElementHandle, PrintOptions};
pub use devtools::{ConsoleEvent, DevToolsEvent, NetworkEvent, PageDevTools};
pub use error::BrowserError;
pub use page::{Element, StealthPage};
pub use pool::{BrowserPool, PoolConfig, PoolPage};
pub use wait::WaitBuilder;

// Re-export leaf crate types so callers only need to import dig2browser-core.
pub use dig2browser_detect::{BrowserBinary, BrowserKind, BrowserPreference, BrowserProfile, LaunchConfig};
pub use dig2browser_stealth::{LocaleProfile, StealthConfig, StealthLevel};
pub use dig2browser_cookie::{Cookie, CookieError, CookieJar, InterceptConfig};
