pub mod error;
pub mod browser_detect;
pub mod browser_args;
pub mod stealth;
pub mod browser;
pub mod page;
pub mod pool;
pub mod cookie;

pub use browser::StealthBrowser;
pub use browser_args::{LaunchConfig, BrowserProfile};
pub use browser_detect::{BrowserPreference, BrowserKind};
pub use error::{BrowserError, CookieError};
pub use page::StealthPage;
pub use pool::{BrowserPool, PoolConfig, PoolPage};
pub use stealth::{StealthConfig, StealthLevel, LocaleProfile};
