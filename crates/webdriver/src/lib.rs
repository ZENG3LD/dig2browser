//! W3C WebDriver REST client for dig2browser.
//!
//! # Quick start
//!
//! ```no_run
//! use dig2browser_webdriver::{WdClient, Capabilities};
//!
//! # async fn example() -> Result<(), dig2browser_webdriver::WdError> {
//! let client = WdClient::new("http://localhost:4444");
//! let session = client.new_session(Capabilities::chrome().headless()).await?;
//! session.goto("https://example.com").await?;
//! let title = session.title().await?;
//! println!("title: {title}");
//! session.close().await?;
//! # Ok(())
//! # }
//! ```

mod client;
mod cookie;
mod element;
mod error;
mod eval;
mod nav;
mod screenshot;
mod session;
mod types;
mod window;

pub use client::WdClient;
pub use error::WdError;
pub use session::WdSession;
pub use types::{Capabilities, WdCookie, WdElement};
