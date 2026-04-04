//! W3C WebDriver REST client for dig2browser.
//!
//! # Quick start
//!
//! ```no_run
//! use crate::webdriver::{WdClient, Capabilities};
//!
//! # async fn example() -> Result<(), crate::webdriver::WdError> {
//! let client = WdClient::new("http://localhost:4444");
//! let session = client.new_session(Capabilities::chrome().headless()).await?;
//! session.goto("https://example.com").await?;
//! let title = session.title().await?;
//! println!("title: {title}");
//! session.close().await?;
//! # Ok(())
//! # }
//! ```

mod actions;
mod alert;
mod client;
mod cookie;
mod element;
mod error;
mod eval;
mod frame;
mod nav;
mod print;
mod screenshot;
mod session;
mod timeout;
mod types;
mod window;

pub use actions::ActionChain;
pub use client::WdClient;
pub use element::ElementRect;
pub use error::WdError;
pub use frame::FrameId;
pub use print::{PrintMargin, PrintOptions, PrintPage};
pub use session::WdSession;
pub use timeout::Timeouts;
pub use types::{Capabilities, WdCookie, WdElement};
