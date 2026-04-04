//! CDP WebSocket client for dig2browser.
//!
//! # Quick start
//!
//! ```no_run
//! # async fn run() -> Result<(), dig2browser_cdp::CdpError> {
//! use std::sync::Arc;
//! use dig2browser_cdp::CdpClient;
//!
//! let client: Arc<CdpClient> = CdpClient::connect("ws://localhost:9222/json/version").await?;
//! let root = client.root_session();
//!
//! let targets = root.get_targets().await?;
//! println!("{targets:?}");
//! # Ok(())
//! # }
//! ```

mod error;
mod session;
mod transport;
mod types;

pub mod domains;

pub use domains::{CdpCookie, RequestPattern, TargetInfo};
pub use error::CdpError;
pub use session::CdpSession;
pub use transport::CdpClient;
pub use types::CdpEvent;
