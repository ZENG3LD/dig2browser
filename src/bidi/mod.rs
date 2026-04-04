//! WebDriver BiDi WebSocket client for dig2browser.
//!
//! # Quick start
//!
//! ```no_run
//! use crate::bidi::BiDiClient;
//!
//! # async fn example() -> Result<(), crate::bidi::BiDiError> {
//! let client = BiDiClient::connect("ws://localhost:4444/session/abc123/bidi").await?;
//! let mut events = client.subscribe();
//!
//! client.subscribe_log(None).await?;
//!
//! while let Ok(event) = events.recv().await {
//!     println!("event: {} — {:?}", event.method, event.params);
//! }
//! # Ok(())
//! # }
//! ```

mod error;
mod events;
mod modules;
mod transport;
mod types;

pub use error::BiDiError;
pub use events::{
    BiDiEventStream, BiDiEventType, BiDiRequest, BiDiResponse, LogEntryAdded, LogSource,
    NetworkBeforeRequestSent, NetworkResponseCompleted,
};
pub use modules::{BrowsingContext, NavigateResult, ScriptTarget};
pub use transport::BiDiClient;
pub use types::BiDiEvent;
