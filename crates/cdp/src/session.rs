//! CDP session handle — wraps `CdpClient` with an optional session identifier
//! (used for targets attached via `Target.attachToTarget`).

use std::sync::Arc;

use crate::error::CdpError;
use crate::transport::CdpClient;

/// A handle to a CDP session.
///
/// - Root session (`session_id == None`): commands target the browser itself.
/// - Attached session (`session_id == Some(id)`): commands are routed to a
///   specific page / worker target.
#[derive(Clone)]
pub struct CdpSession {
    session_id: Option<String>,
    client: Arc<CdpClient>,
}

impl CdpSession {
    pub(crate) fn new(session_id: Option<String>, client: Arc<CdpClient>) -> Self {
        Self { session_id, client }
    }

    /// Create a session handle for a specific `sessionId` returned by
    /// `Target.attachToTarget`.
    pub fn with_session_id(session_id: String, client: Arc<CdpClient>) -> Self {
        Self {
            session_id: Some(session_id),
            client,
        }
    }

    /// The session identifier, if this is not the root session.
    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    /// Send a CDP command and return the `result` object.
    pub async fn call(
        &self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, CdpError> {
        self.client
            .send(method, params, self.session_id.clone())
            .await
    }

    /// Expose the underlying client so domain helpers can subscribe to events.
    pub fn client(&self) -> &Arc<CdpClient> {
        &self.client
    }
}
