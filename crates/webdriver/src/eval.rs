use crate::{error::WdError, session::WdSession};

impl WdSession {
    /// Execute a synchronous JavaScript snippet and return the result.
    pub async fn execute_sync(
        &self,
        script: &str,
        args: Vec<serde_json::Value>,
    ) -> Result<serde_json::Value, WdError> {
        self.post(
            "execute/sync",
            serde_json::json!({ "script": script, "args": args }),
        )
        .await
    }

    /// Execute an asynchronous JavaScript snippet and return the result.
    pub async fn execute_async(
        &self,
        script: &str,
        args: Vec<serde_json::Value>,
    ) -> Result<serde_json::Value, WdError> {
        self.post(
            "execute/async",
            serde_json::json!({ "script": script, "args": args }),
        )
        .await
    }
}
