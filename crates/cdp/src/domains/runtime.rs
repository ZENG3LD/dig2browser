//! CDP Runtime domain helpers.

use serde_json::json;

use crate::error::CdpError;
use crate::session::CdpSession;

impl CdpSession {
    /// Evaluate a JavaScript expression and return the result value.
    pub async fn evaluate(&self, expression: &str) -> Result<serde_json::Value, CdpError> {
        let result = self
            .call(
                "Runtime.evaluate",
                Some(json!({
                    "expression": expression,
                    "returnByValue": true,
                    "awaitPromise": true,
                })),
            )
            .await?;

        if let Some(exception) = result.get("exceptionDetails") {
            let msg = exception["exception"]["description"]
                .as_str()
                .unwrap_or("unknown JS exception")
                .to_owned();
            return Err(CdpError::Protocol {
                code: -32000,
                message: msg,
            });
        }

        Ok(result["result"].clone())
    }

    /// Call a JavaScript function declaration with the provided arguments.
    pub async fn call_function(
        &self,
        declaration: &str,
        args: Vec<serde_json::Value>,
    ) -> Result<serde_json::Value, CdpError> {
        let call_args: Vec<serde_json::Value> = args
            .into_iter()
            .map(|v| json!({ "value": v }))
            .collect();

        let result = self
            .call(
                "Runtime.callFunctionOn",
                Some(json!({
                    "functionDeclaration": declaration,
                    "arguments": call_args,
                    "returnByValue": true,
                    "awaitPromise": true,
                })),
            )
            .await?;

        if let Some(exception) = result.get("exceptionDetails") {
            let msg = exception["exception"]["description"]
                .as_str()
                .unwrap_or("unknown JS exception")
                .to_owned();
            return Err(CdpError::Protocol {
                code: -32000,
                message: msg,
            });
        }

        Ok(result["result"].clone())
    }
}
