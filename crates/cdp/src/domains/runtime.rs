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

    /// Evaluate a JavaScript expression and deserialize the result into `T`.
    pub async fn evaluate_typed<T: serde::de::DeserializeOwned>(
        &self,
        expression: &str,
    ) -> Result<T, CdpError> {
        let value = self.evaluate(expression).await?;
        let typed: T = serde_json::from_value(value["value"].clone())?;
        Ok(typed)
    }

    /// Call a JavaScript function on a remote object identified by `object_id`.
    pub async fn call_function_on(
        &self,
        object_id: &str,
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
                    "objectId": object_id,
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

    /// Register a named binding that can be called from JavaScript.
    ///
    /// When the page calls `window.<name>(payload)` the Runtime domain emits
    /// a `Runtime.bindingCalled` event.
    pub async fn add_binding(&self, name: &str) -> Result<(), CdpError> {
        self.call("Runtime.addBinding", Some(json!({ "name": name })))
            .await?;
        Ok(())
    }

    /// Enable the Runtime domain (required for `consoleAPICalled` events).
    pub async fn enable_runtime(&self) -> Result<(), CdpError> {
        self.call("Runtime.enable", None).await?;
        Ok(())
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
