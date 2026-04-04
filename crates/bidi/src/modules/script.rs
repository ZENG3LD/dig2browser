use std::sync::Arc;

use crate::{error::BiDiError, transport::BiDiClient};

/// Identifies the browsing context that a script should run in.
pub struct ScriptTarget {
    /// The browsing context id (opaque string from the browser).
    pub context: String,
}

impl BiDiClient {
    /// Inject a JavaScript function that executes before any page script on every
    /// navigation. Equivalent to CDP's `Page.addScriptToEvaluateOnNewDocument`.
    ///
    /// Returns the opaque `scriptId` that can be used to remove the script later.
    pub async fn add_preload_script(
        self: &Arc<Self>,
        function_declaration: &str,
        contexts: Option<Vec<String>>,
    ) -> Result<String, BiDiError> {
        let mut params = serde_json::json!({
            "functionDeclaration": function_declaration,
        });

        if let Some(ctxs) = contexts {
            params["contexts"] = serde_json::json!(ctxs);
        }

        let result = self.call("script.addPreloadScript", params).await?;
        let script_id = result
            .get("script")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        Ok(script_id)
    }

    /// Remove a previously registered preload script by its `scriptId`.
    pub async fn remove_preload_script(
        self: &Arc<Self>,
        script_id: &str,
    ) -> Result<(), BiDiError> {
        self.call(
            "script.removePreloadScript",
            serde_json::json!({ "script": script_id }),
        )
        .await?;
        Ok(())
    }

    /// Evaluate a JavaScript expression in the given browsing context.
    pub async fn evaluate(
        self: &Arc<Self>,
        expression: &str,
        target: ScriptTarget,
    ) -> Result<serde_json::Value, BiDiError> {
        let result = self
            .call(
                "script.evaluate",
                serde_json::json!({
                    "expression": expression,
                    "target": { "context": target.context },
                    "awaitPromise": true,
                }),
            )
            .await?;
        Ok(result)
    }

    /// Call a JavaScript function declaration with the given arguments.
    pub async fn call_function(
        self: &Arc<Self>,
        declaration: &str,
        args: Vec<serde_json::Value>,
        target: ScriptTarget,
    ) -> Result<serde_json::Value, BiDiError> {
        let result = self
            .call(
                "script.callFunction",
                serde_json::json!({
                    "functionDeclaration": declaration,
                    "arguments": args,
                    "target": { "context": target.context },
                    "awaitPromise": true,
                }),
            )
            .await?;
        Ok(result)
    }

    /// Evaluate a JavaScript expression in the specified realm.
    pub async fn evaluate_in_realm(
        self: &Arc<Self>,
        expression: &str,
        realm: &str,
    ) -> Result<serde_json::Value, BiDiError> {
        let result = self
            .call(
                "script.evaluate",
                serde_json::json!({
                    "expression": expression,
                    "target": { "realm": realm },
                    "awaitPromise": true,
                }),
            )
            .await?;
        Ok(result)
    }

    /// Release remote object handles, freeing memory on the browser side.
    pub async fn disown(
        self: &Arc<Self>,
        handles: Vec<String>,
        target: ScriptTarget,
    ) -> Result<(), BiDiError> {
        self.call(
            "script.disown",
            serde_json::json!({
                "handles": handles,
                "target": { "context": target.context },
            }),
        )
        .await?;
        Ok(())
    }
}
