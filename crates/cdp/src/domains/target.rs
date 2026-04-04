//! CDP Target domain helpers.

use serde::Deserialize;
use serde_json::json;

use crate::error::CdpError;
use crate::session::CdpSession;

/// Minimal target info returned by `Target.getTargets`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetInfo {
    pub target_id: String,
    pub r#type: String,
    pub title: String,
    pub url: String,
    pub attached: bool,
}

impl CdpSession {
    /// Open a new page target and return its `targetId`.
    pub async fn create_target(&self, url: &str) -> Result<String, CdpError> {
        let result = self
            .call("Target.createTarget", Some(json!({ "url": url })))
            .await?;
        let target_id = result["targetId"]
            .as_str()
            .ok_or_else(|| CdpError::Protocol {
                code: -1,
                message: "missing targetId in Target.createTarget response".to_owned(),
            })?
            .to_owned();
        Ok(target_id)
    }

    /// Attach to an existing target and return the new `sessionId`.
    pub async fn attach_to_target(&self, target_id: &str) -> Result<String, CdpError> {
        let result = self
            .call(
                "Target.attachToTarget",
                Some(json!({ "targetId": target_id, "flatten": true })),
            )
            .await?;
        let session_id = result["sessionId"]
            .as_str()
            .ok_or_else(|| CdpError::Protocol {
                code: -1,
                message: "missing sessionId in Target.attachToTarget response".to_owned(),
            })?
            .to_owned();
        Ok(session_id)
    }

    /// Close a target.
    pub async fn close_target(&self, target_id: &str) -> Result<(), CdpError> {
        self.call(
            "Target.closeTarget",
            Some(json!({ "targetId": target_id })),
        )
        .await?;
        Ok(())
    }

    /// Return info for all known targets.
    pub async fn get_targets(&self) -> Result<Vec<TargetInfo>, CdpError> {
        let result = self.call("Target.getTargets", None).await?;
        let infos: Vec<TargetInfo> = serde_json::from_value(
            result["targetInfos"].clone(),
        )?;
        Ok(infos)
    }
}
