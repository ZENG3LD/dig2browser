use serde::{Deserialize, Serialize};

use crate::{error::WdError, session::WdSession};

/// WebDriver session timeout settings (all values in milliseconds).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Timeouts {
    /// Maximum time to wait for a script to finish executing.
    pub script: Option<u64>,
    /// Maximum time to wait for a page load to complete.
    #[serde(rename = "pageLoad")]
    pub page_load: Option<u64>,
    /// Amount of time to wait when locating elements.
    pub implicit: Option<u64>,
}

impl WdSession {
    /// Override one or more session timeouts.
    ///
    /// Pass `None` for any value you want to leave unchanged.
    pub async fn set_timeouts(
        &self,
        script: Option<u64>,
        page_load: Option<u64>,
        implicit: Option<u64>,
    ) -> Result<(), WdError> {
        let mut body = serde_json::Map::new();
        if let Some(v) = script {
            body.insert("script".to_string(), v.into());
        }
        if let Some(v) = page_load {
            body.insert("pageLoad".to_string(), v.into());
        }
        if let Some(v) = implicit {
            body.insert("implicit".to_string(), v.into());
        }
        self.post("timeouts", serde_json::Value::Object(body))
            .await?;
        Ok(())
    }

    /// Retrieve the current timeout values for this session.
    pub async fn get_timeouts(&self) -> Result<Timeouts, WdError> {
        let val = self.get("timeouts").await?;
        let t: Timeouts = serde_json::from_value(val)?;
        Ok(t)
    }
}
