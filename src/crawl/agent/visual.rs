//! Level 3 visual extraction — screenshot -> agent vision -> coordinate-based
//! actions.

use crate::crawl::agent::actions::VisualAction;
use crate::crawl::agent::session::AgentSession;
use std::path::Path;

/// Drives a single L3 visual extraction turn.
pub struct VisualExtractionSession<'a> {
    session: &'a mut AgentSession,
    job_dir: &'a Path,
}

impl<'a> VisualExtractionSession<'a> {
    pub fn new(session: &'a mut AgentSession, job_dir: &'a Path) -> Self {
        Self { session, job_dir }
    }

    /// Send a screenshot to the agent and get back a list of visual actions.
    ///
    /// The screenshot is written to a file in `job_dir`. The agent reads it
    /// via its Read tool. The response JSON is collected from its text
    /// output.
    pub async fn analyze(
        &mut self,
        screenshot_png: &[u8],
        goal: &str,
        html_hint: &str,
    ) -> Result<Vec<VisualAction>, anyhow::Error> {
        use anyhow::Context;

        let screenshot_path = self.job_dir.join("screenshot_l3.png");
        tokio::fs::write(&screenshot_path, screenshot_png)
            .await
            .with_context(|| {
                format!(
                    "Failed to write L3 screenshot to {}",
                    screenshot_path.display()
                )
            })?;

        let prompt =
            crate::crawl::agent::prompts::build_visual_prompt(&screenshot_path, goal, html_hint);

        let response_raw = self
            .session
            .send_prompt(&prompt)
            .await
            .context("L3 visual prompt failed")?;

        let json_str = extract_json_from_response(&response_raw);
        let response: serde_json::Value = serde_json::from_str(&json_str).unwrap_or_default();

        let visual_actions: Vec<VisualAction> = response
            .get("visual_actions")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        Ok(visual_actions)
    }
}

/// Try to extract a JSON object from an agent response string.
///
/// Attempts direct parse first. Falls back to scanning for a ` ```json ` fenced
/// block, then to the first `{`…`}` span in the string.
fn extract_json_from_response(raw: &str) -> String {
    let trimmed = raw.trim();

    if trimmed.starts_with('{') {
        return trimmed.to_string();
    }

    if let Some(start) = trimmed.find("```json") {
        let after_fence = &trimmed[start + 7..];
        if let Some(end) = after_fence.find("```") {
            return after_fence[..end].trim().to_string();
        }
    }

    if let Some(start) = trimmed.find("```") {
        let after_fence = &trimmed[start + 3..];
        if let Some(end) = after_fence.find("```") {
            let candidate = after_fence[..end].trim();
            if candidate.starts_with('{') {
                return candidate.to_string();
            }
        }
    }

    if let (Some(start), Some(end)) = (trimmed.find('{'), trimmed.rfind('}')) {
        if end > start {
            return trimmed[start..=end].to_string();
        }
    }

    trimmed.to_string()
}
