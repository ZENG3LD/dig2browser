use serde::Serialize;

use crate::webdriver::{error::WdError, session::WdSession};

/// A single action item within an action source.
#[derive(Debug, Clone, Serialize)]
pub struct ActionItem {
    #[serde(rename = "type")]
    pub action_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration: Option<u64>,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

/// One logical input device (pointer, key, or wheel) and its sequence of actions.
#[derive(Debug, Clone, Serialize)]
pub struct ActionSource {
    #[serde(rename = "type")]
    pub source_type: String,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<serde_json::Value>,
    pub actions: Vec<ActionItem>,
}

/// Builder for a W3C Actions API payload.
///
/// Actions for different input sources (pointer, key, wheel) are accumulated
/// separately and combined when [`ActionChain::build`] is called.
pub struct ActionChain {
    pointer_actions: Vec<ActionItem>,
    key_actions: Vec<ActionItem>,
    wheel_actions: Vec<ActionItem>,
}

impl Default for ActionChain {
    fn default() -> Self {
        Self::new()
    }
}

impl ActionChain {
    /// Create an empty action chain.
    pub fn new() -> Self {
        Self {
            pointer_actions: Vec::new(),
            key_actions: Vec::new(),
            wheel_actions: Vec::new(),
        }
    }

    /// Move the pointer to absolute coordinates `(x, y)`.
    pub fn mouse_move(mut self, x: i64, y: i64) -> Self {
        self.pointer_actions.push(ActionItem {
            action_type: "pointerMove".to_string(),
            duration: Some(0),
            extra: serde_json::json!({ "x": x, "y": y }),
        });
        self
    }

    /// Press the primary mouse button.
    pub fn mouse_down(mut self) -> Self {
        self.pointer_actions.push(ActionItem {
            action_type: "pointerDown".to_string(),
            duration: None,
            extra: serde_json::json!({ "button": 0 }),
        });
        self
    }

    /// Release the primary mouse button.
    pub fn mouse_up(mut self) -> Self {
        self.pointer_actions.push(ActionItem {
            action_type: "pointerUp".to_string(),
            duration: None,
            extra: serde_json::json!({ "button": 0 }),
        });
        self
    }

    /// Move to `(x, y)` and perform a single click.
    pub fn click_at(self, x: i64, y: i64) -> Self {
        self.mouse_move(x, y).mouse_down().mouse_up()
    }

    /// Move to `(x, y)` and perform a double-click.
    pub fn double_click_at(self, x: i64, y: i64) -> Self {
        self.mouse_move(x, y)
            .mouse_down()
            .mouse_up()
            .mouse_down()
            .mouse_up()
    }

    /// Dispatch a key-down event for `key`.
    pub fn key_down(mut self, key: &str) -> Self {
        self.key_actions.push(ActionItem {
            action_type: "keyDown".to_string(),
            duration: None,
            extra: serde_json::json!({ "value": key }),
        });
        self
    }

    /// Dispatch a key-up event for `key`.
    pub fn key_up(mut self, key: &str) -> Self {
        self.key_actions.push(ActionItem {
            action_type: "keyUp".to_string(),
            duration: None,
            extra: serde_json::json!({ "value": key }),
        });
        self
    }

    /// Type a string by dispatching key-down + key-up for each character.
    pub fn type_text(mut self, text: &str) -> Self {
        for ch in text.chars() {
            let s = ch.to_string();
            self.key_actions.push(ActionItem {
                action_type: "keyDown".to_string(),
                duration: None,
                extra: serde_json::json!({ "value": s }),
            });
            self.key_actions.push(ActionItem {
                action_type: "keyUp".to_string(),
                duration: None,
                extra: serde_json::json!({ "value": s }),
            });
        }
        self
    }

    /// Insert a pause for `ms` milliseconds on all active input sources.
    pub fn pause(mut self, ms: u64) -> Self {
        let item = ActionItem {
            action_type: "pause".to_string(),
            duration: Some(ms),
            extra: serde_json::Value::Object(Default::default()),
        };
        // Pause is valid on any source; insert on both pointer and key to keep
        // sequences temporally aligned.
        self.pointer_actions.push(item.clone());
        self.key_actions.push(item);
        self
    }

    /// Scroll the wheel by `(delta_x, delta_y)` starting from `(x, y)`.
    pub fn scroll(mut self, x: i64, y: i64, delta_x: i64, delta_y: i64) -> Self {
        self.wheel_actions.push(ActionItem {
            action_type: "scroll".to_string(),
            duration: Some(0),
            extra: serde_json::json!({
                "x": x, "y": y,
                "deltaX": delta_x, "deltaY": delta_y
            }),
        });
        self
    }

    /// Build the JSON payload for `POST /session/{id}/actions`.
    pub(crate) fn build(&self) -> serde_json::Value {
        let mut sources: Vec<serde_json::Value> = Vec::new();

        if !self.pointer_actions.is_empty() {
            let src = ActionSource {
                source_type: "pointer".to_string(),
                id: "mouse0".to_string(),
                parameters: Some(serde_json::json!({ "pointerType": "mouse" })),
                actions: self.pointer_actions.clone(),
            };
            sources.push(serde_json::to_value(src).unwrap_or_default());
        }

        if !self.key_actions.is_empty() {
            let src = ActionSource {
                source_type: "key".to_string(),
                id: "keyboard0".to_string(),
                parameters: None,
                actions: self.key_actions.clone(),
            };
            sources.push(serde_json::to_value(src).unwrap_or_default());
        }

        if !self.wheel_actions.is_empty() {
            let src = ActionSource {
                source_type: "wheel".to_string(),
                id: "wheel0".to_string(),
                parameters: None,
                actions: self.wheel_actions.clone(),
            };
            sources.push(serde_json::to_value(src).unwrap_or_default());
        }

        serde_json::json!({ "actions": sources })
    }
}

impl WdSession {
    /// Perform the given action chain via `POST /session/{id}/actions`.
    pub async fn perform_actions(&self, chain: &ActionChain) -> Result<(), WdError> {
        self.post("actions", chain.build()).await?;
        Ok(())
    }

    /// Release all currently-pressed keys and mouse buttons.
    pub async fn release_actions(&self) -> Result<(), WdError> {
        self.delete("actions").await?;
        Ok(())
    }
}
