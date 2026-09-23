//! Browser action types for L2 (interactive) and L3 (visual) extraction.

use serde::{Deserialize, Serialize};

/// A browser action returned by an agent in L2 interactive mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BrowserAction {
    /// Click the first element matching `selector`.
    Click { selector: String },
    /// Click at viewport coordinates (x, y) — used by L3 visual mode.
    ClickAt { x: f64, y: f64 },
    /// Type `text` into the first element matching `selector`.
    Type { selector: String, text: String },
    /// Scroll to the element matching `selector` (scrollIntoView).
    ScrollTo { selector: String },
    /// Scroll to absolute pixel offset (y).
    ScrollToY { y: u32 },
    /// Scroll to the bottom of the page.
    ScrollBottom,
    /// Wait for an element matching `selector` to appear.
    WaitForElement { selector: String, timeout_ms: u32 },
    /// Wait a fixed number of milliseconds (capped at 10_000 in executor).
    WaitMs { ms: u32 },
    /// Take a screenshot and pass it to the agent's vision turn (triggers L3
    /// sub-turn).
    ScreenshotAndAnalyze,
    /// Dismiss an overlay/modal by clicking it (cookie banners, popups).
    DismissOverlay { selector: String },
    /// Press a keyboard key (e.g. "Enter", "Escape", "Tab").
    PressKey { key: String },
    /// Select a value in a <select> element.
    SelectOption { selector: String, value: String },
}

/// A visual action returned by the agent's vision turn in L3 mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum VisualAction {
    /// Click at viewport coordinates.
    Click {
        x: f64,
        y: f64,
        description: String,
    },
    /// Type text after clicking at coordinates.
    Type {
        x: f64,
        y: f64,
        text: String,
        description: String,
    },
    /// Scroll by delta_y pixels.
    Scroll { delta_y: i32, description: String },
    /// No interaction possible.
    NoAction { reason: String },
}

impl VisualAction {
    /// Convert a visual action into a browser action for execution.
    ///
    /// For `Type`, returns only the `ClickAt` half — the executor is responsible
    /// for issuing the actual keystroke after the click lands.
    pub fn to_browser_action(&self) -> Option<BrowserAction> {
        match self {
            Self::Click { x, y, .. } => Some(BrowserAction::ClickAt { x: *x, y: *y }),
            Self::Type { x, y, .. } => Some(BrowserAction::ClickAt { x: *x, y: *y }),
            Self::Scroll { delta_y, .. } => Some(BrowserAction::ScrollToY {
                y: (*delta_y).max(0) as u32,
            }),
            Self::NoAction { .. } => None,
        }
    }
}

/// Summary of what happened after executing browser actions.
#[derive(Debug)]
pub struct ActionOutcome {
    /// HTML captured after all actions completed.
    pub html: String,
    /// Screenshot taken after actions.
    pub screenshot: Option<Vec<u8>>,
    /// Actions that failed (index, error message).
    pub failed_actions: Vec<(usize, String)>,
    /// Total actions attempted.
    pub total_actions: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_browser_action_round_trip() {
        let actions = vec![
            BrowserAction::Click {
                selector: "button.load-more".into(),
            },
            BrowserAction::ClickAt { x: 100.0, y: 200.0 },
            BrowserAction::Type {
                selector: "input[name=q]".into(),
                text: "search".into(),
            },
            BrowserAction::ScrollBottom,
            BrowserAction::WaitForElement {
                selector: ".results".into(),
                timeout_ms: 5000,
            },
            BrowserAction::WaitMs { ms: 1000 },
            BrowserAction::DismissOverlay {
                selector: ".cookie-banner button".into(),
            },
            BrowserAction::PressKey { key: "Enter".into() },
        ];

        for action in &actions {
            let json = serde_json::to_string(action).unwrap();
            let parsed: BrowserAction = serde_json::from_str(&json).unwrap();
            let json2 = serde_json::to_string(&parsed).unwrap();
            assert_eq!(json, json2);
        }
    }

    #[test]
    fn test_visual_action_round_trip() {
        let actions = vec![
            VisualAction::Click {
                x: 150.0,
                y: 300.0,
                description: "Load More button".into(),
            },
            VisualAction::Type {
                x: 50.0,
                y: 100.0,
                text: "query".into(),
                description: "search box".into(),
            },
            VisualAction::Scroll {
                delta_y: 500,
                description: "scroll down".into(),
            },
            VisualAction::NoAction {
                reason: "no interactive elements".into(),
            },
        ];

        for action in &actions {
            let json = serde_json::to_string(action).unwrap();
            let parsed: VisualAction = serde_json::from_str(&json).unwrap();
            let json2 = serde_json::to_string(&parsed).unwrap();
            assert_eq!(json, json2);
        }
    }

    #[test]
    fn test_visual_to_browser_action() {
        let click = VisualAction::Click {
            x: 100.0,
            y: 200.0,
            description: "btn".into(),
        };
        assert!(
            matches!(click.to_browser_action(), Some(BrowserAction::ClickAt { x, y }) if x == 100.0 && y == 200.0)
        );

        let no_action = VisualAction::NoAction {
            reason: "nope".into(),
        };
        assert!(no_action.to_browser_action().is_none());
    }
}
