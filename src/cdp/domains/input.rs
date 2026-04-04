//! CDP Input domain helpers (mouse, keyboard, touch).

use serde::Serialize;
use serde_json::json;

use crate::cdp::error::CdpError;
use crate::cdp::session::CdpSession;

/// A single touch point for touch events.
#[derive(Debug, Clone, Serialize)]
pub struct TouchPoint {
    pub x: f64,
    pub y: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub radius_x: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub radius_y: Option<f64>,
}

impl CdpSession {
    /// Dispatch a raw mouse event.
    ///
    /// `event_type` is one of `"mousePressed"`, `"mouseReleased"`, `"mouseMoved"`.
    /// `button` is one of `"none"`, `"left"`, `"middle"`, `"right"`.
    pub async fn dispatch_mouse_event(
        &self,
        event_type: &str,
        x: f64,
        y: f64,
        button: &str,
        click_count: u32,
    ) -> Result<(), CdpError> {
        self.call(
            "Input.dispatchMouseEvent",
            Some(json!({
                "type": event_type,
                "x": x,
                "y": y,
                "button": button,
                "clickCount": click_count,
            })),
        )
        .await?;
        Ok(())
    }

    /// High-level left click: `mousePressed` + `mouseReleased` at `(x, y)`.
    pub async fn mouse_click(&self, x: f64, y: f64) -> Result<(), CdpError> {
        self.dispatch_mouse_event("mousePressed", x, y, "left", 1)
            .await?;
        self.dispatch_mouse_event("mouseReleased", x, y, "left", 1)
            .await?;
        Ok(())
    }

    /// Move the mouse to `(x, y)`.
    pub async fn mouse_move(&self, x: f64, y: f64) -> Result<(), CdpError> {
        self.dispatch_mouse_event("mouseMoved", x, y, "none", 0)
            .await?;
        Ok(())
    }

    /// Dispatch a raw key event.
    ///
    /// `event_type` is one of `"keyDown"`, `"keyUp"`, `"char"`.
    pub async fn dispatch_key_event(
        &self,
        event_type: &str,
        key: &str,
        code: &str,
        text: Option<&str>,
    ) -> Result<(), CdpError> {
        let mut params = json!({
            "type": event_type,
            "key": key,
            "code": code,
        });
        if let Some(t) = text {
            params["text"] = serde_json::Value::String(t.to_owned());
        }
        self.call("Input.dispatchKeyEvent", Some(params)).await?;
        Ok(())
    }

    /// Type a string by sending `keyDown` + `keyUp` events for each character.
    pub async fn type_text(&self, text: &str) -> Result<(), CdpError> {
        for ch in text.chars() {
            let s = ch.to_string();
            self.dispatch_key_event("keyDown", &s, &s, Some(&s)).await?;
            self.dispatch_key_event("keyUp", &s, &s, None).await?;
        }
        Ok(())
    }

    /// Press a single key (keyDown + keyUp).
    pub async fn press_key(&self, key: &str, code: &str) -> Result<(), CdpError> {
        self.dispatch_key_event("keyDown", key, code, None).await?;
        self.dispatch_key_event("keyUp", key, code, None).await?;
        Ok(())
    }

    /// Dispatch a touch event.
    ///
    /// `event_type` is one of `"touchStart"`, `"touchEnd"`, `"touchMove"`, `"touchCancel"`.
    pub async fn dispatch_touch_event(
        &self,
        event_type: &str,
        touch_points: Vec<TouchPoint>,
    ) -> Result<(), CdpError> {
        self.call(
            "Input.dispatchTouchEvent",
            Some(json!({
                "type": event_type,
                "touchPoints": touch_points,
            })),
        )
        .await?;
        Ok(())
    }
}
