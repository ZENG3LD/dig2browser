use base64::Engine;
use serde::Deserialize;

use crate::{error::WdError, session::WdSession, types::WdElement};

/// W3C element reference key used in JSON responses.
const ELEMENT_KEY: &str = "element-6066-11e4-a52e-4f735466cecf";

/// Bounding rectangle for a DOM element (all values in CSS pixels).
#[derive(Debug, Clone, Deserialize)]
pub struct ElementRect {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

impl WdSession {
    /// Find the first element matching the given locator strategy.
    ///
    /// Common `using` values: `"css selector"`, `"xpath"`, `"id"`, `"name"`.
    pub async fn find_element(&self, using: &str, value: &str) -> Result<WdElement, WdError> {
        let val = self
            .post("element", serde_json::json!({ "using": using, "value": value }))
            .await?;

        let id = val
            .get(ELEMENT_KEY)
            .or_else(|| val.get("ELEMENT"))
            .and_then(|v| v.as_str())
            .ok_or(WdError::ElementNotFound)?
            .to_string();

        Ok(WdElement { element_id: id })
    }

    /// Find all elements matching the given locator strategy.
    pub async fn find_elements(
        &self,
        using: &str,
        value: &str,
    ) -> Result<Vec<WdElement>, WdError> {
        let val = self
            .post("elements", serde_json::json!({ "using": using, "value": value }))
            .await?;

        let arr = val.as_array().cloned().unwrap_or_default();
        let mut elements = Vec::with_capacity(arr.len());
        for item in arr {
            let id = item
                .get(ELEMENT_KEY)
                .or_else(|| item.get("ELEMENT"))
                .and_then(|v| v.as_str())
                .ok_or(WdError::ElementNotFound)?
                .to_string();
            elements.push(WdElement { element_id: id });
        }
        Ok(elements)
    }

    /// Click an element.
    pub async fn click(&self, element: &WdElement) -> Result<(), WdError> {
        self.post(
            &format!("element/{}/click", element.element_id),
            serde_json::json!({}),
        )
        .await?;
        Ok(())
    }

    /// Send keystrokes to an element.
    pub async fn send_keys(&self, element: &WdElement, text: &str) -> Result<(), WdError> {
        self.post(
            &format!("element/{}/value", element.element_id),
            serde_json::json!({ "text": text }),
        )
        .await?;
        Ok(())
    }

    /// Return the visible text of an element.
    pub async fn element_text(&self, element: &WdElement) -> Result<String, WdError> {
        let val = self
            .get(&format!("element/{}/text", element.element_id))
            .await?;
        Ok(val.as_str().unwrap_or_default().to_string())
    }

    /// Return the value of a named attribute on an element, or `None` if absent.
    pub async fn element_attribute(
        &self,
        element: &WdElement,
        name: &str,
    ) -> Result<Option<String>, WdError> {
        let val = self
            .get(&format!("element/{}/attribute/{name}", element.element_id))
            .await?;
        Ok(val.as_str().map(|s| s.to_string()))
    }

    /// Return the bounding rectangle of the element (using `getBoundingClientRect` via JS).
    pub async fn element_rect(&self, element: &WdElement) -> Result<ElementRect, WdError> {
        let val = self
            .get(&format!("element/{}/rect", element.element_id))
            .await?;
        let rect: ElementRect = serde_json::from_value(val)?;
        Ok(rect)
    }

    /// Return `true` if the element is currently displayed.
    pub async fn element_displayed(&self, element: &WdElement) -> Result<bool, WdError> {
        let val = self
            .get(&format!("element/{}/displayed", element.element_id))
            .await?;
        Ok(val.as_bool().unwrap_or(false))
    }

    /// Return `true` if the element is currently enabled.
    pub async fn element_enabled(&self, element: &WdElement) -> Result<bool, WdError> {
        let val = self
            .get(&format!("element/{}/enabled", element.element_id))
            .await?;
        Ok(val.as_bool().unwrap_or(false))
    }

    /// Return `true` if the element is currently selected (checkbox or radio button).
    pub async fn element_selected(&self, element: &WdElement) -> Result<bool, WdError> {
        let val = self
            .get(&format!("element/{}/selected", element.element_id))
            .await?;
        Ok(val.as_bool().unwrap_or(false))
    }

    /// Return the tag name of the element (e.g. `"input"`, `"div"`).
    pub async fn element_tag(&self, element: &WdElement) -> Result<String, WdError> {
        let val = self
            .get(&format!("element/{}/name", element.element_id))
            .await?;
        Ok(val.as_str().unwrap_or_default().to_string())
    }

    /// Return the computed value of a CSS property for the element.
    pub async fn element_css(
        &self,
        element: &WdElement,
        property: &str,
    ) -> Result<String, WdError> {
        let val = self
            .get(&format!(
                "element/{}/css/{property}",
                element.element_id
            ))
            .await?;
        Ok(val.as_str().unwrap_or_default().to_string())
    }

    /// Take a screenshot of the element and return the raw PNG bytes.
    pub async fn element_screenshot(&self, element: &WdElement) -> Result<Vec<u8>, WdError> {
        let val = self
            .get(&format!("element/{}/screenshot", element.element_id))
            .await?;
        let b64 = val.as_str().unwrap_or_default();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| WdError::Protocol {
                error: "base64".to_string(),
                message: e.to_string(),
            })?;
        Ok(bytes)
    }

    /// Clear the content of an `<input>` or `<textarea>` element.
    pub async fn element_clear(&self, element: &WdElement) -> Result<(), WdError> {
        self.post(
            &format!("element/{}/clear", element.element_id),
            serde_json::json!({}),
        )
        .await?;
        Ok(())
    }

    /// Find the first child element of `parent` matching the given locator.
    pub async fn find_element_from(
        &self,
        parent: &WdElement,
        using: &str,
        value: &str,
    ) -> Result<WdElement, WdError> {
        let val = self
            .post(
                &format!("element/{}/element", parent.element_id),
                serde_json::json!({ "using": using, "value": value }),
            )
            .await?;

        let id = val
            .get(ELEMENT_KEY)
            .or_else(|| val.get("ELEMENT"))
            .and_then(|v| v.as_str())
            .ok_or(WdError::ElementNotFound)?
            .to_string();

        Ok(WdElement { element_id: id })
    }

    /// Find all child elements of `parent` matching the given locator.
    pub async fn find_elements_from(
        &self,
        parent: &WdElement,
        using: &str,
        value: &str,
    ) -> Result<Vec<WdElement>, WdError> {
        let val = self
            .post(
                &format!("element/{}/elements", parent.element_id),
                serde_json::json!({ "using": using, "value": value }),
            )
            .await?;

        let arr = val.as_array().cloned().unwrap_or_default();
        let mut elements = Vec::with_capacity(arr.len());
        for item in arr {
            let id = item
                .get(ELEMENT_KEY)
                .or_else(|| item.get("ELEMENT"))
                .and_then(|v| v.as_str())
                .ok_or(WdError::ElementNotFound)?
                .to_string();
            elements.push(WdElement { element_id: id });
        }
        Ok(elements)
    }

    /// Return the shadow root of the element as a `WdElement` reference.
    pub async fn element_shadow_root(&self, element: &WdElement) -> Result<WdElement, WdError> {
        let val = self
            .get(&format!("element/{}/shadow", element.element_id))
            .await?;

        // Shadow roots use "shadow-6066-11e4-a52e-4f735466cecf" as their key.
        const SHADOW_KEY: &str = "shadow-6066-11e4-a52e-4f735466cecf";
        let id = val
            .get(SHADOW_KEY)
            .or_else(|| val.get(ELEMENT_KEY))
            .and_then(|v| v.as_str())
            .ok_or(WdError::ElementNotFound)?
            .to_string();

        Ok(WdElement { element_id: id })
    }
}
