use crate::{error::WdError, session::WdSession, types::WdElement};

/// W3C element reference key used in JSON responses.
const ELEMENT_KEY: &str = "element-6066-11e4-a52e-4f735466cecf";

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
}
