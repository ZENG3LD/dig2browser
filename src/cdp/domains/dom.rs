//! CDP DOM domain helpers.

use serde::Deserialize;
use serde_json::json;

use crate::cdp::error::CdpError;
use crate::cdp::session::CdpSession;

/// A node in the DOM tree.
#[derive(Debug, Clone, Deserialize)]
pub struct DomNode {
    #[serde(rename = "nodeId")]
    pub node_id: i64,
    #[serde(rename = "nodeType")]
    pub node_type: i64,
    #[serde(rename = "nodeName")]
    pub node_name: String,
    #[serde(rename = "localName")]
    pub local_name: String,
    #[serde(rename = "nodeValue")]
    pub node_value: String,
    #[serde(default)]
    pub children: Vec<DomNode>,
    #[serde(default)]
    pub attributes: Vec<String>,
}

/// Bounding box model for a DOM node (all quads have 8 values: x1,y1…x4,y4).
#[derive(Debug, Clone, Deserialize)]
pub struct BoxModel {
    pub content: Vec<f64>,
    pub padding: Vec<f64>,
    pub border: Vec<f64>,
    pub margin: Vec<f64>,
    pub width: i64,
    pub height: i64,
}

impl CdpSession {
    /// Enable the DOM domain (required before using most DOM methods).
    pub async fn enable_dom(&self) -> Result<(), CdpError> {
        self.call("DOM.enable", None).await?;
        Ok(())
    }

    /// Return the document root node.
    pub async fn get_document(&self) -> Result<DomNode, CdpError> {
        let result = self.call("DOM.getDocument", None).await?;
        let node: DomNode = serde_json::from_value(result["root"].clone())?;
        Ok(node)
    }

    /// Run `querySelector` on `node_id`. Returns `None` if nothing matched.
    pub async fn query_selector(
        &self,
        node_id: i64,
        selector: &str,
    ) -> Result<Option<i64>, CdpError> {
        let result = self
            .call(
                "DOM.querySelector",
                Some(json!({ "nodeId": node_id, "selector": selector })),
            )
            .await?;
        let id = result["nodeId"].as_i64().unwrap_or(0);
        Ok(if id == 0 { None } else { Some(id) })
    }

    /// Run `querySelectorAll` on `node_id`. Returns a list of node ids.
    pub async fn query_selector_all(
        &self,
        node_id: i64,
        selector: &str,
    ) -> Result<Vec<i64>, CdpError> {
        let result = self
            .call(
                "DOM.querySelectorAll",
                Some(json!({ "nodeId": node_id, "selector": selector })),
            )
            .await?;
        let ids: Vec<i64> = serde_json::from_value(result["nodeIds"].clone())?;
        Ok(ids)
    }

    /// Get the bounding box model (position + size) for a node.
    pub async fn get_box_model(&self, node_id: i64) -> Result<BoxModel, CdpError> {
        let result = self
            .call(
                "DOM.getBoxModel",
                Some(json!({ "nodeId": node_id })),
            )
            .await?;
        let model: BoxModel = serde_json::from_value(result["model"].clone())?;
        Ok(model)
    }

    /// Resolve a DOM node to a JS remote object, returning the `objectId`.
    pub async fn resolve_node(&self, node_id: i64) -> Result<String, CdpError> {
        let result = self
            .call(
                "DOM.resolveNode",
                Some(json!({ "nodeId": node_id })),
            )
            .await?;
        let object_id = result["object"]["objectId"]
            .as_str()
            .ok_or_else(|| CdpError::Protocol {
                code: -1,
                message: "missing objectId in DOM.resolveNode response".to_owned(),
            })?
            .to_owned();
        Ok(object_id)
    }

    /// Get the outer HTML of a node.
    pub async fn get_outer_html(&self, node_id: i64) -> Result<String, CdpError> {
        let result = self
            .call(
                "DOM.getOuterHTML",
                Some(json!({ "nodeId": node_id })),
            )
            .await?;
        let html = result["outerHTML"]
            .as_str()
            .ok_or_else(|| CdpError::Protocol {
                code: -1,
                message: "missing outerHTML in DOM.getOuterHTML response".to_owned(),
            })?
            .to_owned();
        Ok(html)
    }

    /// Set a single attribute on a node.
    pub async fn set_attribute(
        &self,
        node_id: i64,
        name: &str,
        value: &str,
    ) -> Result<(), CdpError> {
        self.call(
            "DOM.setAttributeValue",
            Some(json!({ "nodeId": node_id, "name": name, "value": value })),
        )
        .await?;
        Ok(())
    }

    /// Get all attributes of a node as `(name, value)` pairs.
    ///
    /// The CDP response is a flat list `[name, value, name, value, …]`.
    pub async fn get_attributes(&self, node_id: i64) -> Result<Vec<(String, String)>, CdpError> {
        let result = self
            .call(
                "DOM.getAttributes",
                Some(json!({ "nodeId": node_id })),
            )
            .await?;
        let flat: Vec<String> = serde_json::from_value(result["attributes"].clone())?;
        let pairs = flat
            .chunks(2)
            .filter_map(|c| {
                if c.len() == 2 {
                    Some((c[0].clone(), c[1].clone()))
                } else {
                    None
                }
            })
            .collect();
        Ok(pairs)
    }

    /// Focus a DOM node.
    pub async fn focus(&self, node_id: i64) -> Result<(), CdpError> {
        self.call("DOM.focus", Some(json!({ "nodeId": node_id })))
            .await?;
        Ok(())
    }

    /// Return the content-document node id of a frame-owner node (an
    /// `<iframe>`), or `None` if the node owns no reachable content document
    /// (e.g. it is not a frame, or the frame is cross-origin / out-of-process
    /// and lives in a separate CDP session). Uses `DOM.describeNode` with
    /// `pierce` so a same-origin frame's document is included.
    pub async fn content_document_node_id(
        &self,
        node_id: i64,
    ) -> Result<Option<i64>, CdpError> {
        let result = self
            .call(
                "DOM.describeNode",
                Some(json!({ "nodeId": node_id, "pierce": true })),
            )
            .await?;
        Ok(result["node"]["contentDocument"]["nodeId"]
            .as_i64()
            .filter(|id| *id != 0))
    }

    /// Set the files selected by a file `<input>` node (`DOM.setFileInputFiles`).
    /// `files` are absolute local paths the browser process reads itself; no
    /// bytes flow through this call.
    pub async fn set_file_input_files(
        &self,
        node_id: i64,
        files: &[String],
    ) -> Result<(), CdpError> {
        self.call(
            "DOM.setFileInputFiles",
            Some(json!({ "nodeId": node_id, "files": files })),
        )
        .await?;
        Ok(())
    }

    /// Scroll a DOM node into view.
    pub async fn scroll_into_view(&self, node_id: i64) -> Result<(), CdpError> {
        self.call(
            "DOM.scrollIntoViewIfNeeded",
            Some(json!({ "nodeId": node_id })),
        )
        .await?;
        Ok(())
    }
}
