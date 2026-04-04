//! CDP Network domain helpers.

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::cdp::error::CdpError;
use crate::cdp::session::CdpSession;

/// A browser cookie.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CdpCookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    pub secure: bool,
    pub http_only: bool,
    pub expires: Option<f64>,
}

impl CdpSession {
    /// Return all cookies visible to the page.
    pub async fn get_cookies(&self) -> Result<Vec<CdpCookie>, CdpError> {
        let result = self.call("Network.getCookies", None).await?;
        let cookies: Vec<CdpCookie> =
            serde_json::from_value(result["cookies"].clone())?;
        Ok(cookies)
    }

    /// Set a single cookie.
    pub async fn set_cookie(&self, cookie: CdpCookie) -> Result<(), CdpError> {
        let params = serde_json::to_value(&cookie)?;
        self.call("Network.setCookie", Some(params)).await?;
        Ok(())
    }

    /// Delete cookies matching `name` and optionally `domain`.
    pub async fn delete_cookies(
        &self,
        name: &str,
        domain: Option<&str>,
    ) -> Result<(), CdpError> {
        let params = match domain {
            Some(d) => json!({ "name": name, "domain": d }),
            None => json!({ "name": name }),
        };
        self.call("Network.deleteCookies", Some(params)).await?;
        Ok(())
    }

    /// Set extra HTTP headers that will be sent with every request from this page.
    ///
    /// Headers are merged with any existing extra headers. To clear previously
    /// set headers, pass an empty map.
    pub async fn set_extra_http_headers(
        &self,
        headers: std::collections::HashMap<String, String>,
    ) -> Result<(), CdpError> {
        let params = json!({ "headers": headers });
        self.call("Network.setExtraHTTPHeaders", Some(params)).await?;
        Ok(())
    }
}
