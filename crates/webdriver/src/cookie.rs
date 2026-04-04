use crate::{error::WdError, session::WdSession, types::WdCookie};

impl WdSession {
    /// Retrieve all cookies visible to the current document.
    pub async fn get_cookies(&self) -> Result<Vec<WdCookie>, WdError> {
        let val = self.get("cookie").await?;
        let cookies: Vec<WdCookie> = serde_json::from_value(val)?;
        Ok(cookies)
    }

    /// Retrieve a single cookie by name.
    pub async fn get_cookie(&self, name: &str) -> Result<WdCookie, WdError> {
        let val = self.get(&format!("cookie/{name}")).await?;
        let cookie: WdCookie = serde_json::from_value(val)?;
        Ok(cookie)
    }

    /// Add a cookie to the current document's cookie jar.
    pub async fn add_cookie(&self, cookie: WdCookie) -> Result<(), WdError> {
        self.post("cookie", serde_json::json!({ "cookie": cookie }))
            .await?;
        Ok(())
    }

    /// Delete a single cookie by name.
    pub async fn delete_cookie(&self, name: &str) -> Result<(), WdError> {
        self.delete(&format!("cookie/{name}")).await?;
        Ok(())
    }

    /// Delete all cookies for the current document.
    pub async fn delete_all_cookies(&self) -> Result<(), WdError> {
        self.delete("cookie").await?;
        Ok(())
    }
}
