use crate::error::BrowserError;

pub struct StealthPage {
    inner: chromiumoxide::Page,
}

impl StealthPage {
    pub fn new(inner: chromiumoxide::Page) -> Self {
        Self { inner }
    }

    pub async fn goto(&self, url: &str) -> Result<(), BrowserError> {
        self.inner
            .goto(url)
            .await
            .map_err(|e| BrowserError::Navigate {
                url: url.into(),
                detail: e.to_string(),
            })?;
        Ok(())
    }

    pub async fn goto_and_wait(
        &self,
        url: &str,
        selector: &str,
        timeout: std::time::Duration,
    ) -> Result<(), BrowserError> {
        self.goto(url).await?;
        let wait_js = format!(
            r#"(function() {{ return document.querySelector('{}') !== null; }})()"#,
            selector.replace('\'', "\\'")
        );
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if std::time::Instant::now() > deadline {
                return Err(BrowserError::Timeout);
            }
            if let Ok(val) = self.inner.evaluate(wait_js.clone()).await {
                if val.into_value::<bool>().unwrap_or(false) {
                    return Ok(());
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    pub async fn html(&self) -> Result<String, BrowserError> {
        self.inner
            .content()
            .await
            .map_err(|e| BrowserError::Cdp(e.to_string()))
    }

    pub async fn eval(&self, js: &str) -> Result<serde_json::Value, BrowserError> {
        let result = self.inner
            .evaluate(js)
            .await
            .map_err(|e| BrowserError::JsEval(e.to_string()))?;
        result
            .into_value()
            .map_err(|e| BrowserError::JsEval(e.to_string()))
    }

    pub async fn human_delay(&self) {
        crate::stealth::human_delay().await;
    }

    pub async fn human_scroll(&self) -> Result<(), BrowserError> {
        crate::stealth::human_scroll(&self.inner).await
    }

    pub fn raw(&self) -> &chromiumoxide::Page {
        &self.inner
    }
}
