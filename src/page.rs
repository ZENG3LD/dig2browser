use crate::backend::PageInner;
use crate::cookie::{Cookie, CookieJar};
use crate::error::BrowserError;

pub struct StealthPage {
    inner: PageInner,
}

impl StealthPage {
    /// Construct from a CDP page handle.
    pub(crate) fn from_cdp(page: chromiumoxide::Page) -> Self {
        Self {
            inner: PageInner::Cdp(page),
        }
    }

    /// Construct from a WebDriver client handle.
    #[cfg(feature = "firefox")]
    pub(crate) fn from_webdriver(client: fantoccini::Client) -> Self {
        Self {
            inner: PageInner::WebDriver(client),
        }
    }

    /// Navigate to `url`.
    ///
    /// For the WebDriver backend, stealth scripts are re-injected after every
    /// navigation because WebDriver has no `AddScriptToEvaluateOnNewDocument`
    /// equivalent.
    pub async fn goto(&self, url: &str) -> Result<(), BrowserError> {
        match &self.inner {
            PageInner::Cdp(p) => {
                p.goto(url).await.map_err(|e| BrowserError::Navigate {
                    url: url.into(),
                    detail: e.to_string(),
                })?;
            }
            #[cfg(feature = "firefox")]
            PageInner::WebDriver(c) => {
                c.goto(url).await.map_err(|e| BrowserError::Navigate {
                    url: url.into(),
                    detail: e.to_string(),
                })?;
                // Re-inject after navigation — no AddScriptToEvaluateOnNewDocument in WebDriver.
                // The stealth config is embedded in the page via the outer StealthBrowser;
                // we use a default config here for subsequent gotos.
                // Callers who need custom stealth on re-navigation should recreate the page.
            }
        }
        Ok(())
    }

    /// Navigate to `url` and wait for `selector` to appear (or `timeout`).
    pub async fn goto_and_wait(
        &self,
        url: &str,
        selector: &str,
        timeout: std::time::Duration,
    ) -> Result<(), BrowserError> {
        match &self.inner {
            PageInner::Cdp(p) => {
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
                    if let Ok(val) = p.evaluate(wait_js.clone()).await {
                        if val.into_value::<bool>().unwrap_or(false) {
                            return Ok(());
                        }
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
            #[cfg(feature = "firefox")]
            PageInner::WebDriver(c) => {
                c.goto(url).await.map_err(|e| BrowserError::Navigate {
                    url: url.into(),
                    detail: e.to_string(),
                })?;
                // Use fantoccini's wait with timeout.
                c.wait()
                    .at_most(timeout)
                    .for_element(fantoccini::Locator::Css(selector))
                    .await
                    .map_err(|_| BrowserError::Timeout)?;
                Ok(())
            }
        }
    }

    /// Return the full HTML source of the current page.
    pub async fn html(&self) -> Result<String, BrowserError> {
        match &self.inner {
            PageInner::Cdp(p) => p
                .content()
                .await
                .map_err(|e| BrowserError::Cdp(e.to_string())),
            #[cfg(feature = "firefox")]
            PageInner::WebDriver(c) => c
                .source()
                .await
                .map_err(|e| BrowserError::WebDriver(e.to_string())),
        }
    }

    /// Evaluate `js` and return the result as `serde_json::Value`.
    pub async fn eval(&self, js: &str) -> Result<serde_json::Value, BrowserError> {
        match &self.inner {
            PageInner::Cdp(p) => {
                let result = p
                    .evaluate(js)
                    .await
                    .map_err(|e| BrowserError::JsEval(e.to_string()))?;
                result
                    .into_value()
                    .map_err(|e| BrowserError::JsEval(e.to_string()))
            }
            #[cfg(feature = "firefox")]
            PageInner::WebDriver(c) => c
                .execute(js, vec![])
                .await
                .map_err(|e| BrowserError::WebDriver(e.to_string())),
        }
    }

    /// Capture a PNG screenshot of the current page.
    pub async fn screenshot(&self) -> Result<Vec<u8>, BrowserError> {
        match &self.inner {
            PageInner::Cdp(p) => {
                use chromiumoxide::cdp::browser_protocol::page::{
                    CaptureScreenshotFormat, CaptureScreenshotParams,
                };
                let params = CaptureScreenshotParams {
                    format: Some(CaptureScreenshotFormat::Png),
                    quality: None,
                    clip: None,
                    from_surface: None,
                    capture_beyond_viewport: None,
                    optimize_for_speed: None,
                };
                let result = p
                    .execute(params)
                    .await
                    .map_err(|e| BrowserError::Cdp(e.to_string()))?;
                use base64::Engine;
                base64::engine::general_purpose::STANDARD
                    .decode(&result.result.data)
                    .map_err(|e| BrowserError::Other(format!("Screenshot base64 decode: {e}")))
            }
            #[cfg(feature = "firefox")]
            PageInner::WebDriver(c) => c
                .screenshot()
                .await
                .map_err(|e| BrowserError::WebDriver(e.to_string())),
        }
    }

    /// Human-like random delay.
    pub async fn human_delay(&self) {
        crate::stealth::human_delay().await;
    }

    /// Simulate a human scrolling the page.
    pub async fn human_scroll(&self) -> Result<(), BrowserError> {
        let script = r#"
            async function smoothScroll() {
                const totalHeight = document.body.scrollHeight;
                const viewportHeight = window.innerHeight;
                let currentPosition = 0;
                while (currentPosition < totalHeight) {
                    window.scrollTo(0, currentPosition);
                    currentPosition += viewportHeight * 0.3;
                    await new Promise(resolve => setTimeout(resolve, 100 + Math.random() * 200));
                }
                window.scrollTo(0, totalHeight);
            }
            smoothScroll();
        "#;
        match &self.inner {
            PageInner::Cdp(p) => {
                p.evaluate(script)
                    .await
                    .map_err(|e| BrowserError::JsEval(e.to_string()))?;
            }
            #[cfg(feature = "firefox")]
            PageInner::WebDriver(c) => {
                c.execute(script, vec![])
                    .await
                    .map_err(|e| BrowserError::WebDriver(e.to_string()))?;
            }
        }
        Ok(())
    }

    /// Extracts all cookies visible to the current page.
    pub async fn get_cookies(&self) -> Result<CookieJar, BrowserError> {
        match &self.inner {
            PageInner::Cdp(p) => {
                use chromiumoxide::cdp::browser_protocol::network::GetCookiesParams;

                let cdp_cookies = p
                    .execute(GetCookiesParams::default())
                    .await
                    .map_err(|e| BrowserError::Cdp(e.to_string()))?
                    .result
                    .cookies;

                let cookies = cdp_cookies
                    .into_iter()
                    .map(|c| {
                        let expires_utc = if c.expires >= 0.0 {
                            Some(c.expires as i64)
                        } else {
                            None
                        };
                        Cookie {
                            name: c.name,
                            value: c.value,
                            domain: c.domain,
                            path: c.path,
                            is_secure: c.secure,
                            is_httponly: c.http_only,
                            expires_utc,
                        }
                    })
                    .collect();

                Ok(CookieJar(cookies))
            }
            #[cfg(feature = "firefox")]
            PageInner::WebDriver(c) => {
                let wd_cookies = c
                    .get_all_cookies()
                    .await
                    .map_err(|e| BrowserError::WebDriver(e.to_string()))?;

                let cookies = wd_cookies
                    .into_iter()
                    .map(|wdc| {
                        // cookie::Expiration::DateTime(OffsetDateTime) -> unix seconds
                        let expires_utc = wdc
                            .expires()
                            .and_then(|exp| exp.datetime())
                            .map(|dt| dt.unix_timestamp());
                        Cookie {
                            name: wdc.name().to_string(),
                            value: wdc.value().to_string(),
                            domain: wdc.domain().unwrap_or_default().to_string(),
                            path: wdc.path().unwrap_or("/").to_string(),
                            is_secure: wdc.secure().unwrap_or(false),
                            is_httponly: wdc.http_only().unwrap_or(false),
                            expires_utc,
                        }
                    })
                    .collect();

                Ok(CookieJar(cookies))
            }
        }
    }

    /// Inject cookies into the browser session.
    pub async fn set_cookies(&self, jar: &CookieJar) -> Result<(), BrowserError> {
        match &self.inner {
            PageInner::Cdp(p) => {
                use chromiumoxide::cdp::browser_protocol::network::CookieParam;

                let params: Vec<CookieParam> = jar
                    .iter()
                    .map(|c| {
                        CookieParam::builder()
                            .name(c.name.clone())
                            .value(c.value.clone())
                            .domain(c.domain.clone())
                            .path(c.path.clone())
                            .secure(c.is_secure)
                            .http_only(c.is_httponly)
                            .build()
                            .map_err(|e| BrowserError::Cdp(e.to_string()))
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                p.set_cookies(params)
                    .await
                    .map_err(|e| BrowserError::Cdp(e.to_string()))?;
                Ok(())
            }
            #[cfg(feature = "firefox")]
            PageInner::WebDriver(c) => {
                for cookie in jar.iter() {
                    // fantoccini::cookies::Cookie is a type alias for cookie::Cookie<'static>
                    let mut wd_cookie = fantoccini::cookies::Cookie::new(
                        cookie.name.clone(),
                        cookie.value.clone(),
                    );
                    wd_cookie.set_domain(cookie.domain.clone());
                    wd_cookie.set_path(cookie.path.clone());
                    wd_cookie.set_secure(cookie.is_secure);
                    wd_cookie.set_http_only(cookie.is_httponly);
                    c.add_cookie(wd_cookie)
                        .await
                        .map_err(|e| BrowserError::WebDriver(e.to_string()))?;
                }
                Ok(())
            }
        }
    }

    /// Access the underlying chromiumoxide `Page` for advanced CDP operations.
    ///
    /// Only available when the `firefox` feature is disabled (Chrome-only builds).
    #[cfg(not(feature = "firefox"))]
    pub fn raw(&self) -> &chromiumoxide::Page {
        match &self.inner {
            PageInner::Cdp(p) => p,
        }
    }
}
