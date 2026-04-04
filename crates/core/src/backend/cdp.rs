//! CDP (Chrome DevTools Protocol) backend for StealthBrowser.
//!
//! Spawns a Chrome/Edge process, connects via WebSocket, and provides
//! BrowserBackend + PageBackend implementations using dig2browser-cdp.

use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc,
};

use futures::future::BoxFuture;
use tokio::io::{AsyncBufReadExt, BufReader};
use tracing::debug;

use dig2browser_cdp::{CdpClient, CdpSession};
use dig2browser_cookie::Cookie;
use dig2browser_detect::{LaunchConfig, detect_browser};
use dig2browser_stealth::{StealthConfig, get_scripts};

use crate::error::BrowserError;
use super::{BrowserBackend, PageBackend};

// ── Process handle ─────────────────────────────────────────────────────────

/// Internal state for a running CDP browser process.
pub(crate) struct CdpBrowserBackend {
    client: Arc<CdpClient>,
    root: CdpSession,
    launch: LaunchConfig,
    stealth: StealthConfig,
    page_count: AtomicU32,
    /// Child process — kept alive for the lifetime of this backend.
    _child: tokio::process::Child,
    /// Profile dir path, deleted on drop if ephemeral.
    profile_dir: std::path::PathBuf,
    profile_ephemeral: bool,
}

impl Drop for CdpBrowserBackend {
    fn drop(&mut self) {
        if self.profile_ephemeral {
            let _ = std::fs::remove_dir_all(&self.profile_dir);
        }
    }
}

impl CdpBrowserBackend {
    /// Spawn a Chrome/Edge process and connect via CDP WebSocket.
    pub(crate) async fn launch(
        launch: &LaunchConfig,
        stealth: &StealthConfig,
    ) -> Result<Self, BrowserError> {
        let binary = detect_browser(launch.browser_pref)?;
        let port = launch.debug_port.unwrap_or_else(LaunchConfig::find_free_port);
        let (profile_dir, profile_ephemeral) = launch.profile.resolve()?;
        let locale = Some(stealth.locale.locale.as_str());
        let args = launch.build_args(&profile_dir, port, locale);

        debug!(
            "Launching CDP browser: {} with {} args on port {}",
            binary.path.display(),
            args.len(),
            port
        );

        let mut child = tokio::process::Command::new(&binary.path)
            .args(&args)
            .stderr(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stdin(std::process::Stdio::null())
            .spawn()
            .map_err(|e| BrowserError::Launch(e.to_string()))?;

        // Read stderr looking for "DevTools listening on ws://"
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| BrowserError::Launch("could not capture stderr".into()))?;

        let ws_url = Self::find_ws_url(stderr).await?;
        debug!("CDP WebSocket URL: {ws_url}");

        let client = CdpClient::connect(&ws_url)
            .await
            .map_err(|e| BrowserError::Connect(e.to_string()))?;

        let root = client.root_session();

        // Enable Page domain on root so events flow.
        root.call("Page.enable", None)
            .await
            .map_err(|e| BrowserError::Connect(e.to_string()))?;

        Ok(Self {
            client,
            root,
            launch: launch.clone(),
            stealth: stealth.clone(),
            page_count: AtomicU32::new(0),
            _child: child,
            profile_dir,
            profile_ephemeral,
        })
    }

    /// Scan stderr lines until we see the DevTools WS URL.
    async fn find_ws_url(
        stderr: impl tokio::io::AsyncRead + Unpin,
    ) -> Result<String, BrowserError> {
        let reader = BufReader::new(stderr);
        let mut lines = reader.lines();

        let timeout = std::time::Duration::from_secs(30);
        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(BrowserError::Connect(
                    "timed out waiting for DevTools WebSocket URL on stderr".into(),
                ));
            }

            let line_future = lines.next_line();
            match tokio::time::timeout(remaining, line_future).await {
                Ok(Ok(Some(line))) => {
                    debug!("browser stderr: {line}");
                    if let Some(pos) = line.find("ws://") {
                        return Ok(line[pos..].trim().to_owned());
                    }
                }
                Ok(Ok(None)) => {
                    return Err(BrowserError::Connect(
                        "browser stderr closed before DevTools URL appeared".into(),
                    ));
                }
                Ok(Err(e)) => {
                    return Err(BrowserError::Io(e));
                }
                Err(_) => {
                    return Err(BrowserError::Connect(
                        "timed out waiting for DevTools WebSocket URL".into(),
                    ));
                }
            }
        }
    }

    /// Create and attach to a new page target, inject stealth scripts, optionally navigate.
    async fn open_page(&self, url: Option<&str>) -> Result<CdpPageBackend, BrowserError> {
        let nav_url = url.unwrap_or("about:blank");

        // Create a new page target.
        let target_id = self
            .root
            .create_target(nav_url)
            .await
            .map_err(|e| BrowserError::Navigate(e.to_string()))?;

        // Attach to the target to get a session.
        let session_id = self
            .root
            .attach_to_target(&target_id)
            .await
            .map_err(|e| BrowserError::Connect(e.to_string()))?;

        let session = CdpSession::with_session_id(session_id, Arc::clone(&self.client));

        // Enable required domains on this session.
        session
            .call("Page.enable", None)
            .await
            .map_err(|e| BrowserError::Connect(e.to_string()))?;
        session
            .call("Network.enable", None)
            .await
            .map_err(|e| BrowserError::Connect(e.to_string()))?;

        // Inject stealth scripts so they run on every new document.
        let scripts = get_scripts(&self.stealth);
        for script in &scripts {
            session
                .add_script_on_new_document(script)
                .await
                .map_err(|e| BrowserError::StealthInject(e.to_string()))?;
        }

        self.page_count.fetch_add(1, Ordering::Relaxed);

        Ok(CdpPageBackend {
            session,
            target_id,
        })
    }
}

impl BrowserBackend for CdpBrowserBackend {
    fn new_page<'a>(
        &'a self,
        url: &'a str,
    ) -> BoxFuture<'a, Result<Box<dyn PageBackend>, BrowserError>> {
        Box::pin(async move {
            let page = self.open_page(Some(url)).await?;
            Ok(Box::new(page) as Box<dyn PageBackend>)
        })
    }

    fn new_blank_page<'a>(&'a self) -> BoxFuture<'a, Result<Box<dyn PageBackend>, BrowserError>> {
        Box::pin(async move {
            let page = self.open_page(None).await?;
            Ok(Box::new(page) as Box<dyn PageBackend>)
        })
    }

    fn close<'a>(mut self: Box<Self>) -> BoxFuture<'a, Result<(), BrowserError>> {
        Box::pin(async move {
            // Ask the browser to close gracefully via CDP.
            let _ = self.root.call("Browser.close", None).await;
            // Then kill the process if still running.
            let _ = self._child.kill().await;
            if self.profile_ephemeral {
                let _ = std::fs::remove_dir_all(&self.profile_dir);
                self.profile_ephemeral = false; // prevent double-cleanup in Drop
            }
            Ok(())
        })
    }

    fn page_count(&self) -> u32 {
        self.page_count.load(Ordering::Relaxed)
    }

    fn needs_restart(&self) -> bool {
        let limit = self.launch.restart_after_pages;
        limit > 0 && self.page_count() >= limit
    }
}

// ── Page backend ───────────────────────────────────────────────────────────

/// CDP-backed page handle.
pub(crate) struct CdpPageBackend {
    session: CdpSession,
    /// Kept for future use (e.g. closing the target explicitly).
    target_id: String,
}

impl PageBackend for CdpPageBackend {
    fn goto<'a>(&'a self, url: &'a str) -> BoxFuture<'a, Result<(), BrowserError>> {
        Box::pin(async move {
            self.session
                .navigate(url)
                .await
                .map_err(|e| BrowserError::Navigate(e.to_string()))
        })
    }

    fn html<'a>(&'a self) -> BoxFuture<'a, Result<String, BrowserError>> {
        Box::pin(async move {
            self.session
                .get_content()
                .await
                .map_err(|e| BrowserError::JsEval(e.to_string()))
        })
    }

    fn eval<'a>(&'a self, js: &'a str) -> BoxFuture<'a, Result<serde_json::Value, BrowserError>> {
        Box::pin(async move {
            let result = self
                .session
                .evaluate(js)
                .await
                .map_err(|e| BrowserError::JsEval(e.to_string()))?;
            // result is {"type": "...", "value": ...} — return the value field.
            Ok(result
                .get("value")
                .cloned()
                .unwrap_or(serde_json::Value::Null))
        })
    }

    fn screenshot<'a>(&'a self) -> BoxFuture<'a, Result<Vec<u8>, BrowserError>> {
        Box::pin(async move {
            self.session
                .capture_screenshot("png", None)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))
        })
    }

    fn get_cookies<'a>(
        &'a self,
    ) -> BoxFuture<'a, Result<Vec<Cookie>, BrowserError>> {
        Box::pin(async move {
            let cdp_cookies = self
                .session
                .get_cookies()
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            let cookies = cdp_cookies
                .into_iter()
                .map(|c| Cookie {
                    name: c.name,
                    value: c.value,
                    domain: c.domain,
                    path: c.path,
                    is_secure: c.secure,
                    is_httponly: c.http_only,
                    expires_utc: c.expires.map(|f| f as i64),
                })
                .collect();
            Ok(cookies)
        })
    }

    fn set_cookies<'a>(
        &'a self,
        cookies: &'a [Cookie],
    ) -> BoxFuture<'a, Result<(), BrowserError>> {
        Box::pin(async move {
            for cookie in cookies {
                let cdp_cookie = dig2browser_cdp::CdpCookie {
                    name: cookie.name.clone(),
                    value: cookie.value.clone(),
                    domain: cookie.domain.clone(),
                    path: cookie.path.clone(),
                    secure: cookie.is_secure,
                    http_only: cookie.is_httponly,
                    expires: cookie.expires_utc.map(|t| t as f64),
                };
                self.session
                    .set_cookie(cdp_cookie)
                    .await
                    .map_err(|e| BrowserError::Other(e.to_string()))?;
            }
            Ok(())
        })
    }
}

// Suppress lint: target_id is kept for future use (explicit target close).
impl Drop for CdpPageBackend {
    fn drop(&mut self) {
        let _target_id = &self.target_id;
        // Could send Target.closeTarget here, but it requires an async context.
        // The browser will GC detached targets automatically.
    }
}
