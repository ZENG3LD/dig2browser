use std::path::PathBuf;
use std::process::Stdio;

use chromiumoxide::Browser;
use futures::StreamExt;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Child;

use crate::browser_args::LaunchConfig;
use crate::browser_detect::detect_browser;
use crate::error::BrowserError;
use crate::page::StealthPage;
use crate::stealth::{self, StealthConfig};

// ---------------------------------------------------------------------------
// Profile dir newtype
// ---------------------------------------------------------------------------

enum ProfileDir {
    Ephemeral(PathBuf),
    Persistent(PathBuf),
}

impl ProfileDir {
    fn path(&self) -> &PathBuf {
        match self {
            Self::Ephemeral(p) | Self::Persistent(p) => p,
        }
    }

    fn is_ephemeral(&self) -> bool {
        matches!(self, Self::Ephemeral(_))
    }
}

// ---------------------------------------------------------------------------
// StealthBrowser
// ---------------------------------------------------------------------------

pub struct StealthBrowser {
    browser: Browser,
    _handler: tokio::task::JoinHandle<()>,
    _process: Option<Child>,
    profile_dir: ProfileDir,
    stealth: StealthConfig,
}

impl StealthBrowser {
    /// Launch with default config.
    pub async fn launch() -> Result<Self, BrowserError> {
        Self::launch_with(LaunchConfig::default(), StealthConfig::default()).await
    }

    /// Launch with explicit config.
    ///
    /// Follows the proven pattern from daemon4russian-parser: spawn the browser
    /// process manually, read stderr for the DevTools WebSocket URL, then
    /// connect via `Browser::connect` — avoiding the race condition that
    /// `Browser::launch` has on Windows.
    pub async fn launch_with(
        launch: LaunchConfig,
        stealth: StealthConfig,
    ) -> Result<Self, BrowserError> {
        // 1. Locate the browser binary.
        let binary = detect_browser(launch.browser_pref)?;

        // 2. Resolve the profile directory.
        let (profile_path, is_ephemeral) = launch.profile.resolve()?;
        let profile_dir = if is_ephemeral {
            ProfileDir::Ephemeral(profile_path.clone())
        } else {
            ProfileDir::Persistent(profile_path.clone())
        };

        // 3. Pick a debug port.
        let port = launch.debug_port.unwrap_or_else(LaunchConfig::find_free_port);

        // 4. Build CLI args.
        let args = launch.build_args(&profile_path, port);

        // 5. Spawn the browser process with stderr piped.
        let mut child = tokio::process::Command::new(&binary.path)
            .args(&args)
            .stderr(Stdio::piped())
            .stdout(Stdio::null())
            .stdin(Stdio::null())
            .spawn()
            .map_err(BrowserError::Launch)?;

        // 6. Read stderr until we find "DevTools listening on ws://".
        let stderr = child.stderr.take().ok_or_else(|| {
            BrowserError::Connect("No stderr pipe from browser process".to_string())
        })?;
        let mut lines = BufReader::new(stderr).lines();

        const TIMEOUT_SECS: u64 = 15;
        let ws_url =
            tokio::time::timeout(std::time::Duration::from_secs(TIMEOUT_SECS), async {
                while let Ok(Some(line)) = lines.next_line().await {
                    tracing::debug!("[dig2browser] stderr: {}", line);
                    if let Some(idx) = line.find("ws://") {
                        let ws = line[idx..].trim().to_string();
                        if ws.contains("devtools/browser") {
                            return Ok(ws);
                        }
                    }
                }
                Err(BrowserError::Connect(
                    "Browser stderr closed without a DevTools WebSocket URL".to_string(),
                ))
            })
            .await
            .map_err(|_| BrowserError::WsUrlTimeout { secs: TIMEOUT_SECS })??;

        tracing::info!("[dig2browser] DevTools WS: {}", ws_url);

        // 7. Connect chromiumoxide.
        let (browser, mut handler) = Browser::connect(&ws_url)
            .await
            .map_err(|e| BrowserError::Connect(e.to_string()))?;

        // 8. Spawn the CDP event-handler task.
        let handler_task = tokio::spawn(async move {
            while let Some(event) = handler.next().await {
                if let Err(e) = event {
                    tracing::debug!("[dig2browser] CDP handler: {e}");
                }
            }
        });

        Ok(Self {
            browser,
            _handler: handler_task,
            _process: Some(child),
            profile_dir,
            stealth,
        })
    }

    /// Open a new page, inject stealth scripts, then navigate to `url`.
    pub async fn new_page(&self, url: &str) -> Result<StealthPage, BrowserError> {
        let page = self
            .browser
            .new_page("about:blank")
            .await
            .map_err(|e| BrowserError::Cdp(e.to_string()))?;

        stealth::inject_stealth(&page, &self.stealth).await?;

        page.goto(url)
            .await
            .map_err(|e| BrowserError::Navigate {
                url: url.into(),
                detail: e.to_string(),
            })?;

        Ok(StealthPage::new(page))
    }

    /// Open a new blank page with stealth scripts injected (no navigation).
    pub async fn new_blank_page(&self) -> Result<StealthPage, BrowserError> {
        let page = self
            .browser
            .new_page("about:blank")
            .await
            .map_err(|e| BrowserError::Cdp(e.to_string()))?;

        stealth::inject_stealth(&page, &self.stealth).await?;

        Ok(StealthPage::new(page))
    }

    /// Close the browser and, if the profile was ephemeral, delete its directory.
    pub async fn close(mut self) -> Result<(), BrowserError> {
        self.browser
            .close()
            .await
            .map_err(|e| BrowserError::Cdp(e.to_string()))?;

        // Kill child process so we don't leave zombies.
        if let Some(mut child) = self._process.take() {
            let _ = child.kill().await;
        }

        if self.profile_dir.is_ephemeral() {
            // Best effort — ignore errors.
            let _ = tokio::fs::remove_dir_all(self.profile_dir.path()).await;
        }

        Ok(())
    }
}

impl Drop for StealthBrowser {
    fn drop(&mut self) {
        // Best-effort kill: if the process is still alive when the struct is
        // dropped without an explicit close() call, terminate it immediately.
        if let Some(child) = self._process.as_mut() {
            let _ = child.start_kill();
        }
    }
}
