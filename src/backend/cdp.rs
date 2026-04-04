//! Chrome/Edge CDP backend extracted from `browser.rs`.
//!
//! `CdpBrowser` owns the OS process, CDP connection, and profile directory.
//! All logic is identical to the original `StealthBrowser` internals — this
//! is a pure structural refactor with zero behavioral change.

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicU32, Ordering};

use chromiumoxide::Browser;
use chromiumoxide::cdp::browser_protocol::emulation::SetTimezoneOverrideParams;
use futures::StreamExt;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Child;

use crate::browser_args::LaunchConfig;
use crate::browser_detect::detect_browser;
use crate::error::BrowserError;
use crate::stealth::StealthConfig;

// ---------------------------------------------------------------------------
// Profile dir helper
// ---------------------------------------------------------------------------

pub(crate) enum ProfileDir {
    Ephemeral(PathBuf),
    Persistent(PathBuf),
}

impl ProfileDir {
    pub(crate) fn path(&self) -> &PathBuf {
        match self {
            Self::Ephemeral(p) | Self::Persistent(p) => p,
        }
    }

    pub(crate) fn is_ephemeral(&self) -> bool {
        matches!(self, Self::Ephemeral(_))
    }
}

// ---------------------------------------------------------------------------
// CdpBrowser
// ---------------------------------------------------------------------------

/// Chrome/Edge browser instance managed via the CDP protocol.
///
/// Owns the OS child process, CDP handler task, profile directory, and page
/// counter. Extracted verbatim from `StealthBrowser` — zero behavioral change.
pub(crate) struct CdpBrowser {
    pub(crate) browser: Browser,
    pub(crate) _handler: tokio::task::JoinHandle<()>,
    pub(crate) _process: Option<Child>,
    pub(crate) profile_dir: ProfileDir,
    pub(crate) stealth: StealthConfig,
    pub(crate) launch: LaunchConfig,
    pub(crate) page_count: AtomicU32,
}

impl CdpBrowser {
    /// Launch a Chrome/Edge process and connect via CDP.
    pub(crate) async fn launch(
        launch: &LaunchConfig,
        stealth: &StealthConfig,
    ) -> Result<Self, BrowserError> {
        let (browser, _handler, _process, profile_dir) =
            Self::do_launch(launch, stealth).await?;

        Ok(Self {
            browser,
            _handler,
            _process,
            profile_dir,
            stealth: stealth.clone(),
            launch: launch.clone(),
            page_count: AtomicU32::new(0),
        })
    }

    /// Open a new CDP page at `about:blank`.
    pub(crate) async fn new_page(
        &self,
        url: &str,
    ) -> Result<chromiumoxide::Page, BrowserError> {
        let page = self
            .browser
            .new_page("about:blank")
            .await
            .map_err(|e| BrowserError::Cdp(e.to_string()))?;

        crate::stealth::inject_stealth_cdp(&page, &self.stealth).await?;
        apply_cdp_overrides(&page, &self.stealth).await;

        page.goto(url)
            .await
            .map_err(|e| BrowserError::Navigate {
                url: url.into(),
                detail: e.to_string(),
            })?;

        Ok(page)
    }

    /// Open a new CDP page at `about:blank` without navigation.
    pub(crate) async fn new_blank_page(&self) -> Result<chromiumoxide::Page, BrowserError> {
        let page = self
            .browser
            .new_page("about:blank")
            .await
            .map_err(|e| BrowserError::Cdp(e.to_string()))?;

        crate::stealth::inject_stealth_cdp(&page, &self.stealth).await?;
        apply_cdp_overrides(&page, &self.stealth).await;

        Ok(page)
    }

    /// Kill current process and re-launch with the same config.
    pub(crate) async fn restart(&mut self) -> Result<(), BrowserError> {
        if let Err(e) = self.browser.close().await {
            tracing::warn!("[dig2browser/cdp] browser.close() during restart: {e}");
        }
        if let Some(mut child) = self._process.take() {
            let _ = child.kill().await;
        }
        self._handler.abort();

        if self.profile_dir.is_ephemeral() {
            let _ = tokio::fs::remove_dir_all(self.profile_dir.path()).await;
        }

        let (browser, handler, process, profile_dir) =
            Self::do_launch(&self.launch, &self.stealth).await?;

        self.browser = browser;
        self._handler = handler;
        self._process = process;
        self.profile_dir = profile_dir;
        self.page_count.store(0, Ordering::Relaxed);

        Ok(())
    }

    /// Close the browser gracefully and remove ephemeral profile.
    pub(crate) async fn close(mut self) -> Result<(), BrowserError> {
        self.browser
            .close()
            .await
            .map_err(|e| BrowserError::Cdp(e.to_string()))?;

        if let Some(mut child) = self._process.take() {
            let _ = child.kill().await;
        }

        if self.profile_dir.is_ephemeral() {
            let _ = tokio::fs::remove_dir_all(self.profile_dir.path()).await;
        }

        Ok(())
    }

    pub(crate) fn page_count(&self) -> u32 {
        self.page_count.load(Ordering::Relaxed)
    }

    pub(crate) fn increment_page_count(&self) {
        self.page_count.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn needs_restart(&self) -> bool {
        let threshold = self.launch.restart_after_pages;
        threshold > 0 && self.page_count.load(Ordering::Relaxed) >= threshold
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    async fn do_launch(
        launch: &LaunchConfig,
        stealth: &StealthConfig,
    ) -> Result<
        (
            Browser,
            tokio::task::JoinHandle<()>,
            Option<Child>,
            ProfileDir,
        ),
        BrowserError,
    > {
        let binary = detect_browser(launch.browser_pref)?;

        let (profile_path, is_ephemeral) = launch.profile.resolve()?;
        let profile_dir = if is_ephemeral {
            ProfileDir::Ephemeral(profile_path.clone())
        } else {
            ProfileDir::Persistent(profile_path.clone())
        };

        let port = launch.debug_port.unwrap_or_else(LaunchConfig::find_free_port);

        let locale = stealth.locale.locale.as_str();
        let args = launch.build_args(&profile_path, port, Some(locale));

        tracing::info!(
            "[dig2browser] Launching {:?} binary={} port={} profile={} args_count={}",
            binary.kind,
            binary.path.display(),
            port,
            profile_path.display(),
            args.len()
        );
        tracing::info!("[dig2browser] Args: {:?}", &args[..args.len().min(10)]);

        let mut child = tokio::process::Command::new(&binary.path)
            .args(&args)
            .stderr(Stdio::piped())
            .stdout(Stdio::null())
            .stdin(Stdio::null())
            .spawn()
            .map_err(|e| {
                tracing::error!("[dig2browser] Failed to spawn browser: {e}");
                BrowserError::Launch(e)
            })?;

        let child_id = child.id();
        tracing::info!("[dig2browser] Browser process spawned, PID={:?}", child_id);

        let stderr = child.stderr.take().ok_or_else(|| {
            BrowserError::Connect("No stderr pipe from browser process".to_string())
        })?;
        let mut lines = BufReader::new(stderr).lines();

        const TIMEOUT_SECS: u64 = 15;
        let ws_url =
            tokio::time::timeout(std::time::Duration::from_secs(TIMEOUT_SECS), async {
                while let Ok(Some(line)) = lines.next_line().await {
                    tracing::info!("[dig2browser] stderr: {}", line);
                    if let Some(idx) = line.find("ws://") {
                        let ws = line[idx..].trim().to_string();
                        if ws.contains("devtools/browser") {
                            return Ok(ws);
                        }
                    }
                }
                let status = child.try_wait();
                tracing::error!(
                    "[dig2browser] Browser stderr closed. Process status: {:?}",
                    status
                );
                Err(BrowserError::Connect(
                    "Browser stderr closed without a DevTools WebSocket URL".to_string(),
                ))
            })
            .await
            .map_err(|_| {
                tracing::error!("[dig2browser] Timed out waiting {}s for WS URL", TIMEOUT_SECS);
                BrowserError::WsUrlTimeout { secs: TIMEOUT_SECS }
            })??;

        tracing::info!("[dig2browser] DevTools WS: {}", ws_url);

        let (browser, mut handler) = Browser::connect(&ws_url)
            .await
            .map_err(|e| BrowserError::Connect(e.to_string()))?;

        let handler_task = tokio::spawn(async move {
            while let Some(event) = handler.next().await {
                if let Err(e) = event {
                    tracing::debug!("[dig2browser] CDP handler: {e}");
                }
            }
        });

        Ok((browser, handler_task, Some(child), profile_dir))
    }
}

/// Apply CDP-level overrides that cannot be patched reliably with JS alone.
///
/// Currently handles `Emulation.setTimezoneOverride`. Failures are logged and
/// ignored — a page without these overrides is still usable.
pub(crate) async fn apply_cdp_overrides(
    page: &chromiumoxide::Page,
    stealth: &StealthConfig,
) {
    if let Some(tz) = &stealth.locale.timezone {
        let params = SetTimezoneOverrideParams::new(tz.clone());
        if let Err(e) = page.execute(params).await {
            tracing::warn!("[dig2browser] setTimezoneOverride failed: {e}");
        }
    }
}

impl Drop for CdpBrowser {
    fn drop(&mut self) {
        if let Some(child) = self._process.as_mut() {
            let _ = child.start_kill();
        }
    }
}
