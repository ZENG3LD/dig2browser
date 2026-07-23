//! CDP (Chrome DevTools Protocol) backend for StealthBrowser.
//!
//! Spawns a Chrome/Edge process, connects through an inherited pipe by default
//! on Windows (or an explicit WebSocket compatibility endpoint), and provides
//! BrowserBackend + PageBackend implementations using dig2browser-cdp.

use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicBool, AtomicU32, Ordering},
    Arc,
};
#[cfg(windows)]
use std::sync::Mutex as StdMutex;

use base64::Engine;
use futures::future::BoxFuture;
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, BufReader};
#[cfg(windows)]
use tokio::io::AsyncReadExt;
#[cfg(all(windows, feature = "containment-test-hooks"))]
use tokio::io::AsyncWriteExt;
use tokio::sync::{oneshot, Mutex};
use tokio::task::JoinHandle;
use tracing::debug;

use crate::agentic::NavigationPolicy;
use crate::cdp::{CdpClient, CdpError, CdpSession};
use crate::cookies::Cookie;
use crate::detect::args::BrowserProfile;
use crate::detect::version::browser_version;
use crate::detect::{LaunchConfig, detect_browser};
use crate::identity::ProfileOwnershipGuard;
use crate::process_isolation::BrowserProcessIsolation;
use crate::browser_process::BrowserProcess;
#[cfg(windows)]
use crate::browser_process::PreparedWindowsCdpProcess;
use crate::process_tree::OwnedProcessTree;
use crate::stealth::{StealthConfig, get_scripts};

use crate::browser::devtools::DevToolsEvent;
use crate::browser::error::BrowserError;
use super::{BrowserBackend, BoundingBox, ElementHandle, ElementInner, PageBackend, PrintOptions};

// ── Process handle ─────────────────────────────────────────────────────────

/// Internal state for a running CDP browser process.
pub(crate) struct CdpBrowserBackend {
    client: Arc<CdpClient>,
    root: CdpSession,
    launch: LaunchConfig,
    stealth: StealthConfig,
    page_count: AtomicU32,
    exact_policy_claimed: Arc<AtomicBool>,
    browser_closing: Arc<AtomicBool>,
    /// Child process — `Some` when we launched the browser ourselves, `None`
    /// in attach mode (we must not kill a browser the user opened manually).
    _child: Option<BrowserProcess>,
    /// Kernel-owned containment for the complete launched Chromium tree.
    _process_tree: Option<Arc<OwnedProcessTree>>,
    /// Continuous browser stderr drain for owned pipe-controlled launches.
    _stderr_task: Option<JoinHandle<()>>,
    /// Profile dir path, deleted on drop if ephemeral.
    profile_dir: std::path::PathBuf,
    profile_ephemeral: bool,
    /// Exclusive owner token for persistent profiles.
    _profile_guard: Option<ProfileOwnershipGuard>,
    #[cfg(feature = "containment-test-hooks")]
    test_close_delay: Option<std::time::Duration>,
}

#[cfg(feature = "containment-test-hooks")]
const INTERNAL_TEST_CLOSE_DELAY_PREFIX: &str =
    "--dig2browser-internal-test-cdp-close-delay-ms=";

struct CdpDiscovery {
    ws_url: String,
    browser_product: Option<String>,
}

struct EphemeralProfileCleanup {
    path: std::path::PathBuf,
    armed: bool,
}

#[cfg(windows)]
#[derive(Clone)]
struct BoundedStderrCapture {
    bytes: Arc<StdMutex<Vec<u8>>>,
}

#[cfg(windows)]
impl BoundedStderrCapture {
    const MAX_BYTES: usize = 64 * 1024;

    fn new() -> Self {
        Self {
            bytes: Arc::new(StdMutex::new(Vec::new())),
        }
    }

    fn append(&self, chunk: &[u8]) {
        let Ok(mut bytes) = self.bytes.lock() else {
            return;
        };
        if chunk.len() >= Self::MAX_BYTES {
            bytes.clear();
            bytes.extend_from_slice(&chunk[chunk.len() - Self::MAX_BYTES..]);
            return;
        }
        let overflow = bytes
            .len()
            .saturating_add(chunk.len())
            .saturating_sub(Self::MAX_BYTES);
        if overflow != 0 {
            bytes.drain(..overflow);
        }
        bytes.extend_from_slice(chunk);
    }

    fn snapshot(&self) -> String {
        self.bytes
            .lock()
            .map(|bytes| String::from_utf8_lossy(&bytes).trim().to_owned())
            .unwrap_or_default()
    }
}

impl EphemeralProfileCleanup {
    fn new(path: std::path::PathBuf, armed: bool) -> Self {
        Self { path, armed }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

#[cfg(all(windows, feature = "containment-test-hooks"))]
async fn record_test_browser_lifecycle(
    event: &'static str,
    detail: serde_json::Value,
) {
    let Some(path) = std::env::var_os("DIG2BROWSER_BROWSER_LIFECYCLE_LOG") else {
        return;
    };
    if path.is_empty() {
        return;
    }
    let frame = serde_json::json!({
        "at_unix_ms": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64,
        "event": event,
        "detail": detail,
    });
    let mut encoded = match serde_json::to_vec(&frame) {
        Ok(encoded) => encoded,
        Err(error) => {
            debug!(%error, event, "browser lifecycle diagnostic serialization failed");
            return;
        }
    };
    encoded.push(b'\n');
    let mut log = match tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
    {
        Ok(log) => log,
        Err(error) => {
            debug!(%error, event, "browser lifecycle diagnostic open failed");
            return;
        }
    };
    if let Err(error) = log.write_all(&encoded).await {
        debug!(%error, event, "browser lifecycle diagnostic write failed");
    }
}

impl Drop for EphemeralProfileCleanup {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

fn product_version(product: &str) -> Option<&str> {
    let (_, version) = product.split_once('/')?;
    (!version.is_empty()
        && version
            .chars()
            .all(|character| character.is_ascii_digit() || character == '.'))
    .then_some(version)
}

impl Drop for CdpBrowserBackend {
    fn drop(&mut self) {
        // Only kill/clean-up when we own the child (launch mode).
        if let Some(ref mut child) = self._child {
            // kill_on_drop(true) handles the common case, but start_kill() here
            // acts as a safety net for any edge case where the Child's drop
            // behaviour might not fire (e.g. if Child was somehow replaced).
            // start_kill() is non-blocking — it sends the signal without waiting.
            let _ = child.start_kill();
        }
        if let Some(process_tree) = self._process_tree.as_ref() {
            let _ = process_tree.terminate_now();
        }
        if let Some(task) = self._stderr_task.take() {
            task.abort();
        }
        if self.profile_ephemeral {
            let _ = std::fs::remove_dir_all(&self.profile_dir);
        }
    }
}

#[cfg(windows)]
const PROCESS_SINGLETON_LOCK_EXIT_CODE: i32 = 21;

/// A single owned-pipe launch attempt failed. `singleton_lock_contention`
/// is set when the failure signature matches Chromium's `ProcessSingleton`
/// lock-creation failure (exit code 21 / "Lock file can not be created" /
/// Windows `ERROR_SHARING_VIOLATION`, raw code 32) — evidence that a prior
/// launch attempt on the same profile directory had not yet released its
/// lock when this attempt started. That condition is transient, not a
/// terminal launch failure.
#[cfg(windows)]
struct LaunchAttemptError {
    error: BrowserError,
    singleton_lock_contention: bool,
}

#[cfg(windows)]
impl LaunchAttemptError {
    fn terminal(error: BrowserError) -> Self {
        Self {
            error,
            singleton_lock_contention: false,
        }
    }

    fn from_signature(error: BrowserError, stderr: &str, exit_code: Option<i32>) -> Self {
        let singleton_lock_contention = exit_code == Some(PROCESS_SINGLETON_LOCK_EXIT_CODE)
            || stderr.contains("Lock file can not be created")
            || stderr.contains("ProcessSingleton for your profile directory");
        Self {
            error,
            singleton_lock_contention,
        }
    }
}

impl CdpBrowserBackend {
    /// Spawn a Chrome/Edge process and connect through the owned CDP transport.
    #[cfg(test)]
    pub(crate) async fn launch(
        launch: &LaunchConfig,
        stealth: &StealthConfig,
    ) -> Result<Self, BrowserError> {
        Self::launch_with_process_isolation(
            launch,
            stealth,
            &BrowserProcessIsolation::Native,
        )
        .await
    }

    pub(crate) async fn launch_with_process_isolation(
        launch: &LaunchConfig,
        stealth: &StealthConfig,
        process_isolation: &BrowserProcessIsolation,
    ) -> Result<Self, BrowserError> {
        #[cfg(feature = "containment-test-hooks")]
        let (launch, test_close_delay) = {
            let mut launch = launch.clone();
            let test_close_delay = take_containment_test_close_delay(&mut launch)?;
            (launch, test_close_delay)
        };
        #[cfg(not(feature = "containment-test-hooks"))]
        let launch = launch.clone();
        let launch = &launch;
        #[cfg(not(windows))]
        if !process_isolation.is_native() {
            return Err(BrowserError::Launch(
                "outer process isolation is unavailable on this platform".into(),
            ));
        }
        #[cfg(windows)]
        let binary = match process_isolation.browser_binary() {
            Some(binary) => {
                if !browser_kind_matches_preference(binary.kind, launch.browser_pref) {
                    return Err(BrowserError::Launch(format!(
                        "runtime mirror kind {:?} does not match browser preference {:?}",
                        binary.kind, launch.browser_pref
                    )));
                }
                binary.clone()
            }
            None => detect_browser(launch.browser_pref)?,
        };
        #[cfg(not(windows))]
        let binary = detect_browser(launch.browser_pref)?;
        let installed_version = browser_version(&binary);
        let (profile_dir, profile_ephemeral) = launch.profile.resolve()?;
        let mut profile_cleanup =
            EphemeralProfileCleanup::new(profile_dir.clone(), profile_ephemeral);
        let profile_guard = match &launch.profile {
            BrowserProfile::Persistent(_) => Some(
                ProfileOwnershipGuard::acquire(&profile_dir)
                    .map_err(|error| BrowserError::Launch(error.to_string()))?,
            ),
            BrowserProfile::Ephemeral => None,
        };
        let locale = Some(stealth.locale.locale.as_str());
        let process_tree = Arc::new(
            OwnedProcessTree::new()
                .map_err(|error| BrowserError::Launch(error.to_string()))?,
        );

        #[cfg(windows)]
        let (client, child, stderr_task, browser_product) = {
            if let Some(port) = launch.debug_port {
                if !process_isolation.is_native() {
                        return Err(BrowserError::Launch(
                            "a station-owned runtime mirror requires the owned CDP pipe transport".into(),
                        ));
                }
                let args = launch.build_args(&profile_dir, port, locale);
                debug!(
                    "Launching CDP browser: {} with {} args on explicit port {}",
                    binary.path.display(),
                    args.len(),
                    port
                );
                let mut child = tokio::process::Command::new(&binary.path)
                    .args(&args)
                    .stderr(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::null())
                    .stdin(std::process::Stdio::null())
                    .kill_on_drop(true)
                    .spawn()
                    .map_err(|error| BrowserError::Launch(error.to_string()))?;
                let raw_handle = child.raw_handle().ok_or_else(|| {
                    BrowserError::Launch("child process handle is unavailable".into())
                })?;
                if let Err(error) = process_tree.assign_raw_handle(raw_handle) {
                    let _ = child.start_kill();
                    return Err(BrowserError::Launch(format!(
                        "could not contain browser process tree: {error}"
                    )));
                }
                let stderr = match child.stderr.take() {
                    Some(stderr) => stderr,
                    None => {
                        let _ = process_tree.terminate_now();
                        let _ = child.start_kill();
                        return Err(BrowserError::Launch(
                            "could not capture stderr".into(),
                        ));
                    }
                };
                let discovery = match Self::discover_launched_browser(
                    stderr,
                    &mut child,
                    port,
                )
                .await
                {
                    Ok(discovery) => discovery,
                    Err(error) => {
                        let _ = process_tree.terminate_now();
                        let _ = child.start_kill();
                        return Err(error);
                    }
                };
                debug!("CDP WebSocket URL: {}", discovery.ws_url);
                let client = match CdpClient::connect(&discovery.ws_url).await {
                    Ok(client) => client,
                    Err(error) => {
                        let _ = process_tree.terminate_now();
                        let _ = child.start_kill();
                        return Err(BrowserError::Connect(error.to_string()));
                    }
                };
                (
                    client,
                    BrowserProcess::from_tokio(child),
                    None,
                    discovery.browser_product,
                )
            } else {
                let (client, process, stderr_task, browser_product) =
                    Self::launch_owned_pipe_with_lock_retry(
                        &process_tree,
                        &binary.path,
                        launch,
                        &profile_dir,
                        locale,
                    )
                    .await?;
                (client, process, Some(stderr_task), browser_product)
            }
        };

        #[cfg(not(windows))]
        let (client, child, stderr_task, browser_product) = {
            let port = launch.debug_port.unwrap_or_else(LaunchConfig::find_free_port);
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
                .kill_on_drop(true)
                .spawn()
                .map_err(|error| BrowserError::Launch(error.to_string()))?;
            if let Err(error) = process_tree.assign(&child) {
                let _ = child.start_kill();
                return Err(BrowserError::Launch(format!(
                    "could not contain browser process tree: {error}"
                )));
            }
            let stderr = child
                .stderr
                .take()
                .ok_or_else(|| BrowserError::Launch("could not capture stderr".into()))?;
            let discovery = Self::discover_launched_browser(stderr, &mut child, port).await?;
            debug!("CDP WebSocket URL: {}", discovery.ws_url);
            let client = CdpClient::connect(&discovery.ws_url)
                .await
                .map_err(|error| BrowserError::Connect(error.to_string()))?;
            (
                client,
                BrowserProcess::from_tokio(child),
                None,
                discovery.browser_product,
            )
        };

        let root = client.root_session();
        let runtime_version = browser_product
            .as_deref()
            .and_then(product_version)
            .or(installed_version.as_deref());
        let user_agent = stealth.resolve_user_agent(binary.kind, runtime_version);
        let mut resolved_stealth = stealth.clone();
        resolved_stealth.user_agent = user_agent.user_agent;

        let backend = Self {
            client,
            root,
            launch: launch.clone(),
            stealth: resolved_stealth,
            page_count: AtomicU32::new(0),
            exact_policy_claimed: Arc::new(AtomicBool::new(false)),
            browser_closing: Arc::new(AtomicBool::new(false)),
            _child: Some(child),
            _process_tree: Some(process_tree),
            _stderr_task: stderr_task,
            profile_dir,
            profile_ephemeral,
            _profile_guard: profile_guard,
            #[cfg(feature = "containment-test-hooks")]
            test_close_delay,
        };
        profile_cleanup.disarm();
        Ok(backend)
    }

    /// Attach to an already-running Chrome/Edge that was launched with
    /// `--remote-debugging-port=NNNN`. Connect to a browser-level WebSocket
    /// directly (obtain it via [`discover_ws_url`] first).
    ///
    /// Attach mode never kills the user's browser when this backend is dropped.
    pub(crate) async fn attach(
        ws_url: String,
        launch: LaunchConfig,
        stealth: StealthConfig,
    ) -> Result<Self, BrowserError> {
        let client = CdpClient::connect(&ws_url)
            .await
            .map_err(|e| BrowserError::Connect(e.to_string()))?;
        let root = client.root_session();
        Ok(Self {
            client,
            root,
            launch,
            stealth,
            page_count: AtomicU32::new(0),
            exact_policy_claimed: Arc::new(AtomicBool::new(false)),
            browser_closing: Arc::new(AtomicBool::new(false)),
            _child: None, // not our child — do not kill on drop
            _process_tree: None,
            _stderr_task: None,
            profile_dir: std::path::PathBuf::new(),
            profile_ephemeral: false,
            _profile_guard: None,
            #[cfg(feature = "containment-test-hooks")]
            test_close_delay: None,
        })
    }

    /// List all open page targets (tabs). Returns `(target_id, url, title)`
    /// triples.
    pub(crate) async fn list_pages(&self) -> Result<Vec<(String, String, String)>, BrowserError> {
        let targets = self
            .root
            .get_targets()
            .await
            .map_err(|e| BrowserError::Connect(e.to_string()))?;
        Ok(targets
            .into_iter()
            .filter(|t| t.r#type == "page")
            .map(|t| (t.target_id, t.url, t.title))
            .collect())
    }

    /// Attach to an existing page target (open tab) by its `target_id`.
    ///
    /// Applies the same CDP-native stealth overrides as `open_page` (UA/
    /// Client Hints, timezone, device metrics) — those are protocol-level and
    /// take effect on the next navigation/paint regardless of when the
    /// session attached. It does **not** run the JS-injected stealth scripts
    /// (`add_script_on_new_document`): those only apply to documents created
    /// after they are registered on a session, and this session did not exist
    /// when the popup's current document loaded, so re-registering them here
    /// would not retroactively patch the already-loaded page. Known
    /// limitation of attaching to an already-running page (e.g. a
    /// `SwitchToTab` target) rather than one this backend opened itself.
    pub(crate) async fn attach_to_existing_page(
        &self,
        target_id: &str,
    ) -> Result<CdpPageBackend, BrowserError> {
        let session_id = self
            .root
            .attach_to_target(target_id)
            .await
            .map_err(|e| BrowserError::Connect(e.to_string()))?;

        let session = CdpSession::with_session_id(session_id, Arc::clone(&self.client));

        // Enable required domains so events and eval work.
        session
            .call("Page.enable", None)
            .await
            .map_err(|e| BrowserError::Connect(e.to_string()))?;
        session
            .call("Network.enable", None)
            .await
            .map_err(|e| BrowserError::Connect(e.to_string()))?;
        session
            .call("Runtime.enable", None)
            .await
            .map_err(|e| BrowserError::Connect(e.to_string()))?;

        // Never let a page dialog block the (already running) renderer.
        let dialog_task = spawn_dialog_auto_handler(&session);

        let download = setup_download_capture(&session, target_id).await?;

        // CDP-native stealth overrides — see the doc comment above for why
        // this does NOT cover the JS-injected scripts `open_page` also runs.
        apply_cdp_native_stealth(&session, &self.stealth).await?;

        self.page_count.fetch_add(1, Ordering::Relaxed);

        Ok(CdpPageBackend::new(
            session,
            target_id.to_owned(),
            Arc::clone(&self.exact_policy_claimed),
            Arc::clone(&self.browser_closing),
            None,
            dialog_task,
            download,
        ))
    }

    #[cfg(windows)]
    fn spawn_stderr_logger(
        mut stderr: tokio::fs::File,
    ) -> (JoinHandle<()>, BoundedStderrCapture) {
        let capture = BoundedStderrCapture::new();
        let task_capture = capture.clone();
        let task = tokio::spawn(async move {
            #[cfg(feature = "containment-test-hooks")]
            let mut diagnostic_log = match std::env::var_os("DIG2BROWSER_BROWSER_STDERR_LOG") {
                Some(path) if !path.is_empty() => tokio::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .await
                    .ok(),
                _ => None,
            };
            let mut buffer = [0_u8; 8 * 1024];
            loop {
                match stderr.read(&mut buffer).await {
                    Ok(0) => break,
                    Ok(count) => {
                        task_capture.append(&buffer[..count]);
                        #[cfg(feature = "containment-test-hooks")]
                        if let Some(log) = diagnostic_log.as_mut() {
                            if let Err(error) = log.write_all(&buffer[..count]).await {
                                debug!(%error, "browser stderr diagnostic logger stopped");
                                diagnostic_log = None;
                            }
                        }
                        let chunk = String::from_utf8_lossy(&buffer[..count]);
                        debug!("browser stderr: {chunk}");
                    }
                    Err(error) => {
                        debug!(%error, "browser stderr reader stopped");
                        break;
                    }
                }
            }
        });
        (task, capture)
    }

    #[cfg(windows)]
    async fn finish_stderr_capture(
        task: &mut JoinHandle<()>,
        capture: &BoundedStderrCapture,
    ) -> String {
        if tokio::time::timeout(std::time::Duration::from_millis(250), &mut *task)
            .await
            .is_err()
        {
            task.abort();
        }
        capture.snapshot()
    }

    /// Returns a human-readable status string alongside the raw exit code
    /// (when available), so callers can match launch-failure signatures
    /// like Chromium's `ProcessSingleton` lock error (exit code 21)
    /// without re-parsing the display string.
    #[cfg(windows)]
    async fn process_status_context(process: &mut BrowserProcess) -> (String, Option<i32>) {
        match tokio::time::timeout(
            std::time::Duration::from_millis(250),
            process.wait(),
        )
        .await
        {
            Ok(Ok(status)) => (status.to_string(), status.code()),
            Ok(Err(error)) => (format!("status unavailable: {error}"), None),
            Err(_) => ("still running after pipe closure".to_owned(), None),
        }
    }

    #[cfg(windows)]
    fn with_launch_context(message: String, stderr: String, status: String) -> String {
        if stderr.is_empty() {
            format!("{message}; browser process: {status}")
        } else {
            format!("{message}; browser process: {status}; browser stderr: {stderr}")
        }
    }

    /// Deterministically wait for a failed launch attempt's own process
    /// tree to fully exit (bounded) before returning control to the
    /// caller. Chromium's `ProcessSingleton` lock file for a profile
    /// directory is only released once the owning process has actually
    /// exited — sending a termination signal and returning immediately
    /// (the previous fire-and-forget behaviour) let an immediate
    /// same-profile relaunch race the OS teardown of this attempt.
    #[cfg(windows)]
    async fn drain_failed_launch_attempt(
        process_tree: &OwnedProcessTree,
        process: &mut BrowserProcess,
    ) {
        const DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
        if let Err(error) = process_tree.terminate_and_wait(DRAIN_TIMEOUT).await {
            debug!(
                %error,
                "failed browser launch attempt did not fully drain its process tree within the bounded timeout"
            );
        }
        // Safety net: non-blocking and a no-op once the process has exited.
        let _ = process.start_kill();
    }

    /// Perform exactly one owned-pipe Chromium launch attempt against an
    /// already-created (and possibly reused) process-tree containment.
    /// Every failure path deterministically drains its own process before
    /// returning, so a caller may safely retry on the same profile
    /// directory once this returns.
    #[cfg(windows)]
    async fn attempt_owned_pipe_launch(
        process_tree: &OwnedProcessTree,
        binary_path: &std::path::Path,
        launch: &LaunchConfig,
        profile_dir: &std::path::Path,
        locale: Option<&str>,
    ) -> Result<(Arc<CdpClient>, BrowserProcess, JoinHandle<()>, Option<String>), LaunchAttemptError> {
        let prepared = PreparedWindowsCdpProcess::new().map_err(|error| {
            LaunchAttemptError::terminal(BrowserError::Launch(error.to_string()))
        })?;
        let (browser_read, browser_write) = prepared.child_cdp_handles().map_err(|error| {
            LaunchAttemptError::terminal(BrowserError::Launch(error.to_string()))
        })?;
        let args = launch.build_pipe_args(profile_dir, locale, browser_read, browser_write);
        debug!(
            "Launching CDP browser: {} with {} args over owned ASCIIZ pipes",
            binary_path.display(),
            args.len()
        );
        let mut spawned = prepared.spawn_suspended(binary_path, &args).map_err(|error| {
            LaunchAttemptError::terminal(BrowserError::Launch(error.to_string()))
        })?;
        if let Err(error) = process_tree.assign_raw_handle(spawned.process.raw_handle()) {
            let _ = spawned.process.start_kill();
            return Err(LaunchAttemptError::terminal(BrowserError::Launch(format!(
                "could not contain browser process tree: {error}"
            ))));
        }
        if let Err(error) = spawned.process.resume() {
            Self::drain_failed_launch_attempt(process_tree, &mut spawned.process).await;
            return Err(LaunchAttemptError::terminal(BrowserError::Launch(format!(
                "could not resume contained browser process: {error}"
            ))));
        }
        let (mut stderr_task, stderr_capture) = Self::spawn_stderr_logger(spawned.stderr);
        let client = match CdpClient::connect_pipe(spawned.cdp_reader, spawned.cdp_writer).await {
            Ok(client) => client,
            Err(error) => {
                let stderr =
                    Self::finish_stderr_capture(&mut stderr_task, &stderr_capture).await;
                let (status, exit_code) =
                    Self::process_status_context(&mut spawned.process).await;
                Self::drain_failed_launch_attempt(process_tree, &mut spawned.process).await;
                let message =
                    Self::with_launch_context(error.to_string(), stderr.clone(), status);
                return Err(LaunchAttemptError::from_signature(
                    BrowserError::Connect(message),
                    &stderr,
                    exit_code,
                ));
            }
        };
        let root = client.root_session();
        let version = match tokio::time::timeout(
            std::time::Duration::from_secs(30),
            root.call("Browser.getVersion", None),
        )
        .await
        {
            Ok(Ok(version)) => version,
            Ok(Err(error)) => {
                let stderr =
                    Self::finish_stderr_capture(&mut stderr_task, &stderr_capture).await;
                let (status, exit_code) =
                    Self::process_status_context(&mut spawned.process).await;
                Self::drain_failed_launch_attempt(process_tree, &mut spawned.process).await;
                let message =
                    Self::with_launch_context(error.to_string(), stderr.clone(), status);
                return Err(LaunchAttemptError::from_signature(
                    BrowserError::Connect(message),
                    &stderr,
                    exit_code,
                ));
            }
            Err(_) => {
                let stderr =
                    Self::finish_stderr_capture(&mut stderr_task, &stderr_capture).await;
                let (status, exit_code) =
                    Self::process_status_context(&mut spawned.process).await;
                Self::drain_failed_launch_attempt(process_tree, &mut spawned.process).await;
                let message = Self::with_launch_context(
                    "timed out waiting for the CDP pipe".to_owned(),
                    stderr.clone(),
                    status,
                );
                return Err(LaunchAttemptError::from_signature(
                    BrowserError::Connect(message),
                    &stderr,
                    exit_code,
                ));
            }
        };
        let browser_product = version["product"].as_str().map(str::to_owned);
        Ok((client, spawned.process, stderr_task, browser_product))
    }

    /// Launch over owned pipes with a bounded retry when the failure
    /// signature matches Chromium's `ProcessSingleton` lock-creation error.
    /// That lock is transient: it clears once the prior attempt's process
    /// tree — deterministically drained inside
    /// [`Self::attempt_owned_pipe_launch`] — has fully exited. The retry is
    /// bounded to a small total budget so a genuinely (not transiently)
    /// locked profile still fails closed with a clear typed error instead
    /// of looping unbounded.
    #[cfg(windows)]
    async fn launch_owned_pipe_with_lock_retry(
        process_tree: &OwnedProcessTree,
        binary_path: &std::path::Path,
        launch: &LaunchConfig,
        profile_dir: &std::path::Path,
        locale: Option<&str>,
    ) -> Result<(Arc<CdpClient>, BrowserProcess, JoinHandle<()>, Option<String>), BrowserError> {
        const RETRY_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);
        const RETRY_POLL: std::time::Duration = std::time::Duration::from_millis(100);

        let deadline = tokio::time::Instant::now() + RETRY_BUDGET;
        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            match Self::attempt_owned_pipe_launch(
                process_tree,
                binary_path,
                launch,
                profile_dir,
                locale,
            )
            .await
            {
                Ok(result) => return Ok(result),
                Err(failure)
                    if failure.singleton_lock_contention
                        && tokio::time::Instant::now() < deadline =>
                {
                    debug!(
                        attempt,
                        profile = %profile_dir.display(),
                        "browser launch hit a Chromium ProcessSingleton lock still held by \
                         a prior launch attempt on this profile directory; retrying within \
                         the bounded budget"
                    );
                    #[cfg(feature = "containment-test-hooks")]
                    record_test_browser_lifecycle(
                        "process_singleton_lock_retry",
                        serde_json::json!({
                            "attempt": attempt,
                            "profile": profile_dir,
                        }),
                    )
                    .await;
                    tokio::time::sleep(RETRY_POLL).await;
                }
                Err(failure) => return Err(failure.error),
            }
        }
    }

    /// Poll the owned browser's loopback DevTools endpoint while retaining
    /// stderr as a secondary discovery channel.
    async fn discover_launched_browser(
        stderr: tokio::process::ChildStderr,
        child: &mut tokio::process::Child,
        port: u16,
    ) -> Result<CdpDiscovery, BrowserError> {
        let mut stderr_task = tokio::spawn(Self::find_ws_url_on_stderr(stderr));
        let mut stderr_open = true;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
        let mut last_endpoint_error: String;

        loop {
            if let Some(status) = child.try_wait().map_err(BrowserError::Io)? {
                stderr_task.abort();
                return Err(BrowserError::Launch(format!(
                    "browser exited before the DevTools endpoint became ready: {status}"
                )));
            }

            match tokio::time::timeout(
                std::time::Duration::from_millis(500),
                Self::query_devtools_endpoint(port),
            )
            .await
            {
                Ok(Ok(discovery)) => {
                    stderr_task.abort();
                    return Ok(discovery);
                }
                Ok(Err(error)) => last_endpoint_error = error.to_string(),
                Err(_) => last_endpoint_error = "endpoint request timed out".into(),
            }

            if stderr_open {
                tokio::select! {
                    result = &mut stderr_task => {
                        stderr_open = false;
                        if let Ok(Ok(Some(ws_url))) = result {
                            return Ok(CdpDiscovery {
                                ws_url,
                                browser_product: None,
                            });
                        }
                    }
                    _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {}
                }
            } else {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }

            if tokio::time::Instant::now() >= deadline {
                stderr_task.abort();
                return Err(BrowserError::Connect(format!(
                    "timed out waiting for DevTools endpoint on 127.0.0.1:{port}: {last_endpoint_error}"
                )));
            }
        }
    }

    async fn query_devtools_endpoint(port: u16) -> Result<CdpDiscovery, BrowserError> {
        let url = format!("http://127.0.0.1:{port}/json/version");
        let response = reqwest::get(&url)
            .await
            .map_err(|error| BrowserError::Connect(format!("GET {url}: {error}")))?
            .error_for_status()
            .map_err(|error| BrowserError::Connect(format!("GET {url}: {error}")))?;
        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|error| BrowserError::Connect(format!("parse {url}: {error}")))?;
        let ws_url = body
            .get("webSocketDebuggerUrl")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                BrowserError::Connect("no webSocketDebuggerUrl in /json/version".into())
            })?
            .to_owned();
        let browser_product = body
            .get("Browser")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        Ok(CdpDiscovery {
            ws_url,
            browser_product,
        })
    }

    /// Scan stderr until it closes or reports the DevTools WebSocket URL.
    async fn find_ws_url_on_stderr(
        stderr: tokio::process::ChildStderr,
    ) -> Result<Option<String>, std::io::Error> {
        let reader = BufReader::new(stderr);
        let mut lines = reader.lines();

        while let Some(line) = lines.next_line().await? {
            debug!("browser stderr: {line}");
            if let Some(pos) = line.find("ws://") {
                return Ok(Some(line[pos..].trim().to_owned()));
            }
        }
        Ok(None)
    }

    /// Create and attach to a new page target, inject stealth scripts, optionally navigate.
    async fn open_page(&self, url: Option<&str>) -> Result<CdpPageBackend, BrowserError> {
        // Always start as about:blank so we attach before any real navigation begins.
        let target_id = self
            .root
            .create_target("about:blank")
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

        // Answer JavaScript dialogs from now on — before navigate, so a dialog
        // fired during page load (which would block the load event and hang the
        // navigation) is handled rather than stalling the task.
        let dialog_task = spawn_dialog_auto_handler(&session);

        // Capture downloads from now on — before navigate, so a download
        // triggered immediately after load is not missed.
        let download = setup_download_capture(&session, &target_id).await?;

        // ── CDP-native stealth overrides ──────────────────────────────────────
        // These run at the protocol level and are more reliable than JS patching:
        // they survive property-descriptor inspection and also affect HTTP headers.
        apply_cdp_native_stealth(&session, &self.stealth).await?;

        // ── JS stealth scripts ────────────────────────────────────────────────
        // Injected after native overrides. Some overlap with the CDP calls above
        // but JS scripts cover properties that have no CDP equivalent (plugins,
        // permissions, WebGL, etc.) and serve as safety nets for the ones that do.
        let scripts = get_scripts(&self.stealth);
        for script in &scripts {
            session
                .add_script_on_new_document(script)
                .await
                .map_err(|e| BrowserError::StealthInject(e.to_string()))?;
        }

        // Navigate to the target URL and wait for the page to fully load.
        if let Some(nav_url) = url {
            session
                .navigate(nav_url)
                .await
                .map_err(|e| BrowserError::Navigate(e.to_string()))?;
        }

        self.page_count.fetch_add(1, Ordering::Relaxed);

        Ok(CdpPageBackend::new(
            session,
            target_id,
            Arc::clone(&self.exact_policy_claimed),
            Arc::clone(&self.browser_closing),
            self._process_tree.as_ref().map(Arc::clone),
            dialog_task,
            download,
        ))
    }
}

/// Apply the CDP-native stealth overrides (User-Agent + Client Hints,
/// timezone, device metrics) to a session. These run at the protocol level
/// and are more reliable than JS patching — they survive property-descriptor
/// inspection and also affect HTTP headers. Shared by `open_page` (a freshly
/// created target) and `attach_to_existing_page` (an already-open tab this
/// backend did not create, e.g. a `SwitchToTab` target); see the doc comment
/// on `attach_to_existing_page` for what this does **not** cover.
async fn apply_cdp_native_stealth(
    session: &CdpSession,
    stealth: &StealthConfig,
) -> Result<(), BrowserError> {
    // User-Agent + Client Hints: sets Sec-CH-UA* HTTP headers automatically.
    if let Some(profile) = stealth.resolved_profile_from_user_agent() {
        match (profile.brands(), profile.full_version_list()) {
            (Some(brands), Some(full_version_list)) => session
                .set_user_agent_with_metadata(
                    &profile.user_agent,
                    stealth.client_hints.platform(),
                    stealth.client_hints.platform_version(),
                    stealth.client_hints.architecture(),
                    stealth.client_hints.model(),
                    stealth.client_hints.mobile(),
                    &brands,
                    &full_version_list,
                )
                .await
                .map_err(|e| BrowserError::StealthInject(e.to_string()))?,
            _ => session
                .set_user_agent(&profile.user_agent)
                .await
                .map_err(|e| BrowserError::StealthInject(e.to_string()))?,
        }
    }

    // Timezone: fixes both Intl.DateTimeFormat AND new Date().toString().
    // The JS override_timezone script only fixes Intl, missing Date.toString().
    if let Some(tz) = &stealth.locale.timezone {
        session
            .set_timezone(tz)
            .await
            .map_err(|e| BrowserError::StealthInject(e.to_string()))?;
    }

    // Device metrics: screen dimensions + devicePixelRatio at browser level.
    // Also affects CSS media queries and visual viewport, unlike JS patching.
    let (vp_w, vp_h) = stealth.viewport;
    session
        .set_device_metrics(
            vp_w,
            vp_h,
            stealth.device_scale_factor.get(),
            stealth.client_hints.mobile(),
        )
        .await
        .map_err(|e| BrowserError::StealthInject(e.to_string()))?;

    Ok(())
}

async fn remove_profile_dir_with_retry(path: &std::path::Path) -> Result<usize, BrowserError> {
    const ATTEMPTS: usize = 20;
    const RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(100);

    for attempt in 0..ATTEMPTS {
        match tokio::fs::remove_dir_all(path).await {
            Ok(()) => return Ok(attempt + 1),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(attempt + 1);
            }
            Err(error) if attempt + 1 < ATTEMPTS => {
                debug!(
                    path = %path.display(),
                    attempt = attempt + 1,
                    max_attempts = ATTEMPTS,
                    %error,
                    "ephemeral browser profile cleanup is blocked"
                );
                #[cfg(all(windows, feature = "containment-test-hooks"))]
                record_test_browser_lifecycle(
                    "ephemeral_profile_cleanup_blocked",
                    serde_json::json!({
                        "attempt": attempt + 1,
                        "max_attempts": ATTEMPTS,
                        "profile": path,
                        "error": error.to_string(),
                        "os_error": error.raw_os_error(),
                    }),
                )
                .await;
                tokio::time::sleep(RETRY_DELAY).await;
            }
            Err(error) => {
                #[cfg(all(windows, feature = "containment-test-hooks"))]
                record_test_browser_lifecycle(
                    "ephemeral_profile_cleanup_failed",
                    serde_json::json!({
                        "attempt": attempt + 1,
                        "max_attempts": ATTEMPTS,
                        "profile": path,
                        "error": error.to_string(),
                        "os_error": error.raw_os_error(),
                    }),
                )
                .await;
                return Err(BrowserError::Other(format!(
                    "ephemeral browser profile cleanup failed for '{}' after {ATTEMPTS} attempts: {error}",
                    path.display()
                )));
            }
        }
    }
    unreachable!("profile cleanup attempts are non-zero")
}

#[cfg(feature = "containment-test-hooks")]
fn take_containment_test_close_delay(
    launch: &mut LaunchConfig,
) -> Result<Option<std::time::Duration>, BrowserError> {
    let mut retained = Vec::with_capacity(launch.extra_args.len());
    let mut delay = None;
    for argument in std::mem::take(&mut launch.extra_args) {
        let Some(value) = argument.strip_prefix(INTERNAL_TEST_CLOSE_DELAY_PREFIX) else {
            retained.push(argument);
            continue;
        };
        if delay.is_some() {
            return Err(BrowserError::Launch(
                "duplicate internal containment close-delay argument".into(),
            ));
        }
        let millis = value.parse::<u64>().map_err(|_| {
            BrowserError::Launch(
                "invalid internal containment close-delay argument".into(),
            )
        })?;
        if !(1..=60_000).contains(&millis) {
            return Err(BrowserError::Launch(
                "internal containment close delay is outside test bounds".into(),
            ));
        }
        delay = Some(std::time::Duration::from_millis(millis));
    }
    launch.extra_args = retained;
    Ok(delay)
}

#[cfg(windows)]
fn browser_kind_matches_preference(
    kind: crate::detect::BrowserKind,
    preference: crate::detect::BrowserPreference,
) -> bool {
    use crate::detect::{BrowserKind, BrowserPreference};
    match preference {
        BrowserPreference::Auto => matches!(
            kind,
            BrowserKind::Chrome | BrowserKind::Edge | BrowserKind::Chromium
        ),
        BrowserPreference::ChromeOnly => kind == BrowserKind::Chrome,
        BrowserPreference::EdgeOnly => kind == BrowserKind::Edge,
        BrowserPreference::Firefox => false,
    }
}

#[cfg(all(test, windows))]
mod runtime_mirror_kind_tests {
    use super::browser_kind_matches_preference;
    use crate::detect::{BrowserKind, BrowserPreference};

    #[test]
    fn runtime_mirror_kind_must_match_the_selected_backend() {
        assert!(browser_kind_matches_preference(
            BrowserKind::Chrome,
            BrowserPreference::ChromeOnly
        ));
        assert!(browser_kind_matches_preference(
            BrowserKind::Edge,
            BrowserPreference::EdgeOnly
        ));
        assert!(!browser_kind_matches_preference(
            BrowserKind::Chrome,
            BrowserPreference::EdgeOnly
        ));
        assert!(!browser_kind_matches_preference(
            BrowserKind::Edge,
            BrowserPreference::ChromeOnly
        ));
        assert!(!browser_kind_matches_preference(
            BrowserKind::Firefox,
            BrowserPreference::Auto
        ));
    }
}

#[cfg(all(test, feature = "containment-test-hooks"))]
mod containment_test_hook_tests {
    use super::{
        take_containment_test_close_delay, INTERNAL_TEST_CLOSE_DELAY_PREFIX,
    };
    use crate::detect::LaunchConfig;

    #[test]
    fn close_delay_hook_is_bounded_and_removed_before_browser_launch() {
        let mut launch = LaunchConfig::default();
        launch.extra_args = vec![
            "--ordinary-browser-argument".to_owned(),
            format!("{INTERNAL_TEST_CLOSE_DELAY_PREFIX}30000"),
        ];
        let delay = take_containment_test_close_delay(&mut launch)
            .expect("valid close-delay hook");
        assert_eq!(delay, Some(std::time::Duration::from_secs(30)));
        assert_eq!(launch.extra_args, ["--ordinary-browser-argument"]);

        for invalid in ["", "0", "60001", "not-a-number"] {
            let mut launch = LaunchConfig::default();
            launch.extra_args = vec![format!(
                "{INTERNAL_TEST_CLOSE_DELAY_PREFIX}{invalid}"
            )];
            assert!(take_containment_test_close_delay(&mut launch).is_err());
        }

        let mut launch = LaunchConfig::default();
        launch.extra_args = vec![
            format!("{INTERNAL_TEST_CLOSE_DELAY_PREFIX}1"),
            format!("{INTERNAL_TEST_CLOSE_DELAY_PREFIX}2"),
        ];
        assert!(take_containment_test_close_delay(&mut launch).is_err());
    }
}

impl BrowserBackend for CdpBrowserBackend {
    fn as_any_cdp(&self) -> Option<&CdpBrowserBackend> {
        Some(self)
    }

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
            let shutdown_started = std::time::Instant::now();
            #[cfg(all(windows, feature = "containment-test-hooks"))]
            record_test_browser_lifecycle(
                "shutdown_started",
                serde_json::json!({
                    "browser": format!("{:?}", self.launch.browser_pref),
                    "process_id": self._child.as_ref().and_then(BrowserProcess::id),
                    "profile": self.profile_dir,
                }),
            )
            .await;
            debug!(
                browser = ?self.launch.browser_pref,
                process_id = ?self._child.as_ref().and_then(BrowserProcess::id),
                profile = %self.profile_dir.display(),
                "owned CDP browser shutdown started"
            );
            self.browser_closing.store(true, Ordering::Release);
            #[cfg(feature = "containment-test-hooks")]
            if let Some(delay) = self.test_close_delay {
                tokio::time::sleep(delay).await;
            }
            let edge_normal_exit_attempted = self.launch.browser_pref
                == crate::detect::BrowserPreference::EdgeOnly;
            if edge_normal_exit_attempted {
                let edge_quit_started = std::time::Instant::now();
                let edge_quit = tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    self.root.create_target("edge://quit"),
                )
                .await;
                let outcome = match edge_quit {
                    Ok(Ok(_)) => "requested".to_owned(),
                    Ok(Err(error)) => format!("failed: {error}"),
                    Err(error) => format!("timed out: {error}"),
                };
                debug!(
                    elapsed_ms = edge_quit_started.elapsed().as_millis() as u64,
                    outcome = %outcome,
                    "Edge normal-exit request finished"
                );
                #[cfg(all(windows, feature = "containment-test-hooks"))]
                record_test_browser_lifecycle(
                    "edge_normal_exit_requested",
                    serde_json::json!({
                        "elapsed_ms": edge_quit_started.elapsed().as_millis() as u64,
                        "outcome": outcome,
                    }),
                )
                .await;
            }
            let mut child_exited = false;
            if edge_normal_exit_attempted {
                if let Some(ref mut child) = self._child {
                    let edge_exit_started = std::time::Instant::now();
                    let edge_exit = tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        child.wait(),
                    )
                    .await;
                    let outcome = match edge_exit {
                        Ok(Ok(status)) => {
                            child_exited = true;
                            format!("exited: {status}")
                        }
                        Ok(Err(error)) => format!("wait failed: {error}"),
                        Err(error) => format!("timed out: {error}"),
                    };
                    debug!(
                        elapsed_ms = edge_exit_started.elapsed().as_millis() as u64,
                        outcome = %outcome,
                        "Edge normal-exit wait finished"
                    );
                    #[cfg(all(windows, feature = "containment-test-hooks"))]
                    record_test_browser_lifecycle(
                        "edge_normal_exit_wait_finished",
                        serde_json::json!({
                            "elapsed_ms": edge_exit_started.elapsed().as_millis() as u64,
                            "outcome": outcome,
                        }),
                    )
                    .await;
                }
            }
            // Ask the browser to close gracefully via CDP.
            let graceful_close_confirmed = if child_exited {
                true
            } else {
                let graceful_close_started = std::time::Instant::now();
                let graceful_close = tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    self.root.call("Browser.close", None),
                )
                .await;
                let confirmed = matches!(graceful_close, Ok(Ok(_)));
                let outcome = match graceful_close {
                    Ok(Ok(_)) => "confirmed".to_owned(),
                    Ok(Err(error)) => format!("failed: {error}"),
                    Err(error) => format!("timed out: {error}"),
                };
                debug!(
                    elapsed_ms = graceful_close_started.elapsed().as_millis() as u64,
                    outcome = %outcome,
                    "CDP Browser.close finished"
                );
                #[cfg(all(windows, feature = "containment-test-hooks"))]
                record_test_browser_lifecycle(
                    "cdp_browser_close_finished",
                    serde_json::json!({
                        "elapsed_ms": graceful_close_started.elapsed().as_millis() as u64,
                        "outcome": outcome,
                    }),
                )
                .await;
                confirmed
            };
            if self.exact_policy_claimed.load(Ordering::Acquire)
                && !graceful_close_confirmed
            {
                if let Some(process_tree) = self._process_tree.as_ref() {
                    process_tree
                        .terminate_and_wait(std::time::Duration::from_secs(3))
                        .await?;
                }
            }
            // Let Chromium drain its process tree before forcing the owned root
            // process down. This avoids leaving profile files open on Windows.
            if let Some(ref mut child) = self._child {
                let child_wait_started = std::time::Instant::now();
                let child_wait = tokio::time::timeout(
                    std::time::Duration::from_secs(3),
                    child.wait(),
                )
                .await;
                let child_exit_confirmed = matches!(child_wait, Ok(Ok(_)));
                let outcome = match child_wait {
                    Ok(Ok(status)) => format!("exited: {status}"),
                    Ok(Err(error)) => format!("wait failed: {error}"),
                    Err(error) => format!("timed out: {error}"),
                };
                debug!(
                    elapsed_ms = child_wait_started.elapsed().as_millis() as u64,
                    outcome = %outcome,
                    "owned browser root wait finished"
                );
                #[cfg(all(windows, feature = "containment-test-hooks"))]
                record_test_browser_lifecycle(
                    "root_process_wait_finished",
                    serde_json::json!({
                        "elapsed_ms": child_wait_started.elapsed().as_millis() as u64,
                        "outcome": outcome,
                    }),
                )
                .await;
                if !child_exit_confirmed {
                    let kill_started = std::time::Instant::now();
                    let kill = child.kill().await;
                    debug!(
                        elapsed_ms = kill_started.elapsed().as_millis() as u64,
                        outcome = %match &kill {
                            Ok(()) => "terminated".to_owned(),
                            Err(error) => format!("failed: {error}"),
                        },
                        "owned browser root forced termination finished"
                    );
                    #[cfg(all(windows, feature = "containment-test-hooks"))]
                    record_test_browser_lifecycle(
                        "root_process_forced_termination_finished",
                        serde_json::json!({
                            "elapsed_ms": kill_started.elapsed().as_millis() as u64,
                            "outcome": match &kill {
                                Ok(()) => "terminated".to_owned(),
                                Err(error) => format!("failed: {error}"),
                            },
                        }),
                    )
                    .await;
                    kill?;
                }
            }
            if let Some(process_tree) = self._process_tree.as_ref() {
                let tree_wait_started = std::time::Instant::now();
                let process_tree_empty = process_tree
                    .wait_until_empty(std::time::Duration::from_secs(2))
                    .await?;
                debug!(
                    elapsed_ms = tree_wait_started.elapsed().as_millis() as u64,
                    empty = process_tree_empty,
                    "owned browser process-tree drain finished"
                );
                #[cfg(all(windows, feature = "containment-test-hooks"))]
                record_test_browser_lifecycle(
                    "process_tree_drain_finished",
                    serde_json::json!({
                        "elapsed_ms": tree_wait_started.elapsed().as_millis() as u64,
                        "empty": process_tree_empty,
                    }),
                )
                .await;
                if !process_tree_empty {
                    let tree_termination_started = std::time::Instant::now();
                    process_tree
                        .terminate_and_wait(std::time::Duration::from_secs(3))
                        .await?;
                    debug!(
                        elapsed_ms = tree_termination_started.elapsed().as_millis() as u64,
                        "owned browser process-tree forced termination finished"
                    );
                    #[cfg(all(windows, feature = "containment-test-hooks"))]
                    record_test_browser_lifecycle(
                        "process_tree_forced_termination_finished",
                        serde_json::json!({
                            "elapsed_ms": tree_termination_started.elapsed().as_millis() as u64,
                        }),
                    )
                    .await;
                }
            }
            if let Some(mut task) = self._stderr_task.take() {
                if tokio::time::timeout(
                    std::time::Duration::from_secs(1),
                    &mut task,
                )
                .await
                .is_err()
                {
                    task.abort();
                }
            }
            let _ = self.client.close_transport().await;
            if self.profile_ephemeral {
                let profile_cleanup_started = std::time::Instant::now();
                let attempts = remove_profile_dir_with_retry(&self.profile_dir).await?;
                self.profile_ephemeral = false;
                debug!(
                    elapsed_ms = profile_cleanup_started.elapsed().as_millis() as u64,
                    attempts,
                    profile = %self.profile_dir.display(),
                    "ephemeral browser profile cleanup finished"
                );
                #[cfg(all(windows, feature = "containment-test-hooks"))]
                record_test_browser_lifecycle(
                    "ephemeral_profile_cleanup_finished",
                    serde_json::json!({
                        "elapsed_ms": profile_cleanup_started.elapsed().as_millis() as u64,
                        "attempts": attempts,
                        "profile": self.profile_dir,
                    }),
                )
                .await;
            }
            debug!(
                elapsed_ms = shutdown_started.elapsed().as_millis() as u64,
                "owned CDP browser shutdown finished"
            );
            #[cfg(all(windows, feature = "containment-test-hooks"))]
            record_test_browser_lifecycle(
                "shutdown_finished",
                serde_json::json!({
                    "elapsed_ms": shutdown_started.elapsed().as_millis() as u64,
                }),
            )
            .await;
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

/// Upper bound on the bytes `wait_for_download` will read back for one
/// captured download; a larger file on disk is reported as an error rather
/// than loaded into memory.
const MAX_DOWNLOAD_BYTES: u64 = 32 * 1024 * 1024;

/// Lifecycle of one download tracked by `Browser.downloadProgress`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DownloadState {
    InProgress,
    Completed,
    Canceled,
}

/// One download tracked between `Browser.downloadWillBegin` and
/// `Browser.downloadProgress`, keyed by its `guid` in `DownloadRegistryInner::records`.
#[derive(Debug, Clone)]
struct DownloadRecord {
    suggested_filename: String,
    state: DownloadState,
    /// Monotonic arrival order, so `wait_for_download` can prefer the
    /// most-recently-begun completed download when more than one is tracked.
    seq: u64,
}

#[derive(Default)]
struct DownloadRegistryInner {
    next_seq: u64,
    records: HashMap<String, DownloadRecord>,
}

/// Shared, per-session download registry populated by
/// `spawn_download_capture_handler` and polled by `wait_for_download`.
type DownloadRegistry = Arc<Mutex<DownloadRegistryInner>>;

/// Everything a `CdpPageBackend` needs to serve `wait_for_download`, bundled
/// as one constructor argument: the shared registry the background handler
/// keeps up to date, the per-page directory Chrome saves download bytes into
/// (`allowAndName`, named by `guid`), and the handler task itself.
struct DownloadCapture {
    registry: DownloadRegistry,
    dir: std::path::PathBuf,
    task: JoinHandle<()>,
}

/// CDP-backed page handle.
pub(crate) struct CdpPageBackend {
    session: CdpSession,
    /// Kept so callers can close the target explicitly if needed.
    target_id: String,
    request_policy: Mutex<Option<CdpPageRequestPolicy>>,
    request_policy_healthy: Arc<AtomicBool>,
    exact_policy_claimed: Arc<AtomicBool>,
    browser_closing: Arc<AtomicBool>,
    owned_process_tree: Option<Arc<OwnedProcessTree>>,
    /// Always-on handler answering this page's JavaScript dialogs so an
    /// unanswered `alert`/`confirm`/`prompt`/`beforeunload` can never block the
    /// renderer. Aborted on drop.
    dialog_task: JoinHandle<()>,
    /// Registry + directory + handler task backing `wait_for_download`.
    /// Handler aborted and directory removed (best-effort) on drop.
    download: DownloadCapture,
}

impl CdpPageBackend {
    fn new(
        session: CdpSession,
        target_id: String,
        exact_policy_claimed: Arc<AtomicBool>,
        browser_closing: Arc<AtomicBool>,
        owned_process_tree: Option<Arc<OwnedProcessTree>>,
        dialog_task: JoinHandle<()>,
        download: DownloadCapture,
    ) -> Self {
        Self {
            session,
            target_id,
            request_policy: Mutex::new(None),
            request_policy_healthy: Arc::new(AtomicBool::new(true)),
            exact_policy_claimed,
            browser_closing,
            owned_process_tree,
            dialog_task,
            download,
        }
    }

    /// Resolve a frame-piercing compound selector. A selector may address an
    /// element inside a **same-origin** `<iframe>` by chaining segments with
    /// `>>>`: each segment before the last selects a frame owner, whose content
    /// document becomes the context for the next segment. Returns the document
    /// node id the final segment must be queried within, plus that final
    /// segment. A plain selector (no `>>>`) resolves against the top document,
    /// exactly as before.
    ///
    /// Cross-origin (out-of-process) frames live in a separate CDP session and
    /// are not reachable this way — such a descent fails closed with a
    /// not-found error rather than silently crossing into the wrong document.
    async fn resolve_frame_context(
        &self,
        selector: &str,
    ) -> Result<(i64, String), BrowserError> {
        let doc = self
            .session
            .get_document()
            .await
            .map_err(|e| BrowserError::Other(e.to_string()))?;

        let mut segments: Vec<&str> = selector.split(">>>").map(str::trim).collect();
        if segments.iter().any(|segment| segment.is_empty()) {
            return Err(BrowserError::Other(format!(
                "invalid frame selector: {selector}"
            )));
        }
        // `split` always yields at least one element.
        let last = segments.pop().expect("selector has a final segment").to_owned();

        let mut context = doc.node_id;
        for frame_selector in segments {
            let frame_node = self
                .session
                .query_selector(context, frame_selector)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?
                .ok_or_else(|| {
                    BrowserError::Other(format!("frame not found: {frame_selector}"))
                })?;
            context = self
                .session
                .content_document_node_id(frame_node)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?
                .ok_or_else(|| {
                    BrowserError::Other(format!(
                        "not a same-origin frame with a reachable document: {frame_selector}"
                    ))
                })?;
        }
        Ok((context, last))
    }
}

struct CdpPageRequestPolicy {
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

const MAX_GUARDED_TARGET_SESSIONS: usize = 256;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TargetAttachedToTarget {
    session_id: String,
    target_info: GuardedTargetInfo,
    waiting_for_debugger: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GuardedTargetInfo {
    target_id: String,
    #[serde(rename = "type")]
    kind: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TargetDetachedFromTarget {
    session_id: String,
}

async fn enable_fetch_request_policy(session: &CdpSession) -> Result<(), CdpError> {
    session
        .enable_fetch(vec![crate::cdp::domains::fetch::RequestPattern {
            url_pattern: Some("*".to_owned()),
            resource_type: None,
            request_stage: Some("Request".to_owned()),
        }])
        .await
}

async fn enable_target_tree_auto_attach(session: &CdpSession) -> Result<(), CdpError> {
    session
        .call(
            "Target.setAutoAttach",
            Some(serde_json::json!({
                "autoAttach": true,
                "waitForDebuggerOnStart": true,
                "flatten": true,
            })),
        )
        .await?;
    Ok(())
}

async fn arm_guarded_target(
    session: &CdpSession,
    target_kind: &str,
    waiting_for_debugger: bool,
) -> Result<(), CdpError> {
    match target_kind {
        // A tab is a supervisory target. Its page children are armed separately.
        "tab" => enable_target_tree_auto_attach(session).await?,
        // Dedicated workers do not expose the Fetch or Target domains. Their
        // requests are intercepted by the already-armed parent page session.
        "worker" => {}
        _ => {
            enable_fetch_request_policy(session).await?;
            enable_target_tree_auto_attach(session).await?;
        }
    }
    if waiting_for_debugger {
        session
            .call("Runtime.runIfWaitingForDebugger", None)
            .await?;
    }
    Ok(())
}

impl Drop for CdpPageRequestPolicy {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.task.abort();
    }
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
                // Chrome rejects a cookie set with only a bare domain and no URL
                // context (e.g. from about:blank). Synthesize a request-URI from
                // the cookie's host + secure flag; cookies are port-agnostic, so a
                // portless URL matches any port of that host.
                let host = cookie.domain.trim_start_matches('.');
                let scheme = if cookie.is_secure { "https" } else { "http" };
                let cdp_cookie = crate::cdp::CdpCookie {
                    name: cookie.name.clone(),
                    value: cookie.value.clone(),
                    domain: cookie.domain.clone(),
                    path: cookie.path.clone(),
                    secure: cookie.is_secure,
                    http_only: cookie.is_httponly,
                    expires: cookie.expires_utc.map(|t| t as f64),
                    url: Some(format!("{scheme}://{host}/")),
                };
                self.session
                    .set_cookie(cdp_cookie)
                    .await
                    .map_err(|e| BrowserError::Other(e.to_string()))?;
            }
            Ok(())
        })
    }

    // ── Element interaction ────────────────────────────────────────────────

    fn find_element<'a>(
        &'a self,
        selector: &'a str,
    ) -> BoxFuture<'a, Result<ElementHandle, BrowserError>> {
        Box::pin(async move {
            self.session
                .enable_dom()
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            let (context, last) = self.resolve_frame_context(selector).await?;

            let node_id = self
                .session
                .query_selector(context, &last)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?
                .ok_or_else(|| {
                    BrowserError::Other(format!("element not found: {selector}"))
                })?;

            Ok(ElementHandle {
                inner: ElementInner::Cdp { node_id },
            })
        })
    }

    fn set_element_files<'a>(
        &'a self,
        element: &'a ElementHandle,
        paths: &'a [String],
    ) -> BoxFuture<'a, Result<(), BrowserError>> {
        Box::pin(async move {
            let node_id = cdp_node_id(element)?;
            self.session
                .set_file_input_files(node_id, paths)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))
        })
    }

    fn find_elements<'a>(
        &'a self,
        selector: &'a str,
    ) -> BoxFuture<'a, Result<Vec<ElementHandle>, BrowserError>> {
        Box::pin(async move {
            self.session
                .enable_dom()
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            let (context, last) = self.resolve_frame_context(selector).await?;

            let node_ids = self
                .session
                .query_selector_all(context, &last)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            let handles = node_ids
                .into_iter()
                .map(|node_id| ElementHandle {
                    inner: ElementInner::Cdp { node_id },
                })
                .collect();

            Ok(handles)
        })
    }

    fn click_element<'a>(
        &'a self,
        element: &'a ElementHandle,
    ) -> BoxFuture<'a, Result<(), BrowserError>> {
        Box::pin(async move {
            let node_id = cdp_node_id(element)?;

            // Scroll the element into view first.
            self.session
                .scroll_into_view(node_id)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            // Get the bounding box to compute the center.
            let bbox = self
                .session
                .get_box_model(node_id)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            // content quad is [x1,y1, x2,y2, x3,y3, x4,y4].
            let (cx, cy) = quad_center(&bbox.content);

            self.session
                .mouse_click(cx, cy)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))
        })
    }

    fn type_into_element<'a>(
        &'a self,
        element: &'a ElementHandle,
        text: &'a str,
    ) -> BoxFuture<'a, Result<(), BrowserError>> {
        Box::pin(async move {
            let node_id = cdp_node_id(element)?;

            self.session
                .focus(node_id)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            self.session
                .type_text(text)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))
        })
    }

    fn element_text<'a>(
        &'a self,
        element: &'a ElementHandle,
    ) -> BoxFuture<'a, Result<String, BrowserError>> {
        Box::pin(async move {
            let node_id = cdp_node_id(element)?;

            // Resolve to a JS remote object so we can call functions on it.
            let object_id = self
                .session
                .resolve_node(node_id)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            let result = self
                .session
                .call(
                    "Runtime.callFunctionOn",
                    Some(serde_json::json!({
                        "objectId": object_id,
                        "functionDeclaration": "function() { return this.textContent; }",
                        "returnByValue": true,
                    })),
                )
                .await
                .map_err(|e| BrowserError::JsEval(e.to_string()))?;

            Ok(result["result"]["value"]
                .as_str()
                .unwrap_or("")
                .to_owned())
        })
    }

    fn element_attribute<'a>(
        &'a self,
        element: &'a ElementHandle,
        name: &'a str,
    ) -> BoxFuture<'a, Result<Option<String>, BrowserError>> {
        Box::pin(async move {
            let node_id = cdp_node_id(element)?;

            let object_id = self
                .session
                .resolve_node(node_id)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            let attr_name = name.to_owned();
            let result = self
                .session
                .call(
                    "Runtime.callFunctionOn",
                    Some(serde_json::json!({
                        "objectId": object_id,
                        "functionDeclaration": "function(n) { return this.getAttribute(n); }",
                        "arguments": [{ "value": attr_name }],
                        "returnByValue": true,
                    })),
                )
                .await
                .map_err(|e| BrowserError::JsEval(e.to_string()))?;

            let val = &result["result"]["value"];
            if val.is_null() || val.is_string() && val.as_str() == Some("null") {
                Ok(None)
            } else {
                Ok(val.as_str().map(|s| s.to_owned()))
            }
        })
    }

    fn element_html<'a>(
        &'a self,
        element: &'a ElementHandle,
    ) -> BoxFuture<'a, Result<String, BrowserError>> {
        Box::pin(async move {
            let node_id = cdp_node_id(element)?;

            self.session
                .get_outer_html(node_id)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))
        })
    }

    fn element_bounding_box<'a>(
        &'a self,
        element: &'a ElementHandle,
    ) -> BoxFuture<'a, Result<BoundingBox, BrowserError>> {
        Box::pin(async move {
            let node_id = cdp_node_id(element)?;

            let model = self
                .session
                .get_box_model(node_id)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            // border quad: x1,y1, x2,y2, x3,y3, x4,y4
            let b = &model.border;
            if b.len() < 8 {
                return Err(BrowserError::Other(
                    "invalid box model: border quad has fewer than 8 values".into(),
                ));
            }
            // top-left corner = (b[0], b[1]), width and height from CDP model.
            Ok(BoundingBox {
                x: b[0],
                y: b[1],
                width: model.width as f64,
                height: model.height as f64,
            })
        })
    }

    // ── PDF ───────────────────────────────────────────────────────────────

    fn print_pdf<'a>(
        &'a self,
        options: &'a PrintOptions,
    ) -> BoxFuture<'a, Result<Vec<u8>, BrowserError>> {
        Box::pin(async move {
            let mut params = serde_json::json!({
                "landscape": options.landscape,
                "printBackground": options.print_background,
            });

            if let Some(scale) = options.scale {
                params["scale"] = serde_json::Value::from(scale);
            }
            if let Some(w) = options.paper_width {
                params["paperWidth"] = serde_json::Value::from(w);
            }
            if let Some(h) = options.paper_height {
                params["paperHeight"] = serde_json::Value::from(h);
            }

            let result = self
                .session
                .call("Page.printToPDF", Some(params))
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            let encoded = result["data"]
                .as_str()
                .ok_or_else(|| BrowserError::Other("missing data in Page.printToPDF response".into()))?;

            let bytes = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|e| BrowserError::Other(format!("base64 decode error: {e}")))?;

            Ok(bytes)
        })
    }

    // ── Enhanced screenshots ───────────────────────────────────────────────

    fn screenshot_full_page<'a>(&'a self) -> BoxFuture<'a, Result<Vec<u8>, BrowserError>> {
        Box::pin(async move {
            // Get the full page dimensions via JS.
            let dims = self
                .session
                .evaluate("JSON.stringify({ w: document.documentElement.scrollWidth, h: document.documentElement.scrollHeight })")
                .await
                .map_err(|e| BrowserError::JsEval(e.to_string()))?;

            let dims_str = dims["value"].as_str().unwrap_or(r#"{"w":1280,"h":800}"#);
            let dims_val: serde_json::Value =
                serde_json::from_str(dims_str).unwrap_or(serde_json::json!({"w":1280,"h":800}));
            let w = dims_val["w"].as_f64().unwrap_or(1280.0);
            let h = dims_val["h"].as_f64().unwrap_or(800.0);

            let result = self
                .session
                .call(
                    "Page.captureScreenshot",
                    Some(serde_json::json!({
                        "format": "png",
                        "clip": {
                            "x": 0,
                            "y": 0,
                            "width": w,
                            "height": h,
                            "scale": 1,
                        },
                        "captureBeyondViewport": true,
                    })),
                )
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            let encoded = result["data"]
                .as_str()
                .ok_or_else(|| BrowserError::Other("missing data in captureScreenshot response".into()))?;

            base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|e| BrowserError::Other(format!("base64 decode error: {e}")))
        })
    }

    fn screenshot_element<'a>(
        &'a self,
        element: &'a ElementHandle,
    ) -> BoxFuture<'a, Result<Vec<u8>, BrowserError>> {
        Box::pin(async move {
            let node_id = cdp_node_id(element)?;

            self.session
                .scroll_into_view(node_id)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            let model = self
                .session
                .get_box_model(node_id)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            let b = &model.border;
            if b.len() < 8 {
                return Err(BrowserError::Other(
                    "invalid box model: border quad has fewer than 8 values".into(),
                ));
            }

            let x = b[0];
            let y = b[1];
            let w = model.width as f64;
            let h = model.height as f64;

            let result = self
                .session
                .call(
                    "Page.captureScreenshot",
                    Some(serde_json::json!({
                        "format": "png",
                        "clip": {
                            "x": x,
                            "y": y,
                            "width": w,
                            "height": h,
                            "scale": 1,
                        },
                    })),
                )
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            let encoded = result["data"]
                .as_str()
                .ok_or_else(|| BrowserError::Other("missing data in captureScreenshot response".into()))?;

            base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|e| BrowserError::Other(format!("base64 decode error: {e}")))
        })
    }

    fn set_extra_http_headers<'a>(
        &'a self,
        headers: std::collections::HashMap<String, String>,
    ) -> BoxFuture<'a, Result<(), BrowserError>> {
        Box::pin(async move {
            self.session
                .set_extra_http_headers(headers)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))
        })
    }

    fn set_bypass_csp<'a>(&'a self, enabled: bool) -> BoxFuture<'a, Result<(), BrowserError>> {
        Box::pin(async move {
            self.session
                .set_bypass_csp(enabled)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))
        })
    }

    fn add_script_to_evaluate_on_new_document<'a>(
        &'a self,
        source: &'a str,
    ) -> BoxFuture<'a, Result<String, BrowserError>> {
        Box::pin(async move {
            self.session
                .add_script_on_new_document(source)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))
        })
    }

    // ── Raw input by coordinates ──────────────────────────────────────────

    fn click_at<'a>(&'a self, x: f64, y: f64) -> BoxFuture<'a, Result<(), BrowserError>> {
        Box::pin(async move {
            self.session
                .mouse_click(x, y)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))
        })
    }

    fn right_click_at<'a>(&'a self, x: f64, y: f64) -> BoxFuture<'a, Result<(), BrowserError>> {
        Box::pin(async move {
            self.session
                .dispatch_mouse_event("mousePressed", x, y, "right", 1)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;
            self.session
                .dispatch_mouse_event("mouseReleased", x, y, "right", 1)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))
        })
    }

    fn mouse_move_to<'a>(&'a self, x: f64, y: f64) -> BoxFuture<'a, Result<(), BrowserError>> {
        Box::pin(async move {
            self.session
                .mouse_move(x, y)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))
        })
    }

    fn drag<'a>(
        &'a self,
        x1: f64,
        y1: f64,
        x2: f64,
        y2: f64,
    ) -> BoxFuture<'a, Result<(), BrowserError>> {
        Box::pin(async move {
            // Press at source.
            self.session
                .dispatch_mouse_event("mousePressed", x1, y1, "left", 1)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            // Interpolate 10 move steps.
            let steps = 10u32;
            for i in 1..=steps {
                let t = i as f64 / steps as f64;
                let mx = x1 + (x2 - x1) * t;
                let my = y1 + (y2 - y1) * t;
                self.session
                    .dispatch_mouse_event("mouseMoved", mx, my, "left", 0)
                    .await
                    .map_err(|e| BrowserError::Other(e.to_string()))?;
            }

            // Release at destination.
            self.session
                .dispatch_mouse_event("mouseReleased", x2, y2, "left", 1)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))
        })
    }

    fn wheel<'a>(
        &'a self,
        x: f64,
        y: f64,
        dx: f64,
        dy: f64,
    ) -> BoxFuture<'a, Result<(), BrowserError>> {
        Box::pin(async move {
            self.session
                .dispatch_wheel(x, y, dx, dy)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))
        })
    }

    fn key_press<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), BrowserError>> {
        Box::pin(async move {
            let code = key_name_to_code(key);
            let text = if key.chars().count() == 1 {
                Some(key)
            } else {
                None
            };
            self.session
                .dispatch_key_event("keyDown", key, &code, text)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;
            self.session
                .dispatch_key_event("keyUp", key, &code, None)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))
        })
    }

    fn key_chord<'a>(
        &'a self,
        modifiers: &'a [&'a str],
        key: &'a str,
    ) -> BoxFuture<'a, Result<(), BrowserError>> {
        Box::pin(async move {
            let modifier_mask = modifiers_to_mask(modifiers);
            let code = key_name_to_code(key);
            self.session
                .dispatch_key_event_with_modifiers("keyDown", key, &code, None, modifier_mask)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;
            self.session
                .dispatch_key_event_with_modifiers("keyUp", key, &code, None, modifier_mask)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))
        })
    }

    // ── Viewport / device emulation ───────────────────────────────────────

    fn set_viewport<'a>(
        &'a self,
        width: u32,
        height: u32,
        device_scale_factor: f64,
    ) -> BoxFuture<'a, Result<(), BrowserError>> {
        Box::pin(async move {
            self.session
                .call(
                    "Emulation.setDeviceMetricsOverride",
                    Some(serde_json::json!({
                        "width": width,
                        "height": height,
                        "deviceScaleFactor": device_scale_factor,
                        "mobile": false,
                    })),
                )
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;
            Ok(())
        })
    }

    fn clear_viewport_override<'a>(&'a self) -> BoxFuture<'a, Result<(), BrowserError>> {
        Box::pin(async move {
            self.session
                .call("Emulation.clearDeviceMetricsOverride", None)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;
            Ok(())
        })
    }

    fn install_page_request_policy<'a>(
        &'a self,
        policy: NavigationPolicy,
    ) -> BoxFuture<'a, Result<(), BrowserError>> {
        Box::pin(async move {
            if !policy.is_exact() {
                return Ok(());
            }
            let owned_process_tree = self
                .owned_process_tree
                .as_ref()
                .filter(|process_tree| process_tree.supports_immediate_termination())
                .map(Arc::clone)
                .ok_or_else(|| {
                    BrowserError::Other(
                        "exact page request policy requires an owned browser process tree"
                            .into(),
                    )
                })?;
            let browser_closing = Arc::clone(&self.browser_closing);
            let mut active = self.request_policy.lock().await;
            if active.is_some() {
                return Err(BrowserError::Other(
                    "page request policy is already installed".into(),
                ));
            }
            if self
                .exact_policy_claimed
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                return Err(BrowserError::Other(
                    "exact page request policy is already claimed for this browser lifetime"
                        .into(),
                ));
            }
            self.request_policy_healthy.store(false, Ordering::Release);

            let client = Arc::clone(self.session.client());
            let mut events = client.subscribe();
            let mut connection_terminal = client.subscribe_terminal();
            let page_session_id = self
                .session
                .session_id()
                .ok_or_else(|| {
                    BrowserError::Other(
                        "exact page request policy requires an attached target session".into(),
                    )
                })?
                .to_owned();
            let page_target_id = self.target_id.clone();
            enable_fetch_request_policy(&self.session)
                .await
                .map_err(|error| BrowserError::Other(error.to_string()))?;
            enable_target_tree_auto_attach(&self.session)
                .await
                .map_err(|error| BrowserError::Other(error.to_string()))?;
            enable_target_tree_auto_attach(&client.root_session())
                .await
                .map_err(|error| BrowserError::Other(error.to_string()))?;
            if client.is_terminal() {
                return Err(BrowserError::Other(
                    "CDP transport closed while installing exact page request policy".into(),
                ));
            }

            self.request_policy_healthy.store(true, Ordering::Release);
            let healthy = Arc::clone(&self.request_policy_healthy);
            let (shutdown, mut shutdown_rx) = oneshot::channel();
            let task = tokio::spawn(async move {
                let mut guarded_sessions = HashMap::new();
                guarded_sessions.insert(page_session_id, page_target_id);
                let must_terminate = loop {
                    let event = tokio::select! {
                        biased;
                        terminal = connection_terminal.changed() => {
                            if terminal.is_err() || *connection_terminal.borrow() {
                                break true;
                            }
                            continue;
                        }
                        _ = &mut shutdown_rx => break false,
                        event = events.recv() => event,
                    };
                    let event = match event {
                        Ok(event) => event,
                        Err(_) => break true,
                    };
                    if event.method == "Target.detachedFromTarget" {
                        let Some(params) = event.params else {
                            break true;
                        };
                        let detached = match serde_json::from_value::<
                            TargetDetachedFromTarget,
                        >(params) {
                            Ok(detached) => detached,
                            Err(_) => break true,
                        };
                        guarded_sessions.remove(&detached.session_id);
                        continue;
                    }
                    let parent_is_guarded = event
                        .session_id
                        .as_ref()
                        .is_none_or(|session_id| guarded_sessions.contains_key(session_id));
                    if event.method == "Target.attachedToTarget" {
                        if !parent_is_guarded {
                            continue;
                        }
                        let Some(params) = event.params else {
                            break true;
                        };
                        let attached = match serde_json::from_value::<
                            TargetAttachedToTarget,
                        >(params) {
                            Ok(attached) => attached,
                            Err(_) => break true,
                        };
                        if guarded_sessions.contains_key(&attached.session_id) {
                            continue;
                        }
                        if guarded_sessions.len() >= MAX_GUARDED_TARGET_SESSIONS {
                            break true;
                        }
                        guarded_sessions.insert(
                            attached.session_id.clone(),
                            attached.target_info.target_id,
                        );
                        let child = CdpSession::with_session_id(
                            attached.session_id,
                            Arc::clone(&client),
                        );
                        if arm_guarded_target(
                            &child,
                            &attached.target_info.kind,
                            attached.waiting_for_debugger,
                        )
                        .await
                        .is_err()
                        {
                            break true;
                        }
                        continue;
                    }
                    if event.method != "Fetch.requestPaused" {
                        continue;
                    }
                    let Some(event_session_id) = event.session_id.as_ref() else {
                        break true;
                    };
                    if !guarded_sessions.contains_key(event_session_id) {
                        continue;
                    }
                    let Some(params) = event.params else {
                        break true;
                    };
                    let paused = match serde_json::from_value::<
                        crate::cdp::events::FetchRequestPaused,
                    >(params) {
                        Ok(paused) => paused,
                        Err(_) => break true,
                    };
                    let event_session = CdpSession::with_session_id(
                        event_session_id.clone(),
                        Arc::clone(&client),
                    );
                    let result = if policy.allows(&paused.request.url) {
                        event_session.continue_request(&paused.request_id).await
                    } else {
                        event_session
                            .fail_request(&paused.request_id, "BlockedByClient")
                            .await
                    };
                    if result.is_err() {
                        break true;
                    }
                };
                if must_terminate {
                    healthy.store(false, Ordering::Release);
                    if !browser_closing.load(Ordering::Acquire) {
                        let _ = owned_process_tree
                            .terminate_and_wait(std::time::Duration::from_secs(3))
                            .await;
                    }
                }
            });
            *active = Some(CdpPageRequestPolicy {
                shutdown: Some(shutdown),
                task,
            });
            Ok(())
        })
    }

    fn clear_page_request_policy<'a>(
        &'a self,
    ) -> BoxFuture<'a, Result<(), BrowserError>> {
        Box::pin(async move {
            let mut active = self.request_policy.lock().await;
            let Some(mut policy) = active.take() else {
                return Ok(());
            };
            if let Some(shutdown) = policy.shutdown.take() {
                let _ = shutdown.send(());
            }
            if tokio::time::timeout(
                std::time::Duration::from_secs(2),
                &mut policy.task,
            )
            .await
            .is_err()
            {
                policy.task.abort();
            }
            // Leave Fetch and recursive auto-attach armed until Browser.close.
            // With no handler, any late request remains paused rather than
            // creating a shutdown-time egress window.
            self.request_policy_healthy.store(false, Ordering::Release);
            Ok(())
        })
    }

    fn page_request_policy_healthy(&self) -> bool {
        self.request_policy_healthy.load(Ordering::Acquire)
    }

    // ── Raw CDP escape hatch ──────────────────────────────────────────────

    fn cdp_call<'a>(
        &'a self,
        method: &'a str,
        params: Option<serde_json::Value>,
    ) -> BoxFuture<'a, Result<serde_json::Value, BrowserError>> {
        Box::pin(async move {
            self.session
                .call(method, params)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))
        })
    }

    // ── Downloads ────────────────────────────────────────────────────────

    fn wait_for_download<'a>(
        &'a self,
        timeout: std::time::Duration,
    ) -> BoxFuture<'a, Result<(String, Vec<u8>), BrowserError>> {
        Box::pin(async move {
            const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(200);
            let deadline = tokio::time::Instant::now() + timeout;
            loop {
                let completed = {
                    let mut registry = self.download.registry.lock().await;
                    let guid = registry
                        .records
                        .iter()
                        .filter(|(_, record)| record.state == DownloadState::Completed)
                        .max_by_key(|(_, record)| record.seq)
                        .map(|(guid, _)| guid.clone());
                    guid.and_then(|guid| registry.records.remove(&guid).map(|record| (guid, record)))
                };
                if let Some((guid, record)) = completed {
                    let path = self.download.dir.join(&guid);
                    let size = tokio::fs::metadata(&path).await?.len();
                    if size > MAX_DOWNLOAD_BYTES {
                        return Err(BrowserError::Other(format!(
                            "download exceeds the {MAX_DOWNLOAD_BYTES}-byte cap"
                        )));
                    }
                    let bytes = tokio::fs::read(&path).await?;
                    return Ok((record.suggested_filename, bytes));
                }
                if tokio::time::Instant::now() >= deadline {
                    return Err(BrowserError::Timeout(timeout));
                }
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        })
    }

    // ── DevTools events ───────────────────────────────────────────────────

    fn subscribe_events<'a>(
        &'a self,
    ) -> BoxFuture<'a, Result<tokio::sync::broadcast::Receiver<DevToolsEvent>, BrowserError>> {
        Box::pin(async move {
            // CDP events flow through the client's broadcast channel.
            // We bridge CdpEvent → DevToolsEvent in a background task and
            // provide the caller with a broadcast::Receiver<DevToolsEvent>.
            let (tx, rx) = tokio::sync::broadcast::channel(4096);
            let mut cdp_rx = self.session.client().subscribe();

            tokio::spawn(async move {
                loop {
                    match cdp_rx.recv().await {
                        Ok(event) => {
                            let dt_event = bridge_cdp_event(event);
                            if let Some(e) = dt_event {
                                // If all receivers dropped, stop the bridge.
                                if tx.send(e).is_err() {
                                    break;
                                }
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    }
                }
            });

            Ok(rx)
        })
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Extract the CDP node_id from an ElementHandle, returning an error if the
/// handle is for a different backend.
fn cdp_node_id(element: &ElementHandle) -> Result<i64, BrowserError> {
    match &element.inner {
        ElementInner::Cdp { node_id } => Ok(*node_id),
        ElementInner::WebDriver { .. } => Err(BrowserError::Other(
            "ElementHandle is a WebDriver handle, not a CDP handle".into(),
        )),
    }
}

/// Compute the center of a content/border/etc. quad (8-element slice).
fn quad_center(quad: &[f64]) -> (f64, f64) {
    if quad.len() < 8 {
        return (0.0, 0.0);
    }
    let cx = (quad[0] + quad[2] + quad[4] + quad[6]) / 4.0;
    let cy = (quad[1] + quad[3] + quad[5] + quad[7]) / 4.0;
    (cx, cy)
}

/// Map a raw CDP event into a `DevToolsEvent` if it's relevant.
fn bridge_cdp_event(event: crate::cdp::CdpEvent) -> Option<DevToolsEvent> {
    use crate::browser::devtools::{ConsoleEvent, NetworkEvent};

    match event.method.as_str() {
        m if m.starts_with("Network.") => {
            let params = event.params.unwrap_or(serde_json::Value::Null);
            // `response.url`/`request.url` cover normal HTTP flows; WebSocket
            // lifecycle events (`Network.webSocketCreated`,
            // `webSocketWillSendHandshakeRequest`) carry the endpoint URL at
            // the top level instead, and the frame events
            // (`webSocketFrameSent/Received`) carry none — so surfacing the
            // top-level `url` here is what lets the station correlate a
            // frame back to its `wss://` endpoint by `requestId`.
            let url = params["response"]["url"]
                .as_str()
                .or_else(|| params["request"]["url"].as_str())
                .or_else(|| params["url"].as_str())
                .map(|s| s.to_owned());
            let status = params["response"]["status"].as_u64().map(|s| s as u16);
            Some(DevToolsEvent::Network(NetworkEvent {
                method: event.method,
                url,
                status,
                params,
            }))
        }
        "Runtime.consoleAPICalled" => {
            let params = event.params.unwrap_or(serde_json::Value::Null);
            let level = params["type"].as_str().unwrap_or("log").to_owned();
            let text = params["args"]
                .as_array()
                .and_then(|arr| arr.first())
                .and_then(|v| v["value"].as_str())
                .unwrap_or("")
                .to_owned();
            Some(DevToolsEvent::Console(ConsoleEvent { level, text }))
        }
        _ => None,
    }
}

/// Map a DOM key name to a CDP `code` field.
///
/// Single characters map to `"Key{Upper}"` or special values; named keys get
/// their standard code string.
fn key_name_to_code(key: &str) -> String {
    match key {
        "Enter" => "Enter".to_owned(),
        "Escape" => "Escape".to_owned(),
        "Backspace" => "Backspace".to_owned(),
        "Tab" => "Tab".to_owned(),
        "Space" | " " => "Space".to_owned(),
        "ArrowLeft" => "ArrowLeft".to_owned(),
        "ArrowRight" => "ArrowRight".to_owned(),
        "ArrowUp" => "ArrowUp".to_owned(),
        "ArrowDown" => "ArrowDown".to_owned(),
        "Home" => "Home".to_owned(),
        "End" => "End".to_owned(),
        "PageUp" => "PageUp".to_owned(),
        "PageDown" => "PageDown".to_owned(),
        "Delete" => "Delete".to_owned(),
        "Insert" => "Insert".to_owned(),
        "F1" => "F1".to_owned(),
        "F2" => "F2".to_owned(),
        "F3" => "F3".to_owned(),
        "F4" => "F4".to_owned(),
        "F5" => "F5".to_owned(),
        "F6" => "F6".to_owned(),
        "F7" => "F7".to_owned(),
        "F8" => "F8".to_owned(),
        "F9" => "F9".to_owned(),
        "F10" => "F10".to_owned(),
        "F11" => "F11".to_owned(),
        "F12" => "F12".to_owned(),
        other => {
            // Single printable character → "KeyA", "Digit1", etc.
            let ch = other.chars().next().unwrap_or('?');
            if ch.is_ascii_alphabetic() {
                format!("Key{}", ch.to_ascii_uppercase())
            } else if ch.is_ascii_digit() {
                format!("Digit{ch}")
            } else {
                other.to_owned()
            }
        }
    }
}

/// Convert a slice of modifier names into the CDP modifier bitmask.
///
/// CDP bitmask: 1=Alt, 2=Ctrl, 4=Meta, 8=Shift.
fn modifiers_to_mask(modifiers: &[&str]) -> u32 {
    let mut mask = 0u32;
    for m in modifiers {
        match *m {
            "Alt" => mask |= 1,
            "Control" | "Ctrl" => mask |= 2,
            "Meta" | "Command" => mask |= 4,
            "Shift" => mask |= 8,
            _ => {}
        }
    }
    mask
}

// Suppress lint: target_id is kept for future use (explicit target close).
impl Drop for CdpPageBackend {
    fn drop(&mut self) {
        let _target_id = &self.target_id;
        // Stop the dialog auto-handler; its session is going away.
        self.dialog_task.abort();
        // Stop the download-event handler and best-effort remove the
        // per-page download directory it was writing into.
        self.download.task.abort();
        let _ = std::fs::remove_dir_all(&self.download.dir);
        // Could send Target.closeTarget here, but it requires an async context.
        // The browser will GC detached targets automatically.
    }
}

/// Spawn an always-on handler that answers this session's JavaScript dialogs so
/// a page's `alert`/`confirm`/`prompt`/`beforeunload` can never block the
/// renderer (an unanswered dialog stalls JS, hanging navigation, eval, and
/// capture). Policy: cancel the dialogs that offer a Cancel button
/// (`confirm`/`prompt`) — the safe non-action — and acknowledge the rest
/// (`alert` = OK, `beforeunload` = leave, so the engine's own navigations are
/// not blocked). No prompt text is supplied. This is what lets an agent work a
/// dialog-popping page without an `Evaluate` to neutralize the dialogs, and it
/// is scoped to this session by `session_id` so it never answers another page's
/// dialog.
fn spawn_dialog_auto_handler(session: &CdpSession) -> JoinHandle<()> {
    let responder = session.clone();
    let my_session_id = session.session_id().map(str::to_owned);
    let mut events = session.client().subscribe();
    tokio::spawn(async move {
        loop {
            match events.recv().await {
                Ok(event) => {
                    if event.method != "Page.javascriptDialogOpening"
                        || event.session_id.as_deref() != my_session_id.as_deref()
                    {
                        continue;
                    }
                    let dialog_type = event
                        .params
                        .as_ref()
                        .and_then(|params| params["type"].as_str())
                        .unwrap_or_default();
                    let accept = !matches!(dialog_type, "confirm" | "prompt");
                    let _ = responder
                        .call(
                            "Page.handleJavaScriptDialog",
                            Some(serde_json::json!({ "accept": accept })),
                        )
                        .await;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            }
        }
    })
}

/// Enable download capture on `session` (`Browser.setDownloadBehavior`,
/// `allowAndName` — Chrome saves each download under a unique per-page
/// directory, named by its GUID, so no two downloads collide on a filename)
/// and spawn the background handler that keeps a shared registry of
/// in-flight/completed downloads up to date. Backs
/// `PageBackend::wait_for_download`.
async fn setup_download_capture(
    session: &CdpSession,
    target_id: &str,
) -> Result<DownloadCapture, BrowserError> {
    let dir = std::env::temp_dir().join(format!("dig2browser-downloads-{target_id}"));
    tokio::fs::create_dir_all(&dir).await?;
    session
        .set_download_behavior("allowAndName", &dir.to_string_lossy(), true)
        .await
        .map_err(|e| BrowserError::Connect(e.to_string()))?;
    let registry: DownloadRegistry = Arc::new(Mutex::new(DownloadRegistryInner::default()));
    let task = spawn_download_capture_handler(session, Arc::clone(&registry));
    Ok(DownloadCapture { registry, dir, task })
}

/// Spawn a per-session handler that keeps `registry` in sync with this
/// session's `Browser.downloadWillBegin` (records the download's suggested
/// filename) and `Browser.downloadProgress` (records
/// `inProgress`/`completed`/`canceled`) events. Scoped to this session by
/// `session_id`, so it never tracks another page's downloads — the same
/// scoping `spawn_dialog_auto_handler` uses.
fn spawn_download_capture_handler(
    session: &CdpSession,
    registry: DownloadRegistry,
) -> JoinHandle<()> {
    let my_session_id = session.session_id().map(str::to_owned);
    let mut events = session.client().subscribe();
    tokio::spawn(async move {
        loop {
            match events.recv().await {
                Ok(event) => {
                    if event.session_id.as_deref() != my_session_id.as_deref() {
                        continue;
                    }
                    let Some(params) = &event.params else {
                        continue;
                    };
                    let Some(guid) = params["guid"].as_str() else {
                        continue;
                    };
                    match event.method.as_str() {
                        "Browser.downloadWillBegin" => {
                            let suggested_filename = params["suggestedFilename"]
                                .as_str()
                                .unwrap_or_default()
                                .to_owned();
                            let mut registry = registry.lock().await;
                            registry.next_seq += 1;
                            let seq = registry.next_seq;
                            registry.records.insert(
                                guid.to_owned(),
                                DownloadRecord {
                                    suggested_filename,
                                    state: DownloadState::InProgress,
                                    seq,
                                },
                            );
                        }
                        "Browser.downloadProgress" => {
                            let state = match params["state"].as_str() {
                                Some("completed") => DownloadState::Completed,
                                Some("canceled") => DownloadState::Canceled,
                                _ => DownloadState::InProgress,
                            };
                            let mut registry = registry.lock().await;
                            if let Some(record) = registry.records.get_mut(guid) {
                                record.state = state;
                            }
                        }
                        _ => {}
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            }
        }
    })
}

#[cfg(all(test, windows))]
mod transport_loss_e2e;
