//! WebDriver BiDi backend for StealthBrowser.
//!
//! Launches Firefox, creates a WebDriver session with BiDi enabled,
//! then connects a BiDiClient to the returned WebSocket URL.

use std::future::Future;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc,
};
use std::time::Duration;

use futures::future::BoxFuture;
use tokio::io::{AsyncRead, AsyncReadExt};
use tracing::debug;

use crate::bidi::BiDiClient;
use crate::cookies::Cookie;
use crate::detect::{LaunchConfig, BrowserPreference, detect_browser};
use crate::identity::ProfileOwnershipGuard;
use crate::browser_process::BrowserProcess;
use crate::process_tree::OwnedProcessTree;
use crate::stealth::{StealthConfig, get_scripts};
use crate::webdriver::{Capabilities, WdClient, WdSession, WdElement};

use crate::browser::devtools::DevToolsEvent;
use crate::browser::error::BrowserError;
use super::{BrowserBackend, BoundingBox, ElementHandle, ElementInner, PageBackend, PrintOptions};

const WEBDRIVER_DELETE_TIMEOUT: Duration = Duration::from_secs(5);
const GECKODRIVER_MAX_STARTUP_TIMEOUT: Duration = Duration::from_secs(15);
const GECKODRIVER_TERMINATE_TIMEOUT: Duration = Duration::from_secs(5);
const BACKEND_HANDOFF_CLOSE_TIMEOUT: Duration = Duration::from_secs(15);
const GECKODRIVER_LOG_LIMIT: usize = 64 * 1024;
const GECKODRIVER_LINE_LIMIT: usize = 8 * 1024;

struct LaunchReady<T> {
    acknowledge: tokio::sync::oneshot::Sender<()>,
    backend: tokio::sync::oneshot::Receiver<T>,
}

async fn deliver_acknowledged_launch<T, C, F>(
    result: Result<T, BrowserError>,
    result_tx: tokio::sync::oneshot::Sender<Result<LaunchReady<T>, BrowserError>>,
    cleanup: C,
)
where
    T: Send + 'static,
    C: FnOnce(T) -> F + Send,
    F: Future<Output = ()> + Send,
{
    let backend = match result {
        Ok(backend) => backend,
        Err(error) => {
            let _ = result_tx.send(Err(error));
            return;
        }
    };
    let (acknowledge, acknowledged) = tokio::sync::oneshot::channel();
    let (backend_tx, backend_rx) = tokio::sync::oneshot::channel();
    if result_tx
        .send(Ok(LaunchReady {
            acknowledge,
            backend: backend_rx,
        }))
        .is_err()
    {
        cleanup(backend).await;
        return;
    }
    if acknowledged.await.is_err() {
        cleanup(backend).await;
        return;
    }
    if let Err(backend) = backend_tx.send(backend) {
        cleanup(backend).await;
    }
}

struct PendingProfileOwnership {
    guard: Option<ProfileOwnershipGuard>,
    retain_on_drop: bool,
}

impl PendingProfileOwnership {
    fn new(guard: ProfileOwnershipGuard) -> Self {
        Self {
            guard: Some(guard),
            retain_on_drop: false,
        }
    }

    fn arm_for_session_creation(&mut self) {
        self.retain_on_drop = true;
    }

    fn guard_mut(&mut self) -> &mut Option<ProfileOwnershipGuard> {
        &mut self.guard
    }

    fn transfer_to_backend(&mut self) -> Option<ProfileOwnershipGuard> {
        self.retain_on_drop = false;
        self.guard.take()
    }
}

impl Drop for PendingProfileOwnership {
    fn drop(&mut self) {
        if self.retain_on_drop {
            retain_profile_ownership_after_unconfirmed_teardown(
                self.guard.take(),
                &"Firefox startup was cancelled before WebDriver termination was confirmed",
            );
        }
    }
}

// ── Browser backend ────────────────────────────────────────────────────────

/// BiDi (Firefox) browser backend.
pub(crate) struct BiDiBrowserBackend {
    bidi: Arc<BiDiClient>,
    wd_session: Arc<WdSession>,
    launch: LaunchConfig,
    page_count: AtomicU32,
    profile_guard: Option<ProfileOwnershipGuard>,
    profile_dir: std::path::PathBuf,
    remove_profile_on_close: bool,
    owned_geckodriver: Option<OwnedGeckodriver>,
}

struct OwnedGeckodriver {
    process: BrowserProcess,
    process_tree: Arc<OwnedProcessTree>,
    log_readers: Vec<tokio::task::JoinHandle<()>>,
}

impl OwnedGeckodriver {
    async fn terminate(&mut self) -> Result<(), BrowserError> {
        if self.process_tree.supports_immediate_termination() {
            self.process_tree
                .terminate_and_wait(GECKODRIVER_TERMINATE_TIMEOUT)
                .await?;
        } else {
            self.process.kill().await?;
        }
        for reader in self.log_readers.drain(..) {
            reader.abort();
        }
        Ok(())
    }

    async fn finish_after_session_delete(&mut self) -> Result<(), BrowserError> {
        if self.process_tree.supports_immediate_termination() {
            // DELETE asks Firefox to exit gracefully. Stop only the driver
            // root, then let its Firefox descendants finish profile writes
            // while the Job Object still owns and observes them.
            let _ = self.process.start_kill();
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                self.process.wait(),
            )
            .await;
            let exited = self
                .process_tree
                .wait_until_empty(GECKODRIVER_TERMINATE_TIMEOUT)
                .await?;
            if !exited {
                self.process_tree
                    .terminate_and_wait(GECKODRIVER_TERMINATE_TIMEOUT)
                    .await?;
            }
        } else {
            self.process.kill().await?;
        }
        for reader in self.log_readers.drain(..) {
            reader.abort();
        }
        Ok(())
    }
}

impl Drop for OwnedGeckodriver {
    fn drop(&mut self) {
        let _ = self.process_tree.terminate_now();
        let _ = self.process.start_kill();
        for reader in self.log_readers.drain(..) {
            reader.abort();
        }
    }
}

enum GeckodriverLogSignal {
    Listening(SocketAddr),
    Limit(&'static str),
    Eof,
    ReadError(&'static str, std::io::Error),
}

async fn spawn_owned_geckodriver(
    binary: &Path,
    timeout: Duration,
) -> Result<(String, OwnedGeckodriver), BrowserError> {
    #[cfg(not(windows))]
    {
        let _ = (binary, timeout);
        return Err(BrowserError::Launch(
            "owned geckodriver is unsupported without descendant process-tree containment; use a caller-owned WebDriver URL"
                .into(),
        ));
    }

    #[cfg(windows)]
    {
    if timeout.is_zero() || timeout > GECKODRIVER_MAX_STARTUP_TIMEOUT {
        return Err(BrowserError::Launch(format!(
            "owned geckodriver startup timeout must be between 1ns and {GECKODRIVER_MAX_STARTUP_TIMEOUT:?}"
        )));
    }
    if !binary.is_file() {
        return Err(BrowserError::Launch(format!(
            "geckodriver binary is not a file: {}",
            binary.display()
        )));
    }

    let args = vec![
        "--host".to_owned(),
        "127.0.0.1".to_owned(),
        "--port".to_owned(),
        "0".to_owned(),
    ];
    let process_tree = Arc::new(OwnedProcessTree::new()?);

    let (process, stdout, stderr) = {
        let mut spawned = crate::browser_process::spawn_windows_child_suspended(binary, &args)?;
        if let Err(error) = process_tree.assign_raw_handle(spawned.process.raw_handle()) {
            let cleanup = terminate_failed_windows_spawn(&mut spawned.process).await;
            return Err(BrowserError::Launch(format!(
                "cannot assign geckodriver to its Job Object: {error}; root-process cleanup: {cleanup}"
            )));
        }
        if let Err(error) = spawned.process.resume() {
            let cleanup = terminate_failed_windows_spawn(&mut spawned.process).await;
            return Err(BrowserError::Launch(format!(
                "cannot resume contained geckodriver: {error}; root-process cleanup: {cleanup}"
            )));
        }
        (spawned.process, spawned.stdout, spawned.stderr)
    };

    let pid = process.id();
    let (signal_tx, mut signal_rx) = tokio::sync::mpsc::unbounded_channel();
    let readers = vec![
        tokio::spawn(read_geckodriver_log("stdout", stdout, signal_tx.clone())),
        tokio::spawn(read_geckodriver_log("stderr", stderr, signal_tx)),
    ];
    let mut owned = OwnedGeckodriver {
        process,
        process_tree,
        log_readers: readers,
    };
    let readiness = tokio::time::timeout(timeout, async {
        let mut eof_count = 0usize;
        while let Some(signal) = signal_rx.recv().await {
            match signal {
                GeckodriverLogSignal::Listening(endpoint) if endpoint.ip().is_loopback() => {
                    return Ok(endpoint);
                }
                GeckodriverLogSignal::Listening(endpoint) => {
                    return Err(BrowserError::Launch(format!(
                        "owned geckodriver announced a non-loopback listener: {endpoint}"
                    )));
                }
                GeckodriverLogSignal::Limit(stream) => {
                    return Err(BrowserError::Launch(format!(
                        "owned geckodriver {stream} exceeded the bounded readiness log limit"
                    )));
                }
                GeckodriverLogSignal::ReadError(stream, error) => {
                    return Err(BrowserError::Launch(format!(
                        "cannot read owned geckodriver {stream}: {error}"
                    )));
                }
                GeckodriverLogSignal::Eof => {
                    eof_count += 1;
                    if eof_count == 2 {
                        return Err(BrowserError::Launch(
                            "owned geckodriver exited before announcing its listener".into(),
                        ));
                    }
                }
            }
        }
        Err(BrowserError::Launch(
            "owned geckodriver readiness readers stopped unexpectedly".into(),
        ))
    })
    .await;
    match readiness {
        Ok(Ok(endpoint)) => {
            debug!(?pid, %endpoint, "owned geckodriver is listening");
            Ok((format!("http://{endpoint}"), owned))
        }
        Ok(Err(error)) => {
            let _ = owned.terminate().await;
            Err(error)
        }
        Err(_) => {
            let _ = owned.terminate().await;
            Err(BrowserError::Timeout(timeout))
        }
    }
    }
}

#[cfg(windows)]
async fn terminate_failed_windows_spawn(process: &mut BrowserProcess) -> String {
    let kill_result = process.start_kill();
    let wait_result = tokio::time::timeout(GECKODRIVER_TERMINATE_TIMEOUT, process.wait()).await;
    match wait_result {
        Ok(Ok(status)) => format!("confirmed ({status})"),
        Ok(Err(wait_error)) => match kill_result {
            Ok(()) => format!("unconfirmed; wait failed: {wait_error}"),
            Err(kill_error) => {
                format!("unconfirmed; terminate failed: {kill_error}; wait failed: {wait_error}")
            }
        },
        Err(_) => match kill_result {
            Ok(()) => format!("unconfirmed; wait timed out after {GECKODRIVER_TERMINATE_TIMEOUT:?}"),
            Err(kill_error) => format!(
                "unconfirmed; terminate failed: {kill_error}; wait timed out after {GECKODRIVER_TERMINATE_TIMEOUT:?}"
            ),
        },
    }
}

async fn read_geckodriver_log<R>(
    stream: &'static str,
    mut reader: R,
    signals: tokio::sync::mpsc::UnboundedSender<GeckodriverLogSignal>,
) where
    R: AsyncRead + Unpin,
{
    let mut chunk = [0u8; 1024];
    let mut line = Vec::new();
    let mut total = 0usize;
    let mut limited = false;
    loop {
        let read = match reader.read(&mut chunk).await {
            Ok(0) => {
                let _ = signals.send(GeckodriverLogSignal::Eof);
                return;
            }
            Ok(read) => read,
            Err(error) => {
                let _ = signals.send(GeckodriverLogSignal::ReadError(stream, error));
                return;
            }
        };
        if limited {
            continue;
        }
        total = total.saturating_add(read);
        if total > GECKODRIVER_LOG_LIMIT {
            limited = true;
            let _ = signals.send(GeckodriverLogSignal::Limit(stream));
            continue;
        }
        for byte in &chunk[..read] {
            if *byte == b'\n' || *byte == b'\r' {
                if !line.is_empty() {
                    if let Some(endpoint) = parse_geckodriver_listener(&line) {
                        let _ = signals.send(GeckodriverLogSignal::Listening(endpoint));
                    }
                    line.clear();
                }
                continue;
            }
            line.push(*byte);
            if line.len() > GECKODRIVER_LINE_LIMIT {
                limited = true;
                let _ = signals.send(GeckodriverLogSignal::Limit(stream));
                break;
            }
        }
    }
}

fn parse_geckodriver_listener(line: &[u8]) -> Option<SocketAddr> {
    let line = std::str::from_utf8(line).ok()?;
    let endpoint = line.rsplit_once("Listening on ")?.1.trim();
    endpoint.parse().ok()
}

impl BiDiBrowserBackend {
    /// Launch Firefox, create a WebDriver session with BiDi, connect the BiDi client.
    pub(crate) async fn launch(
        launch: &LaunchConfig,
        stealth: &StealthConfig,
    ) -> Result<Self, BrowserError> {
        let launch = launch.clone();
        let stealth = stealth.clone();
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let result = Self::launch_inner(&launch, &stealth).await;
            deliver_acknowledged_launch(result, result_tx, |backend| async move {
                if tokio::time::timeout(
                    BACKEND_HANDOFF_CLOSE_TIMEOUT,
                    Box::new(backend).close(),
                )
                .await
                .is_err()
                {
                    tracing::error!(
                        "timed out closing an unclaimed Firefox backend after launch cancellation"
                    );
                }
            })
            .await;
        });
        let ready = result_rx.await.map_err(|_| {
            BrowserError::Launch("Firefox startup task ended without a result".into())
        })??;
        ready.acknowledge.send(()).map_err(|_| {
            BrowserError::Launch("Firefox startup task ended before handoff acknowledgment".into())
        })?;
        ready.backend.await.map_err(|_| {
            BrowserError::Launch("Firefox startup task ended during acknowledged handoff".into())
        })
    }

    async fn launch_inner(
        launch: &LaunchConfig,
        stealth: &StealthConfig,
    ) -> Result<Self, BrowserError> {
        let binary = detect_browser(BrowserPreference::Firefox)?;
        debug!("Launching Firefox: {}", binary.path.display());
        let (profile_dir, remove_profile_on_close) = launch
            .profile
            .resolve()
            .map_err(|error| BrowserError::Launch(error.to_string()))?;
        let mut profile_ownership = PendingProfileOwnership::new(
            ProfileOwnershipGuard::acquire(&profile_dir)
                .map_err(|error| BrowserError::Launch(error.to_string()))?,
        );

        // An explicit binary gives this worker exclusive ownership of both the
        // driver and the Firefox descendants it creates. Leaving it unset is
        // the explicit compatibility path for a caller-owned WebDriver URL.
        let (webdriver_url, mut owned_geckodriver) = match &launch.geckodriver_binary {
            Some(binary) => {
                let (url, driver) = spawn_owned_geckodriver(
                    binary,
                    launch.geckodriver_startup_timeout,
                )
                .await?;
                (url, Some(driver))
            }
            None => (launch.geckodriver_url.clone(), None),
        };
        let client = WdClient::new(&webdriver_url);

        let mut caps = Capabilities::firefox()
            .with_bidi()
            .with_firefox_stealth_prefs()
            .firefox_binary(&binary.path)
            .firefox_profile(&profile_dir)
            .window_size(launch.window_size.0, launch.window_size.1);
        if launch.headless {
            caps = caps.headless();
        }
        if let Some(browser_proxy) = launch.browser_proxy {
            caps = caps.browser_proxy(browser_proxy);
        }

        // Once the request is polled, cancellation cannot prove that
        // geckodriver did not create a session. Keep ownership quarantined if
        // this future is dropped before a confirmed DELETE.
        profile_ownership.arm_for_session_creation();
        let session = match client.new_session(caps).await {
            Ok(session) => session,
            Err(error) => {
                if owned_geckodriver.is_some() {
                    terminate_owned_geckodriver(&mut owned_geckodriver).await?;
                    profile_ownership.retain_on_drop = false;
                    release_profile_after_confirmed_termination(
                        profile_ownership.guard_mut(),
                        &profile_dir,
                        remove_profile_on_close,
                    )?;
                }
                return Err(BrowserError::Connect(error.to_string()));
            }
        };

        let bidi = complete_post_session_initialization(
            &session,
            profile_ownership.guard_mut(),
            &profile_dir,
            remove_profile_on_close,
            &mut owned_geckodriver,
            async {
        // Extract the BiDi WebSocket URL from capabilities.
        let ws_url = session
            .capabilities
            .get("webSocketUrl")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                BrowserError::Connect(
                    "WebDriver session did not return webSocketUrl — BiDi not supported".into(),
                )
            })?
            .to_owned();

        debug!("BiDi WebSocket URL: {ws_url}");

        let bidi = BiDiClient::connect(&ws_url)
            .await
            .map_err(|e| BrowserError::Connect(e.to_string()))?;

        // Pre-register stealth scripts as preload scripts so they fire on every
        // navigation in any browsing context.
        //
        // BiDi `script.addPreloadScript` expects a *function declaration* string
        // (e.g. `function() { ... }`) — NOT an IIFE expression. The browser
        // parses + calls the function automatically.
        let scripts = get_scripts(stealth);
        for script in &scripts {
            let wrapped = format!("function() {{ {} }}", script);
            bidi.add_preload_script(&wrapped, None)
                .await
                .map_err(|e| BrowserError::StealthInject(e.to_string()))?;
        }
        Ok(bidi)
            },
        )
        .await?;

        Ok(Self {
            bidi,
            wd_session: Arc::new(session),
            launch: launch.clone(),
            page_count: AtomicU32::new(0),
            profile_guard: profile_ownership.transfer_to_backend(),
            profile_dir,
            remove_profile_on_close,
            owned_geckodriver,
        })
    }
}

impl Drop for BiDiBrowserBackend {
    fn drop(&mut self) {
        if let Some(driver) = self.owned_geckodriver.as_ref() {
            let _ = driver.process_tree.terminate_now();
        }
        retain_profile_ownership_after_unconfirmed_teardown(
            self.profile_guard.take(),
            &"Firefox backend dropped before WebDriver termination was confirmed",
        );
    }
}

async fn complete_post_session_initialization<T, F>(
    session: &WdSession,
    profile_guard: &mut Option<ProfileOwnershipGuard>,
    profile_dir: &Path,
    remove_profile_on_close: bool,
    owned_geckodriver: &mut Option<OwnedGeckodriver>,
    initialization: F,
) -> Result<T, BrowserError>
where
    F: Future<Output = Result<T, BrowserError>>,
{
    let initialization_error = match initialization.await {
        Ok(value) => return Ok(value),
        Err(error) => error,
    };

    let delete_result = bounded_delete_webdriver_session(session).await;
    let has_owned_geckodriver = owned_geckodriver.is_some();
    let owned_termination = terminate_owned_geckodriver(owned_geckodriver).await;
    let termination_result = if has_owned_geckodriver {
        owned_termination
    } else {
        Err(external_webdriver_termination_unconfirmed())
    };
    if termination_result.is_ok() {
        if let Err(cleanup_error) = release_profile_after_confirmed_termination(
            profile_guard,
            profile_dir,
            remove_profile_on_close,
        ) {
            tracing::error!(
                "failed to clean profile after confirmed WebDriver termination: {cleanup_error}"
            );
            return Err(BrowserError::Launch(format!(
                "post-session BiDi initialization failed: {initialization_error}; profile cleanup failed: {cleanup_error}"
            )));
        }
    } else {
        let teardown_error = termination_result
            .err()
            .or_else(|| delete_result.err())
            .expect("unconfirmed termination must have an error");
        tracing::error!(
            "post-session BiDi initialization failed and process termination was not confirmed: {teardown_error}"
        );
        retain_profile_ownership_after_unconfirmed_teardown(
            profile_guard.take(),
            &teardown_error,
        );
        return Err(BrowserError::Launch(format!(
            "post-session BiDi initialization failed: {initialization_error}; Firefox termination was not confirmed: {teardown_error}"
        )));
    }

    Err(initialization_error)
}

async fn terminate_owned_geckodriver(
    owned_geckodriver: &mut Option<OwnedGeckodriver>,
) -> Result<(), BrowserError> {
    match owned_geckodriver.as_mut() {
        Some(driver) => driver.terminate().await,
        None => Ok(()),
    }
}

async fn finish_owned_geckodriver_after_session_delete(
    owned_geckodriver: &mut Option<OwnedGeckodriver>,
) -> Result<(), BrowserError> {
    match owned_geckodriver.as_mut() {
        Some(driver) => driver.finish_after_session_delete().await,
        None => Ok(()),
    }
}

async fn bounded_delete_webdriver_session(session: &WdSession) -> Result<(), BrowserError> {
    match tokio::time::timeout(WEBDRIVER_DELETE_TIMEOUT, session.delete("")).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(error)) => Err(BrowserError::WebDriver(error)),
        Err(_) => Err(BrowserError::Timeout(WEBDRIVER_DELETE_TIMEOUT)),
    }
}

fn release_profile_after_confirmed_termination(
    profile_guard: &mut Option<ProfileOwnershipGuard>,
    profile_dir: &Path,
    remove_profile_on_close: bool,
) -> Result<(), BrowserError> {
    release_profile_after_confirmed_termination_with(
        profile_guard,
        profile_dir,
        remove_profile_on_close,
        |path| std::fs::remove_dir_all(path),
    )
}

fn release_profile_after_confirmed_termination_with<R>(
    profile_guard: &mut Option<ProfileOwnershipGuard>,
    profile_dir: &Path,
    remove_profile_on_close: bool,
    remove_profile: R,
) -> Result<(), BrowserError>
where
    R: FnOnce(&Path) -> std::io::Result<()>,
{
    if remove_profile_on_close && profile_dir.exists() {
        if let Err(error) = remove_profile(profile_dir) {
            retain_profile_ownership_after_unconfirmed_teardown(
                profile_guard.take(),
                &format_args!("ephemeral profile cleanup failed: {error}"),
            );
            return Err(BrowserError::Io(error));
        }
    }
    drop(profile_guard.take());
    Ok(())
}

fn external_webdriver_termination_unconfirmed() -> BrowserError {
    BrowserError::Launch(
        "caller-owned WebDriver DELETE does not confirm Firefox process termination".into(),
    )
}

fn mark_external_webdriver_termination_unconfirmed(outcome: &mut TeardownOutcome) {
    outcome.process_termination_confirmed = false;
    if let Err(error) = &outcome.result {
        tracing::error!(
            "external WebDriver teardown also failed before Firefox termination could be confirmed: {error}"
        );
    }
    outcome.result = Err(external_webdriver_termination_unconfirmed());
}

fn quarantine_profile_after_unconfirmed_outcome(
    outcome: &TeardownOutcome,
    profile_guard: &mut Option<ProfileOwnershipGuard>,
) -> bool {
    if outcome.process_termination_confirmed {
        return false;
    }
    let error = outcome
        .result
        .as_ref()
        .expect_err("unconfirmed termination must carry an error");
    retain_profile_ownership_after_unconfirmed_teardown(profile_guard.take(), error);
    true
}

struct TeardownOutcome {
    process_termination_confirmed: bool,
    webdriver_delete_confirmed: bool,
    result: Result<(), BrowserError>,
}

fn reconcile_teardown_results(
    transport_result: Result<(), BrowserError>,
    webdriver_result: Result<(), BrowserError>,
) -> TeardownOutcome {
    match (transport_result, webdriver_result) {
        (Ok(()), Ok(())) => TeardownOutcome {
            process_termination_confirmed: true,
            webdriver_delete_confirmed: true,
            result: Ok(()),
        },
        (Err(transport_error), Ok(())) => TeardownOutcome {
            process_termination_confirmed: true,
            webdriver_delete_confirmed: true,
            result: Err(transport_error),
        },
        (Ok(()), Err(webdriver_error)) => TeardownOutcome {
            process_termination_confirmed: false,
            webdriver_delete_confirmed: false,
            result: Err(webdriver_error),
        },
        (Err(transport_error), Err(webdriver_error)) => {
            tracing::error!(
                "BiDi transport teardown also failed before unconfirmed WebDriver termination: {transport_error}"
            );
            TeardownOutcome {
                process_termination_confirmed: false,
                webdriver_delete_confirmed: false,
                result: Err(webdriver_error),
            }
        }
    }
}

fn accept_transport_error_after_confirmed_owned_termination(
    outcome: &mut TeardownOutcome,
) {
    if outcome.process_termination_confirmed
        && outcome.webdriver_delete_confirmed
        && outcome.result.is_err()
    {
        outcome.result = Ok(());
    }
}

async fn teardown_concurrently<T, W>(
    transport: T,
    webdriver: W,
) -> TeardownOutcome
where
    T: Future<Output = Result<(), BrowserError>>,
    W: Future<Output = Result<(), BrowserError>>,
{
    let (transport_result, webdriver_result) = tokio::join!(transport, webdriver);
    reconcile_teardown_results(transport_result, webdriver_result)
}

impl BrowserBackend for BiDiBrowserBackend {
    fn new_page<'a>(
        &'a self,
        url: &'a str,
    ) -> BoxFuture<'a, Result<Box<dyn PageBackend>, BrowserError>> {
        Box::pin(async move {
            let handle = self
                .wd_session
                .new_window()
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            // Switch WebDriver focus to the new window.
            self.wd_session
                .switch_to_window(&handle)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            // Navigate to the requested URL.
            self.wd_session
                .goto(url)
                .await
                .map_err(|e| BrowserError::Navigate(e.to_string()))?;

            self.page_count.fetch_add(1, Ordering::Relaxed);

            let page = BiDiPageBackend {
                wd_session: Arc::clone(&self.wd_session),
                _bidi: Arc::clone(&self.bidi),
                window_handle: handle,
            };

            Ok(Box::new(page) as Box<dyn PageBackend>)
        })
    }

    fn new_blank_page<'a>(&'a self) -> BoxFuture<'a, Result<Box<dyn PageBackend>, BrowserError>> {
        Box::pin(async move {
            let handle = self
                .wd_session
                .new_window()
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            self.wd_session
                .switch_to_window(&handle)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            self.page_count.fetch_add(1, Ordering::Relaxed);

            let page = BiDiPageBackend {
                wd_session: Arc::clone(&self.wd_session),
                _bidi: Arc::clone(&self.bidi),
                window_handle: handle,
            };

            Ok(Box::new(page) as Box<dyn PageBackend>)
        })
    }

    fn close<'a>(self: Box<Self>) -> BoxFuture<'a, Result<(), BrowserError>> {
        Box::pin(async move {
            let mut backend = self;

            // Run DELETE independently of transport teardown. This guarantees
            // geckodriver receives its bounded termination request even when
            // the WebSocket close path stalls or needs task abortion.
            let mut outcome = teardown_concurrently(
                async {
                    backend
                        .bidi
                        .close_transport()
                        .await
                        .map_err(BrowserError::BiDi)
                },
                bounded_delete_webdriver_session(&backend.wd_session),
            )
            .await;
            if backend.owned_geckodriver.is_some() {
                match finish_owned_geckodriver_after_session_delete(
                    &mut backend.owned_geckodriver,
                )
                .await
                {
                    Ok(()) => {
                        outcome.process_termination_confirmed = true;
                        accept_transport_error_after_confirmed_owned_termination(
                            &mut outcome,
                        );
                    }
                    Err(error) => {
                        outcome.process_termination_confirmed = false;
                        outcome.result = Err(error);
                    }
                }
            } else {
                mark_external_webdriver_termination_unconfirmed(&mut outcome);
            }
            if quarantine_profile_after_unconfirmed_outcome(
                &outcome,
                &mut backend.profile_guard,
            ) {
                return outcome.result;
            }

            let cleanup_result = release_profile_after_confirmed_termination(
                &mut backend.profile_guard,
                &backend.profile_dir,
                backend.remove_profile_on_close,
            );
            match (outcome.result, cleanup_result) {
                (Ok(()), cleanup_result) => cleanup_result,
                (Err(transport_error), Ok(())) => Err(transport_error),
                (Err(transport_error), Err(cleanup_error)) => {
                    tracing::error!(
                        "profile cleanup also failed after BiDi transport error: {cleanup_error}"
                    );
                    Err(transport_error)
                }
            }
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

// ── Page backend ────────────────────────────────────────────────────────────

fn retain_profile_ownership_after_unconfirmed_teardown(
    guard: Option<ProfileOwnershipGuard>,
    error: &dyn std::fmt::Display,
) {
    if let Some(guard) = guard {
        tracing::error!(
            "WebDriver termination was not confirmed; retaining profile ownership until process exit: {error}"
        );
        guard.retain_until_process_exit();
    }
}

/// BiDi-backed page handle.
pub(crate) struct BiDiPageBackend {
    wd_session: Arc<WdSession>,
    /// Kept alive so the underlying WebSocket connection stays open.
    _bidi: Arc<BiDiClient>,
    window_handle: String,
}

impl PageBackend for BiDiPageBackend {
    fn goto<'a>(&'a self, url: &'a str) -> BoxFuture<'a, Result<(), BrowserError>> {
        Box::pin(async move {
            // Ensure the WebDriver focus is on our window.
            self.wd_session
                .switch_to_window(&self.window_handle)
                .await
                .map_err(|e| BrowserError::Navigate(e.to_string()))?;

            self.wd_session
                .goto(url)
                .await
                .map_err(|e| BrowserError::Navigate(e.to_string()))
        })
    }

    fn html<'a>(&'a self) -> BoxFuture<'a, Result<String, BrowserError>> {
        Box::pin(async move {
            self.wd_session
                .switch_to_window(&self.window_handle)
                .await
                .map_err(|e| BrowserError::JsEval(e.to_string()))?;

            self.wd_session
                .source()
                .await
                .map_err(|e| BrowserError::JsEval(e.to_string()))
        })
    }

    fn eval<'a>(&'a self, js: &'a str) -> BoxFuture<'a, Result<serde_json::Value, BrowserError>> {
        Box::pin(async move {
            self.wd_session
                .switch_to_window(&self.window_handle)
                .await
                .map_err(|e| BrowserError::JsEval(e.to_string()))?;

            // WebDriver execute/sync wraps the script in a function body,
            // so bare expressions like "document.title" return undefined.
            // Auto-prepend "return" for expression-style scripts.
            let script = if needs_return_prefix(js) {
                format!("return {js}")
            } else {
                js.to_owned()
            };

            self.wd_session
                .execute_sync(&script, vec![])
                .await
                .map_err(|e| BrowserError::JsEval(e.to_string()))
        })
    }

    fn screenshot<'a>(&'a self) -> BoxFuture<'a, Result<Vec<u8>, BrowserError>> {
        Box::pin(async move {
            self.wd_session
                .switch_to_window(&self.window_handle)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            self.wd_session
                .screenshot()
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))
        })
    }

    fn get_cookies<'a>(
        &'a self,
    ) -> BoxFuture<'a, Result<Vec<Cookie>, BrowserError>> {
        Box::pin(async move {
            self.wd_session
                .switch_to_window(&self.window_handle)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            let wd_cookies = self
                .wd_session
                .get_cookies()
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            let cookies = wd_cookies
                .into_iter()
                .map(|c| Cookie {
                    name: c.name,
                    value: c.value,
                    domain: c.domain.unwrap_or_default(),
                    path: c.path.unwrap_or_else(|| "/".into()),
                    is_secure: c.secure.unwrap_or(false),
                    is_httponly: c.http_only.unwrap_or(false),
                    expires_utc: c.expiry.map(|e| e as i64),
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
            self.wd_session
                .switch_to_window(&self.window_handle)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            for cookie in cookies {
                let wd_cookie = crate::webdriver::WdCookie {
                    name: cookie.name.clone(),
                    value: cookie.value.clone(),
                    domain: Some(cookie.domain.clone()),
                    path: Some(cookie.path.clone()),
                    secure: Some(cookie.is_secure),
                    http_only: Some(cookie.is_httponly),
                    expiry: cookie.expires_utc.map(|t| t as u64),
                };
                self.wd_session
                    .add_cookie(wd_cookie)
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
            self.wd_session
                .switch_to_window(&self.window_handle)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            let el = self
                .wd_session
                .find_element("css selector", selector)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            Ok(ElementHandle {
                inner: ElementInner::WebDriver {
                    element_id: el.element_id,
                },
            })
        })
    }

    fn find_elements<'a>(
        &'a self,
        selector: &'a str,
    ) -> BoxFuture<'a, Result<Vec<ElementHandle>, BrowserError>> {
        Box::pin(async move {
            self.wd_session
                .switch_to_window(&self.window_handle)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            let els = self
                .wd_session
                .find_elements("css selector", selector)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            Ok(els
                .into_iter()
                .map(|el| ElementHandle {
                    inner: ElementInner::WebDriver {
                        element_id: el.element_id,
                    },
                })
                .collect())
        })
    }

    fn click_element<'a>(
        &'a self,
        element: &'a ElementHandle,
    ) -> BoxFuture<'a, Result<(), BrowserError>> {
        Box::pin(async move {
            let wd_el = wd_element(element)?;
            self.wd_session
                .switch_to_window(&self.window_handle)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            self.wd_session
                .click(&wd_el)
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
            let wd_el = wd_element(element)?;
            self.wd_session
                .switch_to_window(&self.window_handle)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            self.wd_session
                .send_keys(&wd_el, text)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))
        })
    }

    fn element_text<'a>(
        &'a self,
        element: &'a ElementHandle,
    ) -> BoxFuture<'a, Result<String, BrowserError>> {
        Box::pin(async move {
            let wd_el = wd_element(element)?;
            self.wd_session
                .switch_to_window(&self.window_handle)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            self.wd_session
                .element_text(&wd_el)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))
        })
    }

    fn element_attribute<'a>(
        &'a self,
        element: &'a ElementHandle,
        name: &'a str,
    ) -> BoxFuture<'a, Result<Option<String>, BrowserError>> {
        Box::pin(async move {
            let wd_el = wd_element(element)?;
            self.wd_session
                .switch_to_window(&self.window_handle)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            self.wd_session
                .element_attribute(&wd_el, name)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))
        })
    }

    fn element_html<'a>(
        &'a self,
        element: &'a ElementHandle,
    ) -> BoxFuture<'a, Result<String, BrowserError>> {
        Box::pin(async move {
            let wd_el = wd_element(element)?;
            self.wd_session
                .switch_to_window(&self.window_handle)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            // Use execute_sync to get outerHTML via the element reference.
            let el_json = serde_json::json!({
                "element-6066-11e4-a52e-4f735466cecf": wd_el.element_id
            });
            let result = self
                .wd_session
                .execute_sync("return arguments[0].outerHTML", vec![el_json])
                .await
                .map_err(|e| BrowserError::JsEval(e.to_string()))?;

            Ok(result.as_str().unwrap_or("").to_owned())
        })
    }

    fn element_bounding_box<'a>(
        &'a self,
        element: &'a ElementHandle,
    ) -> BoxFuture<'a, Result<BoundingBox, BrowserError>> {
        Box::pin(async move {
            let wd_el = wd_element(element)?;
            self.wd_session
                .switch_to_window(&self.window_handle)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            let rect = self
                .wd_session
                .element_rect(&wd_el)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            Ok(BoundingBox {
                x: rect.x,
                y: rect.y,
                width: rect.width,
                height: rect.height,
            })
        })
    }

    // ── PDF ───────────────────────────────────────────────────────────────

    fn print_pdf<'a>(
        &'a self,
        options: &'a PrintOptions,
    ) -> BoxFuture<'a, Result<Vec<u8>, BrowserError>> {
        Box::pin(async move {
            self.wd_session
                .switch_to_window(&self.window_handle)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            let wd_opts = crate::webdriver::PrintOptions {
                orientation: if options.landscape {
                    Some("landscape".to_owned())
                } else {
                    Some("portrait".to_owned())
                },
                scale: options.scale,
                background: if options.print_background { Some(true) } else { None },
                page: options.paper_width.zip(options.paper_height).map(|(w, h)| {
                    crate::webdriver::PrintPage { width: w, height: h }
                }),
                margin: None,
            };

            let result = self
                .wd_session
                .print_pdf(wd_opts)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            Ok(result)
        })
    }

    // ── Enhanced screenshots ───────────────────────────────────────────────

    fn screenshot_full_page<'a>(&'a self) -> BoxFuture<'a, Result<Vec<u8>, BrowserError>> {
        Box::pin(async move {
            self.wd_session
                .switch_to_window(&self.window_handle)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            // Scroll to max to trigger lazy loading, then take screenshot.
            // WebDriver screenshot already returns full-page in Firefox.
            let _ = self
                .wd_session
                .execute_sync(
                    "window.scrollTo(0, document.body.scrollHeight)",
                    vec![],
                )
                .await;

            // Brief yield so the browser processes the scroll.
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;

            self.wd_session
                .screenshot()
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))
        })
    }

    fn screenshot_element<'a>(
        &'a self,
        element: &'a ElementHandle,
    ) -> BoxFuture<'a, Result<Vec<u8>, BrowserError>> {
        Box::pin(async move {
            let wd_el = wd_element(element)?;
            self.wd_session
                .switch_to_window(&self.window_handle)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            let bytes = self
                .wd_session
                .element_screenshot(&wd_el)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            Ok(bytes)
        })
    }

    fn set_extra_http_headers<'a>(
        &'a self,
        _headers: std::collections::HashMap<String, String>,
    ) -> BoxFuture<'a, Result<(), BrowserError>> {
        // BiDi has no direct equivalent of Network.setExtraHTTPHeaders.
        // Return Ok(()) so callers can use the same API regardless of backend.
        Box::pin(async move { Ok(()) })
    }

    fn set_bypass_csp<'a>(&'a self, _enabled: bool) -> BoxFuture<'a, Result<(), BrowserError>> {
        // Page.setBypassCSP is a CDP-only feature. BiDi has no equivalent.
        // Return Ok(()) so callers can use the same API regardless of backend.
        Box::pin(async move { Ok(()) })
    }

    fn add_script_to_evaluate_on_new_document<'a>(
        &'a self,
        _source: &'a str,
    ) -> BoxFuture<'a, Result<String, BrowserError>> {
        // BiDi equivalent is addPreloadScript, which is already used internally for stealth.
        // The public StealthPage::add_script_to_evaluate_on_new_document is CDP-only.
        // Return empty identifier string so callers are not broken.
        Box::pin(async move { Ok(String::new()) })
    }

    // ── Raw input by coordinates (no-op on BiDi — WebDriver has no Input domain) ──

    fn click_at<'a>(&'a self, x: f64, y: f64) -> BoxFuture<'a, Result<(), BrowserError>> {
        let js = format!("document.elementFromPoint({x}, {y})?.click()");
        Box::pin(async move {
            self.wd_session
                .execute_sync(&js, vec![])
                .await
                .map(|_| ())
                .map_err(|e| BrowserError::Other(e.to_string()))
        })
    }

    fn right_click_at<'a>(&'a self, _x: f64, _y: f64) -> BoxFuture<'a, Result<(), BrowserError>> {
        // BiDi has no right-click by coordinates; no-op.
        Box::pin(async move { Ok(()) })
    }

    fn mouse_move_to<'a>(&'a self, _x: f64, _y: f64) -> BoxFuture<'a, Result<(), BrowserError>> {
        Box::pin(async move { Ok(()) })
    }

    fn drag<'a>(
        &'a self,
        _x1: f64,
        _y1: f64,
        _x2: f64,
        _y2: f64,
    ) -> BoxFuture<'a, Result<(), BrowserError>> {
        Box::pin(async move { Ok(()) })
    }

    fn wheel<'a>(
        &'a self,
        _x: f64,
        _y: f64,
        _dx: f64,
        _dy: f64,
    ) -> BoxFuture<'a, Result<(), BrowserError>> {
        Box::pin(async move { Ok(()) })
    }

    fn key_press<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), BrowserError>> {
        let script = format!("document.activeElement?.dispatchEvent(new KeyboardEvent('keydown', {{key: {key_json}, bubbles: true}}));", key_json = serde_json::to_string(key).unwrap_or_else(|_| "\"\"".into()));
        Box::pin(async move {
            self.wd_session
                .execute_sync(&script, vec![])
                .await
                .map(|_| ())
                .map_err(|e| BrowserError::Other(e.to_string()))
        })
    }

    fn key_chord<'a>(
        &'a self,
        _modifiers: &'a [&'a str],
        _key: &'a str,
    ) -> BoxFuture<'a, Result<(), BrowserError>> {
        Box::pin(async move { Ok(()) })
    }

    // ── Viewport emulation ────────────────────────────────────────────────

    fn set_viewport<'a>(
        &'a self,
        _width: u32,
        _height: u32,
        _device_scale_factor: f64,
    ) -> BoxFuture<'a, Result<(), BrowserError>> {
        Box::pin(async move { Ok(()) })
    }

    fn clear_viewport_override<'a>(&'a self) -> BoxFuture<'a, Result<(), BrowserError>> {
        Box::pin(async move { Ok(()) })
    }

    // ── Raw CDP escape hatch (not available on BiDi) ──────────────────────

    fn cdp_call<'a>(
        &'a self,
        _method: &'a str,
        _params: Option<serde_json::Value>,
    ) -> BoxFuture<'a, Result<serde_json::Value, BrowserError>> {
        Box::pin(async move {
            Err(BrowserError::Other(
                "cdp_call is not supported on the BiDi (Firefox) backend".into(),
            ))
        })
    }

    // ── DevTools events ───────────────────────────────────────────────────

    fn subscribe_events<'a>(
        &'a self,
    ) -> BoxFuture<'a, Result<tokio::sync::broadcast::Receiver<DevToolsEvent>, BrowserError>> {
        Box::pin(async move {
            // Tell Firefox to actually send network + log events.
            self._bidi
                .subscribe_network(None)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;
            self._bidi
                .subscribe_log(None)
                .await
                .map_err(|e| BrowserError::Other(e.to_string()))?;

            // Subscribe to BiDi events and bridge to DevToolsEvent.
            let (tx, rx) = tokio::sync::broadcast::channel::<DevToolsEvent>(4096);
            let mut bidi_rx = self._bidi.subscribe();

            tokio::spawn(async move {
                loop {
                    match bidi_rx.recv().await {
                        Ok(event) => {
                            let dt_event = bridge_bidi_event(event);
                            if let Some(e) = dt_event {
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

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Extract a `WdElement` from an `ElementHandle`, returning an error if it's
/// a CDP handle.
fn wd_element(element: &ElementHandle) -> Result<WdElement, BrowserError> {
    match &element.inner {
        ElementInner::WebDriver { element_id } => Ok(WdElement {
            element_id: element_id.clone(),
        }),
        ElementInner::Cdp { .. } => Err(BrowserError::Other(
            "ElementHandle is a CDP handle, not a WebDriver handle".into(),
        )),
    }
}

/// Map a raw BiDi event into a `DevToolsEvent` if it's relevant.
fn bridge_bidi_event(event: crate::bidi::BiDiEvent) -> Option<DevToolsEvent> {
    use crate::browser::devtools::{ConsoleEvent, NetworkEvent};

    match event.method.as_str() {
        m if m.starts_with("network.") => {
            let params = event.params.clone();
            let url = params["request"]["url"].as_str().map(|s| s.to_owned());
            let status = params["response"]["status"].as_u64().map(|s| s as u16);
            Some(DevToolsEvent::Network(NetworkEvent {
                method: event.method,
                url,
                status,
                params,
            }))
        }
        "log.entryAdded" => {
            let params = event.params.clone();
            let level = params["level"].as_str().unwrap_or("log").to_owned();
            let text = params["text"].as_str().unwrap_or("").to_owned();
            Some(DevToolsEvent::Console(ConsoleEvent { level, text }))
        }
        _ => None,
    }
}

/// Returns `true` if the JS snippet is a bare expression that needs `return`
/// prepended for WebDriver `execute/sync` (which wraps scripts in a function body).
///
/// Statements like `return ...`, `var ...`, `let ...`, `const ...`, `if ...`,
/// `for ...`, `while ...`, `try ...`, `throw ...`, `{...}` are left as-is.
fn needs_return_prefix(js: &str) -> bool {
    let trimmed = js.trim_start();
    if trimmed.is_empty() {
        return false;
    }
    // Already has return, or is a statement.
    let statement_prefixes = [
        "return ", "return;", "var ", "let ", "const ", "if ", "if(", "for ", "for(",
        "while ", "while(", "do ", "do{", "switch ", "switch(", "try ", "try{",
        "throw ", "function ", "class ", "async ", "await ", "{",
    ];
    let lower = trimmed.to_ascii_lowercase();
    for prefix in &statement_prefixes {
        if lower.starts_with(prefix) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod lifecycle_tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
    use std::time::Instant;

    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_acknowledged_launch_closes_unclaimed_backend_asynchronously() {
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        let cleanup_ran = Arc::new(AtomicBool::new(false));
        let cleanup_observed = Arc::clone(&cleanup_ran);
        let (cleanup_tx, cleanup_rx) = tokio::sync::oneshot::channel();
        let delivery = tokio::spawn(async move {
            deliver_acknowledged_launch(Ok(7_u8), result_tx, move |backend| async move {
                assert_eq!(backend, 7);
                cleanup_observed.store(true, AtomicOrdering::SeqCst);
                let _ = cleanup_tx.send(());
            })
            .await;
        });

        let ready = result_rx.await.unwrap().unwrap();
        ready.acknowledge.send(()).unwrap();
        drop(ready.backend);

        cleanup_rx.await.unwrap();
        delivery.await.unwrap();
        assert!(cleanup_ran.load(AtomicOrdering::SeqCst));
    }

    #[test]
    fn geckodriver_listener_parser_accepts_only_complete_socket_addresses() {
        assert_eq!(
            parse_geckodriver_listener(b"1712345678\tgeckodriver\tINFO\tListening on 127.0.0.1:54321"),
            Some("127.0.0.1:54321".parse().unwrap())
        );
        assert_eq!(
            parse_geckodriver_listener(b"Listening on localhost:4444"),
            None
        );
        assert_eq!(parse_geckodriver_listener(b"unrelated log line"), None);
    }

    #[tokio::test]
    async fn geckodriver_readiness_reader_rejects_an_unbounded_line() {
        use tokio::io::AsyncWriteExt;

        let (reader, mut writer) = tokio::io::duplex(GECKODRIVER_LINE_LIMIT * 2);
        let (signals, mut received) = tokio::sync::mpsc::unbounded_channel();
        let task = tokio::spawn(read_geckodriver_log("test", reader, signals));
        writer
            .write_all(&vec![b'x'; GECKODRIVER_LINE_LIMIT + 1])
            .await
            .unwrap();
        assert!(matches!(
            received.recv().await,
            Some(GeckodriverLogSignal::Limit("test"))
        ));
        drop(writer);
        task.await.unwrap();
    }

    fn spawn_delete_server(
        profile_dir: std::path::PathBuf,
    ) -> (String, std::thread::JoinHandle<bool>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(7);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            return false;
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => return false,
                }
            };
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = [0_u8; 2048];
            let bytes_read = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..bytes_read]);
            let received_delete = request.starts_with("DELETE /session/test-session ");
            let ownership_was_held = ProfileOwnershipGuard::acquire(&profile_dir).is_err();

            let body = r#"{"value":null}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
            stream.flush().unwrap();
            received_delete && ownership_was_held
        });
        (endpoint, server)
    }

    #[tokio::test]
    async fn post_session_failure_with_external_webdriver_retains_profile_ownership() {
        let profile_dir = std::env::temp_dir().join(format!(
            "dig2browser-bidi-post-session-failure-{}",
            uuid::Uuid::new_v4()
        ));
        let mut profile_guard = Some(ProfileOwnershipGuard::acquire(&profile_dir).unwrap());
        let (webdriver_url, server) = spawn_delete_server(profile_dir.clone());
        let session = WdSession {
            client: Arc::new(WdClient::new(&webdriver_url)),
            session_id: "test-session".into(),
            capabilities: serde_json::json!({}),
        };

        let result = complete_post_session_initialization(
            &session,
            &mut profile_guard,
            &profile_dir,
            false,
            &mut None,
            async { Err::<(), _>(BrowserError::Connect("missing BiDi URL".into())) },
        )
        .await;

        assert!(matches!(result, Err(BrowserError::Launch(_))));
        assert!(server.join().unwrap(), "DELETE did not observe profile ownership");
        assert!(profile_guard.is_none(), "ownership must move into quarantine");
        assert!(ProfileOwnershipGuard::acquire(&profile_dir).is_err());
        ProfileOwnershipGuard::release_retained_for_test(&profile_dir);
        std::fs::remove_dir_all(profile_dir).unwrap();
    }

    #[tokio::test]
    async fn webdriver_delete_runs_while_transport_teardown_is_pending() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let delete_seen = Arc::new(tokio::sync::Notify::new());
        let server_delete_seen = Arc::clone(&delete_seen);
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 2048];
            let bytes_read = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..bytes_read]);
            let received_delete = request.starts_with("DELETE /session/test-session ");
            server_delete_seen.notify_one();
            let body = r#"{"value":null}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
            received_delete
        });
        let session = WdSession {
            client: Arc::new(WdClient::new(&endpoint)),
            session_id: "test-session".into(),
            capabilities: serde_json::json!({}),
        };
        let transport = async move {
            tokio::time::timeout(Duration::from_secs(1), delete_seen.notified())
                .await
                .expect("DELETE must start before transport teardown returns");
            Err(BrowserError::BiDi(crate::bidi::BiDiError::ConnectionClosed))
        };

        let outcome = teardown_concurrently(
            transport,
            bounded_delete_webdriver_session(&session),
        )
        .await;

        assert!(server.join().unwrap());
        assert!(outcome.process_termination_confirmed);
        assert!(matches!(outcome.result, Err(BrowserError::BiDi(_))));
    }

    #[test]
    fn confirmed_delete_and_owned_termination_accept_transport_teardown_error() {
        let mut closed = reconcile_teardown_results(
            Err(BrowserError::BiDi(
                crate::bidi::BiDiError::ConnectionClosed,
            )),
            Ok(()),
        );
        closed.process_termination_confirmed = true;
        accept_transport_error_after_confirmed_owned_termination(&mut closed);
        assert!(closed.result.is_ok());

        let mut delete_failed = reconcile_teardown_results(
            Err(BrowserError::BiDi(
                crate::bidi::BiDiError::ConnectionClosed,
            )),
            Err(BrowserError::Other("WebDriver DELETE failed".into())),
        );
        delete_failed.process_termination_confirmed = true;
        accept_transport_error_after_confirmed_owned_termination(
            &mut delete_failed,
        );
        assert!(delete_failed.result.is_err());
    }

    #[test]
    fn external_webdriver_delete_does_not_confirm_firefox_termination() {
        let mut outcome = reconcile_teardown_results(Ok(()), Ok(()));

        mark_external_webdriver_termination_unconfirmed(&mut outcome);

        assert!(!outcome.process_termination_confirmed);
        assert!(matches!(outcome.result, Err(BrowserError::Launch(_))));
    }

    #[test]
    fn external_webdriver_close_quarantines_profile_after_successful_delete() {
        let profile_dir = std::env::temp_dir().join(format!(
            "dig2browser-bidi-external-close-{}",
            uuid::Uuid::new_v4()
        ));
        let mut profile_guard = Some(ProfileOwnershipGuard::acquire(&profile_dir).unwrap());
        let mut outcome = reconcile_teardown_results(Ok(()), Ok(()));
        mark_external_webdriver_termination_unconfirmed(&mut outcome);

        assert!(quarantine_profile_after_unconfirmed_outcome(
            &outcome,
            &mut profile_guard,
        ));
        assert!(profile_guard.is_none());
        assert!(ProfileOwnershipGuard::acquire(&profile_dir).is_err());
        ProfileOwnershipGuard::release_retained_for_test(&profile_dir);
        std::fs::remove_dir_all(profile_dir).unwrap();
    }

    #[test]
    fn ephemeral_profile_is_deleted_before_ownership_is_released() {
        let profile_dir = std::env::temp_dir().join(format!(
            "dig2browser-bidi-confirmed-delete-{}",
            uuid::Uuid::new_v4()
        ));
        let mut profile_guard = Some(ProfileOwnershipGuard::acquire(&profile_dir).unwrap());
        std::fs::write(profile_dir.join("state"), b"test").unwrap();
        let observed_held_ownership = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&observed_held_ownership);
        release_profile_after_confirmed_termination_with(
            &mut profile_guard,
            &profile_dir,
            true,
            move |path| {
                observed.store(
                    ProfileOwnershipGuard::acquire(path).is_err(),
                    AtomicOrdering::SeqCst,
                );
                std::fs::remove_dir_all(path)
            },
        )
        .unwrap();
        assert!(observed_held_ownership.load(AtomicOrdering::SeqCst));
        assert!(profile_guard.is_none());
        assert!(!profile_dir.exists());
    }

    #[test]
    fn ephemeral_profile_cleanup_failure_quarantines_ownership() {
        let profile_dir = std::env::temp_dir().join(format!(
            "dig2browser-bidi-cleanup-failure-{}",
            uuid::Uuid::new_v4()
        ));
        let mut profile_guard = Some(ProfileOwnershipGuard::acquire(&profile_dir).unwrap());
        let result = release_profile_after_confirmed_termination_with(
            &mut profile_guard,
            &profile_dir,
            true,
            |_| Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied")),
        );

        assert!(matches!(result, Err(BrowserError::Io(_))));
        assert!(profile_guard.is_none(), "ownership must move into quarantine");
        assert!(ProfileOwnershipGuard::acquire(&profile_dir).is_err());
        ProfileOwnershipGuard::release_retained_for_test(&profile_dir);
        std::fs::remove_dir_all(profile_dir).unwrap();
    }

    #[test]
    fn webdriver_delete_failure_retains_profile_ownership() {
        let profile_dir = std::env::temp_dir().join(format!(
            "dig2browser-bidi-unconfirmed-delete-{}",
            uuid::Uuid::new_v4()
        ));
        let outcome = reconcile_teardown_results(
            Ok(()),
            Err(BrowserError::Other("WebDriver DELETE failed".into())),
        );
        assert!(!outcome.process_termination_confirmed);
        let guard = ProfileOwnershipGuard::acquire(&profile_dir).unwrap();
        let error = outcome.result.as_ref().unwrap_err();
        retain_profile_ownership_after_unconfirmed_teardown(
            Some(guard),
            error,
        );
        assert!(ProfileOwnershipGuard::acquire(&profile_dir).is_err());
        ProfileOwnershipGuard::release_retained_for_test(&profile_dir);
        std::fs::remove_dir_all(profile_dir).unwrap();
    }

    #[test]
    fn cancelled_session_creation_retains_profile_ownership() {
        let profile_dir = std::env::temp_dir().join(format!(
            "dig2browser-bidi-cancelled-start-{}",
            uuid::Uuid::new_v4()
        ));
        let guard = ProfileOwnershipGuard::acquire(&profile_dir).unwrap();
        let mut pending = PendingProfileOwnership::new(guard);
        pending.arm_for_session_creation();

        drop(pending);

        assert!(ProfileOwnershipGuard::acquire(&profile_dir).is_err());
        ProfileOwnershipGuard::release_retained_for_test(&profile_dir);
        std::fs::remove_dir_all(profile_dir).unwrap();
    }
}
