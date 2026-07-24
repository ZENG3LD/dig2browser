//! Multi-client named-pipe server for the station daemon.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dig2browser::agentic::{
    AgentReply, Capability, CapabilitySet, CaptureArtifact, CapturePolicy,
    L1Capability, L2Capability, L3Capability, WorkerError,
};
use dig2browser_protocol::{
    read_worker_request, validate_pipe_suffix, write_worker_response,
    CaptureCompleteness, CollectionRequest, CollectionResponse, CollectionTask,
    CollectionTaskResult, CrawlRequest, EvidenceCapture, FailureClass, InteractiveElement,
    MonitorRequest, MonitorResponse, ProfileClass, RequestKind, ResolvedRuntimeRecord,
    ResponseStatus, StationStatus, TaskCapturePolicy, TaskReply, TaskStep, WorkerRequest,
    WorkerResponse, MAX_INTERACTIVE_ELEMENTS, PROTOCOL_VERSION,
};
use dig2browser_trace::LedgerError;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;

use crate::{
    collection::{
        BeginCollection, CaptureReceiptPolicy, CollectionError, CollectionManager,
    },
    crawl::{CrawlError, CrawlManager},
    live::{LiveCaptureManager, LiveError},
    monitor::{DurableMonitorManager, MonitorError},
    BrowserLease, BrowserStation, BrowserTask, BrowserTaskStep, IdentityRequest,
    RuntimeRegistryError, RuntimeRequirements, RuntimeSelector, StationError,
    StationFleetStatus,
};

const MAX_CONNECTIONS: usize = 1_024;
const ACQUIRE_RETRY_WINDOW: Duration = Duration::from_secs(3);
const ACQUIRE_RETRY_DELAY: Duration = Duration::from_millis(100);

#[derive(Default)]
struct ServerTelemetry {
    accepted_connections: AtomicU64,
    active_connections: AtomicU64,
    completed_connections: AtomicU64,
    aborted_connections: AtomicU64,
    captures_started: AtomicU64,
    captures_in_flight: AtomicU64,
    captures_succeeded: AtomicU64,
    captures_failed: AtomicU64,
    captures_timed_out: AtomicU64,
    last_failure_unix_ms: AtomicU64,
    last_failure_class: AtomicU64,
}

impl ServerTelemetry {
    fn connection_accepted(&self) {
        self.accepted_connections.fetch_add(1, Ordering::AcqRel);
        self.active_connections.fetch_add(1, Ordering::AcqRel);
    }

    fn connection_completed(&self) {
        self.completed_connections.fetch_add(1, Ordering::AcqRel);
    }

    fn connection_aborted(&self) {
        self.aborted_connections.fetch_add(1, Ordering::AcqRel);
    }

    fn failure(&self, class: FailureClass) {
        self.last_failure_class
            .store(class as u64, Ordering::Release);
        self.last_failure_unix_ms
            .store(unix_time_ms(), Ordering::Release);
    }

    fn status(&self, fleet: StationFleetStatus) -> StationStatus {
        StationStatus {
            shutting_down: fleet.shutting_down,
            resident_identities: usize_u64(fleet.resident_identities),
            starting_workers: usize_u64(fleet.starting_workers),
            ready_workers: usize_u64(fleet.ready_workers),
            degraded_workers: usize_u64(fleet.degraded_workers),
            restarting_workers: usize_u64(fleet.restarting_workers),
            shutting_down_workers: usize_u64(fleet.shutting_down_workers),
            stopped_workers: usize_u64(fleet.stopped_workers),
            active_leases: usize_u64(fleet.active_leases),
            command_limit: usize_u64(fleet.command_limit),
            command_available: usize_u64(fleet.command_available),
            command_waiters: usize_u64(fleet.command_waiters),
            accepted_connections: self.accepted_connections.load(Ordering::Acquire),
            active_connections: self.active_connections.load(Ordering::Acquire),
            completed_connections: self.completed_connections.load(Ordering::Acquire),
            aborted_connections: self.aborted_connections.load(Ordering::Acquire),
            captures_started: self.captures_started.load(Ordering::Acquire),
            captures_in_flight: self.captures_in_flight.load(Ordering::Acquire),
            captures_succeeded: self.captures_succeeded.load(Ordering::Acquire),
            captures_failed: self.captures_failed.load(Ordering::Acquire),
            captures_timed_out: self.captures_timed_out.load(Ordering::Acquire),
            last_failure_unix_ms: self.last_failure_unix_ms.load(Ordering::Acquire),
            last_failure_class: failure_class_from_atomic(
                self.last_failure_class.load(Ordering::Acquire),
            ),
        }
    }
}

struct ActiveConnection<'a> {
    telemetry: &'a ServerTelemetry,
}

impl Drop for ActiveConnection<'_> {
    fn drop(&mut self) {
        self.telemetry
            .active_connections
            .fetch_sub(1, Ordering::AcqRel);
    }
}

struct CaptureObservation<'a> {
    telemetry: &'a ServerTelemetry,
    finished: bool,
}

impl<'a> CaptureObservation<'a> {
    fn start(telemetry: &'a ServerTelemetry) -> Self {
        telemetry.captures_started.fetch_add(1, Ordering::AcqRel);
        telemetry
            .captures_in_flight
            .fetch_add(1, Ordering::AcqRel);
        Self {
            telemetry,
            finished: false,
        }
    }

    fn success(mut self) {
        self.telemetry
            .captures_succeeded
            .fetch_add(1, Ordering::AcqRel);
        self.finish();
    }

    fn failure(mut self, class: FailureClass) {
        self.telemetry
            .captures_failed
            .fetch_add(1, Ordering::AcqRel);
        if class == FailureClass::Timeout {
            self.telemetry
                .captures_timed_out
                .fetch_add(1, Ordering::AcqRel);
        }
        self.telemetry.failure(class);
        self.finish();
    }

    fn finish(&mut self) {
        self.finished = true;
        self.telemetry
            .captures_in_flight
            .fetch_sub(1, Ordering::AcqRel);
    }
}

impl Drop for CaptureObservation<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.telemetry
                .captures_failed
                .fetch_add(1, Ordering::AcqRel);
            self.telemetry.failure(FailureClass::Cancelled);
            self.telemetry
                .captures_in_flight
                .fetch_sub(1, Ordering::AcqRel);
        }
    }
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pipe_name: String,
    max_connections: usize,
    drain_timeout: Duration,
    allow_remote_shutdown: bool,
    allow_interactive_tasks: bool,
    allow_scripted_tasks: bool,
    allow_identity_status: bool,
    allow_session_state_updates: bool,
    allow_headful_auth: bool,
    allow_session_health: bool,
    trace_root: Option<PathBuf>,
    crawl_root: Option<PathBuf>,
    monitor_root: Option<PathBuf>,
    allow_durable_read: bool,
    allow_durable_write: bool,
    allow_crawl_read: bool,
    allow_crawl_write: bool,
    allow_authenticated_crawl: bool,
    allow_live_events: bool,
    allow_session_import: bool,
    allow_file_upload: bool,
    allow_downloads: bool,
    allow_output_shaping: bool,
}

impl ServerConfig {
    pub fn new(
        pipe_name: impl Into<String>,
        max_connections: usize,
        drain_timeout: Duration,
    ) -> Result<Self, ConfigError> {
        let pipe_name = pipe_name.into();
        validate_pipe_suffix(&pipe_name).map_err(|_| ConfigError::InvalidPipeName)?;
        if max_connections == 0 || max_connections > MAX_CONNECTIONS {
            return Err(ConfigError::InvalidConnectionLimit);
        }
        if !(Duration::from_millis(100)..=Duration::from_secs(5 * 60))
            .contains(&drain_timeout)
        {
            return Err(ConfigError::InvalidDrainTimeout);
        }
        Ok(Self {
            pipe_name,
            max_connections,
            drain_timeout,
            allow_remote_shutdown: false,
            allow_interactive_tasks: false,
            allow_scripted_tasks: false,
            allow_identity_status: false,
            allow_session_state_updates: false,
            allow_headful_auth: false,
            allow_session_health: false,
            trace_root: None,
            crawl_root: None,
            monitor_root: None,
            allow_durable_read: false,
            allow_durable_write: false,
            allow_crawl_read: false,
            allow_crawl_write: false,
            allow_authenticated_crawl: false,
            allow_live_events: false,
            allow_session_import: false,
            allow_file_upload: false,
            allow_downloads: false,
            allow_output_shaping: false,
        })
    }

    pub fn allow_remote_shutdown(mut self, allow: bool) -> Self {
        self.allow_remote_shutdown = allow;
        self
    }

    pub fn allow_interactive_tasks(mut self, allow: bool) -> Self {
        self.allow_interactive_tasks = allow;
        self
    }

    pub fn allow_file_upload(mut self, allow: bool) -> Self {
        self.allow_file_upload = allow;
        self
    }

    /// Allow a `WaitForDownload` task step to capture a page-triggered
    /// download and hand its bytes back. Default-deny; independent of
    /// `--allow-interactive-tasks` / `--allow-scripted-tasks` /
    /// `--allow-file-upload`.
    pub fn allow_downloads(mut self, allow: bool) -> Self {
        self.allow_downloads = allow;
        self
    }

    pub fn allow_scripted_tasks(mut self, allow: bool) -> Self {
        self.allow_scripted_tasks = allow;
        self
    }

    pub fn allow_session_state_updates(mut self, allow: bool) -> Self {
        self.allow_session_state_updates = allow;
        self
    }

    pub fn allow_identity_status(mut self, allow: bool) -> Self {
        self.allow_identity_status = allow;
        self
    }

    pub fn allow_headful_auth(mut self, allow: bool) -> Self {
        self.allow_headful_auth = allow;
        self
    }

    pub fn allow_session_health(mut self, allow: bool) -> Self {
        self.allow_session_health = allow;
        self
    }

    pub fn trace_root(mut self, root: impl Into<PathBuf>) -> Result<Self, ConfigError> {
        let root = root.into();
        if !root.is_absolute() {
            return Err(ConfigError::InvalidTraceRoot);
        }
        self.trace_root = Some(root);
        Ok(self)
    }

    pub fn crawl_root(mut self, root: impl Into<PathBuf>) -> Result<Self, ConfigError> {
        let root = root.into();
        if !root.is_absolute() {
            return Err(ConfigError::InvalidCrawlRoot);
        }
        self.crawl_root = Some(root);
        Ok(self)
    }

    /// Durable-monitor root: `<root>/cas` (shared content-addressed store) +
    /// `<root>/journals` (one append-only journal per monitor). Enables the
    /// `DurableMonitor` request family; admission is gated per-operation by
    /// `--allow-durable-read` / `--allow-durable-write`.
    pub fn monitor_root(mut self, root: impl Into<PathBuf>) -> Result<Self, ConfigError> {
        let root = root.into();
        if !root.is_absolute() {
            return Err(ConfigError::InvalidTraceRoot);
        }
        self.monitor_root = Some(root);
        Ok(self)
    }

    pub fn allow_durable_read(mut self, allow: bool) -> Self {
        self.allow_durable_read = allow;
        self
    }

    pub fn allow_durable_write(mut self, allow: bool) -> Self {
        self.allow_durable_write = allow;
        self
    }

    pub fn allow_crawl_read(mut self, allow: bool) -> Self {
        self.allow_crawl_read = allow;
        self
    }

    pub fn allow_crawl_write(mut self, allow: bool) -> Self {
        self.allow_crawl_write = allow;
        self
    }

    /// Allow a crawl to run under an `Authenticated` profile (session reuse).
    /// Subordinate to the crawl/durable gates; default-deny.
    pub fn allow_authenticated_crawl(mut self, allow: bool) -> Self {
        self.allow_authenticated_crawl = allow;
        self
    }

    /// Gate the entire `LiveEvents` request kind. Unlike the snapshot/trace
    /// paths, live events are raw (unsanitized real URLs and WebSocket/SSE
    /// payloads) by design, so this is a single hard, default-deny flag
    /// rather than a split read/write pair.
    pub fn allow_live_events(mut self, allow: bool) -> Self {
        self.allow_live_events = allow;
        self
    }

    /// Allow importing a prepared session from a local file into an
    /// authenticated profile (`RequestKind::ImportSession`). Default-deny; the
    /// station reads the file locally, so no cookie material crosses the pipe.
    pub fn allow_session_import(mut self, allow: bool) -> Self {
        self.allow_session_import = allow;
        self
    }

    /// Allow read-side declarative output shaping (`read_shaped`) over a
    /// collection's captured HTML. Default-deny; the effective gate at the
    /// dispatch site is this flag **and** `--allow-durable-read` (shaping
    /// reads a durable artifact).
    pub fn allow_output_shaping(mut self, allow: bool) -> Self {
        self.allow_output_shaping = allow;
        self
    }

    pub fn full_pipe_name(&self) -> String {
        format!(r"\\.\pipe\{}", self.pipe_name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerReport {
    pub stop_reason: StopReason,
    pub accepted_connections: u64,
    pub completed_connections: u64,
    pub aborted_connections: u64,
    pub stopped_workers: usize,
    pub drain_timed_out: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    ShutdownChannel,
    RemoteRequest,
}

impl StopReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ShutdownChannel => "shutdown_channel",
            Self::RemoteRequest => "remote_request",
        }
    }
}

pub async fn run_station_server(
    station: BrowserStation,
    config: ServerConfig,
    shutdown: watch::Receiver<bool>,
) -> Result<ServerReport, ServerError> {
    #[cfg(windows)]
    {
        run_windows_server(station, config, shutdown).await
    }

    #[cfg(not(windows))]
    {
        let _ = (station, config, shutdown);
        Err(ServerError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
async fn run_windows_server(
    station: BrowserStation,
    config: ServerConfig,
    mut shutdown: watch::Receiver<bool>,
) -> Result<ServerReport, ServerError> {
    use tokio::net::windows::named_pipe::ServerOptions;

    let pipe_name = config.full_pipe_name();
    let (connection_shutdown, _) = watch::channel(false);
    let (remote_shutdown, mut remote_requests) = mpsc::channel::<()>(1);
    let telemetry = Arc::new(ServerTelemetry::default());
    let crawl_execution_authorized = config.allow_crawl_write
        && config.allow_crawl_read
        && config.allow_durable_write
        && config.allow_durable_read;
    let collections = config
        .trace_root
        .as_ref()
        .map(|root| CollectionManager::open_deferred(station.clone(), root.clone()))
        .transpose()?;
    let crawls = match (config.crawl_root.as_ref(), config.trace_root.as_ref(), collections.as_ref()) {
        (Some(crawl_root), Some(trace_root), Some(collections)) => Some(CrawlManager::open_deferred(
            station.clone(),
            collections.clone(),
            crawl_root.clone(),
            trace_root,
            crawl_execution_authorized,
            crawl_execution_authorized && config.allow_authenticated_crawl,
        )?),
        (Some(_), _, _) => return Err(ServerError::CrawlTraceRequired),
        (None, _, _) => None,
    };
    if let Some(crawls) = &crawls {
        crawls.reconcile_and_recover()?;
    }
    if let Some(collections) = &collections {
        collections.reconcile_successor()?;
    }
    if let Some(crawls) = &crawls {
        crawls.start_runners()?;
    }
    // Live capture carries no durable state, so it is always constructed
    // (cheap, in-memory); `--allow-live-events` gates admission per-request
    // below, not construction.
    let live = LiveCaptureManager::open(station.clone());
    // A durable monitor persists to disk, so (like collections) it is only
    // constructed when a monitor root is configured; `open` reconciles any
    // journal a previous run left open. Admission is gated per-operation by
    // `--allow-durable-read` / `--allow-durable-write` below.
    let monitors = config
        .monitor_root
        .as_ref()
        .map(|root| DurableMonitorManager::open(station.clone(), root))
        .transpose()?;
    let mut connections = JoinSet::new();
    let mut first_instance = true;
    let mut remote_stop = false;

    loop {
        if *shutdown.borrow() || remote_stop {
            break;
        }
        while connections.len() >= config.max_connections {
            tokio::select! {
                joined = connections.join_next() => {
                    match joined {
                        Some(Ok(Ok(()))) => {
                            telemetry.connection_completed()
                        }
                        Some(Ok(Err(_))) | Some(Err(_)) => {
                            telemetry.connection_aborted()
                        }
                        None => break,
                    }
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                request = remote_requests.recv() => {
                    if request.is_some() {
                        remote_stop = true;
                        break;
                    }
                }
            }
            if *shutdown.borrow() || remote_stop {
                break;
            }
        }
        if *shutdown.borrow() || remote_stop {
            break;
        }

        let server = ServerOptions::new()
            .first_pipe_instance(first_instance)
            .reject_remote_clients(true)
            .create(&pipe_name)?;
        first_instance = false;
        tokio::select! {
            connected = server.connect() => {
                connected?;
                telemetry.connection_accepted();
                let connection_shutdown = connection_shutdown.subscribe();
                let context = ConnectionContext {
                    station: station.clone(),
                    collections: collections.clone(),
                    crawls: crawls.clone(),
                    live: live.clone(),
                    monitor: monitors.clone(),
                    telemetry: Arc::clone(&telemetry),
                    remote_shutdown: remote_shutdown.clone(),
                    allow_remote_shutdown: config.allow_remote_shutdown,
                    task_permissions: TaskPermissions {
                        interaction: config.allow_interactive_tasks,
                        script: config.allow_scripted_tasks,
                        identity_status: config.allow_identity_status,
                        session_updates: config.allow_session_state_updates,
                        headful_auth: config.allow_headful_auth,
                        session_health: config.allow_session_health,
                        durable_read: config.allow_durable_read,
                        durable_write: config.allow_durable_write,
                        crawl_read: config.allow_crawl_read,
                        crawl_write: config.allow_crawl_write,
                        live_events: config.allow_live_events,
                        session_import: config.allow_session_import,
                        file_upload: config.allow_file_upload,
                        download: config.allow_downloads,
                        output_shaping: config.allow_output_shaping,
                    },
                };
                connections.spawn(async move {
                    serve_connection(server, context, connection_shutdown).await
                });
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            request = remote_requests.recv() => {
                if request.is_some() {
                    remote_stop = true;
                    break;
                }
            }
        }
    }

    connection_shutdown.send_replace(true);
    drop(remote_shutdown);
    let drained = tokio::time::timeout(config.drain_timeout, async {
        while let Some(result) = connections.join_next().await {
            match result {
                Ok(Ok(())) => telemetry.connection_completed(),
                Ok(Err(_)) | Err(_) => {
                    telemetry.connection_aborted()
                }
            }
        }
    })
    .await;
    let mut drain_timed_out = drained.is_err();
    if drain_timed_out {
        telemetry.aborted_connections.fetch_add(
            u64::try_from(connections.len()).unwrap_or(u64::MAX),
            Ordering::AcqRel,
        );
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
    let crawl_shutdown = match crawls {
        Some(crawls) => crawls.shutdown(config.drain_timeout).await,
        None => Ok(false),
    };
    drain_timed_out |= crawl_shutdown?;
    let collection_shutdown = match collections {
        Some(collections) => collections.shutdown(config.drain_timeout).await,
        None => Ok(false),
    };
    // Release every held live-capture lease before the station's own
    // shutdown force-closes registered workers, so live sessions wind down
    // cleanly rather than surfacing as a mid-shutdown worker loss.
    drain_timed_out |= live.shutdown(config.drain_timeout).await?;
    let shutdown_report = station.shutdown().await?;
    drain_timed_out |= collection_shutdown?;
    Ok(ServerReport {
        stop_reason: if remote_stop {
            StopReason::RemoteRequest
        } else {
            StopReason::ShutdownChannel
        },
        accepted_connections: telemetry.accepted_connections.load(Ordering::Acquire),
        completed_connections: telemetry.completed_connections.load(Ordering::Acquire),
        aborted_connections: telemetry.aborted_connections.load(Ordering::Acquire),
        stopped_workers: shutdown_report.stopped,
        drain_timed_out,
    })
}

#[cfg(windows)]
struct ConnectionContext {
    station: BrowserStation,
    collections: Option<CollectionManager>,
    crawls: Option<CrawlManager>,
    live: LiveCaptureManager,
    monitor: Option<DurableMonitorManager>,
    telemetry: Arc<ServerTelemetry>,
    remote_shutdown: mpsc::Sender<()>,
    allow_remote_shutdown: bool,
    task_permissions: TaskPermissions,
}

#[cfg(windows)]
async fn serve_connection(
    mut stream: tokio::net::windows::named_pipe::NamedPipeServer,
    context: ConnectionContext,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), ServerError> {
    let ConnectionContext {
        station,
        collections,
        crawls,
        live,
        monitor,
        telemetry,
        remote_shutdown,
        allow_remote_shutdown,
        task_permissions,
    } = context;
    let _active = ActiveConnection {
        telemetry: telemetry.as_ref(),
    };
    loop {
        let request = tokio::select! {
            request = read_worker_request(&mut stream) => request?,
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
                continue;
            }
        };
        let Some(request) = request else {
            return Ok(());
        };
        if request.validate().is_err() {
            let response = WorkerResponse::failure(
                &request,
                ResponseStatus::Invalid,
                "invalid request",
            );
            write_worker_response(&mut stream, &response).await?;
            continue;
        }
        let should_shutdown = request.kind == RequestKind::Shutdown && allow_remote_shutdown;
        let response = match request.kind {
            RequestKind::Capture => capture(&station, telemetry.as_ref(), &request).await,
            RequestKind::Task => {
                run_task(
                    &station,
                    telemetry.as_ref(),
                    &request,
                    task_permissions,
                )
                .await
            }
            RequestKind::Collection => {
                collection_request(
                    collections.as_ref(),
                    &request,
                    task_permissions,
                )
                .await
            }
            RequestKind::Crawl => {
                crawl_request(
                    crawls.as_ref(),
                    &request,
                    task_permissions,
                )
                .await
            }
            RequestKind::LiveEvents if task_permissions.live_events => {
                live_request(&live, &request).await
            }
            RequestKind::LiveEvents => WorkerResponse::failure(
                &request,
                ResponseStatus::Invalid,
                "live events disabled",
            ),
            RequestKind::Health => WorkerResponse::empty(&request, ResponseStatus::Ok),
            RequestKind::Status => {
                let fleet = station.fleet_status().await;
                WorkerResponse::station_status(&request, &telemetry.status(fleet))
            }
            RequestKind::IdentityStatus if task_permissions.identity_status => {
                identity_status(&station, &request).await
            }
            RequestKind::IdentityStatus => WorkerResponse::failure(
                &request,
                ResponseStatus::Invalid,
                "identity status disabled",
            ),
            RequestKind::UpdateIdentityState if task_permissions.session_updates => {
                update_identity_state(&station, &request).await
            }
            RequestKind::UpdateIdentityState => WorkerResponse::failure(
                &request,
                ResponseStatus::Invalid,
                "session state updates disabled",
            ),
            RequestKind::BeginAuthSession if task_permissions.headful_auth => {
                begin_auth_session(&station, &request).await
            }
            RequestKind::BeginAuthSession => WorkerResponse::failure(
                &request,
                ResponseStatus::Invalid,
                "headful authentication disabled",
            ),
            RequestKind::FinishAuthSession if task_permissions.headful_auth => {
                finish_auth_session(&station, &request).await
            }
            RequestKind::FinishAuthSession => WorkerResponse::failure(
                &request,
                ResponseStatus::Invalid,
                "headful authentication disabled",
            ),
            RequestKind::CheckAuthSession if task_permissions.session_health => {
                check_auth_session(&station, &request).await
            }
            RequestKind::CheckAuthSession => WorkerResponse::failure(
                &request,
                ResponseStatus::Invalid,
                "session health disabled",
            ),
            RequestKind::ImportSession if task_permissions.session_import => {
                import_session(&station, &request).await
            }
            RequestKind::ImportSession => WorkerResponse::failure(
                &request,
                ResponseStatus::Invalid,
                "session import disabled",
            ),
            RequestKind::DurableMonitor => {
                monitor_request(monitor.as_ref(), &request, task_permissions).await
            }
            RequestKind::Shutdown if allow_remote_shutdown => {
                WorkerResponse::empty(&request, ResponseStatus::Ok)
            }
            RequestKind::Shutdown => WorkerResponse::failure(
                &request,
                ResponseStatus::Invalid,
                "remote shutdown disabled",
            ),
            _ => WorkerResponse::failure(
                &request,
                ResponseStatus::Unsupported,
                "request kind unsupported",
            ),
        };
        write_worker_response(&mut stream, &response).await?;
        if should_shutdown {
            let _ = remote_shutdown.send(()).await;
            return Ok(());
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct TaskPermissions {
    interaction: bool,
    script: bool,
    identity_status: bool,
    session_updates: bool,
    headful_auth: bool,
    session_health: bool,
    durable_read: bool,
    durable_write: bool,
    crawl_read: bool,
    crawl_write: bool,
    live_events: bool,
    session_import: bool,
    file_upload: bool,
    download: bool,
    output_shaping: bool,
}

async fn crawl_request(
    crawls: Option<&CrawlManager>,
    request: &WorkerRequest,
    permissions: TaskPermissions,
) -> WorkerResponse {
    let Some(crawls) = crawls else {
        return WorkerResponse::failure(
            request,
            ResponseStatus::Unsupported,
            "durable crawler unavailable",
        );
    };
    let Some(operation) = request.crawl.as_ref() else {
        return WorkerResponse::failure(
            request,
            ResponseStatus::Invalid,
            "crawl request missing",
        );
    };
    match operation {
        CrawlRequest::Begin { .. }
            if !permissions.crawl_write
                || !permissions.crawl_read
                || !permissions.durable_read
                || !permissions.durable_write =>
        {
            return WorkerResponse::failure(
                request,
                ResponseStatus::Invalid,
                "crawl begin disabled",
            )
        }
        CrawlRequest::Status { .. } | CrawlRequest::ReadEvents { .. }
            if !permissions.crawl_read =>
        {
            return WorkerResponse::failure(
                request,
                ResponseStatus::Invalid,
                "crawl reads disabled",
            )
        }
        // Output shaping reads a durable page artifact via the collection
        // store, so it is gated on its own flag plus the two sibling read
        // gates the collection `ReadShaped` handler uses.
        CrawlRequest::ReadShaped { .. }
            if !permissions.output_shaping
                || !permissions.crawl_read
                || !permissions.durable_read =>
        {
            return WorkerResponse::failure(
                request,
                ResponseStatus::Invalid,
                "output shaping disabled",
            )
        }
        CrawlRequest::Cancel { .. } if !permissions.crawl_write => {
            return WorkerResponse::failure(
                request,
                ResponseStatus::Invalid,
                "crawl writes disabled",
            )
        }
        _ => {}
    }
    match crawls.handle(&request.profile_id, operation.clone()).await {
        Ok(response) => WorkerResponse::crawl_response(request, &response)
            .unwrap_or_else(|_| {
                WorkerResponse::failure(
                    request,
                    ResponseStatus::Protocol,
                    "crawl response invalid",
                )
            }),
        Err(error) => crawl_error_response(request, &error),
    }
}

fn crawl_error_response(request: &WorkerRequest, error: &CrawlError) -> WorkerResponse {
    let (status, message) = match error {
        CrawlError::AuthenticatedProfileUnsupported => {
            (ResponseStatus::Unsupported, "authenticated crawling unsupported")
        }
        CrawlError::JobNotFound
        | CrawlError::JobConflict
        | CrawlError::JobTerminal
        | CrawlError::InvalidJournalName
        | CrawlError::InvalidBinding
        | CrawlError::InvalidProfileId
        | CrawlError::InvalidBudget
        | CrawlError::InvalidCursor
        | CrawlError::FinalUrlOutsideScope
        | CrawlError::InvalidArtifactReference
        | CrawlError::InvalidHex
        | CrawlError::CanonicalUrl(_)
        | CrawlError::Spec(_)
        | CrawlError::Task(_)
        | CrawlError::Shape(_) => (ResponseStatus::Invalid, "crawl request rejected"),
        CrawlError::ArtifactTooLarge => {
            (ResponseStatus::TooLarge, "crawl artifact exceeds limit")
        }
        CrawlError::AdmissionClosed
        | CrawlError::RuntimeUnavailable
        | CrawlError::Collection(_)
        | CrawlError::Station(_) => (ResponseStatus::Unavailable, "crawler unavailable"),
        CrawlError::CorruptState(_)
        | CrawlError::MissingHtmlCapture
        | CrawlError::CountOverflow
        | CrawlError::ManagerStatePoisoned
        | CrawlError::Protocol(_)
        | CrawlError::Crawler(_) => (ResponseStatus::Protocol, "crawl state invalid"),
        _ => (ResponseStatus::Unavailable, "crawler unavailable"),
    };
    WorkerResponse::failure(request, status, message)
}

async fn live_request(
    live: &LiveCaptureManager,
    request: &WorkerRequest,
) -> WorkerResponse {
    let Some(operation) = request.live.as_ref() else {
        return WorkerResponse::failure(
            request,
            ResponseStatus::Invalid,
            "live event request missing",
        );
    };
    match live.handle(&request.profile_id, operation.clone()).await {
        Ok(response) => WorkerResponse::live_response(request, &response).unwrap_or_else(|_| {
            WorkerResponse::failure(
                request,
                ResponseStatus::Protocol,
                "live event response invalid",
            )
        }),
        Err(error) => live_error_response(request, &error),
    }
}

fn live_error_response(request: &WorkerRequest, error: &LiveError) -> WorkerResponse {
    let (status, message) = match error {
        LiveError::SessionConflict
        | LiveError::SessionNotFound
        | LiveError::InvalidProfileId => (ResponseStatus::Invalid, "live event request rejected"),
        LiveError::AdmissionClosed | LiveError::AtCapacity => {
            (ResponseStatus::Unavailable, "live capture unavailable")
        }
        LiveError::Station(
            StationError::Identity(_)
            | StationError::PersonaMismatch
            | StationError::PersonaBindingRequired
            | StationError::ProfileBindingMismatch
            | StationError::ProfileBindingRequired
            | StationError::PersonaRuntimeMismatch
            | StationError::IdentityClassMismatch
            | StationError::IdentityClassBindingRequired
            | StationError::InvalidPersona
            | StationError::CapabilityDenied
            | StationError::Worker(WorkerError::InvalidInput)
            | StationError::Route(_),
        ) => (ResponseStatus::Invalid, "live event request rejected"),
        LiveError::Station(
            StationError::AtCapacity
            | StationError::RuntimeSelectionBusy
            | StationError::ShuttingDown,
        ) => (ResponseStatus::Unavailable, "live capture unavailable"),
        LiveError::ManagerStatePoisoned | LiveError::Protocol(_) => {
            (ResponseStatus::Protocol, "live event state invalid")
        }
        _ => (ResponseStatus::Unavailable, "live capture unavailable"),
    };
    WorkerResponse::failure(request, status, message)
}

async fn monitor_request(
    manager: Option<&DurableMonitorManager>,
    request: &WorkerRequest,
    permissions: TaskPermissions,
) -> WorkerResponse {
    let Some(operation) = request.monitor.as_ref() else {
        return WorkerResponse::failure(
            request,
            ResponseStatus::Invalid,
            "durable monitor request missing",
        );
    };
    let Some(manager) = manager else {
        return WorkerResponse::failure(
            request,
            ResponseStatus::Unavailable,
            "durable monitoring unavailable",
        );
    };
    // Write operations (start/stop a monitor) need `--allow-durable-write`; read
    // operations (page records, fetch a frame) need `--allow-durable-read`.
    let permitted = match operation {
        MonitorRequest::Begin { .. } | MonitorRequest::Stop { .. } => permissions.durable_write,
        MonitorRequest::Read { .. } | MonitorRequest::ReadFrame { .. } => permissions.durable_read,
    };
    if !permitted {
        return WorkerResponse::failure(
            request,
            ResponseStatus::Invalid,
            "durable monitoring disabled",
        );
    }
    let result = match operation {
        MonitorRequest::Begin {
            profile_class,
            persona,
            url,
            filter,
        } => manager
            .begin(
                &request.profile_id,
                *profile_class,
                persona.clone(),
                url.clone(),
                *filter,
            )
            .await
            .map(|monitor_id| MonitorResponse::Accepted { monitor_id }),
        MonitorRequest::Read {
            monitor_id,
            cursor,
            limit,
        } => manager
            .read_page(monitor_id, *cursor, usize::from(*limit))
            .map(MonitorResponse::Events),
        MonitorRequest::ReadFrame { artifact, .. } => manager
            .read_frame_by_ref(artifact)
            .map(|payload| MonitorResponse::Frame { payload }),
        MonitorRequest::Stop { monitor_id } => manager.stop(monitor_id).await.map(|()| {
            MonitorResponse::Stopped {
                monitor_id: monitor_id.clone(),
            }
        }),
    };
    match result {
        Ok(response) => WorkerResponse::monitor_response(request, &response).unwrap_or_else(|_| {
            WorkerResponse::failure(
                request,
                ResponseStatus::Protocol,
                "durable monitor response invalid",
            )
        }),
        Err(error) => monitor_error_response(request, &error),
    }
}

fn monitor_error_response(request: &WorkerRequest, error: &MonitorError) -> WorkerResponse {
    let (status, message) = match error {
        MonitorError::SessionNotFound => {
            (ResponseStatus::Invalid, "durable monitor request rejected")
        }
        MonitorError::SessionConflict | MonitorError::AdmissionClosed => {
            (ResponseStatus::Unavailable, "durable monitoring unavailable")
        }
        MonitorError::StatePoisoned | MonitorError::Protocol(_) => {
            (ResponseStatus::Protocol, "durable monitor state invalid")
        }
        MonitorError::Station(
            StationError::Identity(_)
            | StationError::PersonaMismatch
            | StationError::PersonaBindingRequired
            | StationError::ProfileBindingMismatch
            | StationError::ProfileBindingRequired
            | StationError::PersonaRuntimeMismatch
            | StationError::IdentityClassMismatch
            | StationError::IdentityClassBindingRequired
            | StationError::InvalidPersona
            | StationError::CapabilityDenied
            | StationError::Worker(WorkerError::InvalidInput)
            | StationError::Route(_),
        ) => (ResponseStatus::Invalid, "durable monitor request rejected"),
        _ => (
            ResponseStatus::Unavailable,
            "durable monitoring unavailable",
        ),
    };
    WorkerResponse::failure(request, status, message)
}

async fn collection_request(
    collections: Option<&CollectionManager>,
    request: &WorkerRequest,
    permissions: TaskPermissions,
) -> WorkerResponse {
    let Some(collections) = collections else {
        return WorkerResponse::failure(
            request,
            ResponseStatus::Unsupported,
            "durable collections unavailable",
        );
    };
    let Some(operation) = request.collection.as_ref() else {
        return WorkerResponse::failure(
            request,
            ResponseStatus::Invalid,
            "collection request missing",
        );
    };
    let result = match operation {
        CollectionRequest::Begin {
            collection_id,
            profile_class,
            persona,
            task,
        } => {
            if !permissions.durable_write || !permissions.durable_read {
                return WorkerResponse::failure(
                    request,
                    ResponseStatus::Invalid,
                    "durable collection begin disabled",
                );
            }
            if *profile_class != ProfileClass::Public {
                return WorkerResponse::failure(
                    request,
                    ResponseStatus::Unsupported,
                    "authenticated durable collections unsupported",
                );
            }
            if task.requires_interaction() && !permissions.interaction {
                return WorkerResponse::failure(
                    request,
                    ResponseStatus::Invalid,
                    "interactive tasks disabled",
                );
            }
            if task.requires_script() && !permissions.script {
                return WorkerResponse::failure(
                    request,
                    ResponseStatus::Invalid,
                    "scripted tasks disabled",
                );
            }
            if task.requires_file_upload() && !permissions.file_upload {
                return WorkerResponse::failure(
                    request,
                    ResponseStatus::Invalid,
                    "file upload disabled",
                );
            }
            if task.requires_download() && !permissions.download {
                return WorkerResponse::failure(
                    request,
                    ResponseStatus::Invalid,
                    "downloads disabled",
                );
            }
            let station_task = match to_station_task(task) {
                Ok(task) => task,
                Err(_) => {
                    return WorkerResponse::failure(
                        request,
                        ResponseStatus::Invalid,
                        "invalid collection task",
                    )
                }
            };
            let (runtime_selector, runtime_requirements) = task
                .runtime_contract()
                .map(|contract| {
                    (
                        contract.selector(),
                        Some(contract.requirements().clone()),
                    )
                })
                .unwrap_or((RuntimeSelector::Auto, None));
            let mut canonical_request = request.clone();
            canonical_request.request_id = 0;
            let task_sha256 = match canonical_request.encode() {
                Ok(bytes) => dig2browser::digest::sha256_bytes(&bytes),
                Err(_) => {
                    return WorkerResponse::failure(
                        request,
                        ResponseStatus::Protocol,
                        "collection digest unavailable",
                    )
                }
            };
            collections
                .begin(BeginCollection {
                    collection_id: *collection_id,
                    task_sha256,
                    identity: IdentityRequest::public_persona(
                        &request.profile_id,
                        persona.clone(),
                    ),
                    capabilities: task_capabilities(task),
                    runtime_selector,
                    runtime_requirements,
                    task: station_task,
                    capture_receipt: CaptureReceiptPolicy::IfCaptured,
                })
                .await
                .map(|collection_id| CollectionResponse::Accepted { collection_id })
        }
        CollectionRequest::ReadTrace {
            collection_id,
            cursor,
            limit,
        } => {
            if !permissions.durable_read {
                return WorkerResponse::failure(
                    request,
                    ResponseStatus::Invalid,
                    "durable collection reads disabled",
                );
            }
            collections
                .read_trace(*collection_id, *cursor, *limit)
                .map(CollectionResponse::TracePage)
        }
        CollectionRequest::ReadArtifact {
            collection_id,
            sha256,
            offset,
            max_bytes,
        } => {
            if !permissions.durable_read {
                return WorkerResponse::failure(
                    request,
                    ResponseStatus::Invalid,
                    "durable collection reads disabled",
                );
            }
            collections
                .read_artifact(*collection_id, *sha256, *offset, *max_bytes)
                .map(CollectionResponse::ArtifactChunk)
        }
        CollectionRequest::ReadReceipt { collection_id } => {
            if !permissions.durable_read {
                return WorkerResponse::failure(
                    request,
                    ResponseStatus::Invalid,
                    "durable collection reads disabled",
                );
            }
            collections
                .read_receipt(*collection_id)
                .map(CollectionResponse::Receipt)
        }
        CollectionRequest::ReadShaped {
            collection_id,
            schema,
            cursor,
            limit,
        } => {
            // Output shaping reads a durable artifact, so it is gated on
            // both its own flag and the durable-read gate the sibling reads
            // use.
            if !permissions.output_shaping || !permissions.durable_read {
                return WorkerResponse::failure(
                    request,
                    ResponseStatus::Invalid,
                    "output shaping disabled",
                );
            }
            collections
                .read_shaped(*collection_id, schema, *cursor, *limit)
                .map(CollectionResponse::ShapedRows)
        }
        CollectionRequest::Cancel { collection_id } => {
            if !permissions.durable_write {
                return WorkerResponse::failure(
                    request,
                    ResponseStatus::Invalid,
                    "durable collection writes disabled",
                );
            }
            collections
                .cancel(*collection_id)
                .await
                .map(|_| CollectionResponse::Cancelled {
                    collection_id: *collection_id,
                })
        }
    };
    match result {
        Ok(response) => WorkerResponse::collection_response(request, &response)
            .unwrap_or_else(|_| {
                WorkerResponse::failure(
                    request,
                    ResponseStatus::Protocol,
                    "collection response invalid",
                )
            }),
        Err(error) => collection_error_response(request, &error),
    }
}

fn collection_error_response(
    request: &WorkerRequest,
    error: &CollectionError,
) -> WorkerResponse {
    let (status, message) = match error {
        CollectionError::CollectionConflict
        | CollectionError::InvalidTask
        | CollectionError::Shape(_)
        | CollectionError::Station(
            StationError::Identity(_)
            | StationError::PersonaMismatch
            | StationError::PersonaBindingRequired
            | StationError::ProfileBindingMismatch
            | StationError::ProfileBindingRequired
            | StationError::PersonaRuntimeMismatch
            | StationError::IdentityClassMismatch
            | StationError::IdentityClassBindingRequired
            | StationError::InvalidPersona
            | StationError::Worker(WorkerError::InvalidInput)
            | StationError::Route(_),
        )
        | CollectionError::Ledger(
            LedgerError::CollectionNotFound
            | LedgerError::ArtifactNotCommitted
            | LedgerError::InvalidCursor,
        ) => (ResponseStatus::Invalid, "collection request rejected"),
        CollectionError::Station(error) if is_runtime_contract_unsupported(error) => {
            (ResponseStatus::Unsupported, "runtime contract unsupported")
        }
        CollectionError::AtCapacity
        | CollectionError::AdmissionClosed
        | CollectionError::ReceiptNotReady
        | CollectionError::TerminalPersistenceFailed
        | CollectionError::Station(
            StationError::AtCapacity
            | StationError::RuntimeSelectionBusy
            | StationError::ShuttingDown,
        ) => (ResponseStatus::Unavailable, "collection unavailable"),
        CollectionError::Ledger(
            LedgerError::ArtifactTooLarge | LedgerError::EventLimitExceeded,
        ) => (ResponseStatus::TooLarge, "collection limit exceeded"),
        CollectionError::ReceiptUnavailable => {
            (ResponseStatus::Invalid, "collection receipt unavailable")
        }
        CollectionError::CorruptTrace
        | CollectionError::CorruptReceipt
        | CollectionError::ManagerStatePoisoned
        | CollectionError::LedgerPoisoned
        | CollectionError::Protocol(_)
        | CollectionError::Ledger(
            LedgerError::Protocol(_)
            | LedgerError::InvalidTransition(_)
            | LedgerError::Corrupt(_),
        ) => (ResponseStatus::Protocol, "collection trace invalid"),
        _ => (ResponseStatus::Unavailable, "collection unavailable"),
    };
    WorkerResponse::failure(request, status, message)
}

async fn check_auth_session(
    station: &BrowserStation,
    request: &WorkerRequest,
) -> WorkerResponse {
    let (Some(persona), Some(probe)) =
        (request.persona.clone(), request.session_probe.clone())
    else {
        return WorkerResponse::failure(
            request,
            ResponseStatus::Invalid,
            "session health probe missing",
        );
    };
    let identity = IdentityRequest::authenticated_persona(
        &request.profile_id,
        persona,
    );
    match station.check_auth_session(identity, probe).await {
        Ok(status) => WorkerResponse::identity_status(request, &status).unwrap_or_else(|_| {
            WorkerResponse::failure(
                request,
                ResponseStatus::Protocol,
                "session health status invalid",
            )
        }),
        Err(
            StationError::Identity(_)
            | StationError::PersonaMismatch
            | StationError::ProfileBindingMismatch
            | StationError::ProfileBindingRequired
            | StationError::PersonaRuntimeMismatch
            | StationError::IdentityClassMismatch
            | StationError::AuthenticatedProfileRequired
            | StationError::InvalidSessionState
            | StationError::Route(_),
        ) => WorkerResponse::failure(
            request,
            ResponseStatus::Invalid,
            "session health rejected",
        ),
        Err(StationError::AuthSessionBusy | StationError::AtCapacity) => {
            WorkerResponse::failure(
                request,
                ResponseStatus::Unavailable,
                "session health busy",
            )
        }
        Err(_) => WorkerResponse::failure(
            request,
            ResponseStatus::Unavailable,
            "session health unavailable",
        ),
    }
}

async fn begin_auth_session(
    station: &BrowserStation,
    request: &WorkerRequest,
) -> WorkerResponse {
    let Some(persona) = request.persona.clone() else {
        return WorkerResponse::failure(
            request,
            ResponseStatus::Invalid,
            "persona missing",
        );
    };
    let identity = IdentityRequest::authenticated_persona(
        &request.profile_id,
        persona,
    );
    match station
        .begin_auth_session(identity, request.url.clone())
        .await
    {
        Ok(()) => WorkerResponse::empty(request, ResponseStatus::Ok),
        Err(
            StationError::Identity(_)
            | StationError::PersonaMismatch
            | StationError::PersonaBindingRequired
            | StationError::ProfileBindingMismatch
            | StationError::ProfileBindingRequired
            | StationError::PersonaRuntimeMismatch
            | StationError::IdentityClassMismatch
            | StationError::IdentityClassBindingRequired
            | StationError::InvalidPersona
            | StationError::AuthenticatedProfileRequired
            | StationError::Worker(WorkerError::InvalidInput)
            | StationError::Route(_),
        ) => WorkerResponse::failure(
            request,
            ResponseStatus::Invalid,
            "authentication identity rejected",
        ),
        Err(StationError::AuthSessionBusy | StationError::AtCapacity) => {
            WorkerResponse::failure(
                request,
                ResponseStatus::Unavailable,
                "authentication session busy",
            )
        }
        Err(_) => WorkerResponse::failure(
            request,
            ResponseStatus::Unavailable,
            "authentication session unavailable",
        ),
    }
}

async fn finish_auth_session(
    station: &BrowserStation,
    request: &WorkerRequest,
) -> WorkerResponse {
    match station.finish_auth_session(&request.profile_id).await {
        Ok(()) => WorkerResponse::empty(request, ResponseStatus::Ok),
        Err(StationError::Identity(_) | StationError::AuthSessionNotFound) => {
            WorkerResponse::failure(
                request,
                ResponseStatus::Invalid,
                "authentication session not found",
            )
        }
        Err(StationError::AuthSessionBusy) => WorkerResponse::failure(
            request,
            ResponseStatus::Unavailable,
            "authentication session busy",
        ),
        Err(_) => WorkerResponse::failure(
            request,
            ResponseStatus::Unavailable,
            "authentication session unavailable",
        ),
    }
}

/// TTL applied to the `Ready` session-state written after a successful import.
const SESSION_IMPORT_TTL_SECONDS: u32 = 24 * 60 * 60;

async fn import_session(
    station: &BrowserStation,
    request: &WorkerRequest,
) -> WorkerResponse {
    let Some(persona) = request.persona.clone() else {
        return WorkerResponse::failure(request, ResponseStatus::Invalid, "persona missing");
    };
    // The station reads the prepared-session file itself; `request.url` carries
    // a local path, never cookie material.
    let bytes = match std::fs::read(&request.url) {
        Ok(bytes) => bytes,
        Err(_) => {
            return WorkerResponse::failure(
                request,
                ResponseStatus::Invalid,
                "session file unreadable",
            );
        }
    };
    let cookies = match crate::session_import::parse_session_cookies(&bytes) {
        Ok(cookies) => cookies,
        Err(_) => {
            return WorkerResponse::failure(
                request,
                ResponseStatus::Invalid,
                "session file invalid",
            );
        }
    };
    let identity = IdentityRequest::authenticated_persona(&request.profile_id, persona);
    match station
        .import_session(identity, cookies, SESSION_IMPORT_TTL_SECONDS)
        .await
    {
        Ok(_count) => WorkerResponse::empty(request, ResponseStatus::Ok),
        Err(
            StationError::Identity(_)
            | StationError::PersonaMismatch
            | StationError::PersonaBindingRequired
            | StationError::ProfileBindingMismatch
            | StationError::ProfileBindingRequired
            | StationError::PersonaRuntimeMismatch
            | StationError::IdentityClassMismatch
            | StationError::IdentityClassBindingRequired
            | StationError::InvalidPersona
            | StationError::AuthenticatedProfileRequired
            | StationError::InvalidSessionState
            | StationError::Worker(WorkerError::InvalidInput)
            | StationError::Route(_),
        ) => WorkerResponse::failure(request, ResponseStatus::Invalid, "session import rejected"),
        Err(StationError::AuthSessionBusy | StationError::AtCapacity) => {
            WorkerResponse::failure(request, ResponseStatus::Unavailable, "session import busy")
        }
        Err(_) => WorkerResponse::failure(
            request,
            ResponseStatus::Unavailable,
            "session import unavailable",
        ),
    }
}

async fn identity_status(
    station: &BrowserStation,
    request: &WorkerRequest,
) -> WorkerResponse {
    match station.identity_session_status(&request.profile_id).await {
        Ok(status) => WorkerResponse::identity_status(request, &status).unwrap_or_else(|_| {
            WorkerResponse::failure(
                request,
                ResponseStatus::Protocol,
                "identity status invalid",
            )
        }),
        Err(StationError::Identity(_)) => WorkerResponse::failure(
            request,
            ResponseStatus::Invalid,
            "invalid profile",
        ),
        Err(StationError::SessionStateCorrupt) => WorkerResponse::failure(
            request,
            ResponseStatus::Protocol,
            "identity status corrupt",
        ),
        Err(_) => WorkerResponse::failure(
            request,
            ResponseStatus::Unavailable,
            "identity status unavailable",
        ),
    }
}

async fn update_identity_state(
    station: &BrowserStation,
    request: &WorkerRequest,
) -> WorkerResponse {
    let Some(update) = request.session_update else {
        return WorkerResponse::failure(
            request,
            ResponseStatus::Invalid,
            "session state missing",
        );
    };
    match station
        .update_identity_session(&request.profile_id, update)
        .await
    {
        Ok(()) => WorkerResponse::empty(request, ResponseStatus::Ok),
        Err(
            StationError::Identity(_)
            | StationError::AuthenticatedProfileRequired
            | StationError::InvalidSessionState,
        ) => WorkerResponse::failure(
            request,
            ResponseStatus::Invalid,
            "session state rejected",
        ),
        Err(StationError::SessionStateCorrupt) => WorkerResponse::failure(
            request,
            ResponseStatus::Protocol,
            "identity status corrupt",
        ),
        Err(_) => WorkerResponse::failure(
            request,
            ResponseStatus::Unavailable,
            "session state unavailable",
        ),
    }
}

async fn run_task(
    station: &BrowserStation,
    telemetry: &ServerTelemetry,
    request: &WorkerRequest,
    permissions: TaskPermissions,
) -> WorkerResponse {
    let started = Instant::now();
    let observation = CaptureObservation::start(telemetry);
    let Some(task) = request.task.as_ref() else {
        observation.failure(FailureClass::Protocol);
        return failure(request, ResponseStatus::Invalid, "task missing", started);
    };
    if task.requires_interaction() && !permissions.interaction {
        observation.failure(FailureClass::Protocol);
        return failure(
            request,
            ResponseStatus::Invalid,
            "interactive tasks disabled",
            started,
        );
    }
    if task.requires_script() && !permissions.script {
        observation.failure(FailureClass::Protocol);
        return failure(
            request,
            ResponseStatus::Invalid,
            "scripted tasks disabled",
            started,
        );
    }
    if task.requires_file_upload() && !permissions.file_upload {
        observation.failure(FailureClass::Protocol);
        return failure(
            request,
            ResponseStatus::Invalid,
            "file upload disabled",
            started,
        );
    }
    if task.requires_download() && !permissions.download {
        observation.failure(FailureClass::Protocol);
        return failure(
            request,
            ResponseStatus::Invalid,
            "downloads disabled",
            started,
        );
    }
    let station_task = match to_station_task(task) {
        Ok(task) => task,
        Err(_) => {
            observation.failure(FailureClass::Protocol);
            return failure(request, ResponseStatus::Invalid, "invalid task", started);
        }
    };
    if station.validate_task_targets(&station_task).is_err() {
        observation.failure(FailureClass::Protocol);
        return failure(
            request,
            ResponseStatus::Invalid,
            "navigation target rejected",
            started,
        );
    }
    let capabilities = task_capabilities(task);
    let Some(persona) = request.persona.clone() else {
        observation.failure(FailureClass::Protocol);
        return failure(request, ResponseStatus::Invalid, "persona missing", started);
    };
    let identity = match request.profile_class {
        Some(ProfileClass::Public) => {
            IdentityRequest::public_persona(&request.profile_id, persona)
        }
        Some(ProfileClass::Authenticated) => {
            IdentityRequest::authenticated_persona(&request.profile_id, persona)
        }
        None => {
            observation.failure(FailureClass::Protocol);
            return failure(
                request,
                ResponseStatus::Invalid,
                "profile class missing",
                started,
            );
        }
    };
    let runtime_contract = task.runtime_contract();
    let requested_selector = runtime_contract
        .map(|contract| contract.selector())
        .unwrap_or(RuntimeSelector::Auto);
    let client_requirements = runtime_contract
        .map(|contract| contract.requirements());
    let lease = acquire_task_lease(
        station,
        identity,
        capabilities,
        &station_task,
        requested_selector,
        client_requirements,
    )
    .await;
    let lease = match lease {
        Ok(lease) => lease,
        Err(
            error @ (StationError::PersonaMismatch
            | StationError::PersonaBindingRequired
            | StationError::ProfileBindingMismatch
            | StationError::ProfileBindingRequired
            | StationError::PersonaRuntimeMismatch
            | StationError::IdentityClassMismatch
            | StationError::IdentityClassBindingRequired
            | StationError::InvalidPersona
            | StationError::Route(_)),
        ) => {
            observation.failure(station_error_class(&error, FailureClass::Protocol));
            return failure(
                request,
                ResponseStatus::Invalid,
                "persona contract rejected",
                started,
            );
        }
        Err(error) if runtime_contract.is_some() && is_runtime_contract_unsupported(&error) => {
            observation.failure(station_error_class(&error, FailureClass::Unavailable));
            return failure(
                request,
                ResponseStatus::Unsupported,
                "runtime contract unsupported",
                started,
            );
        }
        Err(error) => {
            observation.failure(station_error_class(&error, FailureClass::Unavailable));
            #[cfg(feature = "containment-test-hooks")]
            let message = format!("browser unavailable: {error}");
            #[cfg(not(feature = "containment-test-hooks"))]
            let message = "browser unavailable".to_owned();
            return failure(
                request,
                ResponseStatus::Unavailable,
                &message,
                started,
            );
        }
    };
    let result = match lease.run_task(&station_task).await {
        Ok(result) => result,
        Err(error) => {
            observation.failure(station_error_class(&error, FailureClass::CaptureFailed));
            let message = match task_step_index(&error) {
                Some(index) => format!("task failed at step {index}"),
                None => "task failed".to_owned(),
            };
            return failure(
                request,
                ResponseStatus::CaptureFailed,
                &message,
                started,
            );
        }
    };
    let protocol_result = match runtime_contract
        .map(|_| ResolvedRuntimeRecord::from_resolved(lease.resolved_runtime()))
        .transpose()
        .and_then(|runtime| to_protocol_result(task, result, runtime))
    {
        Ok(result) => result,
        Err(_) => {
            observation.failure(FailureClass::Protocol);
            return failure(
                request,
                ResponseStatus::Protocol,
                "task result invalid",
                started,
            );
        }
    };
    let mut response = match WorkerResponse::task_result(request, &protocol_result) {
        Ok(response) => response,
        Err(_) => {
            observation.failure(FailureClass::TooLarge);
            return failure(
                request,
                ResponseStatus::TooLarge,
                "task result exceeds response limit",
                started,
            );
        }
    };
    response.duration_ms = elapsed_ms(started);
    observation.success();
    response
}

fn to_station_task(task: &CollectionTask) -> Result<BrowserTask, crate::TaskError> {
    BrowserTask::new(
        task.steps()
            .iter()
            .map(|step| match step {
                TaskStep::Navigate { url } => BrowserTaskStep::Navigate { url: url.clone() },
                TaskStep::Wait { duration } => BrowserTaskStep::Wait {
                    duration: *duration,
                },
                TaskStep::Wheel {
                    x,
                    y,
                    delta_x,
                    delta_y,
                } => BrowserTaskStep::Wheel {
                    x: *x,
                    y: *y,
                    delta_x: *delta_x,
                    delta_y: *delta_y,
                },
                TaskStep::KeyPress { key } => BrowserTaskStep::KeyPress { key: key.clone() },
                TaskStep::ClickSelector { selector } => BrowserTaskStep::ClickSelector {
                    selector: selector.clone(),
                },
                TaskStep::TypeSelector { selector, text } => BrowserTaskStep::TypeSelector {
                    selector: selector.clone(),
                    text: text.clone(),
                },
                TaskStep::ReadSelectorText { selector } => BrowserTaskStep::ReadSelectorText {
                    selector: selector.clone(),
                },
                TaskStep::Evaluate { script } => BrowserTaskStep::Evaluate {
                    script: script.clone(),
                },
                TaskStep::Capture { policy } => BrowserTaskStep::Capture {
                    policy: to_capture_policy(*policy),
                },
                TaskStep::WaitForSelector { selector, timeout } => {
                    BrowserTaskStep::WaitForSelector {
                        selector: selector.clone(),
                        timeout: *timeout,
                    }
                }
                TaskStep::WaitForLoadState { state, timeout } => {
                    BrowserTaskStep::WaitForLoadState {
                        state: *state,
                        timeout: *timeout,
                    }
                }
                TaskStep::ReadInteractiveElements => {
                    BrowserTaskStep::ReadInteractiveElements
                }
                TaskStep::SelectOption { selector, value } => {
                    BrowserTaskStep::SelectOption {
                        selector: selector.clone(),
                        value: value.clone(),
                    }
                }
                TaskStep::UploadFile { selector, path } => {
                    BrowserTaskStep::UploadFile {
                        selector: selector.clone(),
                        path: path.clone(),
                    }
                }
                TaskStep::WaitForDownload { timeout } => {
                    BrowserTaskStep::WaitForDownload { timeout: *timeout }
                }
                TaskStep::ListTabs => BrowserTaskStep::ListTabs,
                TaskStep::SwitchToTab { id } => BrowserTaskStep::SwitchToTab {
                    id: id.clone(),
                },
            })
            .collect(),
    )
}

fn to_capture_policy(policy: TaskCapturePolicy) -> CapturePolicy {
    match policy {
        TaskCapturePolicy::StateOnly => CapturePolicy::StateOnly,
        TaskCapturePolicy::HtmlOnly => CapturePolicy::HtmlOnly,
        TaskCapturePolicy::EvidenceViewport => CapturePolicy::EvidenceViewport,
    }
}

fn task_capabilities(task: &CollectionTask) -> CapabilitySet {
    let mut capabilities = vec![Capability::L3(L3Capability::Lifecycle)];
    let mut add = |capability| {
        if !capabilities.contains(&capability) {
            capabilities.push(capability);
        }
    };
    for step in task.steps() {
        match step {
            TaskStep::Navigate { .. } => add(Capability::L3(L3Capability::Navigate)),
            TaskStep::Wait { .. } => {}
            TaskStep::Wheel { .. } => add(Capability::L1(L1Capability::Scroll)),
            TaskStep::KeyPress { .. } => add(Capability::L1(L1Capability::Keyboard)),
            TaskStep::ClickSelector { .. }
            | TaskStep::TypeSelector { .. }
            | TaskStep::SelectOption { .. }
            | TaskStep::UploadFile { .. } => {
                add(Capability::L2(L2Capability::Inspect));
                add(Capability::L2(L2Capability::Interact));
            }
            TaskStep::ReadSelectorText { .. } => {
                add(Capability::L2(L2Capability::Inspect));
            }
            TaskStep::WaitForSelector { .. }
            | TaskStep::WaitForLoadState { .. }
            | TaskStep::ReadInteractiveElements => {
                add(Capability::L2(L2Capability::Inspect));
            }
            TaskStep::Evaluate { .. } => add(Capability::L2(L2Capability::Evaluate)),
            TaskStep::Capture { .. } | TaskStep::WaitForDownload { .. } => {
                add(Capability::L3(L3Capability::Capture))
            }
            TaskStep::ListTabs => add(Capability::L2(L2Capability::Inspect)),
            TaskStep::SwitchToTab { .. } => add(Capability::L3(L3Capability::Lifecycle)),
        }
    }
    CapabilitySet::new(capabilities).expect("bounded task capabilities are unique")
}

fn to_protocol_result(
    task: &CollectionTask,
    result: crate::BrowserTaskResult,
    runtime: Option<ResolvedRuntimeRecord>,
) -> Result<CollectionTaskResult, dig2browser_protocol::ProtocolError> {
    if result.replies.len() != task.steps().len()
        || result.step_metrics.len() != task.steps().len()
    {
        return Err(dig2browser_protocol::ProtocolError::InvalidTaskResult);
    }
    let mut requested_url = String::new();
    let mut replies = Vec::with_capacity(result.replies.len());
    for ((step, reply), metrics) in task
        .steps()
        .iter()
        .zip(result.replies)
        .zip(result.step_metrics)
    {
        if let TaskStep::Navigate { url } = step {
            requested_url.clone_from(url);
        }
        let reply = match reply {
            AgentReply::Acknowledged => TaskReply::Acknowledged,
            AgentReply::Text(text) => TaskReply::Text(text),
            AgentReply::ScriptValue(value) => {
                // `ReadInteractiveElements` runs a fixed station-authored DOM
                // read; the root crate returns the raw JSON array (it cannot
                // depend on `-protocol`), so the typing into `InteractiveElement`
                // records happens here at the station boundary.
                if matches!(step, TaskStep::ReadInteractiveElements) {
                    TaskReply::Elements(parse_interactive_elements(&value)?)
                } else {
                    TaskReply::ScriptJson(value.to_string())
                }
            }
            AgentReply::Capture(artifact) => {
                let TaskStep::Capture { policy } = step else {
                    return Err(dig2browser_protocol::ProtocolError::InvalidTaskResult);
                };
                TaskReply::Capture(Box::new(evidence_capture(
                    &requested_url,
                    *policy,
                    artifact,
                    metrics.completed_at_unix_ms,
                    metrics.duration_ms,
                )))
            }
            AgentReply::Download {
                suggested_filename,
                bytes,
            } => TaskReply::Download {
                suggested_filename,
                bytes,
            },
            AgentReply::Tabs(tabs) => TaskReply::Tabs(
                tabs.into_iter()
                    .map(|tab| dig2browser_protocol::TabInfo::new(tab.id, tab.url, tab.title))
                    .collect::<Result<_, _>>()?,
            ),
            AgentReply::Element(_) => {
                return Err(dig2browser_protocol::ProtocolError::InvalidTaskResult)
            }
        };
        replies.push(reply);
    }
    match runtime {
        Some(runtime) => CollectionTaskResult::new_with_runtime(replies, runtime),
        None => CollectionTaskResult::new(replies),
    }
}

/// Type the fixed enumeration script's raw JSON (`[{role, name, selector}, …]`)
/// into bounded `InteractiveElement` records. Fail-closed: any non-array,
/// non-object entry, missing required field, over-count, or field that fails
/// the protocol bounds is rejected as `InvalidTaskResult`. `name` may be absent
/// or empty (an unlabeled control); `role` and `selector` are required.
fn parse_interactive_elements(
    value: &serde_json::Value,
) -> Result<Vec<InteractiveElement>, dig2browser_protocol::ProtocolError> {
    let array = value
        .as_array()
        .ok_or(dig2browser_protocol::ProtocolError::InvalidTaskResult)?;
    if array.len() > MAX_INTERACTIVE_ELEMENTS {
        return Err(dig2browser_protocol::ProtocolError::InvalidTaskResult);
    }
    let mut elements = Vec::with_capacity(array.len());
    for entry in array {
        let object = entry
            .as_object()
            .ok_or(dig2browser_protocol::ProtocolError::InvalidTaskResult)?;
        let required = |key: &str| {
            object
                .get(key)
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
                .ok_or(dig2browser_protocol::ProtocolError::InvalidTaskResult)
        };
        let role = required("role")?;
        let name = object
            .get("name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let selector = required("selector")?;
        elements.push(
            InteractiveElement::new(role, name, selector)
                .map_err(|_| dig2browser_protocol::ProtocolError::InvalidTaskResult)?,
        );
    }
    Ok(elements)
}

fn evidence_capture(
    requested_url: &str,
    policy: TaskCapturePolicy,
    artifact: CaptureArtifact,
    captured_at_unix_ms: u64,
    duration_ms: u64,
) -> EvidenceCapture {
    let (state, html, png) = match artifact {
        CaptureArtifact::StateOnly(state) => (state, Vec::new(), Vec::new()),
        CaptureArtifact::HtmlOnly { state, html } => (state, html.into_bytes(), Vec::new()),
        CaptureArtifact::EvidenceViewport { state, html, png } => {
            (state, html.into_bytes(), png)
        }
    };
    let html_sha256 = dig2browser::digest::sha256_bytes(&html);
    let png_sha256 = (!png.is_empty()).then(|| dig2browser::digest::sha256_bytes(&png));
    EvidenceCapture {
        completeness: CaptureCompleteness::Complete,
        policy,
        requested_url: requested_url.to_owned(),
        final_url: state.url,
        captured_at_unix_ms,
        duration_ms,
        http_status: state.http_status,
        title: state.title,
        ready_state: state.ready_state,
        html,
        png,
        html_sha256,
        png_sha256,
        collector_version: format!("dig2browser-station/{}", env!("CARGO_PKG_VERSION")),
        protocol_version: PROTOCOL_VERSION,
    }
}

async fn capture(
    station: &BrowserStation,
    telemetry: &ServerTelemetry,
    request: &WorkerRequest,
) -> WorkerResponse {
    let started = Instant::now();
    let observation = CaptureObservation::start(telemetry);
    if station.validate_navigation_target(&request.url).is_err() {
        observation.failure(FailureClass::Protocol);
        return failure(
            request,
            ResponseStatus::Invalid,
            "navigation target rejected",
            started,
        );
    }
    let lease = match monitoring_lease(station, &request.profile_id).await {
        Ok(lease) => lease,
        Err(error) => {
            observation.failure(station_error_class(&error, FailureClass::Unavailable));
            return failure(
                request,
                ResponseStatus::Unavailable,
                "browser unavailable",
                started,
            )
        }
    };
    let first_attempt = lease
        .navigate_and_capture(&request.url, CapturePolicy::EvidenceViewport)
        .await;
    let artifact = match first_attempt {
        Ok(artifact) => artifact,
        Err(error) if is_navigation_failure(&error) => {
            let recovered = lease.execute(dig2browser::agentic::AgentCommand::Restart).await;
            if recovered.is_err() {
                observation.failure(station_error_class(&error, FailureClass::CaptureFailed));
                return failure(
                    request,
                    ResponseStatus::CaptureFailed,
                    "capture failed",
                    started,
                );
            }
            match lease
                .navigate_and_capture(&request.url, CapturePolicy::EvidenceViewport)
                .await
            {
                Ok(artifact) => artifact,
                Err(error) => {
                    observation.failure(station_error_class(
                        &error,
                        FailureClass::CaptureFailed,
                    ));
                    return failure(
                        request,
                        ResponseStatus::CaptureFailed,
                        "capture failed",
                        started,
                    );
                }
            }
        }
        Err(error) => {
            observation.failure(station_error_class(&error, FailureClass::CaptureFailed));
            return failure(
                request,
                ResponseStatus::CaptureFailed,
                "capture failed",
                started,
            )
        }
    };
    let CaptureArtifact::EvidenceViewport { state, html, png } = artifact else {
        observation.failure(FailureClass::CaptureFailed);
        return failure(
            request,
            ResponseStatus::CaptureFailed,
            "capture policy failed",
            started,
        );
    };
    let response = WorkerResponse {
        status: ResponseStatus::Ok,
        kind: request.kind,
        request_id: request.request_id,
        http_status: state.http_status,
        duration_ms: elapsed_ms(started),
        final_url: state.url,
        title: state.title,
        error: String::new(),
        html: html.into_bytes(),
        png,
    };
    if response.validate().is_err() {
        observation.failure(FailureClass::TooLarge);
        return failure(
            request,
            ResponseStatus::TooLarge,
            "capture exceeds response limit",
            started,
        );
    }
    observation.success();
    response
}

async fn monitoring_lease(
    station: &BrowserStation,
    profile_id: &str,
) -> Result<BrowserLease, StationError> {
    acquire_lease(
        station,
        IdentityRequest::public_desktop(profile_id),
        CapabilitySet::monitoring(),
    )
    .await
}

async fn acquire_lease(
    station: &BrowserStation,
    identity: IdentityRequest,
    capabilities: CapabilitySet,
) -> Result<BrowserLease, StationError> {
    let deadline = tokio::time::Instant::now() + ACQUIRE_RETRY_WINDOW;
    loop {
        match station
            .lease(identity.clone(), capabilities.clone())
            .await
        {
            Ok(lease) => return Ok(lease),
            Err(error) if is_terminal_admission_error(&error) => return Err(error),
            Err(error) if tokio::time::Instant::now() >= deadline => return Err(error),
            Err(_) => tokio::time::sleep(ACQUIRE_RETRY_DELAY).await,
        }
    }
}

async fn acquire_task_lease(
    station: &BrowserStation,
    identity: IdentityRequest,
    capabilities: CapabilitySet,
    task: &BrowserTask,
    selector: RuntimeSelector,
    client_requirements: Option<&RuntimeRequirements>,
) -> Result<BrowserLease, StationError> {
    let deadline = tokio::time::Instant::now() + ACQUIRE_RETRY_WINDOW;
    loop {
        match station
            .lease_for_task(
                identity.clone(),
                capabilities.clone(),
                task,
                selector,
                client_requirements,
            )
            .await
        {
            Ok(lease) => return Ok(lease),
            Err(error) if is_terminal_admission_error(&error) => return Err(error),
            Err(error) if tokio::time::Instant::now() >= deadline => return Err(error),
            Err(_) => tokio::time::sleep(ACQUIRE_RETRY_DELAY).await,
        }
    }
}

fn is_terminal_admission_error(error: &StationError) -> bool {
    matches!(
        error,
        StationError::ShuttingDown
            | StationError::CapabilityDenied
            | StationError::Identity(_)
            | StationError::PersonaMismatch
            | StationError::PersonaBindingRequired
            | StationError::ProfileBindingMismatch
            | StationError::ProfileBindingRequired
            | StationError::PersonaRuntimeMismatch
            | StationError::IdentityClassMismatch
            | StationError::IdentityClassBindingRequired
            | StationError::InvalidPersona
            | StationError::PersonaIo(_)
            | StationError::Route(_)
            | StationError::RuntimeSelectionDenied { .. }
            | StationError::RuntimeSelectionBusy
            | StationError::RuntimeBackendUnsupported(_)
            | StationError::RuntimeRequirements(_)
            | StationError::RuntimeRegistry(RuntimeRegistryError::Incompatible { .. })
            | StationError::Worker(WorkerError::InvalidInput)
    )
}

fn is_runtime_contract_unsupported(error: &StationError) -> bool {
    matches!(
        error,
        StationError::RuntimeSelectionDenied { .. }
            | StationError::PersonaRuntimeMismatch
            | StationError::RuntimeBackendUnsupported(_)
            | StationError::RuntimeRegistry(RuntimeRegistryError::Incompatible { .. })
    )
}

fn failure(
    request: &WorkerRequest,
    status: ResponseStatus,
    message: &str,
    started: Instant,
) -> WorkerResponse {
    let mut response = WorkerResponse::failure(request, status, message);
    response.duration_ms = elapsed_ms(started);
    response
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn station_error_class(error: &StationError, fallback: FailureClass) -> FailureClass {
    match error {
        StationError::Worker(WorkerError::CommandTimeout(_)) => FailureClass::Timeout,
        StationError::WaitTimeout => FailureClass::Timeout,
        StationError::TaskStepFailed { source, .. } => station_error_class(source, fallback),
        _ => fallback,
    }
}

fn task_step_index(error: &StationError) -> Option<usize> {
    match error {
        StationError::TaskStepFailed { index, .. } => Some(*index),
        _ => None,
    }
}

fn is_navigation_failure(error: &StationError) -> bool {
    matches!(
        error,
        StationError::Worker(WorkerError::Runtime(runtime))
            if runtime.kind() == dig2browser::agentic::RuntimeFailureKind::Navigation
    )
}

fn usize_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or_default()
}

fn failure_class_from_atomic(value: u64) -> FailureClass {
    match value {
        1 => FailureClass::Unavailable,
        2 => FailureClass::CaptureFailed,
        3 => FailureClass::TooLarge,
        4 => FailureClass::Protocol,
        5 => FailureClass::Timeout,
        6 => FailureClass::Cancelled,
        _ => FailureClass::None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("invalid pipe name")]
    InvalidPipeName,
    #[error("invalid connection limit")]
    InvalidConnectionLimit,
    #[error("invalid drain timeout")]
    InvalidDrainTimeout,
    #[error("trace root must be absolute")]
    InvalidTraceRoot,
    #[error("crawl root must be absolute")]
    InvalidCrawlRoot,
}

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("station IPC is unsupported on this platform")]
    UnsupportedPlatform,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Frame(#[from] dig2browser_protocol::FrameError),
    #[error(transparent)]
    Collection(#[from] CollectionError),
    #[error(transparent)]
    Crawl(#[from] CrawlError),
    #[error(transparent)]
    Live(#[from] LiveError),
    #[error(transparent)]
    Monitor(#[from] MonitorError),
    #[error("crawl root requires a trace root")]
    CrawlTraceRequired,
    #[error(transparent)]
    Station(#[from] crate::StationError),
}
