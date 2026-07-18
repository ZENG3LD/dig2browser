//! Multi-client named-pipe server for the station daemon.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dig2browser::agentic::{CapabilitySet, CaptureArtifact, CapturePolicy, WorkerError};
use dig2browser_protocol::{
    read_worker_request, validate_pipe_suffix, write_worker_response, FailureClass,
    RequestKind, ResponseStatus, StationStatus, WorkerRequest, WorkerResponse,
};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;

use crate::{
    BrowserLease, BrowserStation, IdentityRequest, StationError, StationFleetStatus,
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
        })
    }

    pub fn allow_remote_shutdown(mut self, allow: bool) -> Self {
        self.allow_remote_shutdown = allow;
        self
    }

    pub fn full_pipe_name(&self) -> String {
        format!(r"\\.\pipe\{}", self.pipe_name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerReport {
    pub accepted_connections: u64,
    pub completed_connections: u64,
    pub aborted_connections: u64,
    pub stopped_workers: usize,
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
        if *shutdown.borrow() {
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
                let station = station.clone();
                let telemetry = Arc::clone(&telemetry);
                let connection_shutdown = connection_shutdown.subscribe();
                let remote_shutdown = remote_shutdown.clone();
                let allow_remote_shutdown = config.allow_remote_shutdown;
                connections.spawn(async move {
                    serve_connection(
                        server,
                        station,
                        telemetry,
                        connection_shutdown,
                        remote_shutdown,
                        allow_remote_shutdown,
                    ).await
                });
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            request = remote_requests.recv() => {
                if request.is_some() {
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
    if drained.is_err() {
        telemetry.aborted_connections.fetch_add(
            u64::try_from(connections.len()).unwrap_or(u64::MAX),
            Ordering::AcqRel,
        );
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
    let shutdown_report = station.shutdown().await?;
    Ok(ServerReport {
        accepted_connections: telemetry.accepted_connections.load(Ordering::Acquire),
        completed_connections: telemetry.completed_connections.load(Ordering::Acquire),
        aborted_connections: telemetry.aborted_connections.load(Ordering::Acquire),
        stopped_workers: shutdown_report.stopped,
    })
}

#[cfg(windows)]
async fn serve_connection(
    mut stream: tokio::net::windows::named_pipe::NamedPipeServer,
    station: BrowserStation,
    telemetry: Arc<ServerTelemetry>,
    mut shutdown: watch::Receiver<bool>,
    remote_shutdown: mpsc::Sender<()>,
    allow_remote_shutdown: bool,
) -> Result<(), ServerError> {
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
            RequestKind::Health => WorkerResponse::empty(&request, ResponseStatus::Ok),
            RequestKind::Status => {
                let fleet = station.fleet_status().await;
                WorkerResponse::station_status(&request, &telemetry.status(fleet))
            }
            RequestKind::Shutdown if allow_remote_shutdown => {
                WorkerResponse::empty(&request, ResponseStatus::Ok)
            }
            RequestKind::Shutdown => WorkerResponse::failure(
                &request,
                ResponseStatus::Invalid,
                "remote shutdown disabled",
            ),
        };
        write_worker_response(&mut stream, &response).await?;
        if should_shutdown {
            let _ = remote_shutdown.send(()).await;
            return Ok(());
        }
    }
}

async fn capture(
    station: &BrowserStation,
    telemetry: &ServerTelemetry,
    request: &WorkerRequest,
) -> WorkerResponse {
    let started = Instant::now();
    let observation = CaptureObservation::start(telemetry);
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
    let artifact = match lease
        .navigate_and_capture(&request.url, CapturePolicy::EvidenceViewport)
        .await
    {
        Ok(artifact) => artifact,
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
    let deadline = tokio::time::Instant::now() + ACQUIRE_RETRY_WINDOW;
    loop {
        match station
            .lease(
                IdentityRequest::public_desktop(profile_id),
                CapabilitySet::monitoring(),
            )
            .await
        {
            Ok(lease) => return Ok(lease),
            Err(error @ StationError::ShuttingDown)
            | Err(error @ StationError::CapabilityDenied)
            | Err(error @ StationError::Identity(_)) => return Err(error),
            Err(error) if tokio::time::Instant::now() >= deadline => return Err(error),
            Err(_) => tokio::time::sleep(ACQUIRE_RETRY_DELAY).await,
        }
    }
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
    if matches!(error, StationError::Worker(WorkerError::CommandTimeout(_))) {
        FailureClass::Timeout
    } else {
        fallback
    }
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
    Station(#[from] crate::StationError),
}
