//! Multi-client named-pipe server for the station daemon.

use std::time::{Duration, Instant};

use dig2browser::agentic::{CapabilitySet, CaptureArtifact, CapturePolicy};
use dig2browser_protocol::{
    read_worker_request, validate_pipe_suffix, write_worker_response, RequestKind,
    ResponseStatus, WorkerRequest, WorkerResponse,
};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;

use crate::{BrowserLease, BrowserStation, IdentityRequest, StationError};

const MAX_CONNECTIONS: usize = 1_024;
const ACQUIRE_RETRY_WINDOW: Duration = Duration::from_secs(3);
const ACQUIRE_RETRY_DELAY: Duration = Duration::from_millis(100);

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
    let mut connections = JoinSet::new();
    let mut first_instance = true;
    let mut accepted_connections = 0_u64;
    let mut completed_connections = 0_u64;
    let mut aborted_connections = 0_u64;
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
                            completed_connections = completed_connections.saturating_add(1)
                        }
                        Some(Ok(Err(_))) | Some(Err(_)) => {
                            aborted_connections = aborted_connections.saturating_add(1)
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
                accepted_connections = accepted_connections.saturating_add(1);
                let station = station.clone();
                let connection_shutdown = connection_shutdown.subscribe();
                let remote_shutdown = remote_shutdown.clone();
                let allow_remote_shutdown = config.allow_remote_shutdown;
                connections.spawn(async move {
                    serve_connection(
                        server,
                        station,
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
                Ok(Ok(())) => completed_connections = completed_connections.saturating_add(1),
                Ok(Err(_)) | Err(_) => {
                    aborted_connections = aborted_connections.saturating_add(1)
                }
            }
        }
    })
    .await;
    if drained.is_err() {
        aborted_connections = aborted_connections
            .saturating_add(u64::try_from(connections.len()).unwrap_or(u64::MAX));
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
    let shutdown_report = station.shutdown().await?;
    Ok(ServerReport {
        accepted_connections,
        completed_connections,
        aborted_connections,
        stopped_workers: shutdown_report.stopped,
    })
}

#[cfg(windows)]
async fn serve_connection(
    mut stream: tokio::net::windows::named_pipe::NamedPipeServer,
    station: BrowserStation,
    mut shutdown: watch::Receiver<bool>,
    remote_shutdown: mpsc::Sender<()>,
    allow_remote_shutdown: bool,
) -> Result<(), ServerError> {
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
            RequestKind::Capture => capture(&station, &request).await,
            RequestKind::Health => WorkerResponse::empty(&request, ResponseStatus::Ok),
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

async fn capture(station: &BrowserStation, request: &WorkerRequest) -> WorkerResponse {
    let started = Instant::now();
    let lease = match monitoring_lease(station, &request.profile_id).await {
        Ok(lease) => lease,
        Err(_) => {
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
        Err(_) => {
            return failure(
                request,
                ResponseStatus::CaptureFailed,
                "capture failed",
                started,
            )
        }
    };
    let CaptureArtifact::EvidenceViewport { state, html, png } = artifact else {
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
        return failure(
            request,
            ResponseStatus::TooLarge,
            "capture exceeds response limit",
            started,
        );
    }
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
