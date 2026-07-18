//! Reconnecting local IPC client for `dig2browser-station`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use dig2browser_protocol::{
    read_worker_response, validate_pipe_suffix, write_worker_request, FrameError,
    WorkerRequest, WorkerResponse,
};
use tokio::sync::Mutex;

pub use dig2browser_protocol::{
    BrowserPersona, CaptureCompleteness, CollectionTask, CollectionTaskResult,
    EvidenceCapture, FailureClass, IdentitySessionStatus, MobilePersonaConfig,
    PersonaKind, ProfileClass, ResponseStatus, SessionPhase,
    SessionStateUpdate, StationStatus, TaskCapturePolicy, TaskReply, TaskStep,
    DEFAULT_STATION_PIPE,
};

const MIN_TIMEOUT: Duration = Duration::from_millis(100);
const MAX_TIMEOUT: Duration = Duration::from_secs(15 * 60);

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pipe_name: String,
    connect_timeout: Duration,
    request_timeout: Duration,
}

impl ClientConfig {
    pub fn local_default(
        connect_timeout: Duration,
        request_timeout: Duration,
    ) -> Result<Self, ConfigError> {
        Self::new(DEFAULT_STATION_PIPE, connect_timeout, request_timeout)
    }

    pub fn new(
        pipe_name: impl Into<String>,
        connect_timeout: Duration,
        request_timeout: Duration,
    ) -> Result<Self, ConfigError> {
        let pipe_name = pipe_name.into();
        validate_pipe_suffix(&pipe_name).map_err(|_| ConfigError::InvalidPipeName)?;
        if !(MIN_TIMEOUT..=MAX_TIMEOUT).contains(&connect_timeout) {
            return Err(ConfigError::InvalidConnectTimeout);
        }
        if !(MIN_TIMEOUT..=MAX_TIMEOUT).contains(&request_timeout) {
            return Err(ConfigError::InvalidRequestTimeout);
        }
        Ok(Self {
            pipe_name,
            connect_timeout,
            request_timeout,
        })
    }

    pub fn pipe_name(&self) -> &str {
        &self.pipe_name
    }

    fn full_pipe_name(&self) -> String {
        format!(r"\\.\pipe\{}", self.pipe_name)
    }
}

/// A reconnecting, request-correlating client for one station endpoint.
pub struct StationClient {
    config: ClientConfig,
    next_request_id: AtomicU64,
    #[cfg(windows)]
    stream: Mutex<Option<tokio::net::windows::named_pipe::NamedPipeClient>>,
}

impl StationClient {
    pub async fn connect(config: ClientConfig) -> Result<Self, ClientError> {
        #[cfg(windows)]
        {
            let stream = connect_pipe(&config).await?;
            let client = Self {
                config,
                next_request_id: AtomicU64::new(1),
                stream: Mutex::new(Some(stream)),
            };
            client.health().await?;
            Ok(client)
        }

        #[cfg(not(windows))]
        {
            let _ = config;
            Err(ClientError::UnsupportedPlatform)
        }
    }

    pub async fn health(&self) -> Result<(), ClientError> {
        let request = WorkerRequest::health(self.take_request_id());
        let response = self.call(request).await?;
        require_ok(&response)
    }

    pub async fn status(&self) -> Result<StationStatus, ClientError> {
        let request = WorkerRequest::status(self.take_request_id());
        let response = self.call(request).await?;
        require_ok(&response)?;
        response
            .decode_station_status()
            .map_err(|_| ClientError::InvalidResponse)
    }

    pub async fn capture(
        &self,
        profile_id: impl Into<String>,
        url: impl Into<String>,
    ) -> Result<CaptureResult, ClientError> {
        let request = WorkerRequest::capture(self.take_request_id(), profile_id, url);
        let response = self.call(request).await?;
        require_ok(&response)?;
        if response.final_url.is_empty() || response.html.is_empty() || response.png.is_empty() {
            return Err(ClientError::InvalidResponse);
        }
        Ok(CaptureResult {
            final_url: response.final_url,
            title: (!response.title.is_empty()).then_some(response.title),
            http_status: response.http_status,
            duration_ms: response.duration_ms,
            html: response.html,
            png: response.png,
        })
    }

    pub async fn run_task(
        &self,
        profile_id: impl Into<String>,
        task: CollectionTask,
    ) -> Result<CollectionTaskResult, ClientError> {
        let request = WorkerRequest::task(self.take_request_id(), profile_id, task);
        let response = self.call(request).await?;
        require_ok(&response)?;
        response
            .decode_task_result()
            .map_err(|_| ClientError::InvalidResponse)
    }

    pub async fn run_task_with_persona(
        &self,
        profile_id: impl Into<String>,
        persona: BrowserPersona,
        task: CollectionTask,
    ) -> Result<CollectionTaskResult, ClientError> {
        let request = WorkerRequest::task_with_persona(
            self.take_request_id(),
            profile_id,
            persona,
            task,
        );
        let response = self.call(request).await?;
        require_ok(&response)?;
        response
            .decode_task_result()
            .map_err(|_| ClientError::InvalidResponse)
    }

    pub async fn run_task_with_identity(
        &self,
        profile_id: impl Into<String>,
        profile_class: ProfileClass,
        persona: BrowserPersona,
        task: CollectionTask,
    ) -> Result<CollectionTaskResult, ClientError> {
        let request = WorkerRequest::task_with_identity(
            self.take_request_id(),
            profile_id,
            profile_class,
            persona,
            task,
        );
        let response = self.call(request).await?;
        require_ok(&response)?;
        response
            .decode_task_result()
            .map_err(|_| ClientError::InvalidResponse)
    }

    /// Run a public-profile task while periodically yielding for lease
    /// heartbeats or cooperative cancellation. Cancellation disconnects the
    /// pipe so a late task reply cannot desynchronize the next request.
    pub async fn run_task_with_progress<E, F>(
        &self,
        profile_id: impl Into<String>,
        task: CollectionTask,
        progress_interval: Duration,
        mut progress: F,
    ) -> Result<CollectionTaskResult, CaptureProgressError<E>>
    where
        F: FnMut() -> Result<(), E>,
    {
        if let Err(error) = progress() {
            self.disconnect().await;
            return Err(CaptureProgressError::Aborted(error));
        }

        enum Outcome<T, E> {
            Task(Result<T, ClientError>),
            Aborted(E),
        }

        let progress_interval = progress_interval.max(Duration::from_millis(10));
        let outcome = {
            let task = self.run_task(profile_id, task);
            tokio::pin!(task);
            loop {
                tokio::select! {
                    result = &mut task => break Outcome::Task(result),
                    () = tokio::time::sleep(progress_interval) => {
                        if let Err(error) = progress() {
                            break Outcome::Aborted(error);
                        }
                    }
                }
            }
        };

        match outcome {
            Outcome::Task(result) => result.map_err(CaptureProgressError::Client),
            Outcome::Aborted(error) => {
                self.disconnect().await;
                Err(CaptureProgressError::Aborted(error))
            }
        }
    }

    pub async fn identity_status(
        &self,
        profile_id: impl Into<String>,
    ) -> Result<IdentitySessionStatus, ClientError> {
        let request = WorkerRequest::identity_status(self.take_request_id(), profile_id);
        let response = self.call(request).await?;
        require_ok(&response)?;
        response
            .decode_identity_status()
            .map_err(|_| ClientError::InvalidResponse)
    }

    pub async fn update_identity_state(
        &self,
        profile_id: impl Into<String>,
        update: SessionStateUpdate,
    ) -> Result<(), ClientError> {
        let request = WorkerRequest::update_identity_state(
            self.take_request_id(),
            profile_id,
            update,
        );
        let response = self.call(request).await?;
        require_ok(&response)
    }

    /// Capture while periodically yielding control to the caller for lease
    /// heartbeats or cooperative cancellation. Cancelling drops the in-flight
    /// request and disconnects the pipe so its late response cannot desync the
    /// next request.
    pub async fn capture_with_progress<E, F>(
        &self,
        profile_id: impl Into<String>,
        url: impl Into<String>,
        progress_interval: Duration,
        mut progress: F,
    ) -> Result<CaptureResult, CaptureProgressError<E>>
    where
        F: FnMut() -> Result<(), E>,
    {
        if let Err(error) = progress() {
            self.disconnect().await;
            return Err(CaptureProgressError::Aborted(error));
        }

        enum Outcome<T, E> {
            Capture(Result<T, ClientError>),
            Aborted(E),
        }

        let progress_interval = progress_interval.max(Duration::from_millis(10));
        let outcome = {
            let capture = self.capture(profile_id, url);
            tokio::pin!(capture);
            loop {
                tokio::select! {
                    result = &mut capture => break Outcome::Capture(result),
                    () = tokio::time::sleep(progress_interval) => {
                        if let Err(error) = progress() {
                            break Outcome::Aborted(error);
                        }
                    }
                }
            }
        };

        match outcome {
            Outcome::Capture(result) => result.map_err(CaptureProgressError::Client),
            Outcome::Aborted(error) => {
                self.disconnect().await;
                Err(CaptureProgressError::Aborted(error))
            }
        }
    }

    /// Request daemon shutdown. The server may deny this unless its operator
    /// explicitly enabled remote control for the local pipe.
    pub async fn shutdown(&self) -> Result<(), ClientError> {
        let request = WorkerRequest::shutdown(self.take_request_id());
        let response = self.call(request).await?;
        require_ok(&response)
    }

    pub async fn disconnect(&self) {
        #[cfg(windows)]
        {
            self.stream.lock().await.take();
        }
    }

    fn take_request_id(&self) -> u64 {
        loop {
            let current = self.next_request_id.load(Ordering::Relaxed).max(1);
            let next = current.wrapping_add(1).max(1);
            if self
                .next_request_id
                .compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return current;
            }
        }
    }

    async fn call(&self, request: WorkerRequest) -> Result<WorkerResponse, ClientError> {
        #[cfg(windows)]
        {
            let mut locked = self.stream.lock().await;
            if locked.is_none() {
                *locked = Some(connect_pipe(&self.config).await?);
            }
            let result = tokio::time::timeout(self.config.request_timeout, async {
                let stream = locked.as_mut().expect("station stream connected");
                write_worker_request(stream, &request).await?;
                read_worker_response(stream).await
            })
            .await;
            let response = match result {
                Ok(Ok(response)) => response,
                Ok(Err(error)) => {
                    *locked = None;
                    return Err(ClientError::Frame(error));
                }
                Err(_) => {
                    *locked = None;
                    return Err(ClientError::RequestTimeout);
                }
            };
            if response.request_id != request.request_id || response.kind != request.kind {
                *locked = None;
                return Err(ClientError::InvalidResponse);
            }
            Ok(response)
        }

        #[cfg(not(windows))]
        {
            let _ = request;
            Err(ClientError::UnsupportedPlatform)
        }
    }
}

/// Synchronous facade for collectors that do not otherwise need a Tokio
/// runtime. It retains the same reconnect and request-correlation guarantees
/// as [`StationClient`].
pub struct BlockingStationClient {
    runtime: tokio::runtime::Runtime,
    client: StationClient,
}

impl BlockingStationClient {
    pub fn connect(config: ClientConfig) -> Result<Self, ClientError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(ClientError::Runtime)?;
        let client = runtime.block_on(StationClient::connect(config))?;
        Ok(Self { runtime, client })
    }

    pub fn health(&self) -> Result<(), ClientError> {
        self.runtime.block_on(self.client.health())
    }

    pub fn status(&self) -> Result<StationStatus, ClientError> {
        self.runtime.block_on(self.client.status())
    }

    pub fn capture(
        &self,
        profile_id: impl Into<String>,
        url: impl Into<String>,
    ) -> Result<CaptureResult, ClientError> {
        self.runtime.block_on(self.client.capture(profile_id, url))
    }

    pub fn run_task(
        &self,
        profile_id: impl Into<String>,
        task: CollectionTask,
    ) -> Result<CollectionTaskResult, ClientError> {
        self.runtime.block_on(self.client.run_task(profile_id, task))
    }

    pub fn run_task_with_persona(
        &self,
        profile_id: impl Into<String>,
        persona: BrowserPersona,
        task: CollectionTask,
    ) -> Result<CollectionTaskResult, ClientError> {
        self.runtime.block_on(
            self.client
                .run_task_with_persona(profile_id, persona, task),
        )
    }

    pub fn run_task_with_identity(
        &self,
        profile_id: impl Into<String>,
        profile_class: ProfileClass,
        persona: BrowserPersona,
        task: CollectionTask,
    ) -> Result<CollectionTaskResult, ClientError> {
        self.runtime.block_on(self.client.run_task_with_identity(
            profile_id,
            profile_class,
            persona,
            task,
        ))
    }

    pub fn identity_status(
        &self,
        profile_id: impl Into<String>,
    ) -> Result<IdentitySessionStatus, ClientError> {
        self.runtime.block_on(self.client.identity_status(profile_id))
    }

    pub fn run_task_with_progress<E, F>(
        &self,
        profile_id: impl Into<String>,
        task: CollectionTask,
        progress_interval: Duration,
        progress: F,
    ) -> Result<CollectionTaskResult, CaptureProgressError<E>>
    where
        F: FnMut() -> Result<(), E>,
    {
        self.runtime.block_on(self.client.run_task_with_progress(
            profile_id,
            task,
            progress_interval,
            progress,
        ))
    }

    pub fn update_identity_state(
        &self,
        profile_id: impl Into<String>,
        update: SessionStateUpdate,
    ) -> Result<(), ClientError> {
        self.runtime
            .block_on(self.client.update_identity_state(profile_id, update))
    }

    pub fn capture_with_progress<E, F>(
        &self,
        profile_id: impl Into<String>,
        url: impl Into<String>,
        progress_interval: Duration,
        progress: F,
    ) -> Result<CaptureResult, CaptureProgressError<E>>
    where
        F: FnMut() -> Result<(), E>,
    {
        self.runtime.block_on(self.client.capture_with_progress(
            profile_id,
            url,
            progress_interval,
            progress,
        ))
    }

    pub fn disconnect(&self) {
        self.runtime.block_on(self.client.disconnect());
    }

    pub fn shutdown(&self) -> Result<(), ClientError> {
        self.runtime.block_on(self.client.shutdown())
    }
}

#[cfg(windows)]
async fn connect_pipe(
    config: &ClientConfig,
) -> Result<tokio::net::windows::named_pipe::NamedPipeClient, ClientError> {
    use tokio::net::windows::named_pipe::ClientOptions;

    let pipe_name = config.full_pipe_name();
    let deadline = tokio::time::Instant::now() + config.connect_timeout;
    loop {
        match ClientOptions::new().open(&pipe_name) {
            Ok(stream) => return Ok(stream),
            Err(error) if tokio::time::Instant::now() < deadline => {
                retry_delay(error).await;
            }
            Err(_) => return Err(ClientError::ConnectTimeout),
        }
    }
}

#[cfg(windows)]
async fn retry_delay(_error: std::io::Error) {
    tokio::time::sleep(Duration::from_millis(50)).await;
}

fn require_ok(response: &WorkerResponse) -> Result<(), ClientError> {
    if response.status == ResponseStatus::Ok {
        return Ok(());
    }
    Err(ClientError::Remote {
        status: response.status,
        message: response.error.clone(),
    })
}

#[derive(Debug)]
pub struct CaptureResult {
    pub final_url: String,
    pub title: Option<String>,
    pub http_status: Option<u16>,
    pub duration_ms: u64,
    pub html: Vec<u8>,
    pub png: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("invalid pipe name")]
    InvalidPipeName,
    #[error("invalid connect timeout")]
    InvalidConnectTimeout,
    #[error("invalid request timeout")]
    InvalidRequestTimeout,
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("station IPC is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("station connection timed out")]
    ConnectTimeout,
    #[error("station request timed out")]
    RequestTimeout,
    #[error("station returned an invalid response")]
    InvalidResponse,
    #[error("failed to create station client runtime: {0}")]
    Runtime(#[source] std::io::Error),
    #[error("station rejected request with {status:?}: {message}")]
    Remote {
        status: ResponseStatus,
        message: String,
    },
    #[error(transparent)]
    Frame(#[from] FrameError),
}

#[derive(Debug)]
pub enum CaptureProgressError<E> {
    Client(ClientError),
    Aborted(E),
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig2browser_protocol::RequestKind;

    #[test]
    fn validates_pipe_and_timeouts() {
        let default = ClientConfig::local_default(
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .expect("valid default station endpoint");
        assert_eq!(default.pipe_name(), DEFAULT_STATION_PIPE);
        assert!(matches!(
            ClientConfig::new("bad\\pipe", Duration::from_secs(1), Duration::from_secs(1)),
            Err(ConfigError::InvalidPipeName)
        ));
        assert!(matches!(
            ClientConfig::new("station", Duration::from_millis(1), Duration::from_secs(1)),
            Err(ConfigError::InvalidConnectTimeout)
        ));
    }

    #[test]
    fn request_kind_values_remain_compatible() {
        assert_eq!(RequestKind::Capture as u8, 1);
        assert_eq!(RequestKind::Health as u8, 2);
        assert_eq!(RequestKind::Shutdown as u8, 3);
        assert_eq!(RequestKind::Status as u8, 4);
        assert_eq!(RequestKind::Task as u8, 5);
        assert_eq!(RequestKind::IdentityStatus as u8, 6);
        assert_eq!(RequestKind::UpdateIdentityState as u8, 7);
    }
}
