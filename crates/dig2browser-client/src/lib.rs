//! Reconnecting local IPC client for `dig2browser-station`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use dig2browser_protocol::{
    read_worker_response, validate_pipe_suffix, write_worker_request, FrameError,
    WorkerRequest, WorkerResponse,
};
use tokio::sync::Mutex;

pub use dig2browser_protocol::{
    ArtifactChunk, ArtifactCommitted, ArtifactMediaType, ArtifactRef,
    ArtifactRole, BrowserPersona, CaptureCompleteness, CollectionId,
    CollectionReceipt, CollectionReceiptArtifacts, CollectionReceiptMetadata,
    CollectionRequest, CollectionResponse, CollectionTask, CollectionTaskResult,
    CompiledPersona, ControlTransport, CrawlCounts, CrawlCursor, CrawlEvent, CrawlEventKind,
    CrawlEventPage, CrawlJobId, CrawlPhase, CrawlRequest, CrawlResponse, CrawlSpec,
    CrawlStatus, EngineFamily, EvidenceCapture, FailureClass,
    IdentitySessionStatus, InterruptedReason, LiveCursor, LiveEvent, LiveEventKind,
    LiveEventPage, LiveFilter, LiveRequest, LiveResponse, LiveSessionId, LiveTarget,
    MobilePersonaConfig, MonitorCursor, MonitorEvent, MonitorEventKind, MonitorFrame,
    MonitorStopReason, PersonaKind,
    PageArtifact,
    PersonaCompiler, PersonaDeviceClass, PersonaMode, PersonaPreset, ProfileClass,
    ResolvedRuntimeRecord, ResponseStatus, RouteRef, RouteRefError, RuntimeFeature,
    RuntimeKind, RuntimeLimitation, RuntimeRequirements, RuntimeSelector,
    SessionPhase, SessionHealthProbe, SessionStateUpdate, SseEvent, StartedTrace,
    StationStatus, StepOutcome, StepSummary, SupportLevel, TaskCapturePolicy,
    TaskReply, TaskRuntimeContract, TaskStep, TerminalOutcome, TerminalTrace,
    TraceCursor, TraceEvent, TraceEventKind, TracePage, WebSocketDirection,
    WebSocketFrame, WebSocketOpcode,
    MAX_ARTIFACT_CHUNK_BYTES, MAX_CRAWL_ALLOWED_ORIGINS, MAX_CRAWL_DEPTH,
    MAX_CRAWL_EVENTS, MAX_CRAWL_PAGES, MAX_CRAWL_RETRIES, MAX_CRAWL_SEEDS,
    MAX_CRAWL_URL_BYTES, MAX_LIVE_CONSOLE_LEVEL_BYTES, MAX_LIVE_CONSOLE_TEXT_BYTES,
    MAX_LIVE_EVENTS, MAX_LIVE_METHOD_BYTES, MAX_LIVE_NETWORK_PARAMS_BYTES,
    MAX_LIVE_SSE_EVENT_TYPE_BYTES, MAX_LIVE_SSE_ID_BYTES,
    MAX_LIVE_URL_BYTES, MAX_TRACE_EVENTS, DEFAULT_STATION_PIPE, HOST_DIRECT,
    PROTOCOL_VERSION,
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
        let runtime_contract = task.runtime_contract().cloned();
        let request = WorkerRequest::task(self.take_request_id(), profile_id, task);
        let response = self.call(request).await?;
        require_task_result(&response, runtime_contract.as_ref())
    }

    pub async fn run_task_with_persona(
        &self,
        profile_id: impl Into<String>,
        persona: BrowserPersona,
        task: CollectionTask,
    ) -> Result<CollectionTaskResult, ClientError> {
        let runtime_contract = task.runtime_contract().cloned();
        let request = WorkerRequest::task_with_persona(
            self.take_request_id(),
            profile_id,
            persona,
            task,
        );
        let response = self.call(request).await?;
        require_task_result(&response, runtime_contract.as_ref())
    }

    pub async fn run_task_with_identity(
        &self,
        profile_id: impl Into<String>,
        profile_class: ProfileClass,
        persona: BrowserPersona,
        task: CollectionTask,
    ) -> Result<CollectionTaskResult, ClientError> {
        let runtime_contract = task.runtime_contract().cloned();
        let request = WorkerRequest::task_with_identity(
            self.take_request_id(),
            profile_id,
            profile_class,
            persona,
            task,
        );
        let response = self.call(request).await?;
        require_task_result(&response, runtime_contract.as_ref())
    }

    pub async fn begin_collection(
        &self,
        profile_id: impl Into<String>,
        task: CollectionTask,
    ) -> Result<CollectionHandle, ClientError> {
        let collection_id = CollectionId::new(*uuid::Uuid::new_v4().as_bytes())
            .map_err(|_| ClientError::InvalidCollectionRequest)?;
        self.begin_collection_with_id(profile_id, collection_id, task)
            .await
    }

    pub async fn begin_collection_with_id(
        &self,
        profile_id: impl Into<String>,
        collection_id: CollectionId,
        task: CollectionTask,
    ) -> Result<CollectionHandle, ClientError> {
        self.begin_collection_with_identity(
            profile_id,
            collection_id,
            ProfileClass::Public,
            BrowserPersona::desktop_default(),
            task,
        )
        .await
    }

    pub async fn begin_collection_with_identity(
        &self,
        profile_id: impl Into<String>,
        collection_id: CollectionId,
        profile_class: ProfileClass,
        persona: BrowserPersona,
        task: CollectionTask,
    ) -> Result<CollectionHandle, ClientError> {
        let runtime_contract = task.runtime_contract().cloned();
        let collection = CollectionRequest::begin(
            collection_id,
            profile_class,
            persona,
            task,
        )
        .map_err(|_| ClientError::InvalidCollectionRequest)?;
        let request = WorkerRequest::begin_collection(
            self.take_request_id(),
            profile_id,
            collection,
        )
        .map_err(|_| ClientError::InvalidCollectionRequest)?;
        let response = self.call(request).await?;
        let response = require_collection_response(&response)?;
        let CollectionResponse::Accepted {
            collection_id: accepted,
        } = response
        else {
            return Err(ClientError::InvalidResponse);
        };
        if accepted != collection_id {
            return Err(ClientError::InvalidResponse);
        }
        let page = self
            .read_trace(collection_id, TraceCursor::START, 1)
            .await?;
        let [event] = page.events() else {
            return Err(ClientError::InvalidResponse);
        };
        let TraceEventKind::Started(started) = event.kind() else {
            return Err(ClientError::InvalidResponse);
        };
        if event.cursor() != TraceCursor::new(1)
            || runtime_contract.as_ref().is_some_and(|contract| {
                !runtime_satisfies_contract(started.runtime(), contract)
            })
        {
            return Err(ClientError::InvalidResponse);
        }
        Ok(CollectionHandle {
            collection_id,
            cursor: event.cursor(),
            runtime: started.runtime().clone(),
        })
    }

    pub async fn read_trace(
        &self,
        collection_id: CollectionId,
        cursor: TraceCursor,
        limit: u8,
    ) -> Result<TracePage, ClientError> {
        let collection = CollectionRequest::read_trace(collection_id, cursor, limit)
            .map_err(|_| ClientError::InvalidCollectionRequest)?;
        let request = WorkerRequest::collection(self.take_request_id(), collection)
            .map_err(|_| ClientError::InvalidCollectionRequest)?;
        let response = require_collection_response(&self.call(request).await?)?;
        let CollectionResponse::TracePage(page) = response else {
            return Err(ClientError::InvalidResponse);
        };
        if page.collection_id() != collection_id {
            return Err(ClientError::InvalidResponse);
        }
        Ok(page)
    }

    pub async fn read_artifact_chunk(
        &self,
        collection_id: CollectionId,
        sha256: [u8; 32],
        offset: u64,
        max_bytes: u32,
    ) -> Result<ArtifactChunk, ClientError> {
        let collection = CollectionRequest::read_artifact(
            collection_id,
            sha256,
            offset,
            max_bytes,
        )
        .map_err(|_| ClientError::InvalidCollectionRequest)?;
        let request = WorkerRequest::collection(self.take_request_id(), collection)
            .map_err(|_| ClientError::InvalidCollectionRequest)?;
        let response = require_collection_response(&self.call(request).await?)?;
        let CollectionResponse::ArtifactChunk(chunk) = response else {
            return Err(ClientError::InvalidResponse);
        };
        if chunk.collection_id() != collection_id
            || chunk.sha256() != &sha256
            || chunk.offset() != offset
        {
            return Err(ClientError::InvalidResponse);
        }
        Ok(chunk)
    }

    pub async fn read_collection_receipt(
        &self,
        collection_id: CollectionId,
    ) -> Result<CollectionReceipt, ClientError> {
        let collection = CollectionRequest::read_receipt(collection_id)
            .map_err(|_| ClientError::InvalidCollectionRequest)?;
        let request = WorkerRequest::collection(self.take_request_id(), collection)
            .map_err(|_| ClientError::InvalidCollectionRequest)?;
        let response = require_collection_response(&self.call(request).await?)?;
        require_collection_receipt(response, collection_id)
    }

    pub async fn cancel_collection(
        &self,
        collection_id: CollectionId,
    ) -> Result<(), ClientError> {
        let collection = CollectionRequest::cancel(collection_id)
            .map_err(|_| ClientError::InvalidCollectionRequest)?;
        let request = WorkerRequest::collection(self.take_request_id(), collection)
            .map_err(|_| ClientError::InvalidCollectionRequest)?;
        let response = require_collection_response(&self.call(request).await?)?;
        match response {
            CollectionResponse::Cancelled {
                collection_id: cancelled,
            } if cancelled == collection_id => Ok(()),
            _ => Err(ClientError::InvalidResponse),
        }
    }

    pub async fn begin_crawl(
        &self,
        profile_id: impl Into<String>,
        spec: CrawlSpec,
    ) -> Result<CrawlJobId, ClientError> {
        let job_id = CrawlJobId::new(*uuid::Uuid::new_v4().as_bytes())
            .map_err(|_| ClientError::InvalidCrawlRequest)?;
        self.begin_crawl_with_id(profile_id, job_id, spec).await
    }

    pub async fn begin_crawl_with_id(
        &self,
        profile_id: impl Into<String>,
        job_id: CrawlJobId,
        spec: CrawlSpec,
    ) -> Result<CrawlJobId, ClientError> {
        self.begin_crawl_with_identity(
            profile_id,
            job_id,
            ProfileClass::Public,
            BrowserPersona::desktop_default(),
            spec,
        )
        .await
    }

    pub async fn begin_crawl_with_identity(
        &self,
        profile_id: impl Into<String>,
        job_id: CrawlJobId,
        profile_class: ProfileClass,
        persona: BrowserPersona,
        spec: CrawlSpec,
    ) -> Result<CrawlJobId, ClientError> {
        let crawl = CrawlRequest::begin(job_id, profile_class, persona, spec)
            .map_err(|_| ClientError::InvalidCrawlRequest)?;
        let request = WorkerRequest::begin_crawl(
            self.take_request_id(),
            profile_id,
            crawl,
        )
        .map_err(|_| ClientError::InvalidCrawlRequest)?;
        let response = require_crawl_response(&self.call(request).await?)?;
        match response {
            CrawlResponse::Accepted { job_id: accepted } if accepted == job_id => {
                Ok(job_id)
            }
            _ => Err(ClientError::InvalidResponse),
        }
    }

    pub async fn crawl_status(
        &self,
        job_id: CrawlJobId,
    ) -> Result<CrawlStatus, ClientError> {
        let crawl = CrawlRequest::status(job_id)
            .map_err(|_| ClientError::InvalidCrawlRequest)?;
        let request = WorkerRequest::crawl(self.take_request_id(), crawl)
            .map_err(|_| ClientError::InvalidCrawlRequest)?;
        let response = require_crawl_response(&self.call(request).await?)?;
        let CrawlResponse::Status(status) = response else {
            return Err(ClientError::InvalidResponse);
        };
        if status.job_id() != job_id {
            return Err(ClientError::InvalidResponse);
        }
        Ok(status)
    }

    pub async fn read_crawl_events(
        &self,
        job_id: CrawlJobId,
        cursor: CrawlCursor,
        limit: u8,
    ) -> Result<CrawlEventPage, ClientError> {
        let crawl = CrawlRequest::read_events(job_id, cursor, limit)
            .map_err(|_| ClientError::InvalidCrawlRequest)?;
        let request = WorkerRequest::crawl(self.take_request_id(), crawl)
            .map_err(|_| ClientError::InvalidCrawlRequest)?;
        let response = require_crawl_response(&self.call(request).await?)?;
        let CrawlResponse::Events(page) = response else {
            return Err(ClientError::InvalidResponse);
        };
        if page.job_id() != job_id || page.validate_after(cursor).is_err() {
            return Err(ClientError::InvalidResponse);
        }
        Ok(page)
    }

    pub async fn cancel_crawl(&self, job_id: CrawlJobId) -> Result<(), ClientError> {
        let crawl = CrawlRequest::cancel(job_id)
            .map_err(|_| ClientError::InvalidCrawlRequest)?;
        let request = WorkerRequest::crawl(self.take_request_id(), crawl)
            .map_err(|_| ClientError::InvalidCrawlRequest)?;
        let response = require_crawl_response(&self.call(request).await?)?;
        match response {
            CrawlResponse::Cancelled { job_id: cancelled } if cancelled == job_id => Ok(()),
            _ => Err(ClientError::InvalidResponse),
        }
    }

    /// Begin a raw, bounded, cursored live DevTools event subscription for
    /// a station-owned page. Requires the station operator to have enabled
    /// `--allow-live-events`; unlike the snapshot/trace paths, events
    /// returned via [`read_live_events`](Self::read_live_events) carry real
    /// URLs and WebSocket/SSE frame payloads unsanitized.
    pub async fn begin_live_capture(
        &self,
        profile_id: impl Into<String>,
        target: LiveTarget,
        filter: LiveFilter,
    ) -> Result<LiveSessionId, ClientError> {
        let session_id = LiveSessionId::new(*uuid::Uuid::new_v4().as_bytes())
            .map_err(|_| ClientError::InvalidLiveRequest)?;
        self.begin_live_capture_with_id(profile_id, session_id, target, filter)
            .await
    }

    pub async fn begin_live_capture_with_id(
        &self,
        profile_id: impl Into<String>,
        session_id: LiveSessionId,
        target: LiveTarget,
        filter: LiveFilter,
    ) -> Result<LiveSessionId, ClientError> {
        self.begin_live_capture_with_identity(
            profile_id,
            session_id,
            ProfileClass::Public,
            BrowserPersona::desktop_default(),
            target,
            filter,
        )
        .await
    }

    pub async fn begin_live_capture_with_identity(
        &self,
        profile_id: impl Into<String>,
        session_id: LiveSessionId,
        profile_class: ProfileClass,
        persona: BrowserPersona,
        target: LiveTarget,
        filter: LiveFilter,
    ) -> Result<LiveSessionId, ClientError> {
        let live = LiveRequest::begin(session_id, profile_class, persona, target, filter)
            .map_err(|_| ClientError::InvalidLiveRequest)?;
        let request = WorkerRequest::begin_live(self.take_request_id(), profile_id, live)
            .map_err(|_| ClientError::InvalidLiveRequest)?;
        let response = require_live_response(&self.call(request).await?)?;
        match response {
            LiveResponse::Accepted {
                session_id: accepted,
            } if accepted == session_id => Ok(session_id),
            _ => Err(ClientError::InvalidResponse),
        }
    }

    pub async fn read_live_events(
        &self,
        session_id: LiveSessionId,
        cursor: LiveCursor,
        limit: u8,
    ) -> Result<LiveEventPage, ClientError> {
        let live = LiveRequest::read(session_id, cursor, limit)
            .map_err(|_| ClientError::InvalidLiveRequest)?;
        let request = WorkerRequest::live(self.take_request_id(), live)
            .map_err(|_| ClientError::InvalidLiveRequest)?;
        let response = require_live_response(&self.call(request).await?)?;
        let LiveResponse::Events(page) = response else {
            return Err(ClientError::InvalidResponse);
        };
        if page.session_id() != session_id || page.validate_after(cursor).is_err() {
            return Err(ClientError::InvalidResponse);
        }
        Ok(page)
    }

    pub async fn stop_live_capture(&self, session_id: LiveSessionId) -> Result<(), ClientError> {
        let live = LiveRequest::stop(session_id).map_err(|_| ClientError::InvalidLiveRequest)?;
        let request = WorkerRequest::live(self.take_request_id(), live)
            .map_err(|_| ClientError::InvalidLiveRequest)?;
        let response = require_live_response(&self.call(request).await?)?;
        match response {
            LiveResponse::Stopped {
                session_id: stopped,
            } if stopped == session_id => Ok(()),
            _ => Err(ClientError::InvalidResponse),
        }
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

    /// Start a station-owned visible Chromium window for operator login. The
    /// station retains exclusive profile ownership and returns no cookie data.
    pub async fn begin_auth_session(
        &self,
        profile_id: impl Into<String>,
        persona: BrowserPersona,
        url: impl Into<String>,
    ) -> Result<(), ClientError> {
        let request = WorkerRequest::begin_auth_session(
            self.take_request_id(),
            profile_id,
            persona,
            url,
        );
        let response = self.call(request).await?;
        require_ok(&response)
    }

    /// Import a prepared session from a **local file** into an authenticated
    /// profile. `path` is a local filesystem path the station reads itself —
    /// the cookie material never crosses the pipe. Gated by
    /// `--allow-session-import`; fails closed on a non-authenticated identity or
    /// an existing public profile.
    pub async fn import_session(
        &self,
        profile_id: impl Into<String>,
        persona: BrowserPersona,
        path: impl Into<String>,
    ) -> Result<(), ClientError> {
        let request = WorkerRequest::import_session(
            self.take_request_id(),
            profile_id,
            persona,
            path,
        );
        let response = self.call(request).await?;
        require_ok(&response)
    }

    /// Close a station-owned visible login window and release its profile back
    /// to the headless worker pool. Session readiness remains operator-set.
    pub async fn finish_auth_session(
        &self,
        profile_id: impl Into<String>,
    ) -> Result<(), ClientError> {
        let request = WorkerRequest::finish_auth_session(
            self.take_request_id(),
            profile_id,
        );
        let response = self.call(request).await?;
        require_ok(&response)
    }

    /// Classify an authenticated profile from bounded operator-defined DOM
    /// evidence. Only the resulting lifecycle state is returned.
    pub async fn check_auth_session(
        &self,
        profile_id: impl Into<String>,
        persona: BrowserPersona,
        probe: SessionHealthProbe,
    ) -> Result<IdentitySessionStatus, ClientError> {
        let request = WorkerRequest::check_auth_session(
            self.take_request_id(),
            profile_id,
            persona,
            probe,
        );
        let response = self.call(request).await?;
        require_ok(&response)?;
        response
            .decode_identity_status()
            .map_err(|_| ClientError::InvalidResponse)
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

    pub fn begin_collection(
        &self,
        profile_id: impl Into<String>,
        task: CollectionTask,
    ) -> Result<CollectionHandle, ClientError> {
        self.runtime
            .block_on(self.client.begin_collection(profile_id, task))
    }

    pub fn begin_collection_with_id(
        &self,
        profile_id: impl Into<String>,
        collection_id: CollectionId,
        task: CollectionTask,
    ) -> Result<CollectionHandle, ClientError> {
        self.runtime.block_on(
            self.client
                .begin_collection_with_id(profile_id, collection_id, task),
        )
    }

    pub fn read_trace(
        &self,
        collection_id: CollectionId,
        cursor: TraceCursor,
        limit: u8,
    ) -> Result<TracePage, ClientError> {
        self.runtime
            .block_on(self.client.read_trace(collection_id, cursor, limit))
    }

    pub fn read_artifact_chunk(
        &self,
        collection_id: CollectionId,
        sha256: [u8; 32],
        offset: u64,
        max_bytes: u32,
    ) -> Result<ArtifactChunk, ClientError> {
        self.runtime.block_on(self.client.read_artifact_chunk(
            collection_id,
            sha256,
            offset,
            max_bytes,
        ))
    }

    pub fn read_collection_receipt(
        &self,
        collection_id: CollectionId,
    ) -> Result<CollectionReceipt, ClientError> {
        self.runtime
            .block_on(self.client.read_collection_receipt(collection_id))
    }

    pub fn cancel_collection(
        &self,
        collection_id: CollectionId,
    ) -> Result<(), ClientError> {
        self.runtime
            .block_on(self.client.cancel_collection(collection_id))
    }

    pub fn begin_crawl(
        &self,
        profile_id: impl Into<String>,
        spec: CrawlSpec,
    ) -> Result<CrawlJobId, ClientError> {
        self.runtime
            .block_on(self.client.begin_crawl(profile_id, spec))
    }

    pub fn begin_crawl_with_id(
        &self,
        profile_id: impl Into<String>,
        job_id: CrawlJobId,
        spec: CrawlSpec,
    ) -> Result<CrawlJobId, ClientError> {
        self.runtime.block_on(
            self.client
                .begin_crawl_with_id(profile_id, job_id, spec),
        )
    }

    pub fn begin_crawl_with_identity(
        &self,
        profile_id: impl Into<String>,
        job_id: CrawlJobId,
        profile_class: ProfileClass,
        persona: BrowserPersona,
        spec: CrawlSpec,
    ) -> Result<CrawlJobId, ClientError> {
        self.runtime.block_on(self.client.begin_crawl_with_identity(
            profile_id,
            job_id,
            profile_class,
            persona,
            spec,
        ))
    }

    pub fn crawl_status(
        &self,
        job_id: CrawlJobId,
    ) -> Result<CrawlStatus, ClientError> {
        self.runtime.block_on(self.client.crawl_status(job_id))
    }

    pub fn read_crawl_events(
        &self,
        job_id: CrawlJobId,
        cursor: CrawlCursor,
        limit: u8,
    ) -> Result<CrawlEventPage, ClientError> {
        self.runtime
            .block_on(self.client.read_crawl_events(job_id, cursor, limit))
    }

    pub fn cancel_crawl(&self, job_id: CrawlJobId) -> Result<(), ClientError> {
        self.runtime.block_on(self.client.cancel_crawl(job_id))
    }

    pub fn begin_live_capture(
        &self,
        profile_id: impl Into<String>,
        target: LiveTarget,
        filter: LiveFilter,
    ) -> Result<LiveSessionId, ClientError> {
        self.runtime
            .block_on(self.client.begin_live_capture(profile_id, target, filter))
    }

    pub fn begin_live_capture_with_id(
        &self,
        profile_id: impl Into<String>,
        session_id: LiveSessionId,
        target: LiveTarget,
        filter: LiveFilter,
    ) -> Result<LiveSessionId, ClientError> {
        self.runtime.block_on(self.client.begin_live_capture_with_id(
            profile_id,
            session_id,
            target,
            filter,
        ))
    }

    pub fn begin_live_capture_with_identity(
        &self,
        profile_id: impl Into<String>,
        session_id: LiveSessionId,
        profile_class: ProfileClass,
        persona: BrowserPersona,
        target: LiveTarget,
        filter: LiveFilter,
    ) -> Result<LiveSessionId, ClientError> {
        self.runtime.block_on(self.client.begin_live_capture_with_identity(
            profile_id,
            session_id,
            profile_class,
            persona,
            target,
            filter,
        ))
    }

    pub fn read_live_events(
        &self,
        session_id: LiveSessionId,
        cursor: LiveCursor,
        limit: u8,
    ) -> Result<LiveEventPage, ClientError> {
        self.runtime
            .block_on(self.client.read_live_events(session_id, cursor, limit))
    }

    pub fn stop_live_capture(&self, session_id: LiveSessionId) -> Result<(), ClientError> {
        self.runtime
            .block_on(self.client.stop_live_capture(session_id))
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

    pub fn begin_auth_session(
        &self,
        profile_id: impl Into<String>,
        persona: BrowserPersona,
        url: impl Into<String>,
    ) -> Result<(), ClientError> {
        self.runtime.block_on(
            self.client
                .begin_auth_session(profile_id, persona, url),
        )
    }

    pub fn import_session(
        &self,
        profile_id: impl Into<String>,
        persona: BrowserPersona,
        path: impl Into<String>,
    ) -> Result<(), ClientError> {
        self.runtime.block_on(
            self.client
                .import_session(profile_id, persona, path),
        )
    }

    pub fn finish_auth_session(
        &self,
        profile_id: impl Into<String>,
    ) -> Result<(), ClientError> {
        self.runtime
            .block_on(self.client.finish_auth_session(profile_id))
    }

    pub fn check_auth_session(
        &self,
        profile_id: impl Into<String>,
        persona: BrowserPersona,
        probe: SessionHealthProbe,
    ) -> Result<IdentitySessionStatus, ClientError> {
        self.runtime.block_on(
            self.client
                .check_auth_session(profile_id, persona, probe),
        )
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

fn require_task_result(
    response: &WorkerResponse,
    runtime_contract: Option<&TaskRuntimeContract>,
) -> Result<CollectionTaskResult, ClientError> {
    require_ok(response)?;
    let result = response
        .decode_task_result()
        .map_err(|_| ClientError::InvalidResponse)?;
    let runtime_is_valid = match (runtime_contract, result.runtime()) {
        (None, None) => true,
        (Some(contract), Some(runtime)) => runtime_satisfies_contract(runtime, contract),
        _ => false,
    };
    if !runtime_is_valid {
        return Err(ClientError::InvalidResponse);
    }
    Ok(result)
}

fn require_collection_response(
    response: &WorkerResponse,
) -> Result<CollectionResponse, ClientError> {
    require_ok(response)?;
    response
        .decode_collection_response()
        .map_err(|_| ClientError::InvalidResponse)
}

fn require_collection_receipt(
    response: CollectionResponse,
    collection_id: CollectionId,
) -> Result<CollectionReceipt, ClientError> {
    let CollectionResponse::Receipt(receipt) = response else {
        return Err(ClientError::InvalidResponse);
    };
    if receipt.collection_id() != collection_id {
        return Err(ClientError::InvalidResponse);
    }
    Ok(receipt)
}

fn require_crawl_response(response: &WorkerResponse) -> Result<CrawlResponse, ClientError> {
    require_ok(response)?;
    response
        .decode_crawl_response()
        .map_err(|_| ClientError::InvalidResponse)
}

fn require_live_response(response: &WorkerResponse) -> Result<LiveResponse, ClientError> {
    require_ok(response)?;
    response
        .decode_live_response()
        .map_err(|_| ClientError::InvalidResponse)
}

fn runtime_satisfies_contract(
    runtime: &ResolvedRuntimeRecord,
    contract: &TaskRuntimeContract,
) -> bool {
    if let RuntimeSelector::Exact(kind) = contract.selector() {
        if runtime.kind() != kind {
            return false;
        }
    }
    contract.requirements().features().iter().all(|required| {
        runtime.granted().iter().any(|support| {
            support.feature() == *required
                && match support.level() {
                    SupportLevel::Native | SupportLevel::Emulated => true,
                    SupportLevel::Partial => contract.requirements().allow_partial(),
                    SupportLevel::Unsupported => false,
                }
        })
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionHandle {
    collection_id: CollectionId,
    cursor: TraceCursor,
    runtime: ResolvedRuntimeRecord,
}

impl CollectionHandle {
    pub fn collection_id(&self) -> CollectionId {
        self.collection_id
    }

    pub fn cursor(&self) -> TraceCursor {
        self.cursor
    }

    pub fn runtime(&self) -> &ResolvedRuntimeRecord {
        &self.runtime
    }
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
    #[error("invalid collection request")]
    InvalidCollectionRequest,
    #[error("invalid crawl request")]
    InvalidCrawlRequest,
    #[error("invalid live event request")]
    InvalidLiveRequest,
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
    use dig2browser_core::{FeatureSupport, RuntimeDescriptor};
    use dig2browser_protocol::RequestKind;

    fn runtime_record(
        kind: RuntimeKind,
        support: Vec<FeatureSupport>,
        allow_partial: bool,
    ) -> ResolvedRuntimeRecord {
        let features = support.iter().map(FeatureSupport::feature).collect();
        let descriptor = RuntimeDescriptor::new(
            kind,
            EngineFamily::Chromium,
            ControlTransport::Cdp,
            support,
        )
        .expect("valid test runtime descriptor");
        let requirements = RuntimeRequirements::new(features, allow_partial)
            .expect("valid test runtime requirements");
        let resolved = descriptor
            .negotiate(&requirements, Some("test-version".to_owned()))
            .expect("test runtime resolves");
        ResolvedRuntimeRecord::from_resolved(&resolved)
            .expect("valid test runtime record")
    }

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
        assert_eq!(RequestKind::BeginAuthSession as u8, 8);
        assert_eq!(RequestKind::FinishAuthSession as u8, 9);
        assert_eq!(RequestKind::CheckAuthSession as u8, 10);
        assert_eq!(RequestKind::Collection as u8, 11);
        assert_eq!(RequestKind::Crawl as u8, 12);
        assert_eq!(RequestKind::LiveEvents as u8, 13);
    }

    #[test]
    fn runtime_contract_validation_is_fail_closed() {
        let native = runtime_record(
            RuntimeKind::Chrome,
            vec![FeatureSupport::new(
                RuntimeFeature::Navigate,
                SupportLevel::Native,
                Vec::new(),
            )],
            false,
        );
        let exact_chrome = TaskRuntimeContract::new(
            RuntimeSelector::Exact(RuntimeKind::Chrome),
            RuntimeRequirements::new(vec![RuntimeFeature::Navigate], false)
                .expect("valid exact Chrome requirements"),
        )
        .expect("valid exact Chrome contract");
        assert!(runtime_satisfies_contract(&native, &exact_chrome));

        let exact_edge = TaskRuntimeContract::new(
            RuntimeSelector::Exact(RuntimeKind::Edge),
            RuntimeRequirements::new(vec![RuntimeFeature::Navigate], false)
                .expect("valid exact Edge requirements"),
        )
        .expect("valid exact Edge contract");
        assert!(!runtime_satisfies_contract(&native, &exact_edge));

        let missing = TaskRuntimeContract::new(
            RuntimeSelector::Auto,
            RuntimeRequirements::new(vec![RuntimeFeature::ScriptEvaluate], false)
                .expect("valid missing-feature requirements"),
        )
        .expect("valid missing-feature contract");
        assert!(!runtime_satisfies_contract(&native, &missing));

        let partial = runtime_record(
            RuntimeKind::Chrome,
            vec![FeatureSupport::new(
                RuntimeFeature::DomInspect,
                SupportLevel::Partial,
                vec![RuntimeLimitation::NoNativeMobileApis],
            )],
            true,
        );
        let strict_partial = TaskRuntimeContract::new(
            RuntimeSelector::Auto,
            RuntimeRequirements::new(vec![RuntimeFeature::DomInspect], false)
                .expect("valid strict requirements"),
        )
        .expect("valid strict contract");
        assert!(!runtime_satisfies_contract(&partial, &strict_partial));
        let allowed_partial = TaskRuntimeContract::new(
            RuntimeSelector::Auto,
            RuntimeRequirements::new(vec![RuntimeFeature::DomInspect], true)
                .expect("valid partial requirements"),
        )
        .expect("valid partial contract");
        assert!(runtime_satisfies_contract(&partial, &allowed_partial));
    }

    #[test]
    fn collection_receipt_response_is_bound_to_requested_collection() {
        let expected = CollectionId::new([1; 16]).expect("expected collection id");
        let other = CollectionId::new([2; 16]).expect("other collection id");
        let receipt = CollectionReceipt::new(
            expected,
            [3; 32],
            CollectionReceiptMetadata {
                completed_at_unix_ms: 1_784_500_000_020,
                final_url: "https://example.test/final".to_owned(),
                http_status: Some(200),
                title: Some("Example".to_owned()),
                ready_state: "complete".to_owned(),
                capture_duration_ms: 20,
                collector_version: "dig2browser-station/0.1.0".to_owned(),
                protocol_version: dig2browser_protocol::PROTOCOL_VERSION,
            },
            CollectionReceiptArtifacts {
                html: ArtifactRef::new(
                    [4; 32],
                    41,
                    ArtifactMediaType::TextHtmlUtf8,
                )
                .expect("HTML artifact"),
                viewport_png: Some(
                    ArtifactRef::new([5; 32], 97, ArtifactMediaType::ImagePng)
                        .expect("PNG artifact"),
                ),
            },
        )
        .expect("valid receipt");

        assert_eq!(
            require_collection_receipt(
                CollectionResponse::Receipt(receipt.clone()),
                expected,
            )
            .expect("matching receipt"),
            receipt,
        );
        assert!(matches!(
            require_collection_receipt(CollectionResponse::Receipt(receipt), other),
            Err(ClientError::InvalidResponse)
        ));
    }
}
