//! Lightweight D2BQ/D2BR v1 wire contract shared by station servers and clients.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

mod crawl;
mod identity;
mod live;
mod monitor;
mod session;
mod task;
mod trace;

pub use crawl::{
    CrawlCounts, CrawlCursor, CrawlEvent, CrawlEventKind, CrawlEventPage, CrawlJobId,
    CrawlPhase, CrawlRequest, CrawlResponse, CrawlSpec, CrawlStatus,
    PageArtifact, MAX_CRAWL_ALLOWED_ORIGINS, MAX_CRAWL_DEPTH,
    MAX_CRAWL_EVENTS, MAX_CRAWL_EVENT_DETAIL_BYTES, MAX_CRAWL_PAGES,
    MAX_CRAWL_RETRIES, MAX_CRAWL_SEEDS, MAX_CRAWL_URL_BYTES,
};
pub use identity::{BrowserPersona, MobilePersonaConfig, PersonaKind};
pub use live::{
    LiveCursor, LiveEvent, LiveEventKind, LiveEventPage, LiveFilter, LiveRequest,
    LiveResponse, LiveSessionId, LiveTarget, SseEvent, WebSocketDirection,
    WebSocketFrame, WebSocketOpcode, MAX_LIVE_CONSOLE_LEVEL_BYTES,
    MAX_LIVE_CONSOLE_TEXT_BYTES, MAX_LIVE_EVENTS, MAX_LIVE_METHOD_BYTES,
    MAX_LIVE_NETWORK_PARAMS_BYTES, MAX_LIVE_SSE_EVENT_TYPE_BYTES,
    MAX_LIVE_SSE_ID_BYTES, MAX_LIVE_URL_BYTES,
};
pub use monitor::{
    validate_monitor_id, MonitorCursor, MonitorEvent, MonitorEventKind, MonitorEventPage,
    MonitorFrame, MonitorRequest, MonitorResponse, MonitorStopReason, MAX_MONITOR_EVENT_BYTES,
    MAX_MONITOR_FRAME_BYTES, MAX_MONITOR_ID_BYTES, MAX_MONITOR_PAGE_EVENTS, MAX_MONITOR_URL_BYTES,
};
pub use session::{
    IdentitySessionStatus, ProfileClass, SessionHealthProbe, SessionPhase,
    SessionStateUpdate,
};

pub use task::{
    CaptureCompleteness, CollectionTask, CollectionTaskResult, EvidenceCapture,
    ResolvedRuntimeRecord, TaskCapturePolicy, TaskReply, TaskRuntimeContract,
    TaskStep, MAX_TASK_RESULT_BYTES, MAX_TASK_STEPS, MAX_TASK_WAIT,
    MAX_COLLECTOR_VERSION_BYTES, MAX_SELECTOR_BYTES,
};
pub use trace::{
    ArtifactChunk, ArtifactCommitted, ArtifactMediaType, ArtifactRef,
    ArtifactRole, CollectionId, CollectionReceipt, CollectionReceiptArtifacts,
    CollectionReceiptMetadata, CollectionRequest, CollectionResponse,
    InterruptedReason, StartedTrace, StepOutcome, StepSummary, TerminalOutcome,
    TerminalTrace, TraceCursor, TraceEvent, TraceEventKind, TracePage,
    MAX_ARTIFACT_CHUNK_BYTES, MAX_TRACE_EVENTS, MAX_TRACE_STEP_SUMMARIES,
};
pub use dig2browser_core::{
    CompiledPersona, ControlTransport, EngineFamily, FeatureSupport,
    PersonaCompiler, PersonaDeviceClass, PersonaMode, PersonaPreset,
    ResolvedRuntime, RouteRef, RouteRefError, RuntimeFeature, RuntimeKind,
    RuntimeLimitation, RuntimeRequirements, RuntimeRequirementsError,
    RuntimeSelector, SupportLevel, HOST_DIRECT,
};

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
pub const MAX_FINAL_URL_BYTES: usize = 16 * 1024;
pub const MAX_TITLE_BYTES: usize = 16 * 1024;
pub const MAX_ERROR_BYTES: usize = 1024;
pub const MAX_HTML_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_PNG_BYTES: usize = 32 * 1024 * 1024;
pub const DEFAULT_STATION_PIPE: &str = "dig2browser-station-v1";

const REQUEST_MAGIC: [u8; 4] = *b"D2BQ";
const RESPONSE_MAGIC: [u8; 4] = *b"D2BR";
const REQUEST_HEADER_BYTES: usize = 22;
const RESPONSE_HEADER_BYTES: usize = 56;
const STATUS_MAGIC: [u8; 4] = *b"D2ST";
const STATUS_SCHEMA_VERSION: u16 = 1;
const STATUS_FIELDS: usize = 22;
const STATUS_PAYLOAD_BYTES: usize = 8 + STATUS_FIELDS * 8;
const TASK_IDENTITY_MAGIC: [u8; 4] = *b"D2TI";
const TASK_IDENTITY_SCHEMA_VERSION: u16 = 2;
const AUTH_IDENTITY_MAGIC: [u8; 4] = *b"D2AI";
const AUTH_IDENTITY_SCHEMA_VERSION: u16 = 1;
const HEALTH_IDENTITY_MAGIC: [u8; 4] = *b"D2HI";
const HEALTH_IDENTITY_SCHEMA_VERSION: u16 = 1;
const IMPORT_IDENTITY_MAGIC: [u8; 4] = *b"D2II";
const IMPORT_IDENTITY_SCHEMA_VERSION: u16 = 1;
const MAX_SESSION_IMPORT_PATH_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum RequestKind {
    Capture = 1,
    Health = 2,
    Shutdown = 3,
    Status = 4,
    Task = 5,
    IdentityStatus = 6,
    UpdateIdentityState = 7,
    BeginAuthSession = 8,
    FinishAuthSession = 9,
    CheckAuthSession = 10,
    Collection = 11,
    Crawl = 12,
    LiveEvents = 13,
    ImportSession = 14,
    DurableMonitor = 15,
}

impl RequestKind {
    fn from_wire(value: u8) -> Result<Self, ProtocolError> {
        match value {
            1 => Ok(Self::Capture),
            2 => Ok(Self::Health),
            3 => Ok(Self::Shutdown),
            4 => Ok(Self::Status),
            5 => Ok(Self::Task),
            6 => Ok(Self::IdentityStatus),
            7 => Ok(Self::UpdateIdentityState),
            8 => Ok(Self::BeginAuthSession),
            9 => Ok(Self::FinishAuthSession),
            10 => Ok(Self::CheckAuthSession),
            11 => Ok(Self::Collection),
            12 => Ok(Self::Crawl),
            13 => Ok(Self::LiveEvents),
            14 => Ok(Self::ImportSession),
            15 => Ok(Self::DurableMonitor),
            _ => Err(ProtocolError::InvalidRequest),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct WorkerRequest {
    pub kind: RequestKind,
    pub request_id: u64,
    pub profile_id: String,
    pub url: String,
    pub task: Option<CollectionTask>,
    pub persona: Option<BrowserPersona>,
    pub profile_class: Option<ProfileClass>,
    pub session_update: Option<SessionStateUpdate>,
    pub session_probe: Option<SessionHealthProbe>,
    pub collection: Option<CollectionRequest>,
    pub crawl: Option<CrawlRequest>,
    pub live: Option<LiveRequest>,
    pub monitor: Option<MonitorRequest>,
}

impl WorkerRequest {
    pub fn capture(request_id: u64, profile_id: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            kind: RequestKind::Capture,
            request_id,
            profile_id: profile_id.into(),
            url: url.into(),
            task: None,
            persona: None,
            profile_class: None,
            session_update: None,
            session_probe: None,
            collection: None,
            crawl: None,
            live: None,
            monitor: None,
        }
    }

    pub fn task(
        request_id: u64,
        profile_id: impl Into<String>,
        task: CollectionTask,
    ) -> Self {
        Self::task_with_persona(
            request_id,
            profile_id,
            BrowserPersona::desktop_default(),
            task,
        )
    }

    pub fn task_with_persona(
        request_id: u64,
        profile_id: impl Into<String>,
        persona: BrowserPersona,
        task: CollectionTask,
    ) -> Self {
        Self::task_with_identity(
            request_id,
            profile_id,
            ProfileClass::Public,
            persona,
            task,
        )
    }

    pub fn task_with_identity(
        request_id: u64,
        profile_id: impl Into<String>,
        profile_class: ProfileClass,
        persona: BrowserPersona,
        task: CollectionTask,
    ) -> Self {
        Self {
            kind: RequestKind::Task,
            request_id,
            profile_id: profile_id.into(),
            url: String::new(),
            task: Some(task),
            persona: Some(persona),
            profile_class: Some(profile_class),
            session_update: None,
            session_probe: None,
            collection: None,
            crawl: None,
            live: None,
            monitor: None,
        }
    }

    pub fn identity_status(request_id: u64, profile_id: impl Into<String>) -> Self {
        Self {
            kind: RequestKind::IdentityStatus,
            request_id,
            profile_id: profile_id.into(),
            url: String::new(),
            task: None,
            persona: None,
            profile_class: None,
            session_update: None,
            session_probe: None,
            collection: None,
            crawl: None,
            live: None,
            monitor: None,
        }
    }

    pub fn update_identity_state(
        request_id: u64,
        profile_id: impl Into<String>,
        update: SessionStateUpdate,
    ) -> Self {
        Self {
            kind: RequestKind::UpdateIdentityState,
            request_id,
            profile_id: profile_id.into(),
            url: String::new(),
            task: None,
            persona: None,
            profile_class: None,
            session_update: Some(update),
            session_probe: None,
            collection: None,
            crawl: None,
            live: None,
            monitor: None,
        }
    }

    pub fn begin_auth_session(
        request_id: u64,
        profile_id: impl Into<String>,
        persona: BrowserPersona,
        url: impl Into<String>,
    ) -> Self {
        Self {
            kind: RequestKind::BeginAuthSession,
            request_id,
            profile_id: profile_id.into(),
            url: url.into(),
            task: None,
            persona: Some(persona),
            profile_class: Some(ProfileClass::Authenticated),
            session_update: None,
            session_probe: None,
            collection: None,
            crawl: None,
            live: None,
            monitor: None,
        }
    }

    pub fn finish_auth_session(request_id: u64, profile_id: impl Into<String>) -> Self {
        Self {
            kind: RequestKind::FinishAuthSession,
            request_id,
            profile_id: profile_id.into(),
            url: String::new(),
            task: None,
            persona: None,
            profile_class: None,
            session_update: None,
            session_probe: None,
            collection: None,
            crawl: None,
            live: None,
            monitor: None,
        }
    }

    pub fn check_auth_session(
        request_id: u64,
        profile_id: impl Into<String>,
        persona: BrowserPersona,
        probe: SessionHealthProbe,
    ) -> Self {
        Self {
            kind: RequestKind::CheckAuthSession,
            request_id,
            profile_id: profile_id.into(),
            url: String::new(),
            task: None,
            persona: Some(persona),
            profile_class: Some(ProfileClass::Authenticated),
            session_update: None,
            session_probe: Some(probe),
            collection: None,
            crawl: None,
            live: None,
            monitor: None,
        }
    }

    /// Import a prepared session into an authenticated profile. `path` is a
    /// **local filesystem path** the station reads itself — the cookie bytes
    /// never travel on the wire.
    pub fn import_session(
        request_id: u64,
        profile_id: impl Into<String>,
        persona: BrowserPersona,
        path: impl Into<String>,
    ) -> Self {
        Self {
            kind: RequestKind::ImportSession,
            request_id,
            profile_id: profile_id.into(),
            url: path.into(),
            task: None,
            persona: Some(persona),
            profile_class: Some(ProfileClass::Authenticated),
            session_update: None,
            session_probe: None,
            collection: None,
            crawl: None,
            live: None,
            monitor: None,
        }
    }

    pub fn begin_collection(
        request_id: u64,
        profile_id: impl Into<String>,
        collection: CollectionRequest,
    ) -> Result<Self, ProtocolError> {
        if !collection.is_begin() {
            return Err(ProtocolError::InvalidCollectionPayload);
        }
        let request = Self {
            kind: RequestKind::Collection,
            request_id,
            profile_id: profile_id.into(),
            url: String::new(),
            task: None,
            persona: None,
            profile_class: None,
            session_update: None,
            session_probe: None,
            collection: Some(collection),
            crawl: None,
            live: None,
            monitor: None,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn collection(
        request_id: u64,
        collection: CollectionRequest,
    ) -> Result<Self, ProtocolError> {
        if collection.is_begin() {
            return Err(ProtocolError::InvalidCollectionPayload);
        }
        let request = Self {
            kind: RequestKind::Collection,
            request_id,
            profile_id: String::new(),
            url: String::new(),
            task: None,
            persona: None,
            profile_class: None,
            session_update: None,
            session_probe: None,
            collection: Some(collection),
            crawl: None,
            live: None,
            monitor: None,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn begin_crawl(
        request_id: u64,
        profile_id: impl Into<String>,
        crawl: CrawlRequest,
    ) -> Result<Self, ProtocolError> {
        if !crawl.is_begin() {
            return Err(ProtocolError::InvalidCrawlPayload);
        }
        let request = Self {
            kind: RequestKind::Crawl,
            request_id,
            profile_id: profile_id.into(),
            url: String::new(),
            task: None,
            persona: None,
            profile_class: None,
            session_update: None,
            session_probe: None,
            collection: None,
            crawl: Some(crawl),
            live: None,
            monitor: None,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn crawl(
        request_id: u64,
        crawl: CrawlRequest,
    ) -> Result<Self, ProtocolError> {
        if crawl.is_begin() {
            return Err(ProtocolError::InvalidCrawlPayload);
        }
        let request = Self {
            kind: RequestKind::Crawl,
            request_id,
            profile_id: String::new(),
            url: String::new(),
            task: None,
            persona: None,
            profile_class: None,
            session_update: None,
            session_probe: None,
            collection: None,
            crawl: Some(crawl),
            live: None,
            monitor: None,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn begin_live(
        request_id: u64,
        profile_id: impl Into<String>,
        live: LiveRequest,
    ) -> Result<Self, ProtocolError> {
        if !live.is_begin() {
            return Err(ProtocolError::InvalidLivePayload);
        }
        let request = Self {
            kind: RequestKind::LiveEvents,
            request_id,
            profile_id: profile_id.into(),
            url: String::new(),
            task: None,
            persona: None,
            profile_class: None,
            session_update: None,
            session_probe: None,
            collection: None,
            crawl: None,
            live: Some(live),
            monitor: None,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn live(request_id: u64, live: LiveRequest) -> Result<Self, ProtocolError> {
        if live.is_begin() {
            return Err(ProtocolError::InvalidLivePayload);
        }
        let request = Self {
            kind: RequestKind::LiveEvents,
            request_id,
            profile_id: String::new(),
            url: String::new(),
            task: None,
            persona: None,
            profile_class: None,
            session_update: None,
            session_probe: None,
            collection: None,
            crawl: None,
            live: Some(live),
            monitor: None,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn begin_monitor(
        request_id: u64,
        profile_id: impl Into<String>,
        monitor: MonitorRequest,
    ) -> Result<Self, ProtocolError> {
        if !monitor.is_begin() {
            return Err(ProtocolError::InvalidMonitorPayload);
        }
        let request = Self {
            kind: RequestKind::DurableMonitor,
            request_id,
            profile_id: profile_id.into(),
            url: String::new(),
            task: None,
            persona: None,
            profile_class: None,
            session_update: None,
            session_probe: None,
            collection: None,
            crawl: None,
            live: None,
            monitor: Some(monitor),
        };
        request.validate()?;
        Ok(request)
    }

    pub fn monitor(request_id: u64, monitor: MonitorRequest) -> Result<Self, ProtocolError> {
        if monitor.is_begin() {
            return Err(ProtocolError::InvalidMonitorPayload);
        }
        let request = Self {
            kind: RequestKind::DurableMonitor,
            request_id,
            profile_id: String::new(),
            url: String::new(),
            task: None,
            persona: None,
            profile_class: None,
            session_update: None,
            session_probe: None,
            collection: None,
            crawl: None,
            live: None,
            monitor: Some(monitor),
        };
        request.validate()?;
        Ok(request)
    }

    pub fn health(request_id: u64) -> Self {
        Self::control(RequestKind::Health, request_id)
    }

    pub fn shutdown(request_id: u64) -> Self {
        Self::control(RequestKind::Shutdown, request_id)
    }

    pub fn status(request_id: u64) -> Self {
        Self::control(RequestKind::Status, request_id)
    }

    fn control(kind: RequestKind, request_id: u64) -> Self {
        Self {
            kind,
            request_id,
            profile_id: String::new(),
            url: String::new(),
            task: None,
            persona: None,
            profile_class: None,
            session_update: None,
            session_probe: None,
            collection: None,
            crawl: None,
            live: None,
            monitor: None,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        let profile_len = u16::try_from(self.profile_id.len())
            .map_err(|_| ProtocolError::InvalidRequest)?;
        let task_payload = if self.kind == RequestKind::Task {
            Some(encode_task_identity_payload(
                self.profile_class
                    .ok_or(ProtocolError::InvalidRequest)?,
                self.persona
                    .as_ref()
                    .ok_or(ProtocolError::InvalidRequest)?,
                self.task
                    .as_ref()
                    .ok_or(ProtocolError::InvalidRequest)?,
            )?)
        } else {
            None
        };
        let session_payload = if self.kind == RequestKind::UpdateIdentityState {
            Some(
                self.session_update
                    .as_ref()
                    .ok_or(ProtocolError::InvalidRequest)?
                    .encode()?,
            )
        } else {
            None
        };
        let auth_payload = if self.kind == RequestKind::BeginAuthSession {
            Some(encode_auth_identity_payload(
                self.profile_class
                    .ok_or(ProtocolError::InvalidRequest)?,
                self.persona
                    .as_ref()
                    .ok_or(ProtocolError::InvalidRequest)?,
                &self.url,
            )?)
        } else {
            None
        };
        let import_payload = if self.kind == RequestKind::ImportSession {
            Some(encode_import_identity_payload(
                self.profile_class
                    .ok_or(ProtocolError::InvalidRequest)?,
                self.persona
                    .as_ref()
                    .ok_or(ProtocolError::InvalidRequest)?,
                &self.url,
            )?)
        } else {
            None
        };
        let probe_payload = if self.kind == RequestKind::CheckAuthSession {
            Some(encode_health_identity_payload(
                self.profile_class
                    .ok_or(ProtocolError::InvalidRequest)?,
                self.persona
                    .as_ref()
                    .ok_or(ProtocolError::InvalidRequest)?,
                self.session_probe
                    .as_ref()
                    .ok_or(ProtocolError::InvalidRequest)?,
            )?)
        } else {
            None
        };
        let collection_payload = if self.kind == RequestKind::Collection {
            Some(
                self.collection
                    .as_ref()
                    .ok_or(ProtocolError::InvalidRequest)?
                    .encode()?,
            )
        } else {
            None
        };
        let crawl_payload = if self.kind == RequestKind::Crawl {
            Some(
                self.crawl
                    .as_ref()
                    .ok_or(ProtocolError::InvalidRequest)?
                    .encode()?,
            )
        } else {
            None
        };
        let live_payload = if self.kind == RequestKind::LiveEvents {
            Some(
                self.live
                    .as_ref()
                    .ok_or(ProtocolError::InvalidRequest)?
                    .encode()?,
            )
        } else {
            None
        };
        let monitor_payload = if self.kind == RequestKind::DurableMonitor {
            Some(
                self.monitor
                    .as_ref()
                    .ok_or(ProtocolError::InvalidRequest)?
                    .encode()?,
            )
        } else {
            None
        };
        let body = task_payload
            .as_deref()
            .or(session_payload.as_deref())
            .or(auth_payload.as_deref())
            .or(import_payload.as_deref())
            .or(probe_payload.as_deref())
            .or(collection_payload.as_deref())
            .or(crawl_payload.as_deref())
            .or(live_payload.as_deref())
            .or(monitor_payload.as_deref())
            .unwrap_or(self.url.as_bytes());
        let url_len = u32::try_from(body.len()).map_err(|_| ProtocolError::InvalidRequest)?;
        let total = REQUEST_HEADER_BYTES
            .checked_add(self.profile_id.len())
            .and_then(|value| value.checked_add(body.len()))
            .ok_or(ProtocolError::InvalidRequest)?;
        if total > MAX_REQUEST_BYTES {
            return Err(ProtocolError::InvalidRequest);
        }
        let mut bytes = Vec::with_capacity(total);
        bytes.extend_from_slice(&REQUEST_MAGIC);
        bytes.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        bytes.push(self.kind as u8);
        bytes.push(0);
        bytes.extend_from_slice(&self.request_id.to_le_bytes());
        bytes.extend_from_slice(&profile_len.to_le_bytes());
        bytes.extend_from_slice(&url_len.to_le_bytes());
        bytes.extend_from_slice(self.profile_id.as_bytes());
        bytes.extend_from_slice(body);
        Ok(bytes)
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.kind != RequestKind::Collection && self.collection.is_some() {
            return Err(ProtocolError::InvalidRequest);
        }
        if self.kind != RequestKind::Crawl && self.crawl.is_some() {
            return Err(ProtocolError::InvalidRequest);
        }
        if self.kind != RequestKind::LiveEvents && self.live.is_some() {
            return Err(ProtocolError::InvalidRequest);
        }
        if self.kind != RequestKind::DurableMonitor && self.monitor.is_some() {
            return Err(ProtocolError::InvalidRequest);
        }
        match self.kind {
            RequestKind::Capture => {
                validate_profile_id(&self.profile_id)?;
                validate_http_url(&self.url)?;
                if self.task.is_none()
                    && self.persona.is_none()
                    && self.profile_class.is_none()
                    && self.session_update.is_none()
                    && self.session_probe.is_none()
                {
                    Ok(())
                } else {
                    Err(ProtocolError::InvalidRequest)
                }
            }
            RequestKind::Task => {
                validate_profile_id(&self.profile_id)?;
                if !self.url.is_empty() {
                    return Err(ProtocolError::InvalidRequest);
                }
                self.task
                    .as_ref()
                    .ok_or(ProtocolError::InvalidRequest)?
                    .validate()?;
                self.persona
                    .as_ref()
                    .ok_or(ProtocolError::InvalidRequest)?
                    .validate()?;
                if self.profile_class.is_none()
                    || self.session_update.is_some()
                    || self.session_probe.is_some()
                {
                    Err(ProtocolError::InvalidRequest)
                } else {
                    Ok(())
                }
            }
            RequestKind::IdentityStatus => {
                validate_profile_id(&self.profile_id)?;
                if self.url.is_empty()
                    && self.task.is_none()
                    && self.persona.is_none()
                    && self.profile_class.is_none()
                    && self.session_update.is_none()
                    && self.session_probe.is_none()
                {
                    Ok(())
                } else {
                    Err(ProtocolError::InvalidRequest)
                }
            }
            RequestKind::UpdateIdentityState => {
                validate_profile_id(&self.profile_id)?;
                if self.url.is_empty()
                    && self.task.is_none()
                    && self.persona.is_none()
                    && self.profile_class.is_none()
                    && self.session_probe.is_none()
                {
                    self.session_update
                        .as_ref()
                        .ok_or(ProtocolError::InvalidRequest)?
                        .validate()
                } else {
                    Err(ProtocolError::InvalidRequest)
                }
            }
            RequestKind::BeginAuthSession => {
                validate_profile_id(&self.profile_id)?;
                validate_http_url(&self.url)?;
                self.persona
                    .as_ref()
                    .ok_or(ProtocolError::InvalidRequest)?
                    .validate()?;
                if self.task.is_none()
                    && self.profile_class == Some(ProfileClass::Authenticated)
                    && self.session_update.is_none()
                    && self.session_probe.is_none()
                {
                    Ok(())
                } else {
                    Err(ProtocolError::InvalidRequest)
                }
            }
            RequestKind::FinishAuthSession => {
                validate_profile_id(&self.profile_id)?;
                if self.url.is_empty()
                    && self.task.is_none()
                    && self.persona.is_none()
                    && self.profile_class.is_none()
                    && self.session_update.is_none()
                    && self.session_probe.is_none()
                {
                    Ok(())
                } else {
                    Err(ProtocolError::InvalidRequest)
                }
            }
            RequestKind::CheckAuthSession => {
                validate_profile_id(&self.profile_id)?;
                if !self.url.is_empty() || self.task.is_some() || self.session_update.is_some() {
                    return Err(ProtocolError::InvalidRequest);
                }
                self.persona
                    .as_ref()
                    .ok_or(ProtocolError::InvalidRequest)?
                    .validate()?;
                self.session_probe
                    .as_ref()
                    .ok_or(ProtocolError::InvalidRequest)?
                    .validate()?;
                if self.profile_class == Some(ProfileClass::Authenticated) {
                    Ok(())
                } else {
                    Err(ProtocolError::InvalidRequest)
                }
            }
            RequestKind::ImportSession => {
                validate_profile_id(&self.profile_id)?;
                if self.task.is_some()
                    || self.session_update.is_some()
                    || self.session_probe.is_some()
                {
                    return Err(ProtocolError::InvalidRequest);
                }
                validate_session_import_path(&self.url)?;
                self.persona
                    .as_ref()
                    .ok_or(ProtocolError::InvalidRequest)?
                    .validate()?;
                if self.profile_class == Some(ProfileClass::Authenticated) {
                    Ok(())
                } else {
                    Err(ProtocolError::InvalidRequest)
                }
            }
            RequestKind::Collection => {
                if !self.url.is_empty()
                    || self.task.is_some()
                    || self.persona.is_some()
                    || self.profile_class.is_some()
                    || self.session_update.is_some()
                    || self.session_probe.is_some()
                {
                    return Err(ProtocolError::InvalidRequest);
                }
                let collection = self
                    .collection
                    .as_ref()
                    .ok_or(ProtocolError::InvalidRequest)?;
                collection.validate()?;
                if collection.is_begin() {
                    validate_profile_id(&self.profile_id)
                } else if self.profile_id.is_empty() {
                    Ok(())
                } else {
                    Err(ProtocolError::InvalidRequest)
                }
            }
            RequestKind::Crawl => {
                if !self.url.is_empty()
                    || self.task.is_some()
                    || self.persona.is_some()
                    || self.profile_class.is_some()
                    || self.session_update.is_some()
                    || self.session_probe.is_some()
                {
                    return Err(ProtocolError::InvalidRequest);
                }
                let crawl = self
                    .crawl
                    .as_ref()
                    .ok_or(ProtocolError::InvalidRequest)?;
                crawl.validate()?;
                if crawl.is_begin() {
                    validate_profile_id(&self.profile_id)
                } else if self.profile_id.is_empty() {
                    Ok(())
                } else {
                    Err(ProtocolError::InvalidRequest)
                }
            }
            RequestKind::LiveEvents => {
                if !self.url.is_empty()
                    || self.task.is_some()
                    || self.persona.is_some()
                    || self.profile_class.is_some()
                    || self.session_update.is_some()
                    || self.session_probe.is_some()
                {
                    return Err(ProtocolError::InvalidRequest);
                }
                let live = self
                    .live
                    .as_ref()
                    .ok_or(ProtocolError::InvalidRequest)?;
                live.validate()?;
                if live.is_begin() {
                    validate_profile_id(&self.profile_id)
                } else if self.profile_id.is_empty() {
                    Ok(())
                } else {
                    Err(ProtocolError::InvalidRequest)
                }
            }
            RequestKind::DurableMonitor => {
                if !self.url.is_empty()
                    || self.task.is_some()
                    || self.persona.is_some()
                    || self.profile_class.is_some()
                    || self.session_update.is_some()
                    || self.session_probe.is_some()
                {
                    return Err(ProtocolError::InvalidRequest);
                }
                let monitor = self
                    .monitor
                    .as_ref()
                    .ok_or(ProtocolError::InvalidRequest)?;
                monitor.validate()?;
                if monitor.is_begin() {
                    validate_profile_id(&self.profile_id)
                } else if self.profile_id.is_empty() {
                    Ok(())
                } else {
                    Err(ProtocolError::InvalidRequest)
                }
            }
            RequestKind::Health | RequestKind::Shutdown | RequestKind::Status => {
                if self.profile_id.is_empty()
                    && self.url.is_empty()
                    && self.task.is_none()
                    && self.persona.is_none()
                    && self.profile_class.is_none()
                    && self.session_update.is_none()
                    && self.session_probe.is_none()
                {
                    Ok(())
                } else {
                    Err(ProtocolError::InvalidRequest)
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum FailureClass {
    None = 0,
    Unavailable = 1,
    CaptureFailed = 2,
    TooLarge = 3,
    Protocol = 4,
    Timeout = 5,
    Cancelled = 6,
}

impl FailureClass {
    fn from_wire(value: u64) -> Result<Self, ProtocolError> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::Unavailable),
            2 => Ok(Self::CaptureFailed),
            3 => Ok(Self::TooLarge),
            4 => Ok(Self::Protocol),
            5 => Ok(Self::Timeout),
            6 => Ok(Self::Cancelled),
            _ => Err(ProtocolError::InvalidStatusPayload),
        }
    }
}

/// Sanitized aggregate station telemetry. It intentionally contains no
/// identity IDs, URLs, cookies, profile paths or raw error messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StationStatus {
    pub shutting_down: bool,
    pub resident_identities: u64,
    pub starting_workers: u64,
    pub ready_workers: u64,
    pub degraded_workers: u64,
    pub restarting_workers: u64,
    pub shutting_down_workers: u64,
    pub stopped_workers: u64,
    pub active_leases: u64,
    pub command_limit: u64,
    pub command_available: u64,
    pub command_waiters: u64,
    pub accepted_connections: u64,
    pub active_connections: u64,
    pub completed_connections: u64,
    pub aborted_connections: u64,
    pub captures_started: u64,
    pub captures_in_flight: u64,
    pub captures_succeeded: u64,
    pub captures_failed: u64,
    pub captures_timed_out: u64,
    pub last_failure_unix_ms: u64,
    pub last_failure_class: FailureClass,
}

impl StationStatus {
    pub fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(STATUS_PAYLOAD_BYTES);
        payload.extend_from_slice(&STATUS_MAGIC);
        payload.extend_from_slice(&STATUS_SCHEMA_VERSION.to_le_bytes());
        payload.extend_from_slice(&u16::from(self.shutting_down).to_le_bytes());
        for field in [
            self.resident_identities,
            self.starting_workers,
            self.ready_workers,
            self.degraded_workers,
            self.restarting_workers,
            self.shutting_down_workers,
            self.stopped_workers,
            self.active_leases,
            self.command_limit,
            self.command_available,
            self.command_waiters,
            self.accepted_connections,
            self.active_connections,
            self.completed_connections,
            self.aborted_connections,
            self.captures_started,
            self.captures_in_flight,
            self.captures_succeeded,
            self.captures_failed,
            self.captures_timed_out,
            self.last_failure_unix_ms,
            self.last_failure_class as u64,
        ] {
            payload.extend_from_slice(&field.to_le_bytes());
        }
        payload
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.len() != STATUS_PAYLOAD_BYTES
            || payload[..4] != STATUS_MAGIC
            || u16::from_le_bytes(payload[4..6].try_into().unwrap()) != STATUS_SCHEMA_VERSION
        {
            return Err(ProtocolError::InvalidStatusPayload);
        }
        let flags = u16::from_le_bytes(payload[6..8].try_into().unwrap());
        if flags & !1 != 0 {
            return Err(ProtocolError::InvalidStatusPayload);
        }
        let mut offset = 8;
        let mut next = || {
            let value = u64::from_le_bytes(payload[offset..offset + 8].try_into().unwrap());
            offset += 8;
            value
        };
        Ok(Self {
            shutting_down: flags & 1 == 1,
            resident_identities: next(),
            starting_workers: next(),
            ready_workers: next(),
            degraded_workers: next(),
            restarting_workers: next(),
            shutting_down_workers: next(),
            stopped_workers: next(),
            active_leases: next(),
            command_limit: next(),
            command_available: next(),
            command_waiters: next(),
            accepted_connections: next(),
            active_connections: next(),
            completed_connections: next(),
            aborted_connections: next(),
            captures_started: next(),
            captures_in_flight: next(),
            captures_succeeded: next(),
            captures_failed: next(),
            captures_timed_out: next(),
            last_failure_unix_ms: next(),
            last_failure_class: FailureClass::from_wire(next())?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ResponseStatus {
    Ok = 0,
    Invalid = 1,
    Unavailable = 2,
    CaptureFailed = 3,
    TooLarge = 4,
    Protocol = 5,
    Unsupported = 6,
}

impl ResponseStatus {
    fn from_wire(value: u8) -> Result<Self, FrameError> {
        match value {
            0 => Ok(Self::Ok),
            1 => Ok(Self::Invalid),
            2 => Ok(Self::Unavailable),
            3 => Ok(Self::CaptureFailed),
            4 => Ok(Self::TooLarge),
            5 => Ok(Self::Protocol),
            6 => Ok(Self::Unsupported),
            _ => Err(FrameError::InvalidResponse),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerResponse {
    pub status: ResponseStatus,
    pub kind: RequestKind,
    pub request_id: u64,
    pub http_status: Option<u16>,
    pub duration_ms: u64,
    pub final_url: String,
    pub title: String,
    pub error: String,
    pub html: Vec<u8>,
    pub png: Vec<u8>,
}

impl WorkerResponse {
    pub fn empty(request: &WorkerRequest, status: ResponseStatus) -> Self {
        Self {
            status,
            kind: request.kind,
            request_id: request.request_id,
            http_status: None,
            duration_ms: 0,
            final_url: String::new(),
            title: String::new(),
            error: String::new(),
            html: Vec::new(),
            png: Vec::new(),
        }
    }

    pub fn failure(request: &WorkerRequest, status: ResponseStatus, error: &str) -> Self {
        let mut response = Self::empty(request, status);
        response.error = sanitize_error(error);
        response
    }

    pub fn station_status(request: &WorkerRequest, status: &StationStatus) -> Self {
        let mut response = Self::empty(request, ResponseStatus::Ok);
        response.html = status.encode();
        response
    }

    pub fn identity_status(
        request: &WorkerRequest,
        status: &IdentitySessionStatus,
    ) -> Result<Self, ProtocolError> {
        let mut response = Self::empty(request, ResponseStatus::Ok);
        response.html = status.encode()?;
        response.validate()?;
        Ok(response)
    }

    pub fn task_result(
        request: &WorkerRequest,
        result: &CollectionTaskResult,
    ) -> Result<Self, ProtocolError> {
        let mut response = Self::empty(request, ResponseStatus::Ok);
        response.html = result.encode()?;
        response.validate()?;
        Ok(response)
    }

    pub fn collection_response(
        request: &WorkerRequest,
        result: &CollectionResponse,
    ) -> Result<Self, ProtocolError> {
        let mut response = Self::empty(request, ResponseStatus::Ok);
        response.html = result.encode()?;
        response.validate()?;
        Ok(response)
    }

    pub fn crawl_response(
        request: &WorkerRequest,
        result: &CrawlResponse,
    ) -> Result<Self, ProtocolError> {
        let mut response = Self::empty(request, ResponseStatus::Ok);
        response.html = result.encode()?;
        response.validate()?;
        Ok(response)
    }

    pub fn live_response(
        request: &WorkerRequest,
        result: &LiveResponse,
    ) -> Result<Self, ProtocolError> {
        let mut response = Self::empty(request, ResponseStatus::Ok);
        response.html = result.encode()?;
        response.validate()?;
        Ok(response)
    }

    pub fn decode_live_response(&self) -> Result<LiveResponse, ProtocolError> {
        if self.kind != RequestKind::LiveEvents
            || self.status != ResponseStatus::Ok
            || self.http_status.is_some()
            || !self.final_url.is_empty()
            || !self.title.is_empty()
            || !self.error.is_empty()
            || !self.png.is_empty()
        {
            return Err(ProtocolError::InvalidLivePayload);
        }
        LiveResponse::decode(&self.html)
    }

    pub fn monitor_response(
        request: &WorkerRequest,
        result: &MonitorResponse,
    ) -> Result<Self, ProtocolError> {
        let mut response = Self::empty(request, ResponseStatus::Ok);
        response.html = result.encode()?;
        response.validate()?;
        Ok(response)
    }

    pub fn decode_monitor_response(&self) -> Result<MonitorResponse, ProtocolError> {
        if self.kind != RequestKind::DurableMonitor
            || self.status != ResponseStatus::Ok
            || self.http_status.is_some()
            || !self.final_url.is_empty()
            || !self.title.is_empty()
            || !self.error.is_empty()
            || !self.png.is_empty()
        {
            return Err(ProtocolError::InvalidMonitorPayload);
        }
        MonitorResponse::decode(&self.html)
    }

    pub fn decode_collection_response(&self) -> Result<CollectionResponse, ProtocolError> {
        if self.kind != RequestKind::Collection
            || self.status != ResponseStatus::Ok
            || self.http_status.is_some()
            || !self.final_url.is_empty()
            || !self.title.is_empty()
            || !self.error.is_empty()
            || !self.png.is_empty()
        {
            return Err(ProtocolError::InvalidCollectionPayload);
        }
        CollectionResponse::decode(&self.html)
    }

    pub fn decode_crawl_response(&self) -> Result<CrawlResponse, ProtocolError> {
        if self.kind != RequestKind::Crawl
            || self.status != ResponseStatus::Ok
            || self.http_status.is_some()
            || !self.final_url.is_empty()
            || !self.title.is_empty()
            || !self.error.is_empty()
            || !self.png.is_empty()
        {
            return Err(ProtocolError::InvalidCrawlPayload);
        }
        CrawlResponse::decode(&self.html)
    }

    pub fn decode_task_result(&self) -> Result<CollectionTaskResult, ProtocolError> {
        if self.kind != RequestKind::Task
            || self.status != ResponseStatus::Ok
            || self.http_status.is_some()
            || !self.final_url.is_empty()
            || !self.title.is_empty()
            || !self.error.is_empty()
            || !self.png.is_empty()
        {
            return Err(ProtocolError::InvalidTaskResult);
        }
        CollectionTaskResult::decode(&self.html)
    }

    pub fn decode_station_status(&self) -> Result<StationStatus, ProtocolError> {
        if self.kind != RequestKind::Status
            || self.status != ResponseStatus::Ok
            || self.http_status.is_some()
            || !self.final_url.is_empty()
            || !self.title.is_empty()
            || !self.error.is_empty()
            || !self.png.is_empty()
        {
            return Err(ProtocolError::InvalidStatusPayload);
        }
        StationStatus::decode(&self.html)
    }

    pub fn decode_identity_status(&self) -> Result<IdentitySessionStatus, ProtocolError> {
        if !matches!(
            self.kind,
            RequestKind::IdentityStatus | RequestKind::CheckAuthSession
        )
            || self.status != ResponseStatus::Ok
            || self.http_status.is_some()
            || !self.final_url.is_empty()
            || !self.title.is_empty()
            || !self.error.is_empty()
            || !self.png.is_empty()
        {
            return Err(ProtocolError::InvalidSessionPayload);
        }
        IdentitySessionStatus::decode(&self.html)
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        let capacity = RESPONSE_HEADER_BYTES
            .checked_add(self.final_url.len())
            .and_then(|size| size.checked_add(self.title.len()))
            .and_then(|size| size.checked_add(self.error.len()))
            .and_then(|size| size.checked_add(self.html.len()))
            .and_then(|size| size.checked_add(self.png.len()))
            .ok_or(ProtocolError::ResponseTooLarge)?;
        let mut bytes = Vec::with_capacity(capacity);
        bytes.extend_from_slice(&response_header(self)?);
        bytes.extend_from_slice(self.final_url.as_bytes());
        bytes.extend_from_slice(self.title.as_bytes());
        bytes.extend_from_slice(self.error.as_bytes());
        bytes.extend_from_slice(&self.html);
        bytes.extend_from_slice(&self.png);
        Ok(bytes)
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.final_url.len() > MAX_FINAL_URL_BYTES
            || self.title.len() > MAX_TITLE_BYTES
            || self.error.len() > MAX_ERROR_BYTES
            || self.html.len() > MAX_HTML_BYTES
            || self.png.len() > MAX_PNG_BYTES
        {
            return Err(ProtocolError::ResponseTooLarge);
        }
        if self.kind == RequestKind::Status && self.status == ResponseStatus::Ok {
            self.decode_station_status()?;
        }
        if self.kind == RequestKind::Task && self.status == ResponseStatus::Ok {
            self.decode_task_result()?;
        }
        if self.kind == RequestKind::Collection && self.status == ResponseStatus::Ok {
            self.decode_collection_response()?;
        }
        if self.kind == RequestKind::Crawl && self.status == ResponseStatus::Ok {
            self.decode_crawl_response()?;
        }
        if self.kind == RequestKind::LiveEvents && self.status == ResponseStatus::Ok {
            self.decode_live_response()?;
        }
        if matches!(
            self.kind,
            RequestKind::IdentityStatus | RequestKind::CheckAuthSession
        ) && self.status == ResponseStatus::Ok
        {
            self.decode_identity_status()?;
        }
        Ok(())
    }
}

pub fn validate_pipe_suffix(value: &str) -> Result<(), PipeNameError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(PipeNameError);
    }
    Ok(())
}

pub async fn write_worker_request<W>(
    stream: &mut W,
    request: &WorkerRequest,
) -> Result<(), FrameError>
where
    W: AsyncWrite + Unpin,
{
    stream.write_all(&request.encode()?).await?;
    stream.flush().await?;
    Ok(())
}

fn encode_task_identity_payload(
    profile_class: ProfileClass,
    persona: &BrowserPersona,
    task: &CollectionTask,
) -> Result<Vec<u8>, ProtocolError> {
    let persona = persona.encode()?;
    let task = task.encode_payload()?;
    let persona_len = u16::try_from(persona.len())
        .map_err(|_| ProtocolError::InvalidIdentityPayload)?;
    let mut payload = Vec::with_capacity(10 + persona.len() + task.len());
    payload.extend_from_slice(&TASK_IDENTITY_MAGIC);
    payload.extend_from_slice(&TASK_IDENTITY_SCHEMA_VERSION.to_le_bytes());
    payload.extend_from_slice(&persona_len.to_le_bytes());
    payload.push(profile_class as u8);
    payload.push(0);
    payload.extend_from_slice(&persona);
    payload.extend_from_slice(&task);
    Ok(payload)
}

fn decode_task_identity_payload(
    payload: &[u8],
) -> Result<(ProfileClass, BrowserPersona, CollectionTask), ProtocolError> {
    if payload.starts_with(b"D2TK") {
        return Ok((
            ProfileClass::Public,
            BrowserPersona::desktop_default(),
            CollectionTask::decode_payload(payload)?,
        ));
    }
    if payload.len() < 8 || payload[..4] != TASK_IDENTITY_MAGIC {
        return Err(ProtocolError::InvalidIdentityPayload);
    }
    let schema = u16::from_le_bytes(payload[4..6].try_into().unwrap());
    if !matches!(schema, 1 | TASK_IDENTITY_SCHEMA_VERSION) {
        return Err(ProtocolError::InvalidIdentityPayload);
    }
    let persona_len = usize::from(u16::from_le_bytes(payload[6..8].try_into().unwrap()));
    let (profile_class, persona_offset) = if schema == 1 {
        (ProfileClass::Public, 8usize)
    } else {
        if payload.len() < 10 || payload[9] != 0 {
            return Err(ProtocolError::InvalidIdentityPayload);
        }
        (ProfileClass::from_wire(payload[8])?, 10usize)
    };
    let persona_end = persona_offset
        .checked_add(persona_len)
        .ok_or(ProtocolError::InvalidIdentityPayload)?;
    if persona_end >= payload.len() {
        return Err(ProtocolError::InvalidIdentityPayload);
    }
    let (persona, consumed) = BrowserPersona::decode(&payload[persona_offset..persona_end])?;
    if consumed != persona_len {
        return Err(ProtocolError::InvalidIdentityPayload);
    }
    let task = CollectionTask::decode_payload(&payload[persona_end..])?;
    Ok((profile_class, persona, task))
}

fn encode_auth_identity_payload(
    profile_class: ProfileClass,
    persona: &BrowserPersona,
    url: &str,
) -> Result<Vec<u8>, ProtocolError> {
    if profile_class != ProfileClass::Authenticated {
        return Err(ProtocolError::InvalidIdentityPayload);
    }
    let persona = persona.encode()?;
    let persona_len = u16::try_from(persona.len())
        .map_err(|_| ProtocolError::InvalidIdentityPayload)?;
    let mut payload = Vec::with_capacity(10 + persona.len() + url.len());
    payload.extend_from_slice(&AUTH_IDENTITY_MAGIC);
    payload.extend_from_slice(&AUTH_IDENTITY_SCHEMA_VERSION.to_le_bytes());
    payload.extend_from_slice(&persona_len.to_le_bytes());
    payload.push(profile_class as u8);
    payload.push(0);
    payload.extend_from_slice(&persona);
    payload.extend_from_slice(url.as_bytes());
    Ok(payload)
}

fn decode_auth_identity_payload(
    payload: &[u8],
) -> Result<(ProfileClass, BrowserPersona, String), ProtocolError> {
    if payload.len() < 10
        || payload[..4] != AUTH_IDENTITY_MAGIC
        || u16::from_le_bytes(payload[4..6].try_into().unwrap())
            != AUTH_IDENTITY_SCHEMA_VERSION
        || payload[9] != 0
    {
        return Err(ProtocolError::InvalidIdentityPayload);
    }
    let persona_len = usize::from(u16::from_le_bytes(payload[6..8].try_into().unwrap()));
    let profile_class = ProfileClass::from_wire(payload[8])?;
    if profile_class != ProfileClass::Authenticated {
        return Err(ProtocolError::InvalidIdentityPayload);
    }
    let persona_end = 10usize
        .checked_add(persona_len)
        .ok_or(ProtocolError::InvalidIdentityPayload)?;
    if persona_end >= payload.len() {
        return Err(ProtocolError::InvalidIdentityPayload);
    }
    let (persona, consumed) = BrowserPersona::decode(&payload[10..persona_end])?;
    if consumed != persona_len {
        return Err(ProtocolError::InvalidIdentityPayload);
    }
    let url = std::str::from_utf8(&payload[persona_end..])
        .map_err(|_| ProtocolError::InvalidIdentityPayload)?
        .to_owned();
    validate_http_url(&url)?;
    Ok((profile_class, persona, url))
}

fn validate_session_import_path(path: &str) -> Result<(), ProtocolError> {
    if path.is_empty()
        || path.len() > MAX_SESSION_IMPORT_PATH_BYTES
        || path.contains('\0')
    {
        return Err(ProtocolError::InvalidRequest);
    }
    Ok(())
}

/// Like `encode_auth_identity_payload`, but the trailing string is a local
/// filesystem path (the prepared-session file), not an HTTP URL.
fn encode_import_identity_payload(
    profile_class: ProfileClass,
    persona: &BrowserPersona,
    path: &str,
) -> Result<Vec<u8>, ProtocolError> {
    if profile_class != ProfileClass::Authenticated {
        return Err(ProtocolError::InvalidIdentityPayload);
    }
    validate_session_import_path(path)?;
    let persona = persona.encode()?;
    let persona_len = u16::try_from(persona.len())
        .map_err(|_| ProtocolError::InvalidIdentityPayload)?;
    let mut payload = Vec::with_capacity(10 + persona.len() + path.len());
    payload.extend_from_slice(&IMPORT_IDENTITY_MAGIC);
    payload.extend_from_slice(&IMPORT_IDENTITY_SCHEMA_VERSION.to_le_bytes());
    payload.extend_from_slice(&persona_len.to_le_bytes());
    payload.push(profile_class as u8);
    payload.push(0);
    payload.extend_from_slice(&persona);
    payload.extend_from_slice(path.as_bytes());
    Ok(payload)
}

fn decode_import_identity_payload(
    payload: &[u8],
) -> Result<(ProfileClass, BrowserPersona, String), ProtocolError> {
    if payload.len() < 10
        || payload[..4] != IMPORT_IDENTITY_MAGIC
        || u16::from_le_bytes(payload[4..6].try_into().unwrap())
            != IMPORT_IDENTITY_SCHEMA_VERSION
        || payload[9] != 0
    {
        return Err(ProtocolError::InvalidIdentityPayload);
    }
    let persona_len = usize::from(u16::from_le_bytes(payload[6..8].try_into().unwrap()));
    let profile_class = ProfileClass::from_wire(payload[8])?;
    if profile_class != ProfileClass::Authenticated {
        return Err(ProtocolError::InvalidIdentityPayload);
    }
    let persona_end = 10usize
        .checked_add(persona_len)
        .ok_or(ProtocolError::InvalidIdentityPayload)?;
    if persona_end >= payload.len() {
        return Err(ProtocolError::InvalidIdentityPayload);
    }
    let (persona, consumed) = BrowserPersona::decode(&payload[10..persona_end])?;
    if consumed != persona_len {
        return Err(ProtocolError::InvalidIdentityPayload);
    }
    let path = std::str::from_utf8(&payload[persona_end..])
        .map_err(|_| ProtocolError::InvalidIdentityPayload)?
        .to_owned();
    validate_session_import_path(&path)?;
    Ok((profile_class, persona, path))
}

fn encode_health_identity_payload(
    profile_class: ProfileClass,
    persona: &BrowserPersona,
    probe: &SessionHealthProbe,
) -> Result<Vec<u8>, ProtocolError> {
    if profile_class != ProfileClass::Authenticated {
        return Err(ProtocolError::InvalidIdentityPayload);
    }
    let persona = persona.encode()?;
    let probe = probe.encode()?;
    let persona_len = u16::try_from(persona.len())
        .map_err(|_| ProtocolError::InvalidIdentityPayload)?;
    let mut payload = Vec::with_capacity(10 + persona.len() + probe.len());
    payload.extend_from_slice(&HEALTH_IDENTITY_MAGIC);
    payload.extend_from_slice(&HEALTH_IDENTITY_SCHEMA_VERSION.to_le_bytes());
    payload.extend_from_slice(&persona_len.to_le_bytes());
    payload.push(profile_class as u8);
    payload.push(0);
    payload.extend_from_slice(&persona);
    payload.extend_from_slice(&probe);
    Ok(payload)
}

fn decode_health_identity_payload(
    payload: &[u8],
) -> Result<(ProfileClass, BrowserPersona, SessionHealthProbe), ProtocolError> {
    if payload.len() < 10
        || payload[..4] != HEALTH_IDENTITY_MAGIC
        || u16::from_le_bytes(payload[4..6].try_into().unwrap())
            != HEALTH_IDENTITY_SCHEMA_VERSION
        || payload[9] != 0
    {
        return Err(ProtocolError::InvalidIdentityPayload);
    }
    let persona_len = usize::from(u16::from_le_bytes(payload[6..8].try_into().unwrap()));
    let profile_class = ProfileClass::from_wire(payload[8])?;
    if profile_class != ProfileClass::Authenticated {
        return Err(ProtocolError::InvalidIdentityPayload);
    }
    let persona_end = 10usize
        .checked_add(persona_len)
        .ok_or(ProtocolError::InvalidIdentityPayload)?;
    if persona_end >= payload.len() {
        return Err(ProtocolError::InvalidIdentityPayload);
    }
    let (persona, consumed) = BrowserPersona::decode(&payload[10..persona_end])?;
    if consumed != persona_len {
        return Err(ProtocolError::InvalidIdentityPayload);
    }
    let probe = SessionHealthProbe::decode(&payload[persona_end..])?;
    Ok((profile_class, persona, probe))
}

pub async fn read_worker_request<R>(
    stream: &mut R,
) -> Result<Option<WorkerRequest>, FrameError>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; REQUEST_HEADER_BYTES];
    let first = stream.read(&mut header[..4]).await?;
    if first == 0 {
        return Ok(None);
    }
    stream.read_exact(&mut header[first..]).await?;
    if header[..4] != REQUEST_MAGIC
        || u16::from_le_bytes(header[4..6].try_into().unwrap()) != PROTOCOL_VERSION
        || header[7] != 0
    {
        return Err(FrameError::Protocol(ProtocolError::InvalidRequest));
    }
    let kind = RequestKind::from_wire(header[6])?;
    let request_id = u64::from_le_bytes(header[8..16].try_into().unwrap());
    let profile_len = u16::from_le_bytes(header[16..18].try_into().unwrap()) as usize;
    let url_len = u32::from_le_bytes(header[18..22].try_into().unwrap()) as usize;
    let total = REQUEST_HEADER_BYTES
        .checked_add(profile_len)
        .and_then(|value| value.checked_add(url_len))
        .ok_or(ProtocolError::InvalidRequest)?;
    if total > MAX_REQUEST_BYTES {
        return Err(FrameError::Protocol(ProtocolError::InvalidRequest));
    }
    let mut payload = vec![0_u8; profile_len + url_len];
    stream.read_exact(&mut payload).await?;
    let profile_id = std::str::from_utf8(&payload[..profile_len])
        .map_err(|_| FrameError::Protocol(ProtocolError::InvalidRequest))?
        .to_owned();
    let body = &payload[profile_len..];
    if kind == RequestKind::Collection {
        let request = WorkerRequest {
            kind,
            request_id,
            profile_id,
            url: String::new(),
            task: None,
            persona: None,
            profile_class: None,
            session_update: None,
            session_probe: None,
            collection: Some(CollectionRequest::decode(body)?),
            crawl: None,
            live: None,
            monitor: None,
        };
        request.validate()?;
        return Ok(Some(request));
    }
    if kind == RequestKind::Crawl {
        let request = WorkerRequest {
            kind,
            request_id,
            profile_id,
            url: String::new(),
            task: None,
            persona: None,
            profile_class: None,
            session_update: None,
            session_probe: None,
            collection: None,
            crawl: Some(CrawlRequest::decode(body)?),
            live: None,
            monitor: None,
        };
        request.validate()?;
        return Ok(Some(request));
    }
    if kind == RequestKind::LiveEvents {
        let request = WorkerRequest {
            kind,
            request_id,
            profile_id,
            url: String::new(),
            task: None,
            persona: None,
            profile_class: None,
            session_update: None,
            session_probe: None,
            collection: None,
            crawl: None,
            live: Some(LiveRequest::decode(body)?),
            monitor: None,
        };
        request.validate()?;
        return Ok(Some(request));
    }
    if kind == RequestKind::DurableMonitor {
        let request = WorkerRequest {
            kind,
            request_id,
            profile_id,
            url: String::new(),
            task: None,
            persona: None,
            profile_class: None,
            session_update: None,
            session_probe: None,
            collection: None,
            crawl: None,
            live: None,
            monitor: Some(MonitorRequest::decode(body)?),
        };
        request.validate()?;
        return Ok(Some(request));
    }
    let (url, task, persona, profile_class, session_update) = if kind == RequestKind::Task {
        let (profile_class, persona, task) = decode_task_identity_payload(body)?;
        (
            String::new(),
            Some(task),
            Some(persona),
            Some(profile_class),
            None,
        )
    } else if kind == RequestKind::BeginAuthSession {
        let (profile_class, persona, url) = decode_auth_identity_payload(body)?;
        (url, None, Some(persona), Some(profile_class), None)
    } else if kind == RequestKind::ImportSession {
        let (profile_class, persona, path) = decode_import_identity_payload(body)?;
        (path, None, Some(persona), Some(profile_class), None)
    } else if kind == RequestKind::CheckAuthSession {
        let (profile_class, persona, session_probe) =
            decode_health_identity_payload(body)?;
        let request = WorkerRequest {
            kind,
            request_id,
            profile_id,
            url: String::new(),
            task: None,
            persona: Some(persona),
            profile_class: Some(profile_class),
            session_update: None,
            session_probe: Some(session_probe),
            collection: None,
            crawl: None,
            live: None,
            monitor: None,
        };
        request.validate()?;
        return Ok(Some(request));
    } else if kind == RequestKind::UpdateIdentityState {
        (
            String::new(),
            None,
            None,
            None,
            Some(SessionStateUpdate::decode(body)?),
        )
    } else {
        (
            std::str::from_utf8(body)
                .map_err(|_| FrameError::Protocol(ProtocolError::InvalidRequest))?
                .to_owned(),
            None,
            None,
            None,
            None,
        )
    };
    let request = WorkerRequest {
        kind,
        request_id,
        profile_id,
        url,
        task,
        persona,
        profile_class,
        session_update,
        session_probe: None,
        collection: None,
        crawl: None,
        live: None,
        monitor: None,
    };
    request.validate()?;
    Ok(Some(request))
}

pub async fn write_worker_response<W>(
    stream: &mut W,
    response: &WorkerResponse,
) -> Result<(), FrameError>
where
    W: AsyncWrite + Unpin,
{
    stream.write_all(&response.encode()?).await?;
    stream.flush().await?;
    Ok(())
}

pub async fn read_worker_response<R>(stream: &mut R) -> Result<WorkerResponse, FrameError>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; RESPONSE_HEADER_BYTES];
    stream.read_exact(&mut header).await?;
    if header[..4] != RESPONSE_MAGIC
        || u16::from_le_bytes(header[4..6].try_into().unwrap()) != PROTOCOL_VERSION
        || u16::from_le_bytes(header[18..20].try_into().unwrap()) != 0
    {
        return Err(FrameError::InvalidResponse);
    }
    let status = ResponseStatus::from_wire(header[6])?;
    let kind = RequestKind::from_wire(header[7]).map_err(|_| FrameError::InvalidResponse)?;
    let request_id = u64::from_le_bytes(header[8..16].try_into().unwrap());
    let raw_http_status = u16::from_le_bytes(header[16..18].try_into().unwrap());
    let http_status = match raw_http_status {
        0 => None,
        100..=599 => Some(raw_http_status),
        _ => return Err(FrameError::InvalidResponse),
    };
    let duration_ms = u64::from_le_bytes(header[20..28].try_into().unwrap());
    let final_url_len = u32::from_le_bytes(header[28..32].try_into().unwrap()) as usize;
    let title_len = u32::from_le_bytes(header[32..36].try_into().unwrap()) as usize;
    let error_len = u32::from_le_bytes(header[36..40].try_into().unwrap()) as usize;
    let html_len = usize::try_from(u64::from_le_bytes(header[40..48].try_into().unwrap()))
        .map_err(|_| FrameError::InvalidResponse)?;
    let png_len = usize::try_from(u64::from_le_bytes(header[48..56].try_into().unwrap()))
        .map_err(|_| FrameError::InvalidResponse)?;
    if final_url_len > MAX_FINAL_URL_BYTES
        || title_len > MAX_TITLE_BYTES
        || error_len > MAX_ERROR_BYTES
        || html_len > MAX_HTML_BYTES
        || png_len > MAX_PNG_BYTES
    {
        return Err(FrameError::Protocol(ProtocolError::ResponseTooLarge));
    }
    let response = WorkerResponse {
        status,
        kind,
        request_id,
        http_status,
        duration_ms,
        final_url: read_utf8(stream, final_url_len).await?,
        title: read_utf8(stream, title_len).await?,
        error: read_utf8(stream, error_len).await?,
        html: read_bytes(stream, html_len).await?,
        png: read_bytes(stream, png_len).await?,
    };
    response.validate()?;
    Ok(response)
}

async fn read_utf8<R>(stream: &mut R, len: usize) -> Result<String, FrameError>
where
    R: AsyncRead + Unpin,
{
    String::from_utf8(read_bytes(stream, len).await?)
        .map_err(|_| FrameError::InvalidResponse)
}

async fn read_bytes<R>(stream: &mut R, len: usize) -> Result<Vec<u8>, FrameError>
where
    R: AsyncRead + Unpin,
{
    let mut bytes = vec![0_u8; len];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}

fn response_header(
    response: &WorkerResponse,
) -> Result<[u8; RESPONSE_HEADER_BYTES], ProtocolError> {
    response.validate()?;
    let mut header = [0_u8; RESPONSE_HEADER_BYTES];
    header[0..4].copy_from_slice(&RESPONSE_MAGIC);
    header[4..6].copy_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    header[6] = response.status as u8;
    header[7] = response.kind as u8;
    header[8..16].copy_from_slice(&response.request_id.to_le_bytes());
    header[16..18].copy_from_slice(&response.http_status.unwrap_or(0).to_le_bytes());
    header[20..28].copy_from_slice(&response.duration_ms.to_le_bytes());
    header[28..32].copy_from_slice(&(response.final_url.len() as u32).to_le_bytes());
    header[32..36].copy_from_slice(&(response.title.len() as u32).to_le_bytes());
    header[36..40].copy_from_slice(&(response.error.len() as u32).to_le_bytes());
    header[40..48].copy_from_slice(&(response.html.len() as u64).to_le_bytes());
    header[48..56].copy_from_slice(&(response.png.len() as u64).to_le_bytes());
    Ok(header)
}

fn validate_profile_id(value: &str) -> Result<(), ProtocolError> {
    if value.is_empty()
        || value.len() > 128
        || value == "."
        || value == ".."
        || value.ends_with('.')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ProtocolError::InvalidRequest);
    }
    Ok(())
}

pub(crate) fn validate_http_url(value: &str) -> Result<(), ProtocolError> {
    let remainder = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
        .ok_or(ProtocolError::InvalidRequest)?;
    let authority = remainder.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty()
        || authority.chars().any(char::is_whitespace)
        || value.chars().any(char::is_control)
    {
        return Err(ProtocolError::InvalidRequest);
    }
    Ok(())
}

fn sanitize_error(value: &str) -> String {
    let mut sanitized = String::with_capacity(value.len().min(MAX_ERROR_BYTES));
    for character in value.chars() {
        if character.is_control() {
            continue;
        }
        if sanitized.len() + character.len_utf8() > MAX_ERROR_BYTES {
            break;
        }
        sanitized.push(character);
    }
    sanitized
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipeNameError;

impl std::fmt::Display for PipeNameError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "invalid pipe name")
    }
}

impl std::error::Error for PipeNameError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    InvalidRequest,
    ResponseTooLarge,
    InvalidStatusPayload,
    InvalidTaskPayload,
    InvalidTaskResult,
    InvalidIdentityPayload,
    InvalidSessionPayload,
    InvalidCollectionPayload,
    InvalidCrawlPayload,
    InvalidLivePayload,
    InvalidMonitorPayload,
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRequest => write!(formatter, "invalid request"),
            Self::ResponseTooLarge => write!(formatter, "response exceeds protocol limits"),
            Self::InvalidStatusPayload => write!(formatter, "station status payload is invalid"),
            Self::InvalidTaskPayload => write!(formatter, "browser task payload is invalid"),
            Self::InvalidTaskResult => write!(formatter, "browser task result is invalid"),
            Self::InvalidIdentityPayload => {
                write!(formatter, "browser identity payload is invalid")
            }
            Self::InvalidSessionPayload => {
                write!(formatter, "browser session payload is invalid")
            }
            Self::InvalidCollectionPayload => {
                write!(formatter, "collection payload is invalid")
            }
            Self::InvalidCrawlPayload => write!(formatter, "crawl payload is invalid"),
            Self::InvalidLivePayload => write!(formatter, "live event payload is invalid"),
            Self::InvalidMonitorPayload => {
                write!(formatter, "monitor event payload is invalid")
            }
        }
    }
}

impl std::error::Error for ProtocolError {}

#[derive(Debug)]
pub enum FrameError {
    Io(io::Error),
    InvalidResponse,
    Protocol(ProtocolError),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "IPC I/O failure: {error}"),
            Self::InvalidResponse => write!(formatter, "IPC response is invalid"),
            Self::Protocol(error) => write!(formatter, "IPC protocol failure: {error}"),
        }
    }
}

impl std::error::Error for FrameError {}

impl From<io::Error> for FrameError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<ProtocolError> for FrameError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_response_status_has_stable_wire_code() {
        assert_eq!(ResponseStatus::Unsupported as u8, 6);
        assert_eq!(
            ResponseStatus::from_wire(6).expect("decode unsupported"),
            ResponseStatus::Unsupported
        );
    }

    #[test]
    fn request_kind_wire_codes_are_stable_and_extensions_are_append_only() {
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

    #[tokio::test]
    async fn request_and_response_round_trip_fixed_v1_layout() {
        let request = WorkerRequest::capture(42, "review.example", "https://example.test/path");
        let request_bytes = request.encode().expect("request");
        let mut expected_request = Vec::from(*b"D2BQ");
        expected_request.extend_from_slice(&1_u16.to_le_bytes());
        expected_request.extend_from_slice(&[1, 0]);
        expected_request.extend_from_slice(&42_u64.to_le_bytes());
        expected_request.extend_from_slice(&14_u16.to_le_bytes());
        expected_request.extend_from_slice(&25_u32.to_le_bytes());
        expected_request.extend_from_slice(b"review.example");
        expected_request.extend_from_slice(b"https://example.test/path");
        assert_eq!(request_bytes, expected_request);
        let mut request_reader = &request_bytes[..];
        assert_eq!(
            read_worker_request(&mut request_reader)
                .await
                .expect("decode")
                .expect("request"),
            request
        );

        let response = WorkerResponse {
            status: ResponseStatus::Ok,
            kind: RequestKind::Capture,
            request_id: 42,
            http_status: Some(200),
            duration_ms: 7,
            final_url: "https://example.test/final".to_owned(),
            title: "Example".to_owned(),
            error: String::new(),
            html: b"<html>ok</html>".to_vec(),
            png: vec![137, 80, 78, 71],
        };
        let response_bytes = response.encode().expect("response");
        assert_eq!(&response_bytes[..4], b"D2BR");
        let mut response_reader = &response_bytes[..];
        assert_eq!(
            read_worker_response(&mut response_reader)
                .await
                .expect("decode"),
            response
        );
    }


    #[tokio::test]
    async fn collection_outer_request_and_typed_response_round_trip() {
        let collection_id = CollectionId::new([9; 16]).unwrap();
        let task = CollectionTask::new(vec![TaskStep::Navigate {
            url: "https://example.test/collection".to_owned(),
        }])
        .unwrap();
        let collection = CollectionRequest::begin(
            collection_id,
            ProfileClass::Public,
            BrowserPersona::desktop_default(),
            task,
        )
        .unwrap();
        let request = WorkerRequest::begin_collection(
            91,
            "collection-profile",
            collection,
        )
        .unwrap();
        let encoded = request.encode().unwrap();
        assert_eq!(&encoded[..4], b"D2BQ");
        assert_eq!(encoded[6], 11);
        let mut reader = encoded.as_slice();
        assert_eq!(read_worker_request(&mut reader).await.unwrap().unwrap(), request);

        let result = CollectionResponse::Accepted { collection_id };
        let response = WorkerResponse::collection_response(&request, &result).unwrap();
        assert_eq!(response.decode_collection_response().unwrap(), result);
        assert!(response.final_url.is_empty());
        assert!(response.title.is_empty());
        assert!(response.error.is_empty());
        assert!(response.png.is_empty());
    }

    #[tokio::test]
    async fn authentication_session_requests_round_trip_without_secret_fields() {
        let begin = WorkerRequest::begin_auth_session(
            81,
            "operator-profile",
            BrowserPersona::mobile_default(),
            "https://example.test/login",
        );
        let bytes = begin.encode().expect("encode begin auth session");
        assert!(!bytes.windows(6).any(|window| window == b"Cookie"));
        let mut reader = &bytes[..];
        assert_eq!(
            read_worker_request(&mut reader)
                .await
                .expect("decode begin auth session")
                .expect("begin auth request"),
            begin
        );

        let finish = WorkerRequest::finish_auth_session(82, "operator-profile");
        let bytes = finish.encode().expect("encode finish auth session");
        let mut reader = &bytes[..];
        assert_eq!(
            read_worker_request(&mut reader)
                .await
                .expect("decode finish auth session")
                .expect("finish auth request"),
            finish
        );

        let check = WorkerRequest::check_auth_session(
            83,
            "operator-profile",
            BrowserPersona::desktop_default(),
            SessionHealthProbe {
                url: "https://example.test/account".to_owned(),
                ready_selector: "[data-authenticated]".to_owned(),
                reauth_selector: "form[action*='login']".to_owned(),
                ready_ttl_seconds: 900,
            },
        );
        let bytes = check.encode().expect("encode auth health probe");
        let mut reader = &bytes[..];
        assert_eq!(
            read_worker_request(&mut reader)
                .await
                .expect("decode auth health probe")
                .expect("auth health request"),
            check
        );
    }

    #[tokio::test]
    async fn import_session_request_round_trips_carrying_a_path_not_cookies() {
        let import = WorkerRequest::import_session(
            84,
            "operator-profile",
            BrowserPersona::desktop_default(),
            "C:/tmp/prepared-session.json",
        );
        let bytes = import.encode().expect("encode import session");
        // The wire carries a path, never cookie material.
        assert!(!bytes.windows(6).any(|window| window == b"Cookie"));
        let mut reader = &bytes[..];
        let decoded = read_worker_request(&mut reader)
            .await
            .expect("decode import session")
            .expect("import session request");
        assert_eq!(decoded, import);
        assert_eq!(decoded.kind, RequestKind::ImportSession);
        assert_eq!(decoded.url, "C:/tmp/prepared-session.json");
        assert_eq!(decoded.profile_class, Some(ProfileClass::Authenticated));
    }

    #[test]
    fn station_status_round_trips_without_sensitive_fields() {
        let request = WorkerRequest::status(73);
        let status = StationStatus {
            shutting_down: false,
            resident_identities: 3,
            starting_workers: 0,
            ready_workers: 2,
            degraded_workers: 1,
            restarting_workers: 0,
            shutting_down_workers: 0,
            stopped_workers: 0,
            active_leases: 4,
            command_limit: 8,
            command_available: 5,
            command_waiters: 2,
            accepted_connections: 11,
            active_connections: 3,
            completed_connections: 7,
            aborted_connections: 1,
            captures_started: 20,
            captures_in_flight: 2,
            captures_succeeded: 16,
            captures_failed: 2,
            captures_timed_out: 1,
            last_failure_unix_ms: 1_784_402_400_000,
            last_failure_class: FailureClass::Timeout,
        };
        let response = WorkerResponse::station_status(&request, &status);
        assert_eq!(response.decode_station_status().expect("status"), status);
        assert_eq!(response.html.len(), STATUS_PAYLOAD_BYTES);
        assert!(response.final_url.is_empty());
        assert!(response.title.is_empty());
        assert!(response.error.is_empty());
        assert!(response.png.is_empty());
    }

    #[tokio::test]
    async fn authenticated_task_and_session_requests_round_trip() {
        let task = CollectionTask::new(vec![TaskStep::Navigate {
            url: "https://example.test/".to_owned(),
        }])
        .unwrap();
        let request = WorkerRequest::task_with_identity(
            81,
            "authenticated-profile",
            ProfileClass::Authenticated,
            BrowserPersona::mobile_default(),
            task,
        );
        let encoded = request.encode().unwrap();
        let mut reader = encoded.as_slice();
        assert_eq!(read_worker_request(&mut reader).await.unwrap().unwrap(), request);

        let update = WorkerRequest::update_identity_state(
            82,
            "authenticated-profile",
            SessionStateUpdate {
                phase: SessionPhase::Ready,
                expires_at_unix_ms: Some(1_800_000_000_000),
            },
        );
        let encoded = update.encode().unwrap();
        let mut reader = encoded.as_slice();
        assert_eq!(read_worker_request(&mut reader).await.unwrap().unwrap(), update);

        let status_request = WorkerRequest::identity_status(83, "authenticated-profile");
        let status = IdentitySessionStatus {
            profile_exists: true,
            persona_bound: true,
            profile_class: Some(ProfileClass::Authenticated),
            phase: SessionPhase::ReauthRequired,
            updated_at_unix_ms: 1_700_000_000_000,
            expires_at_unix_ms: None,
        };
        let response = WorkerResponse::identity_status(&status_request, &status).unwrap();
        assert_eq!(response.decode_identity_status().unwrap(), status);
    }
}
