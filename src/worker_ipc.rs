use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::agentic::{
    AgentCommand, AgentReply, BrowserWorker, BrowserWorkerConfig, CapabilitySet, CaptureArtifact,
    CapturePolicy, WorkerLifecycle,
};
use crate::identity::{
    validate_profile_id, BrowserBackend, DevicePersona, IdentityClass, IdentityProfile,
};

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
pub const MAX_FINAL_URL_BYTES: usize = 16 * 1024;
pub const MAX_TITLE_BYTES: usize = 16 * 1024;
pub const MAX_ERROR_BYTES: usize = 1024;
pub const MAX_HTML_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_PNG_BYTES: usize = 32 * 1024 * 1024;

const REQUEST_MAGIC: [u8; 4] = *b"D2BQ";
const RESPONSE_MAGIC: [u8; 4] = *b"D2BR";
const REQUEST_HEADER_BYTES: usize = 22;
const RESPONSE_HEADER_BYTES: usize = 56;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RequestKind {
    Capture = 1,
    Health = 2,
    Shutdown = 3,
}

impl RequestKind {
    fn from_wire(value: u8) -> Result<Self, ProtocolError> {
        match value {
            1 => Ok(Self::Capture),
            2 => Ok(Self::Health),
            3 => Ok(Self::Shutdown),
            _ => Err(ProtocolError::InvalidRequest),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerRequest {
    pub kind: RequestKind,
    pub request_id: u64,
    pub profile_id: String,
    pub url: String,
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
    fn empty(request: &WorkerRequest, status: ResponseStatus) -> Self {
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

    fn failure(request: &WorkerRequest, status: ResponseStatus, error: &str) -> Self {
        let mut response = Self::empty(request, status);
        response.error = sanitize_error(error);
        response
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        validate_response(self)?;
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
}

#[derive(Debug, Clone)]
pub struct WorkerIpcConfig {
    pipe_name: String,
    profiles_root: PathBuf,
    command_timeout: Duration,
    max_resident: usize,
}

impl WorkerIpcConfig {
    pub fn new(
        pipe_name: impl Into<String>,
        profiles_root: impl Into<PathBuf>,
        command_timeout: Duration,
        max_resident: usize,
    ) -> Result<Self, ConfigError> {
        let pipe_name = pipe_name.into();
        validate_pipe_suffix(&pipe_name)?;
        let profiles_root = profiles_root.into();
        if !profiles_root.is_absolute() {
            return Err(ConfigError::ProfilesRootNotAbsolute);
        }
        if command_timeout < Duration::from_millis(100)
            || command_timeout > Duration::from_secs(15 * 60)
        {
            return Err(ConfigError::InvalidTimeout);
        }
        if max_resident == 0 || max_resident > 64 {
            return Err(ConfigError::InvalidResidentLimit);
        }
        Ok(Self {
            pipe_name,
            profiles_root,
            command_timeout,
            max_resident,
        })
    }

    pub fn full_pipe_name(&self) -> String {
        format!(r"\\.\pipe\{}", self.pipe_name)
    }

    pub fn profiles_root(&self) -> &Path {
        &self.profiles_root
    }
}

pub fn validate_pipe_suffix(value: &str) -> Result<(), ConfigError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ConfigError::InvalidPipeName);
    }
    Ok(())
}

pub async fn run_worker_server(config: WorkerIpcConfig) -> Result<(), ServerError> {
    std::fs::create_dir_all(config.profiles_root())?;
    run_platform_server(config).await
}

#[cfg(windows)]
async fn run_platform_server(config: WorkerIpcConfig) -> Result<(), ServerError> {
    use tokio::net::windows::named_pipe::ServerOptions;

    let pipe_name = config.full_pipe_name();
    let mut pipe = ServerOptions::new()
        .first_pipe_instance(true)
        .reject_remote_clients(true)
        .create(&pipe_name)?;
    pipe.connect().await?;

    let mut registry = WorkerRegistry::new(
        config.profiles_root,
        config.command_timeout,
        config.max_resident,
    );
    let result = serve_connection(&mut pipe, &mut registry).await;
    registry.shutdown_all().await;
    result
}

#[cfg(not(windows))]
async fn run_platform_server(_config: WorkerIpcConfig) -> Result<(), ServerError> {
    Err(ServerError::UnsupportedPlatform)
}

async fn serve_connection<S>(stream: &mut S, registry: &mut WorkerRegistry) -> Result<(), ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let request = match read_request(stream).await {
            Ok(Some(request)) => request,
            Ok(None) => break,
            Err(ReadRequestError::Io(error)) => return Err(ServerError::Io(error)),
            Err(error) => {
                let response = protocol_failure_response(error.request_id(), error.kind());
                write_response(stream, &response).await?;
                break;
            }
        };

        if validate_request_fields(&request).is_err() {
            let response = WorkerResponse::failure(
                &request,
                ResponseStatus::Invalid,
                "invalid request",
            );
            write_response(stream, &response).await?;
            continue;
        }

        let should_shutdown = request.kind == RequestKind::Shutdown;
        let response = match request.kind {
            RequestKind::Capture => registry.capture(&request).await,
            RequestKind::Health => WorkerResponse::empty(&request, ResponseStatus::Ok),
            RequestKind::Shutdown => WorkerResponse::empty(&request, ResponseStatus::Ok),
        };
        write_response(stream, &response).await?;
        if should_shutdown {
            break;
        }
    }
    Ok(())
}

struct WorkerEntry {
    worker: BrowserWorker,
    last_used: u64,
}

struct WorkerRegistry {
    profiles_root: PathBuf,
    command_timeout: Duration,
    max_resident: usize,
    clock: u64,
    workers: HashMap<String, WorkerEntry>,
}

impl WorkerRegistry {
    fn new(profiles_root: PathBuf, command_timeout: Duration, max_resident: usize) -> Self {
        Self {
            profiles_root,
            command_timeout,
            max_resident,
            clock: 0,
            workers: HashMap::new(),
        }
    }

    async fn capture(&mut self, request: &WorkerRequest) -> WorkerResponse {
        let started = Instant::now();
        if validate_capture_request(request).is_err() {
            return WorkerResponse::failure(request, ResponseStatus::Invalid, "invalid request");
        }

        let worker = match self.worker(&request.profile_id).await {
            Ok(worker) => worker,
            Err(()) => {
                return WorkerResponse::failure(
                    request,
                    ResponseStatus::Unavailable,
                    "browser unavailable",
                )
            }
        };

        if worker
            .execute(AgentCommand::Navigate {
                url: request.url.clone(),
            })
            .await
            .is_err()
        {
            self.remove_worker(&request.profile_id).await;
            let mut response = WorkerResponse::failure(
                request,
                ResponseStatus::CaptureFailed,
                "navigation failed",
            );
            response.duration_ms = elapsed_ms(started);
            return response;
        }

        let artifact = match worker
            .execute(AgentCommand::Capture {
                policy: CapturePolicy::EvidenceViewport,
            })
            .await
        {
            Ok(AgentReply::Capture(artifact)) => artifact,
            _ => {
                self.remove_worker(&request.profile_id).await;
                let mut response = WorkerResponse::failure(
                    request,
                    ResponseStatus::CaptureFailed,
                    "capture failed",
                );
                response.duration_ms = elapsed_ms(started);
                return response;
            }
        };

        let (state, html, png) = match artifact {
            CaptureArtifact::EvidenceViewport { state, html, png } => {
                (state, html.into_bytes(), png)
            }
            _ => {
                return WorkerResponse::failure(
                    request,
                    ResponseStatus::CaptureFailed,
                    "capture policy failed",
                )
            }
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
            html,
            png,
        };
        if validate_response(&response).is_err() {
            let mut failure = WorkerResponse::failure(
                request,
                ResponseStatus::TooLarge,
                "capture exceeds response limit",
            );
            failure.duration_ms = response.duration_ms;
            return failure;
        }
        response
    }

    async fn worker(&mut self, profile_id: &str) -> Result<BrowserWorker, ()> {
        self.clock = self.clock.saturating_add(1);
        if let Some(worker) = self.workers.get(profile_id).map(|entry| entry.worker.clone()) {
            let ready = match worker.snapshot().lifecycle {
                WorkerLifecycle::Ready => true,
                WorkerLifecycle::Degraded => worker
                    .execute(AgentCommand::Restart)
                    .await
                    .is_ok(),
                _ => worker
                    .wait_until_settled()
                    .await
                    .is_ok_and(|snapshot| snapshot.lifecycle == WorkerLifecycle::Ready),
            };
            if ready {
                if let Some(entry) = self.workers.get_mut(profile_id) {
                    entry.last_used = self.clock;
                }
                return Ok(worker);
            }
            self.remove_worker(profile_id).await;
        }

        if self.workers.len() >= self.max_resident {
            if let Some(evicted_id) = self
                .workers
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(id, _)| id.clone())
            {
                if let Some(entry) = self.workers.remove(&evicted_id) {
                    let _ = entry.worker.shutdown().await;
                }
            }
        }

        let identity = IdentityProfile::new(
            &self.profiles_root,
            profile_id,
            IdentityClass::Public,
            BrowserBackend::Chromium,
            DevicePersona::DesktopNative,
        )
        .map_err(|_| ())?;
        let config = BrowserWorkerConfig {
            command_timeout: self.command_timeout,
            ..BrowserWorkerConfig::default()
        };
        let worker = BrowserWorker::spawn(identity, CapabilitySet::monitoring(), config)
            .map_err(|_| ())?;
        let snapshot = worker.wait_until_settled().await.map_err(|_| ())?;
        if snapshot.lifecycle != WorkerLifecycle::Ready {
            let _ = worker.shutdown().await;
            return Err(());
        }
        self.workers.insert(
            profile_id.to_owned(),
            WorkerEntry {
                worker: worker.clone(),
                last_used: self.clock,
            },
        );
        Ok(worker)
    }

    async fn shutdown_all(&mut self) {
        let workers: Vec<_> = self.workers.drain().map(|(_, entry)| entry.worker).collect();
        for worker in workers {
            let _ = worker.shutdown().await;
        }
    }

    async fn remove_worker(&mut self, profile_id: &str) {
        if let Some(entry) = self.workers.remove(profile_id) {
            let _ = entry.worker.shutdown().await;
        }
    }
}

async fn write_response<W>(stream: &mut W, response: &WorkerResponse) -> Result<(), ServerError>
where
    W: AsyncWrite + Unpin,
{
    let header = response_header(response)?;
    stream.write_all(&header).await?;
    stream.write_all(response.final_url.as_bytes()).await?;
    stream.write_all(response.title.as_bytes()).await?;
    stream.write_all(response.error.as_bytes()).await?;
    stream.write_all(&response.html).await?;
    stream.write_all(&response.png).await?;
    stream.flush().await?;
    Ok(())
}

fn response_header(response: &WorkerResponse) -> Result<[u8; RESPONSE_HEADER_BYTES], ProtocolError> {
    validate_response(response)?;
    let mut header = [0u8; RESPONSE_HEADER_BYTES];
    header[0..4].copy_from_slice(&RESPONSE_MAGIC);
    header[4..6].copy_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    header[6] = response.status as u8;
    header[7] = response.kind as u8;
    header[8..16].copy_from_slice(&response.request_id.to_le_bytes());
    header[16..18].copy_from_slice(&response.http_status.unwrap_or(0).to_le_bytes());
    header[18..20].copy_from_slice(&0u16.to_le_bytes());
    header[20..28].copy_from_slice(&response.duration_ms.to_le_bytes());
    header[28..32].copy_from_slice(&(response.final_url.len() as u32).to_le_bytes());
    header[32..36].copy_from_slice(&(response.title.len() as u32).to_le_bytes());
    header[36..40].copy_from_slice(&(response.error.len() as u32).to_le_bytes());
    header[40..48].copy_from_slice(&(response.html.len() as u64).to_le_bytes());
    header[48..56].copy_from_slice(&(response.png.len() as u64).to_le_bytes());
    Ok(header)
}

async fn read_request<R>(stream: &mut R) -> Result<Option<WorkerRequest>, ReadRequestError>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; REQUEST_HEADER_BYTES];
    let first = stream
        .read(&mut header[..4])
        .await
        .map_err(ReadRequestError::Io)?;
    if first == 0 {
        return Ok(None);
    }
    stream
        .read_exact(&mut header[first..])
        .await
        .map_err(ReadRequestError::Io)?;

    let request_id = u64::from_le_bytes(header[8..16].try_into().unwrap());
    let kind_byte = header[6];
    let kind = RequestKind::from_wire(kind_byte)
        .map_err(|_| ReadRequestError::Protocol { request_id, kind_byte })?;
    if header[..4] != REQUEST_MAGIC
        || u16::from_le_bytes(header[4..6].try_into().unwrap()) != PROTOCOL_VERSION
        || header[7] != 0
    {
        return Err(ReadRequestError::Protocol { request_id, kind_byte });
    }

    let profile_len = u16::from_le_bytes(header[16..18].try_into().unwrap()) as usize;
    let url_len = u32::from_le_bytes(header[18..22].try_into().unwrap()) as usize;
    let total = REQUEST_HEADER_BYTES
        .checked_add(profile_len)
        .and_then(|value| value.checked_add(url_len))
        .ok_or(ReadRequestError::Protocol { request_id, kind_byte })?;
    if total > MAX_REQUEST_BYTES {
        return Err(ReadRequestError::Protocol { request_id, kind_byte });
    }
    let mut payload = vec![0u8; profile_len + url_len];
    stream
        .read_exact(&mut payload)
        .await
        .map_err(ReadRequestError::Io)?;
    let profile_id = std::str::from_utf8(&payload[..profile_len])
        .map_err(|_| ReadRequestError::Protocol { request_id, kind_byte })?
        .to_owned();
    let url = std::str::from_utf8(&payload[profile_len..])
        .map_err(|_| ReadRequestError::Protocol { request_id, kind_byte })?
        .to_owned();
    Ok(Some(WorkerRequest {
        kind,
        request_id,
        profile_id,
        url,
    }))
}

fn validate_capture_request(request: &WorkerRequest) -> Result<(), ProtocolError> {
    if request.kind != RequestKind::Capture || validate_profile_id(&request.profile_id).is_err() {
        return Err(ProtocolError::InvalidRequest);
    }
    let url = url::Url::parse(&request.url).map_err(|_| ProtocolError::InvalidRequest)?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(ProtocolError::InvalidRequest);
    }
    Ok(())
}

fn validate_request_fields(request: &WorkerRequest) -> Result<(), ProtocolError> {
    match request.kind {
        RequestKind::Capture => validate_capture_request(request),
        RequestKind::Health | RequestKind::Shutdown => {
            if request.profile_id.is_empty() && request.url.is_empty() {
                Ok(())
            } else {
                Err(ProtocolError::InvalidRequest)
            }
        }
    }
}

fn validate_response(response: &WorkerResponse) -> Result<(), ProtocolError> {
    if response.final_url.len() > MAX_FINAL_URL_BYTES
        || response.title.len() > MAX_TITLE_BYTES
        || response.error.len() > MAX_ERROR_BYTES
        || response.html.len() > MAX_HTML_BYTES
        || response.png.len() > MAX_PNG_BYTES
    {
        return Err(ProtocolError::ResponseTooLarge);
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

fn protocol_failure_response(request_id: u64, kind: RequestKind) -> WorkerResponse {
    WorkerResponse {
        status: ResponseStatus::Protocol,
        kind,
        request_id,
        http_status: None,
        duration_ms: 0,
        final_url: String::new(),
        title: String::new(),
        error: "protocol error".to_owned(),
        html: Vec::new(),
        png: Vec::new(),
    }
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigError {
    InvalidPipeName,
    ProfilesRootNotAbsolute,
    InvalidTimeout,
    InvalidResidentLimit,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPipeName => write!(formatter, "pipe name is invalid"),
            Self::ProfilesRootNotAbsolute => write!(formatter, "profiles root must be absolute"),
            Self::InvalidTimeout => write!(formatter, "timeout is invalid"),
            Self::InvalidResidentLimit => write!(formatter, "resident worker limit is invalid"),
        }
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug)]
pub enum ServerError {
    Io(io::Error),
    Protocol(ProtocolError),
    UnsupportedPlatform,
}

impl std::fmt::Display for ServerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "worker I/O failure: {error}"),
            Self::Protocol(error) => write!(formatter, "worker protocol failure: {error}"),
            Self::UnsupportedPlatform => write!(formatter, "worker IPC requires Windows"),
        }
    }
}

impl std::error::Error for ServerError {}

impl From<io::Error> for ServerError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<ProtocolError> for ServerError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    InvalidRequest,
    ResponseTooLarge,
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRequest => write!(formatter, "invalid request"),
            Self::ResponseTooLarge => write!(formatter, "response exceeds protocol limits"),
        }
    }
}

impl std::error::Error for ProtocolError {}

#[derive(Debug)]
enum ReadRequestError {
    Io(io::Error),
    Protocol { request_id: u64, kind_byte: u8 },
}

impl ReadRequestError {
    fn request_id(&self) -> u64 {
        match self {
            Self::Io(_) => 0,
            Self::Protocol { request_id, .. } => *request_id,
        }
    }

    fn kind(&self) -> RequestKind {
        match self {
            Self::Protocol { kind_byte, .. } => {
                RequestKind::from_wire(*kind_byte).unwrap_or(RequestKind::Health)
            }
            Self::Io(_) => RequestKind::Health,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_bytes(kind: RequestKind, id: u64, profile: &str, url: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&REQUEST_MAGIC);
        bytes.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        bytes.push(kind as u8);
        bytes.push(0);
        bytes.extend_from_slice(&id.to_le_bytes());
        bytes.extend_from_slice(&(profile.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&(url.len() as u32).to_le_bytes());
        bytes.extend_from_slice(profile.as_bytes());
        bytes.extend_from_slice(url.as_bytes());
        bytes
    }

    #[tokio::test]
    async fn request_codec_matches_fixed_wire_layout() {
        let bytes = request_bytes(
            RequestKind::Capture,
            42,
            "review.example",
            "https://example.test/path",
        );
        let mut reader = &bytes[..];
        let request = read_request(&mut reader).await.unwrap().unwrap();
        assert_eq!(request.kind, RequestKind::Capture);
        assert_eq!(request.request_id, 42);
        assert_eq!(request.profile_id, "review.example");
        assert_eq!(request.url, "https://example.test/path");
        assert_eq!(bytes.len(), REQUEST_HEADER_BYTES + 14 + 25);
    }

    #[test]
    fn response_codec_matches_fixed_wire_layout() {
        let response = WorkerResponse {
            status: ResponseStatus::Ok,
            kind: RequestKind::Capture,
            request_id: 7,
            http_status: Some(200),
            duration_ms: 123,
            final_url: "https://example.test/".into(),
            title: "Example".into(),
            error: String::new(),
            html: b"<html></html>".to_vec(),
            png: vec![0x89, b'P', b'N', b'G'],
        };
        let bytes = response.encode().unwrap();
        assert_eq!(&bytes[..4], b"D2BR");
        assert_eq!(u16::from_le_bytes(bytes[4..6].try_into().unwrap()), 1);
        assert_eq!(bytes[6], 0);
        assert_eq!(bytes[7], 1);
        assert_eq!(u64::from_le_bytes(bytes[8..16].try_into().unwrap()), 7);
        assert_eq!(u16::from_le_bytes(bytes[16..18].try_into().unwrap()), 200);
        assert_eq!(u16::from_le_bytes(bytes[18..20].try_into().unwrap()), 0);
        assert_eq!(u64::from_le_bytes(bytes[20..28].try_into().unwrap()), 123);
        assert_eq!(bytes.len(), RESPONSE_HEADER_BYTES + 21 + 7 + 13 + 4);
    }

    #[tokio::test]
    async fn request_codec_rejects_oversized_and_non_utf8_payloads() {
        let mut oversized = request_bytes(RequestKind::Capture, 1, "p", "https://example.test");
        oversized[18..22].copy_from_slice(&(MAX_REQUEST_BYTES as u32).to_le_bytes());
        let mut oversized_reader = &oversized[..];
        assert!(read_request(&mut oversized_reader).await.is_err());

        let mut invalid = request_bytes(RequestKind::Capture, 2, "p", "https://example.test");
        invalid[REQUEST_HEADER_BYTES] = 0xff;
        let mut invalid_reader = &invalid[..];
        assert!(read_request(&mut invalid_reader).await.is_err());
    }

    #[test]
    fn config_accepts_only_safe_pipe_suffix_and_absolute_root() {
        assert!(WorkerIpcConfig::new(
            "dig2browser.public-v1",
            std::env::temp_dir(),
            Duration::from_secs(90),
            4,
        )
        .is_ok());
        assert!(WorkerIpcConfig::new(
            r"\\.\pipe\raw",
            std::env::temp_dir(),
            Duration::from_secs(90),
            4,
        )
        .is_err());
    }

    #[test]
    fn capture_validation_rejects_non_http_and_unsafe_profile() {
        let mut request = WorkerRequest {
            kind: RequestKind::Capture,
            request_id: 1,
            profile_id: "../escape".into(),
            url: "https://example.test".into(),
        };
        assert!(validate_capture_request(&request).is_err());
        request.profile_id = "public".into();
        request.url = "file:///secret".into();
        assert!(validate_capture_request(&request).is_err());
    }

    #[test]
    fn control_requests_require_empty_payloads() {
        let mut request = WorkerRequest {
            kind: RequestKind::Health,
            request_id: 1,
            profile_id: String::new(),
            url: String::new(),
        };
        assert!(validate_request_fields(&request).is_ok());
        request.profile_id = "unexpected".into();
        assert!(validate_request_fields(&request).is_err());
        request.kind = RequestKind::Shutdown;
        assert!(validate_request_fields(&request).is_err());
    }
}
