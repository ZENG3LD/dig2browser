//! Lightweight D2BQ/D2BR v1 wire contract shared by station servers and clients.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

mod task;

pub use task::{
    CaptureCompleteness, CollectionTask, CollectionTaskResult, EvidenceCapture,
    TaskCapturePolicy, TaskReply, TaskStep, MAX_TASK_RESULT_BYTES, MAX_TASK_STEPS,
    MAX_TASK_WAIT,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RequestKind {
    Capture = 1,
    Health = 2,
    Shutdown = 3,
    Status = 4,
    Task = 5,
}

impl RequestKind {
    fn from_wire(value: u8) -> Result<Self, ProtocolError> {
        match value {
            1 => Ok(Self::Capture),
            2 => Ok(Self::Health),
            3 => Ok(Self::Shutdown),
            4 => Ok(Self::Status),
            5 => Ok(Self::Task),
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
}

impl WorkerRequest {
    pub fn capture(request_id: u64, profile_id: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            kind: RequestKind::Capture,
            request_id,
            profile_id: profile_id.into(),
            url: url.into(),
            task: None,
        }
    }

    pub fn task(
        request_id: u64,
        profile_id: impl Into<String>,
        task: CollectionTask,
    ) -> Self {
        Self {
            kind: RequestKind::Task,
            request_id,
            profile_id: profile_id.into(),
            url: String::new(),
            task: Some(task),
        }
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
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        let profile_len = u16::try_from(self.profile_id.len())
            .map_err(|_| ProtocolError::InvalidRequest)?;
        let task_payload = match &self.task {
            Some(task) => task.encode_payload()?,
            None => Vec::new(),
        };
        let body = if self.kind == RequestKind::Task {
            task_payload.as_slice()
        } else {
            self.url.as_bytes()
        };
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
        match self.kind {
            RequestKind::Capture => {
                validate_profile_id(&self.profile_id)?;
                validate_http_url(&self.url)?;
                if self.task.is_none() {
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
                    .validate()
            }
            RequestKind::Health | RequestKind::Shutdown | RequestKind::Status => {
                if self.profile_id.is_empty() && self.url.is_empty() && self.task.is_none() {
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

    pub fn task_result(
        request: &WorkerRequest,
        result: &CollectionTaskResult,
    ) -> Result<Self, ProtocolError> {
        let mut response = Self::empty(request, ResponseStatus::Ok);
        response.html = result.encode()?;
        response.validate()?;
        Ok(response)
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
    let (url, task) = if kind == RequestKind::Task {
        (
            String::new(),
            Some(CollectionTask::decode_payload(body)?),
        )
    } else {
        (
            std::str::from_utf8(body)
                .map_err(|_| FrameError::Protocol(ProtocolError::InvalidRequest))?
                .to_owned(),
            None,
        )
    };
    let request = WorkerRequest {
        kind,
        request_id,
        profile_id,
        url,
        task,
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
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRequest => write!(formatter, "invalid request"),
            Self::ResponseTooLarge => write!(formatter, "response exceeds protocol limits"),
            Self::InvalidStatusPayload => write!(formatter, "station status payload is invalid"),
            Self::InvalidTaskPayload => write!(formatter, "browser task payload is invalid"),
            Self::InvalidTaskResult => write!(formatter, "browser task result is invalid"),
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

    #[tokio::test]
    async fn request_and_response_round_trip_fixed_v1_layout() {
        let request = WorkerRequest::capture(42, "review.example", "https://example.test/path");
        let request_bytes = request.encode().expect("request");
        assert_eq!(&request_bytes[..4], b"D2BQ");
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
}
