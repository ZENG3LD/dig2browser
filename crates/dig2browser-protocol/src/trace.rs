use crate::task::{decode_runtime_record, encode_runtime_record};
use crate::{
    BrowserPersona, CollectionTask, FailureClass, ProfileClass, ProtocolError,
    ResolvedRuntimeRecord, MAX_FINAL_URL_BYTES, MAX_HTML_BYTES, MAX_PNG_BYTES,
    MAX_REQUEST_BYTES, MAX_TITLE_BYTES, MAX_COLLECTOR_VERSION_BYTES,
    MAX_SELECTOR_BYTES, PROTOCOL_VERSION,
};
use crate::shape::{OutputSchema, RowPage, ShapeCursor, MAX_ROWS_PER_PAGE};

pub const MAX_TRACE_EVENTS: usize = 64;
pub const MAX_TRACE_STEP_SUMMARIES: usize = 64;
pub const MAX_ARTIFACT_CHUNK_BYTES: usize = 256 * 1024;

const COLLECTION_REQUEST_MAGIC: [u8; 4] = *b"D2CQ";
const COLLECTION_RESPONSE_MAGIC: [u8; 4] = *b"D2CP";
const TRACE_EVENT_MAGIC: [u8; 4] = *b"D2CE";
const COLLECTION_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CollectionId([u8; 16]);

impl CollectionId {
    pub fn new(bytes: [u8; 16]) -> Result<Self, ProtocolError> {
        if bytes == [0; 16] {
            return Err(ProtocolError::InvalidCollectionPayload);
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn into_bytes(self) -> [u8; 16] {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TraceCursor(u32);

impl TraceCursor {
    pub const START: Self = Self(0);

    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    pub const fn value(self) -> u32 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactRole {
    Html,
    ViewportPng,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactMediaType {
    TextHtmlUtf8,
    ImagePng,
    /// Opaque bytes (`application/octet-stream`) — the media type for a durable
    /// monitor's captured WebSocket/SSE frame payload, whose text-vs-binary
    /// semantics are carried out-of-band by the frame's opcode in the monitor
    /// journal record, not by this media type. Never produced by the
    /// finite-task collection/crawl path.
    ApplicationOctetStream,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactRef {
    sha256: [u8; 32],
    len: u64,
    media_type: ArtifactMediaType,
}

impl ArtifactRef {
    pub fn new(
        sha256: [u8; 32],
        len: u64,
        media_type: ArtifactMediaType,
    ) -> Result<Self, ProtocolError> {
        if sha256 == [0; 32] || len == 0 {
            return Err(ProtocolError::InvalidCollectionPayload);
        }
        Ok(Self {
            sha256,
            len,
            media_type,
        })
    }

    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn media_type(&self) -> ArtifactMediaType {
        self.media_type
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartedTrace {
    task_sha256: [u8; 32],
    step_count: u8,
    runtime: ResolvedRuntimeRecord,
}

impl StartedTrace {
    pub fn new(
        task_sha256: [u8; 32],
        step_count: u8,
        runtime: ResolvedRuntimeRecord,
    ) -> Result<Self, ProtocolError> {
        if task_sha256 == [0; 32]
            || step_count == 0
            || usize::from(step_count) > MAX_TRACE_STEP_SUMMARIES
        {
            return Err(ProtocolError::InvalidCollectionPayload);
        }
        encode_runtime_record(&runtime)
            .map_err(|_| ProtocolError::InvalidCollectionPayload)?;
        Ok(Self {
            task_sha256,
            step_count,
            runtime,
        })
    }

    pub fn task_sha256(&self) -> &[u8; 32] {
        &self.task_sha256
    }

    pub fn step_count(&self) -> u8 {
        self.step_count
    }

    pub fn runtime(&self) -> &ResolvedRuntimeRecord {
        &self.runtime
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactCommitted {
    step_index: u8,
    role: ArtifactRole,
    artifact: ArtifactRef,
}

impl ArtifactCommitted {
    pub fn new(
        step_index: u8,
        role: ArtifactRole,
        artifact: ArtifactRef,
    ) -> Result<Self, ProtocolError> {
        if usize::from(step_index) >= MAX_TRACE_STEP_SUMMARIES
            || !role_matches_media_type(role, artifact.media_type())
        {
            return Err(ProtocolError::InvalidCollectionPayload);
        }
        Ok(Self {
            step_index,
            role,
            artifact,
        })
    }

    pub fn step_index(&self) -> u8 {
        self.step_index
    }

    pub fn role(&self) -> ArtifactRole {
        self.role
    }

    pub fn artifact(&self) -> &ArtifactRef {
        &self.artifact
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepOutcome {
    Succeeded,
    Failed(FailureClass),
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StepSummary {
    step_index: u8,
    completed_at_unix_ms: u64,
    duration_ms: u64,
    outcome: StepOutcome,
}

impl StepSummary {
    pub fn new(
        step_index: u8,
        completed_at_unix_ms: u64,
        duration_ms: u64,
        outcome: StepOutcome,
    ) -> Result<Self, ProtocolError> {
        if usize::from(step_index) >= MAX_TRACE_STEP_SUMMARIES
            || !valid_step_outcome(outcome)
        {
            return Err(ProtocolError::InvalidCollectionPayload);
        }
        Ok(Self {
            step_index,
            completed_at_unix_ms,
            duration_ms,
            outcome,
        })
    }

    pub fn step_index(&self) -> u8 {
        self.step_index
    }

    pub fn completed_at_unix_ms(&self) -> u64 {
        self.completed_at_unix_ms
    }

    pub fn duration_ms(&self) -> u64 {
        self.duration_ms
    }

    pub fn outcome(&self) -> StepOutcome {
        self.outcome
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalOutcome {
    Succeeded,
    Failed(FailureClass),
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalTrace {
    outcome: TerminalOutcome,
    steps: Vec<StepSummary>,
}

impl TerminalTrace {
    pub fn new(
        outcome: TerminalOutcome,
        steps: Vec<StepSummary>,
    ) -> Result<Self, ProtocolError> {
        if !valid_terminal_outcome(outcome)
            || steps.len() > MAX_TRACE_STEP_SUMMARIES
            || !strictly_increasing_steps(&steps)
        {
            return Err(ProtocolError::InvalidCollectionPayload);
        }
        Ok(Self { outcome, steps })
    }

    pub fn outcome(&self) -> TerminalOutcome {
        self.outcome
    }

    pub fn steps(&self) -> &[StepSummary] {
        &self.steps
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptedReason {
    SuccessorReconciliation,
    ShutdownTimeout,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceEventKind {
    Started(StartedTrace),
    ArtifactCommitted(ArtifactCommitted),
    Terminal(TerminalTrace),
    Interrupted(InterruptedReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceEvent {
    cursor: TraceCursor,
    timestamp_unix_ms: u64,
    kind: TraceEventKind,
}

impl TraceEvent {
    pub fn new(
        cursor: TraceCursor,
        timestamp_unix_ms: u64,
        kind: TraceEventKind,
    ) -> Result<Self, ProtocolError> {
        if cursor == TraceCursor::START {
            return Err(ProtocolError::InvalidCollectionPayload);
        }
        validate_event_kind(&kind)?;
        Ok(Self {
            cursor,
            timestamp_unix_ms,
            kind,
        })
    }

    pub fn cursor(&self) -> TraceCursor {
        self.cursor
    }

    pub fn timestamp_unix_ms(&self) -> u64 {
        self.timestamp_unix_ms
    }

    pub fn kind(&self) -> &TraceEventKind {
        &self.kind
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut output = Vec::new();
        output.extend_from_slice(&TRACE_EVENT_MAGIC);
        output.extend_from_slice(&COLLECTION_SCHEMA_VERSION.to_le_bytes());
        encode_trace_event(&mut output, self)?;
        Ok(output)
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        let mut input = Input::new(payload);
        if input.bytes(4)? != TRACE_EVENT_MAGIC
            || input.u16()? != COLLECTION_SCHEMA_VERSION
        {
            return Err(ProtocolError::InvalidCollectionPayload);
        }
        let event = decode_trace_event(&mut input)?;
        if !input.is_empty() {
            return Err(ProtocolError::InvalidCollectionPayload);
        }
        Ok(event)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum CollectionRequest {
    Begin {
        collection_id: CollectionId,
        profile_class: ProfileClass,
        persona: BrowserPersona,
        task: CollectionTask,
    },
    ReadTrace {
        collection_id: CollectionId,
        cursor: TraceCursor,
        limit: u8,
    },
    ReadArtifact {
        collection_id: CollectionId,
        sha256: [u8; 32],
        offset: u64,
        max_bytes: u32,
    },
    ReadReceipt {
        collection_id: CollectionId,
    },
    /// Declarative output shaping (Phase C, axis 7) over a collection's
    /// captured HTML: project it onto `schema` and page the resulting rows.
    ReadShaped {
        collection_id: CollectionId,
        schema: OutputSchema,
        cursor: ShapeCursor,
        limit: u16,
    },
    Cancel {
        collection_id: CollectionId,
    },
}

impl CollectionRequest {
    pub fn begin(
        collection_id: CollectionId,
        profile_class: ProfileClass,
        persona: BrowserPersona,
        task: CollectionTask,
    ) -> Result<Self, ProtocolError> {
        let request = Self::Begin {
            collection_id,
            profile_class,
            persona,
            task,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn read_trace(
        collection_id: CollectionId,
        cursor: TraceCursor,
        limit: u8,
    ) -> Result<Self, ProtocolError> {
        let request = Self::ReadTrace {
            collection_id,
            cursor,
            limit,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn read_artifact(
        collection_id: CollectionId,
        sha256: [u8; 32],
        offset: u64,
        max_bytes: u32,
    ) -> Result<Self, ProtocolError> {
        let request = Self::ReadArtifact {
            collection_id,
            sha256,
            offset,
            max_bytes,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn cancel(collection_id: CollectionId) -> Result<Self, ProtocolError> {
        let request = Self::Cancel { collection_id };
        request.validate()?;
        Ok(request)
    }

    pub fn read_receipt(collection_id: CollectionId) -> Result<Self, ProtocolError> {
        let request = Self::ReadReceipt { collection_id };
        request.validate()?;
        Ok(request)
    }

    pub fn read_shaped(
        collection_id: CollectionId,
        schema: OutputSchema,
        cursor: ShapeCursor,
        limit: u16,
    ) -> Result<Self, ProtocolError> {
        let request = Self::ReadShaped {
            collection_id,
            schema,
            cursor,
            limit,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn is_begin(&self) -> bool {
        matches!(self, Self::Begin { .. })
    }

    pub fn collection_id(&self) -> CollectionId {
        match self {
            Self::Begin { collection_id, .. }
            | Self::ReadTrace { collection_id, .. }
            | Self::ReadArtifact { collection_id, .. }
            | Self::ReadReceipt { collection_id }
            | Self::ReadShaped { collection_id, .. }
            | Self::Cancel { collection_id } => *collection_id,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        let mut output = Vec::new();
        output.extend_from_slice(&COLLECTION_REQUEST_MAGIC);
        output.extend_from_slice(&COLLECTION_SCHEMA_VERSION.to_le_bytes());
        match self {
            Self::Begin {
                collection_id,
                profile_class,
                persona,
                task,
            } => {
                output.push(1);
                output.push(0);
                output.extend_from_slice(collection_id.as_bytes());
                output.extend_from_slice(&crate::encode_task_identity_payload(
                    *profile_class,
                    persona,
                    task,
                )?);
            }
            Self::ReadTrace {
                collection_id,
                cursor,
                limit,
            } => {
                output.push(2);
                output.push(0);
                output.extend_from_slice(collection_id.as_bytes());
                output.extend_from_slice(&cursor.value().to_le_bytes());
                output.push(*limit);
            }
            Self::ReadArtifact {
                collection_id,
                sha256,
                offset,
                max_bytes,
            } => {
                output.push(3);
                output.push(0);
                output.extend_from_slice(collection_id.as_bytes());
                output.extend_from_slice(sha256);
                output.extend_from_slice(&offset.to_le_bytes());
                output.extend_from_slice(&max_bytes.to_le_bytes());
            }
            Self::Cancel { collection_id } => {
                output.push(4);
                output.push(0);
                output.extend_from_slice(collection_id.as_bytes());
            }
            Self::ReadReceipt { collection_id } => {
                output.push(5);
                output.push(0);
                output.extend_from_slice(collection_id.as_bytes());
            }
            Self::ReadShaped {
                collection_id,
                schema,
                cursor,
                limit,
            } => {
                output.push(6);
                output.push(0);
                output.extend_from_slice(collection_id.as_bytes());
                let schema_bytes = schema.encode()?;
                let schema_len = u32::try_from(schema_bytes.len())
                    .map_err(|_| ProtocolError::InvalidCollectionPayload)?;
                output.extend_from_slice(&schema_len.to_le_bytes());
                output.extend_from_slice(&schema_bytes);
                output.extend_from_slice(&cursor.value().to_le_bytes());
                output.extend_from_slice(&limit.to_le_bytes());
            }
        }
        if output.len() > MAX_REQUEST_BYTES {
            return Err(ProtocolError::InvalidCollectionPayload);
        }
        Ok(output)
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.len() > MAX_REQUEST_BYTES {
            return Err(ProtocolError::InvalidCollectionPayload);
        }
        let mut input = Input::new(payload);
        if input.bytes(4)? != COLLECTION_REQUEST_MAGIC
            || input.u16()? != COLLECTION_SCHEMA_VERSION
        {
            return Err(ProtocolError::InvalidCollectionPayload);
        }
        let operation = input.u8()?;
        if input.u8()? != 0 {
            return Err(ProtocolError::InvalidCollectionPayload);
        }
        let request = match operation {
            1 => {
                let collection_id = input.collection_id()?;
                let (profile_class, persona, task) =
                    crate::decode_task_identity_payload(input.remaining())
                        .map_err(|_| ProtocolError::InvalidCollectionPayload)?;
                input.consume_remaining();
                Self::begin(collection_id, profile_class, persona, task)?
            }
            2 => Self::read_trace(
                input.collection_id()?,
                TraceCursor::new(input.u32()?),
                input.u8()?,
            )?,
            3 => Self::read_artifact(
                input.collection_id()?,
                input.array_32()?,
                input.u64()?,
                input.u32()?,
            )?,
            4 => Self::cancel(input.collection_id()?)?,
            5 => Self::read_receipt(input.collection_id()?)?,
            6 => {
                let collection_id = input.collection_id()?;
                let schema_len = usize::try_from(input.u32()?)
                    .map_err(|_| ProtocolError::InvalidCollectionPayload)?;
                let schema = OutputSchema::decode(input.bytes(schema_len)?)?;
                let cursor = ShapeCursor::new(input.u64()?);
                let limit = input.u16()?;
                Self::read_shaped(collection_id, schema, cursor, limit)?
            }
            _ => return Err(ProtocolError::InvalidCollectionPayload),
        };
        if !input.is_empty() {
            return Err(ProtocolError::InvalidCollectionPayload);
        }
        Ok(request)
    }

    pub(crate) fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Begin {
                collection_id,
                persona,
                task,
                ..
            } => {
                CollectionId::new(*collection_id.as_bytes())?;
                persona
                    .validate()
                    .map_err(|_| ProtocolError::InvalidCollectionPayload)?;
                task.validate()
                    .map_err(|_| ProtocolError::InvalidCollectionPayload)
            }
            Self::ReadTrace {
                collection_id,
                limit,
                ..
            } => {
                CollectionId::new(*collection_id.as_bytes())?;
                if *limit == 0 || usize::from(*limit) > MAX_TRACE_EVENTS {
                    return Err(ProtocolError::InvalidCollectionPayload);
                }
                Ok(())
            }
            Self::Cancel { collection_id } | Self::ReadReceipt { collection_id } => {
                CollectionId::new(*collection_id.as_bytes()).map(|_| ())
            }
            Self::ReadArtifact {
                collection_id,
                sha256,
                max_bytes,
                ..
            } => {
                CollectionId::new(*collection_id.as_bytes())?;
                if *sha256 == [0; 32]
                    || *max_bytes == 0
                    || u64::from(*max_bytes)
                        > MAX_ARTIFACT_CHUNK_BYTES as u64
                {
                    return Err(ProtocolError::InvalidCollectionPayload);
                }
                Ok(())
            }
            Self::ReadShaped {
                collection_id,
                schema,
                limit,
                ..
            } => {
                CollectionId::new(*collection_id.as_bytes())?;
                schema.validate()?;
                if *limit == 0 || usize::from(*limit) > MAX_ROWS_PER_PAGE {
                    return Err(ProtocolError::InvalidCollectionPayload);
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionReceiptMetadata {
    pub completed_at_unix_ms: u64,
    pub final_url: String,
    pub http_status: Option<u16>,
    pub title: Option<String>,
    pub ready_state: String,
    pub capture_duration_ms: u64,
    pub collector_version: String,
    pub protocol_version: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionReceiptArtifacts {
    pub html: ArtifactRef,
    pub viewport_png: Option<ArtifactRef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionReceipt {
    collection_id: CollectionId,
    task_sha256: [u8; 32],
    completed_at_unix_ms: u64,
    final_url: String,
    http_status: Option<u16>,
    title: Option<String>,
    ready_state: String,
    capture_duration_ms: u64,
    collector_version: String,
    protocol_version: u16,
    html: ArtifactRef,
    viewport_png: Option<ArtifactRef>,
}

impl CollectionReceipt {
    pub fn new(
        collection_id: CollectionId,
        task_sha256: [u8; 32],
        metadata: CollectionReceiptMetadata,
        artifacts: CollectionReceiptArtifacts,
    ) -> Result<Self, ProtocolError> {
        let receipt = Self {
            collection_id,
            task_sha256,
            completed_at_unix_ms: metadata.completed_at_unix_ms,
            final_url: metadata.final_url,
            http_status: metadata.http_status,
            title: metadata.title,
            ready_state: metadata.ready_state,
            capture_duration_ms: metadata.capture_duration_ms,
            collector_version: metadata.collector_version,
            protocol_version: metadata.protocol_version,
            html: artifacts.html,
            viewport_png: artifacts.viewport_png,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn collection_id(&self) -> CollectionId {
        self.collection_id
    }

    pub fn task_sha256(&self) -> &[u8; 32] {
        &self.task_sha256
    }

    pub fn completed_at_unix_ms(&self) -> u64 {
        self.completed_at_unix_ms
    }

    pub fn final_url(&self) -> &str {
        &self.final_url
    }

    pub fn http_status(&self) -> Option<u16> {
        self.http_status
    }

    pub fn title(&self) -> Option<&str> {
        self.title.as_deref()
    }

    pub fn ready_state(&self) -> &str {
        &self.ready_state
    }

    pub fn capture_duration_ms(&self) -> u64 {
        self.capture_duration_ms
    }

    pub fn collector_version(&self) -> &str {
        &self.collector_version
    }

    pub fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    pub fn html(&self) -> &ArtifactRef {
        &self.html
    }

    pub fn viewport_png(&self) -> Option<&ArtifactRef> {
        self.viewport_png.as_ref()
    }

    fn validate(&self) -> Result<(), ProtocolError> {
        CollectionId::new(*self.collection_id.as_bytes())?;
        crate::validate_http_url(&self.final_url)
            .map_err(|_| ProtocolError::InvalidCollectionPayload)?;
        if self.task_sha256 == [0; 32]
            || self.completed_at_unix_ms == 0
            || self.final_url.len() > MAX_FINAL_URL_BYTES
            || self.http_status.is_some_and(|status| !(100..=599).contains(&status))
            || self.title.as_ref().is_some_and(|title| {
                title.is_empty() || title.len() > MAX_TITLE_BYTES
            })
            || self.ready_state.len() > MAX_SELECTOR_BYTES
            || self.collector_version.is_empty()
            || self.collector_version.len() > MAX_COLLECTOR_VERSION_BYTES
            || self.collector_version.chars().any(char::is_control)
            || self.protocol_version != PROTOCOL_VERSION
            || self.html.media_type() != ArtifactMediaType::TextHtmlUtf8
            || usize::try_from(self.html.len()).ok().is_none_or(|len| {
                len == 0 || len > MAX_HTML_BYTES
            })
            || self.viewport_png.as_ref().is_some_and(|artifact| {
                artifact.media_type() != ArtifactMediaType::ImagePng
                    || usize::try_from(artifact.len()).ok().is_none_or(|len| {
                        len == 0 || len > MAX_PNG_BYTES
                    })
            })
        {
            return Err(ProtocolError::InvalidCollectionPayload);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TracePage {
    collection_id: CollectionId,
    events: Vec<TraceEvent>,
    next_cursor: TraceCursor,
    complete: bool,
}

impl TracePage {
    pub fn new(
        collection_id: CollectionId,
        events: Vec<TraceEvent>,
        next_cursor: TraceCursor,
        complete: bool,
    ) -> Result<Self, ProtocolError> {
        if events.len() > MAX_TRACE_EVENTS || !strictly_increasing_events(&events) {
            return Err(ProtocolError::InvalidCollectionPayload);
        }
        if events.last().map(TraceEvent::cursor).is_some_and(|cursor| cursor != next_cursor) {
            return Err(ProtocolError::InvalidCollectionPayload);
        }
        Ok(Self {
            collection_id,
            events,
            next_cursor,
            complete,
        })
    }

    pub fn collection_id(&self) -> CollectionId {
        self.collection_id
    }

    pub fn events(&self) -> &[TraceEvent] {
        &self.events
    }

    pub fn next_cursor(&self) -> TraceCursor {
        self.next_cursor
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactChunk {
    collection_id: CollectionId,
    sha256: [u8; 32],
    offset: u64,
    total_len: u64,
    bytes: Vec<u8>,
    eof: bool,
}

impl ArtifactChunk {
    pub fn new(
        collection_id: CollectionId,
        sha256: [u8; 32],
        offset: u64,
        total_len: u64,
        bytes: Vec<u8>,
        eof: bool,
    ) -> Result<Self, ProtocolError> {
        let end = offset
            .checked_add(u64::try_from(bytes.len()).map_err(|_| {
                ProtocolError::InvalidCollectionPayload
            })?)
            .ok_or(ProtocolError::InvalidCollectionPayload)?;
        if sha256 == [0; 32]
            || total_len == 0
            || bytes.len() > MAX_ARTIFACT_CHUNK_BYTES
            || end > total_len
            || eof != (end == total_len)
            || (bytes.is_empty() && !eof)
        {
            return Err(ProtocolError::InvalidCollectionPayload);
        }
        Ok(Self {
            collection_id,
            sha256,
            offset,
            total_len,
            bytes,
            eof,
        })
    }

    pub fn collection_id(&self) -> CollectionId {
        self.collection_id
    }

    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }

    pub fn offset(&self) -> u64 {
        self.offset
    }

    pub fn total_len(&self) -> u64 {
        self.total_len
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn is_eof(&self) -> bool {
        self.eof
    }
}

// `PartialEq`-only (not `Eq`): `ShapedRows` carries a `RowPage`, whose cells
// may be `Value::Real(f64)` — the same reason `CollectionRequest` (which
// carries `OutputSchema`, also `f64`-bearing via `Extractor::Const`) is
// `PartialEq`-only.
#[derive(Debug, Clone, PartialEq)]
pub enum CollectionResponse {
    Accepted { collection_id: CollectionId },
    TracePage(TracePage),
    ArtifactChunk(ArtifactChunk),
    Cancelled { collection_id: CollectionId },
    Receipt(CollectionReceipt),
    /// One page of declarative output-shaping rows (Phase C, axis 7).
    ShapedRows(RowPage),
}

impl CollectionResponse {
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut output = Vec::new();
        output.extend_from_slice(&COLLECTION_RESPONSE_MAGIC);
        output.extend_from_slice(&COLLECTION_SCHEMA_VERSION.to_le_bytes());
        match self {
            Self::Accepted { collection_id } => {
                output.push(1);
                output.push(0);
                output.extend_from_slice(collection_id.as_bytes());
            }
            Self::TracePage(page) => {
                output.push(2);
                output.push(u8::from(page.complete));
                output.extend_from_slice(page.collection_id.as_bytes());
                output.extend_from_slice(&page.next_cursor.value().to_le_bytes());
                output.push(page.events.len() as u8);
                for event in &page.events {
                    encode_trace_event(&mut output, event)?;
                }
            }
            Self::ArtifactChunk(chunk) => {
                output.push(3);
                output.push(u8::from(chunk.eof));
                output.extend_from_slice(chunk.collection_id.as_bytes());
                output.extend_from_slice(&chunk.sha256);
                output.extend_from_slice(&chunk.offset.to_le_bytes());
                output.extend_from_slice(&chunk.total_len.to_le_bytes());
                output.extend_from_slice(&(chunk.bytes.len() as u32).to_le_bytes());
                output.extend_from_slice(&chunk.bytes);
            }
            Self::Cancelled { collection_id } => {
                output.push(4);
                output.push(0);
                output.extend_from_slice(collection_id.as_bytes());
            }
            Self::Receipt(receipt) => {
                receipt.validate()?;
                let mut flags = 0_u8;
                if receipt.viewport_png.is_some() {
                    flags |= 1;
                }
                if receipt.title.is_some() {
                    flags |= 2;
                }
                if receipt.http_status.is_some() {
                    flags |= 4;
                }
                output.push(5);
                output.push(flags);
                output.extend_from_slice(receipt.collection_id.as_bytes());
                output.extend_from_slice(&receipt.task_sha256);
                output.extend_from_slice(&receipt.completed_at_unix_ms.to_le_bytes());
                output.extend_from_slice(&receipt.http_status.unwrap_or(0).to_le_bytes());
                output.extend_from_slice(&(receipt.final_url.len() as u32).to_le_bytes());
                output.extend_from_slice(
                    &(receipt.title.as_ref().map_or(0, String::len) as u32).to_le_bytes(),
                );
                output.extend_from_slice(&(receipt.ready_state.len() as u32).to_le_bytes());
                output.extend_from_slice(
                    &(receipt.collector_version.len() as u16).to_le_bytes(),
                );
                output.extend_from_slice(&receipt.capture_duration_ms.to_le_bytes());
                output.extend_from_slice(&receipt.protocol_version.to_le_bytes());
                encode_artifact_ref(&mut output, &receipt.html);
                if let Some(viewport_png) = &receipt.viewport_png {
                    encode_artifact_ref(&mut output, viewport_png);
                }
                output.extend_from_slice(receipt.final_url.as_bytes());
                if let Some(title) = &receipt.title {
                    output.extend_from_slice(title.as_bytes());
                }
                output.extend_from_slice(receipt.ready_state.as_bytes());
                output.extend_from_slice(receipt.collector_version.as_bytes());
            }
            Self::ShapedRows(page) => {
                output.push(6);
                output.push(0);
                let page_bytes = page.encode()?;
                let page_len = u32::try_from(page_bytes.len())
                    .map_err(|_| ProtocolError::InvalidCollectionPayload)?;
                output.extend_from_slice(&page_len.to_le_bytes());
                output.extend_from_slice(&page_bytes);
            }
        }
        Ok(output)
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        let mut input = Input::new(payload);
        if input.bytes(4)? != COLLECTION_RESPONSE_MAGIC
            || input.u16()? != COLLECTION_SCHEMA_VERSION
        {
            return Err(ProtocolError::InvalidCollectionPayload);
        }
        let operation = input.u8()?;
        let flags = input.u8()?;
        let response = match operation {
            1 if flags == 0 => Self::Accepted {
                collection_id: input.collection_id()?,
            },
            2 if flags & !1 == 0 => {
                let collection_id = input.collection_id()?;
                let next_cursor = TraceCursor::new(input.u32()?);
                let count = usize::from(input.u8()?);
                if count > MAX_TRACE_EVENTS {
                    return Err(ProtocolError::InvalidCollectionPayload);
                }
                let mut events = Vec::with_capacity(count);
                for _ in 0..count {
                    events.push(decode_trace_event(&mut input)?);
                }
                Self::TracePage(TracePage::new(
                    collection_id,
                    events,
                    next_cursor,
                    flags & 1 == 1,
                )?)
            }
            3 if flags & !1 == 0 => {
                let collection_id = input.collection_id()?;
                let sha256 = input.array_32()?;
                let offset = input.u64()?;
                let total_len = input.u64()?;
                let len = usize::try_from(input.u32()?)
                    .map_err(|_| ProtocolError::InvalidCollectionPayload)?;
                if len > MAX_ARTIFACT_CHUNK_BYTES {
                    return Err(ProtocolError::InvalidCollectionPayload);
                }
                let bytes = input.bytes(len)?.to_vec();
                Self::ArtifactChunk(ArtifactChunk::new(
                    collection_id,
                    sha256,
                    offset,
                    total_len,
                    bytes,
                    flags & 1 == 1,
                )?)
            }
            4 if flags == 0 => Self::Cancelled {
                collection_id: input.collection_id()?,
            },
            5 if flags & !0b111 == 0 => {
                let collection_id = input.collection_id()?;
                let task_sha256 = input.array_32()?;
                let completed_at_unix_ms = input.u64()?;
                let raw_status = input.u16()?;
                let http_status = match (flags & 4 != 0, raw_status) {
                    (false, 0) => None,
                    (true, 100..=599) => Some(raw_status),
                    _ => return Err(ProtocolError::InvalidCollectionPayload),
                };
                let final_url_len = usize::try_from(input.u32()?)
                    .map_err(|_| ProtocolError::InvalidCollectionPayload)?;
                let title_len = usize::try_from(input.u32()?)
                    .map_err(|_| ProtocolError::InvalidCollectionPayload)?;
                let ready_state_len = usize::try_from(input.u32()?)
                    .map_err(|_| ProtocolError::InvalidCollectionPayload)?;
                let collector_version_len = usize::from(input.u16()?);
                let capture_duration_ms = input.u64()?;
                let protocol_version = input.u16()?;
                if final_url_len > MAX_FINAL_URL_BYTES
                    || title_len > MAX_TITLE_BYTES
                    || ready_state_len > MAX_SELECTOR_BYTES
                    || collector_version_len > MAX_COLLECTOR_VERSION_BYTES
                    || (flags & 2 == 0) != (title_len == 0)
                {
                    return Err(ProtocolError::InvalidCollectionPayload);
                }
                let html = decode_artifact_ref(&mut input)?;
                let viewport_png = if flags & 1 != 0 {
                    Some(decode_artifact_ref(&mut input)?)
                } else {
                    None
                };
                let final_url = std::str::from_utf8(input.bytes(final_url_len)?)
                    .map_err(|_| ProtocolError::InvalidCollectionPayload)?
                    .to_owned();
                let title = if flags & 2 != 0 {
                    Some(
                        std::str::from_utf8(input.bytes(title_len)?)
                            .map_err(|_| ProtocolError::InvalidCollectionPayload)?
                            .to_owned(),
                    )
                } else {
                    None
                };
                let ready_state = std::str::from_utf8(input.bytes(ready_state_len)?)
                    .map_err(|_| ProtocolError::InvalidCollectionPayload)?
                    .to_owned();
                let collector_version =
                    std::str::from_utf8(input.bytes(collector_version_len)?)
                        .map_err(|_| ProtocolError::InvalidCollectionPayload)?
                        .to_owned();
                Self::Receipt(CollectionReceipt::new(
                    collection_id,
                    task_sha256,
                    CollectionReceiptMetadata {
                        completed_at_unix_ms,
                        final_url,
                        http_status,
                        title,
                        ready_state,
                        capture_duration_ms,
                        collector_version,
                        protocol_version,
                    },
                    CollectionReceiptArtifacts { html, viewport_png },
                )?)
            }
            6 if flags == 0 => {
                let page_len = usize::try_from(input.u32()?)
                    .map_err(|_| ProtocolError::InvalidCollectionPayload)?;
                Self::ShapedRows(RowPage::decode(input.bytes(page_len)?)?)
            }
            _ => return Err(ProtocolError::InvalidCollectionPayload),
        };
        if !input.is_empty() {
            return Err(ProtocolError::InvalidCollectionPayload);
        }
        Ok(response)
    }
}

fn encode_trace_event(
    output: &mut Vec<u8>,
    event: &TraceEvent,
) -> Result<(), ProtocolError> {
    if event.cursor == TraceCursor::START {
        return Err(ProtocolError::InvalidCollectionPayload);
    }
    validate_event_kind(&event.kind)?;
    output.extend_from_slice(&event.cursor.value().to_le_bytes());
    output.extend_from_slice(&event.timestamp_unix_ms.to_le_bytes());
    match &event.kind {
        TraceEventKind::Started(started) => {
            output.push(1);
            output.extend_from_slice(&started.task_sha256);
            output.push(started.step_count);
            let runtime = encode_runtime_record(&started.runtime)
                .map_err(|_| ProtocolError::InvalidCollectionPayload)?;
            let len = u16::try_from(runtime.len())
                .map_err(|_| ProtocolError::InvalidCollectionPayload)?;
            output.extend_from_slice(&len.to_le_bytes());
            output.extend_from_slice(&runtime);
        }
        TraceEventKind::ArtifactCommitted(committed) => {
            output.push(2);
            output.push(committed.step_index);
            output.push(artifact_role_to_wire(committed.role));
            encode_artifact_ref(output, &committed.artifact);
        }
        TraceEventKind::Terminal(terminal) => {
            output.push(3);
            encode_terminal_outcome(output, terminal.outcome);
            output.push(terminal.steps.len() as u8);
            for step in &terminal.steps {
                output.push(step.step_index);
                output.extend_from_slice(&step.completed_at_unix_ms.to_le_bytes());
                output.extend_from_slice(&step.duration_ms.to_le_bytes());
                encode_step_outcome(output, step.outcome);
            }
        }
        TraceEventKind::Interrupted(reason) => {
            output.push(4);
            output.push(interrupted_reason_to_wire(*reason));
        }
    }
    Ok(())
}

fn decode_trace_event(input: &mut Input<'_>) -> Result<TraceEvent, ProtocolError> {
    let cursor = TraceCursor::new(input.u32()?);
    let timestamp_unix_ms = input.u64()?;
    let kind = match input.u8()? {
        1 => {
            let task_sha256 = input.array_32()?;
            let step_count = input.u8()?;
            let runtime_len = usize::from(input.u16()?);
            let runtime = decode_runtime_record(input.bytes(runtime_len)?)
                .map_err(|_| ProtocolError::InvalidCollectionPayload)?;
            TraceEventKind::Started(StartedTrace::new(
                task_sha256,
                step_count,
                runtime,
            )?)
        }
        2 => {
            let step_index = input.u8()?;
            let role = artifact_role_from_wire(input.u8()?)?;
            let artifact = decode_artifact_ref(input)?;
            TraceEventKind::ArtifactCommitted(ArtifactCommitted::new(
                step_index,
                role,
                artifact,
            )?)
        }
        3 => {
            let outcome = decode_terminal_outcome(input)?;
            let count = usize::from(input.u8()?);
            if count > MAX_TRACE_STEP_SUMMARIES {
                return Err(ProtocolError::InvalidCollectionPayload);
            }
            let mut steps = Vec::with_capacity(count);
            for _ in 0..count {
                steps.push(StepSummary::new(
                    input.u8()?,
                    input.u64()?,
                    input.u64()?,
                    decode_step_outcome(input)?,
                )?);
            }
            TraceEventKind::Terminal(TerminalTrace::new(outcome, steps)?)
        }
        4 => TraceEventKind::Interrupted(interrupted_reason_from_wire(input.u8()?)?),
        _ => return Err(ProtocolError::InvalidCollectionPayload),
    };
    TraceEvent::new(cursor, timestamp_unix_ms, kind)
}

fn encode_artifact_ref(output: &mut Vec<u8>, artifact: &ArtifactRef) {
    output.extend_from_slice(&artifact.sha256);
    output.extend_from_slice(&artifact.len.to_le_bytes());
    output.push(artifact_media_type_to_wire(artifact.media_type));
}

fn decode_artifact_ref(input: &mut Input<'_>) -> Result<ArtifactRef, ProtocolError> {
    ArtifactRef::new(
        input.array_32()?,
        input.u64()?,
        artifact_media_type_from_wire(input.u8()?)?,
    )
}

fn encode_terminal_outcome(output: &mut Vec<u8>, outcome: TerminalOutcome) {
    match outcome {
        TerminalOutcome::Succeeded => output.push(1),
        TerminalOutcome::Failed(failure) => {
            output.push(2);
            output.extend_from_slice(&(failure as u64).to_le_bytes());
        }
        TerminalOutcome::Cancelled => output.push(3),
    }
}

fn decode_terminal_outcome(input: &mut Input<'_>) -> Result<TerminalOutcome, ProtocolError> {
    let outcome = match input.u8()? {
        1 => TerminalOutcome::Succeeded,
        2 => TerminalOutcome::Failed(decode_failure_class(input.u64()?)?),
        3 => TerminalOutcome::Cancelled,
        _ => return Err(ProtocolError::InvalidCollectionPayload),
    };
    if !valid_terminal_outcome(outcome) {
        return Err(ProtocolError::InvalidCollectionPayload);
    }
    Ok(outcome)
}

fn encode_step_outcome(output: &mut Vec<u8>, outcome: StepOutcome) {
    match outcome {
        StepOutcome::Succeeded => output.push(1),
        StepOutcome::Failed(failure) => {
            output.push(2);
            output.extend_from_slice(&(failure as u64).to_le_bytes());
        }
        StepOutcome::Cancelled => output.push(3),
    }
}

fn decode_step_outcome(input: &mut Input<'_>) -> Result<StepOutcome, ProtocolError> {
    let outcome = match input.u8()? {
        1 => StepOutcome::Succeeded,
        2 => StepOutcome::Failed(decode_failure_class(input.u64()?)?),
        3 => StepOutcome::Cancelled,
        _ => return Err(ProtocolError::InvalidCollectionPayload),
    };
    if !valid_step_outcome(outcome) {
        return Err(ProtocolError::InvalidCollectionPayload);
    }
    Ok(outcome)
}

fn artifact_role_to_wire(role: ArtifactRole) -> u8 {
    match role {
        ArtifactRole::Html => 1,
        ArtifactRole::ViewportPng => 2,
    }
}

fn artifact_role_from_wire(value: u8) -> Result<ArtifactRole, ProtocolError> {
    match value {
        1 => Ok(ArtifactRole::Html),
        2 => Ok(ArtifactRole::ViewportPng),
        _ => Err(ProtocolError::InvalidCollectionPayload),
    }
}

fn artifact_media_type_to_wire(media_type: ArtifactMediaType) -> u8 {
    match media_type {
        ArtifactMediaType::TextHtmlUtf8 => 1,
        ArtifactMediaType::ImagePng => 2,
        ArtifactMediaType::ApplicationOctetStream => 3,
    }
}

fn artifact_media_type_from_wire(
    value: u8,
) -> Result<ArtifactMediaType, ProtocolError> {
    match value {
        1 => Ok(ArtifactMediaType::TextHtmlUtf8),
        2 => Ok(ArtifactMediaType::ImagePng),
        3 => Ok(ArtifactMediaType::ApplicationOctetStream),
        _ => Err(ProtocolError::InvalidCollectionPayload),
    }
}

fn interrupted_reason_to_wire(reason: InterruptedReason) -> u8 {
    match reason {
        InterruptedReason::SuccessorReconciliation => 1,
        InterruptedReason::ShutdownTimeout => 2,
    }
}

fn interrupted_reason_from_wire(value: u8) -> Result<InterruptedReason, ProtocolError> {
    match value {
        1 => Ok(InterruptedReason::SuccessorReconciliation),
        2 => Ok(InterruptedReason::ShutdownTimeout),
        _ => Err(ProtocolError::InvalidCollectionPayload),
    }
}

fn decode_failure_class(value: u64) -> Result<FailureClass, ProtocolError> {
    FailureClass::from_wire(value).map_err(|_| ProtocolError::InvalidCollectionPayload)
}

fn valid_failure_class(failure: FailureClass) -> bool {
    !matches!(failure, FailureClass::None | FailureClass::Cancelled)
}

fn valid_step_outcome(outcome: StepOutcome) -> bool {
    match outcome {
        StepOutcome::Succeeded | StepOutcome::Cancelled => true,
        StepOutcome::Failed(failure) => valid_failure_class(failure),
    }
}

fn valid_terminal_outcome(outcome: TerminalOutcome) -> bool {
    match outcome {
        TerminalOutcome::Succeeded | TerminalOutcome::Cancelled => true,
        TerminalOutcome::Failed(failure) => valid_failure_class(failure),
    }
}

fn role_matches_media_type(role: ArtifactRole, media_type: ArtifactMediaType) -> bool {
    matches!(
        (role, media_type),
        (ArtifactRole::Html, ArtifactMediaType::TextHtmlUtf8)
            | (ArtifactRole::ViewportPng, ArtifactMediaType::ImagePng)
    )
}

fn strictly_increasing_steps(steps: &[StepSummary]) -> bool {
    steps
        .windows(2)
        .all(|pair| pair[0].step_index < pair[1].step_index)
}

fn strictly_increasing_events(events: &[TraceEvent]) -> bool {
    events
        .windows(2)
        .all(|pair| pair[0].cursor < pair[1].cursor)
}

fn validate_event_kind(kind: &TraceEventKind) -> Result<(), ProtocolError> {
    match kind {
        TraceEventKind::Started(started) => {
            StartedTrace::new(
                started.task_sha256,
                started.step_count,
                started.runtime.clone(),
            )?;
        }
        TraceEventKind::ArtifactCommitted(committed) => {
            ArtifactCommitted::new(
                committed.step_index,
                committed.role,
                committed.artifact.clone(),
            )?;
        }
        TraceEventKind::Terminal(terminal) => {
            TerminalTrace::new(terminal.outcome, terminal.steps.clone())?;
        }
        TraceEventKind::Interrupted(_) => {}
    }
    Ok(())
}

struct Input<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Input<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.offset..]
    }

    fn consume_remaining(&mut self) {
        self.offset = self.bytes.len();
    }

    fn bytes(&mut self, len: usize) -> Result<&'a [u8], ProtocolError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(ProtocolError::InvalidCollectionPayload)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ProtocolError::InvalidCollectionPayload)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, ProtocolError> {
        Ok(self.bytes(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ProtocolError> {
        Ok(u16::from_le_bytes(self.bytes(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32, ProtocolError> {
        Ok(u32::from_le_bytes(self.bytes(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, ProtocolError> {
        Ok(u64::from_le_bytes(self.bytes(8)?.try_into().unwrap()))
    }

    fn array_32(&mut self) -> Result<[u8; 32], ProtocolError> {
        self.bytes(32)?
            .try_into()
            .map_err(|_| ProtocolError::InvalidCollectionPayload)
    }

    fn collection_id(&mut self) -> Result<CollectionId, ProtocolError> {
        CollectionId::new(
            self.bytes(16)?
                .try_into()
                .map_err(|_| ProtocolError::InvalidCollectionPayload)?,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shape::{
        Cardinality, Column, ColumnType, CssPick, Extractor, MetaField, OnError, Row,
        ScopeSelector, Value,
    };
    use crate::{
        ControlTransport, EngineFamily, FeatureSupport, RuntimeFeature,
        RuntimeKind, RuntimeRequirements, SupportLevel, TaskStep,
    };
    use dig2browser_core::RuntimeDescriptor;

    fn collection_id() -> CollectionId {
        CollectionId::new([7; 16]).expect("valid collection id")
    }

    fn task() -> CollectionTask {
        CollectionTask::new(vec![TaskStep::Navigate {
            url: "https://example.test/collection".to_owned(),
        }])
        .expect("valid task")
    }

    fn runtime() -> ResolvedRuntimeRecord {
        let descriptor = RuntimeDescriptor::new(
            RuntimeKind::Chrome,
            EngineFamily::Chromium,
            ControlTransport::Cdp,
            vec![FeatureSupport::new(
                RuntimeFeature::Navigate,
                SupportLevel::Native,
                Vec::new(),
            )],
        )
        .expect("valid descriptor");
        let requirements = RuntimeRequirements::new(
            vec![RuntimeFeature::Navigate],
            false,
        )
        .expect("valid requirements");
        let resolved = descriptor
            .negotiate(&requirements, Some("test-runtime".to_owned()))
            .expect("resolved runtime");
        ResolvedRuntimeRecord::from_resolved(&resolved).expect("runtime record")
    }

    fn events() -> Vec<TraceEvent> {
        let started = StartedTrace::new([1; 32], 1, runtime()).expect("started");
        let artifact = ArtifactRef::new(
            [2; 32],
            17,
            ArtifactMediaType::TextHtmlUtf8,
        )
        .expect("artifact");
        let committed = ArtifactCommitted::new(0, ArtifactRole::Html, artifact)
            .expect("committed");
        let summary = StepSummary::new(
            0,
            1_784_500_000_020,
            20,
            StepOutcome::Succeeded,
        )
        .expect("summary");
        let terminal = TerminalTrace::new(
            TerminalOutcome::Succeeded,
            vec![summary],
        )
        .expect("terminal");
        vec![
            TraceEvent::new(
                TraceCursor::new(1),
                1_784_500_000_000,
                TraceEventKind::Started(started),
            )
            .expect("started event"),
            TraceEvent::new(
                TraceCursor::new(2),
                1_784_500_000_010,
                TraceEventKind::ArtifactCommitted(committed),
            )
            .expect("artifact event"),
            TraceEvent::new(
                TraceCursor::new(3),
                1_784_500_000_020,
                TraceEventKind::Terminal(terminal),
            )
            .expect("terminal event"),
            TraceEvent::new(
                TraceCursor::new(4),
                1_784_500_000_030,
                TraceEventKind::Interrupted(
                    InterruptedReason::SuccessorReconciliation,
                ),
            )
            .expect("interrupted event"),
        ]
    }

    #[test]
    fn collection_requests_round_trip_with_exact_bounded_read_layout() {
        let begin = CollectionRequest::begin(
            collection_id(),
            ProfileClass::Public,
            BrowserPersona::desktop_default(),
            task(),
        )
        .expect("begin request");
        assert_eq!(
            CollectionRequest::decode(&begin.encode().expect("encode begin"))
                .expect("decode begin"),
            begin
        );

        let read = CollectionRequest::read_trace(
            collection_id(),
            TraceCursor::new(9),
            64,
        )
        .expect("read trace");
        let encoded = read.encode().expect("encode read trace");
        let mut expected = Vec::from(*b"D2CQ");
        expected.extend_from_slice(&1_u16.to_le_bytes());
        expected.extend_from_slice(&[2, 0]);
        expected.extend_from_slice(&[7; 16]);
        expected.extend_from_slice(&9_u32.to_le_bytes());
        expected.push(64);
        assert_eq!(encoded, expected);
        assert_eq!(CollectionRequest::decode(&encoded).unwrap(), read);

        for request in [
            CollectionRequest::read_artifact(
                collection_id(),
                [3; 32],
                256,
                MAX_ARTIFACT_CHUNK_BYTES as u32,
            )
            .unwrap(),
            CollectionRequest::read_receipt(collection_id()).unwrap(),
            CollectionRequest::cancel(collection_id()).unwrap(),
        ] {
            assert_eq!(
                CollectionRequest::decode(&request.encode().unwrap()).unwrap(),
                request
            );
        }
    }

    fn page_level_schema() -> OutputSchema {
        OutputSchema::new(
            "page".to_owned(),
            Cardinality::PageLevel,
            vec![Column::new(
                "title".to_owned(),
                ColumnType::Text,
                Extractor::Meta(MetaField::Title),
                OnError::Null,
            )
            .expect("title column")],
        )
        .expect("valid page-level schema")
    }

    fn item_scope_schema() -> OutputSchema {
        OutputSchema::new(
            "products".to_owned(),
            Cardinality::ItemScope(ScopeSelector::Css(".product-card".to_owned())),
            vec![Column::new(
                "name".to_owned(),
                ColumnType::Text,
                Extractor::Css {
                    selector: ".name".to_owned(),
                    pick: CssPick::Text,
                },
                OnError::Null,
            )
            .expect("name column")],
        )
        .expect("valid item-scope schema")
    }

    #[test]
    fn read_shaped_request_round_trips_page_level_and_item_scope_schemas() {
        for schema in [page_level_schema(), item_scope_schema()] {
            let request = CollectionRequest::read_shaped(
                collection_id(),
                schema.clone(),
                ShapeCursor::new(3),
                256,
            )
            .expect("read shaped request");
            assert_eq!(
                CollectionRequest::decode(&request.encode().expect("encode read shaped"))
                    .expect("decode read shaped"),
                request
            );
            let CollectionRequest::ReadShaped {
                collection_id: decoded_id,
                schema: decoded_schema,
                cursor,
                limit,
            } = CollectionRequest::decode(&request.encode().unwrap()).unwrap()
            else {
                panic!("expected ReadShaped request");
            };
            assert_eq!(decoded_id, collection_id());
            assert_eq!(decoded_schema, schema);
            assert_eq!(cursor, ShapeCursor::new(3));
            assert_eq!(limit, 256);
        }
    }

    #[test]
    fn read_shaped_request_rejects_zero_and_oversized_limit() {
        assert!(CollectionRequest::read_shaped(
            collection_id(),
            page_level_schema(),
            ShapeCursor::START,
            0,
        )
        .is_err());
        assert!(CollectionRequest::read_shaped(
            collection_id(),
            page_level_schema(),
            ShapeCursor::START,
            u16::try_from(MAX_ROWS_PER_PAGE + 1).unwrap(),
        )
        .is_err());
    }

    #[test]
    fn shaped_rows_response_round_trips_with_and_without_next_cursor() {
        let columns = vec![("title".to_owned(), ColumnType::Text)];
        let rows = vec![Row::new(vec![Value::Text("Catalog".to_owned())]).unwrap()];

        let incomplete = RowPage::new(
            columns.clone(),
            rows.clone(),
            Some(ShapeCursor::new(1)),
            false,
        )
        .expect("incomplete row page");
        let response = CollectionResponse::ShapedRows(incomplete);
        let encoded = response.encode().expect("encode shaped rows");
        assert_eq!(CollectionResponse::decode(&encoded).unwrap(), response);
        let CollectionResponse::ShapedRows(decoded) =
            CollectionResponse::decode(&encoded).unwrap()
        else {
            panic!("expected ShapedRows response");
        };
        assert_eq!(decoded.next_cursor(), Some(ShapeCursor::new(1)));
        assert!(!decoded.is_complete());

        let complete = RowPage::new(columns, rows, None, true).expect("complete row page");
        let response = CollectionResponse::ShapedRows(complete);
        let encoded = response.encode().expect("encode complete shaped rows");
        assert_eq!(CollectionResponse::decode(&encoded).unwrap(), response);
        let CollectionResponse::ShapedRows(decoded) =
            CollectionResponse::decode(&encoded).unwrap()
        else {
            panic!("expected ShapedRows response");
        };
        assert_eq!(decoded.next_cursor(), None);
        assert!(decoded.is_complete());
    }

    #[test]
    fn trace_events_and_collection_responses_round_trip() {
        let events = events();
        for event in &events {
            assert_eq!(
                TraceEvent::decode(&event.encode().unwrap()).unwrap(),
                event.clone()
            );
        }
        let page = TracePage::new(
            collection_id(),
            events,
            TraceCursor::new(4),
            true,
        )
        .expect("trace page");
        let response = CollectionResponse::TracePage(page);
        assert_eq!(
            CollectionResponse::decode(&response.encode().unwrap()).unwrap(),
            response
        );

        let chunk = ArtifactChunk::new(
            collection_id(),
            [4; 32],
            4,
            8,
            vec![5; 4],
            true,
        )
        .expect("artifact chunk");
        let response = CollectionResponse::ArtifactChunk(chunk);
        assert_eq!(
            CollectionResponse::decode(&response.encode().unwrap()).unwrap(),
            response
        );

        let receipt = CollectionReceipt::new(
            collection_id(),
            [5; 32],
            CollectionReceiptMetadata {
                completed_at_unix_ms: 1_784_500_000_020,
                final_url: "https://example.test/final".to_owned(),
                http_status: Some(200),
                title: Some("Example".to_owned()),
                ready_state: "complete".to_owned(),
                capture_duration_ms: 20,
                collector_version: "dig2browser-station/0.1.0".to_owned(),
                protocol_version: PROTOCOL_VERSION,
            },
            CollectionReceiptArtifacts {
                html: ArtifactRef::new(
                    [6; 32],
                    41,
                    ArtifactMediaType::TextHtmlUtf8,
                )
                .unwrap(),
                viewport_png: Some(
                    ArtifactRef::new([7; 32], 97, ArtifactMediaType::ImagePng)
                        .unwrap(),
                ),
            },
        )
        .expect("valid receipt");
        let response = CollectionResponse::Receipt(receipt);
        assert_eq!(
            CollectionResponse::decode(&response.encode().unwrap()).unwrap(),
            response
        );
    }

    #[test]
    fn malformed_flags_enums_and_bounds_fail_closed() {
        let request = CollectionRequest::read_trace(
            collection_id(),
            TraceCursor::START,
            1,
        )
        .unwrap();
        let mut unknown_flags = request.encode().unwrap();
        unknown_flags[7] = 1;
        assert!(CollectionRequest::decode(&unknown_flags).is_err());

        let mut excessive_limit = request.encode().unwrap();
        excessive_limit[28] = 65;
        assert!(CollectionRequest::decode(&excessive_limit).is_err());
        assert!(CollectionRequest::read_trace(
            collection_id(),
            TraceCursor::START,
            0,
        )
        .is_err());
        assert!(CollectionRequest::read_artifact(
            collection_id(),
            [1; 32],
            0,
            (MAX_ARTIFACT_CHUNK_BYTES + 1) as u32,
        )
        .is_err());

        assert!(CollectionReceipt::new(
            collection_id(),
            [0; 32],
            CollectionReceiptMetadata {
                completed_at_unix_ms: 1,
                final_url: "https://example.test/final".to_owned(),
                http_status: None,
                title: None,
                ready_state: "complete".to_owned(),
                capture_duration_ms: 1,
                collector_version: "dig2browser-station/0.1.0".to_owned(),
                protocol_version: PROTOCOL_VERSION,
            },
            CollectionReceiptArtifacts {
                html: ArtifactRef::new(
                    [2; 32],
                    17,
                    ArtifactMediaType::TextHtmlUtf8,
                )
                .unwrap(),
                viewport_png: None,
            },
        )
        .is_err());

        let mut unknown_event = events()[0].encode().unwrap();
        unknown_event[18] = u8::MAX;
        assert!(TraceEvent::decode(&unknown_event).is_err());

        let too_many = (1..=65)
            .map(|cursor| {
                TraceEvent::new(
                    TraceCursor::new(cursor),
                    1,
                    TraceEventKind::Interrupted(InterruptedReason::ShutdownTimeout),
                )
                .unwrap()
            })
            .collect();
        assert!(TracePage::new(
            collection_id(),
            too_many,
            TraceCursor::new(65),
            false,
        )
        .is_err());
        assert!(ArtifactChunk::new(
            collection_id(),
            [1; 32],
            0,
            (MAX_ARTIFACT_CHUNK_BYTES + 1) as u64,
            vec![0; MAX_ARTIFACT_CHUNK_BYTES + 1],
            true,
        )
        .is_err());
    }
}
