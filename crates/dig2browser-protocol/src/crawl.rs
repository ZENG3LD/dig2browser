use crate::shape::{OutputSchema, RowPage, ShapeCursor, MAX_ROWS_PER_PAGE};
use crate::{
    ArtifactMediaType, ArtifactRef, BrowserPersona, CollectionId, ProfileClass,
    ProtocolError, MAX_REQUEST_BYTES,
};
use std::net::{Ipv4Addr, Ipv6Addr};

pub const MAX_CRAWL_SEEDS: usize = 64;
pub const MAX_CRAWL_ALLOWED_ORIGINS: usize = 64;
pub const MAX_CRAWL_URL_BYTES: usize = 4 * 1024;
pub const MAX_CRAWL_PAGES: u32 = 10_000;
pub const MAX_CRAWL_DEPTH: u32 = 64;
pub const MAX_CRAWL_RETRIES: u32 = 7;
pub const MAX_CRAWL_EVENTS: usize = 64;
pub const MAX_CRAWL_EVENT_DETAIL_BYTES: usize = 1024;

const CRAWL_REQUEST_MAGIC: [u8; 4] = *b"D2WQ";
const CRAWL_RESPONSE_MAGIC: [u8; 4] = *b"D2WP";
const CRAWL_EVENT_MAGIC: [u8; 4] = *b"D2WE";
const CRAWL_REQUEST_SCHEMA_VERSION: u16 = 1;
const CRAWL_RESPONSE_SCHEMA_VERSION: u16 = 1;
const CRAWL_EVENT_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CrawlJobId([u8; 16]);

impl CrawlJobId {
    pub fn new(bytes: [u8; 16]) -> Result<Self, ProtocolError> {
        if bytes == [0; 16] {
            return Err(ProtocolError::InvalidCrawlPayload);
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
pub struct CrawlCursor(u64);

impl CrawlCursor {
    pub const START: Self = Self(0);

    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn value(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrawlSpec {
    seeds: Vec<String>,
    allowed_origins: Vec<String>,
    max_pages: u32,
    max_depth: u32,
    max_retries: u32,
}

impl CrawlSpec {
    pub fn new<S, Seed, O, Origin>(
        seeds: S,
        allowed_origins: O,
        max_pages: u32,
        max_depth: u32,
        max_retries: u32,
    ) -> Result<Self, ProtocolError>
    where
        S: IntoIterator<Item = Seed>,
        Seed: Into<String>,
        O: IntoIterator<Item = Origin>,
        Origin: Into<String>,
    {
        let mut seeds: Vec<String> = seeds.into_iter().map(Into::into).collect();
        let mut allowed_origins: Vec<String> =
            allowed_origins.into_iter().map(Into::into).collect();
        seeds.sort_unstable();
        seeds.dedup();
        allowed_origins.sort_unstable();
        allowed_origins.dedup();
        let spec = Self {
            seeds,
            allowed_origins,
            max_pages,
            max_depth,
            max_retries,
        };
        spec.validate()?;
        Ok(spec)
    }

    pub fn seeds(&self) -> &[String] {
        &self.seeds
    }

    pub fn allowed_origins(&self) -> &[String] {
        &self.allowed_origins
    }

    pub fn max_pages(&self) -> u32 {
        self.max_pages
    }

    pub fn max_depth(&self) -> u32 {
        self.max_depth
    }

    pub fn max_retries(&self) -> u32 {
        self.max_retries
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.seeds.is_empty()
            || self.seeds.len() > MAX_CRAWL_SEEDS
            || self.allowed_origins.is_empty()
            || self.allowed_origins.len() > MAX_CRAWL_ALLOWED_ORIGINS
            || self.seeds.len() > self.max_pages as usize
            || !(1..=MAX_CRAWL_PAGES).contains(&self.max_pages)
            || self.max_depth > MAX_CRAWL_DEPTH
            || self.max_retries > MAX_CRAWL_RETRIES
            || !strictly_increasing_strings(&self.seeds)
            || !strictly_increasing_strings(&self.allowed_origins)
        {
            return Err(ProtocolError::InvalidCrawlPayload);
        }
        for origin in &self.allowed_origins {
            validate_exact_origin(origin)?;
        }
        for seed in &self.seeds {
            validate_canonical_url(seed)?;
            let origin = canonical_url_origin(seed)?;
            if self
                .allowed_origins
                .binary_search_by(|allowed| allowed.as_str().cmp(origin))
                .is_err()
            {
                return Err(ProtocolError::InvalidCrawlPayload);
            }
        }
        if encoded_spec_len(self)? > MAX_REQUEST_BYTES {
            return Err(ProtocolError::InvalidCrawlPayload);
        }
        Ok(())
    }
}

// `PartialEq`-only (not `Eq`): `ReadShaped` carries an `OutputSchema`, whose
// columns may hold `Extractor::Const(Value::Real(f64))` — the same reason
// `CollectionRequest` (which also carries `OutputSchema`) is `PartialEq`-only.
#[derive(Debug, Clone, PartialEq)]
pub enum CrawlRequest {
    Begin {
        job_id: CrawlJobId,
        profile_class: ProfileClass,
        persona: BrowserPersona,
        spec: CrawlSpec,
    },
    Status {
        job_id: CrawlJobId,
    },
    ReadEvents {
        job_id: CrawlJobId,
        cursor: CrawlCursor,
        limit: u8,
    },
    /// Declarative output shaping (Phase C, axis 7) over an entire crawl
    /// job's succeeded pages: project each page's captured HTML onto
    /// `schema` and page the concatenated resulting rows.
    ReadShaped {
        job_id: CrawlJobId,
        schema: OutputSchema,
        cursor: ShapeCursor,
        limit: u16,
    },
    Cancel {
        job_id: CrawlJobId,
    },
}

impl CrawlRequest {
    pub fn begin(
        job_id: CrawlJobId,
        profile_class: ProfileClass,
        persona: BrowserPersona,
        spec: CrawlSpec,
    ) -> Result<Self, ProtocolError> {
        let request = Self::Begin {
            job_id,
            profile_class,
            persona,
            spec,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn status(job_id: CrawlJobId) -> Result<Self, ProtocolError> {
        let request = Self::Status { job_id };
        request.validate()?;
        Ok(request)
    }

    pub fn read_events(
        job_id: CrawlJobId,
        cursor: CrawlCursor,
        limit: u8,
    ) -> Result<Self, ProtocolError> {
        let request = Self::ReadEvents {
            job_id,
            cursor,
            limit,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn read_shaped(
        job_id: CrawlJobId,
        schema: OutputSchema,
        cursor: ShapeCursor,
        limit: u16,
    ) -> Result<Self, ProtocolError> {
        let request = Self::ReadShaped {
            job_id,
            schema,
            cursor,
            limit,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn cancel(job_id: CrawlJobId) -> Result<Self, ProtocolError> {
        let request = Self::Cancel { job_id };
        request.validate()?;
        Ok(request)
    }

    pub fn job_id(&self) -> CrawlJobId {
        match self {
            Self::Begin { job_id, .. }
            | Self::Status { job_id }
            | Self::ReadEvents { job_id, .. }
            | Self::ReadShaped { job_id, .. }
            | Self::Cancel { job_id } => *job_id,
        }
    }

    pub fn is_begin(&self) -> bool {
        matches!(self, Self::Begin { .. })
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        CrawlJobId::new(*self.job_id().as_bytes())?;
        match self {
            Self::Begin { persona, spec, .. } => {
                let persona_len = persona
                    .encode()
                    .map_err(|_| ProtocolError::InvalidCrawlPayload)?
                    .len();
                spec.validate()?;
                let total = 32usize
                    .checked_add(persona_len)
                    .and_then(|value| value.checked_add(encoded_spec_len(spec).ok()?))
                    .ok_or(ProtocolError::InvalidCrawlPayload)?;
                if total > MAX_REQUEST_BYTES {
                    return Err(ProtocolError::InvalidCrawlPayload);
                }
                Ok(())
            }
            Self::ReadEvents { limit, .. } => {
                if *limit == 0 || usize::from(*limit) > MAX_CRAWL_EVENTS {
                    return Err(ProtocolError::InvalidCrawlPayload);
                }
                Ok(())
            }
            Self::ReadShaped { schema, limit, .. } => {
                schema.validate()?;
                if *limit == 0 || usize::from(*limit) > MAX_ROWS_PER_PAGE {
                    return Err(ProtocolError::InvalidCrawlPayload);
                }
                Ok(())
            }
            Self::Status { .. } | Self::Cancel { .. } => Ok(()),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        let mut output = Vec::new();
        output.extend_from_slice(&CRAWL_REQUEST_MAGIC);
        output.extend_from_slice(&CRAWL_REQUEST_SCHEMA_VERSION.to_le_bytes());
        match self {
            Self::Begin {
                job_id,
                profile_class,
                persona,
                spec,
            } => {
                output.extend_from_slice(&[1, 0]);
                output.extend_from_slice(job_id.as_bytes());
                output.push(*profile_class as u8);
                output.push(0);
                let persona = persona
                    .encode()
                    .map_err(|_| ProtocolError::InvalidCrawlPayload)?;
                let spec = encode_spec(spec)?;
                let persona_len = u16::try_from(persona.len())
                    .map_err(|_| ProtocolError::InvalidCrawlPayload)?;
                let spec_len = u32::try_from(spec.len())
                    .map_err(|_| ProtocolError::InvalidCrawlPayload)?;
                output.extend_from_slice(&persona_len.to_le_bytes());
                output.extend_from_slice(&spec_len.to_le_bytes());
                output.extend_from_slice(&persona);
                output.extend_from_slice(&spec);
            }
            Self::Status { job_id } => {
                output.extend_from_slice(&[2, 0]);
                output.extend_from_slice(job_id.as_bytes());
            }
            Self::ReadEvents {
                job_id,
                cursor,
                limit,
            } => {
                output.extend_from_slice(&[3, 0]);
                output.extend_from_slice(job_id.as_bytes());
                output.extend_from_slice(&cursor.value().to_le_bytes());
                output.push(*limit);
            }
            Self::ReadShaped {
                job_id,
                schema,
                cursor,
                limit,
            } => {
                output.extend_from_slice(&[5, 0]);
                output.extend_from_slice(job_id.as_bytes());
                let schema_bytes = schema.encode()?;
                let schema_len = u32::try_from(schema_bytes.len())
                    .map_err(|_| ProtocolError::InvalidCrawlPayload)?;
                output.extend_from_slice(&schema_len.to_le_bytes());
                output.extend_from_slice(&schema_bytes);
                output.extend_from_slice(&cursor.value().to_le_bytes());
                output.extend_from_slice(&limit.to_le_bytes());
            }
            Self::Cancel { job_id } => {
                output.extend_from_slice(&[4, 0]);
                output.extend_from_slice(job_id.as_bytes());
            }
        }
        ensure_payload_bound(&output)?;
        Ok(output)
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        ensure_payload_bound(payload)?;
        let mut input = Input::new(payload);
        if input.bytes(4)? != CRAWL_REQUEST_MAGIC
            || input.u16()? != CRAWL_REQUEST_SCHEMA_VERSION
        {
            return Err(ProtocolError::InvalidCrawlPayload);
        }
        let operation = input.u8()?;
        if input.u8()? != 0 {
            return Err(ProtocolError::InvalidCrawlPayload);
        }
        let request = match operation {
            1 => {
                let job_id = input.job_id()?;
                let profile_class = ProfileClass::from_wire(input.u8()?)
                    .map_err(|_| ProtocolError::InvalidCrawlPayload)?;
                if input.u8()? != 0 {
                    return Err(ProtocolError::InvalidCrawlPayload);
                }
                let persona_len = usize::from(input.u16()?);
                let spec_len = usize::try_from(input.u32()?)
                    .map_err(|_| ProtocolError::InvalidCrawlPayload)?;
                let (persona, consumed) = BrowserPersona::decode(input.bytes(persona_len)?)
                    .map_err(|_| ProtocolError::InvalidCrawlPayload)?;
                if consumed != persona_len {
                    return Err(ProtocolError::InvalidCrawlPayload);
                }
                let spec = decode_spec(input.bytes(spec_len)?)?;
                Self::begin(job_id, profile_class, persona, spec)?
            }
            2 => Self::status(input.job_id()?)?,
            3 => Self::read_events(
                input.job_id()?,
                CrawlCursor::new(input.u64()?),
                input.u8()?,
            )?,
            4 => Self::cancel(input.job_id()?)?,
            5 => {
                let job_id = input.job_id()?;
                let schema_len = usize::try_from(input.u32()?)
                    .map_err(|_| ProtocolError::InvalidCrawlPayload)?;
                let schema = OutputSchema::decode(input.bytes(schema_len)?)?;
                let cursor = ShapeCursor::new(input.u64()?);
                let limit = input.u16()?;
                Self::read_shaped(job_id, schema, cursor, limit)?
            }
            _ => return Err(ProtocolError::InvalidCrawlPayload),
        };
        if !input.is_empty() {
            return Err(ProtocolError::InvalidCrawlPayload);
        }
        Ok(request)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrawlPhase {
    Pending,
    Running,
    Succeeded,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrawlStatus {
    job_id: CrawlJobId,
    phase: CrawlPhase,
    discovered: u32,
    queued: u32,
    in_flight: u32,
    succeeded: u32,
    failed: u32,
    retried: u32,
    last_cursor: CrawlCursor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrawlCounts {
    pub discovered: u32,
    pub queued: u32,
    pub in_flight: u32,
    pub succeeded: u32,
    pub failed: u32,
    pub retried: u32,
}

impl CrawlCounts {
    pub const fn new(
        discovered: u32,
        queued: u32,
        in_flight: u32,
        succeeded: u32,
        failed: u32,
        retried: u32,
    ) -> Self {
        Self {
            discovered,
            queued,
            in_flight,
            succeeded,
            failed,
            retried,
        }
    }
}

impl CrawlStatus {
    pub fn new(
        job_id: CrawlJobId,
        phase: CrawlPhase,
        counts: CrawlCounts,
        last_cursor: CrawlCursor,
    ) -> Result<Self, ProtocolError> {
        let status = Self {
            job_id,
            phase,
            discovered: counts.discovered,
            queued: counts.queued,
            in_flight: counts.in_flight,
            succeeded: counts.succeeded,
            failed: counts.failed,
            retried: counts.retried,
            last_cursor,
        };
        status.validate()?;
        Ok(status)
    }

    pub fn job_id(&self) -> CrawlJobId {
        self.job_id
    }

    pub fn phase(&self) -> CrawlPhase {
        self.phase
    }

    pub fn discovered(&self) -> u32 {
        self.discovered
    }

    pub fn queued(&self) -> u32 {
        self.queued
    }

    pub fn in_flight(&self) -> u32 {
        self.in_flight
    }

    pub fn succeeded(&self) -> u32 {
        self.succeeded
    }

    pub fn failed(&self) -> u32 {
        self.failed
    }

    pub fn retried(&self) -> u32 {
        self.retried
    }

    pub fn last_cursor(&self) -> CrawlCursor {
        self.last_cursor
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        CrawlJobId::new(*self.job_id.as_bytes())?;
        let accounted = self
            .queued
            .checked_add(self.in_flight)
            .and_then(|value| value.checked_add(self.succeeded))
            .and_then(|value| value.checked_add(self.failed))
            .ok_or(ProtocolError::InvalidCrawlPayload)?;
        if self.discovered > MAX_CRAWL_PAGES
            || accounted != self.discovered
            || self.retried > MAX_CRAWL_PAGES.saturating_mul(MAX_CRAWL_RETRIES)
        {
            return Err(ProtocolError::InvalidCrawlPayload);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageArtifact {
    collection_id: CollectionId,
    html: ArtifactRef,
}

impl PageArtifact {
    pub fn new(
        collection_id: CollectionId,
        html: ArtifactRef,
    ) -> Result<Self, ProtocolError> {
        let page = Self {
            collection_id,
            html,
        };
        page.validate()?;
        Ok(page)
    }

    pub fn collection_id(&self) -> CollectionId {
        self.collection_id
    }

    pub fn html(&self) -> &ArtifactRef {
        &self.html
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        CollectionId::new(*self.collection_id.as_bytes())
            .map_err(|_| ProtocolError::InvalidCrawlPayload)?;
        ArtifactRef::new(
            *self.html.sha256(),
            self.html.len(),
            self.html.media_type(),
        )
        .map_err(|_| ProtocolError::InvalidCrawlPayload)?;
        if self.html.media_type() != ArtifactMediaType::TextHtmlUtf8 {
            return Err(ProtocolError::InvalidCrawlPayload);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrawlEventKind {
    JobStarted,
    UrlQueued,
    PageStarted,
    PageSucceeded,
    PageFailed,
    RetryScheduled,
    Recovered,
    JobSucceeded,
    JobFailed,
    JobCancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrawlEvent {
    cursor: CrawlCursor,
    timestamp_unix_ms: u64,
    kind: CrawlEventKind,
    canonical_url: Option<String>,
    depth: u32,
    attempt: u32,
    page: Option<PageArtifact>,
    http_status: Option<u16>,
    detail: Option<String>,
}

impl CrawlEvent {
    pub fn new(
        cursor: CrawlCursor,
        timestamp_unix_ms: u64,
        kind: CrawlEventKind,
        canonical_url: Option<String>,
        depth: u32,
        attempt: u32,
        page: Option<PageArtifact>,
    ) -> Result<Self, ProtocolError> {
        let event = Self {
            cursor,
            timestamp_unix_ms,
            kind,
            canonical_url,
            depth,
            attempt,
            page,
            http_status: None,
            detail: None,
        };
        event.validate()?;
        Ok(event)
    }

    pub fn with_outcome(
        mut self,
        http_status: Option<u16>,
        detail: Option<String>,
    ) -> Result<Self, ProtocolError> {
        self.http_status = http_status;
        self.detail = detail;
        self.validate()?;
        Ok(self)
    }

    pub fn cursor(&self) -> CrawlCursor {
        self.cursor
    }

    pub fn timestamp_unix_ms(&self) -> u64 {
        self.timestamp_unix_ms
    }

    pub fn kind(&self) -> CrawlEventKind {
        self.kind
    }

    pub fn canonical_url(&self) -> Option<&str> {
        self.canonical_url.as_deref()
    }

    pub fn depth(&self) -> u32 {
        self.depth
    }

    pub fn attempt(&self) -> u32 {
        self.attempt
    }

    pub fn page(&self) -> Option<&PageArtifact> {
        self.page.as_ref()
    }

    pub fn http_status(&self) -> Option<u16> {
        self.http_status
    }

    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.cursor == CrawlCursor::START || self.depth > MAX_CRAWL_DEPTH {
            return Err(ProtocolError::InvalidCrawlPayload);
        }
        if let Some(page) = &self.page {
            page.validate()?;
        }
        if self.http_status.is_some_and(|status| !(100..=599).contains(&status))
            || (self.http_status.is_some() && self.kind != CrawlEventKind::PageSucceeded)
        {
            return Err(ProtocolError::InvalidCrawlPayload);
        }
        if let Some(detail) = &self.detail {
            if detail.trim().is_empty()
                || detail.len() > MAX_CRAWL_EVENT_DETAIL_BYTES
                || detail.chars().any(char::is_control)
                || !matches!(
                    self.kind,
                    CrawlEventKind::PageFailed
                        | CrawlEventKind::RetryScheduled
                        | CrawlEventKind::Recovered
                        | CrawlEventKind::JobFailed
                )
            {
                return Err(ProtocolError::InvalidCrawlPayload);
            }
        }
        let is_job_event = matches!(
            self.kind,
            CrawlEventKind::JobStarted
                | CrawlEventKind::JobSucceeded
                | CrawlEventKind::JobFailed
                | CrawlEventKind::JobCancelled
        );
        if is_job_event {
            if self.canonical_url.is_some()
                || self.depth != 0
                || self.attempt != 0
                || self.page.is_some()
                || self.http_status.is_some()
                || (self.detail.is_some() && self.kind != CrawlEventKind::JobFailed)
            {
                return Err(ProtocolError::InvalidCrawlPayload);
            }
            return Ok(());
        }
        let url = self
            .canonical_url
            .as_deref()
            .ok_or(ProtocolError::InvalidCrawlPayload)?;
        validate_canonical_url(url)?;
        let valid_attempt = match self.kind {
            CrawlEventKind::UrlQueued => self.attempt == 0,
            CrawlEventKind::PageStarted
            | CrawlEventKind::PageSucceeded
            | CrawlEventKind::PageFailed
            | CrawlEventKind::RetryScheduled
            | CrawlEventKind::Recovered => {
                (1..=MAX_CRAWL_RETRIES + 1).contains(&self.attempt)
            }
            _ => false,
        };
        if !valid_attempt
            || (self.kind == CrawlEventKind::PageSucceeded && self.page.is_none())
            || (self.page.is_some() && self.kind != CrawlEventKind::PageSucceeded)
        {
            return Err(ProtocolError::InvalidCrawlPayload);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        let mut output = Vec::new();
        output.extend_from_slice(&CRAWL_EVENT_MAGIC);
        output.extend_from_slice(&CRAWL_EVENT_SCHEMA_VERSION.to_le_bytes());
        output.extend_from_slice(&self.cursor.value().to_le_bytes());
        output.extend_from_slice(&self.timestamp_unix_ms.to_le_bytes());
        output.push(event_kind_to_wire(self.kind));
        let flags = u8::from(self.page.is_some())
            | (u8::from(self.http_status.is_some()) << 1)
            | (u8::from(self.detail.is_some()) << 2);
        output.push(flags);
        output.extend_from_slice(&self.depth.to_le_bytes());
        output.extend_from_slice(&self.attempt.to_le_bytes());
        let url = self.canonical_url.as_deref().unwrap_or_default();
        encode_string_u16(&mut output, url)?;
        if let Some(http_status) = self.http_status {
            output.extend_from_slice(&http_status.to_le_bytes());
        }
        if let Some(detail) = &self.detail {
            encode_bounded_string_u16(&mut output, detail, MAX_CRAWL_EVENT_DETAIL_BYTES)?;
        }
        if let Some(page) = &self.page {
            encode_page_artifact(&mut output, page);
        }
        ensure_payload_bound(&output)?;
        Ok(output)
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        ensure_payload_bound(payload)?;
        let mut input = Input::new(payload);
        if input.bytes(4)? != CRAWL_EVENT_MAGIC
            || input.u16()? != CRAWL_EVENT_SCHEMA_VERSION
        {
            return Err(ProtocolError::InvalidCrawlPayload);
        }
        let cursor = CrawlCursor::new(input.u64()?);
        let timestamp_unix_ms = input.u64()?;
        let kind = event_kind_from_wire(input.u8()?)?;
        let flags = input.u8()?;
        if flags & !0b111 != 0 {
            return Err(ProtocolError::InvalidCrawlPayload);
        }
        let depth = input.u32()?;
        let attempt = input.u32()?;
        let url = input.string_u16(MAX_CRAWL_URL_BYTES)?;
        let canonical_url = if url.is_empty() { None } else { Some(url) };
        let http_status = if flags & 0b010 != 0 {
            Some(input.u16()?)
        } else {
            None
        };
        let detail = if flags & 0b100 != 0 {
            Some(input.string_u16(MAX_CRAWL_EVENT_DETAIL_BYTES)?)
        } else {
            None
        };
        let page = if flags & 1 == 1 {
            Some(decode_page_artifact(&mut input)?)
        } else {
            None
        };
        if !input.is_empty() {
            return Err(ProtocolError::InvalidCrawlPayload);
        }
        Self::new(
            cursor,
            timestamp_unix_ms,
            kind,
            canonical_url,
            depth,
            attempt,
            page,
        )?
        .with_outcome(http_status, detail)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrawlEventPage {
    job_id: CrawlJobId,
    events: Vec<CrawlEvent>,
    next_cursor: CrawlCursor,
    complete: bool,
}

impl CrawlEventPage {
    pub fn new(
        job_id: CrawlJobId,
        events: Vec<CrawlEvent>,
        next_cursor: CrawlCursor,
        complete: bool,
    ) -> Result<Self, ProtocolError> {
        let page = Self {
            job_id,
            events,
            next_cursor,
            complete,
        };
        page.validate()?;
        Ok(page)
    }

    pub fn job_id(&self) -> CrawlJobId {
        self.job_id
    }

    pub fn events(&self) -> &[CrawlEvent] {
        &self.events
    }

    pub fn next_cursor(&self) -> CrawlCursor {
        self.next_cursor
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        CrawlJobId::new(*self.job_id.as_bytes())?;
        if self.events.len() > MAX_CRAWL_EVENTS
            || !self.events.windows(2).all(|pair| {
                pair[0]
                    .cursor
                    .value()
                    .checked_add(1)
                    .is_some_and(|next| next == pair[1].cursor.value())
            })
            || self
                .events
                .last()
                .is_some_and(|event| event.cursor != self.next_cursor)
        {
            return Err(ProtocolError::InvalidCrawlPayload);
        }
        for event in &self.events {
            event.validate()?;
        }
        let encoded_len = self.events.iter().try_fold(36usize, |total, event| {
            total
                .checked_add(4)
                .and_then(|value| value.checked_add(event.encode().ok()?.len()))
        });
        if match encoded_len {
            Some(len) => len > MAX_REQUEST_BYTES,
            None => true,
        } {
            return Err(ProtocolError::InvalidCrawlPayload);
        }
        Ok(())
    }

    pub fn validate_after(&self, cursor: CrawlCursor) -> Result<(), ProtocolError> {
        self.validate()?;
        match self.events.first() {
            Some(first) => {
                let expected = cursor
                    .value()
                    .checked_add(1)
                    .ok_or(ProtocolError::InvalidCrawlPayload)?;
                if first.cursor().value() != expected {
                    return Err(ProtocolError::InvalidCrawlPayload);
                }
            }
            None if self.next_cursor != cursor => {
                return Err(ProtocolError::InvalidCrawlPayload);
            }
            None => {}
        }
        Ok(())
    }
}

// `PartialEq`-only (not `Eq`): `ShapedRows` carries a `RowPage`, whose cells
// may be `Value::Real(f64)` — the same reason `CrawlRequest` (which carries
// `OutputSchema`, also `f64`-bearing) is `PartialEq`-only.
#[derive(Debug, Clone, PartialEq)]
pub enum CrawlResponse {
    Accepted { job_id: CrawlJobId },
    Status(CrawlStatus),
    Events(CrawlEventPage),
    /// One page of declarative output-shaping rows over a crawl job's
    /// succeeded pages (Phase C, axis 7).
    ShapedRows(RowPage),
    Cancelled { job_id: CrawlJobId },
}

impl CrawlResponse {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Accepted { job_id } | Self::Cancelled { job_id } => {
                CrawlJobId::new(*job_id.as_bytes()).map(|_| ())
            }
            Self::Status(status) => status.validate(),
            Self::Events(page) => page.validate(),
            // `RowPage`'s fields are private to `shape.rs`, so a `RowPage`
            // can only reach here through `RowPage::new`/`RowPage::decode`,
            // both of which already validate it — nothing further to check.
            Self::ShapedRows(_) => Ok(()),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        let mut output = Vec::new();
        output.extend_from_slice(&CRAWL_RESPONSE_MAGIC);
        output.extend_from_slice(&CRAWL_RESPONSE_SCHEMA_VERSION.to_le_bytes());
        match self {
            Self::Accepted { job_id } => {
                output.extend_from_slice(&[1, 0]);
                output.extend_from_slice(job_id.as_bytes());
            }
            Self::Status(status) => {
                output.extend_from_slice(&[2, 0]);
                encode_status(&mut output, status);
            }
            Self::Events(page) => {
                output.extend_from_slice(&[3, 0]);
                output.extend_from_slice(page.job_id.as_bytes());
                output.extend_from_slice(&page.next_cursor.value().to_le_bytes());
                output.push(u8::from(page.complete));
                output.push(0);
                output.extend_from_slice(&(page.events.len() as u16).to_le_bytes());
                for event in &page.events {
                    let event = event.encode()?;
                    let len = u32::try_from(event.len())
                        .map_err(|_| ProtocolError::InvalidCrawlPayload)?;
                    output.extend_from_slice(&len.to_le_bytes());
                    output.extend_from_slice(&event);
                }
            }
            Self::ShapedRows(page) => {
                output.extend_from_slice(&[5, 0]);
                let page_bytes = page.encode()?;
                let page_len = u32::try_from(page_bytes.len())
                    .map_err(|_| ProtocolError::InvalidCrawlPayload)?;
                output.extend_from_slice(&page_len.to_le_bytes());
                output.extend_from_slice(&page_bytes);
            }
            Self::Cancelled { job_id } => {
                output.extend_from_slice(&[4, 0]);
                output.extend_from_slice(job_id.as_bytes());
            }
        }
        ensure_payload_bound(&output)?;
        Ok(output)
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        ensure_payload_bound(payload)?;
        let mut input = Input::new(payload);
        if input.bytes(4)? != CRAWL_RESPONSE_MAGIC
            || input.u16()? != CRAWL_RESPONSE_SCHEMA_VERSION
        {
            return Err(ProtocolError::InvalidCrawlPayload);
        }
        let operation = input.u8()?;
        if input.u8()? != 0 {
            return Err(ProtocolError::InvalidCrawlPayload);
        }
        let response = match operation {
            1 => Self::Accepted {
                job_id: input.job_id()?,
            },
            2 => Self::Status(decode_status(&mut input)?),
            3 => {
                let job_id = input.job_id()?;
                let next_cursor = CrawlCursor::new(input.u64()?);
                let complete = match input.u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err(ProtocolError::InvalidCrawlPayload),
                };
                if input.u8()? != 0 {
                    return Err(ProtocolError::InvalidCrawlPayload);
                }
                let count = usize::from(input.u16()?);
                if count > MAX_CRAWL_EVENTS {
                    return Err(ProtocolError::InvalidCrawlPayload);
                }
                let mut events = Vec::with_capacity(count);
                for _ in 0..count {
                    let len = usize::try_from(input.u32()?)
                        .map_err(|_| ProtocolError::InvalidCrawlPayload)?;
                    events.push(CrawlEvent::decode(input.bytes(len)?)?);
                }
                Self::Events(CrawlEventPage::new(
                    job_id,
                    events,
                    next_cursor,
                    complete,
                )?)
            }
            4 => Self::Cancelled {
                job_id: input.job_id()?,
            },
            5 => {
                let page_len = usize::try_from(input.u32()?)
                    .map_err(|_| ProtocolError::InvalidCrawlPayload)?;
                Self::ShapedRows(RowPage::decode(input.bytes(page_len)?)?)
            }
            _ => return Err(ProtocolError::InvalidCrawlPayload),
        };
        if !input.is_empty() {
            return Err(ProtocolError::InvalidCrawlPayload);
        }
        response.validate()?;
        Ok(response)
    }
}

fn encode_spec(spec: &CrawlSpec) -> Result<Vec<u8>, ProtocolError> {
    spec.validate()?;
    let mut output = Vec::new();
    output.extend_from_slice(&(spec.seeds.len() as u16).to_le_bytes());
    output.extend_from_slice(&(spec.allowed_origins.len() as u16).to_le_bytes());
    output.extend_from_slice(&spec.max_pages.to_le_bytes());
    output.extend_from_slice(&spec.max_depth.to_le_bytes());
    output.extend_from_slice(&spec.max_retries.to_le_bytes());
    for seed in &spec.seeds {
        encode_string_u16(&mut output, seed)?;
    }
    for origin in &spec.allowed_origins {
        encode_string_u16(&mut output, origin)?;
    }
    ensure_payload_bound(&output)?;
    Ok(output)
}

fn encoded_spec_len(spec: &CrawlSpec) -> Result<usize, ProtocolError> {
    spec.seeds
        .iter()
        .chain(&spec.allowed_origins)
        .try_fold(16usize, |total, value| {
            total
                .checked_add(2)
                .and_then(|value_len| value_len.checked_add(value.len()))
                .ok_or(ProtocolError::InvalidCrawlPayload)
        })
}

fn decode_spec(payload: &[u8]) -> Result<CrawlSpec, ProtocolError> {
    ensure_payload_bound(payload)?;
    let mut input = Input::new(payload);
    let seed_count = usize::from(input.u16()?);
    let origin_count = usize::from(input.u16()?);
    if seed_count == 0
        || seed_count > MAX_CRAWL_SEEDS
        || origin_count == 0
        || origin_count > MAX_CRAWL_ALLOWED_ORIGINS
    {
        return Err(ProtocolError::InvalidCrawlPayload);
    }
    let max_pages = input.u32()?;
    let max_depth = input.u32()?;
    let max_retries = input.u32()?;
    let mut seeds = Vec::with_capacity(seed_count);
    for _ in 0..seed_count {
        seeds.push(input.string_u16(MAX_CRAWL_URL_BYTES)?);
    }
    let mut allowed_origins = Vec::with_capacity(origin_count);
    for _ in 0..origin_count {
        allowed_origins.push(input.string_u16(MAX_CRAWL_URL_BYTES)?);
    }
    if !input.is_empty() {
        return Err(ProtocolError::InvalidCrawlPayload);
    }
    let spec = CrawlSpec {
        seeds,
        allowed_origins,
        max_pages,
        max_depth,
        max_retries,
    };
    spec.validate()?;
    Ok(spec)
}

fn encode_status(output: &mut Vec<u8>, status: &CrawlStatus) {
    output.extend_from_slice(status.job_id.as_bytes());
    output.push(phase_to_wire(status.phase));
    output.push(0);
    output.extend_from_slice(&status.discovered.to_le_bytes());
    output.extend_from_slice(&status.queued.to_le_bytes());
    output.extend_from_slice(&status.in_flight.to_le_bytes());
    output.extend_from_slice(&status.succeeded.to_le_bytes());
    output.extend_from_slice(&status.failed.to_le_bytes());
    output.extend_from_slice(&status.retried.to_le_bytes());
    output.extend_from_slice(&status.last_cursor.value().to_le_bytes());
}

fn decode_status(input: &mut Input<'_>) -> Result<CrawlStatus, ProtocolError> {
    let job_id = input.job_id()?;
    let phase = phase_from_wire(input.u8()?)?;
    if input.u8()? != 0 {
        return Err(ProtocolError::InvalidCrawlPayload);
    }
    CrawlStatus::new(
        job_id,
        phase,
        CrawlCounts::new(
            input.u32()?,
            input.u32()?,
            input.u32()?,
            input.u32()?,
            input.u32()?,
            input.u32()?,
        ),
        CrawlCursor::new(input.u64()?),
    )
}

fn encode_page_artifact(output: &mut Vec<u8>, page: &PageArtifact) {
    output.extend_from_slice(page.collection_id.as_bytes());
    output.extend_from_slice(page.html.sha256());
    output.extend_from_slice(&page.html.len().to_le_bytes());
    output.extend_from_slice(&[1, 0]);
}

fn decode_page_artifact(input: &mut Input<'_>) -> Result<PageArtifact, ProtocolError> {
    let collection_id = input.collection_id()?;
    let sha256 = input.array_32()?;
    let len = input.u64()?;
    if input.u8()? != 1 || input.u8()? != 0 {
        return Err(ProtocolError::InvalidCrawlPayload);
    }
    let html = ArtifactRef::new(sha256, len, ArtifactMediaType::TextHtmlUtf8)
        .map_err(|_| ProtocolError::InvalidCrawlPayload)?;
    PageArtifact::new(collection_id, html)
}

fn phase_to_wire(phase: CrawlPhase) -> u8 {
    match phase {
        CrawlPhase::Pending => 1,
        CrawlPhase::Running => 2,
        CrawlPhase::Succeeded => 3,
        CrawlPhase::Failed => 4,
        CrawlPhase::Cancelled => 5,
    }
}

fn phase_from_wire(value: u8) -> Result<CrawlPhase, ProtocolError> {
    match value {
        1 => Ok(CrawlPhase::Pending),
        2 => Ok(CrawlPhase::Running),
        3 => Ok(CrawlPhase::Succeeded),
        4 => Ok(CrawlPhase::Failed),
        5 => Ok(CrawlPhase::Cancelled),
        _ => Err(ProtocolError::InvalidCrawlPayload),
    }
}

fn event_kind_to_wire(kind: CrawlEventKind) -> u8 {
    match kind {
        CrawlEventKind::JobStarted => 1,
        CrawlEventKind::UrlQueued => 2,
        CrawlEventKind::PageStarted => 3,
        CrawlEventKind::PageSucceeded => 4,
        CrawlEventKind::PageFailed => 5,
        CrawlEventKind::RetryScheduled => 6,
        CrawlEventKind::Recovered => 7,
        CrawlEventKind::JobSucceeded => 8,
        CrawlEventKind::JobFailed => 9,
        CrawlEventKind::JobCancelled => 10,
    }
}

fn event_kind_from_wire(value: u8) -> Result<CrawlEventKind, ProtocolError> {
    match value {
        1 => Ok(CrawlEventKind::JobStarted),
        2 => Ok(CrawlEventKind::UrlQueued),
        3 => Ok(CrawlEventKind::PageStarted),
        4 => Ok(CrawlEventKind::PageSucceeded),
        5 => Ok(CrawlEventKind::PageFailed),
        6 => Ok(CrawlEventKind::RetryScheduled),
        7 => Ok(CrawlEventKind::Recovered),
        8 => Ok(CrawlEventKind::JobSucceeded),
        9 => Ok(CrawlEventKind::JobFailed),
        10 => Ok(CrawlEventKind::JobCancelled),
        _ => Err(ProtocolError::InvalidCrawlPayload),
    }
}

fn validate_canonical_url(value: &str) -> Result<(), ProtocolError> {
    if value.is_empty()
        || value.len() > MAX_CRAWL_URL_BYTES
        || value.contains('#')
        || value.bytes().any(|byte| !byte.is_ascii())
        || value.chars().any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(ProtocolError::InvalidCrawlPayload);
    }
    let origin = canonical_url_origin(value)?;
    validate_exact_origin(origin)?;
    let remainder = &value[origin.len()..];
    if !remainder.starts_with('/')
        || remainder.contains("/./")
        || remainder.contains("/../")
        || remainder.ends_with("/.")
        || remainder.ends_with("/..")
        || remainder.ends_with('?')
    {
        return Err(ProtocolError::InvalidCrawlPayload);
    }
    Ok(())
}

fn validate_exact_origin(value: &str) -> Result<(), ProtocolError> {
    if value.is_empty()
        || value.len() > MAX_CRAWL_URL_BYTES
        || value.chars().any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(ProtocolError::InvalidCrawlPayload);
    }
    let (scheme, authority) = split_scheme_authority(value)?;
    if authority.is_empty()
        || authority.contains('@')
        || authority.bytes().any(|byte| !byte.is_ascii())
        || authority.to_ascii_lowercase() != authority
    {
        return Err(ProtocolError::InvalidCrawlPayload);
    }
    let port = validate_authority(authority)?;
    if matches!((scheme, port), ("http", Some(80)) | ("https", Some(443))) {
        return Err(ProtocolError::InvalidCrawlPayload);
    }
    Ok(())
}

fn canonical_url_origin(value: &str) -> Result<&str, ProtocolError> {
    let prefix_len = if value.starts_with("https://") {
        8
    } else if value.starts_with("http://") {
        7
    } else {
        return Err(ProtocolError::InvalidCrawlPayload);
    };
    let authority_len = value[prefix_len..]
        .find(['/', '?', '#'])
        .unwrap_or(value.len() - prefix_len);
    let end = prefix_len
        .checked_add(authority_len)
        .ok_or(ProtocolError::InvalidCrawlPayload)?;
    value.get(..end).ok_or(ProtocolError::InvalidCrawlPayload)
}

fn split_scheme_authority(value: &str) -> Result<(&str, &str), ProtocolError> {
    if let Some(authority) = value.strip_prefix("https://") {
        if authority.contains('/') || authority.contains('?') || authority.contains('#') {
            return Err(ProtocolError::InvalidCrawlPayload);
        }
        return Ok(("https", authority));
    }
    if let Some(authority) = value.strip_prefix("http://") {
        if authority.contains('/') || authority.contains('?') || authority.contains('#') {
            return Err(ProtocolError::InvalidCrawlPayload);
        }
        return Ok(("http", authority));
    }
    Err(ProtocolError::InvalidCrawlPayload)
}

fn validate_authority(authority: &str) -> Result<Option<u16>, ProtocolError> {
    let (host, port) = if authority.starts_with('[') {
        let close = authority
            .find(']')
            .ok_or(ProtocolError::InvalidCrawlPayload)?;
        let host = &authority[..=close];
        let suffix = &authority[close + 1..];
        let port = if suffix.is_empty() {
            None
        } else {
            Some(
                suffix
                    .strip_prefix(':')
                    .ok_or(ProtocolError::InvalidCrawlPayload)?,
            )
        };
        let address = host[1..host.len() - 1]
            .parse::<Ipv6Addr>()
            .map_err(|_| ProtocolError::InvalidCrawlPayload)?;
        if format!("[{address}]") != host {
            return Err(ProtocolError::InvalidCrawlPayload);
        }
        (host, port)
    } else {
        if authority.matches(':').count() > 1 {
            return Err(ProtocolError::InvalidCrawlPayload);
        }
        match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    if host.is_empty() || (!host.starts_with('[') && !valid_canonical_host(host)) {
        return Err(ProtocolError::InvalidCrawlPayload);
    }
    port.map(|value| {
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(ProtocolError::InvalidCrawlPayload);
        }
        let port = value
            .parse::<u16>()
            .map_err(|_| ProtocolError::InvalidCrawlPayload)?;
        if port == 0 || port.to_string() != value {
            return Err(ProtocolError::InvalidCrawlPayload);
        }
        Ok(port)
    })
    .transpose()
}

fn valid_canonical_host(host: &str) -> bool {
    if host.bytes().all(|byte| byte.is_ascii_digit() || byte == b'.') {
        return host
            .parse::<Ipv4Addr>()
            .is_ok_and(|address| address.to_string() == host);
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
            })
    })
}

fn strictly_increasing_strings(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn encode_string_u16(output: &mut Vec<u8>, value: &str) -> Result<(), ProtocolError> {
    encode_bounded_string_u16(output, value, MAX_CRAWL_URL_BYTES)
}

fn encode_bounded_string_u16(
    output: &mut Vec<u8>,
    value: &str,
    max_len: usize,
) -> Result<(), ProtocolError> {
    if value.len() > max_len {
        return Err(ProtocolError::InvalidCrawlPayload);
    }
    let len = u16::try_from(value.len())
        .map_err(|_| ProtocolError::InvalidCrawlPayload)?;
    output.extend_from_slice(&len.to_le_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn ensure_payload_bound(payload: &[u8]) -> Result<(), ProtocolError> {
    if payload.len() > MAX_REQUEST_BYTES {
        return Err(ProtocolError::InvalidCrawlPayload);
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

    fn bytes(&mut self, len: usize) -> Result<&'a [u8], ProtocolError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(ProtocolError::InvalidCrawlPayload)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ProtocolError::InvalidCrawlPayload)?;
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
            .map_err(|_| ProtocolError::InvalidCrawlPayload)
    }

    fn job_id(&mut self) -> Result<CrawlJobId, ProtocolError> {
        CrawlJobId::new(
            self.bytes(16)?
                .try_into()
                .map_err(|_| ProtocolError::InvalidCrawlPayload)?,
        )
    }

    fn collection_id(&mut self) -> Result<CollectionId, ProtocolError> {
        CollectionId::new(
            self.bytes(16)?
                .try_into()
                .map_err(|_| ProtocolError::InvalidCrawlPayload)?,
        )
        .map_err(|_| ProtocolError::InvalidCrawlPayload)
    }

    fn string_u16(&mut self, max_len: usize) -> Result<String, ProtocolError> {
        let len = usize::from(self.u16()?);
        if len > max_len {
            return Err(ProtocolError::InvalidCrawlPayload);
        }
        std::str::from_utf8(self.bytes(len)?)
            .map(str::to_owned)
            .map_err(|_| ProtocolError::InvalidCrawlPayload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shape::{
        Cardinality, Column, ColumnType, CssPick, Extractor, MetaField, OnError, Row, Value,
    };

    fn job_id() -> CrawlJobId {
        CrawlJobId::new([7; 16]).expect("job id")
    }

    fn spec() -> CrawlSpec {
        CrawlSpec::new(
            [
                "https://example.test/a",
                "https://example.test/b?q=1",
            ],
            ["https://example.test"],
            32,
            4,
            2,
        )
        .expect("crawl spec")
    }

    fn page_artifact() -> PageArtifact {
        PageArtifact::new(
            CollectionId::new([8; 16]).expect("collection id"),
            ArtifactRef::new([9; 32], 128, ArtifactMediaType::TextHtmlUtf8)
                .expect("HTML artifact"),
        )
        .expect("page artifact")
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
            Cardinality::ItemScope(".product-card".to_owned()),
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
    fn requests_round_trip_with_separate_magic_and_bounded_spec() {
        let requests = [
            CrawlRequest::begin(
                job_id(),
                ProfileClass::Public,
                BrowserPersona::desktop_default(),
                spec(),
            )
            .expect("begin"),
            CrawlRequest::status(job_id()).expect("status"),
            CrawlRequest::read_events(job_id(), CrawlCursor::new(11), 64)
                .expect("events"),
            CrawlRequest::cancel(job_id()).expect("cancel"),
        ];
        for request in requests {
            let encoded = request.encode().expect("encode request");
            assert_eq!(&encoded[..4], b"D2WQ");
            assert_eq!(CrawlRequest::decode(&encoded).unwrap(), request);
        }
        assert!(CrawlJobId::new([0; 16]).is_err());
        assert!(CrawlRequest::read_events(job_id(), CrawlCursor::START, 0).is_err());
    }

    #[test]
    fn read_shaped_request_round_trips_page_level_and_item_scope_schemas() {
        for schema in [page_level_schema(), item_scope_schema()] {
            let request = CrawlRequest::read_shaped(
                job_id(),
                schema.clone(),
                ShapeCursor::new(3),
                256,
            )
            .expect("read shaped request");
            let encoded = request.encode().expect("encode read shaped");
            assert_eq!(&encoded[..4], b"D2WQ");
            assert_eq!(CrawlRequest::decode(&encoded).unwrap(), request);
            let CrawlRequest::ReadShaped {
                job_id: decoded_id,
                schema: decoded_schema,
                cursor,
                limit,
            } = CrawlRequest::decode(&encoded).unwrap()
            else {
                panic!("expected ReadShaped request");
            };
            assert_eq!(decoded_id, job_id());
            assert_eq!(decoded_schema, schema);
            assert_eq!(cursor, ShapeCursor::new(3));
            assert_eq!(limit, 256);
        }
    }

    #[test]
    fn read_shaped_request_rejects_zero_and_oversized_limit() {
        assert!(CrawlRequest::read_shaped(
            job_id(),
            page_level_schema(),
            ShapeCursor::START,
            0,
        )
        .is_err());
        assert!(CrawlRequest::read_shaped(
            job_id(),
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
        let response = CrawlResponse::ShapedRows(incomplete);
        let encoded = response.encode().expect("encode shaped rows");
        assert_eq!(&encoded[..4], b"D2WP");
        assert_eq!(CrawlResponse::decode(&encoded).unwrap(), response);
        let CrawlResponse::ShapedRows(decoded) = CrawlResponse::decode(&encoded).unwrap()
        else {
            panic!("expected ShapedRows response");
        };
        assert_eq!(decoded.next_cursor(), Some(ShapeCursor::new(1)));
        assert!(!decoded.is_complete());

        let complete = RowPage::new(columns, rows, None, true).expect("complete row page");
        let response = CrawlResponse::ShapedRows(complete);
        let encoded = response.encode().expect("encode complete shaped rows");
        assert_eq!(CrawlResponse::decode(&encoded).unwrap(), response);
        let CrawlResponse::ShapedRows(decoded) = CrawlResponse::decode(&encoded).unwrap()
        else {
            panic!("expected ShapedRows response");
        };
        assert_eq!(decoded.next_cursor(), None);
        assert!(decoded.is_complete());
    }

    #[test]
    fn spec_rejects_noncanonical_or_out_of_scope_urls_and_bounds() {
        assert!(CrawlSpec::new(
            ["https://EXAMPLE.test/a"],
            ["https://example.test"],
            1,
            0,
            0,
        )
        .is_err());
        assert!(CrawlSpec::new(
            ["https://other.test/a"],
            ["https://example.test"],
            1,
            0,
            0,
        )
        .is_err());
        assert!(CrawlSpec::new(
            ["https://example.test/a#fragment"],
            ["https://example.test"],
            1,
            0,
            0,
        )
        .is_err());
        assert!(CrawlSpec::new(
            ["https://example.test/a"],
            ["https://example.test"],
            0,
            0,
            0,
        )
        .is_err());
    }

    #[test]
    fn lifecycle_events_and_responses_round_trip() {
        let started = CrawlEvent::new(
            CrawlCursor::new(1),
            1_784_500_000_000,
            CrawlEventKind::JobStarted,
            None,
            0,
            0,
            None,
        )
        .expect("started");
        let succeeded = CrawlEvent::new(
            CrawlCursor::new(2),
            1_784_500_000_100,
            CrawlEventKind::PageSucceeded,
            Some("https://example.test/a".to_owned()),
            1,
            1,
            Some(page_artifact()),
        )
        .and_then(|event| event.with_outcome(Some(200), None))
        .expect("succeeded");
        let failed = CrawlEvent::new(
            CrawlCursor::new(3),
            1_784_500_000_200,
            CrawlEventKind::PageFailed,
            Some("https://example.test/b?q=1".to_owned()),
            1,
            1,
            None,
        )
        .and_then(|event| {
            event.with_outcome(None, Some("navigation timeout".to_owned()))
        })
        .expect("failed");
        let recovered = CrawlEvent::new(
            CrawlCursor::new(4),
            1_784_500_000_300,
            CrawlEventKind::Recovered,
            Some("https://example.test/b?q=1".to_owned()),
            1,
            1,
            None,
        )
        .and_then(|event| event.with_outcome(None, Some("lease recovery".to_owned())))
        .expect("recovered");
        let job_failed = CrawlEvent::new(
            CrawlCursor::new(5),
            1_784_500_000_400,
            CrawlEventKind::JobFailed,
            None,
            0,
            0,
            None,
        )
        .and_then(|event| {
            event.with_outcome(None, Some("station unavailable".to_owned()))
        })
        .expect("job failed");
        for event in [&started, &succeeded, &failed, &recovered, &job_failed] {
            let encoded = event.encode().expect("encode event");
            assert_eq!(&encoded[..4], b"D2WE");
            assert_eq!(CrawlEvent::decode(&encoded).unwrap(), event.clone());
        }
        assert_eq!(succeeded.http_status(), Some(200));
        assert_eq!(failed.detail(), Some("navigation timeout"));
        assert_eq!(job_failed.detail(), Some("station unavailable"));
        let page = CrawlEventPage::new(
            job_id(),
            vec![started, succeeded],
            CrawlCursor::new(2),
            true,
        )
        .expect("event page");
        let status = CrawlStatus::new(
            job_id(),
            CrawlPhase::Succeeded,
            CrawlCounts::new(1, 0, 0, 1, 0, 0),
            CrawlCursor::new(2),
        )
        .expect("status");
        for response in [
            CrawlResponse::Accepted { job_id: job_id() },
            CrawlResponse::Status(status),
            CrawlResponse::Events(page),
            CrawlResponse::Cancelled { job_id: job_id() },
        ] {
            let encoded = response.encode().expect("encode response");
            assert_eq!(&encoded[..4], b"D2WP");
            assert_eq!(CrawlResponse::decode(&encoded).unwrap(), response);
        }
    }

    #[test]
    fn malformed_tags_flags_lengths_and_event_shapes_fail_closed() {
        let mut request = CrawlRequest::status(job_id()).unwrap().encode().unwrap();
        request[7] = 1;
        assert!(CrawlRequest::decode(&request).is_err());

        let event = CrawlEvent::new(
            CrawlCursor::new(1),
            1,
            CrawlEventKind::UrlQueued,
            Some("https://example.test/".to_owned()),
            0,
            0,
            None,
        )
        .unwrap();
        let mut unknown_kind = event.encode().unwrap();
        unknown_kind[22] = u8::MAX;
        assert!(CrawlEvent::decode(&unknown_kind).is_err());
        assert!(CrawlEvent::new(
            CrawlCursor::new(2),
            1,
            CrawlEventKind::PageFailed,
            None,
            0,
            1,
            None,
        )
        .is_err());
        assert!(CrawlEvent::new(
            CrawlCursor::new(2),
            1,
            CrawlEventKind::PageFailed,
            Some("https://example.test/".to_owned()),
            0,
            1,
            Some(page_artifact()),
        )
        .is_err());
        assert!(CrawlEvent::new(
            CrawlCursor::new(3),
            1,
            CrawlEventKind::PageStarted,
            Some("https://example.test/".to_owned()),
            0,
            1,
            None,
        )
        .and_then(|event| event.with_outcome(Some(200), None))
        .is_err());
        assert!(CrawlEvent::new(
            CrawlCursor::new(3),
            1,
            CrawlEventKind::PageSucceeded,
            Some("https://example.test/".to_owned()),
            0,
            1,
            None,
        )
        .is_err());
        assert!(CrawlEvent::new(
            CrawlCursor::new(3),
            1,
            CrawlEventKind::JobFailed,
            None,
            0,
            0,
            None,
        )
        .and_then(|event| {
            event.with_outcome(
                None,
                Some("x".repeat(MAX_CRAWL_EVENT_DETAIL_BYTES + 1)),
            )
        })
        .is_err());
        assert!(CrawlEvent::new(
            CrawlCursor::new(3),
            1,
            CrawlEventKind::JobStarted,
            None,
            0,
            0,
            None,
        )
        .and_then(|event| event.with_outcome(None, Some("not allowed".to_owned())))
        .is_err());

        assert!(CrawlStatus::new(
            job_id(),
            CrawlPhase::Running,
            CrawlCounts::new(2, 1, 0, 0, 0, 0),
            CrawlCursor::START,
        )
        .is_err());

        let second = CrawlEvent::new(
            CrawlCursor::new(2),
            1,
            CrawlEventKind::JobStarted,
            None,
            0,
            0,
            None,
        )
        .unwrap();
        let fourth = CrawlEvent::new(
            CrawlCursor::new(4),
            2,
            CrawlEventKind::JobCancelled,
            None,
            0,
            0,
            None,
        )
        .unwrap();
        assert!(CrawlEventPage::new(
            job_id(),
            vec![second.clone(), fourth],
            CrawlCursor::new(4),
            true,
        )
        .is_err());
        let page = CrawlEventPage::new(
            job_id(),
            vec![second],
            CrawlCursor::new(2),
            false,
        )
        .unwrap();
        assert!(page.validate_after(CrawlCursor::START).is_err());
        assert!(page.validate_after(CrawlCursor::new(1)).is_ok());
        let empty = CrawlEventPage::new(
            job_id(),
            Vec::new(),
            CrawlCursor::new(2),
            false,
        )
        .unwrap();
        assert!(empty.validate_after(CrawlCursor::new(1)).is_err());

        let mut oversized = vec![0; MAX_REQUEST_BYTES + 1];
        oversized[..4].copy_from_slice(b"D2WQ");
        assert!(CrawlRequest::decode(&oversized).is_err());
    }
}
