//! Live DevTools event subscription over the D2LQ/D2LP/D2LE wire family.
//!
//! Unlike the crawl/collection families, live events are **raw**: real URLs,
//! HTTP/response metadata and WebSocket/SSE frame payloads cross the wire
//! unsanitized, because observing a page's actual live network traffic is
//! the point of this capability. The station gates it behind a hard,
//! default-deny admission flag (`--allow-live-events`); this module only
//! defines bounded wire shapes, it does not attempt to sanitize content.

use crate::{validate_http_url, BrowserPersona, ProfileClass, ProtocolError, MAX_HTML_BYTES, MAX_REQUEST_BYTES};

/// Per-`Read` page limit, mirroring `MAX_CRAWL_EVENTS`. Also used as the
/// bounded ring-buffer retention capacity per live session (see
/// `dig2browser-station`), so a session never retains more events than one
/// page can return.
pub const MAX_LIVE_EVENTS: usize = 64;
/// URL bound for both the navigate target and any event-carried URL,
/// consistent with `MAX_CRAWL_URL_BYTES`.
pub const MAX_LIVE_URL_BYTES: usize = 4 * 1024;
/// CDP/BiDi method name bound (e.g. `"Network.webSocketFrameReceived"`).
pub const MAX_LIVE_METHOD_BYTES: usize = 128;
/// Console severity level bound (`"log"`, `"warn"`, `"error"`, ...).
pub const MAX_LIVE_CONSOLE_LEVEL_BYTES: usize = 32;
/// Console message text bound.
pub const MAX_LIVE_CONSOLE_TEXT_BYTES: usize = 4 * 1024;
/// Per-event bound on raw `Network.*` CDP params (JSON-encoded), which is
/// where WebSocket/SSE frame payloads live (`Network.webSocketFrameReceived
/// /Sent`, `eventSource*`). 64 KiB matches `MAX_REQUEST_BYTES`, the existing
/// whole-request bound used elsewhere on this wire; reusing it here gives a
/// generous single-frame cap that comfortably covers realistic WS text/JSON
/// frames (market-data ticks, chat, control messages) while keeping one
/// event's worst-case size a small, fixed multiple of one wire frame — never
/// unbounded. Frames larger than this are truncated (`truncated=true`)
/// rather than the whole event being dropped, so method/url/status metadata
/// is never lost even when a payload tail is cut.
pub const MAX_LIVE_NETWORK_PARAMS_BYTES: usize = 64 * 1024;
/// SSE `event:` field bound (`Network.eventSourceMessageReceived.eventName`).
/// SSE event-type tokens are short, application-defined identifiers, not
/// free text, so this is far below `MAX_LIVE_NETWORK_PARAMS_BYTES`.
pub const MAX_LIVE_SSE_EVENT_TYPE_BYTES: usize = 128;
/// SSE `id:` field bound (`Network.eventSourceMessageReceived.eventId`). A
/// little more generous than the event-type bound since some servers pack
/// structured identifiers (UUIDs, composite cursors) into it.
pub const MAX_LIVE_SSE_ID_BYTES: usize = 256;
/// Outer bound for an encoded `LiveResponse` (dominated by `Events` pages,
/// which can carry up to `MAX_LIVE_EVENTS` network events near the params
/// cap). Matches `MAX_HTML_BYTES`, the existing bound for the wire channel
/// (`WorkerResponse.html`) this response is embedded in.
const MAX_LIVE_RESPONSE_BYTES: usize = MAX_HTML_BYTES;

const LIVE_REQUEST_MAGIC: [u8; 4] = *b"D2LQ";
const LIVE_RESPONSE_MAGIC: [u8; 4] = *b"D2LP";
const LIVE_EVENT_MAGIC: [u8; 4] = *b"D2LE";
const LIVE_REQUEST_SCHEMA_VERSION: u16 = 1;
const LIVE_RESPONSE_SCHEMA_VERSION: u16 = 1;
const LIVE_EVENT_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LiveSessionId([u8; 16]);

impl LiveSessionId {
    pub fn new(bytes: [u8; 16]) -> Result<Self, ProtocolError> {
        if bytes == [0; 16] {
            return Err(ProtocolError::InvalidLivePayload);
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
pub struct LiveCursor(u64);

impl LiveCursor {
    pub const START: Self = Self(0);

    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn value(self) -> u64 {
        self.0
    }
}

/// The page the station opens for a live session. Kept to a single
/// navigate-and-stream shape for this slice — no interactive steps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveTarget {
    Navigate { url: String },
}

impl LiveTarget {
    fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Navigate { url } => {
                validate_http_url(url).map_err(|_| ProtocolError::InvalidLivePayload)
            }
        }
    }
}

/// Which DevTools event families a session receives. `websocket_only`
/// narrows `network` events to `Network.webSocket*`/`Network.eventSource*`
/// methods only (it has no effect when `network` is `false`) — this lets a
/// WS-feed consumer ask for frame traffic without the full HTTP/XHR firehose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveFilter {
    network: bool,
    websocket_only: bool,
    console: bool,
}

impl LiveFilter {
    pub const fn new(network: bool, websocket_only: bool, console: bool) -> Self {
        Self {
            network,
            websocket_only,
            console,
        }
    }

    pub const fn all() -> Self {
        Self::new(true, false, true)
    }

    pub const fn network(self) -> bool {
        self.network
    }

    pub const fn websocket_only(self) -> bool {
        self.websocket_only
    }

    pub const fn console(self) -> bool {
        self.console
    }

    fn to_wire(self) -> u8 {
        u8::from(self.network) | (u8::from(self.websocket_only) << 1) | (u8::from(self.console) << 2)
    }

    fn from_wire(value: u8) -> Result<Self, ProtocolError> {
        if value & !0b111 != 0 {
            return Err(ProtocolError::InvalidLivePayload);
        }
        Ok(Self::new(value & 1 != 0, value & 0b10 != 0, value & 0b100 != 0))
    }
}

impl Default for LiveFilter {
    fn default() -> Self {
        Self::all()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveRequest {
    Begin {
        session_id: LiveSessionId,
        profile_class: ProfileClass,
        persona: BrowserPersona,
        target: LiveTarget,
        filter: LiveFilter,
    },
    Read {
        session_id: LiveSessionId,
        cursor: LiveCursor,
        limit: u8,
    },
    Stop {
        session_id: LiveSessionId,
    },
}

impl LiveRequest {
    pub fn begin(
        session_id: LiveSessionId,
        profile_class: ProfileClass,
        persona: BrowserPersona,
        target: LiveTarget,
        filter: LiveFilter,
    ) -> Result<Self, ProtocolError> {
        let request = Self::Begin {
            session_id,
            profile_class,
            persona,
            target,
            filter,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn read(
        session_id: LiveSessionId,
        cursor: LiveCursor,
        limit: u8,
    ) -> Result<Self, ProtocolError> {
        let request = Self::Read {
            session_id,
            cursor,
            limit,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn stop(session_id: LiveSessionId) -> Result<Self, ProtocolError> {
        let request = Self::Stop { session_id };
        request.validate()?;
        Ok(request)
    }

    pub fn session_id(&self) -> LiveSessionId {
        match self {
            Self::Begin { session_id, .. }
            | Self::Read { session_id, .. }
            | Self::Stop { session_id } => *session_id,
        }
    }

    pub fn is_begin(&self) -> bool {
        matches!(self, Self::Begin { .. })
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        LiveSessionId::new(*self.session_id().as_bytes())?;
        match self {
            Self::Begin {
                persona, target, ..
            } => {
                persona.validate()?;
                target.validate()
            }
            Self::Read { limit, .. } => {
                if *limit == 0 || usize::from(*limit) > MAX_LIVE_EVENTS {
                    return Err(ProtocolError::InvalidLivePayload);
                }
                Ok(())
            }
            Self::Stop { .. } => Ok(()),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        let mut output = Vec::new();
        output.extend_from_slice(&LIVE_REQUEST_MAGIC);
        output.extend_from_slice(&LIVE_REQUEST_SCHEMA_VERSION.to_le_bytes());
        match self {
            Self::Begin {
                session_id,
                profile_class,
                persona,
                target,
                filter,
            } => {
                output.extend_from_slice(&[1, 0]);
                output.extend_from_slice(session_id.as_bytes());
                output.push(*profile_class as u8);
                output.push(filter.to_wire());
                let persona = persona
                    .encode()
                    .map_err(|_| ProtocolError::InvalidLivePayload)?;
                let persona_len = u16::try_from(persona.len())
                    .map_err(|_| ProtocolError::InvalidLivePayload)?;
                output.extend_from_slice(&persona_len.to_le_bytes());
                output.extend_from_slice(&persona);
                match target {
                    LiveTarget::Navigate { url } => {
                        output.push(1);
                        output.push(0);
                        encode_bounded_string_u32(&mut output, url, MAX_LIVE_URL_BYTES)?;
                    }
                }
            }
            Self::Read {
                session_id,
                cursor,
                limit,
            } => {
                output.extend_from_slice(&[2, 0]);
                output.extend_from_slice(session_id.as_bytes());
                output.extend_from_slice(&cursor.value().to_le_bytes());
                output.push(*limit);
                output.push(0);
            }
            Self::Stop { session_id } => {
                output.extend_from_slice(&[3, 0]);
                output.extend_from_slice(session_id.as_bytes());
            }
        }
        if output.len() > MAX_REQUEST_BYTES {
            return Err(ProtocolError::InvalidLivePayload);
        }
        Ok(output)
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.len() > MAX_REQUEST_BYTES {
            return Err(ProtocolError::InvalidLivePayload);
        }
        let mut input = Input::new(payload);
        if input.bytes(4)? != LIVE_REQUEST_MAGIC || input.u16()? != LIVE_REQUEST_SCHEMA_VERSION {
            return Err(ProtocolError::InvalidLivePayload);
        }
        let operation = input.u8()?;
        if input.u8()? != 0 {
            return Err(ProtocolError::InvalidLivePayload);
        }
        let request = match operation {
            1 => {
                let session_id = input.session_id()?;
                let profile_class = ProfileClass::from_wire(input.u8()?)
                    .map_err(|_| ProtocolError::InvalidLivePayload)?;
                let filter = LiveFilter::from_wire(input.u8()?)?;
                let persona_len = usize::from(input.u16()?);
                let (persona, consumed) = BrowserPersona::decode(input.bytes(persona_len)?)
                    .map_err(|_| ProtocolError::InvalidLivePayload)?;
                if consumed != persona_len {
                    return Err(ProtocolError::InvalidLivePayload);
                }
                let target_tag = input.u8()?;
                if input.u8()? != 0 {
                    return Err(ProtocolError::InvalidLivePayload);
                }
                let target = match target_tag {
                    1 => LiveTarget::Navigate {
                        url: input.string_u32(MAX_LIVE_URL_BYTES)?,
                    },
                    _ => return Err(ProtocolError::InvalidLivePayload),
                };
                Self::begin(session_id, profile_class, persona, target, filter)?
            }
            2 => {
                let session_id = input.session_id()?;
                let cursor = LiveCursor::new(input.u64()?);
                let limit = input.u8()?;
                if input.u8()? != 0 {
                    return Err(ProtocolError::InvalidLivePayload);
                }
                Self::read(session_id, cursor, limit)?
            }
            3 => Self::stop(input.session_id()?)?,
            _ => return Err(ProtocolError::InvalidLivePayload),
        };
        if !input.is_empty() {
            return Err(ProtocolError::InvalidLivePayload);
        }
        Ok(request)
    }
}

/// WebSocket frame direction relative to the browser: `Sent` originated
/// from the page (`Network.webSocketFrameSent`), `Received` arrived from
/// the peer (`Network.webSocketFrameReceived`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebSocketDirection {
    Sent,
    Received,
}

/// WebSocket frame opcode (RFC 6455 §5.2 — the six values a real frame can
/// carry: continuation, text, binary, close, ping, pong). An unrecognized
/// opcode fails typed parsing rather than being coerced; the station falls
/// back to the generic `Network` event kind for that one frame instead of
/// dropping it (see `dig2browser-station::live`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebSocketOpcode {
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
}

impl WebSocketOpcode {
    pub const fn from_rfc6455(value: u8) -> Option<Self> {
        match value {
            0x0 => Some(Self::Continuation),
            0x1 => Some(Self::Text),
            0x2 => Some(Self::Binary),
            0x8 => Some(Self::Close),
            0x9 => Some(Self::Ping),
            0xA => Some(Self::Pong),
            _ => None,
        }
    }

    pub const fn to_rfc6455(self) -> u8 {
        match self {
            Self::Continuation => 0x0,
            Self::Text => 0x1,
            Self::Binary => 0x2,
            Self::Close => 0x8,
            Self::Ping => 0x9,
            Self::Pong => 0xA,
        }
    }
}

/// A single typed WebSocket frame, parsed from `Network.webSocketFrameSent
/// /Received` instead of carried as an opaque JSON blob. `payload` is
/// bounded to `MAX_LIVE_NETWORK_PARAMS_BYTES` — the same bound the generic
/// `Network` params blob uses — and truncated, never dropped, on oversize;
/// `truncated` records that. `url` is best-effort: CDP does not repeat the
/// URL on every frame event, so the station backfills it by correlating the
/// frame's `requestId` against an earlier event on the same request that
/// did carry a URL (typically `Network.webSocketCreated`); it is `None` if
/// that correlation has not been observed yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebSocketFrame {
    direction: WebSocketDirection,
    opcode: WebSocketOpcode,
    payload: Vec<u8>,
    truncated: bool,
    ts_unix_ms: u64,
    url: Option<String>,
}

impl WebSocketFrame {
    pub fn new(
        direction: WebSocketDirection,
        opcode: WebSocketOpcode,
        payload: Vec<u8>,
        truncated: bool,
        ts_unix_ms: u64,
        url: Option<String>,
    ) -> Result<Self, ProtocolError> {
        let frame = Self {
            direction,
            opcode,
            payload,
            truncated,
            ts_unix_ms,
            url,
        };
        frame.validate()?;
        Ok(frame)
    }

    pub fn direction(&self) -> WebSocketDirection {
        self.direction
    }

    pub fn opcode(&self) -> WebSocketOpcode {
        self.opcode
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn is_truncated(&self) -> bool {
        self.truncated
    }

    pub fn ts_unix_ms(&self) -> u64 {
        self.ts_unix_ms
    }

    pub fn url(&self) -> Option<&str> {
        self.url.as_deref()
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.payload.len() > MAX_LIVE_NETWORK_PARAMS_BYTES {
            return Err(ProtocolError::InvalidLivePayload);
        }
        if let Some(url) = &self.url {
            if url.len() > MAX_LIVE_URL_BYTES || url.contains('\0') {
                return Err(ProtocolError::InvalidLivePayload);
            }
        }
        Ok(())
    }
}

/// A single typed server-sent event, parsed from
/// `Network.eventSourceMessageReceived` instead of carried as an opaque
/// JSON blob. SSE is server-push only, so unlike `WebSocketFrame` there is
/// no direction. `event_type`/`id` are `None` when the corresponding SSE
/// field (`event:`/`id:`) was absent — CDP reports an empty string in that
/// case, which the station maps to `None` rather than `Some("")`. `url` is
/// best-effort for the same reason as `WebSocketFrame::url`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    event_type: Option<String>,
    data: Vec<u8>,
    truncated: bool,
    id: Option<String>,
    ts_unix_ms: u64,
    url: Option<String>,
}

impl SseEvent {
    pub fn new(
        event_type: Option<String>,
        data: Vec<u8>,
        truncated: bool,
        id: Option<String>,
        ts_unix_ms: u64,
        url: Option<String>,
    ) -> Result<Self, ProtocolError> {
        let event = Self {
            event_type,
            data,
            truncated,
            id,
            ts_unix_ms,
            url,
        };
        event.validate()?;
        Ok(event)
    }

    pub fn event_type(&self) -> Option<&str> {
        self.event_type.as_deref()
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn is_truncated(&self) -> bool {
        self.truncated
    }

    pub fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }

    pub fn ts_unix_ms(&self) -> u64 {
        self.ts_unix_ms
    }

    pub fn url(&self) -> Option<&str> {
        self.url.as_deref()
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.data.len() > MAX_LIVE_NETWORK_PARAMS_BYTES {
            return Err(ProtocolError::InvalidLivePayload);
        }
        if let Some(event_type) = &self.event_type {
            if event_type.is_empty()
                || event_type.len() > MAX_LIVE_SSE_EVENT_TYPE_BYTES
                || event_type.contains('\0')
            {
                return Err(ProtocolError::InvalidLivePayload);
            }
        }
        if let Some(id) = &self.id {
            if id.is_empty() || id.len() > MAX_LIVE_SSE_ID_BYTES || id.contains('\0') {
                return Err(ProtocolError::InvalidLivePayload);
            }
        }
        if let Some(url) = &self.url {
            if url.len() > MAX_LIVE_URL_BYTES || url.contains('\0') {
                return Err(ProtocolError::InvalidLivePayload);
            }
        }
        Ok(())
    }
}

/// One translated DevTools event family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveEventKind {
    Network {
        method: String,
        url: Option<String>,
        status: Option<u16>,
        /// Raw JSON-encoded CDP event params, bounded to
        /// `MAX_LIVE_NETWORK_PARAMS_BYTES`. This is where WebSocket/SSE
        /// frame payloads live for every `Network.*` method that is not
        /// individually parsed into a typed variant below.
        params: Vec<u8>,
        /// `true` if `params` was truncated to the bound above.
        truncated: bool,
    },
    Console {
        level: String,
        text: String,
    },
    /// A typed WebSocket frame, parsed from `Network.webSocketFrameSent
    /// /Received`. Populated instead of `Network` for those two methods
    /// only — every other `Network.*` method, including
    /// `webSocketCreated`/`webSocketClosed`, still arrives as `Network`.
    WebSocketFrame(WebSocketFrame),
    /// A typed server-sent event, parsed from
    /// `Network.eventSourceMessageReceived`. Populated instead of
    /// `Network` for that one method only.
    SseEvent(SseEvent),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveEvent {
    cursor: LiveCursor,
    ts_unix_ms: u64,
    kind: LiveEventKind,
}

impl LiveEvent {
    pub fn new(cursor: LiveCursor, ts_unix_ms: u64, kind: LiveEventKind) -> Result<Self, ProtocolError> {
        let event = Self {
            cursor,
            ts_unix_ms,
            kind,
        };
        event.validate()?;
        Ok(event)
    }

    pub fn cursor(&self) -> LiveCursor {
        self.cursor
    }

    pub fn ts_unix_ms(&self) -> u64 {
        self.ts_unix_ms
    }

    pub fn kind(&self) -> &LiveEventKind {
        &self.kind
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.cursor == LiveCursor::START {
            return Err(ProtocolError::InvalidLivePayload);
        }
        match &self.kind {
            LiveEventKind::Network {
                method,
                url,
                status,
                params,
                ..
            } => {
                if method.is_empty()
                    || method.len() > MAX_LIVE_METHOD_BYTES
                    || method.contains('\0')
                {
                    return Err(ProtocolError::InvalidLivePayload);
                }
                if let Some(url) = url {
                    if url.len() > MAX_LIVE_URL_BYTES || url.contains('\0') {
                        return Err(ProtocolError::InvalidLivePayload);
                    }
                }
                if status.is_some_and(|status| !(100..=599).contains(&status)) {
                    return Err(ProtocolError::InvalidLivePayload);
                }
                if params.len() > MAX_LIVE_NETWORK_PARAMS_BYTES {
                    return Err(ProtocolError::InvalidLivePayload);
                }
            }
            LiveEventKind::Console { level, text } => {
                if level.is_empty()
                    || level.len() > MAX_LIVE_CONSOLE_LEVEL_BYTES
                    || level.contains('\0')
                {
                    return Err(ProtocolError::InvalidLivePayload);
                }
                if text.len() > MAX_LIVE_CONSOLE_TEXT_BYTES || text.contains('\0') {
                    return Err(ProtocolError::InvalidLivePayload);
                }
            }
            LiveEventKind::WebSocketFrame(frame) => frame.validate()?,
            LiveEventKind::SseEvent(event) => event.validate()?,
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        let mut output = Vec::new();
        output.extend_from_slice(&LIVE_EVENT_MAGIC);
        output.extend_from_slice(&LIVE_EVENT_SCHEMA_VERSION.to_le_bytes());
        output.extend_from_slice(&self.cursor.value().to_le_bytes());
        output.extend_from_slice(&self.ts_unix_ms.to_le_bytes());
        match &self.kind {
            LiveEventKind::Network {
                method,
                url,
                status,
                params,
                truncated,
            } => {
                output.push(1);
                output.push(0);
                encode_bounded_string_u16(&mut output, method, MAX_LIVE_METHOD_BYTES)?;
                output.push(u8::from(url.is_some()));
                if let Some(url) = url {
                    encode_bounded_string_u16(&mut output, url, MAX_LIVE_URL_BYTES)?;
                }
                output.extend_from_slice(&status.unwrap_or(0).to_le_bytes());
                output.push(u8::from(*truncated));
                let params_len = u32::try_from(params.len())
                    .map_err(|_| ProtocolError::InvalidLivePayload)?;
                output.extend_from_slice(&params_len.to_le_bytes());
                output.extend_from_slice(params);
            }
            LiveEventKind::Console { level, text } => {
                output.push(2);
                output.push(0);
                encode_bounded_string_u8(&mut output, level, MAX_LIVE_CONSOLE_LEVEL_BYTES)?;
                encode_bounded_string_u16(&mut output, text, MAX_LIVE_CONSOLE_TEXT_BYTES)?;
            }
            LiveEventKind::WebSocketFrame(frame) => {
                output.push(3);
                output.push(0);
                output.push(websocket_direction_to_wire(frame.direction));
                output.push(frame.opcode.to_rfc6455());
                output.extend_from_slice(&frame.ts_unix_ms.to_le_bytes());
                output.push(u8::from(frame.truncated));
                output.push(u8::from(frame.url.is_some()));
                if let Some(url) = &frame.url {
                    encode_bounded_string_u16(&mut output, url, MAX_LIVE_URL_BYTES)?;
                }
                let payload_len = u32::try_from(frame.payload.len())
                    .map_err(|_| ProtocolError::InvalidLivePayload)?;
                output.extend_from_slice(&payload_len.to_le_bytes());
                output.extend_from_slice(&frame.payload);
            }
            LiveEventKind::SseEvent(event) => {
                output.push(4);
                output.push(0);
                output.extend_from_slice(&event.ts_unix_ms.to_le_bytes());
                output.push(u8::from(event.truncated));
                output.push(u8::from(event.url.is_some()));
                if let Some(url) = &event.url {
                    encode_bounded_string_u16(&mut output, url, MAX_LIVE_URL_BYTES)?;
                }
                output.push(u8::from(event.event_type.is_some()));
                if let Some(event_type) = &event.event_type {
                    encode_bounded_string_u16(&mut output, event_type, MAX_LIVE_SSE_EVENT_TYPE_BYTES)?;
                }
                output.push(u8::from(event.id.is_some()));
                if let Some(id) = &event.id {
                    encode_bounded_string_u16(&mut output, id, MAX_LIVE_SSE_ID_BYTES)?;
                }
                let data_len = u32::try_from(event.data.len())
                    .map_err(|_| ProtocolError::InvalidLivePayload)?;
                output.extend_from_slice(&data_len.to_le_bytes());
                output.extend_from_slice(&event.data);
            }
        }
        Ok(output)
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        let mut input = Input::new(payload);
        if input.bytes(4)? != LIVE_EVENT_MAGIC || input.u16()? != LIVE_EVENT_SCHEMA_VERSION {
            return Err(ProtocolError::InvalidLivePayload);
        }
        let cursor = LiveCursor::new(input.u64()?);
        let ts_unix_ms = input.u64()?;
        let tag = input.u8()?;
        if input.u8()? != 0 {
            return Err(ProtocolError::InvalidLivePayload);
        }
        let kind = match tag {
            1 => {
                let method = input.string_u16(MAX_LIVE_METHOD_BYTES)?;
                let url = match input.u8()? {
                    0 => None,
                    1 => Some(input.string_u16(MAX_LIVE_URL_BYTES)?),
                    _ => return Err(ProtocolError::InvalidLivePayload),
                };
                let raw_status = input.u16()?;
                let status = match raw_status {
                    0 => None,
                    value @ 100..=599 => Some(value),
                    _ => return Err(ProtocolError::InvalidLivePayload),
                };
                let truncated = match input.u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err(ProtocolError::InvalidLivePayload),
                };
                let params_len = usize::try_from(input.u32()?)
                    .map_err(|_| ProtocolError::InvalidLivePayload)?;
                let params = input.bytes(params_len)?.to_vec();
                LiveEventKind::Network {
                    method,
                    url,
                    status,
                    params,
                    truncated,
                }
            }
            2 => {
                let level = input.string_u8(MAX_LIVE_CONSOLE_LEVEL_BYTES)?;
                let text = input.string_u16(MAX_LIVE_CONSOLE_TEXT_BYTES)?;
                LiveEventKind::Console { level, text }
            }
            3 => {
                let direction = websocket_direction_from_wire(input.u8()?)?;
                let opcode = WebSocketOpcode::from_rfc6455(input.u8()?)
                    .ok_or(ProtocolError::InvalidLivePayload)?;
                let frame_ts_unix_ms = input.u64()?;
                let truncated = match input.u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err(ProtocolError::InvalidLivePayload),
                };
                let url = match input.u8()? {
                    0 => None,
                    1 => Some(input.string_u16(MAX_LIVE_URL_BYTES)?),
                    _ => return Err(ProtocolError::InvalidLivePayload),
                };
                let payload_len = usize::try_from(input.u32()?)
                    .map_err(|_| ProtocolError::InvalidLivePayload)?;
                let payload = input.bytes(payload_len)?.to_vec();
                LiveEventKind::WebSocketFrame(WebSocketFrame::new(
                    direction,
                    opcode,
                    payload,
                    truncated,
                    frame_ts_unix_ms,
                    url,
                )?)
            }
            4 => {
                let event_ts_unix_ms = input.u64()?;
                let truncated = match input.u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err(ProtocolError::InvalidLivePayload),
                };
                let url = match input.u8()? {
                    0 => None,
                    1 => Some(input.string_u16(MAX_LIVE_URL_BYTES)?),
                    _ => return Err(ProtocolError::InvalidLivePayload),
                };
                let event_type = match input.u8()? {
                    0 => None,
                    1 => Some(input.string_u16(MAX_LIVE_SSE_EVENT_TYPE_BYTES)?),
                    _ => return Err(ProtocolError::InvalidLivePayload),
                };
                let id = match input.u8()? {
                    0 => None,
                    1 => Some(input.string_u16(MAX_LIVE_SSE_ID_BYTES)?),
                    _ => return Err(ProtocolError::InvalidLivePayload),
                };
                let data_len = usize::try_from(input.u32()?)
                    .map_err(|_| ProtocolError::InvalidLivePayload)?;
                let data = input.bytes(data_len)?.to_vec();
                LiveEventKind::SseEvent(SseEvent::new(
                    event_type,
                    data,
                    truncated,
                    id,
                    event_ts_unix_ms,
                    url,
                )?)
            }
            _ => return Err(ProtocolError::InvalidLivePayload),
        };
        if !input.is_empty() {
            return Err(ProtocolError::InvalidLivePayload);
        }
        Self::new(cursor, ts_unix_ms, kind)
    }
}

fn websocket_direction_to_wire(direction: WebSocketDirection) -> u8 {
    match direction {
        WebSocketDirection::Sent => 0,
        WebSocketDirection::Received => 1,
    }
}

fn websocket_direction_from_wire(value: u8) -> Result<WebSocketDirection, ProtocolError> {
    match value {
        0 => Ok(WebSocketDirection::Sent),
        1 => Ok(WebSocketDirection::Received),
        _ => Err(ProtocolError::InvalidLivePayload),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveEventPage {
    session_id: LiveSessionId,
    events: Vec<LiveEvent>,
    next_cursor: LiveCursor,
    dropped: u64,
    active: bool,
}

impl LiveEventPage {
    pub fn new(
        session_id: LiveSessionId,
        events: Vec<LiveEvent>,
        next_cursor: LiveCursor,
        dropped: u64,
        active: bool,
    ) -> Result<Self, ProtocolError> {
        let page = Self {
            session_id,
            events,
            next_cursor,
            dropped,
            active,
        };
        page.validate()?;
        Ok(page)
    }

    pub fn session_id(&self) -> LiveSessionId {
        self.session_id
    }

    pub fn events(&self) -> &[LiveEvent] {
        &self.events
    }

    pub fn next_cursor(&self) -> LiveCursor {
        self.next_cursor
    }

    /// Cumulative count of ring-buffer-evicted events since this session's
    /// `Begin`, not a per-page delta. A consumer diffs successive values to
    /// learn how many events were lost between two `Read` calls.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// `false` once the session's reader has stopped (explicit `Stop`, TTL
    /// reap, or the underlying worker/page going away) — an honest signal
    /// distinct from "temporarily no new events".
    pub fn is_active(&self) -> bool {
        self.active
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        LiveSessionId::new(*self.session_id.as_bytes())?;
        if self.events.len() > MAX_LIVE_EVENTS
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
            return Err(ProtocolError::InvalidLivePayload);
        }
        for event in &self.events {
            event.validate()?;
        }
        Ok(())
    }

    /// Validate this page as the result of a `Read` issued at `cursor`.
    ///
    /// Unlike the durable crawl-event stream, live events are bounded and
    /// lossy: the per-session ring buffer drops the oldest retained event to
    /// admit a new one once full, so the first returned event's cursor can
    /// be strictly greater than `cursor + 1` — a gap means older events were
    /// dropped (see [`dropped`](Self::dropped)). Requiring only
    /// `first.cursor() > cursor` here (not `== cursor + 1`) is the
    /// intentional, honest difference from `CrawlEventPage::validate_after`.
    pub fn validate_after(&self, cursor: LiveCursor) -> Result<(), ProtocolError> {
        self.validate()?;
        match self.events.first() {
            Some(first) if first.cursor() > cursor => Ok(()),
            Some(_) => Err(ProtocolError::InvalidLivePayload),
            None if self.next_cursor == cursor => Ok(()),
            None => Err(ProtocolError::InvalidLivePayload),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveResponse {
    Accepted { session_id: LiveSessionId },
    Events(LiveEventPage),
    Stopped { session_id: LiveSessionId },
}

impl LiveResponse {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Accepted { session_id } | Self::Stopped { session_id } => {
                LiveSessionId::new(*session_id.as_bytes()).map(|_| ())
            }
            Self::Events(page) => page.validate(),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        let mut output = Vec::new();
        output.extend_from_slice(&LIVE_RESPONSE_MAGIC);
        output.extend_from_slice(&LIVE_RESPONSE_SCHEMA_VERSION.to_le_bytes());
        match self {
            Self::Accepted { session_id } => {
                output.extend_from_slice(&[1, 0]);
                output.extend_from_slice(session_id.as_bytes());
            }
            Self::Events(page) => {
                output.extend_from_slice(&[2, 0]);
                output.extend_from_slice(page.session_id.as_bytes());
                output.extend_from_slice(&page.next_cursor.value().to_le_bytes());
                output.extend_from_slice(&page.dropped.to_le_bytes());
                output.push(u8::from(page.active));
                output.push(0);
                output.extend_from_slice(&(page.events.len() as u16).to_le_bytes());
                for event in &page.events {
                    let event = event.encode()?;
                    let len = u32::try_from(event.len())
                        .map_err(|_| ProtocolError::InvalidLivePayload)?;
                    output.extend_from_slice(&len.to_le_bytes());
                    output.extend_from_slice(&event);
                }
            }
            Self::Stopped { session_id } => {
                output.extend_from_slice(&[3, 0]);
                output.extend_from_slice(session_id.as_bytes());
            }
        }
        if output.len() > MAX_LIVE_RESPONSE_BYTES {
            return Err(ProtocolError::InvalidLivePayload);
        }
        Ok(output)
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.len() > MAX_LIVE_RESPONSE_BYTES {
            return Err(ProtocolError::InvalidLivePayload);
        }
        let mut input = Input::new(payload);
        if input.bytes(4)? != LIVE_RESPONSE_MAGIC || input.u16()? != LIVE_RESPONSE_SCHEMA_VERSION {
            return Err(ProtocolError::InvalidLivePayload);
        }
        let operation = input.u8()?;
        if input.u8()? != 0 {
            return Err(ProtocolError::InvalidLivePayload);
        }
        let response = match operation {
            1 => Self::Accepted {
                session_id: input.session_id()?,
            },
            2 => {
                let session_id = input.session_id()?;
                let next_cursor = LiveCursor::new(input.u64()?);
                let dropped = input.u64()?;
                let active = match input.u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err(ProtocolError::InvalidLivePayload),
                };
                if input.u8()? != 0 {
                    return Err(ProtocolError::InvalidLivePayload);
                }
                let count = usize::from(input.u16()?);
                if count > MAX_LIVE_EVENTS {
                    return Err(ProtocolError::InvalidLivePayload);
                }
                let mut events = Vec::with_capacity(count);
                for _ in 0..count {
                    let len = usize::try_from(input.u32()?)
                        .map_err(|_| ProtocolError::InvalidLivePayload)?;
                    events.push(LiveEvent::decode(input.bytes(len)?)?);
                }
                Self::Events(LiveEventPage::new(
                    session_id,
                    events,
                    next_cursor,
                    dropped,
                    active,
                )?)
            }
            3 => Self::Stopped {
                session_id: input.session_id()?,
            },
            _ => return Err(ProtocolError::InvalidLivePayload),
        };
        if !input.is_empty() {
            return Err(ProtocolError::InvalidLivePayload);
        }
        response.validate()?;
        Ok(response)
    }
}

fn encode_bounded_string_u8(
    output: &mut Vec<u8>,
    value: &str,
    max_len: usize,
) -> Result<(), ProtocolError> {
    if value.len() > max_len {
        return Err(ProtocolError::InvalidLivePayload);
    }
    let len = u8::try_from(value.len()).map_err(|_| ProtocolError::InvalidLivePayload)?;
    output.push(len);
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn encode_bounded_string_u16(
    output: &mut Vec<u8>,
    value: &str,
    max_len: usize,
) -> Result<(), ProtocolError> {
    if value.len() > max_len {
        return Err(ProtocolError::InvalidLivePayload);
    }
    let len = u16::try_from(value.len()).map_err(|_| ProtocolError::InvalidLivePayload)?;
    output.extend_from_slice(&len.to_le_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn encode_bounded_string_u32(
    output: &mut Vec<u8>,
    value: &str,
    max_len: usize,
) -> Result<(), ProtocolError> {
    if value.len() > max_len {
        return Err(ProtocolError::InvalidLivePayload);
    }
    let len = u32::try_from(value.len()).map_err(|_| ProtocolError::InvalidLivePayload)?;
    output.extend_from_slice(&len.to_le_bytes());
    output.extend_from_slice(value.as_bytes());
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
            .ok_or(ProtocolError::InvalidLivePayload)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ProtocolError::InvalidLivePayload)?;
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

    fn session_id(&mut self) -> Result<LiveSessionId, ProtocolError> {
        LiveSessionId::new(
            self.bytes(16)?
                .try_into()
                .map_err(|_| ProtocolError::InvalidLivePayload)?,
        )
    }

    fn string_u8(&mut self, max_len: usize) -> Result<String, ProtocolError> {
        let len = usize::from(self.u8()?);
        if len > max_len {
            return Err(ProtocolError::InvalidLivePayload);
        }
        std::str::from_utf8(self.bytes(len)?)
            .map(str::to_owned)
            .map_err(|_| ProtocolError::InvalidLivePayload)
    }

    fn string_u16(&mut self, max_len: usize) -> Result<String, ProtocolError> {
        let len = usize::from(self.u16()?);
        if len > max_len {
            return Err(ProtocolError::InvalidLivePayload);
        }
        std::str::from_utf8(self.bytes(len)?)
            .map(str::to_owned)
            .map_err(|_| ProtocolError::InvalidLivePayload)
    }

    fn string_u32(&mut self, max_len: usize) -> Result<String, ProtocolError> {
        let len = usize::try_from(self.u32()?)
            .map_err(|_| ProtocolError::InvalidLivePayload)?;
        if len > max_len {
            return Err(ProtocolError::InvalidLivePayload);
        }
        std::str::from_utf8(self.bytes(len)?)
            .map(str::to_owned)
            .map_err(|_| ProtocolError::InvalidLivePayload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session_id() -> LiveSessionId {
        LiveSessionId::new([9; 16]).expect("session id")
    }

    #[test]
    fn requests_round_trip_with_separate_magic_and_bounds() {
        let requests = [
            LiveRequest::begin(
                session_id(),
                ProfileClass::Public,
                BrowserPersona::desktop_default(),
                LiveTarget::Navigate {
                    url: "https://example.test/live".to_owned(),
                },
                LiveFilter::all(),
            )
            .expect("begin"),
            LiveRequest::read(session_id(), LiveCursor::new(11), 32).expect("read"),
            LiveRequest::stop(session_id()).expect("stop"),
        ];
        for request in requests {
            let encoded = request.encode().expect("encode request");
            assert_eq!(&encoded[..4], b"D2LQ");
            assert_eq!(LiveRequest::decode(&encoded).unwrap(), request);
        }
        assert!(LiveSessionId::new([0; 16]).is_err());
        assert!(LiveRequest::read(session_id(), LiveCursor::START, 0).is_err());
        assert!(LiveRequest::read(
            session_id(),
            LiveCursor::START,
            u8::try_from(MAX_LIVE_EVENTS + 1).unwrap_or(u8::MAX)
        )
        .is_err());
    }

    #[test]
    fn events_and_responses_round_trip_including_websocket_frame_shape() {
        let network = LiveEvent::new(
            LiveCursor::new(1),
            1_784_500_000_000,
            LiveEventKind::Network {
                method: "Network.webSocketFrameReceived".to_owned(),
                url: Some("wss://example.test/stream".to_owned()),
                status: None,
                params: br#"{"response":{"payloadData":"ping"}}"#.to_vec(),
                truncated: false,
            },
        )
        .expect("network event");
        let console = LiveEvent::new(
            LiveCursor::new(2),
            1_784_500_000_100,
            LiveEventKind::Console {
                level: "error".to_owned(),
                text: "uncaught exception".to_owned(),
            },
        )
        .expect("console event");
        for event in [&network, &console] {
            let encoded = event.encode().expect("encode event");
            assert_eq!(&encoded[..4], b"D2LE");
            assert_eq!(&LiveEvent::decode(&encoded).unwrap(), event);
        }

        let page = LiveEventPage::new(
            session_id(),
            vec![network, console],
            LiveCursor::new(2),
            5,
            true,
        )
        .expect("event page");
        assert_eq!(page.dropped(), 5);
        assert!(page.is_active());
        assert!(page.validate_after(LiveCursor::START).is_ok());
        assert!(page.validate_after(LiveCursor::new(1)).is_err());

        for response in [
            LiveResponse::Accepted {
                session_id: session_id(),
            },
            LiveResponse::Events(page),
            LiveResponse::Stopped {
                session_id: session_id(),
            },
        ] {
            let encoded = response.encode().expect("encode response");
            assert_eq!(&encoded[..4], b"D2LP");
            assert_eq!(LiveResponse::decode(&encoded).unwrap(), response);
        }
    }

    #[test]
    fn gap_after_ring_drop_is_valid_but_out_of_order_is_not() {
        let event = |cursor: u64| {
            LiveEvent::new(
                LiveCursor::new(cursor),
                1,
                LiveEventKind::Console {
                    level: "log".to_owned(),
                    text: "tick".to_owned(),
                },
            )
            .unwrap()
        };
        // Oldest retained cursor is 20 (10..19 were dropped from the ring);
        // a Read at cursor=5 must accept the gap.
        let page = LiveEventPage::new(session_id(), vec![event(20)], LiveCursor::new(20), 14, true)
            .unwrap();
        assert!(page.validate_after(LiveCursor::new(5)).is_ok());

        // Two events inside one page must still be strictly +1 contiguous.
        let broken = LiveEventPage::new(
            session_id(),
            vec![event(20), event(22)],
            LiveCursor::new(22),
            0,
            true,
        );
        assert!(broken.is_err());
    }

    #[test]
    fn malformed_tags_and_flags_fail_closed() {
        let mut request = LiveRequest::stop(session_id()).unwrap().encode().unwrap();
        request[6] = 9;
        assert!(LiveRequest::decode(&request).is_err());

        let event = LiveEvent::new(
            LiveCursor::new(1),
            1,
            LiveEventKind::Console {
                level: "log".to_owned(),
                text: "hi".to_owned(),
            },
        )
        .unwrap();
        let mut unknown_kind = event.encode().unwrap();
        unknown_kind[22] = u8::MAX;
        assert!(LiveEvent::decode(&unknown_kind).is_err());

        let mut oversized = vec![0; MAX_REQUEST_BYTES + 1];
        oversized[..4].copy_from_slice(b"D2LQ");
        assert!(LiveRequest::decode(&oversized).is_err());

        assert!(LiveFilter::from_wire(0b1000).is_err());
        assert_eq!(LiveFilter::from_wire(0b101).unwrap(), LiveFilter::new(true, false, true));
    }

    #[test]
    fn websocket_opcode_maps_the_six_rfc6455_values_and_rejects_the_rest() {
        let pairs = [
            (0x0, WebSocketOpcode::Continuation),
            (0x1, WebSocketOpcode::Text),
            (0x2, WebSocketOpcode::Binary),
            (0x8, WebSocketOpcode::Close),
            (0x9, WebSocketOpcode::Ping),
            (0xA, WebSocketOpcode::Pong),
        ];
        for (wire, opcode) in pairs {
            assert_eq!(WebSocketOpcode::from_rfc6455(wire), Some(opcode));
            assert_eq!(opcode.to_rfc6455(), wire);
        }
        for reserved in [0x3, 0x4, 0x5, 0x6, 0x7, 0xB, 0xF] {
            assert_eq!(WebSocketOpcode::from_rfc6455(reserved), None);
        }
    }

    #[test]
    fn websocket_frame_and_sse_event_round_trip_through_live_event_and_page() {
        let frame = LiveEvent::new(
            LiveCursor::new(1),
            1_784_500_000_000,
            LiveEventKind::WebSocketFrame(
                WebSocketFrame::new(
                    WebSocketDirection::Received,
                    WebSocketOpcode::Text,
                    br#"{"tick":1}"#.to_vec(),
                    false,
                    1_784_500_000_000,
                    Some("wss://example.test/stream".to_owned()),
                )
                .expect("websocket frame"),
            ),
        )
        .expect("websocket frame event");
        let sse = LiveEvent::new(
            LiveCursor::new(2),
            1_784_500_000_050,
            LiveEventKind::SseEvent(
                SseEvent::new(
                    Some("price".to_owned()),
                    b"{\"symbol\":\"BTC\"}".to_vec(),
                    false,
                    Some("42".to_owned()),
                    1_784_500_000_050,
                    None,
                )
                .expect("sse event"),
            ),
        )
        .expect("sse event event");
        for event in [&frame, &sse] {
            let encoded = event.encode().expect("encode event");
            assert_eq!(&encoded[..4], b"D2LE");
            assert_eq!(&LiveEvent::decode(&encoded).unwrap(), event);
        }
        match frame.kind() {
            LiveEventKind::WebSocketFrame(frame) => {
                assert_eq!(frame.direction(), WebSocketDirection::Received);
                assert_eq!(frame.opcode(), WebSocketOpcode::Text);
                assert_eq!(frame.payload(), br#"{"tick":1}"#);
                assert!(!frame.is_truncated());
                assert_eq!(frame.url(), Some("wss://example.test/stream"));
            }
            _ => panic!("expected a websocket frame kind"),
        }
        match sse.kind() {
            LiveEventKind::SseEvent(event) => {
                assert_eq!(event.event_type(), Some("price"));
                assert_eq!(event.id(), Some("42"));
                assert_eq!(event.url(), None);
                assert!(!event.is_truncated());
            }
            _ => panic!("expected an sse event kind"),
        }

        let page = LiveEventPage::new(session_id(), vec![frame, sse], LiveCursor::new(2), 0, true)
            .expect("event page");
        let response = LiveResponse::Events(page);
        let encoded = response.encode().expect("encode response");
        assert_eq!(&encoded[..4], b"D2LP");
        assert_eq!(LiveResponse::decode(&encoded).unwrap(), response);
    }

    #[test]
    fn websocket_frame_and_sse_event_bounds_and_truncation_flag_fail_closed() {
        assert!(WebSocketFrame::new(
            WebSocketDirection::Sent,
            WebSocketOpcode::Binary,
            vec![0; MAX_LIVE_NETWORK_PARAMS_BYTES + 1],
            false,
            1,
            None,
        )
        .is_err());
        // A truncated frame at exactly the bound, with the flag set, is valid.
        assert!(WebSocketFrame::new(
            WebSocketDirection::Sent,
            WebSocketOpcode::Binary,
            vec![0; MAX_LIVE_NETWORK_PARAMS_BYTES],
            true,
            1,
            None,
        )
        .is_ok());
        assert!(WebSocketFrame::new(
            WebSocketDirection::Sent,
            WebSocketOpcode::Text,
            b"hi".to_vec(),
            false,
            1,
            Some("not\0a\0url".to_owned()),
        )
        .is_err());

        assert!(SseEvent::new(
            Some(String::new()),
            b"data".to_vec(),
            false,
            None,
            1,
            None,
        )
        .is_err());
        assert!(SseEvent::new(
            None,
            vec![0; MAX_LIVE_NETWORK_PARAMS_BYTES + 1],
            true,
            None,
            1,
            None,
        )
        .is_err());

        // A malformed opcode byte fails closed on decode instead of being
        // coerced into a plausible-looking frame.
        let frame = LiveEvent::new(
            LiveCursor::new(1),
            1,
            LiveEventKind::WebSocketFrame(
                WebSocketFrame::new(
                    WebSocketDirection::Sent,
                    WebSocketOpcode::Ping,
                    Vec::new(),
                    false,
                    1,
                    None,
                )
                .unwrap(),
            ),
        )
        .unwrap();
        let mut encoded = frame.encode().unwrap();
        // Byte layout: magic(4) + version(2) + cursor(8) + ts(8) + tag(1) +
        // reserved(1) + direction(1) + opcode(1) -> opcode is byte index 25.
        assert_eq!(encoded[25], WebSocketOpcode::Ping.to_rfc6455());
        encoded[25] = 0x7; // reserved opcode
        assert!(LiveEvent::decode(&encoded).is_err());
    }
}
