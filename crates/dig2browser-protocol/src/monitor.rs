//! Durable monitor journal records over the `D2MO` wire family.
//!
//! A live capture (`crate::live`) is a bounded RAM ring — it does not survive a
//! station restart. A *durable* monitor persists its stream as an append-only
//! journal of small typed [`MonitorEvent`]s (this module) whose frame payloads
//! live content-addressed in the trace CAS (`dig2browser-trace`). The journal
//! stores only metadata: what was captured, in what order, and how it ended —
//! never the payload bytes themselves, which are referenced by [`ArtifactRef`].
//!
//! This mirrors the finite-task trace event (`crate::trace::TraceEvent`): a
//! wrapper carrying a monotone cursor + timestamp around a typed kind, with a
//! self-describing magic + schema version and a fail-closed codec. Unlike the
//! trace, the stream is open-ended (no `step_count`, no event ceiling); a single
//! terminal [`MonitorEventKind::Stopped`] closes it.

use crate::{
    ArtifactMediaType, ArtifactRef, InterruptedReason, LiveFilter, ProtocolError,
    WebSocketDirection, WebSocketOpcode, MAX_LIVE_URL_BYTES,
};

/// Bound on a `Started` record's monitored-page URL, shared with the live
/// capability's URL bound.
pub const MAX_MONITOR_URL_BYTES: usize = MAX_LIVE_URL_BYTES;

/// Hard upper bound on an encoded [`MonitorEvent`]. The record is dominated by
/// the `Started` URL; everything else (a frame's direction/opcode/truncation
/// flag + a 41-byte artifact reference, or a stop reason) is a handful of
/// bytes. The journal that persists these frames each record and refuses to
/// admit one past this bound.
pub const MAX_MONITOR_EVENT_BYTES: usize = MAX_MONITOR_URL_BYTES + 256;

const MONITOR_EVENT_MAGIC: [u8; 4] = *b"D2MO";
const MONITOR_EVENT_SCHEMA_VERSION: u16 = 1;

/// Position of a record in a monitor journal, 1-based; [`MonitorCursor::START`]
/// (0) is the "before the first record" sentinel a reader begins at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MonitorCursor(u64);

impl MonitorCursor {
    pub const START: Self = Self(0);

    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Why a monitor stopped — the single terminal event of a journal. `Requested`
/// is a clean operator/agent stop; `Interrupted` records that the stream ended
/// without a clean stop (e.g. a successor reconciled a journal a crash left
/// open — `InterruptedReason::SuccessorReconciliation`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorStopReason {
    Requested,
    Interrupted(InterruptedReason),
}

/// A committed frame's durable metadata. The payload bytes are NOT here — a
/// non-empty payload is stored content-addressed in the trace CAS and referenced
/// by `artifact` (media type `ApplicationOctetStream`; the opcode carries the
/// text-vs-binary semantics). An **empty** frame (an empty text frame, a
/// bodyless ping/pong) has no CAS object and carries `artifact = None`.
/// `direction`/`opcode` mirror the live [`crate::WebSocketFrame`]; `truncated`
/// records that the payload was bounded before it was committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorFrame {
    direction: WebSocketDirection,
    opcode: WebSocketOpcode,
    truncated: bool,
    artifact: Option<ArtifactRef>,
}

impl MonitorFrame {
    pub fn new(
        direction: WebSocketDirection,
        opcode: WebSocketOpcode,
        truncated: bool,
        artifact: Option<ArtifactRef>,
    ) -> Result<Self, ProtocolError> {
        // An empty-payload frame legitimately has no CAS object; a truncated
        // frame, by contrast, was bounded from a non-empty payload, so it must
        // reference the bytes that were kept.
        if truncated && artifact.is_none() {
            return Err(ProtocolError::InvalidMonitorPayload);
        }
        Ok(Self {
            direction,
            opcode,
            truncated,
            artifact,
        })
    }

    pub fn direction(&self) -> WebSocketDirection {
        self.direction
    }

    pub fn opcode(&self) -> WebSocketOpcode {
        self.opcode
    }

    pub fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// The CAS reference to the frame's payload, or `None` for an empty frame.
    pub fn artifact(&self) -> Option<&ArtifactRef> {
        self.artifact.as_ref()
    }
}

/// One typed monitor journal record kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MonitorEventKind {
    /// The opening record: the monitored page URL and the event filter the
    /// capture was started with. Must be the first record of a journal.
    Started { url: String, filter: LiveFilter },
    /// A captured frame's metadata; its payload is in the CAS (see
    /// [`MonitorFrame`]).
    FrameCommitted(MonitorFrame),
    /// The single terminal record; no record may follow it.
    Stopped(MonitorStopReason),
}

/// A single durable monitor journal record: a monotone cursor + timestamp
/// around a typed kind, self-describing (`D2MO` magic + schema version) and
/// fail-closed on decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorEvent {
    cursor: MonitorCursor,
    timestamp_unix_ms: u64,
    kind: MonitorEventKind,
}

impl MonitorEvent {
    pub fn new(
        cursor: MonitorCursor,
        timestamp_unix_ms: u64,
        kind: MonitorEventKind,
    ) -> Result<Self, ProtocolError> {
        if cursor == MonitorCursor::START {
            return Err(ProtocolError::InvalidMonitorPayload);
        }
        validate_kind(&kind)?;
        Ok(Self {
            cursor,
            timestamp_unix_ms,
            kind,
        })
    }

    pub fn cursor(&self) -> MonitorCursor {
        self.cursor
    }

    pub fn timestamp_unix_ms(&self) -> u64 {
        self.timestamp_unix_ms
    }

    pub fn kind(&self) -> &MonitorEventKind {
        &self.kind
    }

    /// `true` if this record closes the journal (a `Stopped` record).
    pub fn is_terminal(&self) -> bool {
        matches!(self.kind, MonitorEventKind::Stopped(_))
    }

    /// `true` if this record opens the journal (a `Started` record).
    pub fn is_start(&self) -> bool {
        matches!(self.kind, MonitorEventKind::Started { .. })
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        validate_kind(&self.kind)?;
        let mut output = Vec::new();
        output.extend_from_slice(&MONITOR_EVENT_MAGIC);
        output.extend_from_slice(&MONITOR_EVENT_SCHEMA_VERSION.to_le_bytes());
        output.extend_from_slice(&self.cursor.value().to_le_bytes());
        output.extend_from_slice(&self.timestamp_unix_ms.to_le_bytes());
        match &self.kind {
            MonitorEventKind::Started { url, filter } => {
                output.push(1);
                output.push(0);
                encode_bounded_string_u32(&mut output, url, MAX_MONITOR_URL_BYTES)?;
                output.push(filter_to_wire(*filter));
            }
            MonitorEventKind::FrameCommitted(frame) => {
                output.push(2);
                output.push(0);
                output.push(websocket_direction_to_wire(frame.direction));
                output.push(frame.opcode.to_rfc6455());
                output.push(u8::from(frame.truncated));
                output.push(u8::from(frame.artifact.is_some()));
                if let Some(artifact) = &frame.artifact {
                    encode_artifact_ref(&mut output, artifact);
                }
            }
            MonitorEventKind::Stopped(reason) => {
                output.push(3);
                output.push(0);
                encode_stop_reason(&mut output, *reason);
            }
        }
        if output.len() > MAX_MONITOR_EVENT_BYTES {
            return Err(ProtocolError::InvalidMonitorPayload);
        }
        Ok(output)
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.len() > MAX_MONITOR_EVENT_BYTES {
            return Err(ProtocolError::InvalidMonitorPayload);
        }
        let mut input = Input::new(payload);
        if input.bytes(4)? != MONITOR_EVENT_MAGIC
            || input.u16()? != MONITOR_EVENT_SCHEMA_VERSION
        {
            return Err(ProtocolError::InvalidMonitorPayload);
        }
        let cursor = MonitorCursor::new(input.u64()?);
        let timestamp_unix_ms = input.u64()?;
        let tag = input.u8()?;
        if input.u8()? != 0 {
            return Err(ProtocolError::InvalidMonitorPayload);
        }
        let kind = match tag {
            1 => {
                let url = input.string_u32(MAX_MONITOR_URL_BYTES)?;
                let filter = filter_from_wire(input.u8()?)?;
                MonitorEventKind::Started { url, filter }
            }
            2 => {
                let direction = websocket_direction_from_wire(input.u8()?)?;
                let opcode = WebSocketOpcode::from_rfc6455(input.u8()?)
                    .ok_or(ProtocolError::InvalidMonitorPayload)?;
                let truncated = decode_flag(input.u8()?)?;
                let artifact = match input.u8()? {
                    0 => None,
                    1 => Some(decode_artifact_ref(&mut input)?),
                    _ => return Err(ProtocolError::InvalidMonitorPayload),
                };
                MonitorEventKind::FrameCommitted(MonitorFrame::new(
                    direction, opcode, truncated, artifact,
                )?)
            }
            3 => MonitorEventKind::Stopped(decode_stop_reason(&mut input)?),
            _ => return Err(ProtocolError::InvalidMonitorPayload),
        };
        if !input.is_empty() {
            return Err(ProtocolError::InvalidMonitorPayload);
        }
        Self::new(cursor, timestamp_unix_ms, kind)
    }
}

fn validate_kind(kind: &MonitorEventKind) -> Result<(), ProtocolError> {
    match kind {
        MonitorEventKind::Started { url, .. } => {
            if url.is_empty() || url.len() > MAX_MONITOR_URL_BYTES || url.contains('\0') {
                return Err(ProtocolError::InvalidMonitorPayload);
            }
            Ok(())
        }
        MonitorEventKind::FrameCommitted(_) | MonitorEventKind::Stopped(_) => Ok(()),
    }
}

fn filter_to_wire(filter: LiveFilter) -> u8 {
    u8::from(filter.network())
        | (u8::from(filter.websocket_only()) << 1)
        | (u8::from(filter.console()) << 2)
}

fn filter_from_wire(value: u8) -> Result<LiveFilter, ProtocolError> {
    if value & !0b111 != 0 {
        return Err(ProtocolError::InvalidMonitorPayload);
    }
    Ok(LiveFilter::new(
        value & 1 != 0,
        value & 0b10 != 0,
        value & 0b100 != 0,
    ))
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
        _ => Err(ProtocolError::InvalidMonitorPayload),
    }
}

fn decode_flag(value: u8) -> Result<bool, ProtocolError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(ProtocolError::InvalidMonitorPayload),
    }
}

fn encode_artifact_ref(output: &mut Vec<u8>, artifact: &ArtifactRef) {
    output.extend_from_slice(artifact.sha256());
    output.extend_from_slice(&artifact.len().to_le_bytes());
    output.push(artifact_media_type_to_wire(artifact.media_type()));
}

fn decode_artifact_ref(input: &mut Input<'_>) -> Result<ArtifactRef, ProtocolError> {
    let sha256 = input.array_32()?;
    let len = input.u64()?;
    let media_type = artifact_media_type_from_wire(input.u8()?)?;
    ArtifactRef::new(sha256, len, media_type)
        .map_err(|_| ProtocolError::InvalidMonitorPayload)
}

fn artifact_media_type_to_wire(media_type: ArtifactMediaType) -> u8 {
    match media_type {
        ArtifactMediaType::TextHtmlUtf8 => 1,
        ArtifactMediaType::ImagePng => 2,
        ArtifactMediaType::ApplicationOctetStream => 3,
    }
}

fn artifact_media_type_from_wire(value: u8) -> Result<ArtifactMediaType, ProtocolError> {
    match value {
        1 => Ok(ArtifactMediaType::TextHtmlUtf8),
        2 => Ok(ArtifactMediaType::ImagePng),
        3 => Ok(ArtifactMediaType::ApplicationOctetStream),
        _ => Err(ProtocolError::InvalidMonitorPayload),
    }
}

fn encode_stop_reason(output: &mut Vec<u8>, reason: MonitorStopReason) {
    match reason {
        MonitorStopReason::Requested => output.push(1),
        MonitorStopReason::Interrupted(interrupted) => {
            output.push(2);
            output.push(interrupted_reason_to_wire(interrupted));
        }
    }
}

fn decode_stop_reason(input: &mut Input<'_>) -> Result<MonitorStopReason, ProtocolError> {
    match input.u8()? {
        1 => Ok(MonitorStopReason::Requested),
        2 => Ok(MonitorStopReason::Interrupted(interrupted_reason_from_wire(
            input.u8()?,
        )?)),
        _ => Err(ProtocolError::InvalidMonitorPayload),
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
        _ => Err(ProtocolError::InvalidMonitorPayload),
    }
}

fn encode_bounded_string_u32(
    output: &mut Vec<u8>,
    value: &str,
    max_len: usize,
) -> Result<(), ProtocolError> {
    if value.len() > max_len {
        return Err(ProtocolError::InvalidMonitorPayload);
    }
    let len = u32::try_from(value.len()).map_err(|_| ProtocolError::InvalidMonitorPayload)?;
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
            .ok_or(ProtocolError::InvalidMonitorPayload)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ProtocolError::InvalidMonitorPayload)?;
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
            .map_err(|_| ProtocolError::InvalidMonitorPayload)
    }

    fn string_u32(&mut self, max_len: usize) -> Result<String, ProtocolError> {
        let len = usize::try_from(self.u32()?).map_err(|_| ProtocolError::InvalidMonitorPayload)?;
        if len > max_len {
            return Err(ProtocolError::InvalidMonitorPayload);
        }
        std::str::from_utf8(self.bytes(len)?)
            .map(str::to_owned)
            .map_err(|_| ProtocolError::InvalidMonitorPayload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact() -> ArtifactRef {
        ArtifactRef::new([3; 32], 42, ArtifactMediaType::TextHtmlUtf8).expect("artifact ref")
    }

    #[test]
    fn every_kind_round_trips_with_its_own_magic() {
        let events = [
            MonitorEvent::new(
                MonitorCursor::new(1),
                1_784_500_000_000,
                MonitorEventKind::Started {
                    url: "https://example.test/stream".to_owned(),
                    filter: LiveFilter::new(true, true, false),
                },
            )
            .expect("started"),
            MonitorEvent::new(
                MonitorCursor::new(2),
                1_784_500_000_050,
                MonitorEventKind::FrameCommitted(
                    MonitorFrame::new(
                        WebSocketDirection::Received,
                        WebSocketOpcode::Text,
                        true,
                        Some(artifact()),
                    )
                    .expect("frame"),
                ),
            )
            .expect("frame committed"),
            MonitorEvent::new(
                MonitorCursor::new(5),
                1_784_500_000_250,
                MonitorEventKind::FrameCommitted(
                    // An empty frame carries no CAS reference.
                    MonitorFrame::new(
                        WebSocketDirection::Sent,
                        WebSocketOpcode::Ping,
                        false,
                        None,
                    )
                    .expect("empty frame"),
                ),
            )
            .expect("empty frame committed"),
            MonitorEvent::new(
                MonitorCursor::new(3),
                1_784_500_000_100,
                MonitorEventKind::Stopped(MonitorStopReason::Requested),
            )
            .expect("stopped requested"),
            MonitorEvent::new(
                MonitorCursor::new(4),
                1_784_500_000_200,
                MonitorEventKind::Stopped(MonitorStopReason::Interrupted(
                    InterruptedReason::SuccessorReconciliation,
                )),
            )
            .expect("stopped interrupted"),
        ];
        for event in events {
            let encoded = event.encode().expect("encode monitor event");
            assert_eq!(&encoded[..4], b"D2MO");
            assert_eq!(MonitorEvent::decode(&encoded).expect("decode"), event);
        }
    }

    #[test]
    fn start_sentinel_cursor_and_empty_url_are_rejected() {
        assert!(matches!(
            MonitorEvent::new(
                MonitorCursor::START,
                1,
                MonitorEventKind::Stopped(MonitorStopReason::Requested),
            ),
            Err(ProtocolError::InvalidMonitorPayload)
        ));
        assert!(matches!(
            MonitorEvent::new(
                MonitorCursor::new(1),
                1,
                MonitorEventKind::Started {
                    url: String::new(),
                    filter: LiveFilter::all(),
                },
            ),
            Err(ProtocolError::InvalidMonitorPayload)
        ));
    }

    #[test]
    fn malformed_tags_flags_and_reserved_bytes_fail_closed() {
        let stopped = MonitorEvent::new(
            MonitorCursor::new(1),
            1,
            MonitorEventKind::Stopped(MonitorStopReason::Requested),
        )
        .expect("stopped");
        let mut encoded = stopped.encode().expect("encode");
        // Byte layout: magic(4)+version(2)+cursor(8)+ts(8)+tag(1)+reserved(1).
        // Corrupting the kind tag (index 22) fails closed.
        let mut bad_tag = encoded.clone();
        bad_tag[22] = 9;
        assert!(MonitorEvent::decode(&bad_tag).is_err());
        // A non-zero reserved byte (index 23) fails closed.
        encoded[23] = 1;
        assert!(MonitorEvent::decode(&encoded).is_err());

        // A frame with a reserved (non-RFC-6455) opcode fails closed on decode.
        let frame = MonitorEvent::new(
            MonitorCursor::new(1),
            1,
            MonitorEventKind::FrameCommitted(
                MonitorFrame::new(
                    WebSocketDirection::Sent,
                    WebSocketOpcode::Ping,
                    false,
                    Some(artifact()),
                )
                .expect("frame"),
            ),
        )
        .expect("frame event");
        let mut frame_bytes = frame.encode().expect("encode frame");
        // tag(22)+reserved(23)+direction(24)+opcode(25).
        assert_eq!(frame_bytes[25], WebSocketOpcode::Ping.to_rfc6455());
        frame_bytes[25] = 0x7;
        assert!(MonitorEvent::decode(&frame_bytes).is_err());

        // A truncated frame with no artifact is a contradiction and is rejected.
        assert!(matches!(
            MonitorFrame::new(WebSocketDirection::Sent, WebSocketOpcode::Text, true, None),
            Err(ProtocolError::InvalidMonitorPayload)
        ));

        // Trailing garbage past a complete record fails closed.
        let mut trailing = stopped.encode().expect("encode");
        trailing.push(0);
        assert!(MonitorEvent::decode(&trailing).is_err());
    }
}
