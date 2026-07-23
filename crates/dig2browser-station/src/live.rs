//! Live DevTools event capture: a bounded, cursored, in-memory (non-durable)
//! subscription over a station-owned page's `Network.*`/console event
//! stream.
//!
//! Unlike [`crate::collection`]/[`crate::crawl`], sessions here are never
//! written to disk — they are a ring buffer over a live [`PageDevTools`]
//! broadcast, bounded per-session and capped station-wide. Raw page URLs,
//! WebSocket/SSE frame payloads and console text cross this path
//! unsanitized (that is the point of the capability); admission is gated by
//! the station operator's `--allow-live-events` flag, not by content
//! sanitization.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use dig2browser::agentic::{AgentCommand, CapabilitySet};
use dig2browser::browser::{ConsoleEvent, DevToolsEvent, NetworkEvent, PageDevTools};
use dig2browser_protocol::{
    BrowserPersona, LiveCursor, LiveEvent, LiveEventKind, LiveEventPage, LiveFilter,
    LiveRequest, LiveResponse, LiveSessionId, LiveTarget, ProfileClass, SseEvent,
    WebSocketDirection, WebSocketFrame, WebSocketOpcode, MAX_LIVE_CONSOLE_LEVEL_BYTES,
    MAX_LIVE_CONSOLE_TEXT_BYTES, MAX_LIVE_EVENTS, MAX_LIVE_METHOD_BYTES,
    MAX_LIVE_NETWORK_PARAMS_BYTES, MAX_LIVE_SSE_EVENT_TYPE_BYTES, MAX_LIVE_SSE_ID_BYTES,
    MAX_LIVE_URL_BYTES,
};
use tokio::task::JoinHandle;

use crate::{BrowserLease, BrowserStation, IdentityRequest, StationError};

/// Bounded cache of `requestId -> url` learned from `Network.*` events that
/// do carry a URL (`webSocketCreated`, `requestWillBeSent`,
/// `responseReceived`, ...), used to backfill `url` on frame-only events
/// (`webSocketFrameSent/Received`, `eventSourceMessageReceived`) that CDP
/// does not repeat it on. Bounded and drop-oldest like the event ring —
/// this is a best-effort correlation aid, not a durable index, so losing an
/// old entry under sustained load is an accepted, honest trade-off (the
/// frame's `url` simply reads back as `None` for still-open requests whose
/// creation event fell out of the cache).
const MAX_LIVE_REQUEST_URL_ENTRIES: usize = 128;

struct RequestUrlCache {
    urls: HashMap<String, String>,
    order: VecDeque<String>,
}

impl RequestUrlCache {
    fn new() -> Self {
        Self {
            urls: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn remember(&mut self, request_id: &str, url: &str) {
        if self.urls.contains_key(request_id) {
            return;
        }
        if self.order.len() >= MAX_LIVE_REQUEST_URL_ENTRIES {
            if let Some(oldest) = self.order.pop_front() {
                self.urls.remove(&oldest);
            }
        }
        self.urls.insert(request_id.to_owned(), url.to_owned());
        self.order.push_back(request_id.to_owned());
    }

    fn lookup(&self, request_id: &str) -> Option<String> {
        self.urls.get(request_id).cloned()
    }
}

/// Station-wide concurrent live-session cap. Bounds worst-case retained
/// memory alongside `MAX_LIVE_RING_CAPACITY` (each session's ring can hold
/// up to `MAX_LIVE_EVENTS` events, each up to roughly
/// `MAX_LIVE_NETWORK_PARAMS_BYTES` — so worst case is on the order of
/// `MAX_LIVE_SESSIONS * MAX_LIVE_EVENTS * MAX_LIVE_NETWORK_PARAMS_BYTES`,
/// a little over 128 MiB at these bounds).
const MAX_LIVE_SESSIONS: usize = 32;
/// Per-session ring-buffer retention, matching the per-`Read` page limit
/// (`MAX_LIVE_EVENTS`) so a session never retains more than one page's
/// worth of unread events.
const MAX_LIVE_RING_CAPACITY: usize = MAX_LIVE_EVENTS;
/// Soft idle TTL: a session that has not been `Read` (or just-`Begin`) for
/// this long is reaped the next time admission opportunistically sweeps
/// (on `Begin`/`Read`/`Stop`), mirroring `CollectionManager::reap_finished`.
/// A station that receives no further live-capture calls at all leaks
/// expired sessions until the next call or graceful `shutdown` — the same
/// trade-off `reap_finished` already accepts for collections/crawls.
const LIVE_SESSION_IDLE_TTL_MS: u64 = 5 * 60 * 1_000;

#[derive(Clone)]
pub(crate) struct LiveCaptureManager {
    inner: Arc<LiveManagerInner>,
}

struct LiveManagerInner {
    station: BrowserStation,
    sessions: StdMutex<HashMap<LiveSessionId, Arc<LiveSession>>>,
    accepting: AtomicBool,
}

struct LiveSession {
    filter: LiveFilter,
    /// Held only for its `Drop` side effect: releasing the station lease
    /// (and thereby the underlying worker's `active_leases` count) once the
    /// session is removed from the manager's map. Never read directly —
    /// see `CrawlManagerInner::_lock` for the same naming convention.
    _lease: BrowserLease,
    ring: StdMutex<Ring>,
    reader: StdMutex<Option<JoinHandle<()>>>,
    stopped: AtomicBool,
    sequence: AtomicU64,
    last_touched_ms: AtomicU64,
    request_urls: StdMutex<RequestUrlCache>,
}

struct Ring {
    events: VecDeque<LiveEvent>,
    dropped: u64,
}

impl LiveCaptureManager {
    /// Live capture carries no durable state to reconcile, so admission
    /// opens immediately. The CLI's `--allow-live-events` gate is enforced
    /// upstream, in `ipc.rs`, before any request reaches this manager —
    /// `accepting` here only tracks graceful-drain state (see
    /// [`shutdown`](Self::shutdown)).
    pub(crate) fn open(station: BrowserStation) -> Self {
        Self {
            inner: Arc::new(LiveManagerInner {
                station,
                sessions: StdMutex::new(HashMap::new()),
                accepting: AtomicBool::new(true),
            }),
        }
    }

    pub(crate) async fn handle(
        &self,
        profile_id: &str,
        request: LiveRequest,
    ) -> Result<LiveResponse, LiveError> {
        request.validate()?;
        match request {
            LiveRequest::Begin {
                session_id,
                profile_class,
                persona,
                target,
                filter,
            } => {
                self.begin(profile_id, session_id, profile_class, persona, target, filter)
                    .await?;
                Ok(LiveResponse::Accepted { session_id })
            }
            LiveRequest::Read {
                session_id,
                cursor,
                limit,
            } => Ok(LiveResponse::Events(self.read_events(session_id, cursor, limit)?)),
            LiveRequest::Stop { session_id } => {
                self.stop(session_id)?;
                Ok(LiveResponse::Stopped { session_id })
            }
        }
    }

    /// Stop admission, abort every reader task and release every held
    /// lease. Returns `true` if the drain timed out (aborted rather than
    /// finishing cleanly), mirroring `CrawlManager::shutdown`/
    /// `CollectionManager::shutdown`.
    pub(crate) async fn shutdown(&self, timeout: Duration) -> Result<bool, LiveError> {
        self.inner.accepting.store(false, Ordering::Release);
        let sessions: Vec<Arc<LiveSession>> = lock(&self.inner.sessions)?.drain().map(|(_, session)| session).collect();
        let mut handles = Vec::with_capacity(sessions.len());
        for session in &sessions {
            session.stopped.store(true, Ordering::Release);
            if let Some(handle) = lock(&session.reader)?.take() {
                handle.abort();
                handles.push(handle);
            }
        }
        let drained = tokio::time::timeout(timeout, async {
            for handle in handles {
                let _ = handle.await;
            }
        })
        .await
        .is_ok();
        // Dropping `sessions` here releases every held `BrowserLease` back
        // to the station (the worker stays resident, just unleased).
        drop(sessions);
        Ok(!drained)
    }

    async fn begin(
        &self,
        profile_id: &str,
        session_id: LiveSessionId,
        profile_class: ProfileClass,
        persona: BrowserPersona,
        target: LiveTarget,
        filter: LiveFilter,
    ) -> Result<(), LiveError> {
        if !self.inner.accepting.load(Ordering::Acquire) {
            return Err(LiveError::AdmissionClosed);
        }
        validate_profile_id(profile_id)?;
        self.reap_expired()?;
        {
            let sessions = lock(&self.inner.sessions)?;
            if sessions.contains_key(&session_id) {
                return Err(LiveError::SessionConflict);
            }
            if sessions.len() >= MAX_LIVE_SESSIONS {
                return Err(LiveError::AtCapacity);
            }
        }

        let identity = match profile_class {
            ProfileClass::Public => IdentityRequest::public_persona(profile_id, persona),
            ProfileClass::Authenticated => {
                IdentityRequest::authenticated_persona(profile_id, persona)
            }
        };
        let lease = self
            .inner
            .station
            .lease(identity, CapabilitySet::monitoring())
            .await?;
        let LiveTarget::Navigate { url } = target;
        lease.execute(AgentCommand::Navigate { url }).await?;
        let devtools = lease.subscribe_devtools().await?;

        let session = Arc::new(LiveSession {
            filter,
            _lease: lease,
            ring: StdMutex::new(Ring {
                events: VecDeque::with_capacity(MAX_LIVE_RING_CAPACITY),
                dropped: 0,
            }),
            reader: StdMutex::new(None),
            stopped: AtomicBool::new(false),
            sequence: AtomicU64::new(0),
            last_touched_ms: AtomicU64::new(unix_time_ms()),
            request_urls: StdMutex::new(RequestUrlCache::new()),
        });
        let reader_session = Arc::clone(&session);
        let reader = tokio::spawn(async move { run_reader(reader_session, devtools).await });
        *lock(&session.reader)? = Some(reader);

        let mut sessions = lock(&self.inner.sessions)?;
        if !self.inner.accepting.load(Ordering::Acquire) {
            drop(sessions);
            stop_session(&session);
            return Err(LiveError::AdmissionClosed);
        }
        if sessions.contains_key(&session_id) {
            drop(sessions);
            stop_session(&session);
            return Err(LiveError::SessionConflict);
        }
        if sessions.len() >= MAX_LIVE_SESSIONS {
            drop(sessions);
            stop_session(&session);
            return Err(LiveError::AtCapacity);
        }
        sessions.insert(session_id, session);
        Ok(())
    }

    fn read_events(
        &self,
        session_id: LiveSessionId,
        cursor: LiveCursor,
        limit: u8,
    ) -> Result<LiveEventPage, LiveError> {
        self.reap_expired()?;
        let session = self.session(session_id)?;
        session
            .last_touched_ms
            .store(unix_time_ms(), Ordering::Release);
        let (events, dropped) = {
            let ring = lock(&session.ring)?;
            let events: Vec<LiveEvent> = ring
                .events
                .iter()
                .filter(|event| event.cursor().value() > cursor.value())
                .take(usize::from(limit))
                .cloned()
                .collect();
            (events, ring.dropped)
        };
        let next_cursor = events.last().map(LiveEvent::cursor).unwrap_or(cursor);
        let active = !session.stopped.load(Ordering::Acquire)
            && lock(&session.reader)?
                .as_ref()
                .is_some_and(|handle| !handle.is_finished());
        Ok(LiveEventPage::new(session_id, events, next_cursor, dropped, active)?)
    }

    fn stop(&self, session_id: LiveSessionId) -> Result<(), LiveError> {
        let session = lock(&self.inner.sessions)?.remove(&session_id);
        let Some(session) = session else {
            return Err(LiveError::SessionNotFound);
        };
        stop_session(&session);
        Ok(())
    }

    fn session(&self, session_id: LiveSessionId) -> Result<Arc<LiveSession>, LiveError> {
        lock(&self.inner.sessions)?
            .get(&session_id)
            .cloned()
            .ok_or(LiveError::SessionNotFound)
    }

    /// Opportunistically reap sessions idle past `LIVE_SESSION_IDLE_TTL_MS`.
    /// Called at the top of `Begin`/`Read`; see the constant's doc comment
    /// for the accepted "no further calls at all" edge case.
    fn reap_expired(&self) -> Result<(), LiveError> {
        let now = unix_time_ms();
        let expired: Vec<(LiveSessionId, Arc<LiveSession>)> = {
            let mut sessions = lock(&self.inner.sessions)?;
            let expired_ids: Vec<LiveSessionId> = sessions
                .iter()
                .filter(|(_, session)| {
                    now.saturating_sub(session.last_touched_ms.load(Ordering::Acquire))
                        >= LIVE_SESSION_IDLE_TTL_MS
                })
                .map(|(session_id, _)| *session_id)
                .collect();
            expired_ids
                .into_iter()
                .filter_map(|session_id| sessions.remove(&session_id).map(|session| (session_id, session)))
                .collect()
        };
        for (_, session) in expired {
            stop_session(&session);
        }
        Ok(())
    }
}

/// Abort the reader task (best-effort, fire-and-forget) and mark the
/// session stopped. The caller is responsible for having already removed
/// the session from the manager's map — dropping the returned `Arc` (and
/// therefore the held `BrowserLease`) is what actually releases the worker.
fn stop_session(session: &LiveSession) {
    session.stopped.store(true, Ordering::Release);
    if let Ok(mut reader) = session.reader.lock() {
        if let Some(handle) = reader.take() {
            handle.abort();
        }
    }
}

async fn run_reader(session: Arc<LiveSession>, mut devtools: PageDevTools) {
    loop {
        let Some(event) = devtools.next_event().await else {
            return;
        };
        if session.stopped.load(Ordering::Acquire) {
            return;
        }
        if let Some(live_event) = translate_event(&session, event) {
            push_event(&session, live_event);
        }
    }
}

fn translate_event(session: &LiveSession, event: DevToolsEvent) -> Option<LiveEvent> {
    let now = unix_time_ms();
    let kind = match event {
        DevToolsEvent::Network(network) => {
            // Learn requestId -> url from every Network event that carries
            // one, regardless of the active filter, so frame-only events
            // (which never carry a url themselves) can still be backfilled
            // even under `websocket_only` (which would otherwise filter out
            // the correlating `requestWillBeSent`/`responseReceived` event).
            remember_request_url(session, &network);
            if !session.filter.network() {
                return None;
            }
            if session.filter.websocket_only() && !is_websocket_or_sse(&network.method) {
                return None;
            }
            resolve_network_kind(session, network, now)
        }
        DevToolsEvent::Console(console) => {
            if !session.filter.console() {
                return None;
            }
            console_event_kind(console)
        }
    };
    let cursor = LiveCursor::new(session.sequence.fetch_add(1, Ordering::AcqRel) + 1);
    LiveEvent::new(cursor, now, kind).ok()
}

/// Route a `Network.*` event to a typed kind for the two frame-bearing
/// WebSocket methods and the one SSE method; every other method (including
/// WS metadata events like `webSocketCreated`/`webSocketClosed`) keeps the
/// existing generic `Network` shape. Typed parsing itself is best-effort:
/// if the expected CDP params shape is missing or malformed, this falls
/// back to the generic kind rather than dropping the event.
fn resolve_network_kind(session: &LiveSession, network: NetworkEvent, now: u64) -> LiveEventKind {
    match network.method.as_str() {
        "Network.webSocketFrameSent" => {
            parse_websocket_frame(session, &network, WebSocketDirection::Sent, now)
                .unwrap_or_else(|| network_event_kind(network))
        }
        "Network.webSocketFrameReceived" => {
            parse_websocket_frame(session, &network, WebSocketDirection::Received, now)
                .unwrap_or_else(|| network_event_kind(network))
        }
        "Network.eventSourceMessageReceived" => parse_sse_event(session, &network, now)
            .unwrap_or_else(|| network_event_kind(network)),
        _ => network_event_kind(network),
    }
}

fn network_event_kind(network: NetworkEvent) -> LiveEventKind {
    let (params, truncated) = bound_params(&network.params);
    LiveEventKind::Network {
        method: bounded_string(&network.method, MAX_LIVE_METHOD_BYTES),
        url: network.url.map(|url| bounded_string(&url, MAX_LIVE_URL_BYTES)),
        status: network.status,
        params,
        truncated,
    }
}

/// Parse `Network.webSocketFrameSent/Received` params
/// (`{requestId, timestamp, response: {opcode, mask, payloadData}}`) into a
/// typed frame. Per the CDP `Network.WebSocketFrame` type, `payloadData` is
/// the literal UTF-8 text when `opcode == 1` (text) and base64-encoded raw
/// bytes for every other opcode. Returns `None` — asking the caller to fall
/// back to the generic `Network` kind — if `opcode`/`payloadData` are
/// missing or the opcode is not one of the six RFC 6455 values a real frame
/// can carry.
fn parse_websocket_frame(
    session: &LiveSession,
    network: &NetworkEvent,
    direction: WebSocketDirection,
    now: u64,
) -> Option<LiveEventKind> {
    let response = network.params.get("response")?;
    let opcode_raw = u8::try_from(response.get("opcode")?.as_u64()?).ok()?;
    let opcode = WebSocketOpcode::from_rfc6455(opcode_raw)?;
    let payload_text = response.get("payloadData")?.as_str()?;
    let (payload, truncated) = decode_websocket_payload(opcode, payload_text);
    let url = resolve_request_url(session, network);
    WebSocketFrame::new(direction, opcode, payload, truncated, now, url)
        .ok()
        .map(LiveEventKind::WebSocketFrame)
}

/// Parse `Network.eventSourceMessageReceived` params
/// (`{requestId, timestamp, eventName, eventId, data}`) into a typed SSE
/// event. `eventName`/`eventId` are mapped from CDP's empty-string
/// "unset" convention to `None`. Returns `None` (generic-kind fallback) if
/// `data` is missing.
fn parse_sse_event(session: &LiveSession, network: &NetworkEvent, now: u64) -> Option<LiveEventKind> {
    let data = network.params.get("data")?.as_str()?;
    let (data, truncated) = if data.len() > MAX_LIVE_NETWORK_PARAMS_BYTES {
        (truncate_text_payload(data, MAX_LIVE_NETWORK_PARAMS_BYTES), true)
    } else {
        (data.as_bytes().to_vec(), false)
    };
    let event_type = network
        .params
        .get("eventName")
        .and_then(|value| value.as_str())
        .filter(|name| !name.is_empty())
        .map(|name| bounded_string(name, MAX_LIVE_SSE_EVENT_TYPE_BYTES));
    let id = network
        .params
        .get("eventId")
        .and_then(|value| value.as_str())
        .filter(|id| !id.is_empty())
        .map(|id| bounded_string(id, MAX_LIVE_SSE_ID_BYTES));
    let url = resolve_request_url(session, network);
    SseEvent::new(event_type, data, truncated, id, now, url)
        .ok()
        .map(LiveEventKind::SseEvent)
}

/// Decode a CDP `WebSocketFrame.payloadData` string per its documented
/// opcode-dependent encoding, bounding the result to
/// `MAX_LIVE_NETWORK_PARAMS_BYTES` (truncated, not dropped).
fn decode_websocket_payload(opcode: WebSocketOpcode, payload_text: &str) -> (Vec<u8>, bool) {
    if opcode == WebSocketOpcode::Text {
        if payload_text.len() > MAX_LIVE_NETWORK_PARAMS_BYTES {
            (
                truncate_text_payload(payload_text, MAX_LIVE_NETWORK_PARAMS_BYTES),
                true,
            )
        } else {
            (payload_text.as_bytes().to_vec(), false)
        }
    } else {
        let mut bytes = BASE64_STANDARD
            .decode(payload_text)
            .unwrap_or_else(|_| payload_text.as_bytes().to_vec());
        if bytes.len() > MAX_LIVE_NETWORK_PARAMS_BYTES {
            bytes.truncate(MAX_LIVE_NETWORK_PARAMS_BYTES);
            (bytes, true)
        } else {
            (bytes, false)
        }
    }
}

/// Truncate `text` to at most `max_len` bytes at a UTF-8 char boundary.
/// Unlike [`bounded_string`], this does not strip embedded NUL bytes — it
/// bounds a WebSocket/SSE payload, not a protocol string field, so payload
/// content must not be altered beyond the truncation point itself.
fn truncate_text_payload(text: &str, max_len: usize) -> Vec<u8> {
    let mut boundary = text.len().min(max_len);
    while boundary > 0 && !text.is_char_boundary(boundary) {
        boundary -= 1;
    }
    text.as_bytes()[..boundary].to_vec()
}

fn console_event_kind(console: ConsoleEvent) -> LiveEventKind {
    LiveEventKind::Console {
        level: bounded_string(&console.level, MAX_LIVE_CONSOLE_LEVEL_BYTES),
        text: bounded_string(&console.text, MAX_LIVE_CONSOLE_TEXT_BYTES),
    }
}

fn is_websocket_or_sse(method: &str) -> bool {
    method.starts_with("Network.webSocket") || method.starts_with("Network.eventSource")
}

/// Cache `requestId -> url` from a `Network.*` event that carries one, best
/// effort (a poisoned mutex is treated as "nothing learned").
fn remember_request_url(session: &LiveSession, network: &NetworkEvent) {
    let (Some(url), Some(request_id)) = (&network.url, network.params.get("requestId").and_then(|v| v.as_str())) else {
        return;
    };
    if let Ok(mut cache) = session.request_urls.lock() {
        cache.remember(request_id, url);
    }
}

/// Resolve a frame-only event's url: the event's own url if CDP happened to
/// set one, else a lookup by `requestId` in the session's correlation
/// cache, else `None`.
fn resolve_request_url(session: &LiveSession, network: &NetworkEvent) -> Option<String> {
    if let Some(url) = &network.url {
        return Some(bounded_string(url, MAX_LIVE_URL_BYTES));
    }
    let request_id = network.params.get("requestId").and_then(|value| value.as_str())?;
    session
        .request_urls
        .lock()
        .ok()
        .and_then(|cache| cache.lookup(request_id))
        .map(|url| bounded_string(&url, MAX_LIVE_URL_BYTES))
}

fn push_event(session: &LiveSession, event: LiveEvent) {
    let Ok(mut ring) = session.ring.lock() else {
        return;
    };
    if ring.events.len() >= MAX_LIVE_RING_CAPACITY {
        ring.events.pop_front();
        ring.dropped = ring.dropped.saturating_add(1);
    }
    ring.events.push_back(event);
}

/// Bound raw JSON-encoded CDP params to `MAX_LIVE_NETWORK_PARAMS_BYTES`,
/// truncating (never dropping the whole event) so method/url/status
/// metadata always survives even when a WS/SSE frame payload is oversized.
fn bound_params(params: &serde_json::Value) -> (Vec<u8>, bool) {
    let mut bytes = serde_json::to_vec(params).unwrap_or_default();
    if bytes.len() > MAX_LIVE_NETWORK_PARAMS_BYTES {
        bytes.truncate(MAX_LIVE_NETWORK_PARAMS_BYTES);
        (bytes, true)
    } else {
        (bytes, false)
    }
}

/// Truncate `value` to at most `max_len` bytes at a UTF-8 char boundary and
/// strip NUL bytes (the only character the wire's string bounds reject).
fn bounded_string(value: &str, max_len: usize) -> String {
    let mut boundary = value.len().min(max_len);
    while boundary > 0 && !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    value[..boundary].replace('\0', "")
}

fn validate_profile_id(profile_id: &str) -> Result<(), LiveError> {
    dig2browser::identity::validate_profile_id(profile_id).map_err(|_| LiveError::InvalidProfileId)
}

fn lock<T>(mutex: &StdMutex<T>) -> Result<std::sync::MutexGuard<'_, T>, LiveError> {
    mutex.lock().map_err(|_| LiveError::ManagerStatePoisoned)
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or_default()
}

#[derive(Debug, thiserror::Error)]
pub enum LiveError {
    #[error("live-event admission is closed")]
    AdmissionClosed,
    #[error("live-event session identifier is already active")]
    SessionConflict,
    #[error("live-event session concurrency limit reached")]
    AtCapacity,
    #[error("live-event session was not found")]
    SessionNotFound,
    #[error("live-event profile identifier is invalid")]
    InvalidProfileId,
    #[error("live-event manager state is poisoned")]
    ManagerStatePoisoned,
    #[error(transparent)]
    Protocol(#[from] dig2browser_protocol::ProtocolError),
    #[error(transparent)]
    Station(#[from] StationError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_opcode_payload_is_literal_utf8_bytes() {
        let (payload, truncated) = decode_websocket_payload(WebSocketOpcode::Text, "hello");
        assert_eq!(payload, b"hello");
        assert!(!truncated);
    }

    #[test]
    fn binary_opcode_payload_is_base64_decoded() {
        let encoded = BASE64_STANDARD.encode([0xDE, 0xAD, 0xBE, 0xEF]);
        let (payload, truncated) = decode_websocket_payload(WebSocketOpcode::Binary, &encoded);
        assert_eq!(payload, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(!truncated);
    }

    #[test]
    fn binary_opcode_falls_back_to_raw_bytes_when_not_valid_base64() {
        let (payload, truncated) = decode_websocket_payload(WebSocketOpcode::Binary, "not-base64!!");
        assert_eq!(payload, b"not-base64!!");
        assert!(!truncated);
    }

    #[test]
    fn oversized_payload_is_truncated_with_the_flag_set() {
        let text = "x".repeat(MAX_LIVE_NETWORK_PARAMS_BYTES + 16);
        let (payload, truncated) = decode_websocket_payload(WebSocketOpcode::Text, &text);
        assert_eq!(payload.len(), MAX_LIVE_NETWORK_PARAMS_BYTES);
        assert!(truncated);

        let binary = BASE64_STANDARD.encode(vec![7_u8; MAX_LIVE_NETWORK_PARAMS_BYTES + 16]);
        let (payload, truncated) = decode_websocket_payload(WebSocketOpcode::Binary, &binary);
        assert_eq!(payload.len(), MAX_LIVE_NETWORK_PARAMS_BYTES);
        assert!(truncated);
    }

    #[test]
    fn text_payload_truncation_snaps_to_a_char_boundary_and_keeps_nul() {
        // 3-byte UTF-8 char ('€') straddling the requested cut point.
        let text = format!("{}€", "a".repeat(4));
        let truncated = truncate_text_payload(&text, 5);
        assert!(std::str::from_utf8(&truncated).is_ok());
        assert_eq!(truncated, b"aaaa");

        // Unlike `bounded_string`, payload truncation must not strip NUL —
        // it bounds arbitrary content, not a protocol string field.
        let with_nul = "a\0b";
        let kept = truncate_text_payload(with_nul, with_nul.len());
        assert_eq!(kept, b"a\0b");
    }

    #[test]
    fn request_url_cache_remembers_first_url_and_evicts_oldest_over_capacity() {
        let mut cache = RequestUrlCache::new();
        cache.remember("req-1", "https://example.test/first");
        // A later url for the same requestId does not overwrite the first.
        cache.remember("req-1", "https://example.test/second");
        assert_eq!(
            cache.lookup("req-1").as_deref(),
            Some("https://example.test/first")
        );

        for index in 0..MAX_LIVE_REQUEST_URL_ENTRIES {
            cache.remember(&format!("bulk-{index}"), "https://example.test/bulk");
        }
        // The very first entry (`req-1`) must have been evicted once the
        // cache exceeded its bound.
        assert_eq!(cache.lookup("req-1"), None);
        assert!(cache.lookup(&format!("bulk-{}", MAX_LIVE_REQUEST_URL_ENTRIES - 1)).is_some());
    }
}
