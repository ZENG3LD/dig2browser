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

use dig2browser::agentic::{AgentCommand, CapabilitySet};
use dig2browser::browser::{ConsoleEvent, DevToolsEvent, NetworkEvent, PageDevTools};
use dig2browser_protocol::{
    BrowserPersona, LiveCursor, LiveEvent, LiveEventKind, LiveEventPage, LiveFilter,
    LiveRequest, LiveResponse, LiveSessionId, LiveTarget, ProfileClass, MAX_LIVE_CONSOLE_LEVEL_BYTES,
    MAX_LIVE_CONSOLE_TEXT_BYTES, MAX_LIVE_EVENTS, MAX_LIVE_METHOD_BYTES,
    MAX_LIVE_NETWORK_PARAMS_BYTES, MAX_LIVE_URL_BYTES,
};
use tokio::task::JoinHandle;

use crate::{BrowserLease, BrowserStation, IdentityRequest, StationError};

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
    let kind = match event {
        DevToolsEvent::Network(network) => {
            if !session.filter.network() {
                return None;
            }
            if session.filter.websocket_only() && !is_websocket_or_sse(&network.method) {
                return None;
            }
            network_event_kind(network)
        }
        DevToolsEvent::Console(console) => {
            if !session.filter.console() {
                return None;
            }
            console_event_kind(console)
        }
    };
    let cursor = LiveCursor::new(session.sequence.fetch_add(1, Ordering::AcqRel) + 1);
    LiveEvent::new(cursor, unix_time_ms(), kind).ok()
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

fn console_event_kind(console: ConsoleEvent) -> LiveEventKind {
    LiveEventKind::Console {
        level: bounded_string(&console.level, MAX_LIVE_CONSOLE_LEVEL_BYTES),
        text: bounded_string(&console.text, MAX_LIVE_CONSOLE_TEXT_BYTES),
    }
}

fn is_websocket_or_sse(method: &str) -> bool {
    method.starts_with("Network.webSocket") || method.starts_with("Network.eventSource")
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
