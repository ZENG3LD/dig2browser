//! Durable monitor manager: a live DevTools subscription whose captured
//! WebSocket frames are written through a [`MonitorSink`] (content-addressed
//! store + append-only journal) instead of a RAM ring.
//!
//! Where [`crate::live::LiveCaptureManager`] is ephemeral — its ring dies with
//! the worker — a durable monitor persists every frame (payload to the CAS,
//! metadata to the journal, fsync per frame), so it **survives a station
//! restart**: a successor reconciles any journal a crash left open and a reader
//! resumes from a cursor, reading frame payloads back from the CAS byte-exact.
//! Frames are captured from the same `Network.webSocketFrame{Sent,Received}`
//! DevTools events the live path parses; only the sink differs.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use dig2browser::agentic::{AgentCommand, CapabilitySet};
use dig2browser::browser::{DevToolsEvent, NetworkEvent, PageDevTools};
use dig2browser_protocol::{
    ArtifactRef, BrowserPersona, LiveFilter, MonitorCursor, MonitorEvent, MonitorEventPage,
    MonitorFrame, MonitorStopReason, ProfileClass, ProtocolError, WebSocketDirection,
    WebSocketOpcode, MAX_LIVE_NETWORK_PARAMS_BYTES,
};
use dig2browser_trace::{LedgerError, MonitorJournal, MonitorSink, TraceLedger};
use tokio::task::JoinHandle;

use crate::{BrowserLease, BrowserStation, IdentityRequest, StationError};

const CAS_SUBDIR: &str = "cas";
const JOURNALS_SUBDIR: &str = "journals";
const JOURNAL_EXTENSION: &str = "journal";

/// Owns the durable-monitor content-addressed store and journal directory, plus
/// the set of live (resident) monitors. Constructed once per station over a
/// monitor root; on open it reconciles any journal a previous run left open.
#[derive(Clone)]
pub struct DurableMonitorManager {
    inner: Arc<Inner>,
}

struct Inner {
    station: BrowserStation,
    ledger: Arc<TraceLedger>,
    journals_dir: PathBuf,
    sessions: StdMutex<HashMap<String, Arc<MonitorSession>>>,
    accepting: AtomicBool,
}

struct MonitorSession {
    /// Held only for its `Drop` side effect: releasing the station lease. Never
    /// read directly (mirrors `crate::live::LiveSession::_lease`).
    _lease: BrowserLease,
    sink: Arc<StdMutex<MonitorSink>>,
    reader: StdMutex<Option<JoinHandle<()>>>,
    stopped: AtomicBool,
}

impl DurableMonitorManager {
    /// Open the manager over `monitor_root`: `<root>/cas` holds the shared
    /// content-addressed store, `<root>/journals` holds one append-only journal
    /// per monitor. Reconciles every journal without a terminal `Stopped`
    /// (appending a synthetic `Stopped(Interrupted(SuccessorReconciliation))`),
    /// so a crash-left-open monitor becomes cleanly terminal on the next run.
    pub fn open(
        station: BrowserStation,
        monitor_root: impl AsRef<Path>,
    ) -> Result<Self, MonitorError> {
        let monitor_root = monitor_root.as_ref();
        let ledger = TraceLedger::open_at(monitor_root.join(CAS_SUBDIR), unix_time_ms())?;
        let journals_dir = monitor_root.join(JOURNALS_SUBDIR);
        std::fs::create_dir_all(&journals_dir).map_err(LedgerError::Io)?;
        reconcile_journals(&journals_dir)?;
        Ok(Self {
            inner: Arc::new(Inner {
                station,
                ledger: Arc::new(ledger),
                journals_dir,
                sessions: StdMutex::new(HashMap::new()),
                accepting: AtomicBool::new(true),
            }),
        })
    }

    /// Begin a durable monitor over a freshly leased worker navigated to `url`,
    /// returning its identifier. Frames start flowing to the journal + CAS
    /// immediately; the monitor persists across restart until [`stop`](Self::stop).
    pub async fn begin(
        &self,
        profile_id: &str,
        profile_class: ProfileClass,
        persona: BrowserPersona,
        url: String,
        filter: LiveFilter,
    ) -> Result<String, MonitorError> {
        if !self.inner.accepting.load(Ordering::Acquire) {
            return Err(MonitorError::AdmissionClosed);
        }
        let monitor_id = uuid::Uuid::new_v4().simple().to_string();
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
        lease
            .execute(AgentCommand::Navigate { url: url.clone() })
            .await?;
        let devtools = lease.subscribe_devtools().await?;

        let now = unix_time_ms();
        let journal_path = self.journal_path(&monitor_id);
        let mut sink = MonitorSink::open_at(Arc::clone(&self.inner.ledger), &journal_path, now)?;
        sink.start(url, filter, now)?;
        let session = Arc::new(MonitorSession {
            _lease: lease,
            sink: Arc::new(StdMutex::new(sink)),
            reader: StdMutex::new(None),
            stopped: AtomicBool::new(false),
        });
        let reader_session = Arc::clone(&session);
        let reader = tokio::spawn(async move { run_reader(reader_session, devtools).await });
        *lock(&session.reader)? = Some(reader);

        let mut sessions = lock(&self.inner.sessions)?;
        if !self.inner.accepting.load(Ordering::Acquire) {
            drop(sessions);
            stop_session(&session);
            return Err(MonitorError::AdmissionClosed);
        }
        if sessions.contains_key(&monitor_id) {
            drop(sessions);
            stop_session(&session);
            return Err(MonitorError::SessionConflict);
        }
        sessions.insert(monitor_id.clone(), session);
        Ok(monitor_id)
    }

    /// Records strictly after `cursor`, at most `limit`. Served from the live
    /// sink for a resident monitor, or read from the durable journal on disk for
    /// one that is not resident (e.g. after a restart).
    pub fn read(
        &self,
        monitor_id: &str,
        cursor: MonitorCursor,
        limit: usize,
    ) -> Result<Vec<MonitorEvent>, MonitorError> {
        if let Some(session) = lock(&self.inner.sessions)?.get(monitor_id).cloned() {
            return Ok(lock(&session.sink)?.read(cursor, limit));
        }
        let journal_path = self.journal_path(monitor_id);
        if !journal_path.exists() {
            return Err(MonitorError::SessionNotFound);
        }
        // Not resident: the manager already reconciled it on open, so a plain
        // deferred open replays the durable records without mutating them.
        let journal = MonitorJournal::open_deferred(&journal_path)?;
        Ok(journal.read(cursor, limit))
    }

    /// [`read`](Self::read) wrapped as a wire [`MonitorEventPage`] — records
    /// after `cursor`, with the next cursor and whether the page reaches the
    /// journal's terminal record.
    pub fn read_page(
        &self,
        monitor_id: &str,
        cursor: MonitorCursor,
        limit: usize,
    ) -> Result<MonitorEventPage, MonitorError> {
        let events = self.read(monitor_id, cursor, limit)?;
        let next_cursor = events.last().map_or(cursor, MonitorEvent::cursor);
        let terminal = events.last().is_some_and(MonitorEvent::is_terminal);
        Ok(MonitorEventPage::new(
            monitor_id.to_owned(),
            events,
            next_cursor,
            terminal,
        )?)
    }

    /// Read a recorded frame's payload back from the CAS (byte-exact, hash
    /// re-validated); an empty frame yields an empty payload. Works whether or
    /// not the monitor is resident — the CAS is shared and always available.
    pub fn frame_payload(&self, frame: &MonitorFrame) -> Result<Vec<u8>, MonitorError> {
        match frame.artifact() {
            None => Ok(Vec::new()),
            Some(reference) => Ok(self.inner.ledger.read_orphan_artifact(reference)?),
        }
    }

    /// Read a frame payload directly by its CAS reference (the wire path, where
    /// the client already holds the `ArtifactRef` from a records page).
    pub fn read_frame_by_ref(&self, artifact: &ArtifactRef) -> Result<Vec<u8>, MonitorError> {
        Ok(self.inner.ledger.read_orphan_artifact(artifact)?)
    }

    /// Stop a resident monitor: append a terminal `Stopped(Requested)`, then
    /// abort AND await its reader so the journal handle (and its exclusive lock)
    /// is fully released before returning — a subsequent [`read`](Self::read) of
    /// the now-non-resident monitor opens the journal cleanly.
    pub async fn stop(&self, monitor_id: &str) -> Result<(), MonitorError> {
        let session = lock(&self.inner.sessions)?.remove(monitor_id);
        let Some(session) = session else {
            return Err(MonitorError::SessionNotFound);
        };
        if let Ok(mut sink) = session.sink.lock() {
            let _ = sink.stop(MonitorStopReason::Requested, unix_time_ms());
        }
        session.stopped.store(true, Ordering::Release);
        let handle = lock(&session.reader)?.take();
        if let Some(handle) = handle {
            handle.abort();
            let _ = handle.await;
        }
        // The reader has released its session Arc; dropping the local `session`
        // on return releases the last one, closing the journal + its lock.
        Ok(())
    }

    /// Whether a monitor's journal is terminal (stopped or reconciled).
    pub fn is_terminal(&self, monitor_id: &str) -> Result<bool, MonitorError> {
        if let Some(session) = lock(&self.inner.sessions)?.get(monitor_id).cloned() {
            return Ok(lock(&session.sink)?.is_terminal());
        }
        let journal_path = self.journal_path(monitor_id);
        if !journal_path.exists() {
            return Err(MonitorError::SessionNotFound);
        }
        Ok(MonitorJournal::open_deferred(&journal_path)?.is_terminal())
    }

    /// Stop admission and drain every resident monitor, appending a terminal
    /// `Stopped(Requested)` to each so a clean shutdown is distinguishable from a
    /// crash (which a successor would instead reconcile). Returns `true` if the
    /// drain timed out.
    pub async fn shutdown(&self, timeout: Duration) -> Result<bool, MonitorError> {
        self.drain(true, timeout).await
    }

    /// Stop admission and release every resident monitor WITHOUT stopping it,
    /// leaving its journal non-terminal for a successor to reconcile — the
    /// deterministic equivalent of a crash's end state (locks released, records
    /// intact, no clean `Stopped`). Awaits the reader tasks so their journal
    /// handles are actually released before returning.
    pub async fn abandon(&self, timeout: Duration) -> Result<bool, MonitorError> {
        self.drain(false, timeout).await
    }

    async fn drain(&self, append_stop: bool, timeout: Duration) -> Result<bool, MonitorError> {
        self.inner.accepting.store(false, Ordering::Release);
        let sessions: Vec<Arc<MonitorSession>> = lock(&self.inner.sessions)?
            .drain()
            .map(|(_, session)| session)
            .collect();
        let mut handles = Vec::with_capacity(sessions.len());
        for session in &sessions {
            if append_stop {
                if let Ok(mut sink) = session.sink.lock() {
                    let _ = sink.stop(MonitorStopReason::Requested, unix_time_ms());
                }
            }
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
        // Dropping the sessions here releases the last strong refs to their
        // sinks (the reader tasks, now joined, released theirs), closing the
        // journal handles and their exclusive locks.
        drop(sessions);
        Ok(!drained)
    }

    fn journal_path(&self, monitor_id: &str) -> PathBuf {
        self.inner
            .journals_dir
            .join(format!("{monitor_id}.{JOURNAL_EXTENSION}"))
    }
}

/// Abort the reader (best-effort) and mark the session stopped. The caller must
/// have already removed it from the map; dropping the returned `Arc` releases the
/// lease.
fn stop_session(session: &MonitorSession) {
    session.stopped.store(true, Ordering::Release);
    if let Ok(mut reader) = session.reader.lock() {
        if let Some(handle) = reader.take() {
            handle.abort();
        }
    }
}

async fn run_reader(session: Arc<MonitorSession>, mut devtools: PageDevTools) {
    loop {
        let Some(event) = devtools.next_event().await else {
            return;
        };
        if session.stopped.load(Ordering::Acquire) {
            return;
        }
        let DevToolsEvent::Network(network) = event else {
            continue;
        };
        let Some((direction, opcode, payload, truncated)) = parse_ws_frame(&network) else {
            continue;
        };
        let now = unix_time_ms();
        if let Ok(mut sink) = session.sink.lock() {
            // A durable-write failure (disk full, I/O error) drops this frame
            // rather than tearing down the capture; the journal stays consistent
            // (CAS-first ordering) and later frames still record.
            let _ = sink.record_frame(direction, opcode, &payload, truncated, now);
        }
    }
}

/// Parse a `Network.webSocketFrame{Sent,Received}` event into the fields a
/// durable frame record needs. Returns `None` for any other network event or a
/// malformed frame (no opcode / payload, or a non-RFC-6455 opcode).
fn parse_ws_frame(
    network: &NetworkEvent,
) -> Option<(WebSocketDirection, WebSocketOpcode, Vec<u8>, bool)> {
    let direction = match network.method.as_str() {
        "Network.webSocketFrameSent" => WebSocketDirection::Sent,
        "Network.webSocketFrameReceived" => WebSocketDirection::Received,
        _ => return None,
    };
    let response = network.params.get("response")?;
    let opcode = WebSocketOpcode::from_rfc6455(u8::try_from(response.get("opcode")?.as_u64()?).ok()?)?;
    let payload_text = response.get("payloadData")?.as_str()?;
    let (payload, truncated) = decode_ws_payload(opcode, payload_text);
    Some((direction, opcode, payload, truncated))
}

/// Decode a CDP `WebSocketFrame.payloadData` per its opcode-dependent encoding
/// (literal UTF-8 for text, base64 otherwise), bounded to
/// `MAX_LIVE_NETWORK_PARAMS_BYTES` (truncated, not dropped).
fn decode_ws_payload(opcode: WebSocketOpcode, payload_text: &str) -> (Vec<u8>, bool) {
    if opcode == WebSocketOpcode::Text {
        if payload_text.len() > MAX_LIVE_NETWORK_PARAMS_BYTES {
            let mut boundary = MAX_LIVE_NETWORK_PARAMS_BYTES;
            while boundary > 0 && !payload_text.is_char_boundary(boundary) {
                boundary -= 1;
            }
            (payload_text.as_bytes()[..boundary].to_vec(), true)
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

/// Reconcile every `*.journal` in `journals_dir`: opening each with `open_at`
/// appends a synthetic terminal record to any that a crash left open.
fn reconcile_journals(journals_dir: &Path) -> Result<(), MonitorError> {
    let now = unix_time_ms();
    for entry in std::fs::read_dir(journals_dir).map_err(LedgerError::Io)? {
        let entry = entry.map_err(LedgerError::Io)?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some(JOURNAL_EXTENSION) {
            continue;
        }
        // open_at reconciles and then the handle is dropped, releasing the lock.
        let _ = MonitorJournal::open_at(&path, now)?;
    }
    Ok(())
}

fn lock<T>(mutex: &StdMutex<T>) -> Result<std::sync::MutexGuard<'_, T>, MonitorError> {
    mutex.lock().map_err(|_| MonitorError::StatePoisoned)
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or_default()
}

#[derive(Debug, thiserror::Error)]
pub enum MonitorError {
    #[error("durable monitor admission is closed")]
    AdmissionClosed,
    #[error("durable monitor identifier is already active")]
    SessionConflict,
    #[error("durable monitor was not found")]
    SessionNotFound,
    #[error("durable monitor manager state is poisoned")]
    StatePoisoned,
    #[error("durable monitor storage error: {0}")]
    Ledger(#[from] LedgerError),
    #[error("durable monitor protocol error: {0}")]
    Protocol(#[from] ProtocolError),
    #[error(transparent)]
    Station(#[from] StationError),
}
