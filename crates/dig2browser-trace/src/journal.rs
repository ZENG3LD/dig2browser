//! Crash-safe append-only monitor journal.
//!
//! A durable monitor is an open-ended stream, so it does NOT fit the finite-task
//! [`crate::TraceLedger`] (fixed `step_count`, `MAX_COLLECTION_EVENTS` ceiling,
//! O(n) replay-before-every-append). It also is NOT the crawler's snapshot store
//! (whole-state rewrite + slot rotation — O(n) per record for a growing stream).
//! It is a purpose-built append-only log:
//!
//! ```text
//! file  = HEADER  RECORD*
//! HEADER = b"D2MJ"  version:u16-le  reserved:u16-le          (8 bytes)
//! RECORD = len:u32-le  checksum:[u8;8]  payload:[u8; len]
//! ```
//!
//! `checksum` is the first 8 bytes of `SHA-256(payload)`; `payload` is a
//! [`MonitorEvent`] encoded by its own fail-closed codec. Every append is
//! `write_all` + `fsync`, so a fully written+synced record is durable. A crash
//! mid-append can only damage the trailing bytes, so on open a single torn
//! trailing record is tolerated (truncated away); any damage to a fully present
//! record (checksum or decode failure) or in the middle of the file is treated
//! as corruption and fails closed. Frame *payloads* are not stored here — they
//! live content-addressed in the trace CAS and are referenced by [`ArtifactRef`]
//! inside each `FrameCommitted` record.
//!
//! Cursors are 1-based record positions; a reader starts at
//! [`MonitorCursor::START`] (0) and reads forward. Exactly one terminal
//! `Stopped` record closes a journal; a successor that opens a journal left
//! open by a crash appends a synthetic
//! `Stopped(Interrupted(SuccessorReconciliation))`.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use dig2browser_protocol::{
    ArtifactRef, InterruptedReason, LiveFilter, MonitorCursor, MonitorEvent, MonitorEventKind,
    MonitorFrame, MonitorStopReason, WebSocketDirection, WebSocketOpcode, MAX_MONITOR_EVENT_BYTES,
};
use sha2::{Digest, Sha256};

use crate::{sync_directory, unix_time_ms, LedgerError};

const JOURNAL_MAGIC: [u8; 4] = *b"D2MJ";
const JOURNAL_VERSION: u16 = 1;
const HEADER_BYTES: u64 = 8;
/// `len:u32` + `checksum:[u8;8]`.
const RECORD_HEADER_BYTES: u64 = 12;
const CHECKSUM_BYTES: usize = 8;
/// Payload bound per record, matching the protocol's encoded-event bound.
const MAX_RECORD_PAYLOAD_BYTES: u64 = MAX_MONITOR_EVENT_BYTES as u64;

/// A single-writer, crash-safe, append-only monitor journal. Holds an exclusive
/// advisory lock on its file for its whole lifetime; the in-memory record vector
/// is the durable file replayed on open, so reads are served without touching
/// disk and appends stay O(1).
pub struct MonitorJournal {
    path: PathBuf,
    file: File,
    records: Vec<MonitorEvent>,
    terminal: bool,
    last_timestamp: u64,
}

impl MonitorJournal {
    /// Open (creating if absent) the journal at `path`, replaying and truncating
    /// any torn trailing record, then reconcile it against the current time: if
    /// it holds records but no terminal `Stopped`, append a synthetic
    /// `Stopped(Interrupted(SuccessorReconciliation))`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LedgerError> {
        Self::open_at(path, unix_time_ms()?)
    }

    /// [`open`](Self::open) with an explicit successor timestamp for the
    /// reconciliation record (tests and deterministic callers).
    pub fn open_at(
        path: impl AsRef<Path>,
        successor_timestamp_unix_ms: u64,
    ) -> Result<Self, LedgerError> {
        let mut journal = Self::open_deferred(path)?;
        journal.reconcile_at(successor_timestamp_unix_ms)?;
        Ok(journal)
    }

    /// Open and replay WITHOUT reconciling — the caller inspects
    /// [`is_terminal`](Self::is_terminal) / [`record_count`](Self::record_count)
    /// and decides whether to [`reconcile_at`](Self::reconcile_at) or resume.
    pub fn open_deferred(path: impl AsRef<Path>) -> Result<Self, LedgerError> {
        let path = path.as_ref().to_path_buf();
        let parent = path
            .parent()
            .ok_or(LedgerError::Corrupt("journal path has no parent"))?;
        fs::create_dir_all(parent)?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(LedgerError::WriterLocked),
            Err(TryLockError::Error(error)) => return Err(LedgerError::Io(error)),
        }
        sync_directory(parent)?;

        let scan = scan_records(&mut file)?;
        if scan.truncate_to < file_len(&file)? {
            // Remove the torn trailing bytes so the next append starts clean.
            file.set_len(scan.truncate_to)?;
            file.sync_all()?;
        }
        if scan.needs_header {
            file.set_len(0)?;
            file.seek(SeekFrom::Start(0))?;
            file.write_all(&journal_header())?;
            file.sync_all()?;
            sync_directory(parent)?;
        }

        let last_timestamp = scan.records.last().map_or(0, MonitorEvent::timestamp_unix_ms);
        let terminal = scan.records.last().is_some_and(MonitorEvent::is_terminal);
        Ok(Self {
            path,
            file,
            records: scan.records,
            terminal,
            last_timestamp,
        })
    }

    /// The monitored page URL and event filter — must be the journal's first
    /// record.
    pub fn start(
        &mut self,
        url: String,
        filter: LiveFilter,
        timestamp_unix_ms: u64,
    ) -> Result<MonitorEvent, LedgerError> {
        self.append_kind(
            MonitorEventKind::Started { url, filter },
            timestamp_unix_ms,
        )
    }

    /// Append a captured frame's metadata; its payload is already in the CAS,
    /// referenced by `artifact`.
    pub fn commit_frame(
        &mut self,
        direction: WebSocketDirection,
        opcode: WebSocketOpcode,
        truncated: bool,
        artifact: ArtifactRef,
        timestamp_unix_ms: u64,
    ) -> Result<MonitorEvent, LedgerError> {
        let frame = MonitorFrame::new(direction, opcode, truncated, artifact)?;
        self.append_kind(MonitorEventKind::FrameCommitted(frame), timestamp_unix_ms)
    }

    /// Close the journal with a terminal `Stopped` record.
    pub fn stop(
        &mut self,
        reason: MonitorStopReason,
        timestamp_unix_ms: u64,
    ) -> Result<MonitorEvent, LedgerError> {
        self.append_kind(MonitorEventKind::Stopped(reason), timestamp_unix_ms)
    }

    /// If the journal holds records but is not yet terminal, close it with a
    /// synthetic `Stopped(Interrupted(SuccessorReconciliation))`. A no-op on an
    /// empty journal (nothing was ever started) or one already terminal.
    pub fn reconcile_at(&mut self, timestamp_unix_ms: u64) -> Result<(), LedgerError> {
        if self.records.is_empty() || self.terminal {
            return Ok(());
        }
        let timestamp = timestamp_unix_ms.max(self.last_timestamp);
        self.append_kind(
            MonitorEventKind::Stopped(MonitorStopReason::Interrupted(
                InterruptedReason::SuccessorReconciliation,
            )),
            timestamp,
        )?;
        Ok(())
    }

    /// Records strictly after `cursor`, at most `limit`, in order. Mirrors the
    /// trace read model; `limit == 0` yields an empty slice.
    pub fn read(&self, cursor: MonitorCursor, limit: usize) -> Vec<MonitorEvent> {
        self.records
            .iter()
            .filter(|event| event.cursor().value() > cursor.value())
            .take(limit)
            .cloned()
            .collect()
    }

    /// The cursor of the last record (or [`MonitorCursor::START`] if empty).
    pub fn last_cursor(&self) -> MonitorCursor {
        self.records
            .last()
            .map_or(MonitorCursor::START, MonitorEvent::cursor)
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    /// `true` once a terminal `Stopped` record has been written.
    pub fn is_terminal(&self) -> bool {
        self.terminal
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn append_kind(
        &mut self,
        kind: MonitorEventKind,
        timestamp_unix_ms: u64,
    ) -> Result<MonitorEvent, LedgerError> {
        if self.terminal {
            return Err(LedgerError::InvalidTransition("monitor journal is already stopped"));
        }
        match &kind {
            MonitorEventKind::Started { .. } if !self.records.is_empty() => {
                return Err(LedgerError::InvalidTransition("monitor journal already started"));
            }
            MonitorEventKind::Started { .. } => {}
            _ if self.records.is_empty() => {
                return Err(LedgerError::InvalidTransition("monitor record precedes the start record"));
            }
            _ => {}
        }
        if timestamp_unix_ms < self.last_timestamp {
            return Err(LedgerError::InvalidTransition("monitor timestamps must not move backwards"));
        }

        let cursor_value = u64::try_from(self.records.len())
            .ok()
            .and_then(|count| count.checked_add(1))
            .ok_or(LedgerError::Corrupt("monitor cursor overflow"))?;
        let event = MonitorEvent::new(MonitorCursor::new(cursor_value), timestamp_unix_ms, kind)?;
        let payload = event.encode()?;
        append_record(&mut self.file, &payload)?;

        let terminal = event.is_terminal();
        self.records.push(event.clone());
        self.last_timestamp = timestamp_unix_ms;
        if terminal {
            self.terminal = true;
        }
        Ok(event)
    }
}

struct ScanResult {
    records: Vec<MonitorEvent>,
    /// Length the file must be truncated to (end of the last intact record, or
    /// the header when only torn bytes follow it).
    truncate_to: u64,
    /// The file lacked a complete, valid header and must be (re)initialized.
    needs_header: bool,
}

/// Replay the journal file: verify the header, then walk records until a clean
/// EOF or a torn trailing record. A fully present record with a bad checksum or
/// an undecodable payload, or any structural violation (non-contiguous cursor,
/// a record before the start, a record after a terminal), is corruption and
/// fails closed — only trailing incompleteness is tolerated.
fn scan_records(file: &mut File) -> Result<ScanResult, LedgerError> {
    let total = file_len(file)?;
    if total < HEADER_BYTES {
        // Empty, or a header torn during first creation: reinitialize.
        return Ok(ScanResult {
            records: Vec::new(),
            truncate_to: 0,
            needs_header: true,
        });
    }
    file.seek(SeekFrom::Start(0))?;
    let mut header = [0_u8; HEADER_BYTES as usize];
    file.read_exact(&mut header)?;
    if header[..4] != JOURNAL_MAGIC
        || u16::from_le_bytes([header[4], header[5]]) != JOURNAL_VERSION
    {
        return Err(LedgerError::Corrupt("monitor journal header is invalid"));
    }

    let mut records: Vec<MonitorEvent> = Vec::new();
    let mut terminal = false;
    let mut last_timestamp = 0_u64;
    let mut pos = HEADER_BYTES;
    let mut truncate_to = HEADER_BYTES;
    loop {
        let remaining = total - pos;
        if remaining == 0 {
            break;
        }
        if remaining < RECORD_HEADER_BYTES {
            break; // torn record header
        }
        file.seek(SeekFrom::Start(pos))?;
        let mut record_header = [0_u8; RECORD_HEADER_BYTES as usize];
        file.read_exact(&mut record_header)?;
        let len = u64::from(u32::from_le_bytes([
            record_header[0],
            record_header[1],
            record_header[2],
            record_header[3],
        ]));
        if len == 0 || len > MAX_RECORD_PAYLOAD_BYTES {
            break; // torn/garbage length: a synced record always has a valid one
        }
        let payload_start = pos + RECORD_HEADER_BYTES;
        if total - payload_start < len {
            break; // torn payload
        }
        let mut payload = vec![0_u8; usize::try_from(len).map_err(|_| LedgerError::Corrupt("record too large"))?];
        file.read_exact(&mut payload)?;
        if record_header[4..12] != checksum(&payload) {
            // Fully present but corrupt — not a torn tail. Fail closed.
            return Err(LedgerError::Corrupt("monitor record checksum mismatch"));
        }
        let event = MonitorEvent::decode(&payload)?;
        validate_scanned(&records, terminal, last_timestamp, &event)?;
        terminal = event.is_terminal();
        last_timestamp = event.timestamp_unix_ms();
        records.push(event);
        pos = payload_start + len;
        truncate_to = pos;
    }

    Ok(ScanResult {
        records,
        truncate_to,
        needs_header: false,
    })
}

/// Structural checks a replayed record must satisfy relative to the records
/// already accepted. Distinct from the per-record codec validation
/// ([`MonitorEvent::decode`]), which only checks a record in isolation.
fn validate_scanned(
    records: &[MonitorEvent],
    terminal: bool,
    last_timestamp: u64,
    event: &MonitorEvent,
) -> Result<(), LedgerError> {
    if terminal {
        return Err(LedgerError::Corrupt("monitor record follows a terminal record"));
    }
    let expected = u64::try_from(records.len())
        .ok()
        .and_then(|count| count.checked_add(1));
    if Some(event.cursor().value()) != expected {
        return Err(LedgerError::Corrupt("monitor cursor is not contiguous"));
    }
    if records.is_empty() {
        if !event.is_start() {
            return Err(LedgerError::Corrupt("monitor journal does not begin with a start record"));
        }
    } else if event.is_start() {
        return Err(LedgerError::Corrupt("duplicate monitor start record"));
    }
    if event.timestamp_unix_ms() < last_timestamp {
        return Err(LedgerError::Corrupt("monitor timestamps move backwards"));
    }
    Ok(())
}

/// Append one framed record (`len`, `checksum`, `payload`) at the file's end and
/// fsync — the durability point. The file is left positioned at the new end.
fn append_record(file: &mut File, payload: &[u8]) -> Result<(), LedgerError> {
    let len = u32::try_from(payload.len())
        .ok()
        .filter(|len| u64::from(*len) <= MAX_RECORD_PAYLOAD_BYTES)
        .ok_or(LedgerError::Corrupt("monitor record exceeds the hard size limit"))?;
    let mut framed = Vec::with_capacity(RECORD_HEADER_BYTES as usize + payload.len());
    framed.extend_from_slice(&len.to_le_bytes());
    framed.extend_from_slice(&checksum(payload));
    framed.extend_from_slice(payload);
    file.seek(SeekFrom::End(0))?;
    file.write_all(&framed)?;
    file.sync_all()?;
    Ok(())
}

fn journal_header() -> [u8; HEADER_BYTES as usize] {
    let mut header = [0_u8; HEADER_BYTES as usize];
    header[..4].copy_from_slice(&JOURNAL_MAGIC);
    header[4..6].copy_from_slice(&JOURNAL_VERSION.to_le_bytes());
    header
}

fn checksum(payload: &[u8]) -> [u8; CHECKSUM_BYTES] {
    let digest: [u8; 32] = Sha256::digest(payload).into();
    let mut checksum = [0_u8; CHECKSUM_BYTES];
    checksum.copy_from_slice(&digest[..CHECKSUM_BYTES]);
    checksum
}

fn file_len(file: &File) -> Result<u64, LedgerError> {
    Ok(file.metadata()?.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig2browser_protocol::ArtifactMediaType;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(name: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("test clock")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "dig2browser-journal-{name}-{}-{nonce}",
                std::process::id(),
            ));
            fs::create_dir_all(&path).expect("create test root");
            Self(path)
        }

        fn journal(&self) -> PathBuf {
            self.0.join("monitor.journal")
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn artifact(byte: u8) -> ArtifactRef {
        ArtifactRef::new([byte; 32], u64::from(byte) + 1, ArtifactMediaType::TextHtmlUtf8)
            .expect("artifact ref")
    }

    #[test]
    fn append_and_read_round_trips_across_reopen() {
        let root = TestRoot::new("roundtrip");
        {
            let mut journal = MonitorJournal::open_at(root.journal(), 1).expect("open");
            journal
                .start("https://example.test/stream".to_owned(), LiveFilter::all(), 10)
                .expect("start");
            journal
                .commit_frame(
                    WebSocketDirection::Received,
                    WebSocketOpcode::Text,
                    false,
                    artifact(1),
                    11,
                )
                .expect("frame");
            journal
                .stop(MonitorStopReason::Requested, 12)
                .expect("stop");
        }
        // Reopen: the durable records replay identically; a terminal journal is
        // not reconciled again.
        let journal = MonitorJournal::open_at(root.journal(), 99).expect("reopen");
        assert_eq!(journal.record_count(), 3);
        assert!(journal.is_terminal());
        let all = journal.read(MonitorCursor::START, 64);
        assert_eq!(all.len(), 3);
        assert!(all[0].is_start());
        assert!(matches!(
            all[2].kind(),
            MonitorEventKind::Stopped(MonitorStopReason::Requested)
        ));
        // Cursored read.
        let tail = journal.read(all[0].cursor(), 64);
        assert_eq!(tail.len(), 2);
        assert_eq!(tail[0].cursor().value(), 2);
    }

    #[test]
    fn writer_lock_is_exclusive_and_released_with_the_handle() {
        let root = TestRoot::new("lock");
        let first = MonitorJournal::open_at(root.journal(), 1).expect("first writer");
        assert!(matches!(
            MonitorJournal::open_at(root.journal(), 2),
            Err(LedgerError::WriterLocked)
        ));
        drop(first);
        MonitorJournal::open_at(root.journal(), 3).expect("successor writer");
    }

    #[test]
    fn transitions_are_enforced() {
        let root = TestRoot::new("transitions");
        let mut journal = MonitorJournal::open_at(root.journal(), 1).expect("open");
        // A frame before the start record is rejected.
        assert!(matches!(
            journal.commit_frame(
                WebSocketDirection::Sent,
                WebSocketOpcode::Text,
                false,
                artifact(2),
                5,
            ),
            Err(LedgerError::InvalidTransition(_))
        ));
        journal
            .start("https://example.test/s".to_owned(), LiveFilter::all(), 10)
            .expect("start");
        // A second start is rejected.
        assert!(matches!(
            journal.start("https://example.test/again".to_owned(), LiveFilter::all(), 11),
            Err(LedgerError::InvalidTransition(_))
        ));
        // Timestamps must not go backwards.
        assert!(matches!(
            journal.commit_frame(
                WebSocketDirection::Sent,
                WebSocketOpcode::Text,
                false,
                artifact(3),
                9,
            ),
            Err(LedgerError::InvalidTransition(_))
        ));
        journal.stop(MonitorStopReason::Requested, 12).expect("stop");
        // No record may follow the terminal.
        assert!(matches!(
            journal.commit_frame(
                WebSocketDirection::Sent,
                WebSocketOpcode::Text,
                false,
                artifact(4),
                13,
            ),
            Err(LedgerError::InvalidTransition(_))
        ));
    }

    #[test]
    fn successor_reconciles_a_journal_left_open_by_a_crash() {
        let root = TestRoot::new("reconcile");
        {
            let mut journal = MonitorJournal::open_at(root.journal(), 1).expect("open");
            journal
                .start("https://example.test/s".to_owned(), LiveFilter::all(), 10)
                .expect("start");
            journal
                .commit_frame(
                    WebSocketDirection::Received,
                    WebSocketOpcode::Text,
                    false,
                    artifact(5),
                    11,
                )
                .expect("frame");
            // No stop — simulate a crash by just dropping the handle.
        }
        let journal = MonitorJournal::open_at(root.journal(), 50).expect("successor");
        assert!(journal.is_terminal());
        assert_eq!(journal.record_count(), 3);
        let records = journal.read(MonitorCursor::START, 64);
        assert!(matches!(
            records[2].kind(),
            MonitorEventKind::Stopped(MonitorStopReason::Interrupted(
                InterruptedReason::SuccessorReconciliation
            ))
        ));
        assert_eq!(records[2].timestamp_unix_ms(), 50);
        // Release the exclusive lock before the next open.
        drop(journal);
        // Reconciled exactly once: a further successor does not add another.
        let again = MonitorJournal::open_at(root.journal(), 60).expect("second successor");
        assert_eq!(again.record_count(), 3);
    }

    #[test]
    fn a_torn_trailing_record_is_truncated_on_open() {
        let root = TestRoot::new("torn-tail");
        {
            let mut journal = MonitorJournal::open_at(root.journal(), 1).expect("open");
            journal
                .start("https://example.test/s".to_owned(), LiveFilter::all(), 10)
                .expect("start");
            journal
                .commit_frame(
                    WebSocketDirection::Received,
                    WebSocketOpcode::Text,
                    false,
                    artifact(6),
                    11,
                )
                .expect("frame");
            journal.stop(MonitorStopReason::Requested, 12).expect("stop");
        }
        // Simulate a crash mid-append of a fourth record: append a truncated
        // frame (a valid header claiming more payload than is present).
        let before = fs::metadata(root.journal()).expect("meta").len();
        {
            let mut file = OpenOptions::new()
                .append(true)
                .open(root.journal())
                .expect("reopen for tear");
            // len says 40 bytes of payload; write only 4 → torn tail.
            file.write_all(&40_u32.to_le_bytes()).expect("len");
            file.write_all(&[0_u8; CHECKSUM_BYTES]).expect("checksum");
            file.write_all(&[1, 2, 3, 4]).expect("partial payload");
            file.sync_all().expect("sync torn");
        }
        assert!(fs::metadata(root.journal()).expect("meta").len() > before);
        // Open recovers: the torn tail is truncated, the three good records
        // survive, and the file is writable again.
        let mut journal = MonitorJournal::open_at(root.journal(), 20).expect("recover");
        assert_eq!(journal.record_count(), 3);
        assert!(journal.is_terminal());
        assert_eq!(fs::metadata(root.journal()).expect("meta").len(), before);
        // A terminal-but-recovered journal still rejects appends (fail closed).
        assert!(journal
            .commit_frame(
                WebSocketDirection::Sent,
                WebSocketOpcode::Text,
                false,
                artifact(7),
                21,
            )
            .is_err());
    }

    #[test]
    fn a_fully_present_corrupt_record_fails_closed() {
        let root = TestRoot::new("corrupt");
        {
            let mut journal = MonitorJournal::open_at(root.journal(), 1).expect("open");
            journal
                .start("https://example.test/s".to_owned(), LiveFilter::all(), 10)
                .expect("start");
        }
        // Flip a payload byte of the (only) record without fixing its checksum:
        // fully present, so it is corruption, not a torn tail → fail closed.
        let mut bytes = fs::read(root.journal()).expect("read journal");
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        fs::write(root.journal(), &bytes).expect("write tampered");
        assert!(matches!(
            MonitorJournal::open_at(root.journal(), 2),
            Err(LedgerError::Corrupt(_))
        ));
    }
}
