//! Durable monitor sink: the storage bridge from a captured frame to durable
//! state, composing the content-addressed store ([`crate::TraceLedger`]) and the
//! append-only journal ([`crate::MonitorJournal`]).
//!
//! A frame is recorded in two steps, **CAS first, then journal**: the payload is
//! committed to the content-addressed store, and only then is a `FrameCommitted`
//! record — carrying just the resulting [`ArtifactRef`] — appended to the
//! journal. That ordering is the crash-safety invariant: a journal record can
//! never reference a payload that is not already durable, so a crash between the
//! two steps leaves at worst an orphaned (unreferenced, dedup-shared) CAS blob,
//! never a dangling reference. An **empty** frame commits no CAS object and its
//! record carries no reference.
//!
//! This is the runtime-agnostic core the station's durable monitor manager wires
//! a live devtools subscription into; it has no browser or IPC dependency and is
//! unit-tested end-to-end (record → reopen → read payloads back from the CAS).

use std::path::Path;
use std::sync::Arc;

use dig2browser_protocol::{
    ArtifactMediaType, LiveFilter, MonitorCursor, MonitorEvent, MonitorFrame, MonitorStopReason,
    WebSocketDirection, WebSocketOpcode,
};

use crate::{LedgerError, MonitorJournal, TraceLedger};

/// A durable monitor sink over a shared [`TraceLedger`] CAS and its own
/// append-only [`MonitorJournal`]. Owns the journal (single writer) and holds a
/// shared handle to the ledger, which is the single writer of the shared
/// content-addressed store. The ledger is an `Arc` (not a borrow) so a sink can
/// be moved into a long-lived capture task.
pub struct MonitorSink {
    ledger: Arc<TraceLedger>,
    journal: MonitorJournal,
}

impl MonitorSink {
    /// Open a sink over `ledger`'s CAS and a journal at `journal_path`,
    /// reconciling a journal a crash left open (see [`MonitorJournal::open_at`]).
    pub fn open_at(
        ledger: Arc<TraceLedger>,
        journal_path: impl AsRef<Path>,
        successor_timestamp_unix_ms: u64,
    ) -> Result<Self, LedgerError> {
        Ok(Self {
            ledger,
            journal: MonitorJournal::open_at(journal_path, successor_timestamp_unix_ms)?,
        })
    }

    /// Open a sink WITHOUT reconciling the journal — the caller inspects
    /// [`is_terminal`](Self::is_terminal) and decides to resume or reconcile.
    pub fn open_deferred(
        ledger: Arc<TraceLedger>,
        journal_path: impl AsRef<Path>,
    ) -> Result<Self, LedgerError> {
        Ok(Self {
            ledger,
            journal: MonitorJournal::open_deferred(journal_path)?,
        })
    }

    /// Open the monitor's first (`Started`) record.
    pub fn start(
        &mut self,
        url: String,
        filter: LiveFilter,
        timestamp_unix_ms: u64,
    ) -> Result<MonitorEvent, LedgerError> {
        self.journal.start(url, filter, timestamp_unix_ms)
    }

    /// Record a captured frame durably: commit a non-empty `payload` to the CAS
    /// (media type `ApplicationOctetStream`), then append the journal record. An
    /// empty payload commits no CAS object and records `artifact = None`.
    pub fn record_frame(
        &mut self,
        direction: WebSocketDirection,
        opcode: WebSocketOpcode,
        payload: &[u8],
        truncated: bool,
        timestamp_unix_ms: u64,
    ) -> Result<MonitorEvent, LedgerError> {
        let artifact = if payload.is_empty() {
            None
        } else {
            Some(
                self.ledger
                    .commit_orphan_artifact(ArtifactMediaType::ApplicationOctetStream, payload)?,
            )
        };
        self.journal
            .commit_frame(direction, opcode, truncated, artifact, timestamp_unix_ms)
    }

    /// Close the monitor with a terminal `Stopped` record.
    pub fn stop(
        &mut self,
        reason: MonitorStopReason,
        timestamp_unix_ms: u64,
    ) -> Result<MonitorEvent, LedgerError> {
        self.journal.stop(reason, timestamp_unix_ms)
    }

    /// Reconcile a journal left open by a crash (no-op if empty or terminal).
    pub fn reconcile_at(&mut self, timestamp_unix_ms: u64) -> Result<(), LedgerError> {
        self.journal.reconcile_at(timestamp_unix_ms)
    }

    /// Records strictly after `cursor`, at most `limit` — the durable read model.
    pub fn read(&self, cursor: MonitorCursor, limit: usize) -> Vec<MonitorEvent> {
        self.journal.read(cursor, limit)
    }

    /// Read a recorded frame's payload back from the CAS (byte-exact, hash
    /// re-validated on open); an empty frame yields an empty payload.
    pub fn frame_payload(&self, frame: &MonitorFrame) -> Result<Vec<u8>, LedgerError> {
        match frame.artifact() {
            None => Ok(Vec::new()),
            Some(reference) => self.ledger.read_orphan_artifact(reference),
        }
    }

    pub fn last_cursor(&self) -> MonitorCursor {
        self.journal.last_cursor()
    }

    pub fn record_count(&self) -> usize {
        self.journal.record_count()
    }

    pub fn is_terminal(&self) -> bool {
        self.journal.is_terminal()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig2browser_protocol::MonitorEventKind;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(name: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("test clock")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "dig2browser-sink-{name}-{}-{nonce}",
                std::process::id(),
            ));
            fs::create_dir_all(&path).expect("create test root");
            Self(path)
        }

        fn ledger_root(&self) -> PathBuf {
            self.0.join("trace")
        }

        fn journal(&self) -> PathBuf {
            self.0.join("monitors").join("m1.journal")
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn frames_are_durable_and_read_back_byte_exact_across_reopen() {
        let root = TestRoot::new("durable");
        // Record a text frame, an empty frame, and a binary frame, then stop.
        {
            let ledger = Arc::new(TraceLedger::open_at(root.ledger_root(), 1).expect("ledger"));
            let mut sink = MonitorSink::open_at(ledger.clone(), root.journal(), 1).expect("sink");
            sink.start("wss://example.test/feed".to_owned(), LiveFilter::all(), 10)
                .expect("start");
            sink.record_frame(
                WebSocketDirection::Received,
                WebSocketOpcode::Text,
                br#"{"tick":1}"#,
                false,
                11,
            )
            .expect("text frame");
            sink.record_frame(
                WebSocketDirection::Sent,
                WebSocketOpcode::Ping,
                b"",
                false,
                12,
            )
            .expect("empty frame");
            sink.record_frame(
                WebSocketDirection::Received,
                WebSocketOpcode::Binary,
                &[0xDE, 0xAD, 0xBE, 0xEF],
                false,
                13,
            )
            .expect("binary frame");
            sink.stop(MonitorStopReason::Requested, 14).expect("stop");
        }

        // Reopen over the same CAS + journal; a fresh process would see exactly
        // this — the durability the RAM ring cannot provide.
        let ledger = Arc::new(TraceLedger::open_at(root.ledger_root(), 99).expect("reopen ledger"));
        let sink = MonitorSink::open_at(ledger.clone(), root.journal(), 99).expect("reopen sink");
        assert!(sink.is_terminal());
        assert_eq!(sink.record_count(), 5); // start + 3 frames + stop

        let records = sink.read(MonitorCursor::START, 64);
        let frames: Vec<&MonitorFrame> = records
            .iter()
            .filter_map(|event| match event.kind() {
                MonitorEventKind::FrameCommitted(frame) => Some(frame),
                _ => None,
            })
            .collect();
        assert_eq!(frames.len(), 3);

        assert_eq!(frames[0].opcode(), WebSocketOpcode::Text);
        assert_eq!(sink.frame_payload(frames[0]).expect("text payload"), br#"{"tick":1}"#);

        // Empty frame: no CAS reference, empty payload.
        assert_eq!(frames[1].opcode(), WebSocketOpcode::Ping);
        assert!(frames[1].artifact().is_none());
        assert!(sink.frame_payload(frames[1]).expect("empty payload").is_empty());

        assert_eq!(frames[2].opcode(), WebSocketOpcode::Binary);
        assert_eq!(
            sink.frame_payload(frames[2]).expect("binary payload"),
            vec![0xDE, 0xAD, 0xBE, 0xEF]
        );
    }

    #[test]
    fn identical_frame_payloads_dedup_in_the_cas() {
        let root = TestRoot::new("dedup");
        let ledger = Arc::new(TraceLedger::open_at(root.ledger_root(), 1).expect("ledger"));
        let mut sink = MonitorSink::open_at(ledger.clone(), root.journal(), 1).expect("sink");
        sink.start("wss://example.test/feed".to_owned(), LiveFilter::all(), 10)
            .expect("start");
        sink.record_frame(WebSocketDirection::Received, WebSocketOpcode::Text, b"heartbeat", false, 11)
            .expect("frame a");
        sink.record_frame(WebSocketDirection::Received, WebSocketOpcode::Text, b"heartbeat", false, 12)
            .expect("frame b");

        let records = sink.read(MonitorCursor::START, 64);
        let refs: Vec<_> = records
            .iter()
            .filter_map(|event| match event.kind() {
                MonitorEventKind::FrameCommitted(frame) => frame.artifact().cloned(),
                _ => None,
            })
            .collect();
        assert_eq!(refs.len(), 2);
        // Content-addressed: identical payloads share one CAS reference.
        assert_eq!(refs[0].sha256(), refs[1].sha256());
    }

    #[test]
    fn a_crash_left_open_sink_is_reconciled_and_recorded_frames_survive() {
        let root = TestRoot::new("crash");
        {
            let ledger = Arc::new(TraceLedger::open_at(root.ledger_root(), 1).expect("ledger"));
            let mut sink = MonitorSink::open_at(ledger.clone(), root.journal(), 1).expect("sink");
            sink.start("wss://example.test/feed".to_owned(), LiveFilter::all(), 10)
                .expect("start");
            sink.record_frame(WebSocketDirection::Received, WebSocketOpcode::Text, b"partial", false, 11)
                .expect("frame");
            // No stop — drop simulates a crash.
        }
        let ledger = Arc::new(TraceLedger::open_at(root.ledger_root(), 50).expect("reopen ledger"));
        let sink = MonitorSink::open_at(ledger.clone(), root.journal(), 50).expect("reopen sink");
        assert!(sink.is_terminal());
        let records = sink.read(MonitorCursor::START, 64);
        assert_eq!(records.len(), 3); // start + frame + synthetic stop
        // The frame recorded before the crash is still readable from the CAS.
        let frame = records.iter().find_map(|event| match event.kind() {
            MonitorEventKind::FrameCommitted(frame) => Some(frame),
            _ => None,
        });
        assert_eq!(
            sink.frame_payload(frame.expect("frame survived")).expect("payload"),
            b"partial"
        );
    }
}
