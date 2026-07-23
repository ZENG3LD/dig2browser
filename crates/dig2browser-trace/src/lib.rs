//! Crash-safe trace event and content-addressed artifact storage.

use std::fmt;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use dig2browser_protocol::{
    ArtifactChunk, ArtifactCommitted, ArtifactMediaType, ArtifactRef, ArtifactRole,
    CollectionId, InterruptedReason, ProtocolError, StartedTrace, TerminalTrace,
    TraceCursor, TraceEvent, TraceEventKind, TracePage, MAX_ARTIFACT_CHUNK_BYTES,
    MAX_HTML_BYTES, MAX_PNG_BYTES, MAX_TRACE_EVENTS, MAX_TRACE_STEP_SUMMARIES,
};
use sha2::{Digest, Sha256};

pub const MAX_ARTIFACT_BYTES: usize = if MAX_HTML_BYTES > MAX_PNG_BYTES {
    MAX_HTML_BYTES
} else {
    MAX_PNG_BYTES
};
pub const MAX_EVENT_FILE_BYTES: u64 = 1024 * 1024;

// One Started event, up to HTML and viewport PNG for every task step, and one
// terminal event. MAX_TRACE_EVENTS remains the bounded IPC page size.
const MAX_COLLECTION_EVENTS: usize = 2 + (MAX_TRACE_STEP_SUMMARIES * 2);

const LOCK_FILE: &str = ".dig2browser-trace.lock";
const COLLECTIONS_DIR: &str = "collections";
const ARTIFACTS_DIR: &str = "artifacts";

#[derive(Debug)]
pub enum LedgerError {
    Io(io::Error),
    Protocol(ProtocolError),
    WriterLocked,
    CollectionExists,
    CollectionNotFound,
    ArtifactNotCommitted,
    ArtifactTooLarge,
    EventLimitExceeded,
    InvalidCursor,
    InvalidTransition(&'static str),
    Corrupt(&'static str),
}

impl fmt::Display for LedgerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "trace ledger I/O error: {error}"),
            Self::Protocol(error) => write!(formatter, "trace protocol error: {error}"),
            Self::WriterLocked => formatter.write_str("trace ledger writer is already locked"),
            Self::CollectionExists => formatter.write_str("collection already exists"),
            Self::CollectionNotFound => formatter.write_str("collection was not found"),
            Self::ArtifactNotCommitted => {
                formatter.write_str("artifact is not committed for this collection")
            }
            Self::ArtifactTooLarge => formatter.write_str("artifact exceeds the hard size limit"),
            Self::EventLimitExceeded => formatter.write_str("trace event limit exceeded"),
            Self::InvalidCursor => formatter.write_str("trace cursor is outside the durable trace"),
            Self::InvalidTransition(message) => write!(formatter, "invalid trace transition: {message}"),
            Self::Corrupt(message) => write!(formatter, "corrupt trace ledger: {message}"),
        }
    }
}

impl std::error::Error for LedgerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Protocol(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for LedgerError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<ProtocolError> for LedgerError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

pub struct TraceLedger {
    root: PathBuf,
    _lock: File,
}

impl TraceLedger {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, LedgerError> {
        Self::open_at(root, unix_time_ms()?)
    }

    pub fn open_at(
        root: impl AsRef<Path>,
        successor_timestamp_unix_ms: u64,
    ) -> Result<Self, LedgerError> {
        let ledger = Self::open_deferred(root)?;
        ledger.reconcile_at(successor_timestamp_unix_ms, &[])?;
        Ok(ledger)
    }

    pub fn open_deferred(root: impl AsRef<Path>) -> Result<Self, LedgerError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(root.join(LOCK_FILE))?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(LedgerError::WriterLocked),
            Err(TryLockError::Error(error)) => return Err(LedgerError::Io(error)),
        }

        let ledger = Self { root, _lock: lock };
        fs::create_dir_all(ledger.collections_dir())?;
        fs::create_dir_all(ledger.artifacts_dir())?;
        sync_directory(&ledger.root)?;
        Ok(ledger)
    }

    pub fn incomplete_collection_ids(&self) -> Result<Vec<CollectionId>, LedgerError> {
        let mut incomplete = Vec::new();
        for collection_id in self.collection_ids()? {
            if !self.replay(collection_id)?.terminal {
                incomplete.push(collection_id);
            }
        }
        Ok(incomplete)
    }

    pub fn reconcile_at(
        &self,
        timestamp_unix_ms: u64,
        preserve: &[CollectionId],
    ) -> Result<(), LedgerError> {
        for collection_id in self.incomplete_collection_ids()? {
            if preserve.contains(&collection_id) {
                continue;
            }
            let replay = self.replay(collection_id)?;
            self.append_kind(
                collection_id,
                timestamp_unix_ms.max(replay.last_timestamp),
                TraceEventKind::Interrupted(InterruptedReason::SuccessorReconciliation),
            )?;
        }
        Ok(())
    }

    pub fn begin_collection(
        &self,
        collection_id: CollectionId,
        timestamp_unix_ms: u64,
        started: StartedTrace,
    ) -> Result<TraceEvent, LedgerError> {
        let final_dir = self.collection_dir(collection_id);
        if final_dir.exists() {
            return Err(LedgerError::CollectionExists);
        }
        let event = TraceEvent::new(
            TraceCursor::new(1),
            timestamp_unix_ms,
            TraceEventKind::Started(started),
        )?;
        let temp_dir = unique_temp_path(
            &self.collections_dir(),
            &format!(".{}", hex(collection_id.as_bytes())),
        )?;
        fs::create_dir(&temp_dir)?;
        let result = (|| {
            write_new_file(&temp_dir.join(event_file_name(1)), &event.encode()?)?;
            sync_directory(&temp_dir)?;
            if final_dir.exists() {
                return Err(LedgerError::CollectionExists);
            }
            durable_rename(&temp_dir, &final_dir)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&temp_dir);
        }
        result?;
        Ok(event)
    }

    pub fn commit_artifact(
        &self,
        collection_id: CollectionId,
        timestamp_unix_ms: u64,
        step_index: u8,
        role: ArtifactRole,
        media_type: ArtifactMediaType,
        bytes: &[u8],
    ) -> Result<ArtifactRef, LedgerError> {
        if bytes.is_empty() {
            return Err(LedgerError::InvalidTransition("empty artifacts are not valid"));
        }
        if bytes.len() > MAX_ARTIFACT_BYTES {
            return Err(LedgerError::ArtifactTooLarge);
        }
        let replay = self.replay(collection_id)?;
        replay.require_active()?;
        if usize::from(step_index) >= usize::from(replay.step_count) {
            return Err(LedgerError::InvalidTransition("artifact step is outside the collection task"));
        }
        if replay.artifacts.iter().any(|artifact| {
            artifact.step_index == step_index && artifact.role == role
        }) {
            return Err(LedgerError::InvalidTransition("artifact role was already committed for this step"));
        }

        let digest: [u8; 32] = Sha256::digest(bytes).into();
        let artifact = ArtifactRef::new(digest, bytes.len() as u64, media_type)?;
        let committed = ArtifactCommitted::new(step_index, role, artifact.clone())?;
        let artifact_path = self.artifact_path(&digest);
        if artifact_path.exists() {
            validate_artifact_file(&artifact_path, &artifact)?;
        } else {
            let temp_path = unique_temp_path(
                &self.artifacts_dir(),
                &format!(".{}", hex(&digest)),
            )?;
            let write_result: Result<(), LedgerError> = (|| {
                write_new_file(&temp_path, bytes)?;
                if artifact_path.exists() {
                    validate_artifact_file(&artifact_path, &artifact)?;
                    fs::remove_file(&temp_path)?;
                } else {
                    durable_rename(&temp_path, &artifact_path)?;
                }
                Ok(())
            })();
            if write_result.is_err() {
                let _ = fs::remove_file(&temp_path);
            }
            write_result?;
        }

        // Never make a reference durable until the renamed CAS object has been
        // reopened and its length and digest recomputed.
        validate_artifact_file(&artifact_path, &artifact)?;
        self.append_kind(
            collection_id,
            timestamp_unix_ms,
            TraceEventKind::ArtifactCommitted(committed),
        )?;
        Ok(artifact)
    }

    pub fn finish_collection(
        &self,
        collection_id: CollectionId,
        timestamp_unix_ms: u64,
        terminal: TerminalTrace,
    ) -> Result<TraceEvent, LedgerError> {
        let replay = self.replay(collection_id)?;
        replay.require_active()?;
        validate_terminal_steps(&replay, &terminal)?;
        self.revalidate_artifacts(&replay)?;
        self.append_kind(
            collection_id,
            timestamp_unix_ms,
            TraceEventKind::Terminal(terminal),
        )
    }

    pub fn interrupt_collection(
        &self,
        collection_id: CollectionId,
        timestamp_unix_ms: u64,
        reason: InterruptedReason,
    ) -> Result<TraceEvent, LedgerError> {
        let replay = self.replay(collection_id)?;
        replay.require_active()?;
        self.append_kind(
            collection_id,
            timestamp_unix_ms,
            TraceEventKind::Interrupted(reason),
        )
    }

    pub fn read_trace(
        &self,
        collection_id: CollectionId,
        cursor: TraceCursor,
        limit: u8,
    ) -> Result<TracePage, LedgerError> {
        if limit == 0 || usize::from(limit) > MAX_TRACE_EVENTS {
            return Err(LedgerError::InvalidCursor);
        }
        let replay = self.replay(collection_id)?;
        let start = usize::try_from(cursor.value()).map_err(|_| LedgerError::InvalidCursor)?;
        if start > replay.events.len() {
            return Err(LedgerError::InvalidCursor);
        }
        let end = start
            .saturating_add(usize::from(limit))
            .min(replay.events.len());
        let events = replay.events[start..end].to_vec();
        let next_cursor = events.last().map(TraceEvent::cursor).unwrap_or(cursor);
        let complete = replay.terminal && end == replay.events.len();
        Ok(TracePage::new(collection_id, events, next_cursor, complete)?)
    }

    pub fn read_artifact(
        &self,
        collection_id: CollectionId,
        sha256: [u8; 32],
        offset: u64,
        max_bytes: u32,
    ) -> Result<ArtifactChunk, LedgerError> {
        if max_bytes == 0
            || usize::try_from(max_bytes).ok() > Some(MAX_ARTIFACT_CHUNK_BYTES)
        {
            return Err(LedgerError::InvalidCursor);
        }
        let replay = self.replay(collection_id)?;
        let reference = replay
            .artifacts
            .iter()
            .find(|artifact| artifact.reference.sha256() == &sha256)
            .map(|artifact| &artifact.reference)
            .ok_or(LedgerError::ArtifactNotCommitted)?;
        if offset > reference.len() {
            return Err(LedgerError::InvalidCursor);
        }
        let path = self.artifact_path(&sha256);
        let mut file = open_validated_artifact(&path, reference)?;
        let remaining = reference.len() - offset;
        let read_len = remaining.min(u64::from(max_bytes));
        let read_len = usize::try_from(read_len).map_err(|_| LedgerError::ArtifactTooLarge)?;
        file.seek(SeekFrom::Start(offset))?;
        let mut bytes = vec![0; read_len];
        file.read_exact(&mut bytes)?;
        let eof = offset + read_len as u64 == reference.len();
        Ok(ArtifactChunk::new(
            collection_id,
            sha256,
            offset,
            reference.len(),
            bytes,
            eof,
        )?)
    }

    /// Commit `bytes` into the content-addressed store WITHOUT any collection /
    /// step / role bookkeeping. For durable data keyed by its own journal (e.g.
    /// a monitor's captured frames) rather than the finite-task trace: the same
    /// dedup + durable-rename + reopen-and-re-validate guarantees as
    /// `commit_artifact`, but with no `StartedTrace`, no step index, and no
    /// `MAX_COLLECTION_EVENTS` ceiling. Ownership and ordering are the caller's
    /// journal's responsibility; the ledger only guarantees the bytes are stored
    /// content-addressed and byte-exact.
    pub fn commit_orphan_artifact(
        &self,
        media_type: ArtifactMediaType,
        bytes: &[u8],
    ) -> Result<ArtifactRef, LedgerError> {
        if bytes.is_empty() {
            return Err(LedgerError::InvalidTransition("empty artifacts are not valid"));
        }
        if bytes.len() > MAX_ARTIFACT_BYTES {
            return Err(LedgerError::ArtifactTooLarge);
        }
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        let artifact = ArtifactRef::new(digest, bytes.len() as u64, media_type)?;
        let artifact_path = self.artifact_path(&digest);
        if artifact_path.exists() {
            validate_artifact_file(&artifact_path, &artifact)?;
        } else {
            let temp_path = unique_temp_path(
                &self.artifacts_dir(),
                &format!(".{}", hex(&digest)),
            )?;
            let write_result: Result<(), LedgerError> = (|| {
                write_new_file(&temp_path, bytes)?;
                if artifact_path.exists() {
                    validate_artifact_file(&artifact_path, &artifact)?;
                    fs::remove_file(&temp_path)?;
                } else {
                    durable_rename(&temp_path, &artifact_path)?;
                }
                Ok(())
            })();
            if write_result.is_err() {
                let _ = fs::remove_file(&temp_path);
            }
            write_result?;
        }
        validate_artifact_file(&artifact_path, &artifact)?;
        Ok(artifact)
    }

    /// Read a content-addressed artifact by its reference alone (no owning
    /// collection), re-validating length + digest on open. The companion read
    /// for [`commit_orphan_artifact`]. Returns the full byte-exact contents;
    /// callers keep artifacts bounded (monitor frames are small).
    pub fn read_orphan_artifact(
        &self,
        reference: &ArtifactRef,
    ) -> Result<Vec<u8>, LedgerError> {
        let path = self.artifact_path(reference.sha256());
        let mut file = open_validated_artifact(&path, reference)?;
        let capacity = usize::try_from(reference.len()).unwrap_or(0);
        let mut bytes = Vec::with_capacity(capacity);
        file.read_to_end(&mut bytes)?;
        Ok(bytes)
    }

    fn append_kind(
        &self,
        collection_id: CollectionId,
        timestamp_unix_ms: u64,
        kind: TraceEventKind,
    ) -> Result<TraceEvent, LedgerError> {
        let replay = self.replay(collection_id)?;
        replay.require_active()?;
        if replay.events.len() >= MAX_COLLECTION_EVENTS {
            return Err(LedgerError::EventLimitExceeded);
        }
        if timestamp_unix_ms < replay.last_timestamp {
            return Err(LedgerError::InvalidTransition("event timestamps must not move backwards"));
        }
        validate_kind(&replay, &kind)?;
        let cursor_value = u32::try_from(replay.events.len() + 1)
            .map_err(|_| LedgerError::EventLimitExceeded)?;
        let event = TraceEvent::new(
            TraceCursor::new(cursor_value),
            timestamp_unix_ms,
            kind,
        )?;
        let path = self
            .collection_dir(collection_id)
            .join(event_file_name(cursor_value));
        write_atomic_file(&path, &event.encode()?)?;
        Ok(event)
    }

    fn replay(&self, collection_id: CollectionId) -> Result<Replay, LedgerError> {
        let directory = self.collection_dir(collection_id);
        let metadata = match fs::symlink_metadata(&directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(LedgerError::CollectionNotFound)
            }
            Err(error) => return Err(error.into()),
        };
        if !metadata.file_type().is_dir() {
            return Err(LedgerError::Corrupt("collection path is not a directory"));
        }

        let mut files = Vec::new();
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_str().ok_or(LedgerError::Corrupt("non-UTF-8 event filename"))?;
            if name.starts_with('.') && name.ends_with(".tmp") {
                continue;
            }
            let cursor = parse_event_file_name(name)?;
            if !entry.file_type()?.is_file() {
                return Err(LedgerError::Corrupt("event path is not a regular file"));
            }
            files.push((cursor, entry.path()));
        }
        files.sort_by_key(|(cursor, _)| *cursor);
        if files.is_empty() {
            return Err(LedgerError::Corrupt("collection has no start event"));
        }
        if files.len() > MAX_COLLECTION_EVENTS {
            return Err(LedgerError::EventLimitExceeded);
        }

        let mut replay = Replay::default();
        for (index, (file_cursor, path)) in files.into_iter().enumerate() {
            let expected = u32::try_from(index + 1).map_err(|_| LedgerError::EventLimitExceeded)?;
            if file_cursor != expected {
                return Err(LedgerError::Corrupt("event filenames contain a cursor gap"));
            }
            let bytes = read_limited(&path, MAX_EVENT_FILE_BYTES)?;
            let event = TraceEvent::decode(&bytes)?;
            if event.cursor().value() != expected {
                return Err(LedgerError::Corrupt("event payload cursor does not match filename"));
            }
            apply_event(&mut replay, &event)?;
            replay.events.push(event);
        }
        if replay.terminal {
            self.revalidate_artifacts(&replay)?;
        }
        Ok(replay)
    }

    fn revalidate_artifacts(&self, replay: &Replay) -> Result<(), LedgerError> {
        for artifact in &replay.artifacts {
            validate_artifact_file(
                &self.artifact_path(artifact.reference.sha256()),
                &artifact.reference,
            )?;
        }
        Ok(())
    }

    fn collection_ids(&self) -> Result<Vec<CollectionId>, LedgerError> {
        let mut collections = Vec::new();
        for entry in fs::read_dir(self.collections_dir())? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_str().ok_or(LedgerError::Corrupt("non-UTF-8 collection name"))?;
            if name.starts_with('.') && name.ends_with(".tmp") {
                continue;
            }
            if !entry.file_type()?.is_dir() {
                return Err(LedgerError::Corrupt("collection entry is not a directory"));
            }
            let bytes = parse_hex_array::<16>(name)
                .ok_or(LedgerError::Corrupt("invalid collection directory name"))?;
            collections.push(CollectionId::new(bytes)?);
        }
        collections.sort_by_key(|id| id.into_bytes());
        Ok(collections)
    }

    fn collections_dir(&self) -> PathBuf {
        self.root.join(COLLECTIONS_DIR)
    }

    fn collection_dir(&self, collection_id: CollectionId) -> PathBuf {
        self.collections_dir().join(hex(collection_id.as_bytes()))
    }

    fn artifacts_dir(&self) -> PathBuf {
        self.root.join(ARTIFACTS_DIR)
    }

    fn artifact_path(&self, sha256: &[u8; 32]) -> PathBuf {
        self.artifacts_dir().join(format!("{}.blob", hex(sha256)))
    }
}

#[derive(Default)]
struct Replay {
    events: Vec<TraceEvent>,
    step_count: u8,
    last_timestamp: u64,
    terminal: bool,
    artifacts: Vec<CommittedArtifact>,
}

impl Replay {
    fn require_active(&self) -> Result<(), LedgerError> {
        if self.terminal {
            Err(LedgerError::InvalidTransition("collection is already terminal"))
        } else {
            Ok(())
        }
    }
}

struct CommittedArtifact {
    step_index: u8,
    role: ArtifactRole,
    reference: ArtifactRef,
}

fn apply_event(replay: &mut Replay, event: &TraceEvent) -> Result<(), LedgerError> {
    let expected = replay.events.len() + 1;
    if usize::try_from(event.cursor().value()).ok() != Some(expected) {
        return Err(LedgerError::Corrupt("non-contiguous event cursor"));
    }
    if !replay.events.is_empty() && event.timestamp_unix_ms() < replay.last_timestamp {
        return Err(LedgerError::Corrupt("event timestamps move backwards"));
    }
    validate_kind(replay, event.kind())?;
    match event.kind() {
        TraceEventKind::Started(started) => replay.step_count = started.step_count(),
        TraceEventKind::ArtifactCommitted(committed) => {
            replay.artifacts.push(CommittedArtifact {
                step_index: committed.step_index(),
                role: committed.role(),
                reference: committed.artifact().clone(),
            });
        }
        TraceEventKind::Terminal(_) | TraceEventKind::Interrupted(_) => replay.terminal = true,
    }
    replay.last_timestamp = event.timestamp_unix_ms();
    Ok(())
}

fn validate_kind(replay: &Replay, kind: &TraceEventKind) -> Result<(), LedgerError> {
    if replay.terminal {
        return Err(LedgerError::InvalidTransition("event follows a terminal event"));
    }
    match kind {
        TraceEventKind::Started(_) if replay.events.is_empty() => Ok(()),
        TraceEventKind::Started(_) => Err(LedgerError::InvalidTransition("duplicate start event")),
        TraceEventKind::ArtifactCommitted(committed) => {
            if replay.events.is_empty() {
                return Err(LedgerError::InvalidTransition("artifact precedes the start event"));
            }
            if usize::from(committed.step_index()) >= usize::from(replay.step_count) {
                return Err(LedgerError::InvalidTransition("artifact step is outside the collection task"));
            }
            if replay.artifacts.iter().any(|artifact| {
                artifact.step_index == committed.step_index()
                    && artifact.role == committed.role()
            }) {
                return Err(LedgerError::InvalidTransition("duplicate artifact role for one step"));
            }
            Ok(())
        }
        TraceEventKind::Terminal(terminal) => {
            if replay.events.is_empty() {
                return Err(LedgerError::InvalidTransition("terminal event precedes the start event"));
            }
            validate_terminal_steps(replay, terminal)
        }
        TraceEventKind::Interrupted(_) if replay.events.is_empty() => {
            Err(LedgerError::InvalidTransition("interruption precedes the start event"))
        }
        TraceEventKind::Interrupted(_) => Ok(()),
    }
}

fn validate_terminal_steps(replay: &Replay, terminal: &TerminalTrace) -> Result<(), LedgerError> {
    if terminal
        .steps()
        .iter()
        .any(|step| step.step_index() >= replay.step_count)
    {
        return Err(LedgerError::InvalidTransition("terminal step is outside the collection task"));
    }
    Ok(())
}

fn validate_artifact_file(path: &Path, reference: &ArtifactRef) -> Result<(), LedgerError> {
    open_validated_artifact(path, reference).map(|_| ())
}

fn open_validated_artifact(
    path: &Path,
    reference: &ArtifactRef,
) -> Result<File, LedgerError> {
    let mut file = File::open(path)
        .map_err(|error| if error.kind() == io::ErrorKind::NotFound {
            LedgerError::Corrupt("committed artifact is missing")
        } else {
            LedgerError::Io(error)
        })?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(LedgerError::Corrupt("artifact is not a regular file"));
    }
    if metadata.len() != reference.len() {
        return Err(LedgerError::Corrupt("artifact length does not match its reference"));
    }
    if metadata.len() > MAX_ARTIFACT_BYTES as u64 {
        return Err(LedgerError::ArtifactTooLarge);
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest: [u8; 32] = hasher.finalize().into();
    if &digest != reference.sha256() {
        return Err(LedgerError::Corrupt("artifact digest does not match its reference"));
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}

fn read_limited(path: &Path, maximum: u64) -> Result<Vec<u8>, LedgerError> {
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() || metadata.len() > maximum {
        return Err(LedgerError::Corrupt("invalid event file"));
    }
    let capacity = usize::try_from(metadata.len())
        .map_err(|_| LedgerError::Corrupt("event file length cannot fit in memory"))?;
    let mut bytes = Vec::with_capacity(capacity);
    file.read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() {
        return Err(LedgerError::Corrupt("event file changed while being read"));
    }
    Ok(bytes)
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), LedgerError> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn write_atomic_file(path: &Path, bytes: &[u8]) -> Result<(), LedgerError> {
    if bytes.len() as u64 > MAX_EVENT_FILE_BYTES {
        return Err(LedgerError::Corrupt("encoded event exceeds the hard size limit"));
    }
    if path.exists() {
        return Err(LedgerError::Corrupt("immutable event file already exists"));
    }
    let parent = path.parent().ok_or(LedgerError::Corrupt("event path has no parent"))?;
    let name = path.file_name().and_then(|name| name.to_str())
        .ok_or(LedgerError::Corrupt("invalid event filename"))?;
    let temp = unique_temp_path(parent, &format!(".{name}"))?;
    let result = (|| {
        write_new_file(&temp, bytes)?;
        if path.exists() {
            return Err(LedgerError::Corrupt("immutable event file appeared during append"));
        }
        durable_rename(&temp, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn unique_temp_path(parent: &Path, prefix: &str) -> Result<PathBuf, LedgerError> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| LedgerError::Corrupt("system clock precedes the Unix epoch"))?
        .as_nanos();
    for attempt in 0..128_u32 {
        let path = parent.join(format!(
            "{prefix}.{}.{}.{}.tmp",
            std::process::id(),
            nonce,
            attempt,
        ));
        if !path.exists() {
            return Ok(path);
        }
    }
    Err(LedgerError::Corrupt("could not allocate an atomic temporary path"))
}

fn event_file_name(cursor: u32) -> String {
    format!("{cursor:08}.event")
}

fn parse_event_file_name(name: &str) -> Result<u32, LedgerError> {
    if name.len() != 14 || !name.ends_with(".event") {
        return Err(LedgerError::Corrupt("invalid event filename"));
    }
    let digits = &name[..8];
    if !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(LedgerError::Corrupt("invalid event cursor filename"));
    }
    digits.parse().map_err(|_| LedgerError::Corrupt("invalid event cursor"))
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    output
}

fn parse_hex_array<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let bytes = value.as_bytes();
    let mut output = [0; N];
    for (index, output_byte) in output.iter_mut().enumerate() {
        let high = hex_digit(bytes[index * 2])?;
        let low = hex_digit(bytes[index * 2 + 1])?;
        *output_byte = (high << 4) | low;
    }
    if hex(&output) != value {
        return None;
    }
    Some(output)
}

fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn unix_time_ms() -> Result<u64, LedgerError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| LedgerError::Corrupt("system clock precedes the Unix epoch"))?
        .as_millis();
    u64::try_from(millis).map_err(|_| LedgerError::Corrupt("Unix timestamp exceeds u64"))
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), LedgerError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn durable_rename(source: &Path, destination: &Path) -> Result<(), LedgerError> {
    fs::rename(source, destination)?;
    let parent = destination
        .parent()
        .ok_or(LedgerError::Corrupt("renamed path has no parent"))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(windows)]
fn sync_directory(path: &Path) -> Result<(), LedgerError> {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;

    type Handle = *mut c_void;
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    const OPEN_EXISTING: u32 = 3;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const INVALID_HANDLE_VALUE: Handle = -1_isize as Handle;

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateFileW(
            file_name: *const u16,
            desired_access: u32,
            share_mode: u32,
            security_attributes: *mut c_void,
            creation_disposition: u32,
            flags_and_attributes: u32,
            template_file: Handle,
        ) -> Handle;
        fn FlushFileBuffers(file: Handle) -> i32;
        fn CloseHandle(object: Handle) -> i32;
    }

    let path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: path is valid NUL-terminated UTF-16; no security/template
    // pointers are supplied, and the returned handle is checked before use.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(LedgerError::Io(io::Error::last_os_error()));
    }
    // SAFETY: handle was returned by CreateFileW and remains owned here.
    let flushed = unsafe { FlushFileBuffers(handle) };
    // SAFETY: handle is valid and is closed exactly once.
    let _ = unsafe { CloseHandle(handle) };
    if flushed == 0 {
        Err(LedgerError::Io(io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn durable_rename(source: &Path, destination: &Path) -> Result<(), LedgerError> {
    use std::os::windows::ffi::OsStrExt;

    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;

    #[link(name = "kernel32")]
    extern "system" {
        fn MoveFileExW(
            existing_file_name: *const u16,
            new_file_name: *const u16,
            flags: u32,
        ) -> i32;
    }

    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    // SAFETY: both path buffers are valid NUL-terminated UTF-16 and remain
    // alive for the call; the destination is generated inside the owned root.
    let moved = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    };
    if moved == 0 {
        Err(LedgerError::Io(io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig2browser_core::{
        ControlTransport, EngineFamily, RuntimeDescriptor, RuntimeKind,
        RuntimeRequirements,
    };
    use dig2browser_protocol::{
        ResolvedRuntimeRecord, StepOutcome, StepSummary, TerminalOutcome,
    };

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(name: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("test clock")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "dig2browser-trace-{name}-{}-{nonce}",
                std::process::id(),
            ));
            fs::create_dir(&path).expect("create test root");
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn collection(byte: u8) -> CollectionId {
        CollectionId::new([byte; 16]).expect("collection ID")
    }

    fn started(step_count: u8) -> StartedTrace {
        let descriptor = RuntimeDescriptor::new(
            RuntimeKind::Chrome,
            EngineFamily::Chromium,
            ControlTransport::Cdp,
            Vec::new(),
        )
        .expect("runtime descriptor");
        let requirements = RuntimeRequirements::new(Vec::new(), false)
            .expect("runtime requirements");
        let resolved = descriptor
            .negotiate(&requirements, Some("test".to_owned()))
            .expect("resolved runtime");
        StartedTrace::new(
            [9; 32],
            step_count,
            ResolvedRuntimeRecord::from_resolved(&resolved).expect("runtime record"),
        )
        .expect("started trace")
    }

    fn terminal() -> TerminalTrace {
        TerminalTrace::new(TerminalOutcome::Succeeded, Vec::new())
            .expect("terminal trace")
    }

    #[test]
    fn orphan_artifact_round_trips_content_addressed_and_deduped() {
        let root = TestRoot::new("orphan");
        let ledger = TraceLedger::open_at(&root.0, 1).expect("ledger");
        // Media type is irrelevant to the CAS primitive; the monitor journal
        // that consumes this picks a frame media type when it lands.
        let payload = b"durable monitor frame payload".to_vec();

        let first = ledger
            .commit_orphan_artifact(ArtifactMediaType::TextHtmlUtf8, &payload)
            .expect("commit orphan artifact");
        assert_eq!(first.len(), payload.len() as u64);

        // Content-addressed: an identical payload dedups to the same reference.
        let again = ledger
            .commit_orphan_artifact(ArtifactMediaType::TextHtmlUtf8, &payload)
            .expect("recommit identical orphan artifact");
        assert_eq!(first.sha256(), again.sha256());

        // Byte-exact validated read — no owning collection required.
        let read = ledger.read_orphan_artifact(&first).expect("read orphan artifact");
        assert_eq!(read, payload);

        // Empty is rejected without any collection/step bookkeeping.
        assert!(matches!(
            ledger.commit_orphan_artifact(ArtifactMediaType::TextHtmlUtf8, b""),
            Err(LedgerError::InvalidTransition(_))
        ));
    }

    #[test]
    fn orphan_artifact_read_rejects_a_tampered_blob() {
        let root = TestRoot::new("orphan-tamper");
        let ledger = TraceLedger::open_at(&root.0, 1).expect("ledger");
        let reference = ledger
            .commit_orphan_artifact(ArtifactMediaType::TextHtmlUtf8, b"authentic")
            .expect("commit orphan artifact");
        // Same length, different bytes → the reopen-and-re-hash catches it.
        fs::write(ledger.artifact_path(reference.sha256()), b"tampered!")
            .expect("overwrite committed blob");
        assert!(matches!(
            ledger.read_orphan_artifact(&reference),
            Err(LedgerError::Corrupt(_))
        ));
    }

    #[test]
    fn writer_lock_is_exclusive_and_released_with_the_handle() {
        let root = TestRoot::new("lock");
        let first = TraceLedger::open_at(&root.0, 1).expect("first writer");
        assert!(matches!(
            TraceLedger::open_at(&root.0, 2),
            Err(LedgerError::WriterLocked)
        ));
        drop(first);
        TraceLedger::open_at(&root.0, 3).expect("successor writer");
    }

    #[test]
    fn artifact_chunks_are_bound_to_the_committing_collection() {
        let root = TestRoot::new("membership");
        let ledger = TraceLedger::open_at(&root.0, 1).expect("ledger");
        let owner = collection(1);
        let other = collection(2);
        ledger
            .begin_collection(owner, 10, started(1))
            .expect("owner start");
        ledger
            .begin_collection(other, 10, started(1))
            .expect("other start");
        let artifact = ledger
            .commit_artifact(
                owner,
                11,
                0,
                ArtifactRole::Html,
                ArtifactMediaType::TextHtmlUtf8,
                b"abcdef",
            )
            .expect("commit artifact");
        let first = ledger
            .read_artifact(owner, *artifact.sha256(), 0, 3)
            .expect("first chunk");
        assert_eq!(first.bytes(), b"abc");
        assert!(!first.is_eof());
        let second = ledger
            .read_artifact(owner, *artifact.sha256(), 3, 3)
            .expect("second chunk");
        assert_eq!(second.bytes(), b"def");
        assert!(second.is_eof());
        assert!(matches!(
            ledger.read_artifact(other, *artifact.sha256(), 0, 3),
            Err(LedgerError::ArtifactNotCommitted)
        ));
    }

    #[test]
    fn terminal_append_revalidates_committed_artifacts() {
        let root = TestRoot::new("terminal-revalidate");
        let ledger = TraceLedger::open_at(&root.0, 1).expect("ledger");
        let id = collection(3);
        ledger
            .begin_collection(id, 10, started(1))
            .expect("start");
        let artifact = ledger
            .commit_artifact(
                id,
                11,
                0,
                ArtifactRole::Html,
                ArtifactMediaType::TextHtmlUtf8,
                b"durable",
            )
            .expect("commit artifact");
        fs::write(ledger.artifact_path(artifact.sha256()), b"tampered")
            .expect("tamper artifact");
        assert!(matches!(
            ledger.finish_collection(id, 12, terminal()),
            Err(LedgerError::Corrupt(_))
        ));
    }

    #[test]
    fn successor_reconciliation_is_appended_exactly_once() {
        let root = TestRoot::new("successor");
        let id = collection(4);
        {
            let ledger = TraceLedger::open_at(&root.0, 1).expect("initial ledger");
            ledger
                .begin_collection(id, 10, started(1))
                .expect("start");
        }
        {
            let ledger = TraceLedger::open_at(&root.0, 20).expect("successor");
            let page = ledger
                .read_trace(id, TraceCursor::START, 64)
                .expect("reconciled page");
            assert_eq!(page.events().len(), 2);
            assert!(matches!(
                page.events()[1].kind(),
                TraceEventKind::Interrupted(InterruptedReason::SuccessorReconciliation)
            ));
            assert!(page.is_complete());
        }
        let ledger = TraceLedger::open_at(&root.0, 30).expect("next successor");
        let page = ledger
            .read_trace(id, TraceCursor::START, 64)
            .expect("stable page");
        assert_eq!(page.events().len(), 2);
    }

    #[test]
    fn deferred_open_preserves_selected_incomplete_collections_until_reconcile() {
        let root = TestRoot::new("deferred-successor");
        let preserved = collection(40);
        let interrupted = collection(41);
        {
            let ledger = TraceLedger::open_at(&root.0, 1).expect("initial ledger");
            ledger
                .begin_collection(preserved, 10, started(1))
                .expect("start preserved collection");
            ledger
                .begin_collection(interrupted, 11, started(1))
                .expect("start interrupted collection");
        }

        let ledger = TraceLedger::open_deferred(&root.0).expect("deferred successor");
        assert_eq!(
            ledger.incomplete_collection_ids().expect("list incomplete"),
            vec![preserved, interrupted]
        );
        let preserved_page = ledger
            .read_trace(preserved, TraceCursor::START, 64)
            .expect("read deferred trace");
        assert_eq!(preserved_page.events().len(), 1);
        assert!(!preserved_page.is_complete());

        ledger
            .reconcile_at(20, &[preserved])
            .expect("reconcile unpreserved collection");
        assert_eq!(
            ledger.incomplete_collection_ids().expect("list preserved"),
            vec![preserved]
        );
        assert!(ledger
            .read_trace(interrupted, TraceCursor::START, 64)
            .expect("read interrupted trace")
            .is_complete());

        ledger
            .reconcile_at(21, &[])
            .expect("finish successor reconciliation");
        assert!(ledger
            .incomplete_collection_ids()
            .expect("no incomplete collections")
            .is_empty());
    }

    #[test]
    fn replay_rejects_cursor_gaps_and_out_of_range_reads() {
        let root = TestRoot::new("cursor");
        let id = collection(5);
        let ledger = TraceLedger::open_at(&root.0, 1).expect("ledger");
        ledger
            .begin_collection(id, 10, started(1))
            .expect("start");
        assert!(matches!(
            ledger.read_trace(id, TraceCursor::new(2), 1),
            Err(LedgerError::InvalidCursor)
        ));

        let invalid = TraceEvent::new(
            TraceCursor::new(3),
            11,
            TraceEventKind::Interrupted(InterruptedReason::ShutdownTimeout),
        )
        .expect("event");
        write_new_file(
            &ledger.collection_dir(id).join(event_file_name(3)),
            &invalid.encode().expect("encode event"),
        )
        .expect("write cursor gap");
        assert!(matches!(ledger.replay(id), Err(LedgerError::Corrupt(_))));
    }

    #[test]
    fn full_sixty_four_step_evidence_trace_retains_terminal_capacity() {
        let root = TestRoot::new("full-capacity");
        let id = collection(6);
        let ledger = TraceLedger::open_at(&root.0, 1).expect("ledger");
        ledger
            .begin_collection(id, 10, started(64))
            .expect("start full collection");
        let mut steps = Vec::new();
        for index in 0..64_u8 {
            ledger
                .commit_artifact(
                    id,
                    11,
                    index,
                    ArtifactRole::Html,
                    ArtifactMediaType::TextHtmlUtf8,
                    b"<main>evidence</main>",
                )
                .expect("commit HTML artifact");
            ledger
                .commit_artifact(
                    id,
                    11,
                    index,
                    ArtifactRole::ViewportPng,
                    ArtifactMediaType::ImagePng,
                    b"\x89PNG\r\n\x1a\n",
                )
                .expect("commit PNG artifact");
            steps.push(
                StepSummary::new(index, 11, 1, StepOutcome::Succeeded)
                    .expect("step summary"),
            );
        }
        ledger
            .finish_collection(
                id,
                12,
                TerminalTrace::new(TerminalOutcome::Succeeded, steps)
                    .expect("terminal trace"),
            )
            .expect("terminal retains capacity");

        let first = ledger
            .read_trace(id, TraceCursor::START, 64)
            .expect("first trace page");
        let second = ledger
            .read_trace(id, first.next_cursor(), 64)
            .expect("second trace page");
        let third = ledger
            .read_trace(id, second.next_cursor(), 64)
            .expect("terminal trace page");
        assert_eq!(first.events().len(), 64);
        assert_eq!(second.events().len(), 64);
        assert_eq!(third.events().len(), 2);
        assert!(third.is_complete());
        assert!(matches!(
            third.events().last().map(TraceEvent::kind),
            Some(TraceEventKind::Terminal(_))
        ));
    }
}
