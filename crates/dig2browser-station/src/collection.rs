use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dig2browser::agentic::{AgentReply, CapabilitySet, CaptureArtifact};
use dig2browser_protocol::{
    ArtifactChunk, ArtifactMediaType, ArtifactRef, ArtifactRole, CollectionId,
    FailureClass, InterruptedReason, ResolvedRuntimeRecord, StartedTrace,
    StepOutcome, StepSummary, TerminalOutcome, TerminalTrace, TraceCursor,
    TraceEventKind, TracePage, MAX_ARTIFACT_CHUNK_BYTES, MAX_CRAWL_URL_BYTES,
    MAX_HTML_BYTES, MAX_TRACE_EVENTS,
};
use dig2browser_trace::{LedgerError, TraceLedger};
use tokio::sync::Mutex;
use tokio::task::{AbortHandle, JoinHandle, JoinSet};

use crate::{
    BrowserLease, BrowserStation, BrowserTask, BrowserTaskResult, IdentityRequest,
    RuntimeRequirements, RuntimeSelector, StationError,
};

const MAX_ACTIVE_COLLECTIONS: usize = 256;
const RECEIPT_DIRECTORY: &str = ".dig2browser-crawl-receipts";
const RECEIPT_MAGIC: [u8; 4] = *b"D2CR";
const RECEIPT_VERSION: u16 = 1;
const MAX_RECEIPT_URL_BYTES: usize = MAX_CRAWL_URL_BYTES;
static RECEIPT_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
pub(crate) struct CollectionManager {
    inner: Arc<CollectionManagerInner>,
}

struct CollectionManagerInner {
    station: BrowserStation,
    ledger: StdMutex<TraceLedger>,
    receipt_root: PathBuf,
    admission: Mutex<()>,
    active: Mutex<HashMap<CollectionId, ActiveCollection>>,
    terminal_failures: StdMutex<HashSet<CollectionId>>,
    accepting: AtomicBool,
}

struct ActiveCollection {
    cancelled: Arc<AtomicBool>,
    join: JoinHandle<()>,
}

pub(crate) struct BeginCollection {
    pub collection_id: CollectionId,
    pub task_sha256: [u8; 32],
    pub identity: IdentityRequest,
    pub capabilities: CapabilitySet,
    pub runtime_selector: RuntimeSelector,
    pub runtime_requirements: Option<RuntimeRequirements>,
    pub task: BrowserTask,
    pub persist_capture_receipt: bool,
}

pub(crate) enum CollectionExecution {
    Executed(BrowserTaskResult),
    Reconciled(ReconciledCollection),
}

pub(crate) struct ReconciledCollection {
    collection_id: CollectionId,
    final_url: String,
    http_status: Option<u16>,
    html: ArtifactRef,
}

impl ReconciledCollection {
    pub(crate) fn collection_id(&self) -> CollectionId {
        self.collection_id
    }

    pub(crate) fn final_url(&self) -> &str {
        &self.final_url
    }

    pub(crate) fn http_status(&self) -> Option<u16> {
        self.http_status
    }

    pub(crate) fn html(&self) -> &ArtifactRef {
        &self.html
    }
}

#[derive(Clone, PartialEq, Eq)]
struct CaptureReceipt {
    task_sha256: [u8; 32],
    terminal_at_ms: u64,
    final_url: String,
    http_status: Option<u16>,
    html: ArtifactRef,
    steps: Vec<StepSummary>,
}

impl CollectionManager {
    pub(crate) fn open_deferred(
        station: BrowserStation,
        trace_root: impl Into<PathBuf>,
    ) -> Result<Self, CollectionError> {
        let trace_root = prepare_trace_root(trace_root.into(), station.profiles_root())?;
        let receipt_root = trace_root.join(RECEIPT_DIRECTORY);
        std::fs::create_dir_all(&receipt_root)?;
        let ledger = TraceLedger::open_deferred(&trace_root)?;
        Ok(Self {
            inner: Arc::new(CollectionManagerInner {
                station,
                ledger: StdMutex::new(ledger),
                receipt_root,
                admission: Mutex::new(()),
                active: Mutex::new(HashMap::new()),
                terminal_failures: StdMutex::new(HashSet::new()),
                accepting: AtomicBool::new(false),
            }),
        })
    }

    pub(crate) fn reconcile_successor(
        &self,
        preserve_receipt_backed: bool,
    ) -> Result<(), CollectionError> {
        let incomplete = self.with_ledger(|ledger| ledger.incomplete_collection_ids())?;
        let mut preserve = Vec::new();
        if preserve_receipt_backed {
            for collection_id in incomplete {
                let Some(receipt) = read_capture_receipt(
                    &self.inner.receipt_root,
                    collection_id,
                )? else {
                    continue;
                };
                if self.started_digest(collection_id)? != receipt.task_sha256 {
                    return Err(CollectionError::CorruptReceipt);
                }
                verify_receipt_artifact(self, collection_id, &receipt.html)?;
                preserve.push(collection_id);
            }
        }
        self.with_ledger(|ledger| {
            ledger.reconcile_at(unix_time_ms(), &preserve)
        })?;
        self.inner.accepting.store(true, Ordering::Release);
        Ok(())
    }

    pub(crate) async fn begin(
        &self,
        collection: BeginCollection,
    ) -> Result<CollectionId, CollectionError> {
        if !self.inner.accepting.load(Ordering::Acquire) {
            return Err(CollectionError::AdmissionClosed);
        }
        let _admission = self.inner.admission.lock().await;
        if !self.inner.accepting.load(Ordering::Acquire) {
            return Err(CollectionError::AdmissionClosed);
        }
        self.reap_finished().await;
        self.require_collection_healthy(collection.collection_id)?;

        match self.started_digest(collection.collection_id) {
            Ok(existing) if existing == collection.task_sha256 => {
                return Ok(collection.collection_id)
            }
            Ok(_) => return Err(CollectionError::CollectionConflict),
            Err(CollectionError::Ledger(LedgerError::CollectionNotFound)) => {}
            Err(error) => return Err(error),
        }
        if self.inner.active.lock().await.len() >= MAX_ACTIVE_COLLECTIONS {
            return Err(CollectionError::AtCapacity);
        }

        self.inner
            .station
            .validate_task_targets(&collection.task)?;
        let lease = self
            .inner
            .station
            .lease_for_task(
                collection.identity,
                collection.capabilities,
                &collection.task,
                collection.runtime_selector,
                collection.runtime_requirements.as_ref(),
            )
            .await?;
        let runtime = ResolvedRuntimeRecord::from_resolved(lease.resolved_runtime())?;
        let step_count = u8::try_from(collection.task.steps().len())
            .map_err(|_| CollectionError::InvalidTask)?;
        let started = StartedTrace::new(
            collection.task_sha256,
            step_count,
            runtime,
        )?;
        self.with_ledger(|ledger| {
            ledger.begin_collection(
                collection.collection_id,
                unix_time_ms(),
                started,
            )
        })?;

        let cancelled = Arc::new(AtomicBool::new(false));
        let background = Arc::clone(&self.inner);
        let background_cancelled = Arc::clone(&cancelled);
        let collection_id = collection.collection_id;
        let task_sha256 = collection.task_sha256;
        let persist_capture_receipt = collection.persist_capture_receipt;
        let join = tokio::spawn(async move {
            run_collection(
                background,
                collection_id,
                task_sha256,
                lease,
                collection.task,
                background_cancelled,
                persist_capture_receipt,
            )
            .await;
        });
        self.inner.active.lock().await.insert(
            collection_id,
            ActiveCollection { cancelled, join },
        );
        Ok(collection_id)
    }

    pub(crate) async fn execute(
        &self,
        collection: BeginCollection,
        cancelled: Arc<AtomicBool>,
    ) -> Result<CollectionExecution, CollectionError> {
        if !self.inner.accepting.load(Ordering::Acquire) {
            return Err(CollectionError::AdmissionClosed);
        }
        let _admission = self.inner.admission.lock().await;
        if !self.inner.accepting.load(Ordering::Acquire) {
            return Err(CollectionError::AdmissionClosed);
        }
        self.reap_finished().await;
        self.require_collection_healthy(collection.collection_id)?;
        if let Some(completed) = self.reconcile_completed(
            collection.collection_id,
            collection.task_sha256,
        )? {
            return Ok(CollectionExecution::Reconciled(completed));
        }
        match self.started_digest(collection.collection_id) {
            Ok(_) => return Err(CollectionError::CollectionConflict),
            Err(CollectionError::Ledger(LedgerError::CollectionNotFound)) => {}
            Err(error) => return Err(error),
        }

        self.inner
            .station
            .validate_task_targets(&collection.task)?;
        let lease = self
            .inner
            .station
            .lease_for_task(
                collection.identity,
                collection.capabilities,
                &collection.task,
                collection.runtime_selector,
                collection.runtime_requirements.as_ref(),
            )
            .await?;
        let runtime = ResolvedRuntimeRecord::from_resolved(lease.resolved_runtime())?;
        let step_count = u8::try_from(collection.task.steps().len())
            .map_err(|_| CollectionError::InvalidTask)?;
        let started = StartedTrace::new(
            collection.task_sha256,
            step_count,
            runtime,
        )?;
        self.with_ledger(|ledger| {
            ledger.begin_collection(
                collection.collection_id,
                unix_time_ms(),
                started,
            )
        })?;
        drop(_admission);

        let result = lease
            .run_task_with_control(&collection.task, &cancelled)
            .await;
        let persisted = match self.inner.ledger.lock() {
            Ok(ledger) => {
                persist_collection_result(
                    &ledger,
                    &self.inner.receipt_root,
                    collection.collection_id,
                    collection.task_sha256,
                    result.as_ref(),
                    collection.persist_capture_receipt,
                )
            }
            Err(_) => Err(CollectionError::LedgerPoisoned),
        };
        if let Err(error) = persisted {
            self.inner.accepting.store(false, Ordering::Release);
            self.inner
                .terminal_failures
                .lock()
                .map_err(|_| CollectionError::ManagerStatePoisoned)?
                .insert(collection.collection_id);
            return Err(error);
        }
        result
            .map(CollectionExecution::Executed)
            .map_err(CollectionError::Station)
    }

    pub(crate) fn reconcile_completed(
        &self,
        collection_id: CollectionId,
        task_sha256: [u8; 32],
    ) -> Result<Option<ReconciledCollection>, CollectionError> {
        self.require_collection_healthy(collection_id)?;
        match self.started_digest(collection_id) {
            Ok(existing) if existing != task_sha256 => {
                return Err(CollectionError::CollectionConflict)
            }
            Ok(_) => {}
            Err(CollectionError::Ledger(LedgerError::CollectionNotFound)) => {
                return Ok(None)
            }
            Err(error) => return Err(error),
        }

        let Some(receipt) = read_capture_receipt(
            &self.inner.receipt_root,
            collection_id,
        )? else {
            return Ok(None);
        };
        if receipt.task_sha256 != task_sha256 {
            return Err(CollectionError::CollectionConflict);
        }

        let mut cursor = TraceCursor::START;
        let mut terminal = None;
        loop {
            let page = self.read_trace(
                collection_id,
                cursor,
                u8::try_from(MAX_TRACE_EVENTS).unwrap_or(u8::MAX),
            )?;
            for event in page.events() {
                if let TraceEventKind::Terminal(existing) = event.kind() {
                    terminal = Some(existing.outcome());
                }
            }
            if page.is_complete() {
                break;
            }
            if page.next_cursor() == cursor {
                break;
            }
            cursor = page.next_cursor();
        }
        verify_receipt_artifact(self, collection_id, &receipt.html)?;
        match terminal {
            Some(TerminalOutcome::Succeeded) => {}
            Some(_) => return Err(CollectionError::CorruptTrace),
            None => {
                let terminal = TerminalTrace::new(
                    TerminalOutcome::Succeeded,
                    receipt.steps.clone(),
                )?;
                self.with_ledger(|ledger| {
                    ledger.finish_collection(
                        collection_id,
                        receipt.terminal_at_ms,
                        terminal,
                    )
                })?;
            }
        }
        Ok(Some(ReconciledCollection {
            collection_id,
            final_url: receipt.final_url,
            http_status: receipt.http_status,
            html: receipt.html,
        }))
    }

    pub(crate) fn read_trace(
        &self,
        collection_id: CollectionId,
        cursor: TraceCursor,
        limit: u8,
    ) -> Result<TracePage, CollectionError> {
        self.require_collection_healthy(collection_id)?;
        self.with_ledger(|ledger| ledger.read_trace(collection_id, cursor, limit))
    }

    pub(crate) fn read_artifact(
        &self,
        collection_id: CollectionId,
        sha256: [u8; 32],
        offset: u64,
        max_bytes: u32,
    ) -> Result<ArtifactChunk, CollectionError> {
        self.require_collection_healthy(collection_id)?;
        self.with_ledger(|ledger| {
            ledger.read_artifact(collection_id, sha256, offset, max_bytes)
        })
    }

    pub(crate) async fn cancel(
        &self,
        collection_id: CollectionId,
    ) -> Result<(), CollectionError> {
        self.reap_finished().await;
        self.require_collection_healthy(collection_id)?;
        if let Some(active) = self.inner.active.lock().await.get(&collection_id) {
            active.cancelled.store(true, Ordering::Release);
            return Ok(());
        }
        self.with_ledger(|ledger| {
            ledger.read_trace(collection_id, TraceCursor::START, 1)
        })?;
        Ok(())
    }

    pub(crate) async fn shutdown(&self, timeout: Duration) -> Result<bool, CollectionError> {
        self.inner.accepting.store(false, Ordering::Release);
        let _admission = self.inner.admission.lock().await;
        let active: Vec<(CollectionId, ActiveCollection)> =
            self.inner.active.lock().await.drain().collect();
        if active.is_empty() {
            self.require_no_terminal_failures()?;
            return Ok(false);
        }
        let collection_ids: Vec<CollectionId> =
            active.iter().map(|(collection_id, _)| *collection_id).collect();
        let mut aborts: Vec<AbortHandle> = Vec::with_capacity(active.len());
        let mut waiters = JoinSet::new();
        for (collection_id, active) in active {
            active.cancelled.store(true, Ordering::Release);
            aborts.push(active.join.abort_handle());
            waiters.spawn(async move {
                let _ = active.join.await;
                collection_id
            });
        }
        let drained = tokio::time::timeout(timeout, async {
            while waiters.join_next().await.is_some() {}
        })
        .await
        .is_ok();
        if drained {
            self.require_no_terminal_failures()?;
            return Ok(false);
        }
        for abort in aborts {
            abort.abort();
        }
        while waiters.join_next().await.is_some() {}
        for collection_id in collection_ids {
            let result = self.with_ledger(|ledger| {
                ledger.interrupt_collection(
                    collection_id,
                    unix_time_ms(),
                    InterruptedReason::ShutdownTimeout,
                )
            });
            if let Err(CollectionError::Ledger(LedgerError::InvalidTransition(_))) = result {
                self.clear_terminal_failure(collection_id)?;
                continue;
            }
            result?;
            self.clear_terminal_failure(collection_id)?;
        }
        self.require_no_terminal_failures()?;
        Ok(true)
    }

    async fn reap_finished(&self) {
        self.inner
            .active
            .lock()
            .await
            .retain(|_, active| !active.join.is_finished());
    }

    fn started_digest(
        &self,
        collection_id: CollectionId,
    ) -> Result<[u8; 32], CollectionError> {
        let page = self.with_ledger(|ledger| {
            ledger.read_trace(collection_id, TraceCursor::START, 1)
        })?;
        let [event] = page.events() else {
            return Err(CollectionError::CorruptTrace);
        };
        let TraceEventKind::Started(started) = event.kind() else {
            return Err(CollectionError::CorruptTrace);
        };
        Ok(*started.task_sha256())
    }

    fn require_collection_healthy(
        &self,
        collection_id: CollectionId,
    ) -> Result<(), CollectionError> {
        let failures = self
            .inner
            .terminal_failures
            .lock()
            .map_err(|_| CollectionError::ManagerStatePoisoned)?;
        if failures.contains(&collection_id) {
            Err(CollectionError::TerminalPersistenceFailed)
        } else {
            Ok(())
        }
    }

    fn require_no_terminal_failures(&self) -> Result<(), CollectionError> {
        let failures = self
            .inner
            .terminal_failures
            .lock()
            .map_err(|_| CollectionError::ManagerStatePoisoned)?;
        if failures.is_empty() {
            Ok(())
        } else {
            Err(CollectionError::TerminalPersistenceFailed)
        }
    }

    fn clear_terminal_failure(
        &self,
        collection_id: CollectionId,
    ) -> Result<(), CollectionError> {
        self.inner
            .terminal_failures
            .lock()
            .map_err(|_| CollectionError::ManagerStatePoisoned)?
            .remove(&collection_id);
        Ok(())
    }

    fn with_ledger<T>(
        &self,
        operation: impl FnOnce(&TraceLedger) -> Result<T, LedgerError>,
    ) -> Result<T, CollectionError> {
        let ledger = self
            .inner
            .ledger
            .lock()
            .map_err(|_| CollectionError::LedgerPoisoned)?;
        operation(&ledger).map_err(CollectionError::from)
    }
}

async fn run_collection(
    inner: Arc<CollectionManagerInner>,
    collection_id: CollectionId,
    task_sha256: [u8; 32],
    lease: BrowserLease,
    task: BrowserTask,
    cancelled: Arc<AtomicBool>,
    persist_capture_receipt: bool,
) {
    let result = lease.run_task_with_control(&task, &cancelled).await;
    let persisted = match inner.ledger.lock() {
        Ok(ledger) => persist_collection_result(
            &ledger,
            &inner.receipt_root,
            collection_id,
            task_sha256,
            result.as_ref(),
            persist_capture_receipt,
        ),
        Err(_) => Err(CollectionError::LedgerPoisoned),
    };
    if persisted.is_err() {
        inner.accepting.store(false, Ordering::Release);
        if let Ok(mut failures) = inner.terminal_failures.lock() {
            failures.insert(collection_id);
        }
    }
}

fn persist_collection_result(
    ledger: &TraceLedger,
    receipt_root: &Path,
    collection_id: CollectionId,
    task_sha256: [u8; 32],
    result: Result<&BrowserTaskResult, &StationError>,
    persist_capture_receipt: bool,
) -> Result<(), CollectionError> {
    match result {
        Ok(result) => {
            let steps = result
                .step_metrics
                .iter()
                .enumerate()
                .map(|(index, metric)| {
                    StepSummary::new(
                        u8::try_from(index).unwrap_or(u8::MAX),
                        metric.completed_at_unix_ms,
                        metric.duration_ms,
                        StepOutcome::Succeeded,
                    )
                })
                .collect::<Result<Vec<_>, _>>();
            let Ok(steps) = steps else {
                return finish_failed(
                    ledger,
                    collection_id,
                    FailureClass::Protocol,
                    Vec::new(),
                );
            };
            let mut receipt_capture = None;
            for (index, reply) in result.replies.iter().enumerate() {
                let step_index = match u8::try_from(index) {
                    Ok(index) => index,
                    Err(_) => {
                        return finish_failed(
                            ledger,
                            collection_id,
                            FailureClass::Protocol,
                            steps,
                        );
                    }
                };
                let committed = match reply {
                    AgentReply::Capture(CaptureArtifact::HtmlOnly { state, html }) => {
                        ledger.commit_artifact(
                            collection_id,
                            unix_time_ms(),
                            step_index,
                            ArtifactRole::Html,
                            ArtifactMediaType::TextHtmlUtf8,
                            html.as_bytes(),
                        ).map(|artifact| {
                            receipt_capture = Some((
                                state.url.clone(),
                                state.http_status,
                                artifact,
                            ));
                        })
                    }
                    AgentReply::Capture(CaptureArtifact::EvidenceViewport {
                        state,
                        html,
                        png,
                    }) => {
                        let html_artifact = ledger.commit_artifact(
                            collection_id,
                            unix_time_ms(),
                            step_index,
                            ArtifactRole::Html,
                            ArtifactMediaType::TextHtmlUtf8,
                            html.as_bytes(),
                        );
                        html_artifact.and_then(|artifact| {
                            receipt_capture = Some((
                                state.url.clone(),
                                state.http_status,
                                artifact,
                            ));
                            ledger.commit_artifact(
                                collection_id,
                                unix_time_ms(),
                                step_index,
                                ArtifactRole::ViewportPng,
                                ArtifactMediaType::ImagePng,
                                png,
                            )
                        })
                        .map(|_| ())
                    }
                    _ => Ok(()),
                };
                if committed.is_err() {
                    return finish_failed(
                        ledger,
                        collection_id,
                        FailureClass::Protocol,
                        steps,
                    );
                }
            }
            let terminal_at_ms = unix_time_ms();
            if persist_capture_receipt {
                let Some((final_url, http_status, html)) = receipt_capture else {
                    return finish_failed(
                        ledger,
                        collection_id,
                        FailureClass::Protocol,
                        steps,
                    );
                };
                let receipt = CaptureReceipt {
                    task_sha256,
                    terminal_at_ms,
                    final_url,
                    http_status,
                    html,
                    steps: steps.clone(),
                };
                if let Err(error) = write_capture_receipt(
                    receipt_root,
                    collection_id,
                    &receipt,
                ) {
                    let _ = finish_failed(
                        ledger,
                        collection_id,
                        FailureClass::Protocol,
                        steps,
                    );
                    return Err(error);
                }
                #[cfg(feature = "crawler-test-hooks")]
                pause_after_capture_receipt()?;
            }
            let terminal = TerminalTrace::new(TerminalOutcome::Succeeded, steps)?;
            ledger.finish_collection(collection_id, terminal_at_ms, terminal)?;
            Ok(())
        }
        Err(StationError::TaskCancelled) => {
            let terminal = TerminalTrace::new(TerminalOutcome::Cancelled, Vec::new())?;
            ledger.finish_collection(collection_id, unix_time_ms(), terminal)?;
            Ok(())
        }
        Err(_) => finish_failed(
            ledger,
            collection_id,
            FailureClass::CaptureFailed,
            Vec::new(),
        ),
    }
}

fn finish_failed(
    ledger: &TraceLedger,
    collection_id: CollectionId,
    failure: FailureClass,
    steps: Vec<StepSummary>,
) -> Result<(), CollectionError> {
    let terminal = TerminalTrace::new(TerminalOutcome::Failed(failure), steps)?;
    ledger.finish_collection(collection_id, unix_time_ms(), terminal)?;
    Ok(())
}

fn write_capture_receipt(
    root: &Path,
    collection_id: CollectionId,
    receipt: &CaptureReceipt,
) -> Result<(), CollectionError> {
    let path = capture_receipt_path(root, collection_id);
    if path.exists() {
        return match read_capture_receipt(root, collection_id)? {
            Some(existing) if existing == *receipt => Ok(()),
            _ => Err(CollectionError::CorruptReceipt),
        };
    }
    let bytes = encode_capture_receipt(receipt)?;
    let sequence = RECEIPT_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temp_path = root.join(format!(
        ".{}.{}.{}.tmp",
        capture_receipt_name(collection_id),
        std::process::id(),
        sequence,
    ));
    let result = (|| -> Result<(), CollectionError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        match durable_rename(&temp_path, &path) {
            Ok(()) => {}
            Err(CollectionError::Io(error))
                if error.kind() == std::io::ErrorKind::AlreadyExists =>
            {
                match read_capture_receipt(root, collection_id)? {
                    Some(existing) if existing == *receipt => {}
                    _ => return Err(CollectionError::CorruptReceipt),
                }
            }
            Err(error) => return Err(error),
        }
        Ok(())
    })();
    if result.is_err() || temp_path.exists() {
        let _ = std::fs::remove_file(&temp_path);
    }
    result
}

#[cfg(feature = "crawler-test-hooks")]
fn pause_after_capture_receipt() -> Result<(), CollectionError> {
    const ENVIRONMENT: &str = "DIG2BROWSER_TEST_PAUSE_AFTER_CRAWL_RECEIPT";
    let Some(root) = std::env::var_os(ENVIRONMENT).map(PathBuf::from) else {
        return Ok(());
    };
    let paused = root.join("receipt-paused");
    let release = root.join("receipt-release");
    let mut signal = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(paused)?;
    signal.write_all(b"receipt durable; terminal pending\n")?;
    signal.sync_all()?;
    tokio::task::block_in_place(|| {
        while !release.exists() {
            std::thread::sleep(Duration::from_millis(5));
        }
    });
    Ok(())
}

fn verify_receipt_artifact(
    manager: &CollectionManager,
    collection_id: CollectionId,
    artifact: &ArtifactRef,
) -> Result<(), CollectionError> {
    let capacity = usize::try_from(artifact.len())
        .map_err(|_| CollectionError::CorruptReceipt)?;
    if capacity == 0 || capacity > MAX_HTML_BYTES {
        return Err(CollectionError::CorruptReceipt);
    }
    let mut bytes = Vec::with_capacity(capacity);
    let mut offset = 0_u64;
    loop {
        let chunk = manager.read_artifact(
            collection_id,
            *artifact.sha256(),
            offset,
            u32::try_from(MAX_ARTIFACT_CHUNK_BYTES).unwrap_or(u32::MAX),
        )?;
        bytes.extend_from_slice(chunk.bytes());
        offset = offset
            .checked_add(
                u64::try_from(chunk.bytes().len())
                    .map_err(|_| CollectionError::CorruptReceipt)?,
            )
            .ok_or(CollectionError::CorruptReceipt)?;
        if chunk.is_eof() {
            break;
        }
    }
    if offset != artifact.len()
        || dig2browser::digest::sha256_bytes(&bytes) != *artifact.sha256()
    {
        return Err(CollectionError::CorruptReceipt);
    }
    Ok(())
}

fn read_capture_receipt(
    root: &Path,
    collection_id: CollectionId,
) -> Result<Option<CaptureReceipt>, CollectionError> {
    let path = capture_receipt_path(root, collection_id);
    let file = match OpenOptions::new().read(true).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let metadata = file.metadata()?;
    let max_len = u64::try_from(MAX_RECEIPT_URL_BYTES)
        .unwrap_or(u64::MAX)
        .saturating_add(4 * 1024);
    if metadata.len() == 0 || metadata.len() > max_len {
        return Err(CollectionError::CorruptReceipt);
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len()).map_err(|_| CollectionError::CorruptReceipt)?,
    );
    file.take(max_len.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.is_empty()
        || u64::try_from(bytes.len())
            .map_err(|_| CollectionError::CorruptReceipt)?
            > max_len
    {
        return Err(CollectionError::CorruptReceipt);
    }
    decode_capture_receipt(&bytes).map(Some)
}

fn encode_capture_receipt(receipt: &CaptureReceipt) -> Result<Vec<u8>, CollectionError> {
    if receipt.final_url.is_empty()
        || receipt.final_url.len() > MAX_RECEIPT_URL_BYTES
        || receipt.steps.len() > MAX_TRACE_EVENTS
        || receipt.html.media_type() != ArtifactMediaType::TextHtmlUtf8
        || usize::try_from(receipt.html.len()).ok().is_none_or(|len| {
            len == 0 || len > MAX_HTML_BYTES
        })
    {
        return Err(CollectionError::CorruptReceipt);
    }
    let url_len = u32::try_from(receipt.final_url.len())
        .map_err(|_| CollectionError::CorruptReceipt)?;
    let step_count = u8::try_from(receipt.steps.len())
        .map_err(|_| CollectionError::CorruptReceipt)?;
    let mut bytes = Vec::with_capacity(96 + receipt.final_url.len() + receipt.steps.len() * 17);
    bytes.extend_from_slice(&RECEIPT_MAGIC);
    bytes.extend_from_slice(&RECEIPT_VERSION.to_le_bytes());
    bytes.extend_from_slice(&receipt.task_sha256);
    bytes.extend_from_slice(&receipt.terminal_at_ms.to_le_bytes());
    match receipt.http_status {
        Some(status) => {
            bytes.push(1);
            bytes.extend_from_slice(&status.to_le_bytes());
        }
        None => {
            bytes.push(0);
            bytes.extend_from_slice(&0_u16.to_le_bytes());
        }
    }
    bytes.extend_from_slice(&url_len.to_le_bytes());
    bytes.extend_from_slice(receipt.final_url.as_bytes());
    bytes.extend_from_slice(receipt.html.sha256());
    bytes.extend_from_slice(&receipt.html.len().to_le_bytes());
    bytes.push(step_count);
    for step in &receipt.steps {
        if step.outcome() != StepOutcome::Succeeded {
            return Err(CollectionError::CorruptReceipt);
        }
        bytes.push(step.step_index());
        bytes.extend_from_slice(&step.completed_at_unix_ms().to_le_bytes());
        bytes.extend_from_slice(&step.duration_ms().to_le_bytes());
    }
    let checksum = dig2browser::digest::sha256_bytes(&bytes);
    bytes.extend_from_slice(&checksum);
    Ok(bytes)
}

fn decode_capture_receipt(bytes: &[u8]) -> Result<CaptureReceipt, CollectionError> {
    let payload_len = bytes
        .len()
        .checked_sub(32)
        .ok_or(CollectionError::CorruptReceipt)?;
    let (payload, checksum) = bytes.split_at(payload_len);
    if dig2browser::digest::sha256_bytes(payload).as_slice() != checksum {
        return Err(CollectionError::CorruptReceipt);
    }
    let mut input = ReceiptInput::new(payload);
    if input.take(4)? != RECEIPT_MAGIC || input.u16()? != RECEIPT_VERSION {
        return Err(CollectionError::CorruptReceipt);
    }
    let task_sha256 = input.array()?;
    let terminal_at_ms = input.u64()?;
    let status_present = input.u8()?;
    let status = input.u16()?;
    let http_status = match status_present {
        0 if status == 0 => None,
        1 if (100..=599).contains(&status) => Some(status),
        _ => return Err(CollectionError::CorruptReceipt),
    };
    let url_len = usize::try_from(input.u32()?)
        .map_err(|_| CollectionError::CorruptReceipt)?;
    if url_len == 0 || url_len > MAX_RECEIPT_URL_BYTES {
        return Err(CollectionError::CorruptReceipt);
    }
    let final_url = std::str::from_utf8(input.take(url_len)?)
        .map_err(|_| CollectionError::CorruptReceipt)?
        .to_owned();
    let html_sha256 = input.array()?;
    let html_len = input.u64()?;
    if usize::try_from(html_len)
        .ok()
        .is_none_or(|len| len == 0 || len > MAX_HTML_BYTES)
    {
        return Err(CollectionError::CorruptReceipt);
    }
    let html = ArtifactRef::new(
        html_sha256,
        html_len,
        ArtifactMediaType::TextHtmlUtf8,
    )?;
    let step_count = usize::from(input.u8()?);
    if step_count > MAX_TRACE_EVENTS {
        return Err(CollectionError::CorruptReceipt);
    }
    let mut steps = Vec::with_capacity(step_count);
    for _ in 0..step_count {
        steps.push(StepSummary::new(
            input.u8()?,
            input.u64()?,
            input.u64()?,
            StepOutcome::Succeeded,
        )?);
    }
    if !input.is_empty() {
        return Err(CollectionError::CorruptReceipt);
    }
    Ok(CaptureReceipt {
        task_sha256,
        terminal_at_ms,
        final_url,
        http_status,
        html,
        steps,
    })
}

fn capture_receipt_path(root: &Path, collection_id: CollectionId) -> PathBuf {
    root.join(capture_receipt_name(collection_id))
}

fn capture_receipt_name(collection_id: CollectionId) -> String {
    let mut name = String::with_capacity(40);
    for byte in collection_id.as_bytes() {
        use std::fmt::Write as _;
        let _ = write!(&mut name, "{byte:02x}");
    }
    name.push_str(".receipt");
    name
}

#[cfg(unix)]
fn durable_rename(source: &Path, destination: &Path) -> Result<(), CollectionError> {
    std::fs::rename(source, destination)?;
    let parent = destination.parent().ok_or(CollectionError::CorruptReceipt)?;
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(windows)]
fn durable_rename(source: &Path, destination: &Path) -> Result<(), CollectionError> {
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
    // SAFETY: both buffers are NUL-terminated UTF-16 paths inside the owned
    // receipt root and remain alive for the duration of the call.
    let moved = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    };
    if moved == 0 {
        Err(std::io::Error::last_os_error().into())
    } else {
        Ok(())
    }
}

struct ReceiptInput<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ReceiptInput<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], CollectionError> {
        let end = self.offset.checked_add(len).ok_or(CollectionError::CorruptReceipt)?;
        let value = self.bytes.get(self.offset..end).ok_or(CollectionError::CorruptReceipt)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], CollectionError> {
        self.take(N)?
            .try_into()
            .map_err(|_| CollectionError::CorruptReceipt)
    }

    fn u8(&mut self) -> Result<u8, CollectionError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, CollectionError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, CollectionError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, CollectionError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

fn prepare_trace_root(root: PathBuf, profiles_root: &Path) -> Result<PathBuf, CollectionError> {
    if !root.is_absolute() {
        return Err(CollectionError::TraceRootNotAbsolute);
    }
    if paths_overlap(&root, profiles_root) {
        return Err(CollectionError::TraceRootOverlap);
    }
    std::fs::create_dir_all(&root)?;
    let root = std::fs::canonicalize(root)?;
    let profiles_root = std::fs::canonicalize(profiles_root)?;
    if paths_overlap(&root, &profiles_root) {
        return Err(CollectionError::TraceRootOverlap);
    }
    Ok(root)
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or_default()
}

#[derive(Debug, thiserror::Error)]
pub enum CollectionError {
    #[error("collection admission is closed")]
    AdmissionClosed,
    #[error("active collection limit reached")]
    AtCapacity,
    #[error("collection identifier is bound to a different task")]
    CollectionConflict,
    #[error("collection task is invalid")]
    InvalidTask,
    #[error("trace root must be absolute")]
    TraceRootNotAbsolute,
    #[error("trace root must not overlap browser profiles")]
    TraceRootOverlap,
    #[error("trace state is corrupt")]
    CorruptTrace,
    #[error("collection capture receipt is corrupt")]
    CorruptReceipt,
    #[error("collection terminal state could not be persisted")]
    TerminalPersistenceFailed,
    #[error("collection manager state is poisoned")]
    ManagerStatePoisoned,
    #[error("trace ledger mutex is poisoned")]
    LedgerPoisoned,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Protocol(#[from] dig2browser_protocol::ProtocolError),
    #[error(transparent)]
    Ledger(#[from] LedgerError),
    #[error(transparent)]
    Station(#[from] StationError),
}
