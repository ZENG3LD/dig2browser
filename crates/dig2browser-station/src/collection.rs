use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dig2browser::agentic::{AgentReply, CapabilitySet, CaptureArtifact};
use dig2browser_protocol::{
    ArtifactChunk, ArtifactMediaType, ArtifactRole, CollectionId, FailureClass,
    InterruptedReason, ResolvedRuntimeRecord, StartedTrace, StepOutcome,
    StepSummary, TerminalOutcome, TerminalTrace, TraceCursor, TraceEventKind,
    TracePage,
};
use dig2browser_trace::{LedgerError, TraceLedger};
use tokio::sync::Mutex;
use tokio::task::{AbortHandle, JoinHandle, JoinSet};

use crate::{
    BrowserLease, BrowserStation, BrowserTask, BrowserTaskResult, IdentityRequest,
    RuntimeRequirements, RuntimeSelector, StationError,
};

const MAX_ACTIVE_COLLECTIONS: usize = 256;

#[derive(Clone)]
pub(crate) struct CollectionManager {
    inner: Arc<CollectionManagerInner>,
}

struct CollectionManagerInner {
    station: BrowserStation,
    ledger: StdMutex<TraceLedger>,
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
}

impl CollectionManager {
    pub(crate) fn open(
        station: BrowserStation,
        trace_root: impl Into<PathBuf>,
    ) -> Result<Self, CollectionError> {
        let trace_root = prepare_trace_root(trace_root.into(), station.profiles_root())?;
        let ledger = TraceLedger::open(&trace_root)?;
        Ok(Self {
            inner: Arc::new(CollectionManagerInner {
                station,
                ledger: StdMutex::new(ledger),
                admission: Mutex::new(()),
                active: Mutex::new(HashMap::new()),
                terminal_failures: StdMutex::new(HashSet::new()),
                accepting: AtomicBool::new(true),
            }),
        })
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
        let join = tokio::spawn(async move {
            run_collection(
                background,
                collection_id,
                lease,
                collection.task,
                background_cancelled,
            )
            .await;
        });
        self.inner.active.lock().await.insert(
            collection_id,
            ActiveCollection { cancelled, join },
        );
        Ok(collection_id)
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
    lease: BrowserLease,
    task: BrowserTask,
    cancelled: Arc<AtomicBool>,
) {
    let result = lease.run_task_with_control(&task, &cancelled).await;
    let persisted = match inner.ledger.lock() {
        Ok(ledger) => persist_collection_result(&ledger, collection_id, result),
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
    collection_id: CollectionId,
    result: Result<BrowserTaskResult, StationError>,
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
                    AgentReply::Capture(CaptureArtifact::HtmlOnly { html, .. }) => {
                        ledger.commit_artifact(
                            collection_id,
                            unix_time_ms(),
                            step_index,
                            ArtifactRole::Html,
                            ArtifactMediaType::TextHtmlUtf8,
                            html.as_bytes(),
                        ).map(|_| ())
                    }
                    AgentReply::Capture(CaptureArtifact::EvidenceViewport {
                        html,
                        png,
                        ..
                    }) => ledger
                        .commit_artifact(
                            collection_id,
                            unix_time_ms(),
                            step_index,
                            ArtifactRole::Html,
                            ArtifactMediaType::TextHtmlUtf8,
                            html.as_bytes(),
                        )
                        .and_then(|_| {
                            ledger.commit_artifact(
                                collection_id,
                                unix_time_ms(),
                                step_index,
                                ArtifactRole::ViewportPng,
                                ArtifactMediaType::ImagePng,
                                png,
                            )
                        })
                        .map(|_| ()),
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
            let terminal = TerminalTrace::new(TerminalOutcome::Succeeded, steps)?;
            ledger.finish_collection(collection_id, unix_time_ms(), terminal)?;
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
