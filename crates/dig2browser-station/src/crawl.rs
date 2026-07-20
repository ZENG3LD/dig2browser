use std::collections::HashMap;
use std::fs::{File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dig2browser::agentic::{
    AgentReply, CapabilitySet, CaptureArtifact, CapturePolicy,
};
use dig2browser_crawler::{
    extract_links_bounded, CanonicalUrl, Completion, CrawlBudget,
    CrawlEngine, CrawlEventKind as EngineEventKind,
    CrawlSpec as EngineSpec, EngineError, Failure, FileStore, JobState,
    LeaseRecovery, Scope,
};
use dig2browser_protocol::{
    ArtifactMediaType, ArtifactRef, BrowserPersona, CollectionId,
    CrawlCounts, CrawlCursor, CrawlEvent, CrawlEventKind, CrawlEventPage,
    CrawlJobId, CrawlPhase, CrawlRequest, CrawlResponse,
    CrawlSpec, CrawlStatus, PageArtifact, ProfileClass,
    MAX_ARTIFACT_CHUNK_BYTES, MAX_CRAWL_URL_BYTES,
};
use tokio::task::JoinHandle;

use crate::collection::{
    BeginCollection, CollectionExecution, CollectionManager, ReconciledCollection,
};
use crate::{
    BrowserStation, BrowserTask, BrowserTaskStep, IdentityRequest,
    RuntimeSelector,
};

const LOCK_FILE: &str = ".dig2browser-crawl.lock";
const JOURNAL_EXTENSION: &str = "journal";
const BINDING_MAGIC: [u8; 4] = *b"D2CB";
const BINDING_VERSION: u16 = 1;
const ARTIFACT_PREFIX: &str = "d2collection-html-v1";
const LEASE_DURATION_MS: u64 = 15 * 60 * 1_000;

type DurableEngine = CrawlEngine<FileStore>;

#[derive(Clone)]
pub(crate) struct CrawlManager {
    inner: Arc<CrawlManagerInner>,
}

struct CrawlManagerInner {
    station: BrowserStation,
    collections: CollectionManager,
    root: PathBuf,
    _lock: File,
    jobs: StdMutex<HashMap<CrawlJobId, Arc<CrawlJob>>>,
    accepting: AtomicBool,
    execution_authorized: bool,
    sequence: AtomicU64,
}

struct CrawlJob {
    id: CrawlJobId,
    binding: CrawlBinding,
    engine: StdMutex<DurableEngine>,
    stop: AtomicBool,
    operator_cancel: AtomicBool,
    execution_cancel: Arc<AtomicBool>,
    unavailable: AtomicBool,
    runner: StdMutex<Option<JoinHandle<()>>>,
}

#[derive(Clone)]
struct CrawlBinding {
    job_id: CrawlJobId,
    profile_id: String,
    persona: BrowserPersona,
    spec: CrawlSpec,
}

struct CapturedPage {
    final_url: CanonicalUrl,
    status_code: Option<u16>,
    html: String,
    artifact: PageArtifact,
}

impl CrawlManager {
    pub(crate) fn open_deferred(
        station: BrowserStation,
        collections: CollectionManager,
        crawl_root: impl Into<PathBuf>,
        trace_root: &Path,
        allow_execution: bool,
    ) -> Result<Self, CrawlError> {
        tokio::runtime::Handle::try_current()
            .map_err(|_| CrawlError::RuntimeUnavailable)?;
        let root = prepare_crawl_root(
            crawl_root.into(),
            station.profiles_root(),
            trace_root,
        )?;
        let root_lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(root.join(LOCK_FILE))?;
        match root_lock.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(CrawlError::RootLocked),
            Err(TryLockError::Error(error)) => return Err(CrawlError::Io(error)),
        }

        let mut paths = Vec::new();
        for entry in std::fs::read_dir(&root)? {
            let path = entry?.path();
            if path.extension().and_then(|value| value.to_str()) == Some(JOURNAL_EXTENSION) {
                paths.push(path);
            }
        }
        paths.sort_unstable();

        let mut jobs = HashMap::new();
        for path in paths {
            let file_job_id = job_id_from_journal_path(&path)?;
            let engine = CrawlEngine::open(
                FileStore::new(&path),
                unix_time_ms(),
                LeaseRecovery::None,
            )?;
            let binding = decode_binding(engine.spec().execution_binding())?;
            if binding.job_id != file_job_id
                || engine.spec().job_id() != job_id_hex(file_job_id)
            {
                return Err(CrawlError::CorruptState(
                    "crawl journal identity does not match its binding and file name".to_owned(),
                ));
            }
            validate_engine_binding(&station, &engine, &binding)?;
            jobs.insert(file_job_id, Arc::new(CrawlJob::new(file_job_id, binding, engine)));
        }

        let manager = Self {
            inner: Arc::new(CrawlManagerInner {
                station,
                collections,
                root,
                _lock: root_lock,
                jobs: StdMutex::new(jobs),
                accepting: AtomicBool::new(false),
                execution_authorized: allow_execution,
                sequence: AtomicU64::new(1),
            }),
        };
        Ok(manager)
    }

    pub(crate) fn reconcile_and_recover(&self) -> Result<(), CrawlError> {
        if !self.inner.execution_authorized {
            return Ok(());
        }
        for job in self.jobs()? {
            if lock(&job.engine)?.status().state != JobState::Running {
                continue;
            }
            self.reconcile_in_flight(&job)?;
            let mut engine = lock(&job.engine)?;
            if engine.status().state == JobState::Running {
                engine.recover_leases(unix_time_ms(), LeaseRecovery::All)?;
            }
        }
        Ok(())
    }

    pub(crate) fn start_runners(&self) -> Result<(), CrawlError> {
        if !self.inner.execution_authorized {
            return Ok(());
        }
        for job in self.jobs()? {
            if lock(&job.engine)?.status().state == JobState::Running {
                self.spawn_runner(job)?;
            }
        }
        self.inner.accepting.store(true, Ordering::Release);
        Ok(())
    }

    pub(crate) async fn handle(
        &self,
        profile_id: &str,
        request: CrawlRequest,
    ) -> Result<CrawlResponse, CrawlError> {
        request.validate()?;
        match request {
            CrawlRequest::Begin {
                job_id,
                profile_class,
                persona,
                spec,
            } => {
                self.begin(profile_id, job_id, profile_class, persona, spec)?;
                Ok(CrawlResponse::Accepted { job_id })
            }
            CrawlRequest::Status { job_id } => {
                Ok(CrawlResponse::Status(self.status(job_id)?))
            }
            CrawlRequest::ReadEvents {
                job_id,
                cursor,
                limit,
            } => Ok(CrawlResponse::Events(self.read_events(
                job_id,
                cursor,
                limit,
            )?)),
            CrawlRequest::Cancel { job_id } => {
                self.cancel(job_id)?;
                Ok(CrawlResponse::Cancelled { job_id })
            }
        }
    }

    pub(crate) async fn shutdown(&self, timeout: Duration) -> Result<bool, CrawlError> {
        self.inner.accepting.store(false, Ordering::Release);
        let jobs = self.jobs()?;
        for job in &jobs {
            job.stop.store(true, Ordering::Release);
            job.execution_cancel.store(true, Ordering::Release);
        }
        #[cfg(feature = "crawler-test-hooks")]
        signal_shutdown_stop_set()?;

        let mut runners = Vec::new();
        for job in &jobs {
            if let Some(runner) = lock(&job.runner)?.take() {
                runners.push(runner);
            }
        }
        let drained = tokio::time::timeout(timeout, async {
            for runner in &mut runners {
                let _ = runner.await;
            }
        })
        .await
        .is_ok();
        if !drained {
            for runner in &runners {
                runner.abort();
            }
            for runner in runners {
                let _ = runner.await;
            }
        }
        for job in jobs {
            if self.inner.execution_authorized
                && !job.operator_cancel.load(Ordering::Acquire)
                && !job.unavailable.load(Ordering::Acquire)
            {
                if lock(&job.engine)?.status().state != JobState::Running {
                    continue;
                }
                self.reconcile_in_flight(&job)?;
                let mut engine = lock(&job.engine)?;
                if engine.status().state == JobState::Running {
                    engine.recover_leases(unix_time_ms(), LeaseRecovery::All)?;
                }
            }
        }
        Ok(!drained)
    }

    fn begin(
        &self,
        profile_id: &str,
        job_id: CrawlJobId,
        profile_class: ProfileClass,
        persona: BrowserPersona,
        spec: CrawlSpec,
    ) -> Result<(), CrawlError> {
        if !self.inner.accepting.load(Ordering::Acquire) {
            return Err(CrawlError::AdmissionClosed);
        }
        if profile_class != ProfileClass::Public {
            return Err(CrawlError::AuthenticatedProfileUnsupported);
        }
        validate_profile_id(profile_id)?;
        validate_wire_spec(&self.inner.station, &spec)?;

        let begin_request = CrawlRequest::begin(
            job_id,
            profile_class,
            persona.clone(),
            spec.clone(),
        )?;
        let execution_binding = encode_binding(profile_id, &begin_request)?;

        let mut jobs = lock(&self.inner.jobs)?;
        if !self.inner.accepting.load(Ordering::Acquire) {
            return Err(CrawlError::AdmissionClosed);
        }
        if let Some(existing) = jobs.get(&job_id) {
            ensure_job_available(existing)?;
            let existing_engine = lock(&existing.engine)?;
            if existing_engine.spec().execution_binding() == execution_binding.as_slice() {
                return Ok(());
            }
            return Err(CrawlError::JobConflict);
        }

        let path = journal_path(&self.inner.root, job_id);
        if path.exists() {
            return Err(CrawlError::JobConflict);
        }
        let engine_spec = to_engine_spec(job_id, &spec, execution_binding)?;
        let engine = CrawlEngine::create(FileStore::new(path), engine_spec, unix_time_ms())?;
        let job = Arc::new(CrawlJob::new(
            job_id,
            CrawlBinding {
                job_id,
                profile_id: profile_id.to_owned(),
                persona,
                spec,
            },
            engine,
        ));
        jobs.insert(job_id, Arc::clone(&job));
        drop(jobs);
        self.spawn_runner(job)
    }

    fn status(&self, job_id: CrawlJobId) -> Result<CrawlStatus, CrawlError> {
        let job = self.job(job_id)?;
        ensure_job_available(&job)?;
        let engine = lock(&job.engine)?;
        protocol_status(&job, &engine)
    }

    fn read_events(
        &self,
        job_id: CrawlJobId,
        cursor: CrawlCursor,
        limit: u8,
    ) -> Result<CrawlEventPage, CrawlError> {
        let job = self.job(job_id)?;
        ensure_job_available(&job)?;
        let engine = lock(&job.engine)?;
        let terminal = terminal_event(&job, &engine)?;
        let last_cursor = protocol_last_cursor(&job, &engine)?;
        if cursor > last_cursor {
            return Err(CrawlError::InvalidCursor);
        }
        let mut events = Vec::with_capacity(usize::from(limit));
        for event in engine.events_after(cursor.value()) {
            if events.len() >= usize::from(limit) {
                break;
            }
            events.push(to_protocol_event(&engine, event)?);
        }
        if events.len() < usize::from(limit) {
            if let Some(terminal) = terminal {
                if terminal.cursor().value() > cursor.value()
                    && events
                        .last()
                        .is_none_or(|event| event.cursor() < terminal.cursor())
                {
                    events.push(terminal);
                }
            }
        }
        let next_cursor = events
            .last()
            .map(CrawlEvent::cursor)
            .unwrap_or(cursor);
        let complete = is_terminal(&job, &engine)? && next_cursor >= last_cursor;
        Ok(CrawlEventPage::new(
            job_id,
            events,
            next_cursor,
            complete,
        )?)
    }

    fn cancel(&self, job_id: CrawlJobId) -> Result<(), CrawlError> {
        let job = self.job(job_id)?;
        ensure_job_available(&job)?;
        let mut engine = lock(&job.engine)?;
        match engine.status().state {
            JobState::Cancelled => return Ok(()),
            JobState::Running => {}
            JobState::Completed
            | JobState::CompletedWithFailures
            | JobState::FailureBudgetExhausted
            | JobState::Failed => return Err(CrawlError::JobTerminal),
        }
        engine.cancel(
            unix_time_ms(),
            Some("operator cancelled crawl".to_owned()),
        )?;
        drop(engine);
        job.operator_cancel.store(true, Ordering::Release);
        job.stop.store(true, Ordering::Release);
        job.execution_cancel.store(true, Ordering::Release);
        Ok(())
    }

    fn job(&self, job_id: CrawlJobId) -> Result<Arc<CrawlJob>, CrawlError> {
        lock(&self.inner.jobs)?
            .get(&job_id)
            .cloned()
            .ok_or(CrawlError::JobNotFound)
    }

    fn jobs(&self) -> Result<Vec<Arc<CrawlJob>>, CrawlError> {
        Ok(lock(&self.inner.jobs)?.values().cloned().collect())
    }

    fn spawn_runner(&self, job: Arc<CrawlJob>) -> Result<(), CrawlError> {
        let mut runner = lock(&job.runner)?;
        if runner.as_ref().is_some_and(|runner| !runner.is_finished()) {
            return Ok(());
        }
        let inner = Arc::clone(&self.inner);
        let background_job = Arc::clone(&job);
        let handle = tokio::runtime::Handle::try_current()
            .map_err(|_| CrawlError::RuntimeUnavailable)?
            .spawn(async move {
                if let Err(error) = run_job(inner, Arc::clone(&background_job)).await {
                    if background_job.operator_cancel.load(Ordering::Acquire) {
                        return;
                    }
                    persist_runner_failure(&background_job, &error);
                    background_job.stop.store(true, Ordering::Release);
                    background_job.execution_cancel.store(true, Ordering::Release);
                }
            });
        *runner = Some(handle);
        Ok(())
    }

    fn reconcile_in_flight(&self, job: &CrawlJob) -> Result<(), CrawlError> {
        let tokens = lock(&job.engine)?
            .active_lease_tokens()
            .collect::<Vec<_>>();
        for token in tokens {
            let attempt = token.lease().attempt();
            let collection_id = page_collection_id(job.id, token.url().as_str(), attempt)?;
            let task_sha256 = page_task_digest(job.id, token.url().as_str());
            let Some(receipt) = self
                .inner
                .collections
                .reconcile_completed(collection_id, task_sha256)?
            else {
                continue;
            };
            let page = captured_page_from_receipt(&self.inner, job, receipt)?;
            let completion = completion_for_page(&self.inner, job, &page)?;
            lock(&job.engine)?.complete_recovered(
                &token,
                completion,
                unix_time_ms(),
            )?;
        }
        Ok(())
    }
}

impl CrawlJob {
    fn new(id: CrawlJobId, binding: CrawlBinding, engine: DurableEngine) -> Self {
        Self {
            id,
            binding,
            engine: StdMutex::new(engine),
            stop: AtomicBool::new(false),
            operator_cancel: AtomicBool::new(false),
            execution_cancel: Arc::new(AtomicBool::new(false)),
            unavailable: AtomicBool::new(false),
            runner: StdMutex::new(None),
        }
    }
}

async fn run_job(
    inner: Arc<CrawlManagerInner>,
    job: Arc<CrawlJob>,
) -> Result<(), CrawlError> {
    loop {
        if job.stop.load(Ordering::Acquire) {
            return Ok(());
        }

        let lease = {
            let mut engine = lock(&job.engine)?;
            if engine.status().state != JobState::Running {
                return Ok(());
            }
            let lease_sequence = inner.sequence.fetch_add(1, Ordering::Relaxed);
            engine.claim_next(
                "dig2browser-station-crawler",
                format!("{}-{lease_sequence}", job_id_hex(job.id)),
                unix_time_ms(),
                crawl_lease_duration_ms(),
            )?
        };
        let Some(lease) = lease else {
            return Ok(());
        };

        #[cfg(feature = "crawler-test-hooks")]
        if force_runner_persistence_failure() {
            return Err(CrawlError::RuntimeUnavailable);
        }

        let result = execute_page(&inner, &job, &lease).await;
        if job.operator_cancel.load(Ordering::Acquire) {
            return Ok(());
        }
        if job.stop.load(Ordering::Acquire) {
            return Ok(());
        }

        match result {
            Ok(page) => {
                let completion = completion_for_page(&inner, &job, &page)?;
                if job.operator_cancel.load(Ordering::Acquire) {
                    return Ok(());
                }
                if job.stop.load(Ordering::Acquire) {
                    return Ok(());
                }
                let mut engine = lock(&job.engine)?;
                let now_ms = unix_time_ms();
                match engine.complete(
                    &lease,
                    completion.clone(),
                    now_ms,
                ) {
                    Ok(_) => {}
                    Err(EngineError::LeaseExpired) => {
                        engine.complete_recovered(&lease, completion, now_ms)?;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            Err(error) => {
                let failure = page_failure(&error);
                let mut engine = lock(&job.engine)?;
                let now_ms = unix_time_ms();
                match engine.fail(&lease, failure, now_ms) {
                    Ok(_) => {}
                    Err(EngineError::LeaseExpired) => {
                        engine.recover_leases(now_ms, LeaseRecovery::Expired)?;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        }
    }
}

fn page_failure(error: &CrawlError) -> Failure {
    match error {
        CrawlError::FinalUrlOutsideScope => {
            Failure::terminal("final URL is outside the crawl scope")
        }
        CrawlError::MissingHtmlCapture => {
            Failure::terminal("runtime did not produce the required HTML capture")
        }
        CrawlError::ArtifactTooLarge => {
            Failure::terminal("HTML artifact exceeds the crawl limit")
        }
        CrawlError::InvalidArtifactReference | CrawlError::Protocol(_) => {
            Failure::terminal("HTML artifact metadata is invalid")
        }
        CrawlError::CanonicalUrl(_) | CrawlError::Spec(_) | CrawlError::Task(_) => {
            Failure::terminal("crawl page contract is invalid")
        }
        CrawlError::Station(_) => {
            Failure::terminal("crawl navigation policy rejected the page")
        }
        _ => Failure::retryable("page collection failed"),
    }
}

fn durable_job_failure_reason(error: &CrawlError) -> &'static str {
    match error {
        CrawlError::Io(_) => "crawl journal unavailable",
        CrawlError::Collection(_) => "collection store unavailable",
        CrawlError::Crawler(_)
        | CrawlError::CorruptState(_)
        | CrawlError::ManagerStatePoisoned => "crawler state unavailable",
        _ => "crawl execution contract failed",
    }
}

fn persist_runner_failure(job: &CrawlJob, error: &CrawlError) {
    #[cfg(feature = "crawler-test-hooks")]
    if force_runner_persistence_failure() {
        job.unavailable.store(true, Ordering::Release);
        return;
    }

    let persisted = job.engine.lock().is_ok_and(|mut engine| {
        engine
            .fail_job(unix_time_ms(), durable_job_failure_reason(error))
            .is_ok()
    });
    if !persisted {
        job.unavailable.store(true, Ordering::Release);
    }
}

#[cfg(feature = "crawler-test-hooks")]
fn force_runner_persistence_failure() -> bool {
    std::env::var_os("DIG2BROWSER_TEST_FAIL_CRAWL_JOB_PERSISTENCE").is_some()
}

fn crawl_lease_duration_ms() -> u64 {
    #[cfg(feature = "crawler-test-hooks")]
    if let Some(duration) = std::env::var_os("DIG2BROWSER_TEST_CRAWL_LEASE_MS")
        .and_then(|value| value.to_str().and_then(|value| value.parse::<u64>().ok()))
        .filter(|duration| *duration > 0)
    {
        return duration;
    }
    LEASE_DURATION_MS
}

#[cfg(feature = "crawler-test-hooks")]
fn signal_shutdown_stop_set() -> Result<(), CrawlError> {
    let Some(root) = std::env::var_os("DIG2BROWSER_TEST_PAUSE_AFTER_CRAWL_RECEIPT")
        .map(PathBuf::from)
    else {
        return Ok(());
    };
    let signal = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(root.join("shutdown-stop-set"))?;
    signal.sync_all()?;
    Ok(())
}

fn ensure_job_available(job: &CrawlJob) -> Result<(), CrawlError> {
    if job.unavailable.load(Ordering::Acquire) {
        Err(CrawlError::JobUnavailable)
    } else {
        Ok(())
    }
}

async fn execute_page(
    inner: &CrawlManagerInner,
    job: &CrawlJob,
    lease: &dig2browser_crawler::LeaseToken,
) -> Result<CapturedPage, CrawlError> {
    let requested_url = lease.url().as_str();
    inner.station.validate_navigation_target(requested_url)?;
    let task = BrowserTask::new(vec![
        BrowserTaskStep::Navigate {
            url: requested_url.to_owned(),
        },
        BrowserTaskStep::Capture {
            policy: CapturePolicy::HtmlOnly,
        },
    ])?;
    let attempt = lease.lease().attempt();
    let task_sha256 = page_task_digest(job.id, requested_url);
    for prior_attempt in 1..attempt {
        let prior_collection_id = page_collection_id(job.id, requested_url, prior_attempt)?;
        if let Some(receipt) = inner
            .collections
            .reconcile_completed(prior_collection_id, task_sha256)?
        {
            return captured_page_from_receipt(inner, job, receipt);
        }
    }
    let collection_id = page_collection_id(job.id, requested_url, attempt)?;
    let collection = BeginCollection {
        collection_id,
        task_sha256,
        identity: IdentityRequest::public_persona(
            job.binding.profile_id.clone(),
            job.binding.persona.clone(),
        ),
        capabilities: CapabilitySet::monitoring(),
        runtime_selector: RuntimeSelector::Auto,
        runtime_requirements: None,
        task,
        persist_capture_receipt: true,
    };
    let execution = inner
        .collections
        .execute(collection, Arc::clone(&job.execution_cancel))
        .await?;
    let result = match execution {
        CollectionExecution::Executed(result) => result,
        CollectionExecution::Reconciled(receipt) => {
            return captured_page_from_receipt(inner, job, receipt)
        }
    };
    let Some(AgentReply::Capture(CaptureArtifact::HtmlOnly { state, html })) =
        result.replies.last()
    else {
        return Err(CrawlError::MissingHtmlCapture);
    };
    inner.station.validate_navigation_target(&state.url)?;
    let final_url = CanonicalUrl::parse(&state.url)?;
    if !lock(&job.engine)?.spec().allows(&final_url) {
        return Err(CrawlError::FinalUrlOutsideScope);
    }
    if html.is_empty() {
        return Err(CrawlError::MissingHtmlCapture);
    }
    let sha256 = dig2browser::digest::sha256_bytes(html.as_bytes());
    let artifact = PageArtifact::new(
        collection_id,
        ArtifactRef::new(
            sha256,
            u64::try_from(html.len()).map_err(|_| CrawlError::ArtifactTooLarge)?,
            ArtifactMediaType::TextHtmlUtf8,
        )?,
    )?;
    Ok(CapturedPage {
        final_url,
        status_code: state.http_status,
        html: html.clone(),
        artifact,
    })
}

fn captured_page_from_receipt(
    inner: &CrawlManagerInner,
    job: &CrawlJob,
    receipt: ReconciledCollection,
) -> Result<CapturedPage, CrawlError> {
    inner.station.validate_navigation_target(receipt.final_url())?;
    let final_url = CanonicalUrl::parse(receipt.final_url())?;
    if !lock(&job.engine)?.spec().allows(&final_url) {
        return Err(CrawlError::FinalUrlOutsideScope);
    }
    let html_ref = receipt.html().clone();
    let collection_id = receipt.collection_id();
    let capacity = usize::try_from(html_ref.len()).map_err(|_| CrawlError::ArtifactTooLarge)?;
    let mut html = Vec::with_capacity(capacity);
    let mut offset = 0_u64;
    loop {
        let chunk = inner.collections.read_artifact(
            collection_id,
            *html_ref.sha256(),
            offset,
            u32::try_from(MAX_ARTIFACT_CHUNK_BYTES).unwrap_or(u32::MAX),
        )?;
        html.extend_from_slice(chunk.bytes());
        offset = offset
            .checked_add(u64::try_from(chunk.bytes().len()).map_err(|_| CrawlError::ArtifactTooLarge)?)
            .ok_or(CrawlError::ArtifactTooLarge)?;
        if chunk.is_eof() {
            break;
        }
    }
    if offset != html_ref.len() {
        return Err(CrawlError::InvalidArtifactReference);
    }
    let html = String::from_utf8(html).map_err(|_| CrawlError::InvalidArtifactReference)?;
    if html.is_empty() {
        return Err(CrawlError::MissingHtmlCapture);
    }
    Ok(CapturedPage {
        final_url,
        status_code: receipt.http_status(),
        html,
        artifact: PageArtifact::new(collection_id, html_ref)?,
    })
}

fn completion_for_page(
    inner: &CrawlManagerInner,
    job: &CrawlJob,
    page: &CapturedPage,
) -> Result<Completion, CrawlError> {
    let remaining = lock(&job.engine)?.status().remaining_page_capacity;
    let links = if remaining == 0 {
        Vec::new()
    } else {
        extract_links_bounded(
            &page.final_url,
            &page.html,
            remaining.saturating_add(64),
        )
        .into_iter()
        .filter(|url| {
            url.as_str().len() <= MAX_CRAWL_URL_BYTES
                && inner.station.validate_navigation_target(url.as_str()).is_ok()
        })
        .collect::<Vec<_>>()
    };
    Ok(Completion::new(page.status_code)
        .with_artifact_ref(encode_artifact_ref(&page.artifact))
        .with_discovered_links(links))
}

fn protocol_status(job: &CrawlJob, engine: &DurableEngine) -> Result<CrawlStatus, CrawlError> {
    let status = engine.status();
    let phase = match status.state {
        JobState::Running => CrawlPhase::Running,
        JobState::Completed => CrawlPhase::Succeeded,
        JobState::CompletedWithFailures
        | JobState::FailureBudgetExhausted
        | JobState::Failed => CrawlPhase::Failed,
        JobState::Cancelled => CrawlPhase::Cancelled,
    };
    let retried = engine
        .events_after(0)
        .filter(|event| matches!(event.kind(), EngineEventKind::Requeued { .. }))
        .count();
    Ok(CrawlStatus::new(
        job.id,
        phase,
        CrawlCounts::new(
            count_u32(status.total)?,
            count_u32(status.pending)?,
            count_u32(status.in_flight)?,
            count_u32(status.completed)?,
            count_u32(status.failed)?,
            count_u32(retried)?,
        ),
        protocol_last_cursor(job, engine)?,
    )?)
}

fn to_protocol_event(
    engine: &DurableEngine,
    event: &dig2browser_crawler::CrawlEvent,
) -> Result<CrawlEvent, CrawlError> {
    let cursor = CrawlCursor::new(event.sequence());
    let at_ms = event.at_ms();
    match event.kind() {
        EngineEventKind::JobCreated => Ok(CrawlEvent::new(
            cursor,
            at_ms,
            CrawlEventKind::JobStarted,
            None,
            0,
            0,
            None,
        )?),
        EngineEventKind::Enqueued { url, depth } => Ok(CrawlEvent::new(
            cursor,
            at_ms,
            CrawlEventKind::UrlQueued,
            Some(url.as_str().to_owned()),
            *depth,
            0,
            None,
        )?),
        EngineEventKind::Claimed {
            url,
            attempt,
            ..
        } => Ok(CrawlEvent::new(
            cursor,
            at_ms,
            CrawlEventKind::PageStarted,
            Some(url.as_str().to_owned()),
            engine
                .entry(url)
                .ok_or_else(|| CrawlError::CorruptState(
                    "claimed URL is absent from the crawl frontier".to_owned(),
                ))?
                .depth(),
            *attempt,
            None,
        )?),
        EngineEventKind::LeaseRenewed { .. } => Err(CrawlError::CorruptState(
            "lease-renewal events are not representable on the crawl protocol".to_owned(),
        )),
        EngineEventKind::Completed {
            url,
            depth,
            attempt,
            status_code,
            artifact_ref,
        } => {
            let artifact = artifact_ref
                .as_deref()
                .ok_or(CrawlError::InvalidArtifactReference)
                .and_then(decode_artifact_ref)?;
            Ok(CrawlEvent::new(
                cursor,
                at_ms,
                CrawlEventKind::PageSucceeded,
                Some(url.as_str().to_owned()),
                *depth,
                *attempt,
                Some(artifact),
            )?.with_outcome(*status_code, None)?)
        }
        EngineEventKind::Failed {
            url,
            depth,
            attempt,
            error,
        } => Ok(CrawlEvent::new(
            cursor,
            at_ms,
            CrawlEventKind::PageFailed,
            Some(url.as_str().to_owned()),
            *depth,
            *attempt,
            None,
        )?.with_outcome(None, Some(error.clone()))?),
        EngineEventKind::Requeued {
            url,
            depth,
            attempt,
            reason,
        } => Ok(CrawlEvent::new(
            cursor,
            at_ms,
            if reason == "lease recovery" {
                CrawlEventKind::Recovered
            } else {
                CrawlEventKind::RetryScheduled
            },
            Some(url.as_str().to_owned()),
            *depth,
            *attempt,
            None,
        )?.with_outcome(None, Some(reason.clone()))?),
        EngineEventKind::JobFailed { reason } => Ok(CrawlEvent::new(
            cursor,
            at_ms,
            CrawlEventKind::JobFailed,
            None,
            0,
            0,
            None,
        )?.with_outcome(None, Some(reason.clone()))?),
        EngineEventKind::Cancelled { .. } => Ok(CrawlEvent::new(
            cursor,
            at_ms,
            CrawlEventKind::JobCancelled,
            None,
            0,
            0,
            None,
        )?),
    }
}

fn terminal_event(
    _job: &CrawlJob,
    engine: &DurableEngine,
) -> Result<Option<CrawlEvent>, CrawlError> {
    let last = engine.events_after(0).last();
    let last_sequence = last.map(|event| event.sequence()).unwrap_or(0);
    let last_timestamp = last.map(|event| event.at_ms()).unwrap_or_else(unix_time_ms);
    let outcome = terminal_outcome(engine.status().state);
    outcome.map(|(kind, detail)| {
        CrawlEvent::new(
            CrawlCursor::new(last_sequence.saturating_add(1)),
            last_timestamp,
            kind,
            None,
            0,
            0,
            None,
        )
        .and_then(|event| event.with_outcome(None, detail.map(str::to_owned)))
        .map_err(CrawlError::from)
    })
    .transpose()
}

fn terminal_outcome(state: JobState) -> Option<(CrawlEventKind, Option<&'static str>)> {
    match state {
        JobState::Completed => Some((CrawlEventKind::JobSucceeded, None)),
        JobState::CompletedWithFailures => Some((
            CrawlEventKind::JobFailed,
            Some("crawl completed with page failures"),
        )),
        JobState::FailureBudgetExhausted => Some((
            CrawlEventKind::JobFailed,
            Some("crawl failure budget exhausted"),
        )),
        JobState::Running | JobState::Failed | JobState::Cancelled => None,
    }
}

fn protocol_last_cursor(
    job: &CrawlJob,
    engine: &DurableEngine,
) -> Result<CrawlCursor, CrawlError> {
    if let Some(event) = terminal_event(job, engine)? {
        return Ok(event.cursor());
    }
    Ok(CrawlCursor::new(
        engine
            .events_after(0)
            .last()
            .map(|event| event.sequence())
            .unwrap_or(0),
    ))
}

fn is_terminal(_job: &CrawlJob, engine: &DurableEngine) -> Result<bool, CrawlError> {
    Ok(engine.status().state != JobState::Running)
}

fn to_engine_spec(
    job_id: CrawlJobId,
    spec: &CrawlSpec,
    execution_binding: Vec<u8>,
) -> Result<EngineSpec, CrawlError> {
    let budget = CrawlBudget::new(
        usize::try_from(spec.max_pages()).map_err(|_| CrawlError::InvalidBudget)?,
        spec.max_depth(),
        usize::try_from(spec.max_pages()).map_err(|_| CrawlError::InvalidBudget)?,
        spec.max_retries()
            .checked_add(1)
            .ok_or(CrawlError::InvalidBudget)?,
    )?;
    let scope = Scope::origins(spec.allowed_origins())?;
    Ok(EngineSpec::new(
        job_id_hex(job_id),
        spec.seeds(),
        scope,
        budget,
    )?
    .with_execution_binding(execution_binding)?)
}

fn validate_engine_binding(
    station: &BrowserStation,
    engine: &DurableEngine,
    binding: &CrawlBinding,
) -> Result<(), CrawlError> {
    validate_profile_id(&binding.profile_id)?;
    validate_wire_spec(station, &binding.spec)?;
    let expected = to_engine_spec(
        binding.job_id,
        &binding.spec,
        engine.spec().execution_binding().to_vec(),
    )?;
    if &expected != engine.spec() {
        return Err(CrawlError::CorruptState(
            "crawl journal spec does not match its execution binding".to_owned(),
        ));
    }
    Ok(())
}

fn validate_wire_spec(station: &BrowserStation, spec: &CrawlSpec) -> Result<(), CrawlError> {
    spec.validate()?;
    for origin in spec.allowed_origins() {
        station.validate_navigation_target(origin)?;
    }
    for seed in spec.seeds() {
        station.validate_navigation_target(seed)?;
    }
    Ok(())
}

fn encode_binding(profile_id: &str, request: &CrawlRequest) -> Result<Vec<u8>, CrawlError> {
    validate_profile_id(profile_id)?;
    if !request.is_begin() {
        return Err(CrawlError::InvalidBinding);
    }
    let request = request.encode()?;
    let profile_len = u16::try_from(profile_id.len()).map_err(|_| CrawlError::InvalidBinding)?;
    let request_len = u32::try_from(request.len()).map_err(|_| CrawlError::InvalidBinding)?;
    let mut output = Vec::with_capacity(12 + profile_id.len() + request.len());
    output.extend_from_slice(&BINDING_MAGIC);
    output.extend_from_slice(&BINDING_VERSION.to_le_bytes());
    output.extend_from_slice(&profile_len.to_le_bytes());
    output.extend_from_slice(&request_len.to_le_bytes());
    output.extend_from_slice(profile_id.as_bytes());
    output.extend_from_slice(&request);
    if output.len() > 64 * 1024 {
        return Err(CrawlError::InvalidBinding);
    }
    Ok(output)
}

fn decode_binding(bytes: &[u8]) -> Result<CrawlBinding, CrawlError> {
    if bytes.len() < 12 || bytes[..4] != BINDING_MAGIC {
        return Err(CrawlError::InvalidBinding);
    }
    let version = u16::from_le_bytes([bytes[4], bytes[5]]);
    if version != BINDING_VERSION {
        return Err(CrawlError::InvalidBinding);
    }
    let profile_len = usize::from(u16::from_le_bytes([bytes[6], bytes[7]]));
    let request_len = usize::try_from(u32::from_le_bytes([
        bytes[8], bytes[9], bytes[10], bytes[11],
    ]))
    .map_err(|_| CrawlError::InvalidBinding)?;
    let profile_end = 12usize
        .checked_add(profile_len)
        .ok_or(CrawlError::InvalidBinding)?;
    let request_end = profile_end
        .checked_add(request_len)
        .ok_or(CrawlError::InvalidBinding)?;
    if request_end != bytes.len() {
        return Err(CrawlError::InvalidBinding);
    }
    let profile_id = std::str::from_utf8(&bytes[12..profile_end])
        .map_err(|_| CrawlError::InvalidBinding)?
        .to_owned();
    validate_profile_id(&profile_id)?;
    let request = CrawlRequest::decode(&bytes[profile_end..request_end])?;
    let CrawlRequest::Begin {
        job_id,
        profile_class,
        persona,
        spec,
        ..
    } = request
    else {
        return Err(CrawlError::InvalidBinding);
    };
    if profile_class != ProfileClass::Public {
        return Err(CrawlError::AuthenticatedProfileUnsupported);
    }
    Ok(CrawlBinding {
        job_id,
        profile_id,
        persona,
        spec,
    })
}

fn encode_artifact_ref(page: &PageArtifact) -> String {
    format!(
        "{ARTIFACT_PREFIX}:{}:{}:{}",
        hex(page.collection_id().as_bytes()),
        hex(page.html().sha256()),
        page.html().len(),
    )
}

fn decode_artifact_ref(value: &str) -> Result<PageArtifact, CrawlError> {
    let mut parts = value.split(':');
    if parts.next() != Some(ARTIFACT_PREFIX) {
        return Err(CrawlError::InvalidArtifactReference);
    }
    let collection = parts.next().ok_or(CrawlError::InvalidArtifactReference)?;
    let sha256 = parts.next().ok_or(CrawlError::InvalidArtifactReference)?;
    let len = parts
        .next()
        .ok_or(CrawlError::InvalidArtifactReference)?
        .parse::<u64>()
        .map_err(|_| CrawlError::InvalidArtifactReference)?;
    if parts.next().is_some() {
        return Err(CrawlError::InvalidArtifactReference);
    }
    Ok(PageArtifact::new(
        CollectionId::new(decode_hex_array(collection)?)?,
        ArtifactRef::new(
            decode_hex_array(sha256)?,
            len,
            ArtifactMediaType::TextHtmlUtf8,
        )?,
    )?)
}

fn page_collection_id(
    job_id: CrawlJobId,
    url: &str,
    attempt: u32,
) -> Result<CollectionId, CrawlError> {
    let digest = page_digest(b"dig2browser-crawl-collection-v1", job_id, url, attempt);
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    if id == [0; 16] {
        id[15] = 1;
    }
    Ok(CollectionId::new(id)?)
}

fn page_task_digest(job_id: CrawlJobId, url: &str) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(32 + 16 + url.len());
    bytes.extend_from_slice(b"dig2browser-crawl-task-v2");
    bytes.extend_from_slice(job_id.as_bytes());
    bytes.extend_from_slice(url.as_bytes());
    let mut digest = dig2browser::digest::sha256_bytes(&bytes);
    if digest == [0; 32] {
        digest[31] = 1;
    }
    digest
}

fn page_digest(prefix: &[u8], job_id: CrawlJobId, url: &str, attempt: u32) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(prefix.len() + 16 + url.len() + 4);
    bytes.extend_from_slice(prefix);
    bytes.extend_from_slice(job_id.as_bytes());
    bytes.extend_from_slice(url.as_bytes());
    bytes.extend_from_slice(&attempt.to_le_bytes());
    dig2browser::digest::sha256_bytes(&bytes)
}

fn prepare_crawl_root(
    root: PathBuf,
    profiles_root: &Path,
    trace_root: &Path,
) -> Result<PathBuf, CrawlError> {
    if !root.is_absolute() {
        return Err(CrawlError::RootNotAbsolute);
    }
    if paths_overlap(&root, profiles_root) || paths_overlap(&root, trace_root) {
        return Err(CrawlError::RootOverlap);
    }
    std::fs::create_dir_all(&root)?;
    let root = std::fs::canonicalize(root)?;
    let profiles_root = std::fs::canonicalize(profiles_root)?;
    let trace_root = std::fs::canonicalize(trace_root)?;
    if paths_overlap(&root, &profiles_root) || paths_overlap(&root, &trace_root) {
        return Err(CrawlError::RootOverlap);
    }
    Ok(root)
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

fn journal_path(root: &Path, job_id: CrawlJobId) -> PathBuf {
    root.join(format!("{}.{}", job_id_hex(job_id), JOURNAL_EXTENSION))
}

fn job_id_from_journal_path(path: &Path) -> Result<CrawlJobId, CrawlError> {
    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .ok_or(CrawlError::InvalidJournalName)?;
    Ok(CrawlJobId::new(decode_hex_array(stem)?)?)
}

fn job_id_hex(job_id: CrawlJobId) -> String {
    hex(job_id.as_bytes())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[usize::from(byte >> 4)] as char);
        output.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    output
}

fn decode_hex_array<const N: usize>(value: &str) -> Result<[u8; N], CrawlError> {
    if value.len() != N * 2 || !value.is_ascii() {
        return Err(CrawlError::InvalidHex);
    }
    let mut output = [0u8; N];
    let bytes = value.as_bytes();
    for (index, output) in output.iter_mut().enumerate() {
        let high = decode_hex_digit(bytes[index * 2]).ok_or(CrawlError::InvalidHex)?;
        let low = decode_hex_digit(bytes[index * 2 + 1]).ok_or(CrawlError::InvalidHex)?;
        *output = (high << 4) | low;
    }
    if hex(&output) != value {
        return Err(CrawlError::InvalidHex);
    }
    Ok(output)
}

fn decode_hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn validate_profile_id(profile_id: &str) -> Result<(), CrawlError> {
    dig2browser::identity::validate_profile_id(profile_id)
        .map_err(|_| CrawlError::InvalidProfileId)
}

fn count_u32(value: usize) -> Result<u32, CrawlError> {
    u32::try_from(value).map_err(|_| CrawlError::CountOverflow)
}

fn lock<T>(mutex: &StdMutex<T>) -> Result<std::sync::MutexGuard<'_, T>, CrawlError> {
    mutex.lock().map_err(|_| CrawlError::ManagerStatePoisoned)
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or_default()
}

#[derive(Debug, thiserror::Error)]
pub enum CrawlError {
    #[error("crawl admission is closed")]
    AdmissionClosed,
    #[error("authenticated crawl profiles are not supported")]
    AuthenticatedProfileUnsupported,
    #[error("crawl root must be absolute")]
    RootNotAbsolute,
    #[error("crawl root must not overlap browser profiles or collection trace storage")]
    RootOverlap,
    #[error("crawl root is already owned by another station")]
    RootLocked,
    #[error("crawl job was not found")]
    JobNotFound,
    #[error("crawl job identifier is bound to another specification")]
    JobConflict,
    #[error("crawl job is already terminal")]
    JobTerminal,
    #[error("crawl job state is unavailable after a persistence failure")]
    JobUnavailable,
    #[error("crawl event cursor is beyond the durable event stream")]
    InvalidCursor,
    #[error("crawl journal file name is invalid")]
    InvalidJournalName,
    #[error("crawl execution binding is invalid")]
    InvalidBinding,
    #[error("crawl profile identifier is invalid")]
    InvalidProfileId,
    #[error("crawl budget is invalid")]
    InvalidBudget,
    #[error("crawl state is corrupt: {0}")]
    CorruptState(String),
    #[error("crawl page did not produce an HTML capture")]
    MissingHtmlCapture,
    #[error("crawl page redirected outside the job origin scope")]
    FinalUrlOutsideScope,
    #[error("crawl HTML artifact is too large")]
    ArtifactTooLarge,
    #[error("crawl artifact reference is invalid")]
    InvalidArtifactReference,
    #[error("crawl hexadecimal identifier is invalid")]
    InvalidHex,
    #[error("crawl counter exceeds the wire representation")]
    CountOverflow,
    #[error("crawl manager state is poisoned")]
    ManagerStatePoisoned,
    #[error("crawl manager requires an active Tokio runtime")]
    RuntimeUnavailable,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Protocol(#[from] dig2browser_protocol::ProtocolError),
    #[error(transparent)]
    Crawler(#[from] dig2browser_crawler::EngineError),
    #[error(transparent)]
    Spec(#[from] dig2browser_crawler::SpecError),
    #[error(transparent)]
    CanonicalUrl(#[from] dig2browser_crawler::CanonicalUrlError),
    #[error(transparent)]
    Collection(#[from] crate::CollectionError),
    #[error(transparent)]
    Station(#[from] crate::StationError),
    #[error(transparent)]
    Task(#[from] crate::TaskError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_terminal_failures_have_distinct_bounded_reasons() {
        let completed = terminal_outcome(JobState::CompletedWithFailures)
            .expect("completed-with-failures is terminal");
        let exhausted = terminal_outcome(JobState::FailureBudgetExhausted)
            .expect("failure-budget exhaustion is terminal");

        assert_eq!(completed.0, CrawlEventKind::JobFailed);
        assert_eq!(completed.1, Some("crawl completed with page failures"));
        assert_eq!(exhausted.0, CrawlEventKind::JobFailed);
        assert_eq!(exhausted.1, Some("crawl failure budget exhausted"));
        assert_ne!(completed.1, exhausted.1);
        assert!(completed.1.unwrap().len() <= 1_024);
        assert!(exhausted.1.unwrap().len() <= 1_024);
    }
}
