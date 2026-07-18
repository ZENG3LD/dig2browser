//! Stateful resource owner for `dig2browser` consumers.
//!
//! `dig2browser` owns protocols and one browser runtime. This crate owns reuse,
//! admission, leases, capacity and coordinated final shutdown. Product-specific
//! crawling, monitoring schedules and evidence storage stay in consumers.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dig2browser::agentic::{
    AgentCommand, AgentReply, BrowserSnapshot, BrowserWorker, BrowserWorkerConfig,
    Capability, CapabilitySet, CaptureArtifact, CapturePolicy, ElementRef, L1Capability,
    L2Capability, L3Capability, MobileLayout, RuntimeFailureKind, WorkerError,
    WorkerLifecycle,
};
use dig2browser::identity::{
    BrowserBackend, DevicePersona, IdentityClass, IdentityError, IdentityProfile,
    ProfileOwnershipGuard,
};
use dig2browser::stealth::{ClientHintsProfile, LocaleProfile};
use dig2browser_protocol::{BrowserPersona, PersonaKind};
use tokio::sync::{Mutex, RwLock, Semaphore};

pub mod ipc;

const MAX_RESIDENT: usize = 256;
const MAX_IN_FLIGHT: usize = 4_096;
const MAX_TASK_STEPS: usize = 64;
const MAX_TASK_WAIT: Duration = Duration::from_secs(2 * 60);

/// Exclusive, crash-releasing ownership of one canonical station profiles root.
#[derive(Debug)]
pub struct ProfilesRootOwnership {
    root: PathBuf,
    _guard: ProfileOwnershipGuard,
}

impl ProfilesRootOwnership {
    pub fn acquire(root: impl Into<PathBuf>) -> Result<Self, ProfilesRootError> {
        let root = root.into();
        if !root.is_absolute() {
            return Err(ProfilesRootError::NotAbsolute);
        }
        std::fs::create_dir_all(&root).map_err(ProfilesRootError::Io)?;
        let root = std::fs::canonicalize(root).map_err(ProfilesRootError::Io)?;
        if !root.metadata().map_err(ProfilesRootError::Io)?.is_dir() {
            return Err(ProfilesRootError::NotDirectory);
        }
        let guard = match ProfileOwnershipGuard::acquire(&root) {
            Ok(guard) => guard,
            Err(IdentityError::ProfileAlreadyOwned { .. }) => {
                return Err(ProfilesRootError::AlreadyOwned)
            }
            Err(IdentityError::Io(error)) => return Err(ProfilesRootError::Io(error)),
            Err(IdentityError::InvalidProfileId(_)) => {
                return Err(ProfilesRootError::NotDirectory)
            }
        };
        Ok(Self {
            root,
            _guard: guard,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

#[derive(Debug, Clone)]
pub struct StationConfig {
    profiles_root: PathBuf,
    max_resident: usize,
    max_in_flight: usize,
    worker: BrowserWorkerConfig,
    worker_capabilities: CapabilitySet,
}

impl StationConfig {
    pub fn new(
        profiles_root: impl Into<PathBuf>,
        max_resident: usize,
        max_in_flight: usize,
    ) -> Result<Self, ConfigError> {
        let profiles_root = profiles_root.into();
        if !profiles_root.is_absolute() {
            return Err(ConfigError::ProfilesRootNotAbsolute);
        }
        if max_resident == 0 || max_resident > MAX_RESIDENT {
            return Err(ConfigError::InvalidResidentLimit);
        }
        if max_in_flight == 0 || max_in_flight > MAX_IN_FLIGHT {
            return Err(ConfigError::InvalidInFlightLimit);
        }
        Ok(Self {
            profiles_root,
            max_resident,
            max_in_flight,
            worker: BrowserWorkerConfig::default(),
            worker_capabilities: CapabilitySet::all(),
        })
    }

    pub fn with_worker_config(mut self, worker: BrowserWorkerConfig) -> Self {
        self.worker = worker;
        self
    }

    pub fn with_worker_capabilities(
        mut self,
        capabilities: CapabilitySet,
    ) -> Result<Self, ConfigError> {
        if !capabilities.contains(Capability::L3(L3Capability::Lifecycle)) {
            return Err(ConfigError::LifecycleCapabilityRequired);
        }
        self.worker_capabilities = capabilities;
        Ok(self)
    }

    pub fn profiles_root(&self) -> &Path {
        &self.profiles_root
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdentityRequest {
    id: String,
    class: IdentityClass,
    backend: BrowserBackend,
    device: DevicePersona,
    persona: BrowserPersona,
}

impl IdentityRequest {
    pub fn new(
        id: impl Into<String>,
        class: IdentityClass,
        backend: BrowserBackend,
        device: DevicePersona,
    ) -> Self {
        let persona = match device {
            DevicePersona::DesktopNative => BrowserPersona::desktop_default(),
            DevicePersona::MobileLayout => BrowserPersona::mobile_default(),
        };
        Self {
            id: id.into(),
            class,
            backend,
            device,
            persona,
        }
    }

    pub fn with_persona(
        id: impl Into<String>,
        class: IdentityClass,
        backend: BrowserBackend,
        persona: BrowserPersona,
    ) -> Self {
        let device = match persona.kind() {
            PersonaKind::Desktop => DevicePersona::DesktopNative,
            PersonaKind::Mobile => DevicePersona::MobileLayout,
        };
        Self {
            id: id.into(),
            class,
            backend,
            device,
            persona,
        }
    }

    pub fn public_desktop(id: impl Into<String>) -> Self {
        Self::new(
            id,
            IdentityClass::Public,
            BrowserBackend::Chromium,
            DevicePersona::DesktopNative,
        )
    }

    pub fn public_persona(id: impl Into<String>, persona: BrowserPersona) -> Self {
        Self::with_persona(id, IdentityClass::Public, BrowserBackend::Chromium, persona)
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn persona(&self) -> &BrowserPersona {
        &self.persona
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum BrowserTaskStep {
    Navigate { url: String },
    Wait { duration: Duration },
    Wheel {
        x: f64,
        y: f64,
        delta_x: f64,
        delta_y: f64,
    },
    KeyPress { key: String },
    ClickSelector { selector: String },
    TypeSelector { selector: String, text: String },
    ReadSelectorText { selector: String },
    Evaluate { script: String },
    Capture { policy: CapturePolicy },
}

#[derive(Debug, Clone, PartialEq)]
pub struct BrowserTask {
    steps: Vec<BrowserTaskStep>,
}

impl BrowserTask {
    pub fn new(steps: Vec<BrowserTaskStep>) -> Result<Self, TaskError> {
        if steps.is_empty() || steps.len() > MAX_TASK_STEPS {
            return Err(TaskError::InvalidStepCount);
        }
        let mut total_wait = Duration::ZERO;
        for step in &steps {
            match step {
                BrowserTaskStep::Wait { duration } => {
                    if duration.is_zero() || *duration > MAX_TASK_WAIT {
                        return Err(TaskError::InvalidWait);
                    }
                    total_wait = total_wait
                        .checked_add(*duration)
                        .ok_or(TaskError::InvalidWait)?;
                    if total_wait > MAX_TASK_WAIT {
                        return Err(TaskError::InvalidWait);
                    }
                }
                BrowserTaskStep::ClickSelector { selector }
                | BrowserTaskStep::ReadSelectorText { selector }
                | BrowserTaskStep::TypeSelector { selector, .. } => {
                    ElementRef::new(selector, 0).map_err(|_| TaskError::InvalidSelector)?;
                }
                _ => {}
            }
        }
        Ok(Self { steps })
    }

    pub fn steps(&self) -> &[BrowserTaskStep] {
        &self.steps
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserTaskResult {
    pub replies: Vec<AgentReply>,
    pub step_metrics: Vec<BrowserTaskStepMetrics>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrowserTaskStepMetrics {
    pub completed_at_unix_ms: u64,
    pub duration_ms: u64,
}

const PERSONA_MANIFEST: &str = ".dig2browser-persona-v1";

fn apply_persona(
    worker: &mut BrowserWorkerConfig,
    persona: &BrowserPersona,
) -> Result<(), StationError> {
    worker.stealth.viewport = (u32::from(persona.width()), u32::from(persona.height()));
    worker
        .stealth
        .set_device_scale_factor(persona.device_scale_factor())
        .map_err(|_| StationError::InvalidPersona)?;
    worker.stealth.locale = LocaleProfile {
        locale: persona.locale().to_owned(),
        timezone: persona.timezone().map(str::to_owned),
    };
    worker.stealth.client_hints = match persona.kind() {
        PersonaKind::Desktop => ClientHintsProfile::windows_desktop(),
        PersonaKind::Mobile => ClientHintsProfile::android_mobile(
            persona.platform_version(),
            persona.model(),
        ),
    };
    worker.launch.window_size = worker.stealth.viewport;
    worker.mobile_layout = match persona.kind() {
        PersonaKind::Desktop => None,
        PersonaKind::Mobile => Some(
            MobileLayout::new(
                u32::from(persona.width()),
                u32::from(persona.height()),
                persona.device_scale_factor(),
                persona.max_touch_points(),
            )
            .map_err(|_| StationError::InvalidPersona)?,
        ),
    };
    Ok(())
}

fn bind_persona_contract(
    profile: &IdentityProfile,
    persona: &BrowserPersona,
) -> Result<(), StationError> {
    std::fs::create_dir_all(profile.profile_dir()).map_err(StationError::PersonaIo)?;
    let _owner = ProfileOwnershipGuard::acquire(profile.profile_dir())?;
    let manifest = profile.profile_dir().join(PERSONA_MANIFEST);
    let expected = persona_contract(persona);
    match std::fs::read_to_string(&manifest) {
        Ok(current) if current == expected => return Ok(()),
        Ok(_) => return Err(StationError::PersonaMismatch),
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            return Err(StationError::PersonaIo(error))
        }
        Err(_) => {}
    }
    let has_existing_state = std::fs::read_dir(profile.profile_dir())
        .map_err(StationError::PersonaIo)?
        .filter_map(Result::ok)
        .any(|entry| {
            let name = entry.file_name();
            name != PERSONA_MANIFEST && name != ".dig2browser-profile.lock"
        });
    if has_existing_state && persona != &BrowserPersona::desktop_default() {
        return Err(StationError::PersonaBindingRequired);
    }
    let temporary = profile.profile_dir().join(format!(
        "{PERSONA_MANIFEST}.tmp-{}",
        std::process::id()
    ));
    std::fs::write(&temporary, expected.as_bytes()).map_err(StationError::PersonaIo)?;
    match std::fs::rename(&temporary, &manifest) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = std::fs::remove_file(&temporary);
            match std::fs::read_to_string(&manifest) {
                Ok(current) if current == expected => Ok(()),
                Ok(_) => Err(StationError::PersonaMismatch),
                Err(_) => Err(StationError::PersonaIo(error)),
            }
        }
    }
}

fn persona_contract(persona: &BrowserPersona) -> String {
    let timezone = persona.timezone().unwrap_or_default();
    format!(
        "v1|kind={:?}|viewport={}x{}|dpr={}|touch={}|locale={}:{}|timezone={}:{}|platform={}:{}|model={}:{}",
        persona.kind(),
        persona.width(),
        persona.height(),
        persona.device_scale_milli(),
        persona.max_touch_points(),
        persona.locale().len(),
        persona.locale(),
        timezone.len(),
        timezone,
        persona.platform_version().len(),
        persona.platform_version(),
        persona.model().len(),
        persona.model(),
    )
}

struct Slot {
    worker: BrowserWorker,
    session_gate: Mutex<()>,
    active_leases: AtomicUsize,
    last_used: AtomicU64,
}

struct State {
    slots: HashMap<IdentityRequest, Arc<Slot>>,
}

struct Inner {
    config: StationConfig,
    state: Mutex<State>,
    command_slots: Semaphore,
    operation_gate: RwLock<()>,
    shutting_down: AtomicBool,
    clock: AtomicU64,
    command_waiters: AtomicUsize,
}

/// Cloneable facade over one station-owned browser fleet.
#[derive(Clone)]
pub struct BrowserStation {
    inner: Arc<Inner>,
}

impl BrowserStation {
    pub fn new(config: StationConfig) -> Self {
        Self {
            inner: Arc::new(Inner {
                command_slots: Semaphore::new(config.max_in_flight),
                config,
                state: Mutex::new(State {
                    slots: HashMap::new(),
                }),
                operation_gate: RwLock::new(()),
                shutting_down: AtomicBool::new(false),
                clock: AtomicU64::new(0),
                command_waiters: AtomicUsize::new(0),
            }),
        }
    }

    /// Acquire a capability-bounded lease. A persistent identity is never
    /// exposed as a raw worker handle, so station admission cannot be bypassed.
    pub async fn lease(
        &self,
        identity: IdentityRequest,
        capabilities: CapabilitySet,
    ) -> Result<BrowserLease, StationError> {
        if self.inner.shutting_down.load(Ordering::Acquire) {
            return Err(StationError::ShuttingDown);
        }
        if capabilities
            .iter()
            .any(|capability| !self.inner.config.worker_capabilities.contains(capability))
        {
            return Err(StationError::CapabilityDenied);
        }

        let mut state = self.inner.state.lock().await;
        if self.inner.shutting_down.load(Ordering::Acquire) {
            return Err(StationError::ShuttingDown);
        }
        let now = self.inner.clock.fetch_add(1, Ordering::AcqRel) + 1;
        if state
            .slots
            .keys()
            .any(|existing| existing.id == identity.id && existing != &identity)
        {
            return Err(StationError::PersonaMismatch);
        }
        if let Some(slot) = state.slots.get(&identity).cloned() {
            let ready = match slot.worker.snapshot().lifecycle {
                WorkerLifecycle::Ready => true,
                WorkerLifecycle::Degraded => slot
                    .worker
                    .execute(AgentCommand::Restart)
                    .await
                    .is_ok(),
                WorkerLifecycle::Starting | WorkerLifecycle::Restarting => slot
                    .worker
                    .wait_until_settled()
                    .await
                    .is_ok_and(|snapshot| snapshot.lifecycle == WorkerLifecycle::Ready),
                WorkerLifecycle::ShuttingDown | WorkerLifecycle::Stopped => false,
            };
            if ready {
                slot.active_leases.fetch_add(1, Ordering::AcqRel);
                slot.last_used.store(now, Ordering::Release);
                return Ok(BrowserLease::new(self.clone(), identity, slot, capabilities));
            }
            state.slots.remove(&identity);
            let _ = slot.worker.shutdown().await;
        }

        let mut evicted = None;
        if state.slots.len() >= self.inner.config.max_resident {
            let candidate = state
                .slots
                .iter()
                .filter(|(_, slot)| slot.active_leases.load(Ordering::Acquire) == 0)
                .min_by_key(|(_, slot)| slot.last_used.load(Ordering::Acquire))
                .map(|(key, _)| key.clone());
            let Some(candidate) = candidate else {
                return Err(StationError::AtCapacity);
            };
            evicted = state.slots.remove(&candidate);
        }
        if let Some(slot) = evicted {
            slot.worker.shutdown().await?;
        }

        let profile = IdentityProfile::new(
            &self.inner.config.profiles_root,
            &identity.id,
            identity.class,
            identity.backend,
            identity.device,
        )?;
        bind_persona_contract(&profile, identity.persona())?;
        let mut worker_config = self.inner.config.worker.clone();
        apply_persona(&mut worker_config, identity.persona())?;
        let worker = BrowserWorker::spawn(
            profile,
            self.inner.config.worker_capabilities.clone(),
            worker_config,
        )?;
        let snapshot = worker.wait_until_settled().await?;
        let ready = match snapshot.lifecycle {
            WorkerLifecycle::Ready => true,
            WorkerLifecycle::Degraded => worker
                .execute(AgentCommand::Restart)
                .await
                .is_ok(),
            _ => false,
        };
        if !ready {
            let _ = worker.shutdown().await;
            return Err(StationError::WorkerUnavailable);
        }
        let slot = Arc::new(Slot {
            worker,
            session_gate: Mutex::new(()),
            active_leases: AtomicUsize::new(1),
            last_used: AtomicU64::new(now),
        });
        if self.inner.shutting_down.load(Ordering::Acquire) {
            let _ = slot.worker.shutdown().await;
            return Err(StationError::ShuttingDown);
        }
        state.slots.insert(identity.clone(), Arc::clone(&slot));
        Ok(BrowserLease::new(self.clone(), identity, slot, capabilities))
    }

    pub async fn snapshot(&self) -> StationSnapshot {
        let state = self.inner.state.lock().await;
        let active_leases = state
            .slots
            .values()
            .map(|slot| slot.active_leases.load(Ordering::Acquire))
            .sum();
        StationSnapshot {
            resident: state.slots.len(),
            active_leases,
            shutting_down: self.inner.shutting_down.load(Ordering::Acquire),
            workers: state
                .slots
                .iter()
                .map(|(identity, slot)| (identity.clone(), slot.worker.snapshot()))
                .collect(),
        }
    }

    /// Aggregate fleet status suitable for sanitized operator telemetry. No
    /// identity key, profile path, URL or browser content is returned.
    pub async fn fleet_status(&self) -> StationFleetStatus {
        let state = self.inner.state.lock().await;
        let mut status = StationFleetStatus {
            resident_identities: state.slots.len(),
            active_leases: state
                .slots
                .values()
                .map(|slot| slot.active_leases.load(Ordering::Acquire))
                .sum(),
            command_limit: self.inner.config.max_in_flight,
            command_available: self.inner.command_slots.available_permits(),
            command_waiters: self.inner.command_waiters.load(Ordering::Acquire),
            shutting_down: self.inner.shutting_down.load(Ordering::Acquire),
            ..StationFleetStatus::default()
        };
        for slot in state.slots.values() {
            match slot.worker.snapshot().lifecycle {
                WorkerLifecycle::Starting => status.starting_workers += 1,
                WorkerLifecycle::Ready => status.ready_workers += 1,
                WorkerLifecycle::Degraded => status.degraded_workers += 1,
                WorkerLifecycle::Restarting => status.restarting_workers += 1,
                WorkerLifecycle::ShuttingDown => status.shutting_down_workers += 1,
                WorkerLifecycle::Stopped => status.stopped_workers += 1,
            }
        }
        status
    }

    /// Stop admission, drain in-flight commands, close every runtime and return
    /// only after each worker actor has dropped its runtime and process handles.
    pub async fn shutdown(&self) -> Result<ShutdownReport, StationError> {
        if self.inner.shutting_down.swap(true, Ordering::AcqRel) {
            return Err(StationError::ShuttingDown);
        }
        let _drained = self.inner.operation_gate.write().await;
        let workers = {
            let mut state = self.inner.state.lock().await;
            state
                .slots
                .drain()
                .map(|(_, slot)| slot.worker.clone())
                .collect::<Vec<_>>()
        };
        let mut stopped = 0;
        let mut failed = 0;
        for worker in workers {
            match worker.shutdown().await {
                Ok(()) => stopped += 1,
                Err(_) => failed += 1,
            }
        }
        if failed > 0 {
            return Err(StationError::ShutdownIncomplete { stopped, failed });
        }
        Ok(ShutdownReport { stopped })
    }
}

pub struct BrowserLease {
    station: BrowserStation,
    identity: IdentityRequest,
    slot: Arc<Slot>,
    capabilities: CapabilitySet,
}

impl BrowserLease {
    fn new(
        station: BrowserStation,
        identity: IdentityRequest,
        slot: Arc<Slot>,
        capabilities: CapabilitySet,
    ) -> Self {
        Self {
            station,
            identity,
            slot,
            capabilities,
        }
    }

    pub fn identity(&self) -> &IdentityRequest {
        &self.identity
    }

    pub fn snapshot(&self) -> BrowserSnapshot {
        self.slot.worker.snapshot()
    }

    pub async fn execute(&self, command: AgentCommand) -> Result<AgentReply, StationError> {
        if matches!(command, AgentCommand::Shutdown) {
            return Err(StationError::DirectShutdownDenied);
        }
        if !self.capabilities.contains(command.required_capability()) {
            return Err(StationError::CapabilityDenied);
        }
        let _operation = self.station.inner.operation_gate.read().await;
        if self.station.inner.shutting_down.load(Ordering::Acquire) {
            return Err(StationError::ShuttingDown);
        }
        let _session = self.slot.session_gate.lock().await;
        let waiter = CommandWaiter::new(&self.station.inner.command_waiters);
        let _command = self
            .station
            .inner
            .command_slots
            .acquire()
            .await
            .map_err(|_| StationError::ShuttingDown)?;
        drop(waiter);
        let now = self.station.inner.clock.fetch_add(1, Ordering::AcqRel) + 1;
        self.slot.last_used.store(now, Ordering::Release);
        self.slot.worker.execute(command).await.map_err(Into::into)
    }

    /// Navigate and capture under one per-identity session lock so concurrent
    /// consumers cannot interleave page state between the two commands.
    pub async fn navigate_and_capture(
        &self,
        url: impl Into<String>,
        policy: CapturePolicy,
    ) -> Result<CaptureArtifact, StationError> {
        let navigate = AgentCommand::Navigate { url: url.into() };
        let capture = AgentCommand::Capture { policy };
        if !self.capabilities.contains(navigate.required_capability())
            || !self.capabilities.contains(capture.required_capability())
        {
            return Err(StationError::CapabilityDenied);
        }
        let _operation = self.station.inner.operation_gate.read().await;
        if self.station.inner.shutting_down.load(Ordering::Acquire) {
            return Err(StationError::ShuttingDown);
        }
        let _session = self.slot.session_gate.lock().await;
        let waiter = CommandWaiter::new(&self.station.inner.command_waiters);
        let _command = self
            .station
            .inner
            .command_slots
            .acquire()
            .await
            .map_err(|_| StationError::ShuttingDown)?;
        drop(waiter);
        self.slot.worker.execute(navigate).await?;
        let reply = self.slot.worker.execute(capture).await?;
        let AgentReply::Capture(artifact) = reply else {
            return Err(StationError::InvalidWorkerReply);
        };
        let now = self.station.inner.clock.fetch_add(1, Ordering::AcqRel) + 1;
        self.slot.last_used.store(now, Ordering::Release);
        Ok(artifact)
    }

    /// Execute a bounded multi-step task under one identity session and one
    /// global command slot. Other consumers cannot interleave page mutations
    /// between navigation, interaction, extraction, and capture.
    pub async fn run_task(&self, task: &BrowserTask) -> Result<BrowserTaskResult, StationError> {
        self.validate_task_capabilities(task)?;
        let _operation = self.station.inner.operation_gate.read().await;
        if self.station.inner.shutting_down.load(Ordering::Acquire) {
            return Err(StationError::ShuttingDown);
        }
        let _session = self.slot.session_gate.lock().await;
        let waiter = CommandWaiter::new(&self.station.inner.command_waiters);
        let _command = self
            .station
            .inner
            .command_slots
            .acquire()
            .await
            .map_err(|_| StationError::ShuttingDown)?;
        drop(waiter);

        let mut replies = Vec::with_capacity(task.steps().len());
        let mut step_metrics = Vec::with_capacity(task.steps().len());
        for (index, step) in task.steps().iter().enumerate() {
            let started = Instant::now();
            let first_attempt = self.execute_task_step(step).await;
            let reply = match first_attempt {
                Ok(reply) => reply,
                Err(error)
                    if index == 0
                        && matches!(step, BrowserTaskStep::Navigate { .. })
                        && is_navigation_error(&error) =>
                {
                    self.slot
                        .worker
                        .execute(AgentCommand::Restart)
                        .await
                        .map_err(|source| StationError::TaskStepFailed {
                            index,
                            source: Box::new(StationError::from(source)),
                        })?;
                    self.execute_task_step(step)
                        .await
                        .map_err(|source| StationError::TaskStepFailed {
                            index,
                            source: Box::new(source),
                        })?
                }
                Err(source) => {
                    return Err(StationError::TaskStepFailed {
                        index,
                        source: Box::new(source),
                    })
                }
            };
            replies.push(reply);
            step_metrics.push(BrowserTaskStepMetrics {
                completed_at_unix_ms: unix_time_ms(),
                duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            });
        }
        let now = self.station.inner.clock.fetch_add(1, Ordering::AcqRel) + 1;
        self.slot.last_used.store(now, Ordering::Release);
        Ok(BrowserTaskResult {
            replies,
            step_metrics,
        })
    }

    async fn execute_task_step(
        &self,
        step: &BrowserTaskStep,
    ) -> Result<AgentReply, StationError> {
        match step {
            BrowserTaskStep::Navigate { url } => self
                .slot
                .worker
                .execute(AgentCommand::Navigate { url: url.clone() })
                .await
                .map_err(StationError::from),
            BrowserTaskStep::Wait { duration } => {
                tokio::time::sleep(*duration).await;
                Ok(AgentReply::Acknowledged)
            }
            BrowserTaskStep::Wheel {
                x,
                y,
                delta_x,
                delta_y,
            } => self
                .slot
                .worker
                .execute(AgentCommand::Wheel {
                    x: *x,
                    y: *y,
                    delta_x: *delta_x,
                    delta_y: *delta_y,
                })
                .await
                .map_err(StationError::from),
            BrowserTaskStep::KeyPress { key } => self
                .slot
                .worker
                .execute(AgentCommand::KeyPress { key: key.clone() })
                .await
                .map_err(StationError::from),
            BrowserTaskStep::ClickSelector { selector } => {
                let element = self.resolve_task_element(selector).await?;
                self.slot
                    .worker
                    .execute(AgentCommand::ClickElement { element })
                    .await
                    .map_err(StationError::from)
            }
            BrowserTaskStep::TypeSelector { selector, text } => {
                let element = self.resolve_task_element(selector).await?;
                self.slot
                    .worker
                    .execute(AgentCommand::TypeElement {
                        element,
                        text: text.clone(),
                    })
                    .await
                    .map_err(StationError::from)
            }
            BrowserTaskStep::ReadSelectorText { selector } => {
                let element = self.resolve_task_element(selector).await?;
                self.slot
                    .worker
                    .execute(AgentCommand::ReadElementText { element })
                    .await
                    .map_err(StationError::from)
            }
            BrowserTaskStep::Evaluate { script } => self
                .slot
                .worker
                .execute(AgentCommand::Evaluate {
                    script: script.clone(),
                })
                .await
                .map_err(StationError::from),
            BrowserTaskStep::Capture { policy } => self
                .slot
                .worker
                .execute(AgentCommand::Capture { policy: *policy })
                .await
                .map_err(StationError::from),
        }
    }

    async fn resolve_task_element(&self, selector: &str) -> Result<ElementRef, StationError> {
        let reply = self
            .slot
            .worker
            .execute(AgentCommand::ResolveElement {
                selector: selector.to_owned(),
            })
            .await?;
        let AgentReply::Element(element) = reply else {
            return Err(StationError::InvalidWorkerReply);
        };
        Ok(element)
    }

    fn validate_task_capabilities(&self, task: &BrowserTask) -> Result<(), StationError> {
        for step in task.steps() {
            let required: &[Capability] = match step {
                BrowserTaskStep::Navigate { .. } => {
                    &[Capability::L3(L3Capability::Navigate)]
                }
                BrowserTaskStep::Wait { .. } => &[],
                BrowserTaskStep::Wheel { .. } => {
                    &[Capability::L1(L1Capability::Scroll)]
                }
                BrowserTaskStep::KeyPress { .. } => {
                    &[Capability::L1(L1Capability::Keyboard)]
                }
                BrowserTaskStep::ClickSelector { .. }
                | BrowserTaskStep::TypeSelector { .. } => &[
                    Capability::L2(L2Capability::Inspect),
                    Capability::L2(L2Capability::Interact),
                ],
                BrowserTaskStep::ReadSelectorText { .. } => {
                    &[Capability::L2(L2Capability::Inspect)]
                }
                BrowserTaskStep::Evaluate { .. } => {
                    &[Capability::L2(L2Capability::Evaluate)]
                }
                BrowserTaskStep::Capture { .. } => {
                    &[Capability::L3(L3Capability::Capture)]
                }
            };
            if required
                .iter()
                .any(|capability| !self.capabilities.contains(*capability))
            {
                return Err(StationError::CapabilityDenied);
            }
        }
        Ok(())
    }
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .unwrap_or(0)
}

fn is_navigation_error(error: &StationError) -> bool {
    matches!(
        error,
        StationError::Worker(WorkerError::Runtime(runtime))
            if runtime.kind() == RuntimeFailureKind::Navigation
    )
}

struct CommandWaiter<'a> {
    count: &'a AtomicUsize,
}

impl<'a> CommandWaiter<'a> {
    fn new(count: &'a AtomicUsize) -> Self {
        count.fetch_add(1, Ordering::AcqRel);
        Self { count }
    }
}

impl Drop for CommandWaiter<'_> {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Clone for BrowserLease {
    fn clone(&self) -> Self {
        self.slot.active_leases.fetch_add(1, Ordering::AcqRel);
        Self {
            station: self.station.clone(),
            identity: self.identity.clone(),
            slot: Arc::clone(&self.slot),
            capabilities: self.capabilities.clone(),
        }
    }
}

impl Drop for BrowserLease {
    fn drop(&mut self) {
        self.slot.active_leases.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Debug, Clone)]
pub struct StationSnapshot {
    pub resident: usize,
    pub active_leases: usize,
    pub shutting_down: bool,
    pub workers: Vec<(IdentityRequest, BrowserSnapshot)>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StationFleetStatus {
    pub shutting_down: bool,
    pub resident_identities: usize,
    pub starting_workers: usize,
    pub ready_workers: usize,
    pub degraded_workers: usize,
    pub restarting_workers: usize,
    pub shutting_down_workers: usize,
    pub stopped_workers: usize,
    pub active_leases: usize,
    pub command_limit: usize,
    pub command_available: usize,
    pub command_waiters: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShutdownReport {
    pub stopped: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum ProfilesRootError {
    #[error("profiles root must be absolute")]
    NotAbsolute,
    #[error("profiles root must be a directory")]
    NotDirectory,
    #[error("profiles root is already owned by another station")]
    AlreadyOwned,
    #[error("profiles root I/O failed")]
    Io(#[source] std::io::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TaskError {
    #[error("browser task must contain 1 to 64 steps")]
    InvalidStepCount,
    #[error("browser task wait budget is invalid")]
    InvalidWait,
    #[error("browser task selector is invalid")]
    InvalidSelector,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("profiles root must be absolute")]
    ProfilesRootNotAbsolute,
    #[error("resident browser limit is invalid")]
    InvalidResidentLimit,
    #[error("in-flight command limit is invalid")]
    InvalidInFlightLimit,
    #[error("worker capabilities must include lifecycle control")]
    LifecycleCapabilityRequired,
}

#[derive(Debug, thiserror::Error)]
pub enum StationError {
    #[error("station is shutting down")]
    ShuttingDown,
    #[error("requested capability is denied")]
    CapabilityDenied,
    #[error("station-owned workers cannot be shut down through a consumer lease")]
    DirectShutdownDenied,
    #[error("all resident browser slots are leased")]
    AtCapacity,
    #[error("browser worker did not become ready")]
    WorkerUnavailable,
    #[error("browser profile is bound to a different persona")]
    PersonaMismatch,
    #[error("existing profile must be bound as desktop before persona migration")]
    PersonaBindingRequired,
    #[error("browser persona is invalid")]
    InvalidPersona,
    #[error("browser persona manifest I/O failed")]
    PersonaIo(#[source] std::io::Error),
    #[error("browser worker returned an invalid reply")]
    InvalidWorkerReply,
    #[error("browser task step {index} failed")]
    TaskStepFailed {
        index: usize,
        #[source]
        source: Box<StationError>,
    },
    #[error("station shutdown incomplete: {stopped} stopped, {failed} failed")]
    ShutdownIncomplete { stopped: usize, failed: usize },
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error(transparent)]
    Worker(#[from] WorkerError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig2browser::agentic::{Capability, L3Capability};

    #[test]
    fn rejects_relative_profile_root_and_zero_limits() {
        assert!(matches!(
            StationConfig::new("profiles", 1, 1),
            Err(ConfigError::ProfilesRootNotAbsolute)
        ));
        let root = std::env::temp_dir();
        assert!(matches!(
            StationConfig::new(&root, 0, 1),
            Err(ConfigError::InvalidResidentLimit)
        ));
        assert!(matches!(
            StationConfig::new(&root, 1, 0),
            Err(ConfigError::InvalidInFlightLimit)
        ));
    }

    #[test]
    fn station_requires_lifecycle_control() {
        let capabilities = CapabilitySet::new([Capability::L3(L3Capability::Navigate)])
            .expect("valid capability set");
        let config = StationConfig::new(std::env::temp_dir(), 1, 1)
            .expect("valid station config");
        assert!(matches!(
            config.with_worker_capabilities(capabilities),
            Err(ConfigError::LifecycleCapabilityRequired)
        ));
    }

    #[test]
    fn profiles_root_has_one_crash_releasing_owner() {
        let root = std::env::temp_dir().join(format!(
            "dig2browser-station-root-test-{}",
            uuid::Uuid::new_v4()
        ));
        let first = ProfilesRootOwnership::acquire(&root).expect("acquire profiles root");
        assert!(first.root().is_absolute());
        assert!(matches!(
            ProfilesRootOwnership::acquire(&root),
            Err(ProfilesRootError::AlreadyOwned)
        ));
        drop(first);
        let successor =
            ProfilesRootOwnership::acquire(&root).expect("successor acquires profiles root");
        drop(successor);
        std::fs::remove_dir_all(root).expect("remove profiles root fixture");
    }
}
