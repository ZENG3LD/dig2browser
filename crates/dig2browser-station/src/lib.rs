//! Stateful resource owner for `dig2browser` consumers.
//!
//! `dig2browser` owns protocols and one browser runtime. This crate owns reuse,
//! admission, leases, capacity and coordinated final shutdown. Product-specific
//! crawling, monitoring schedules and evidence storage stay in consumers.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use dig2browser::agentic::{
    AgentCommand, AgentReply, BrowserSnapshot, BrowserWorker, BrowserWorkerConfig,
    Capability, CapabilitySet, CaptureArtifact, CapturePolicy, L3Capability, WorkerError,
    WorkerLifecycle,
};
use dig2browser::identity::{
    BrowserBackend, DevicePersona, IdentityClass, IdentityError, IdentityProfile,
};
use tokio::sync::{Mutex, RwLock, Semaphore};

pub mod ipc;

const MAX_RESIDENT: usize = 256;
const MAX_IN_FLIGHT: usize = 4_096;

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
}

impl IdentityRequest {
    pub fn new(
        id: impl Into<String>,
        class: IdentityClass,
        backend: BrowserBackend,
        device: DevicePersona,
    ) -> Self {
        Self {
            id: id.into(),
            class,
            backend,
            device,
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

    pub fn id(&self) -> &str {
        &self.id
    }
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
        let worker = BrowserWorker::spawn(
            profile,
            self.inner.config.worker_capabilities.clone(),
            self.inner.config.worker.clone(),
        )?;
        let snapshot = worker.wait_until_settled().await?;
        if snapshot.lifecycle != WorkerLifecycle::Ready {
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
    #[error("browser worker returned an invalid reply")]
    InvalidWorkerReply,
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
}
