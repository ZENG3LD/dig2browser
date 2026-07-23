//! Stateful resource owner for `dig2browser` consumers.
//!
//! `dig2browser` owns protocols and one browser runtime. This crate owns reuse,
//! admission, leases, capacity, reusable bounded crawling and coordinated final
//! shutdown. Product-specific discovery policy, monitoring schedules and case
//! publication stay in consumers.

use std::collections::HashMap;
#[cfg(windows)]
use std::ffi::OsString;
use std::io::Write;
#[cfg(windows)]
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dig2browser::agentic::{
    AgentCommand, AgentReply, BrowserSnapshot, BrowserWorker, BrowserWorkerConfig,
    Capability, CapabilitySet, CaptureArtifact, CapturePolicy, CookieSpec, ElementRef,
    L1Capability, L2Capability, L3Capability, MobileLayout, NavigationPolicy,
    RuntimeFailureKind, WorkerError, WorkerLifecycle,
};
use dig2browser::browser::PageDevTools;
use dig2browser::identity::{
    validate_profile_id, BrowserBackend, DevicePersona, IdentityClass,
    IdentityError, IdentityProfile, ProfileOwnershipGuard,
};
use dig2browser::stealth::{ClientHintsProfile, LocaleProfile};
use dig2browser::BrowserProcessIsolation;
use dig2browser_protocol::{
    BrowserPersona, IdentitySessionStatus, PersonaKind, ProfileClass,
    SessionHealthProbe, SessionPhase, SessionStateUpdate,
};
use dig2browser_core::{
    ControlTransport, EngineFamily, PersonaPreset, RouteRef, RuntimeFeature,
    RuntimeRequirementsError,
};
use tokio::sync::{Mutex, RwLock, Semaphore};

use route::PreparedRoute;

mod collection;
pub mod containment;
mod crawl;
mod egress;
pub mod ipc;
mod live;
mod route;
pub mod runtime;
mod session_import;
#[cfg(windows)]
mod windows_containment;
#[cfg(windows)]
pub mod windows_wfp_broker;

pub use dig2browser_core::{
    ResolvedRuntime, RuntimeKind, RuntimeRequirements, RuntimeSelector,
};
pub use collection::CollectionError;
pub use crawl::CrawlError;
pub use egress::{
    EgressError, EgressPeerPolicy, EgressPeerPolicyError, EgressProxy,
    EgressReport,
};
pub use live::LiveError;
pub use route::{
    EgressRouteError, RouteDescriptor, RouteRegistry, RouteRegistryError,
    RouteTransport,
};
pub use runtime::{RuntimeFactory, RuntimeRegistry, RuntimeRegistryError};

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
        let canonical_root = std::fs::canonicalize(root).map_err(ProfilesRootError::Io)?;
        if !canonical_root
            .metadata()
            .map_err(ProfilesRootError::Io)?
            .is_dir()
        {
            return Err(ProfilesRootError::NotDirectory);
        }
        let guard = match ProfileOwnershipGuard::acquire(&canonical_root) {
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
            root: child_process_compatible_path(canonical_root),
            _guard: guard,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

#[cfg(windows)]
fn child_process_compatible_path(path: PathBuf) -> PathBuf {
    const VERBATIM_PREFIX: [u16; 4] = [b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16];
    const VERBATIM_UNC_PREFIX: [u16; 8] = [
        b'\\' as u16,
        b'\\' as u16,
        b'?' as u16,
        b'\\' as u16,
        b'U' as u16,
        b'N' as u16,
        b'C' as u16,
        b'\\' as u16,
    ];

    let encoded = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if encoded.starts_with(&VERBATIM_UNC_PREFIX) {
        let mut compatible = Vec::with_capacity(encoded.len().saturating_sub(6));
        compatible.extend_from_slice(&[b'\\' as u16, b'\\' as u16]);
        compatible.extend_from_slice(&encoded[VERBATIM_UNC_PREFIX.len()..]);
        return PathBuf::from(OsString::from_wide(&compatible));
    }
    if encoded.starts_with(&VERBATIM_PREFIX)
        && encoded.len() >= 7
        && encoded[5] == b':' as u16
        && matches!(encoded[6], value if value == b'\\' as u16 || value == b'/' as u16)
    {
        return PathBuf::from(OsString::from_wide(&encoded[VERBATIM_PREFIX.len()..]));
    }
    path
}

#[cfg(not(windows))]
fn child_process_compatible_path(path: PathBuf) -> PathBuf {
    path
}

#[derive(Debug, Clone)]
pub struct StationConfig {
    profiles_root: PathBuf,
    max_resident: usize,
    max_in_flight: usize,
    worker: BrowserWorkerConfig,
    worker_capabilities: CapabilitySet,
    runtime_selector: RuntimeSelector,
    runtime_registry: RuntimeRegistry,
    route_registry: RouteRegistry,
    navigation_policy: NavigationPolicy,
    process_isolation: BrowserProcessIsolation,
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
            runtime_selector: RuntimeSelector::Auto,
            runtime_registry: RuntimeRegistry::default(),
            route_registry: RouteRegistry::default(),
            navigation_policy: NavigationPolicy::default(),
            process_isolation: BrowserProcessIsolation::Native,
        })
    }

    pub fn with_worker_config(mut self, worker: BrowserWorkerConfig) -> Self {
        self.worker = worker;
        self
    }

    pub fn with_runtime_selector(mut self, selector: RuntimeSelector) -> Self {
        self.runtime_selector = selector;
        self
    }

    pub fn with_runtime_registry(mut self, registry: RuntimeRegistry) -> Self {
        self.runtime_registry = registry;
        self
    }

    pub fn with_route_registry(mut self, registry: RouteRegistry) -> Self {
        self.route_registry = registry;
        self
    }

    pub fn with_navigation_policy(mut self, policy: NavigationPolicy) -> Self {
        self.navigation_policy = policy;
        self
    }

    pub fn with_process_isolation(mut self, isolation: BrowserProcessIsolation) -> Self {
        self.process_isolation = isolation;
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

    pub fn navigation_policy(&self) -> &NavigationPolicy {
        &self.navigation_policy
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

    pub fn authenticated_persona(id: impl Into<String>, persona: BrowserPersona) -> Self {
        Self::with_persona(
            id,
            IdentityClass::Authenticated,
            BrowserBackend::Chromium,
            persona,
        )
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn persona(&self) -> &BrowserPersona {
        &self.persona
    }

    pub fn class(&self) -> IdentityClass {
        self.class
    }

    fn bind_runtime_backend(mut self, runtime: RuntimeKind) -> Result<Self, StationError> {
        self.backend = match runtime {
            RuntimeKind::Chrome | RuntimeKind::Edge => BrowserBackend::Chromium,
            RuntimeKind::Firefox => BrowserBackend::Firefox,
            RuntimeKind::Lightweight => BrowserBackend::Lightweight,
            unsupported => return Err(StationError::RuntimeBackendUnsupported(unsupported)),
        };
        Ok(self)
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
    WaitForSelector { selector: String, timeout: Duration },
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
                BrowserTaskStep::WaitForSelector { selector, timeout } => {
                    ElementRef::new(selector, 0).map_err(|_| TaskError::InvalidSelector)?;
                    if timeout.is_zero() || *timeout > MAX_TASK_WAIT {
                        return Err(TaskError::InvalidWait);
                    }
                    total_wait = total_wait
                        .checked_add(*timeout)
                        .ok_or(TaskError::InvalidWait)?;
                    if total_wait > MAX_TASK_WAIT {
                        return Err(TaskError::InvalidWait);
                    }
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
const PROFILE_CLASS_MANIFEST: &str = ".dig2browser-profile-class-v1";
const PROFILE_BINDING_MANIFEST: &str = ".dig2browser-profile-binding-v2";
const SESSION_STATE_JOURNAL: &str = ".dig2browser-session-state-v1";

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
    worker.stealth.hardware_concurrency = u32::from(persona.hardware_concurrency());
    worker.stealth.device_memory_gb = u32::from(persona.device_memory_gb());
    worker.stealth.webgl_vendor = persona.webgl_vendor().to_owned();
    worker.stealth.webgl_renderer = persona.webgl_renderer().to_owned();
    worker.stealth.max_touch_points = persona.max_touch_points();
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

fn runtime_requirements(
    capabilities: &CapabilitySet,
    persona: &BrowserPersona,
    headful_authentication: bool,
) -> Result<RuntimeRequirements, RuntimeRequirementsError> {
    let mut features = Vec::new();
    for capability in capabilities.iter() {
        match capability {
            Capability::L1(L1Capability::Pointer) => {
                features.push(RuntimeFeature::PointerInput)
            }
            Capability::L1(L1Capability::Keyboard) => {
                features.push(RuntimeFeature::KeyboardInput)
            }
            Capability::L1(L1Capability::Scroll) => {
                features.push(RuntimeFeature::ScrollInput)
            }
            Capability::L2(L2Capability::Inspect) => {
                features.push(RuntimeFeature::DomInspect)
            }
            Capability::L2(L2Capability::Interact) => {
                features.push(RuntimeFeature::DomInteract)
            }
            Capability::L2(L2Capability::Evaluate) => {
                features.push(RuntimeFeature::ScriptEvaluate)
            }
            Capability::L3(L3Capability::Navigate) => {
                features.push(RuntimeFeature::Navigate)
            }
            Capability::L3(L3Capability::Capture) => {
                features.push(RuntimeFeature::CaptureState);
                features.push(RuntimeFeature::CaptureHtml);
                features.push(RuntimeFeature::CaptureViewportPng);
            }
            Capability::L3(L3Capability::Lifecycle) => {
                features.push(RuntimeFeature::Lifecycle)
            }
        }
    }
    features.push(match persona.kind() {
        PersonaKind::Desktop => RuntimeFeature::DesktopWeb,
        PersonaKind::Mobile => RuntimeFeature::MobileWebEmulation,
    });
    if headful_authentication {
        features.push(RuntimeFeature::HeadfulAuthentication);
    }
    RuntimeRequirements::new(features, false)
}

fn task_runtime_requirements(
    task: &BrowserTask,
) -> Result<RuntimeRequirements, RuntimeRequirementsError> {
    let mut features = vec![RuntimeFeature::Lifecycle];
    let mut add = |feature| {
        if !features.contains(&feature) {
            features.push(feature);
        }
    };
    for step in task.steps() {
        match step {
            BrowserTaskStep::Navigate { .. } => add(RuntimeFeature::Navigate),
            BrowserTaskStep::Wait { .. } => {}
            BrowserTaskStep::Wheel { .. } => add(RuntimeFeature::ScrollInput),
            BrowserTaskStep::KeyPress { .. } => add(RuntimeFeature::KeyboardInput),
            BrowserTaskStep::ClickSelector { .. }
            | BrowserTaskStep::TypeSelector { .. } => {
                add(RuntimeFeature::DomInspect);
                add(RuntimeFeature::DomInteract);
            }
            BrowserTaskStep::ReadSelectorText { .. } => {
                add(RuntimeFeature::DomInspect)
            }
            BrowserTaskStep::WaitForSelector { .. } => {
                add(RuntimeFeature::DomInspect)
            }
            BrowserTaskStep::Evaluate { .. } => add(RuntimeFeature::ScriptEvaluate),
            BrowserTaskStep::Capture { policy } => {
                add(RuntimeFeature::CaptureState);
                match policy {
                    CapturePolicy::StateOnly => {}
                    CapturePolicy::HtmlOnly => add(RuntimeFeature::CaptureHtml),
                    CapturePolicy::EvidenceViewport => {
                        add(RuntimeFeature::CaptureHtml);
                        add(RuntimeFeature::CaptureViewportPng);
                    }
                }
            }
        }
    }
    RuntimeRequirements::new(features, false)
}

fn persona_runtime_requirements(
    persona: &BrowserPersona,
) -> Result<RuntimeRequirements, RuntimeRequirementsError> {
    match persona.kind() {
        PersonaKind::Desktop => {
            RuntimeRequirements::new(vec![RuntimeFeature::DesktopWeb], true)
        }
        PersonaKind::Mobile => RuntimeRequirements::new(
            vec![RuntimeFeature::MobileWebEmulation],
            false,
        ),
    }
}

fn authenticated_identity_runtime_requirements(
    identity: &IdentityRequest,
) -> Result<Option<RuntimeRequirements>, RuntimeRequirementsError> {
    match identity.class() {
        IdentityClass::Public => Ok(None),
        IdentityClass::Authenticated => RuntimeRequirements::new(
            vec![RuntimeFeature::PersistentProfile],
            false,
        )
        .map(Some),
    }
}

fn constrained_runtime_selector(
    configured: RuntimeSelector,
    requested: RuntimeSelector,
) -> Result<RuntimeSelector, StationError> {
    match (configured, requested) {
        (RuntimeSelector::Auto, requested) => Ok(requested),
        (configured @ RuntimeSelector::Exact(_), RuntimeSelector::Auto) => Ok(configured),
        (RuntimeSelector::Exact(configured), RuntimeSelector::Exact(requested))
            if configured == requested =>
        {
            Ok(RuntimeSelector::Exact(configured))
        }
        (RuntimeSelector::Exact(configured), RuntimeSelector::Exact(requested)) => {
            Err(StationError::RuntimeSelectionDenied {
                configured,
                requested,
            })
        }
    }
}

fn persona_constrained_runtime_selector(
    configured: RuntimeSelector,
    requested: RuntimeSelector,
    persona: &BrowserPersona,
) -> Result<RuntimeSelector, StationError> {
    let selected = constrained_runtime_selector(configured, requested)?;
    match persona
        .preset()
        .and_then(|preset| preset.required_runtime())
    {
        Some(kind) => constrained_runtime_selector(selected, RuntimeSelector::Exact(kind)),
        None => Ok(selected),
    }
}

fn prepare_persona_route(
    config: &StationConfig,
    persona: &BrowserPersona,
) -> Result<Option<PreparedRoute>, StationError> {
    let default_reference = RouteRef::host_direct();
    let reference = match persona.route_ref() {
        Some(reference) => reference,
        None if config.navigation_policy.is_exact() => &default_reference,
        None => return Ok(None),
    };
    config
        .route_registry
        .prepare(reference, &config.worker)
        .map(Some)
        .map_err(StationError::from)
}

fn validate_persona_runtime(
    persona: &BrowserPersona,
    runtime: &ResolvedRuntime,
) -> Result<(), StationError> {
    if persona
        .preset()
        .is_some_and(|preset| !preset.supports_runtime(runtime.kind()))
    {
        return Err(StationError::PersonaRuntimeMismatch);
    }
    Ok(())
}

fn bind_identity_contract(
    profile: &IdentityProfile,
    persona: &BrowserPersona,
    runtime: &ResolvedRuntime,
) -> Result<(), StationError> {
    std::fs::create_dir_all(profile.profile_dir()).map_err(StationError::PersonaIo)?;
    let _owner = ProfileOwnershipGuard::acquire(profile.profile_dir())?;
    let persona_manifest = profile.profile_dir().join(PERSONA_MANIFEST);
    let class_manifest = profile.profile_dir().join(PROFILE_CLASS_MANIFEST);
    let binding_manifest = profile.profile_dir().join(PROFILE_BINDING_MANIFEST);
    let persona_current = read_optional_manifest(&persona_manifest)?;
    let class_current = read_optional_manifest(&class_manifest)?;
    let binding_current = read_optional_manifest(&binding_manifest)?;
    let has_existing_state = std::fs::read_dir(profile.profile_dir())
        .map_err(StationError::PersonaIo)?
        .filter_map(Result::ok)
        .any(|entry| {
            let name = entry.file_name();
            name != PERSONA_MANIFEST
                && name != PROFILE_CLASS_MANIFEST
                && name != PROFILE_BINDING_MANIFEST
                && name != SESSION_STATE_JOURNAL
                && name != ".dig2browser-profile.lock"
        });

    match (persona.preset(), persona.route_ref()) {
        (Some(_), Some(_)) => {
            validate_persona_runtime(persona, runtime)?;
            let expected_binding = profile_binding_contract(profile, persona, runtime)?;
            match binding_current.as_deref() {
                Some(current) if current == expected_binding => {}
                Some(_) => return Err(StationError::ProfileBindingMismatch),
                None if persona_current.is_some()
                    || class_current.is_some()
                    || has_existing_state =>
                {
                    return Err(StationError::ProfileBindingRequired)
                }
                None => write_once_manifest(&binding_manifest, &expected_binding)?,
            }
        }
        (None, None) if binding_current.is_none() => {}
        (None, None) => return Err(StationError::ProfileBindingMismatch),
        _ => return Err(StationError::InvalidPersona),
    }

    let expected_persona = persona_contract(persona);
    let persona_existed = match persona_current {
        Some(current) if current == expected_persona => true,
        Some(_) => return Err(StationError::PersonaMismatch),
        None => false,
    };
    let expected_class = identity_class_contract(profile.class());
    match class_current {
        Some(current) if current == expected_class => Ok(()),
        Some(_) => Err(StationError::IdentityClassMismatch),
        None => {
            if (persona_existed || has_existing_state)
                && profile.class() != IdentityClass::Public
            {
                return Err(StationError::IdentityClassBindingRequired);
            }
            write_once_manifest(&class_manifest, expected_class)
        }
    }?;

    if !persona_existed {
        if has_existing_state && persona != &BrowserPersona::desktop_default() {
            return Err(StationError::PersonaBindingRequired);
        }
        write_once_manifest(&persona_manifest, &expected_persona)?;
    }
    Ok(())
}

fn read_optional_manifest(path: &Path) -> Result<Option<String>, StationError> {
    match std::fs::read_to_string(path) {
        Ok(current) => Ok(Some(current)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(StationError::PersonaIo(error)),
    }
}

fn write_once_manifest(path: &Path, expected: &str) -> Result<(), StationError> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(StationError::InvalidPersona)?;
    let temporary = path.with_file_name(format!("{file_name}.tmp-{}", std::process::id()));
    std::fs::write(&temporary, expected.as_bytes()).map_err(StationError::PersonaIo)?;
    match std::fs::rename(&temporary, path) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = std::fs::remove_file(&temporary);
            match std::fs::read_to_string(path) {
                Ok(current) if current == expected => Ok(()),
                Ok(_) => Err(StationError::PersonaMismatch),
                Err(_) => Err(StationError::PersonaIo(error)),
            }
        }
    }
}

fn identity_class_contract(class: IdentityClass) -> &'static str {
    match class {
        IdentityClass::Public => "Public",
        IdentityClass::Authenticated => "Authenticated",
    }
}

fn persona_contract(persona: &BrowserPersona) -> String {
    let timezone = persona.timezone().unwrap_or_default();
    let surface = format!(
        "kind={:?}|viewport={}x{}|dpr={}|touch={}|locale={}:{}|timezone={}:{}|platform={}:{}|model={}:{}",
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
    );
    match (persona.preset(), persona.route_ref()) {
        (Some(preset), Some(route)) => format!(
            "v2|preset={}|route={}:{}|{surface}",
            preset.as_str(),
            route.as_str().len(),
            route.as_str(),
        ),
        _ => format!("v1|{surface}"),
    }
}

fn profile_binding_contract(
    profile: &IdentityProfile,
    persona: &BrowserPersona,
    runtime: &ResolvedRuntime,
) -> Result<String, StationError> {
    let preset = persona.preset().ok_or(StationError::InvalidPersona)?;
    let route = persona.route_ref().ok_or(StationError::InvalidPersona)?;
    let persona = persona_contract(persona);
    Ok(format!(
        "v2|preset={}|runtime={:?}|class={}|route={}:{}|persona={}:{}",
        preset.as_str(),
        runtime.kind(),
        identity_class_contract(profile.class()),
        route.as_str().len(),
        route.as_str(),
        persona.len(),
        persona,
    ))
}

fn compiled_persona_metadata(contract: &str) -> Option<(PersonaPreset, &str)> {
    let contract = contract.strip_prefix("v2|preset=")?;
    let (preset_name, contract) = contract.split_once("|route=")?;
    let preset = PersonaPreset::ALL
        .into_iter()
        .find(|candidate| candidate.as_str() == preset_name)?;
    let (route_field, surface) = contract.split_once("|kind=")?;
    let (route_length, route) = route_field.split_once(':')?;
    let route_length = route_length.parse::<usize>().ok()?;
    if route.len() != route_length || RouteRef::new(route).is_err() || surface.is_empty() {
        return None;
    }
    Some((preset, route_field))
}

fn compiled_binding_matches(
    binding: &str,
    persona: &str,
    class: ProfileClass,
) -> bool {
    let Some((preset, route_field)) = compiled_persona_metadata(persona) else {
        return false;
    };
    let matches_runtime = |runtime| {
        preset.supports_runtime(runtime)
            && binding
                == format!(
                    "v2|preset={}|runtime={runtime:?}|class={}|route={route_field}|persona={}:{}",
                    preset.as_str(),
                    match class {
                        ProfileClass::Public => "Public",
                        ProfileClass::Authenticated => "Authenticated",
                    },
                    persona.len(),
                    persona,
                )
    };
    match preset.required_runtime() {
        Some(runtime) => matches_runtime(runtime),
        None => [RuntimeKind::Chrome, RuntimeKind::Edge]
            .into_iter()
            .any(matches_runtime),
    }
}

fn read_identity_session_status(
    profiles_root: &Path,
    profile_id: &str,
) -> Result<IdentitySessionStatus, StationError> {
    let profile_dir = profiles_root.join(profile_id);
    let profile_exists = match std::fs::metadata(&profile_dir) {
        Ok(metadata) => metadata.is_dir(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(StationError::SessionIo(error)),
    };
    if !profile_exists {
        return Ok(IdentitySessionStatus::unknown());
    }

    let persona_contract = match std::fs::read_to_string(profile_dir.join(PERSONA_MANIFEST)) {
        Ok(contract)
            if contract.starts_with("v1|kind=")
                || compiled_persona_metadata(&contract).is_some() => Some(contract),
        Ok(_) => return Err(StationError::SessionStateCorrupt),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(StationError::SessionIo(error)),
    };
    let persona_bound = persona_contract.is_some();
    let compiled_persona = persona_contract
        .as_deref()
        .is_some_and(|contract| contract.starts_with("v2|preset="));
    let profile_class = match std::fs::read_to_string(
        profile_dir.join(PROFILE_CLASS_MANIFEST),
    ) {
        Ok(contract) if contract == "Public" => Some(ProfileClass::Public),
        Ok(contract) if contract == "Authenticated" => {
            Some(ProfileClass::Authenticated)
        }
        Ok(_) => return Err(StationError::SessionStateCorrupt),
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                && persona_bound
                && !compiled_persona => {
            Some(ProfileClass::Public)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(StationError::SessionIo(error)),
    };
    let binding = match std::fs::read_to_string(profile_dir.join(PROFILE_BINDING_MANIFEST)) {
        Ok(binding) => Some(binding),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(StationError::SessionIo(error)),
    };
    match (
        compiled_persona,
        persona_contract.as_deref(),
        profile_class,
        binding.as_deref(),
    ) {
        (true, Some(persona), Some(class), Some(binding))
            if compiled_binding_matches(binding, persona, class) => {}
        (false, Some(_), _, None) | (false, None, None, None) => {}
        _ => return Err(StationError::SessionStateCorrupt),
    }
    let baseline = IdentitySessionStatus {
        profile_exists: true,
        persona_bound,
        profile_class,
        phase: SessionPhase::Unknown,
        updated_at_unix_ms: 0,
        expires_at_unix_ms: None,
    };
    let bytes = match std::fs::read(profile_dir.join(SESSION_STATE_JOURNAL)) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(baseline),
        Err(error) => return Err(StationError::SessionIo(error)),
    };
    let mut records = bytes.chunks_exact(IdentitySessionStatus::ENCODED_LEN);
    let mut latest = None;
    for record in &mut records {
        latest = Some(
            IdentitySessionStatus::decode(record)
                .map_err(|_| StationError::SessionStateCorrupt)?,
        );
    }
    let Some(mut latest) = latest else {
        return Err(StationError::SessionStateCorrupt);
    };
    if latest.profile_class != profile_class
        || latest.persona_bound != persona_bound
        || !latest.profile_exists
    {
        return Err(StationError::SessionStateCorrupt);
    }
    if latest.phase == SessionPhase::Ready
        && latest
            .expires_at_unix_ms
            .is_some_and(|expiry| expiry <= unix_time_ms())
    {
        latest.phase = SessionPhase::Expired;
    }
    Ok(latest)
}

fn append_session_status(
    profile_dir: &Path,
    status: &IdentitySessionStatus,
) -> Result<(), StationError> {
    let encoded = status
        .encode()
        .map_err(|_| StationError::InvalidSessionState)?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(profile_dir.join(SESSION_STATE_JOURNAL))
        .map_err(StationError::SessionIo)?;
    file.write_all(&encoded).map_err(StationError::SessionIo)?;
    file.sync_data().map_err(StationError::SessionIo)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeInstanceIdentity {
    kind: RuntimeKind,
    engine: EngineFamily,
    control: ControlTransport,
    version: Option<String>,
}

impl RuntimeInstanceIdentity {
    fn from_resolved(runtime: &ResolvedRuntime) -> Self {
        Self {
            kind: runtime.kind(),
            engine: runtime.engine(),
            control: runtime.control(),
            version: runtime.version().map(str::to_owned),
        }
    }

    fn matches(&self, runtime: &ResolvedRuntime) -> bool {
        self.kind == runtime.kind()
            && self.engine == runtime.engine()
            && self.control == runtime.control()
            && self.version.as_deref() == runtime.version()
    }
}

struct Slot {
    worker: BrowserWorker,
    runtime: RuntimeInstanceIdentity,
    session_gate: Mutex<()>,
    active_leases: AtomicUsize,
    last_used: AtomicU64,
}

struct State {
    slots: HashMap<IdentityRequest, Arc<Slot>>,
    auth_sessions: HashMap<IdentityRequest, Option<BrowserWorker>>,
}

struct Inner {
    config: StationConfig,
    state: Mutex<State>,
    command_slots: Semaphore,
    operation_gate: RwLock<()>,
    shutting_down: AtomicBool,
    clock: AtomicU64,
    command_waiters: AtomicUsize,
    session_state_gate: Mutex<()>,
    emergency_workers: std::sync::Mutex<Vec<BrowserWorker>>,
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
                    auth_sessions: HashMap::new(),
                }),
                operation_gate: RwLock::new(()),
                shutting_down: AtomicBool::new(false),
                clock: AtomicU64::new(0),
                command_waiters: AtomicUsize::new(0),
                session_state_gate: Mutex::new(()),
                emergency_workers: std::sync::Mutex::new(Vec::new()),
            }),
        }
    }

    fn register_emergency_worker(&self, worker: &BrowserWorker) -> Result<(), StationError> {
        let mut workers = self
            .inner
            .emergency_workers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        workers.retain(|worker| worker.snapshot().lifecycle != WorkerLifecycle::Stopped);
        workers.push(worker.clone());
        if self.inner.shutting_down.load(Ordering::Acquire) {
            worker.abort_now();
            return Err(StationError::ShuttingDown);
        }
        Ok(())
    }

    pub fn profiles_root(&self) -> &Path {
        &self.inner.config.profiles_root
    }

    pub fn validate_navigation_target(&self, url: &str) -> Result<(), StationError> {
        self.inner
            .config
            .navigation_policy
            .validate(url)
            .map_err(|_| StationError::Worker(WorkerError::InvalidInput))
    }

    pub fn validate_task_targets(&self, task: &BrowserTask) -> Result<(), StationError> {
        for step in task.steps() {
            if let BrowserTaskStep::Navigate { url } = step {
                self.validate_navigation_target(url)?;
            }
        }
        Ok(())
    }

    /// Acquire a capability-bounded lease. A persistent identity is never
    /// exposed as a raw worker handle, so station admission cannot be bypassed.
    pub async fn lease(
        &self,
        identity: IdentityRequest,
        capabilities: CapabilitySet,
    ) -> Result<BrowserLease, StationError> {
        self.lease_with_runtime_requirements(
            identity,
            capabilities,
            RuntimeSelector::Auto,
            None,
        )
        .await
    }

    /// Acquire a lease with an opt-in runtime selector and additional runtime
    /// requirements. Caller grants remain governed by `capabilities`.
    pub async fn lease_with_runtime_requirements(
        &self,
        identity: IdentityRequest,
        capabilities: CapabilitySet,
        requested_selector: RuntimeSelector,
        additional_requirements: Option<&RuntimeRequirements>,
    ) -> Result<BrowserLease, StationError> {
        let requirements = runtime_requirements(&capabilities, identity.persona(), false)?;
        let identity_requirements =
            authenticated_identity_runtime_requirements(&identity)?;
        let mut requirement_sets = vec![&requirements];
        if let Some(identity_requirements) = identity_requirements.as_ref() {
            requirement_sets.push(identity_requirements);
        }
        if let Some(additional) = additional_requirements {
            requirement_sets.push(additional);
        }
        self.lease_with_requirement_sets(
            identity,
            capabilities,
            requested_selector,
            &requirement_sets,
        )
        .await
    }

    pub(crate) async fn lease_for_task(
        &self,
        identity: IdentityRequest,
        capabilities: CapabilitySet,
        task: &BrowserTask,
        requested_selector: RuntimeSelector,
        client_requirements: Option<&RuntimeRequirements>,
    ) -> Result<BrowserLease, StationError> {
        self.validate_task_targets(task)?;
        let task_requirements = task_runtime_requirements(task)?;
        let persona_requirements = persona_runtime_requirements(identity.persona())?;
        let identity_requirements =
            authenticated_identity_runtime_requirements(&identity)?;
        let mut requirement_sets = vec![&task_requirements, &persona_requirements];
        if let Some(identity_requirements) = identity_requirements.as_ref() {
            requirement_sets.push(identity_requirements);
        }
        if let Some(client_requirements) = client_requirements {
            requirement_sets.push(client_requirements);
        }
        self.lease_with_requirement_sets(
            identity,
            capabilities,
            requested_selector,
            &requirement_sets,
        )
        .await
    }

    async fn lease_with_requirement_sets(
        &self,
        identity: IdentityRequest,
        capabilities: CapabilitySet,
        requested_selector: RuntimeSelector,
        requirement_sets: &[&RuntimeRequirements],
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
        let selector = persona_constrained_runtime_selector(
            self.inner.config.runtime_selector,
            requested_selector,
            identity.persona(),
        )?;
        let prepared_route = prepare_persona_route(&self.inner.config, identity.persona())?;
        let runtime = self
            .inner
            .config
            .runtime_registry
            .prepare_all(selector, requirement_sets)?;
        if self.inner.config.navigation_policy.is_exact()
            && (!runtime.supports_exact_page_request_policy()
                || !runtime.supports_station_egress()
                || prepared_route
                    .as_ref()
                    .and_then(PreparedRoute::egress_proxy)
                    .is_none())
        {
            return Err(StationError::Worker(WorkerError::InvalidInput));
        }
        validate_persona_runtime(identity.persona(), runtime.resolved())?;
        let identity = identity.bind_runtime_backend(runtime.resolved().kind())?;

        // Cover actor creation and registration with the same gate drained by
        // shutdown. A cancelled lease may leave no state slot, so the worker
        // registry remains the canonical shutdown set.
        let _operation = self.inner.operation_gate.read().await;
        let mut state = self.inner.state.lock().await;
        if self.inner.shutting_down.load(Ordering::Acquire) {
            return Err(StationError::ShuttingDown);
        }
        let now = self.inner.clock.fetch_add(1, Ordering::AcqRel) + 1;
        if state
            .slots
            .keys()
            .chain(state.auth_sessions.keys())
            .any(|existing| existing.id == identity.id && existing != &identity)
        {
            return Err(StationError::PersonaMismatch);
        }
        if state
            .auth_sessions
            .keys()
            .any(|existing| existing.id == identity.id)
        {
            return Err(StationError::AuthSessionBusy);
        }
        if let Some(slot) = state.slots.get(&identity).cloned() {
            if !slot.runtime.matches(runtime.resolved())
                && slot.active_leases.load(Ordering::Acquire) != 0
            {
                return Err(StationError::RuntimeSelectionBusy);
            }
            if slot.runtime.matches(runtime.resolved()) {
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
                    return Ok(BrowserLease::new(
                        self.clone(),
                        identity,
                        slot,
                        capabilities,
                        runtime.resolved().clone(),
                    ));
                }
            }
            state.slots.remove(&identity);
            let _ = slot.worker.shutdown().await;
        }

        let mut evicted = None;
        if state.slots.len() + state.auth_sessions.len()
            >= self.inner.config.max_resident
        {
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
        let resolved_runtime = runtime.resolved().clone();
        bind_identity_contract(&profile, identity.persona(), &resolved_runtime)?;
        let mut worker_config = self.inner.config.worker.clone();
        if let Some(route) = &prepared_route {
            route.apply(&mut worker_config);
        }
        apply_persona(&mut worker_config, identity.persona())?;
        let worker = runtime.spawn(
            profile,
            self.inner.config.worker_capabilities.clone(),
            self.inner.config.navigation_policy.clone(),
            prepared_route
                .as_ref()
                .and_then(PreparedRoute::egress_proxy),
            self.inner.config.process_isolation.clone(),
            worker_config,
        )?;
        self.register_emergency_worker(&worker)?;
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
            runtime: RuntimeInstanceIdentity::from_resolved(&resolved_runtime),
            session_gate: Mutex::new(()),
            active_leases: AtomicUsize::new(1),
            last_used: AtomicU64::new(now),
        });
        if self.inner.shutting_down.load(Ordering::Acquire) {
            let _ = slot.worker.shutdown().await;
            return Err(StationError::ShuttingDown);
        }
        state.slots.insert(identity.clone(), Arc::clone(&slot));
        Ok(BrowserLease::new(
            self.clone(),
            identity,
            slot,
            capabilities,
            resolved_runtime,
        ))
    }

    pub async fn snapshot(&self) -> StationSnapshot {
        let state = self.inner.state.lock().await;
        let active_leases = state
            .slots
            .values()
            .map(|slot| slot.active_leases.load(Ordering::Acquire))
            .sum();
        StationSnapshot {
            resident: state.slots.len() + state.auth_sessions.len(),
            active_leases,
            shutting_down: self.inner.shutting_down.load(Ordering::Acquire),
            workers: state
                .slots
                .iter()
                .map(|(identity, slot)| (identity.clone(), slot.worker.snapshot()))
                .chain(state.auth_sessions.iter().filter_map(|(identity, worker)| {
                    worker
                        .as_ref()
                        .map(|worker| (identity.clone(), worker.snapshot()))
                }))
                .collect(),
        }
    }

    /// Aggregate fleet status suitable for sanitized operator telemetry. No
    /// identity key, profile path, URL or browser content is returned.
    pub async fn fleet_status(&self) -> StationFleetStatus {
        let state = self.inner.state.lock().await;
        let mut status = StationFleetStatus {
            resident_identities: state.slots.len() + state.auth_sessions.len(),
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
        for worker in state.auth_sessions.values() {
            let Some(worker) = worker else {
                status.starting_workers += 1;
                continue;
            };
            match worker.snapshot().lifecycle {
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

    /// Start a visible, station-owned browser for operator authentication.
    /// The profile remains exclusively owned by this station and no session
    /// material is returned to the caller.
    pub async fn begin_auth_session(
        &self,
        identity: IdentityRequest,
        url: String,
    ) -> Result<(), StationError> {
        self.validate_navigation_target(&url)?;
        if identity.class != IdentityClass::Authenticated {
            return Err(StationError::AuthenticatedProfileRequired);
        }
        if self.inner.shutting_down.load(Ordering::Acquire) {
            return Err(StationError::ShuttingDown);
        }
        let selector = persona_constrained_runtime_selector(
            self.inner.config.runtime_selector,
            RuntimeSelector::Auto,
            identity.persona(),
        )?;
        let prepared_route = prepare_persona_route(&self.inner.config, identity.persona())?;
        let worker_capabilities = CapabilitySet::monitoring();
        let requirements = runtime_requirements(
            &worker_capabilities,
            identity.persona(),
            true,
        )?;
        let identity_requirements =
            authenticated_identity_runtime_requirements(&identity)?;
        let mut requirement_sets = vec![&requirements];
        if let Some(identity_requirements) = identity_requirements.as_ref() {
            requirement_sets.push(identity_requirements);
        }
        let runtime = self
            .inner
            .config
            .runtime_registry
            .prepare_all(selector, &requirement_sets)?;
        if self.inner.config.navigation_policy.is_exact()
            && (!runtime.supports_exact_page_request_policy()
                || !runtime.supports_station_egress()
                || prepared_route
                    .as_ref()
                    .and_then(PreparedRoute::egress_proxy)
                    .is_none())
        {
            return Err(StationError::Worker(WorkerError::InvalidInput));
        }
        validate_persona_runtime(identity.persona(), runtime.resolved())?;
        let identity = identity.bind_runtime_backend(runtime.resolved().kind())?;
        let _operation = self.inner.operation_gate.read().await;

        let evicted = {
            let mut state = self.inner.state.lock().await;
            if self.inner.shutting_down.load(Ordering::Acquire) {
                return Err(StationError::ShuttingDown);
            }
            if state
                .slots
                .keys()
                .chain(state.auth_sessions.keys())
                .any(|existing| existing.id == identity.id && existing != &identity)
            {
                return Err(StationError::PersonaMismatch);
            }
            if state
                .auth_sessions
                .keys()
                .any(|existing| existing.id == identity.id)
            {
                return Err(StationError::AuthSessionBusy);
            }

            let mut evicted = None;
            if let Some(slot) = state.slots.get(&identity) {
                if slot.active_leases.load(Ordering::Acquire) != 0 {
                    return Err(StationError::AuthSessionBusy);
                }
                evicted = state.slots.remove(&identity);
            } else if state.slots.len() + state.auth_sessions.len()
                >= self.inner.config.max_resident
            {
                let candidate = state
                    .slots
                    .iter()
                    .filter(|(_, slot)| {
                        slot.active_leases.load(Ordering::Acquire) == 0
                    })
                    .min_by_key(|(_, slot)| slot.last_used.load(Ordering::Acquire))
                    .map(|(key, _)| key.clone());
                let Some(candidate) = candidate else {
                    return Err(StationError::AtCapacity);
                };
                evicted = state.slots.remove(&candidate);
            }
            state.auth_sessions.insert(identity.clone(), None);
            evicted
        };

        if let Some(slot) = evicted {
            if let Err(error) = slot.worker.shutdown().await {
                self.remove_auth_reservation(&identity).await;
                return Err(error.into());
            }
        }

        let profile = match IdentityProfile::new(
            &self.inner.config.profiles_root,
            &identity.id,
            identity.class,
            identity.backend,
            identity.device,
        ) {
            Ok(profile) => profile,
            Err(error) => {
                self.remove_auth_reservation(&identity).await;
                return Err(error.into());
            }
        };
        if let Err(error) = bind_identity_contract(
            &profile,
            identity.persona(),
            runtime.resolved(),
        ) {
            self.remove_auth_reservation(&identity).await;
            return Err(error);
        }
        let mut worker_config = self.inner.config.worker.clone();
        worker_config.launch.headless = false;
        if let Some(route) = &prepared_route {
            route.apply(&mut worker_config);
        }
        if let Err(error) = apply_persona(&mut worker_config, identity.persona()) {
            self.remove_auth_reservation(&identity).await;
            return Err(error);
        }
        let worker = match runtime.spawn(
            profile,
            worker_capabilities,
            self.inner.config.navigation_policy.clone(),
            prepared_route
                .as_ref()
                .and_then(PreparedRoute::egress_proxy),
            self.inner.config.process_isolation.clone(),
            worker_config,
        ) {
            Ok(worker) => worker,
            Err(error) => {
                self.remove_auth_reservation(&identity).await;
                return Err(error.into());
            }
        };
        if let Err(error) = self.register_emergency_worker(&worker) {
            self.remove_auth_reservation(&identity).await;
            return Err(error);
        }
        let ready = match worker.wait_until_settled().await {
            Ok(snapshot) if snapshot.lifecycle == WorkerLifecycle::Ready => true,
            Ok(snapshot) if snapshot.lifecycle == WorkerLifecycle::Degraded => worker
                .execute(AgentCommand::Restart)
                .await
                .is_ok(),
            _ => false,
        };
        if !ready {
            let _ = worker.shutdown().await;
            self.remove_auth_reservation(&identity).await;
            return Err(StationError::WorkerUnavailable);
        }
        if let Err(error) = worker.execute(AgentCommand::Navigate { url }).await {
            let _ = worker.shutdown().await;
            self.remove_auth_reservation(&identity).await;
            return Err(error.into());
        }
        if let Err(error) = self
            .update_identity_session(
                &identity.id,
                SessionStateUpdate {
                    phase: SessionPhase::ReauthRequired,
                    expires_at_unix_ms: None,
                },
            )
            .await
        {
            let _ = worker.shutdown().await;
            self.remove_auth_reservation(&identity).await;
            return Err(error);
        }

        let mut state = self.inner.state.lock().await;
        let Some(reservation) = state.auth_sessions.get_mut(&identity) else {
            drop(state);
            let _ = worker.shutdown().await;
            return Err(StationError::ShuttingDown);
        };
        *reservation = Some(worker);
        Ok(())
    }

    /// Close a visible authentication browser and make the durable profile
    /// eligible for ordinary station leases again.
    pub async fn finish_auth_session(
        &self,
        profile_id: &str,
    ) -> Result<(), StationError> {
        validate_profile_id(profile_id)?;
        if self.inner.shutting_down.load(Ordering::Acquire) {
            return Err(StationError::ShuttingDown);
        }
        let _operation = self.inner.operation_gate.read().await;
        let (identity, worker) = {
            let mut state = self.inner.state.lock().await;
            let Some(identity) = state
                .auth_sessions
                .keys()
                .find(|identity| identity.id == profile_id)
                .cloned()
            else {
                return Err(StationError::AuthSessionNotFound);
            };
            let Some(worker) = state
                .auth_sessions
                .get_mut(&identity)
                .and_then(Option::take)
            else {
                return Err(StationError::AuthSessionBusy);
            };
            (identity, worker)
        };
        let shutdown = worker.shutdown().await;
        self.remove_auth_reservation(&identity).await;
        shutdown.map_err(StationError::from)
    }

    async fn remove_auth_reservation(&self, identity: &IdentityRequest) {
        self.inner.state.lock().await.auth_sessions.remove(identity);
    }

    /// Import a prepared session: install `cookies` into the profile's own
    /// encrypted cookie store (CDP `Network.setCookie`) under an `Authenticated`
    /// identity, then mark the session `Ready`. The cookies are parsed from a
    /// local file the caller supplies (`session_import::parse_session_cookies`);
    /// their values never cross the IPC boundary. Fail-closed: a non-authenticated
    /// identity is rejected, and an existing `Public` profile is rejected by the
    /// profile binding — there is no silent `Public -> Authenticated` promotion.
    /// Returns the number of cookies installed.
    pub async fn import_session(
        &self,
        identity: IdentityRequest,
        cookies: Vec<CookieSpec>,
        session_ttl_seconds: u32,
    ) -> Result<u32, StationError> {
        if identity.class != IdentityClass::Authenticated {
            return Err(StationError::AuthenticatedProfileRequired);
        }
        if cookies.is_empty() {
            return Err(StationError::InvalidSessionState);
        }
        if self.inner.shutting_down.load(Ordering::Acquire) {
            return Err(StationError::ShuttingDown);
        }
        let count = u32::try_from(cookies.len()).unwrap_or(u32::MAX);
        // A prepared session is meant to persist: give any cookie without its own
        // expiry the session TTL, so it is a *persistent* cookie Chrome writes to
        // the on-disk store (a session cookie — no expiry — is RAM-only by browser
        // design and could never be durable).
        let default_expiry_unix = i64::try_from(unix_time_ms() / 1_000)
            .unwrap_or(i64::MAX)
            .saturating_add(i64::from(session_ttl_seconds));
        let cookies: Vec<CookieSpec> = cookies
            .into_iter()
            .map(|mut cookie| {
                if cookie.expires_unix.is_none() {
                    cookie.expires_unix = Some(default_expiry_unix);
                }
                cookie
            })
            .collect();
        // Needs Interact to install cookies; Lifecycle to restart the worker.
        let capabilities = CapabilitySet::new([
            Capability::L2(L2Capability::Interact),
            Capability::L3(L3Capability::Lifecycle),
        ])
        .map_err(|_| StationError::InvalidSessionState)?;
        let lease = self.lease(identity.clone(), capabilities).await?;
        lease
            .execute(AgentCommand::SetCookies { cookies })
            .await?;
        // Restart the browser on the same profile: the graceful close flushes the
        // persistent cookies to the on-disk store and the relaunch reloads them
        // from disk — so the imported session is durable on return (survives worker
        // eviction, a fresh lease, or a station restart), not merely resident in
        // the live worker's memory.
        lease.execute(AgentCommand::Restart).await?;
        drop(lease);
        let expires_at_unix_ms = unix_time_ms()
            .checked_add(u64::from(session_ttl_seconds) * 1_000)
            .ok_or(StationError::InvalidSessionState)?;
        self.update_identity_session(
            &identity.id,
            SessionStateUpdate {
                phase: SessionPhase::Ready,
                expires_at_unix_ms: Some(expires_at_unix_ms),
            },
        )
        .await?;
        Ok(count)
    }

    /// Check a bound authenticated profile using two bounded DOM signals and
    /// persist only the resulting non-secret lifecycle state. Reauth evidence
    /// wins if both selectors match; no match is recorded as unknown.
    pub async fn check_auth_session(
        &self,
        identity: IdentityRequest,
        probe: SessionHealthProbe,
    ) -> Result<IdentitySessionStatus, StationError> {
        if identity.class != IdentityClass::Authenticated {
            return Err(StationError::AuthenticatedProfileRequired);
        }
        probe
            .validate()
            .map_err(|_| StationError::InvalidSessionState)?;
        let current = self.identity_session_status(&identity.id).await?;
        if !current.persona_bound
            || current.profile_class != Some(ProfileClass::Authenticated)
        {
            return Err(StationError::AuthenticatedProfileRequired);
        }

        let ready_selector = serde_json::to_string(&probe.ready_selector)
            .map_err(|_| StationError::InvalidSessionState)?;
        let reauth_selector = serde_json::to_string(&probe.reauth_selector)
            .map_err(|_| StationError::InvalidSessionState)?;
        let script = format!(
            "(()=>{{const ready=document.querySelector({ready_selector})!==null;const reauth=document.querySelector({reauth_selector})!==null;return {{ready,reauth}};}})()"
        );
        let task = BrowserTask::new(vec![
            BrowserTaskStep::Navigate { url: probe.url },
            BrowserTaskStep::Evaluate { script },
        ])
        .map_err(|_| StationError::InvalidSessionState)?;
        self.validate_task_targets(&task)?;
        let lease = self
            .lease(identity.clone(), CapabilitySet::scripted_monitoring())
            .await?;
        let result = lease.run_task(&task).await?;
        let Some(AgentReply::ScriptValue(value)) = result.replies.get(1) else {
            return Err(StationError::InvalidWorkerReply);
        };
        let ready = value
            .get("ready")
            .and_then(serde_json::Value::as_bool)
            .ok_or(StationError::InvalidWorkerReply)?;
        let reauth = value
            .get("reauth")
            .and_then(serde_json::Value::as_bool)
            .ok_or(StationError::InvalidWorkerReply)?;
        drop(lease);

        if reauth {
            self.update_identity_session(
                &identity.id,
                SessionStateUpdate {
                    phase: SessionPhase::ReauthRequired,
                    expires_at_unix_ms: None,
                },
            )
            .await?;
        } else if ready {
            let expires_at_unix_ms = unix_time_ms()
                .checked_add(u64::from(probe.ready_ttl_seconds) * 1_000)
                .ok_or(StationError::InvalidSessionState)?;
            self.update_identity_session(
                &identity.id,
                SessionStateUpdate {
                    phase: SessionPhase::Ready,
                    expires_at_unix_ms: Some(expires_at_unix_ms),
                },
            )
            .await?;
        } else {
            self.mark_identity_session_unknown(&identity.id).await?;
        }
        self.identity_session_status(&identity.id).await
    }

    async fn mark_identity_session_unknown(
        &self,
        profile_id: &str,
    ) -> Result<(), StationError> {
        let _gate = self.inner.session_state_gate.lock().await;
        let current = read_identity_session_status(
            &self.inner.config.profiles_root,
            profile_id,
        )?;
        if !current.persona_bound
            || current.profile_class != Some(ProfileClass::Authenticated)
        {
            return Err(StationError::AuthenticatedProfileRequired);
        }
        append_session_status(
            &self.inner.config.profiles_root.join(profile_id),
            &IdentitySessionStatus {
                profile_exists: true,
                persona_bound: true,
                profile_class: Some(ProfileClass::Authenticated),
                phase: SessionPhase::Unknown,
                updated_at_unix_ms: unix_time_ms(),
                expires_at_unix_ms: None,
            },
        )
    }

    /// Read one profile's non-secret session lifecycle. This never inspects or
    /// returns Chromium cookie storage.
    pub async fn identity_session_status(
        &self,
        profile_id: &str,
    ) -> Result<IdentitySessionStatus, StationError> {
        validate_profile_id(profile_id)?;
        let _gate = self.inner.session_state_gate.lock().await;
        read_identity_session_status(&self.inner.config.profiles_root, profile_id)
    }

    /// Persist an explicit operator transition for an already-bound
    /// authenticated profile. Public profiles cannot acquire authenticated
    /// state through this API.
    pub async fn update_identity_session(
        &self,
        profile_id: &str,
        update: SessionStateUpdate,
    ) -> Result<(), StationError> {
        validate_profile_id(profile_id)?;
        update
            .validate()
            .map_err(|_| StationError::InvalidSessionState)?;
        let now = unix_time_ms();
        if update.phase == SessionPhase::Ready
            && update.expires_at_unix_ms.is_some_and(|expiry| expiry <= now)
        {
            return Err(StationError::InvalidSessionState);
        }
        let _gate = self.inner.session_state_gate.lock().await;
        let current = read_identity_session_status(
            &self.inner.config.profiles_root,
            profile_id,
        )?;
        if !current.persona_bound
            || current.profile_class != Some(ProfileClass::Authenticated)
        {
            return Err(StationError::AuthenticatedProfileRequired);
        }
        let status = IdentitySessionStatus {
            profile_exists: true,
            persona_bound: true,
            profile_class: Some(ProfileClass::Authenticated),
            phase: update.phase,
            updated_at_unix_ms: now,
            expires_at_unix_ms: update.expires_at_unix_ms,
        };
        append_session_status(
            &self.inner.config.profiles_root.join(profile_id),
            &status,
        )
    }

    /// Stop admission, drain in-flight commands, close every runtime and return
    /// only after each worker actor has dropped its runtime and process handles.
    pub async fn shutdown(&self) -> Result<ShutdownReport, StationError> {
        if self.inner.shutting_down.swap(true, Ordering::AcqRel) {
            return Err(StationError::ShuttingDown);
        }
        let _drained = self.inner.operation_gate.write().await;
        {
            let mut state = self.inner.state.lock().await;
            state.slots.clear();
            state.auth_sessions.clear();
        }
        let workers = {
            let registered = self
                .inner
                .emergency_workers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            registered.clone()
        };
        let mut stopped = 0;
        let mut failed = 0;
        for worker in workers {
            match worker.shutdown().await {
                Ok(()) => stopped += 1,
                Err(_) => failed += 1,
            }
        }
        self.inner
            .emergency_workers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        if failed > 0 {
            return Err(StationError::ShutdownIncomplete { stopped, failed });
        }
        Ok(ShutdownReport { stopped })
    }

    /// Emergency shutdown after loss of an external containment boundary.
    /// Admission stops first, then every registered actor is cancelled before
    /// any IPC or collection drain can delay browser process-tree termination.
    pub async fn emergency_shutdown(&self) -> ShutdownReport {
        self.inner.shutting_down.store(true, Ordering::Release);
        let active_workers = {
            let registered = self
                .inner
                .emergency_workers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            registered.clone()
        };
        for worker in active_workers {
            worker.abort_now();
        }

        // Admission that already holds the read side may still register a
        // worker after the first snapshot. Such registration observes
        // `shutting_down`, aborts itself, and remains in the canonical registry
        // collected after the gate drains.
        let _drained = self.inner.operation_gate.write().await;
        let workers = {
            let mut registered = self
                .inner
                .emergency_workers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::mem::take(&mut *registered)
        };
        for worker in &workers {
            worker.abort_now();
        }
        let stopped = workers.len();
        for worker in &workers {
            worker.wait_aborted().await;
        }
        let mut state = self.inner.state.lock().await;
        state.slots.clear();
        state.auth_sessions.clear();
        ShutdownReport { stopped }
    }
}

pub struct BrowserLease {
    station: BrowserStation,
    identity: IdentityRequest,
    slot: Arc<Slot>,
    capabilities: CapabilitySet,
    resolved_runtime: ResolvedRuntime,
}

impl BrowserLease {
    fn new(
        station: BrowserStation,
        identity: IdentityRequest,
        slot: Arc<Slot>,
        capabilities: CapabilitySet,
        resolved_runtime: ResolvedRuntime,
    ) -> Self {
        Self {
            station,
            identity,
            slot,
            capabilities,
            resolved_runtime,
        }
    }

    pub fn identity(&self) -> &IdentityRequest {
        &self.identity
    }

    pub fn snapshot(&self) -> BrowserSnapshot {
        self.slot.worker.snapshot()
    }

    pub fn resolved_runtime(&self) -> &ResolvedRuntime {
        &self.resolved_runtime
    }

    fn validate_navigation(&self, url: &str) -> Result<(), StationError> {
        self.station.validate_navigation_target(url)
    }

    fn validate_task_navigation(&self, task: &BrowserTask) -> Result<(), StationError> {
        self.station.validate_task_targets(task)
    }

    pub async fn execute(&self, command: AgentCommand) -> Result<AgentReply, StationError> {
        if let AgentCommand::Navigate { url } = &command {
            self.validate_navigation(url)?;
        }
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

    /// Subscribe to this lease's worker's live DevTools event stream.
    /// Requires `L3Capability::Capture`, the same lease grant `Capture`
    /// task steps already require. This bypasses the queued `AgentCommand`
    /// pipeline (see `BrowserWorker::subscribe_devtools`), so unlike
    /// `execute`/`run_task` it does not take the per-identity `session_gate`
    /// or the station-wide `command_slots` admission semaphore — it is a
    /// cheap, side-channel subscribe, not a page-mutating command.
    pub(crate) async fn subscribe_devtools(&self) -> Result<PageDevTools, StationError> {
        if !self.capabilities.contains(Capability::L3(L3Capability::Capture)) {
            return Err(StationError::CapabilityDenied);
        }
        let _operation = self.station.inner.operation_gate.read().await;
        if self.station.inner.shutting_down.load(Ordering::Acquire) {
            return Err(StationError::ShuttingDown);
        }
        self.slot
            .worker
            .subscribe_devtools()
            .await
            .map_err(Into::into)
    }

    /// Navigate and capture under one per-identity session lock so concurrent
    /// consumers cannot interleave page state between the two commands.
    pub async fn navigate_and_capture(
        &self,
        url: impl Into<String>,
        policy: CapturePolicy,
    ) -> Result<CaptureArtifact, StationError> {
        let url = url.into();
        self.validate_navigation(&url)?;
        let navigate = AgentCommand::Navigate { url };
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
        self.run_task_controlled(task, None).await
    }

    pub(crate) async fn run_task_with_control(
        &self,
        task: &BrowserTask,
        cancelled: &AtomicBool,
    ) -> Result<BrowserTaskResult, StationError> {
        self.run_task_controlled(task, Some(cancelled)).await
    }

    async fn run_task_controlled(
        &self,
        task: &BrowserTask,
        cancelled: Option<&AtomicBool>,
    ) -> Result<BrowserTaskResult, StationError> {
        self.validate_task_navigation(task)?;
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
            if cancelled.is_some_and(|cancelled| cancelled.load(Ordering::Acquire)) {
                return Err(StationError::TaskCancelled);
            }
            let started = Instant::now();
            let first_attempt = self
                .execute_task_step_controlled(step, cancelled)
                .await;
            let reply = match first_attempt {
                Ok(reply) => reply,
                Err(StationError::TaskCancelled) => {
                    return Err(StationError::TaskCancelled)
                }
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
                    match self.execute_task_step_controlled(step, cancelled).await {
                        Ok(reply) => reply,
                        Err(StationError::TaskCancelled) => {
                            return Err(StationError::TaskCancelled)
                        }
                        Err(source) => {
                            return Err(StationError::TaskStepFailed {
                                index,
                                source: Box::new(source),
                            })
                        }
                    }
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

    async fn execute_task_step_controlled(
        &self,
        step: &BrowserTaskStep,
        cancelled: Option<&AtomicBool>,
    ) -> Result<AgentReply, StationError> {
        if let BrowserTaskStep::Wait { duration } = step {
            let deadline = Instant::now() + *duration;
            loop {
                if cancelled.is_some_and(|cancelled| cancelled.load(Ordering::Acquire)) {
                    return Err(StationError::TaskCancelled);
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Ok(AgentReply::Acknowledged);
                }
                tokio::time::sleep(remaining.min(Duration::from_millis(100))).await;
            }
        }
        if let BrowserTaskStep::WaitForSelector { selector, timeout } = step {
            return self.wait_for_selector(selector, *timeout, cancelled).await;
        }
        let reply = self.execute_task_step(step).await?;
        if cancelled.is_some_and(|cancelled| cancelled.load(Ordering::Acquire)) {
            return Err(StationError::TaskCancelled);
        }
        Ok(reply)
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
            BrowserTaskStep::WaitForSelector { selector, timeout } => {
                self.wait_for_selector(selector, *timeout, None).await
            }
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

    /// Poll for `selector` until it resolves in the DOM or `timeout` elapses.
    ///
    /// Presence-only (a `ResolveElement` success), so it needs just `Inspect`
    /// and never grants interaction or script capability. Cancellation-aware
    /// (same 100 ms granularity as `Wait`); returns `WaitTimeout` if the
    /// element never resolves within the budget.
    async fn wait_for_selector(
        &self,
        selector: &str,
        timeout: Duration,
        cancelled: Option<&AtomicBool>,
    ) -> Result<AgentReply, StationError> {
        let deadline = Instant::now() + timeout;
        loop {
            if cancelled.is_some_and(|cancelled| cancelled.load(Ordering::Acquire)) {
                return Err(StationError::TaskCancelled);
            }
            if self
                .slot
                .worker
                .execute(AgentCommand::ResolveElement {
                    selector: selector.to_owned(),
                })
                .await
                .is_ok()
            {
                return Ok(AgentReply::Acknowledged);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(StationError::WaitTimeout);
            }
            tokio::time::sleep(remaining.min(Duration::from_millis(100))).await;
        }
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
                BrowserTaskStep::WaitForSelector { .. } => {
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
            resolved_runtime: self.resolved_runtime.clone(),
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
    #[error("requested runtime conflicts with station runtime policy")]
    RuntimeSelectionDenied {
        configured: RuntimeKind,
        requested: RuntimeKind,
    },
    #[error("selected runtime has no station identity backend")]
    RuntimeBackendUnsupported(RuntimeKind),
    #[error("the identity is leased by a different runtime instance")]
    RuntimeSelectionBusy,
    #[error("browser profile is bound to a different persona")]
    PersonaMismatch,
    #[error("browser profile is bound to a different compiled persona, runtime, or route")]
    ProfileBindingMismatch,
    #[error("existing profile requires an explicit compiled-binding migration")]
    ProfileBindingRequired,
    #[error("compiled persona is incompatible with the selected runtime")]
    PersonaRuntimeMismatch,
    #[error("browser profile is bound to a different identity class")]
    IdentityClassMismatch,
    #[error("existing profile must be bound as desktop before persona migration")]
    PersonaBindingRequired,
    #[error("existing public profile cannot be promoted to authenticated")]
    IdentityClassBindingRequired,
    #[error("browser persona is invalid")]
    InvalidPersona,
    #[error("browser persona manifest I/O failed")]
    PersonaIo(#[source] std::io::Error),
    #[error("browser route contract is unavailable")]
    Route(#[from] RouteRegistryError),
    #[error("an authenticated profile is required")]
    AuthenticatedProfileRequired,
    #[error("browser authentication session is busy")]
    AuthSessionBusy,
    #[error("browser authentication session was not found")]
    AuthSessionNotFound,
    #[error("browser session transition is invalid")]
    InvalidSessionState,
    #[error("browser session state is corrupt")]
    SessionStateCorrupt,
    #[error("browser session state I/O failed")]
    SessionIo(#[source] std::io::Error),
    #[error("browser worker returned an invalid reply")]
    InvalidWorkerReply,
    #[error("browser task was cancelled")]
    TaskCancelled,
    #[error("wait-for-selector timed out before the element resolved")]
    WaitTimeout,
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
    RuntimeRequirements(#[from] RuntimeRequirementsError),
    #[error(transparent)]
    RuntimeRegistry(#[from] RuntimeRegistryError),
    #[error(transparent)]
    Worker(#[from] WorkerError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::AtomicUsize;

    use dig2browser::agentic::{
        BrowserRuntime, Capability, CaptureArtifact, CapturePolicy,
        DocumentState, L3Capability, RuntimeError, RuntimeResult,
    };
    use dig2browser_core::{
        FeatureSupport, NegotiationError, RuntimeDescriptor, SupportLevel,
    };

    type RuntimeFuture<'a, T> =
        Pin<Box<dyn Future<Output = RuntimeResult<T>> + Send + 'a>>;

    struct LifecycleTestRuntime {
        closes: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
        close_failure: bool,
        close_release: Option<Arc<tokio::sync::Semaphore>>,
    }

    impl Drop for LifecycleTestRuntime {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl BrowserRuntime for LifecycleTestRuntime {
        fn start(&mut self) -> RuntimeFuture<'_, ()> {
            Box::pin(async { Ok(()) })
        }

        fn restart(&mut self) -> RuntimeFuture<'_, ()> {
            Box::pin(async { Ok(()) })
        }

        fn close(&mut self) -> RuntimeFuture<'_, ()> {
            self.closes.fetch_add(1, Ordering::SeqCst);
            let close_failure = self.close_failure;
            let close_release = self.close_release.clone();
            Box::pin(async move {
                if let Some(close_release) = close_release {
                    close_release
                        .acquire()
                        .await
                        .expect("close release semaphore remains open")
                        .forget();
                }
                if close_failure {
                    Err(RuntimeError::new(RuntimeFailureKind::Shutdown))
                } else {
                    Ok(())
                }
            })
        }

        fn needs_restart(&self) -> bool {
            false
        }

        fn navigate<'a>(&'a mut self, url: &'a str) -> RuntimeFuture<'a, DocumentState> {
            let url = url.to_owned();
            Box::pin(async move {
                Ok(DocumentState {
                    url,
                    title: String::new(),
                    ready_state: "complete".to_owned(),
                    http_status: Some(200),
                })
            })
        }

        fn click_at(&mut self, _x: f64, _y: f64) -> RuntimeFuture<'_, ()> {
            Box::pin(async { Ok(()) })
        }

        fn wheel(
            &mut self,
            _x: f64,
            _y: f64,
            _delta_x: f64,
            _delta_y: f64,
        ) -> RuntimeFuture<'_, ()> {
            Box::pin(async { Ok(()) })
        }

        fn key_press<'a>(&'a mut self, _key: &'a str) -> RuntimeFuture<'a, ()> {
            Box::pin(async { Ok(()) })
        }

        fn resolve_element<'a>(
            &'a mut self,
            _selector: &'a str,
        ) -> RuntimeFuture<'a, ()> {
            Box::pin(async { Ok(()) })
        }

        fn click_element<'a>(&'a mut self, _selector: &'a str) -> RuntimeFuture<'a, ()> {
            Box::pin(async { Ok(()) })
        }

        fn type_element<'a>(
            &'a mut self,
            _selector: &'a str,
            _text: &'a str,
        ) -> RuntimeFuture<'a, ()> {
            Box::pin(async { Ok(()) })
        }

        fn read_element_text<'a>(
            &'a mut self,
            _selector: &'a str,
        ) -> RuntimeFuture<'a, String> {
            Box::pin(async { Ok(String::new()) })
        }

        fn evaluate<'a>(
            &'a mut self,
            _script: &'a str,
        ) -> RuntimeFuture<'a, serde_json::Value> {
            Box::pin(async { Ok(serde_json::Value::Null) })
        }

        fn capture(&mut self, _policy: CapturePolicy) -> RuntimeFuture<'_, CaptureArtifact> {
            Box::pin(async {
                Ok(CaptureArtifact::StateOnly(DocumentState {
                    url: String::new(),
                    title: String::new(),
                    ready_state: "complete".to_owned(),
                    http_status: None,
                }))
            })
        }
    }

    struct ExactPreflightRuntimeFactory {
        descriptor: RuntimeDescriptor,
        station_egress: bool,
    }

    impl ExactPreflightRuntimeFactory {
        fn new() -> Self {
            Self::with_station_egress(true)
        }

        fn without_station_egress() -> Self {
            Self::with_station_egress(false)
        }

        fn with_station_egress(station_egress: bool) -> Self {
            let features = [
                RuntimeFeature::DomInspect,
                RuntimeFeature::Navigate,
                RuntimeFeature::CaptureState,
                RuntimeFeature::CaptureHtml,
                RuntimeFeature::CaptureViewportPng,
                RuntimeFeature::Lifecycle,
                RuntimeFeature::PersistentProfile,
                RuntimeFeature::HeadfulAuthentication,
                RuntimeFeature::DesktopWeb,
            ]
            .into_iter()
            .map(|feature| FeatureSupport::new(feature, SupportLevel::Native, Vec::new()))
            .collect();
            Self {
                descriptor: RuntimeDescriptor::new(
                    RuntimeKind::Chrome,
                    EngineFamily::Chromium,
                    ControlTransport::Cdp,
                    features,
                )
                .expect("valid exact preflight descriptor"),
                station_egress,
            }
        }
    }

    impl RuntimeFactory for ExactPreflightRuntimeFactory {
        fn descriptor(&self) -> &RuntimeDescriptor {
            &self.descriptor
        }

        fn supports_exact_page_request_policy(&self) -> bool {
            true
        }

        fn supports_station_egress(&self) -> bool {
            self.station_egress
        }

        fn probe_version(&self) -> Result<Option<String>, RuntimeRegistryError> {
            Ok(Some("preflight-test".to_owned()))
        }

        fn spawn(
            &self,
            _identity: IdentityProfile,
            _capabilities: CapabilitySet,
            _config: BrowserWorkerConfig,
        ) -> Result<BrowserWorker, WorkerError> {
            panic!("unguarded exact route must fail before runtime spawn")
        }
    }

    fn capture_task_requirements(policy: CapturePolicy) -> RuntimeRequirements {
        let task = BrowserTask::new(vec![BrowserTaskStep::Capture { policy }])
            .expect("valid capture task");
        task_runtime_requirements(&task).expect("valid runtime requirements")
    }

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

    #[tokio::test]
    async fn shutdown_waits_for_actor_registered_during_admission_race() {
        let root = std::env::temp_dir().join(format!(
            "dig2browser-station-register-shutdown-race-{}",
            uuid::Uuid::new_v4()
        ));
        let config = StationConfig::new(&root, 1, 1).expect("valid station config");
        let station = BrowserStation::new(config);
        let operation = station.inner.operation_gate.read().await;
        let shutdown_station = station.clone();
        let shutdown = tokio::spawn(async move { shutdown_station.shutdown().await });
        while !station.inner.shutting_down.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }

        let closes = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let profile = IdentityProfile::new(
            &root,
            "register-race",
            IdentityClass::Public,
            BrowserBackend::Chromium,
            DevicePersona::DesktopNative,
        )
        .unwrap();
        let worker = BrowserWorker::spawn_with_runtime(
            profile,
            CapabilitySet::monitoring(),
            1,
            LifecycleTestRuntime {
                closes: Arc::clone(&closes),
                drops: Arc::clone(&drops),
                close_failure: false,
                close_release: None,
            },
        )
        .unwrap();
        assert!(matches!(
            station.register_emergency_worker(&worker),
            Err(StationError::ShuttingDown)
        ));

        drop(operation);
        match shutdown.await.unwrap() {
            Ok(report) => assert_eq!(report.stopped, 1),
            Err(StationError::ShutdownIncomplete { stopped, failed }) => {
                assert_eq!(stopped, 0);
                assert_eq!(failed, 1);
            }
            Err(error) => panic!("unexpected shutdown result: {error}"),
        }
        assert_eq!(closes.load(Ordering::SeqCst), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn shutdown_reports_registered_worker_close_failure() {
        let root = std::env::temp_dir().join(format!(
            "dig2browser-station-close-failure-{}",
            uuid::Uuid::new_v4()
        ));
        let config = StationConfig::new(&root, 1, 1).expect("valid station config");
        let station = BrowserStation::new(config);
        let closes = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let profile = IdentityProfile::new(
            &root,
            "close-failure",
            IdentityClass::Public,
            BrowserBackend::Chromium,
            DevicePersona::DesktopNative,
        )
        .unwrap();
        let worker = BrowserWorker::spawn_with_runtime(
            profile,
            CapabilitySet::monitoring(),
            1,
            LifecycleTestRuntime {
                closes: Arc::clone(&closes),
                drops: Arc::clone(&drops),
                close_failure: true,
                close_release: None,
            },
        )
        .unwrap();
        worker.wait_until_settled().await.unwrap();
        station.register_emergency_worker(&worker).unwrap();

        assert!(matches!(
            station.shutdown().await,
            Err(StationError::ShutdownIncomplete {
                stopped: 0,
                failed: 1,
            })
        ));
        assert_eq!(closes.load(Ordering::SeqCst), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn emergency_shutdown_aborts_registered_actor_before_admission_drain() {
        let root = std::env::temp_dir().join(format!(
            "dig2browser-station-emergency-register-race-{}",
            uuid::Uuid::new_v4()
        ));
        let config = StationConfig::new(&root, 1, 1).expect("valid station config");
        let station = BrowserStation::new(config);
        let closes = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let profile = IdentityProfile::new(
            &root,
            "emergency-register-race",
            IdentityClass::Public,
            BrowserBackend::Chromium,
            DevicePersona::DesktopNative,
        )
        .unwrap();
        let worker = BrowserWorker::spawn_with_runtime(
            profile,
            CapabilitySet::monitoring(),
            1,
            LifecycleTestRuntime {
                closes: Arc::clone(&closes),
                drops: Arc::clone(&drops),
                close_failure: false,
                close_release: None,
            },
        )
        .unwrap();
        station.register_emergency_worker(&worker).unwrap();
        worker.wait_until_settled().await.unwrap();

        let operation = station.inner.operation_gate.read().await;
        let shutdown_station = station.clone();
        let shutdown = tokio::spawn(async move { shutdown_station.emergency_shutdown().await });
        tokio::time::timeout(Duration::from_secs(1), async {
            while !station.inner.shutting_down.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
            worker.wait_stopped().await.unwrap();
        })
        .await
        .expect("emergency abort waited for admission drain");
        assert!(!shutdown.is_finished());
        assert_eq!(drops.load(Ordering::SeqCst), 1);

        drop(operation);
        let report = shutdown.await.unwrap();
        assert_eq!(report.stopped, 1);
        assert_eq!(closes.load(Ordering::SeqCst), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn emergency_shutdown_preempts_normal_shutdown_after_registry_snapshot() {
        let root = std::env::temp_dir().join(format!(
            "dig2browser-station-concurrent-shutdown-{}",
            uuid::Uuid::new_v4()
        ));
        let config = StationConfig::new(&root, 1, 1).expect("valid station config");
        let station = BrowserStation::new(config);
        let closes = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let close_release = Arc::new(tokio::sync::Semaphore::new(0));
        let profile = IdentityProfile::new(
            &root,
            "concurrent-shutdown",
            IdentityClass::Public,
            BrowserBackend::Chromium,
            DevicePersona::DesktopNative,
        )
        .unwrap();
        let worker = BrowserWorker::spawn_with_runtime(
            profile,
            CapabilitySet::monitoring(),
            1,
            LifecycleTestRuntime {
                closes: Arc::clone(&closes),
                drops: Arc::clone(&drops),
                close_failure: false,
                close_release: Some(Arc::clone(&close_release)),
            },
        )
        .unwrap();
        worker.wait_until_settled().await.unwrap();
        station.register_emergency_worker(&worker).unwrap();

        let normal_station = station.clone();
        let normal = tokio::spawn(async move { normal_station.shutdown().await });
        tokio::time::timeout(Duration::from_secs(1), async {
            while closes.load(Ordering::SeqCst) < 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("normal shutdown did not enter runtime close");

        let emergency_station = station.clone();
        let emergency = tokio::spawn(async move {
            emergency_station.emergency_shutdown().await
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while closes.load(Ordering::SeqCst) < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("emergency shutdown could not reach worker held by normal shutdown");

        close_release.add_permits(2);
        let _ = normal.await.expect("join normal shutdown");
        let _ = emergency.await.expect("join emergency shutdown");
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn capture_policy_derives_only_required_runtime_features() {
        assert_eq!(
            capture_task_requirements(CapturePolicy::StateOnly).features(),
            &[
                RuntimeFeature::Lifecycle,
                RuntimeFeature::CaptureState,
            ]
        );
        assert_eq!(
            capture_task_requirements(CapturePolicy::HtmlOnly).features(),
            &[
                RuntimeFeature::Lifecycle,
                RuntimeFeature::CaptureState,
                RuntimeFeature::CaptureHtml,
            ]
        );
        assert_eq!(
            capture_task_requirements(CapturePolicy::EvidenceViewport).features(),
            &[
                RuntimeFeature::Lifecycle,
                RuntimeFeature::CaptureState,
                RuntimeFeature::CaptureHtml,
                RuntimeFeature::CaptureViewportPng,
            ]
        );
    }

    #[test]
    fn task_runtime_features_are_step_exact_and_deduplicated() {
        let task = BrowserTask::new(vec![
            BrowserTaskStep::Navigate { url: "https://example.test".to_owned() },
            BrowserTaskStep::Wait { duration: Duration::from_millis(1) },
            BrowserTaskStep::Wheel { x: 0.0, y: 0.0, delta_x: 0.0, delta_y: 1.0 },
            BrowserTaskStep::KeyPress { key: "Tab".to_owned() },
            BrowserTaskStep::ClickSelector { selector: "#target".to_owned() },
            BrowserTaskStep::TypeSelector {
                selector: "#target".to_owned(),
                text: "value".to_owned(),
            },
            BrowserTaskStep::ReadSelectorText { selector: "#target".to_owned() },
            BrowserTaskStep::Evaluate { script: "document.title".to_owned() },
            BrowserTaskStep::Capture { policy: CapturePolicy::HtmlOnly },
        ])
        .expect("valid task");
        let requirements =
            task_runtime_requirements(&task).expect("valid runtime requirements");
        assert!(!requirements.allow_partial());
        assert_eq!(
            requirements.features(),
            &[
                RuntimeFeature::Lifecycle,
                RuntimeFeature::Navigate,
                RuntimeFeature::ScrollInput,
                RuntimeFeature::KeyboardInput,
                RuntimeFeature::DomInspect,
                RuntimeFeature::DomInteract,
                RuntimeFeature::ScriptEvaluate,
                RuntimeFeature::CaptureState,
                RuntimeFeature::CaptureHtml,
            ]
        );
    }

    #[test]
    fn client_partial_policy_cannot_weaken_task_requirements() {
        let descriptor = RuntimeDescriptor::new(
            RuntimeKind::Lightweight,
            EngineFamily::Dig2Lightweight,
            ControlTransport::Native,
            vec![
                FeatureSupport::new(
                    RuntimeFeature::Lifecycle,
                    SupportLevel::Native,
                    Vec::new(),
                ),
                FeatureSupport::new(
                    RuntimeFeature::Navigate,
                    SupportLevel::Partial,
                    Vec::new(),
                ),
                FeatureSupport::new(
                    RuntimeFeature::DesktopWeb,
                    SupportLevel::Partial,
                    Vec::new(),
                ),
            ],
        )
        .expect("valid runtime descriptor");
        let task = BrowserTask::new(vec![BrowserTaskStep::Navigate {
            url: "https://example.test".to_owned(),
        }])
        .expect("valid task");
        let task_requirements =
            task_runtime_requirements(&task).expect("valid task requirements");
        let persona_requirements = persona_runtime_requirements(
            &BrowserPersona::desktop_default(),
        )
        .expect("valid persona requirements");
        let client_requirements = RuntimeRequirements::new(
            vec![RuntimeFeature::Navigate],
            true,
        )
        .expect("valid client requirements");

        assert!(matches!(
            descriptor.negotiate_all(
                &[
                    &task_requirements,
                    &persona_requirements,
                    &client_requirements,
                ],
                None,
            ),
            Err(NegotiationError::PartialSupportDenied(
                RuntimeFeature::Navigate
            ))
        ));
    }

    #[test]
    fn persistent_profile_is_strictly_authenticated_only() {
        let public = IdentityRequest::public_desktop("public");
        assert!(
            authenticated_identity_runtime_requirements(&public)
                .expect("valid public requirements")
                .is_none()
        );

        let authenticated = IdentityRequest::authenticated_persona(
            "authenticated",
            BrowserPersona::desktop_default(),
        );
        let requirements = authenticated_identity_runtime_requirements(&authenticated)
            .expect("valid authenticated requirements")
            .expect("authenticated requirement set");
        assert!(!requirements.allow_partial());
        assert_eq!(
            requirements.features(),
            &[RuntimeFeature::PersistentProfile]
        );
    }

    #[test]
    fn open_web_legacy_persona_skips_route_resolution_and_arguments() {
        let config = StationConfig::new(std::env::temp_dir(), 1, 1)
            .expect("valid station config")
            .with_route_registry(RouteRegistry::empty());
        let persona = BrowserPersona::desktop_default();
        let mut worker = config.worker.clone();
        let original_arguments = worker.launch.extra_args.clone();

        let prepared = prepare_persona_route(&config, &persona)
            .expect("OpenWeb does not resolve a missing route reference");
        if let Some(route) = &prepared {
            route.apply(&mut worker);
        }

        assert!(prepared.is_none());
        assert_eq!(worker.launch.extra_args, original_arguments);
    }

    #[tokio::test]
    async fn exact_policy_rejects_unguarded_route_before_profile_write() {
        let root = std::env::temp_dir().join(format!(
            "dig2browser-station-exact-preflight-test-{}",
            uuid::Uuid::new_v4()
        ));
        let policy = NavigationPolicy::exact_origins(["https://example.test"])
            .expect("valid exact policy");
        let mut runtimes = RuntimeRegistry::empty();
        runtimes
            .register(ExactPreflightRuntimeFactory::new(), false)
            .expect("register exact preflight runtime");
        let config = StationConfig::new(&root, 1, 1)
            .expect("valid station config")
            .with_runtime_selector(RuntimeSelector::Exact(RuntimeKind::Chrome))
            .with_runtime_registry(runtimes)
            .with_navigation_policy(policy);
        let station = BrowserStation::new(config);

        assert!(matches!(
            station
                .lease(
                    IdentityRequest::public_desktop("exact-preflight"),
                    CapabilitySet::monitoring(),
                )
                .await,
            Err(StationError::Worker(WorkerError::InvalidInput))
        ));
        assert!(!root.exists());
    }

    #[tokio::test]
    async fn exact_policy_rejects_runtime_without_station_egress_before_profile_write() {
        let root = std::env::temp_dir().join(format!(
            "dig2browser-station-runtime-egress-preflight-test-{}",
            uuid::Uuid::new_v4()
        ));
        let policy = NavigationPolicy::exact_origins(["https://example.test"])
            .expect("valid exact policy");
        let endpoint = "127.0.0.1:18080".parse().expect("loopback endpoint");
        let mut routes = RouteRegistry::empty();
        routes
            .register(
                RouteDescriptor::guarded_host_direct(RouteRef::host_direct(), endpoint)
                    .expect("valid guarded route"),
            )
            .expect("register guarded route");
        let mut runtimes = RuntimeRegistry::empty();
        runtimes
            .register(ExactPreflightRuntimeFactory::without_station_egress(), false)
            .expect("register non-egress runtime");
        let config = StationConfig::new(&root, 1, 1)
            .expect("valid station config")
            .with_runtime_selector(RuntimeSelector::Exact(RuntimeKind::Chrome))
            .with_runtime_registry(runtimes)
            .with_route_registry(routes)
            .with_navigation_policy(policy);
        let station = BrowserStation::new(config);

        assert!(matches!(
            station
                .lease(
                    IdentityRequest::public_desktop("runtime-egress-preflight"),
                    CapabilitySet::monitoring(),
                )
                .await,
            Err(StationError::Worker(WorkerError::InvalidInput))
        ));
        assert!(!root.exists());
    }

    #[tokio::test]
    async fn exact_policy_rejects_unguarded_auth_before_reservation_or_profile_write() {
        let root = std::env::temp_dir().join(format!(
            "dig2browser-station-auth-egress-preflight-test-{}",
            uuid::Uuid::new_v4()
        ));
        let policy = NavigationPolicy::exact_origins(["https://example.test"])
            .expect("valid exact policy");
        let mut runtimes = RuntimeRegistry::empty();
        runtimes
            .register(ExactPreflightRuntimeFactory::new(), true)
            .expect("register exact preflight runtime");
        let config = StationConfig::new(&root, 1, 1)
            .expect("valid station config")
            .with_runtime_selector(RuntimeSelector::Exact(RuntimeKind::Chrome))
            .with_runtime_registry(runtimes)
            .with_navigation_policy(policy);
        let station = BrowserStation::new(config);
        let identity = IdentityRequest::authenticated_persona(
            "auth-egress-preflight",
            BrowserPersona::desktop_default(),
        );

        assert!(matches!(
            station
                .begin_auth_session(identity, "https://example.test/login".to_owned())
                .await,
            Err(StationError::Worker(WorkerError::InvalidInput))
        ));
        assert_eq!(station.snapshot().await.resident, 0);
        assert!(!root.exists());
    }

    #[test]
    fn profiles_root_has_one_crash_releasing_owner() {
        let root = std::env::temp_dir().join(format!(
            "dig2browser-station-root-test-{}",
            uuid::Uuid::new_v4()
        ));
        let first = ProfilesRootOwnership::acquire(&root).expect("acquire profiles root");
        assert!(first.root().is_absolute());
        #[cfg(windows)]
        assert!(!first.root().to_string_lossy().starts_with(r"\\?\"));
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

    #[test]
    fn session_status_accepts_firefox_compiled_profile_binding() {
        let root = std::env::temp_dir().join(format!(
            "dig2browser-station-firefox-session-status-test-{}",
            uuid::Uuid::new_v4()
        ));
        let profile_dir = root.join("firefox-auth");
        std::fs::create_dir_all(&profile_dir).expect("create Firefox profile fixture");
        let route = RouteRef::host_direct();
        let persona = BrowserPersona::compiled(
            PersonaPreset::FirefoxWindowsDesktopV1,
            route.clone(),
        )
        .expect("compile Firefox persona");
        let persona = persona_contract(&persona);
        let binding = format!(
            "v2|preset={}|runtime=Firefox|class=Authenticated|route={}:{}|persona={}:{}",
            PersonaPreset::FirefoxWindowsDesktopV1.as_str(),
            route.as_str().len(),
            route.as_str(),
            persona.len(),
            persona,
        );
        std::fs::write(profile_dir.join(PERSONA_MANIFEST), &persona)
            .expect("write persona manifest");
        std::fs::write(profile_dir.join(PROFILE_CLASS_MANIFEST), "Authenticated")
            .expect("write class manifest");
        std::fs::write(profile_dir.join(PROFILE_BINDING_MANIFEST), binding)
            .expect("write Firefox binding manifest");

        let status = read_identity_session_status(&root, "firefox-auth")
            .expect("Firefox binding must be valid session state");

        assert!(status.profile_exists);
        assert!(status.persona_bound);
        assert_eq!(status.profile_class, Some(ProfileClass::Authenticated));
        assert_eq!(status.phase, SessionPhase::Unknown);
        std::fs::remove_dir_all(root).expect("remove Firefox profile fixture");
    }
}
