use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use dig2browser::agentic::{
    BrowserWorker, BrowserWorkerConfig, CapabilitySet, NavigationPolicy,
    WorkerError,
};
use dig2browser::detect::{
    BrowserPreference, detect_browser, version::browser_version,
};
use dig2browser::identity::IdentityProfile;
use dig2browser_core::{
    ControlTransport, EngineFamily, FeatureSupport, NegotiationError,
    ResolvedRuntime, RuntimeDescriptor, RuntimeFeature, RuntimeKind,
    RuntimeLimitation, RuntimeRequirements, RuntimeSelector, SupportLevel,
};
use dig2browser_runtime_lightweight::{
    LightweightRuntime, LightweightRuntimeConfig, RUNTIME_VERSION,
    runtime_descriptor as lightweight_runtime_descriptor,
};

/// Launch boundary for one concrete browser runtime.
pub trait RuntimeFactory: Send + Sync {
    fn descriptor(&self) -> &RuntimeDescriptor;

    fn supports_exact_page_request_policy(&self) -> bool {
        false
    }

    /// Whether HTTP(S) can use the station-owned proxy. This does not claim
    /// containment for UDP or any other non-HTTP transport. The station records
    /// its own more precise level when the runtime is registered.
    fn supports_station_egress(&self) -> bool {
        false
    }

    /// Probe current host readiness without creating a profile or process.
    fn probe_version(&self) -> Result<Option<String>, RuntimeRegistryError>;

    fn spawn(
        &self,
        identity: IdentityProfile,
        capabilities: CapabilitySet,
        config: BrowserWorkerConfig,
    ) -> Result<BrowserWorker, WorkerError>;

    fn spawn_with_navigation_policy(
        &self,
        identity: IdentityProfile,
        capabilities: CapabilitySet,
        policy: NavigationPolicy,
        config: BrowserWorkerConfig,
    ) -> Result<BrowserWorker, WorkerError> {
        if policy.is_exact() {
            return Err(WorkerError::InvalidInput);
        }
        self.spawn(identity, capabilities, config)
    }

    fn spawn_with_station_egress(
        &self,
        identity: IdentityProfile,
        capabilities: CapabilitySet,
        policy: NavigationPolicy,
        egress_proxy: Option<SocketAddr>,
        config: BrowserWorkerConfig,
    ) -> Result<BrowserWorker, WorkerError> {
        if egress_proxy.is_some() {
            return Err(WorkerError::InvalidInput);
        }
        self.spawn_with_navigation_policy(identity, capabilities, policy, config)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StationEgressSupport {
    Unsupported,
    HttpProxy,
    /// Chromium receives QUIC and WebRTC mitigation switches in addition to
    /// the HTTP proxy. This is not all-protocol or OS-level containment.
    HttpProxyWithBrowserUdpMitigation,
}

impl StationEgressSupport {
    fn is_supported(self) -> bool {
        !matches!(self, Self::Unsupported)
    }
}

#[derive(Clone)]
struct RegisteredRuntime {
    factory: Arc<dyn RuntimeFactory>,
    station_egress: StationEgressSupport,
}

/// Station-owned catalog of concrete runtime adapters.
#[derive(Clone)]
pub struct RuntimeRegistry {
    factories: HashMap<RuntimeKind, RegisteredRuntime>,
    auto_order: Vec<RuntimeKind>,
}

impl RuntimeRegistry {
    pub fn empty() -> Self {
        Self {
            factories: HashMap::new(),
            auto_order: Vec::new(),
        }
    }

    pub fn chromium_defaults() -> Self {
        let mut registry = Self::empty();
        registry
            .register_with_station_egress(
                ChromiumRuntimeFactory::chrome(),
                true,
                ChromiumRuntimeFactory::station_egress_support(),
            )
            .expect("built-in Chrome runtime kind must be unique");
        registry
            .register_with_station_egress(
                ChromiumRuntimeFactory::edge(),
                true,
                ChromiumRuntimeFactory::station_egress_support(),
            )
            .expect("built-in Edge runtime kind must be unique");
        registry
    }

    pub fn builtin_defaults() -> Self {
        let mut registry = Self::chromium_defaults();
        registry
            .register_with_station_egress(
                LightweightRuntimeFactory::new(),
                false,
                LightweightRuntimeFactory::station_egress_support(),
            )
            .expect("built-in Lightweight runtime kind must be unique");
        registry
    }

    pub fn register<F>(
        &mut self,
        factory: F,
        include_in_auto: bool,
    ) -> Result<(), RuntimeRegistryError>
    where
        F: RuntimeFactory + 'static,
    {
        let station_egress = if factory.supports_station_egress() {
            StationEgressSupport::HttpProxy
        } else {
            StationEgressSupport::Unsupported
        };
        self.register_with_station_egress(factory, include_in_auto, station_egress)
    }

    fn register_with_station_egress<F>(
        &mut self,
        factory: F,
        include_in_auto: bool,
        station_egress: StationEgressSupport,
    ) -> Result<(), RuntimeRegistryError>
    where
        F: RuntimeFactory + 'static,
    {
        let kind = factory.descriptor().kind();
        if self.factories.contains_key(&kind) {
            return Err(RuntimeRegistryError::DuplicateRuntime(kind));
        }
        self.factories.insert(
            kind,
            RegisteredRuntime {
                factory: Arc::new(factory),
                station_egress,
            },
        );
        if include_in_auto {
            self.auto_order.push(kind);
        }
        Ok(())
    }

    pub fn resolve(
        &self,
        selector: RuntimeSelector,
        requirements: &RuntimeRequirements,
    ) -> Result<ResolvedRuntime, RuntimeRegistryError> {
        self.prepare(selector, requirements)
            .map(|prepared| prepared.resolved)
    }

    pub(crate) fn prepare(
        &self,
        selector: RuntimeSelector,
        requirements: &RuntimeRequirements,
    ) -> Result<PreparedRuntime, RuntimeRegistryError> {
        self.prepare_all(selector, &[requirements])
    }

    pub(crate) fn prepare_all(
        &self,
        selector: RuntimeSelector,
        requirement_sets: &[&RuntimeRequirements],
    ) -> Result<PreparedRuntime, RuntimeRegistryError> {
        match selector {
            RuntimeSelector::Exact(kind) => {
                self.prepare_exact(kind, requirement_sets)
            }
            RuntimeSelector::Auto => {
                let mut last_incompatible = None;
                for kind in &self.auto_order {
                    match self.prepare_exact(*kind, requirement_sets) {
                        Ok(prepared) => return Ok(prepared),
                        Err(RuntimeRegistryError::Unavailable(_))
                        | Err(RuntimeRegistryError::NotRegistered(_)) => {}
                        Err(error @ RuntimeRegistryError::Incompatible { .. }) => {
                            last_incompatible = Some(error);
                        }
                        Err(error) => return Err(error),
                    }
                }
                Err(last_incompatible.unwrap_or(RuntimeRegistryError::NoAvailableRuntime))
            }
        }
    }

    fn prepare_exact(
        &self,
        kind: RuntimeKind,
        requirement_sets: &[&RuntimeRequirements],
    ) -> Result<PreparedRuntime, RuntimeRegistryError> {
        let registration = self
            .factories
            .get(&kind)
            .ok_or(RuntimeRegistryError::NotRegistered(kind))?;
        let factory = Arc::clone(&registration.factory);
        let resolved = factory
            .descriptor()
            .negotiate_all(requirement_sets, None)
            .map_err(|source| RuntimeRegistryError::Incompatible { kind, source })?;
        let version = factory.probe_version()?;
        let resolved = resolved.with_version(version);
        Ok(PreparedRuntime {
            factory,
            resolved,
            station_egress: registration.station_egress,
        })
    }
}

impl Default for RuntimeRegistry {
    fn default() -> Self {
        Self::builtin_defaults()
    }
}

impl fmt::Debug for RuntimeRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut kinds: Vec<_> = self.factories.keys().copied().collect();
        kinds.sort_unstable();
        formatter
            .debug_struct("RuntimeRegistry")
            .field("registered", &kinds)
            .field("auto_order", &self.auto_order)
            .finish()
    }
}

pub(crate) struct PreparedRuntime {
    factory: Arc<dyn RuntimeFactory>,
    resolved: ResolvedRuntime,
    station_egress: StationEgressSupport,
}

impl PreparedRuntime {
    pub(crate) fn resolved(&self) -> &ResolvedRuntime {
        &self.resolved
    }

    pub(crate) fn supports_exact_page_request_policy(&self) -> bool {
        self.factory.supports_exact_page_request_policy()
    }

    /// Whether HTTP(S) can use the station-owned proxy. Non-HTTP containment is
    /// described separately by `station_egress_support`.
    pub(crate) fn supports_station_egress(&self) -> bool {
        self.station_egress_support().is_supported()
    }

    pub(crate) fn station_egress_support(&self) -> StationEgressSupport {
        self.station_egress
    }

    pub(crate) fn spawn(
        &self,
        identity: IdentityProfile,
        capabilities: CapabilitySet,
        policy: NavigationPolicy,
        egress_proxy: Option<SocketAddr>,
        config: BrowserWorkerConfig,
    ) -> Result<BrowserWorker, WorkerError> {
        self.factory.spawn_with_station_egress(
            identity,
            capabilities,
            policy,
            egress_proxy,
            config,
        )
    }
}

struct ChromiumRuntimeFactory {
    descriptor: RuntimeDescriptor,
    preference: BrowserPreference,
}

impl ChromiumRuntimeFactory {
    fn chrome() -> Self {
        Self::new(RuntimeKind::Chrome, BrowserPreference::ChromeOnly)
    }

    fn edge() -> Self {
        Self::new(RuntimeKind::Edge, BrowserPreference::EdgeOnly)
    }

    fn new(kind: RuntimeKind, preference: BrowserPreference) -> Self {
        let limitations = vec![
            RuntimeLimitation::NoNativeMobileApis,
            RuntimeLimitation::NoCarrierState,
            RuntimeLimitation::NoHardwareAttestation,
        ];
        let native = [
            RuntimeFeature::PointerInput,
            RuntimeFeature::KeyboardInput,
            RuntimeFeature::ScrollInput,
            RuntimeFeature::DomInspect,
            RuntimeFeature::DomInteract,
            RuntimeFeature::ScriptEvaluate,
            RuntimeFeature::Navigate,
            RuntimeFeature::CaptureState,
            RuntimeFeature::CaptureHtml,
            RuntimeFeature::CaptureViewportPng,
            RuntimeFeature::Lifecycle,
            RuntimeFeature::PersistentProfile,
            RuntimeFeature::HeadfulAuthentication,
            RuntimeFeature::DesktopWeb,
        ];
        let mut features = native
            .into_iter()
            .map(|feature| FeatureSupport::new(feature, SupportLevel::Native, Vec::new()))
            .collect::<Vec<_>>();
        features.push(FeatureSupport::new(
            RuntimeFeature::MobileWebEmulation,
            SupportLevel::Emulated,
            limitations.clone(),
        ));
        features.push(FeatureSupport::new(
            RuntimeFeature::NativeMobileDevice,
            SupportLevel::Unsupported,
            limitations,
        ));
        let descriptor = RuntimeDescriptor::new(
            kind,
            EngineFamily::Chromium,
            ControlTransport::Cdp,
            features,
        )
        .expect("built-in Chromium descriptor must not duplicate features");
        Self {
            descriptor,
            preference,
        }
    }

    fn station_egress_support() -> StationEgressSupport {
        if cfg!(windows) {
            StationEgressSupport::HttpProxyWithBrowserUdpMitigation
        } else {
            StationEgressSupport::Unsupported
        }
    }
}

fn chromium_station_egress_args(
    endpoint: SocketAddr,
) -> Result<[String; 4], WorkerError> {
    if !endpoint.ip().is_loopback() || endpoint.port() == 0 {
        return Err(WorkerError::InvalidInput);
    }
    Ok([
        format!("--proxy-server=http://{endpoint}"),
        "--proxy-bypass-list=<-loopback>".to_owned(),
        "--disable-quic".to_owned(),
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp".to_owned(),
    ])
}

impl RuntimeFactory for ChromiumRuntimeFactory {
    fn descriptor(&self) -> &RuntimeDescriptor {
        &self.descriptor
    }

    fn supports_exact_page_request_policy(&self) -> bool {
        cfg!(windows)
    }

    fn supports_station_egress(&self) -> bool {
        cfg!(windows)
    }

    fn probe_version(&self) -> Result<Option<String>, RuntimeRegistryError> {
        let binary = detect_browser(self.preference)
            .map_err(|_| RuntimeRegistryError::Unavailable(self.descriptor.kind()))?;
        Ok(browser_version(&binary))
    }

    fn spawn(
        &self,
        identity: IdentityProfile,
        capabilities: CapabilitySet,
        config: BrowserWorkerConfig,
    ) -> Result<BrowserWorker, WorkerError> {
        self.spawn_with_navigation_policy(
            identity,
            capabilities,
            NavigationPolicy::default(),
            config,
        )
    }

    fn spawn_with_navigation_policy(
        &self,
        identity: IdentityProfile,
        capabilities: CapabilitySet,
        policy: NavigationPolicy,
        mut config: BrowserWorkerConfig,
    ) -> Result<BrowserWorker, WorkerError> {
        config.launch.browser_pref = self.preference;
        // The default is a Chrome UA. An explicit runtime must derive its UA
        // and client-hint brand from the browser actually selected above.
        config.stealth.user_agent.clear();
        BrowserWorker::spawn_with_navigation_policy(
            identity,
            capabilities,
            config,
            policy,
        )
    }

    fn spawn_with_station_egress(
        &self,
        identity: IdentityProfile,
        capabilities: CapabilitySet,
        policy: NavigationPolicy,
        egress_proxy: Option<SocketAddr>,
        mut config: BrowserWorkerConfig,
    ) -> Result<BrowserWorker, WorkerError> {
        if let Some(endpoint) = egress_proxy {
            config
                .launch
                .extra_args
                .extend(chromium_station_egress_args(endpoint)?);
        }
        self.spawn_with_navigation_policy(identity, capabilities, policy, config)
    }
}

struct LightweightRuntimeFactory {
    descriptor: RuntimeDescriptor,
}

impl LightweightRuntimeFactory {
    fn new() -> Self {
        Self {
            descriptor: lightweight_runtime_descriptor(),
        }
    }

    fn station_egress_support() -> StationEgressSupport {
        StationEgressSupport::HttpProxy
    }
}

impl RuntimeFactory for LightweightRuntimeFactory {
    fn descriptor(&self) -> &RuntimeDescriptor {
        &self.descriptor
    }

    fn supports_exact_page_request_policy(&self) -> bool {
        true
    }

    fn supports_station_egress(&self) -> bool {
        true
    }

    fn probe_version(&self) -> Result<Option<String>, RuntimeRegistryError> {
        Ok(Some(RUNTIME_VERSION.to_owned()))
    }

    fn spawn(
        &self,
        identity: IdentityProfile,
        capabilities: CapabilitySet,
        config: BrowserWorkerConfig,
    ) -> Result<BrowserWorker, WorkerError> {
        self.spawn_with_navigation_policy(
            identity,
            capabilities,
            NavigationPolicy::default(),
            config,
        )
    }

    fn spawn_with_navigation_policy(
        &self,
        identity: IdentityProfile,
        capabilities: CapabilitySet,
        navigation_policy: NavigationPolicy,
        config: BrowserWorkerConfig,
    ) -> Result<BrowserWorker, WorkerError> {
        let runtime = LightweightRuntime::new_with_navigation_policy(
            identity.clone(),
            LightweightRuntimeConfig::default(),
            navigation_policy.clone(),
        )?;
        BrowserWorker::spawn_with_runtime_and_timeout_and_navigation_policy(
            identity,
            capabilities,
            config.queue_capacity,
            config.command_timeout,
            navigation_policy,
            runtime,
        )
    }

    fn spawn_with_station_egress(
        &self,
        identity: IdentityProfile,
        capabilities: CapabilitySet,
        navigation_policy: NavigationPolicy,
        egress_proxy: Option<SocketAddr>,
        config: BrowserWorkerConfig,
    ) -> Result<BrowserWorker, WorkerError> {
        let runtime = LightweightRuntime::new_with_navigation_policy_and_proxy(
            identity.clone(),
            LightweightRuntimeConfig::default(),
            navigation_policy.clone(),
            egress_proxy,
        )?;
        BrowserWorker::spawn_with_runtime_and_timeout_and_navigation_policy(
            identity,
            capabilities,
            config.queue_capacity,
            config.command_timeout,
            navigation_policy,
            runtime,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RuntimeRegistryError {
    #[error("runtime {0:?} is already registered")]
    DuplicateRuntime(RuntimeKind),
    #[error("runtime {0:?} is not registered")]
    NotRegistered(RuntimeKind),
    #[error("runtime {0:?} is not available on this host")]
    Unavailable(RuntimeKind),
    #[error("no runtime in the automatic selection order is available")]
    NoAvailableRuntime,
    #[error("runtime {kind:?} does not satisfy the requirements")]
    Incompatible {
        kind: RuntimeKind,
        #[source]
        source: NegotiationError,
    },
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    struct ProbeCountingFactory {
        descriptor: RuntimeDescriptor,
        probes: Arc<AtomicUsize>,
    }

    impl RuntimeFactory for ProbeCountingFactory {
        fn descriptor(&self) -> &RuntimeDescriptor {
            &self.descriptor
        }

        fn probe_version(&self) -> Result<Option<String>, RuntimeRegistryError> {
            self.probes.fetch_add(1, Ordering::AcqRel);
            Ok(Some("test-version".to_owned()))
        }

        fn spawn(
            &self,
            _identity: IdentityProfile,
            _capabilities: CapabilitySet,
            _config: BrowserWorkerConfig,
        ) -> Result<BrowserWorker, WorkerError> {
            panic!("static incompatibility must never reach spawn")
        }
    }

    #[test]
    fn static_incompatibility_does_not_probe_host_readiness() {
        let descriptor = RuntimeDescriptor::new(
            RuntimeKind::Chrome,
            EngineFamily::Chromium,
            ControlTransport::Cdp,
            vec![FeatureSupport::new(
                RuntimeFeature::NativeMobileDevice,
                SupportLevel::Unsupported,
                vec![RuntimeLimitation::NoNativeMobileApis],
            )],
        )
        .expect("valid test descriptor");
        let probes = Arc::new(AtomicUsize::new(0));
        let mut registry = RuntimeRegistry::empty();
        registry
            .register(
                ProbeCountingFactory {
                    descriptor,
                    probes: Arc::clone(&probes),
                },
                true,
            )
            .expect("register test runtime");
        let requirements = RuntimeRequirements::new(
            vec![RuntimeFeature::NativeMobileDevice],
            false,
        )
        .expect("valid requirements");

        assert!(matches!(
            registry.resolve(RuntimeSelector::Auto, &requirements),
            Err(RuntimeRegistryError::Incompatible {
                kind: RuntimeKind::Chrome,
                source: NegotiationError::UnsupportedFeature(
                    RuntimeFeature::NativeMobileDevice
                ),
            })
        ));
        assert_eq!(probes.load(Ordering::Acquire), 0);
    }

    #[test]
    fn lightweight_is_registered_but_never_selected_automatically() {
        let registry = RuntimeRegistry::builtin_defaults();
        let requirements = RuntimeRequirements::new(
            vec![RuntimeFeature::Navigate, RuntimeFeature::DesktopWeb],
            true,
        )
        .expect("valid lightweight requirements");

        let exact = registry
            .resolve(RuntimeSelector::Exact(RuntimeKind::Lightweight), &requirements)
            .expect("resolve explicit lightweight runtime");
        assert_eq!(exact.kind(), RuntimeKind::Lightweight);
        assert!(!registry.auto_order.contains(&RuntimeKind::Lightweight));
    }

    #[test]
    fn station_egress_support_is_declared_precisely() {
        let custom = ProbeCountingFactory {
            descriptor: lightweight_runtime_descriptor(),
            probes: Arc::new(AtomicUsize::new(0)),
        };
        let requirements = RuntimeRequirements::new(
            vec![RuntimeFeature::Navigate],
            false,
        )
        .expect("valid runtime requirements");
        let prepared = RuntimeRegistry::builtin_defaults()
            .prepare(
                RuntimeSelector::Exact(RuntimeKind::Lightweight),
                &requirements,
            )
            .expect("prepare lightweight runtime");

        assert!(!custom.supports_station_egress());
        let mut custom_registry = RuntimeRegistry::empty();
        custom_registry
            .register(custom, false)
            .expect("register custom runtime");
        let custom_prepared = custom_registry
            .prepare(
                RuntimeSelector::Exact(RuntimeKind::Lightweight),
                &requirements,
            )
            .expect("prepare custom runtime");
        assert_eq!(
            custom_prepared.station_egress,
            StationEgressSupport::Unsupported,
        );
        assert_eq!(
            LightweightRuntimeFactory::station_egress_support(),
            StationEgressSupport::HttpProxy,
        );
        assert!(prepared.supports_station_egress());
        assert_eq!(
            prepared.station_egress_support(),
            StationEgressSupport::HttpProxy,
        );
        assert_eq!(
            ChromiumRuntimeFactory::station_egress_support(),
            if cfg!(windows) {
                StationEgressSupport::HttpProxyWithBrowserUdpMitigation
            } else {
                StationEgressSupport::Unsupported
            },
        );
    }

    #[test]
    fn chromium_station_egress_arguments_are_exact_and_bounded() {
        let endpoint = "127.0.0.1:18080".parse().expect("loopback endpoint");
        assert_eq!(
            chromium_station_egress_args(endpoint).expect("valid endpoint"),
            [
                "--proxy-server=http://127.0.0.1:18080".to_owned(),
                "--proxy-bypass-list=<-loopback>".to_owned(),
                "--disable-quic".to_owned(),
                "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"
                    .to_owned(),
            ],
        );
        assert!(matches!(
            chromium_station_egress_args(
                "192.0.2.1:18080".parse().expect("non-loopback endpoint")
            ),
            Err(WorkerError::InvalidInput)
        ));
        assert!(matches!(
            chromium_station_egress_args(
                "127.0.0.1:0".parse().expect("zero-port endpoint")
            ),
            Err(WorkerError::InvalidInput)
        ));
    }
}
