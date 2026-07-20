use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use dig2browser::agentic::{
    BrowserWorker, BrowserWorkerConfig, CapabilitySet, WorkerError,
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

/// Launch boundary for one concrete browser runtime.
pub trait RuntimeFactory: Send + Sync {
    fn descriptor(&self) -> &RuntimeDescriptor;

    /// Probe current host readiness without creating a profile or process.
    fn probe_version(&self) -> Result<Option<String>, RuntimeRegistryError>;

    fn spawn(
        &self,
        identity: IdentityProfile,
        capabilities: CapabilitySet,
        config: BrowserWorkerConfig,
    ) -> Result<BrowserWorker, WorkerError>;
}

/// Station-owned catalog of concrete runtime adapters.
#[derive(Clone)]
pub struct RuntimeRegistry {
    factories: HashMap<RuntimeKind, Arc<dyn RuntimeFactory>>,
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
            .register(ChromiumRuntimeFactory::chrome(), true)
            .expect("built-in Chrome runtime kind must be unique");
        registry
            .register(ChromiumRuntimeFactory::edge(), true)
            .expect("built-in Edge runtime kind must be unique");
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
        let kind = factory.descriptor().kind();
        if self.factories.contains_key(&kind) {
            return Err(RuntimeRegistryError::DuplicateRuntime(kind));
        }
        self.factories.insert(kind, Arc::new(factory));
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
        let factory = Arc::clone(
            self.factories
                .get(&kind)
                .ok_or(RuntimeRegistryError::NotRegistered(kind))?,
        );
        let resolved = factory
            .descriptor()
            .negotiate_all(requirement_sets, None)
            .map_err(|source| RuntimeRegistryError::Incompatible { kind, source })?;
        let version = factory.probe_version()?;
        let resolved = resolved.with_version(version);
        Ok(PreparedRuntime { factory, resolved })
    }
}

impl Default for RuntimeRegistry {
    fn default() -> Self {
        Self::chromium_defaults()
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
}

impl PreparedRuntime {
    pub(crate) fn resolved(&self) -> &ResolvedRuntime {
        &self.resolved
    }

    pub(crate) fn spawn(
        &self,
        identity: IdentityProfile,
        capabilities: CapabilitySet,
        config: BrowserWorkerConfig,
    ) -> Result<BrowserWorker, WorkerError> {
        self.factory.spawn(identity, capabilities, config)
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
}

impl RuntimeFactory for ChromiumRuntimeFactory {
    fn descriptor(&self) -> &RuntimeDescriptor {
        &self.descriptor
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
        mut config: BrowserWorkerConfig,
    ) -> Result<BrowserWorker, WorkerError> {
        config.launch.browser_pref = self.preference;
        // The default is a Chrome UA. An explicit runtime must derive its UA
        // and client-hint brand from the browser actually selected above.
        config.stealth.user_agent.clear();
        BrowserWorker::spawn(identity, capabilities, config)
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
}
