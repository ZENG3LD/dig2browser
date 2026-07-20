//! Runtime identity, capability truth, and fail-closed negotiation.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RuntimeKind {
    Chrome,
    Edge,
    Firefox,
    Lightweight,
    Android,
    WebView2,
    Servo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuntimeSelector {
    Auto,
    Exact(RuntimeKind),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EngineFamily {
    Chromium,
    Gecko,
    Dig2Lightweight,
    AndroidChromium,
    WebView2,
    Servo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ControlTransport {
    Cdp,
    WebDriverBidi,
    Native,
    Adb,
    Embedder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RuntimeFeature {
    PointerInput,
    KeyboardInput,
    ScrollInput,
    DomInspect,
    DomInteract,
    ScriptEvaluate,
    Navigate,
    CaptureState,
    CaptureHtml,
    CaptureViewportPng,
    Lifecycle,
    PersistentProfile,
    HeadfulAuthentication,
    DesktopWeb,
    MobileWebEmulation,
    NativeMobileDevice,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SupportLevel {
    Native,
    Emulated,
    Partial,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuntimeLimitation {
    NoNativeMobileApis,
    NoCarrierState,
    NoHardwareAttestation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeatureSupport {
    feature: RuntimeFeature,
    level: SupportLevel,
    limitations: Vec<RuntimeLimitation>,
}

impl FeatureSupport {
    pub fn new(
        feature: RuntimeFeature,
        level: SupportLevel,
        limitations: Vec<RuntimeLimitation>,
    ) -> Self {
        Self {
            feature,
            level,
            limitations,
        }
    }

    pub fn feature(&self) -> RuntimeFeature {
        self.feature
    }

    pub fn level(&self) -> SupportLevel {
        self.level
    }

    pub fn limitations(&self) -> &[RuntimeLimitation] {
        &self.limitations
    }
}

/// A runtime's version-independent declaration of actual support.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeDescriptor {
    kind: RuntimeKind,
    engine: EngineFamily,
    control: ControlTransport,
    features: Vec<FeatureSupport>,
}

impl RuntimeDescriptor {
    pub fn new(
        kind: RuntimeKind,
        engine: EngineFamily,
        control: ControlTransport,
        features: Vec<FeatureSupport>,
    ) -> Result<Self, RuntimeDescriptorError> {
        if let Some(feature) = duplicate_feature(features.iter().map(FeatureSupport::feature)) {
            return Err(RuntimeDescriptorError::DuplicateFeature(feature));
        }
        Ok(Self {
            kind,
            engine,
            control,
            features,
        })
    }

    pub fn kind(&self) -> RuntimeKind {
        self.kind
    }

    pub fn engine(&self) -> EngineFamily {
        self.engine
    }

    pub fn control(&self) -> ControlTransport {
        self.control
    }

    pub fn features(&self) -> &[FeatureSupport] {
        &self.features
    }

    pub fn support_for(&self, feature: RuntimeFeature) -> Option<&FeatureSupport> {
        self.features.iter().find(|support| support.feature == feature)
    }

    /// Negotiate requirements without starting or creating a runtime profile.
    pub fn negotiate(
        &self,
        requirements: &RuntimeRequirements,
        version: Option<String>,
    ) -> Result<ResolvedRuntime, NegotiationError> {
        self.negotiate_all(&[requirements], version)
    }

    /// Negotiate independent requirement sets without letting one set's
    /// partial-support policy weaken another set.
    pub fn negotiate_all(
        &self,
        requirement_sets: &[&RuntimeRequirements],
        version: Option<String>,
    ) -> Result<ResolvedRuntime, NegotiationError> {
        let capacity = requirement_sets
            .iter()
            .map(|requirements| requirements.features.len())
            .sum();
        let mut granted: Vec<FeatureSupport> = Vec::with_capacity(capacity);
        for requirements in requirement_sets {
            for feature in &requirements.features {
                let support = self
                    .support_for(*feature)
                    .ok_or(NegotiationError::MissingFeature(*feature))?;
                match support.level {
                    SupportLevel::Native | SupportLevel::Emulated => {}
                    SupportLevel::Partial if requirements.allow_partial => {}
                    SupportLevel::Partial => {
                        return Err(NegotiationError::PartialSupportDenied(*feature));
                    }
                    SupportLevel::Unsupported => {
                        return Err(NegotiationError::UnsupportedFeature(*feature));
                    }
                }
                if !granted
                    .iter()
                    .any(|granted| granted.feature == *feature)
                {
                    granted.push(support.clone());
                }
            }
        }
        Ok(ResolvedRuntime {
            kind: self.kind,
            engine: self.engine,
            control: self.control,
            version,
            granted,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeRequirements {
    features: Vec<RuntimeFeature>,
    allow_partial: bool,
}

impl RuntimeRequirements {
    pub fn new(
        features: Vec<RuntimeFeature>,
        allow_partial: bool,
    ) -> Result<Self, RuntimeRequirementsError> {
        if let Some(feature) = duplicate_feature(features.iter().copied()) {
            return Err(RuntimeRequirementsError::DuplicateFeature(feature));
        }
        Ok(Self {
            features,
            allow_partial,
        })
    }

    pub fn features(&self) -> &[RuntimeFeature] {
        &self.features
    }

    pub fn allow_partial(&self) -> bool {
        self.allow_partial
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRuntime {
    kind: RuntimeKind,
    engine: EngineFamily,
    control: ControlTransport,
    version: Option<String>,
    granted: Vec<FeatureSupport>,
}

impl ResolvedRuntime {
    pub fn kind(&self) -> RuntimeKind {
        self.kind
    }

    pub fn engine(&self) -> EngineFamily {
        self.engine
    }

    pub fn control(&self) -> ControlTransport {
        self.control
    }

    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    pub fn granted(&self) -> &[FeatureSupport] {
        &self.granted
    }

    pub fn with_version(mut self, version: Option<String>) -> Self {
        self.version = version;
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeDescriptorError {
    DuplicateFeature(RuntimeFeature),
}

impl fmt::Display for RuntimeDescriptorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateFeature(feature) => {
                write!(formatter, "runtime descriptor declares {feature:?} more than once")
            }
        }
    }
}

impl std::error::Error for RuntimeDescriptorError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeRequirementsError {
    DuplicateFeature(RuntimeFeature),
}

impl fmt::Display for RuntimeRequirementsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateFeature(feature) => {
                write!(formatter, "runtime requirements contain {feature:?} more than once")
            }
        }
    }
}

impl std::error::Error for RuntimeRequirementsError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegotiationError {
    MissingFeature(RuntimeFeature),
    UnsupportedFeature(RuntimeFeature),
    PartialSupportDenied(RuntimeFeature),
}

impl fmt::Display for NegotiationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingFeature(feature) => {
                write!(formatter, "runtime does not declare required feature {feature:?}")
            }
            Self::UnsupportedFeature(feature) => {
                write!(formatter, "runtime does not support required feature {feature:?}")
            }
            Self::PartialSupportDenied(feature) => write!(
                formatter,
                "runtime only partially supports required feature {feature:?}"
            ),
        }
    }
}

impl std::error::Error for NegotiationError {}

fn duplicate_feature(features: impl IntoIterator<Item = RuntimeFeature>) -> Option<RuntimeFeature> {
    let mut seen = Vec::new();
    for feature in features {
        if seen.contains(&feature) {
            return Some(feature);
        }
        seen.push(feature);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn support(feature: RuntimeFeature, level: SupportLevel) -> FeatureSupport {
        FeatureSupport::new(feature, level, Vec::new())
    }

    fn descriptor(features: Vec<FeatureSupport>) -> RuntimeDescriptor {
        RuntimeDescriptor::new(
            RuntimeKind::Chrome,
            EngineFamily::Chromium,
            ControlTransport::Cdp,
            features,
        )
        .expect("test descriptor must be valid")
    }

    fn requirements(
        features: Vec<RuntimeFeature>,
        allow_partial: bool,
    ) -> RuntimeRequirements {
        RuntimeRequirements::new(features, allow_partial)
            .expect("test requirements must be valid")
    }

    #[test]
    fn full_native_support_is_granted() {
        let descriptor = descriptor(vec![support(
            RuntimeFeature::Navigate,
            SupportLevel::Native,
        )]);
        let requirements = requirements(vec![RuntimeFeature::Navigate], false);

        let resolved = descriptor
            .negotiate(&requirements, Some("127.0.0".to_owned()))
            .expect("native support must satisfy the requirement");

        assert_eq!(resolved.kind(), RuntimeKind::Chrome);
        assert_eq!(resolved.engine(), EngineFamily::Chromium);
        assert_eq!(resolved.control(), ControlTransport::Cdp);
        assert_eq!(resolved.version(), Some("127.0.0"));
        assert_eq!(resolved.granted(), descriptor.features());
    }

    #[test]
    fn emulated_support_is_granted() {
        let descriptor = descriptor(vec![support(
            RuntimeFeature::MobileWebEmulation,
            SupportLevel::Emulated,
        )]);
        let requirements = requirements(vec![RuntimeFeature::MobileWebEmulation], false);

        let resolved = descriptor
            .negotiate(&requirements, None)
            .expect("emulated support must satisfy the requirement");

        assert_eq!(resolved.granted()[0].level(), SupportLevel::Emulated);
    }

    #[test]
    fn partial_support_is_rejected_by_default() {
        let descriptor = descriptor(vec![support(
            RuntimeFeature::DomInspect,
            SupportLevel::Partial,
        )]);
        let requirements = requirements(vec![RuntimeFeature::DomInspect], false);

        assert_eq!(
            descriptor.negotiate(&requirements, None),
            Err(NegotiationError::PartialSupportDenied(
                RuntimeFeature::DomInspect
            ))
        );
    }

    #[test]
    fn partial_support_can_be_explicitly_granted() {
        let descriptor = descriptor(vec![FeatureSupport::new(
            RuntimeFeature::MobileWebEmulation,
            SupportLevel::Partial,
            vec![RuntimeLimitation::NoNativeMobileApis],
        )]);
        let requirements = requirements(vec![RuntimeFeature::MobileWebEmulation], true);

        let resolved = descriptor
            .negotiate(&requirements, None)
            .expect("partial support must be granted when explicitly allowed");

        assert_eq!(
            resolved.granted()[0].limitations(),
            &[RuntimeLimitation::NoNativeMobileApis]
        );
    }

    #[test]
    fn missing_support_fails_closed() {
        let descriptor = descriptor(Vec::new());
        let requirements = requirements(vec![RuntimeFeature::CaptureHtml], false);

        assert_eq!(
            descriptor.negotiate(&requirements, None),
            Err(NegotiationError::MissingFeature(
                RuntimeFeature::CaptureHtml
            ))
        );
    }

    #[test]
    fn explicitly_unsupported_feature_fails_closed() {
        let descriptor = descriptor(vec![support(
            RuntimeFeature::NativeMobileDevice,
            SupportLevel::Unsupported,
        )]);
        let requirements = requirements(vec![RuntimeFeature::NativeMobileDevice], true);

        assert_eq!(
            descriptor.negotiate(&requirements, None),
            Err(NegotiationError::UnsupportedFeature(
                RuntimeFeature::NativeMobileDevice
            ))
        );
    }

    #[test]
    fn duplicate_declarations_and_requirements_are_rejected() {
        let declarations = RuntimeDescriptor::new(
            RuntimeKind::Chrome,
            EngineFamily::Chromium,
            ControlTransport::Cdp,
            vec![
                support(RuntimeFeature::Navigate, SupportLevel::Native),
                support(RuntimeFeature::Navigate, SupportLevel::Emulated),
            ],
        );
        assert_eq!(
            declarations,
            Err(RuntimeDescriptorError::DuplicateFeature(
                RuntimeFeature::Navigate
            ))
        );

        let requirements = RuntimeRequirements::new(
            vec![RuntimeFeature::Navigate, RuntimeFeature::Navigate],
            false,
        );
        assert_eq!(
            requirements,
            Err(RuntimeRequirementsError::DuplicateFeature(
                RuntimeFeature::Navigate
            ))
        );
    }

    #[test]
    fn independent_requirement_sets_keep_their_partial_policy() {
        let descriptor = descriptor(vec![
            support(RuntimeFeature::Navigate, SupportLevel::Native),
            support(RuntimeFeature::DomInspect, SupportLevel::Partial),
        ]);
        let base = requirements(vec![RuntimeFeature::Navigate], false);
        let optional = requirements(vec![RuntimeFeature::DomInspect], true);
        let resolved = descriptor
            .negotiate_all(&[&base, &optional], None)
            .expect("partial policy applies only to the optional set");
        assert_eq!(resolved.granted().len(), 2);

        let strict = requirements(vec![RuntimeFeature::DomInspect], false);
        assert_eq!(
            descriptor.negotiate_all(&[&base, &optional, &strict], None),
            Err(NegotiationError::PartialSupportDenied(
                RuntimeFeature::DomInspect
            ))
        );
    }
}
