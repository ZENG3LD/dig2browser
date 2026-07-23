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

/// Stable persona selection mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PersonaMode {
    PrivacyCohort,
    NamedCompatibility,
}

/// Device class described by a compiled browser persona.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PersonaDeviceClass {
    Desktop,
    MobileWeb,
}

impl PersonaDeviceClass {
    /// Declared CPU thread count (`navigator.hardwareConcurrency`).
    ///
    /// Desktop: unchanged from the prior fixed 8-thread default (a common
    /// mid-range baseline). Mobile: the real Pixel 7 (Tensor G2) is
    /// 2x Cortex-X1 + 2x Cortex-A78 + 4x Cortex-A55 = 8 threads, so the
    /// value is coincidentally identical but now explicit and sourced from
    /// the persona rather than a shared hardcoded default.
    pub const fn hardware_concurrency(self) -> u8 {
        match self {
            Self::Desktop => 8,
            Self::MobileWeb => 8,
        }
    }

    /// Declared device memory in GB (`navigator.deviceMemory`).
    ///
    /// Desktop: unchanged from the prior fixed 8 GB default. Mobile: the
    /// real Pixel 7 base configuration ships 8 GB RAM.
    pub const fn device_memory_gb(self) -> u8 {
        match self {
            Self::Desktop => 8,
            Self::MobileWeb => 8,
        }
    }

    /// `WEBGL_debug_renderer_info` `UNMASKED_VENDOR_WEBGL` string for this
    /// device class.
    pub const fn webgl_vendor(self) -> &'static str {
        match self {
            Self::Desktop => "Google Inc. (NVIDIA)",
            Self::MobileWeb => "ARM",
        }
    }

    /// `WEBGL_debug_renderer_info` `UNMASKED_RENDERER_WEBGL` string for this
    /// device class.
    ///
    /// Mobile: the real Pixel 7 (Tensor G2) GPU is a Mali-G710. This only
    /// controls the two *queried* strings — the underlying GL pipeline
    /// (extension list, shader precision, draw timing) is still the real
    /// host GPU regardless (see
    /// `dig2browser/src/stealth/scripts.rs::override_webgl_vendor`).
    pub const fn webgl_renderer(self) -> &'static str {
        match self {
            Self::Desktop => {
                "ANGLE (NVIDIA, NVIDIA GeForce GTX 1080 Direct3D11 vs_5_0 ps_5_0, D3D11)"
            }
            Self::MobileWeb => "Mali-G710",
        }
    }
}

/// Versioned persona presets with stable names and runtime compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PersonaPreset {
    ChromiumDesktopPrivacyCohortV1,
    ChromeWindowsDesktopV1,
    EdgeWindowsDesktopV1,
    FirefoxWindowsDesktopV1,
    ChromeAndroidPixel7MobileWebV1,
}

impl PersonaPreset {
    pub const ALL: [Self; 5] = [
        Self::ChromiumDesktopPrivacyCohortV1,
        Self::ChromeWindowsDesktopV1,
        Self::EdgeWindowsDesktopV1,
        Self::FirefoxWindowsDesktopV1,
        Self::ChromeAndroidPixel7MobileWebV1,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ChromiumDesktopPrivacyCohortV1 => {
                "chromium-desktop-privacy-cohort-v1"
            }
            Self::ChromeWindowsDesktopV1 => "chrome-windows-desktop-v1",
            Self::EdgeWindowsDesktopV1 => "edge-windows-desktop-v1",
            Self::FirefoxWindowsDesktopV1 => "firefox-windows-desktop-v1",
            Self::ChromeAndroidPixel7MobileWebV1 => {
                "chrome-android-pixel7-mobile-web-v1"
            }
        }
    }

    pub const fn mode(self) -> PersonaMode {
        match self {
            Self::ChromiumDesktopPrivacyCohortV1 => PersonaMode::PrivacyCohort,
            Self::ChromeWindowsDesktopV1
            | Self::EdgeWindowsDesktopV1
            | Self::FirefoxWindowsDesktopV1
            | Self::ChromeAndroidPixel7MobileWebV1 => PersonaMode::NamedCompatibility,
        }
    }

    pub const fn device_class(self) -> PersonaDeviceClass {
        match self {
            Self::ChromeAndroidPixel7MobileWebV1 => PersonaDeviceClass::MobileWeb,
            Self::ChromiumDesktopPrivacyCohortV1
            | Self::ChromeWindowsDesktopV1
            | Self::EdgeWindowsDesktopV1
            | Self::FirefoxWindowsDesktopV1 => PersonaDeviceClass::Desktop,
        }
    }

    pub const fn required_runtime(self) -> Option<RuntimeKind> {
        match self {
            Self::ChromiumDesktopPrivacyCohortV1 => None,
            Self::ChromeWindowsDesktopV1
            | Self::ChromeAndroidPixel7MobileWebV1 => Some(RuntimeKind::Chrome),
            Self::EdgeWindowsDesktopV1 => Some(RuntimeKind::Edge),
            Self::FirefoxWindowsDesktopV1 => Some(RuntimeKind::Firefox),
        }
    }

    pub const fn supports_runtime(self, runtime: RuntimeKind) -> bool {
        match self {
            Self::ChromiumDesktopPrivacyCohortV1 => {
                matches!(runtime, RuntimeKind::Chrome | RuntimeKind::Edge)
            }
            Self::ChromeWindowsDesktopV1
            | Self::ChromeAndroidPixel7MobileWebV1 => {
                matches!(runtime, RuntimeKind::Chrome)
            }
            Self::EdgeWindowsDesktopV1 => matches!(runtime, RuntimeKind::Edge),
            Self::FirefoxWindowsDesktopV1 => matches!(runtime, RuntimeKind::Firefox),
        }
    }
}

/// Opaque, validated routing identity carried with compiled personas.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RouteRef(String);

pub const HOST_DIRECT: &str = "host.direct";

impl RouteRef {
    pub fn new(value: impl Into<String>) -> Result<Self, RouteRefError> {
        let value = value.into();
        if value.is_empty() || value.len() > 64 {
            return Err(RouteRefError::InvalidLength);
        }
        if !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
        }) {
            return Err(RouteRefError::InvalidCharacter);
        }
        Ok(Self(value))
    }

    pub fn host_direct() -> Self {
        Self(HOST_DIRECT.to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for RouteRef {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for RouteRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteRefError {
    InvalidLength,
    InvalidCharacter,
}

impl fmt::Display for RouteRefError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength => formatter.write_str("route reference must contain 1 to 64 bytes"),
            Self::InvalidCharacter => formatter.write_str(
                "route reference contains a character outside ASCII letters, digits, dot, underscore, and hyphen",
            ),
        }
    }
}

impl std::error::Error for RouteRefError {}

/// Fully materialized persona fields produced from a versioned preset.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CompiledPersona {
    preset: PersonaPreset,
    route_ref: RouteRef,
    width: u16,
    height: u16,
    device_scale_milli: u16,
    max_touch_points: u8,
    locale: &'static str,
    timezone: Option<&'static str>,
    platform_version: &'static str,
    model: &'static str,
    hardware_concurrency: u8,
    device_memory_gb: u8,
    webgl_vendor: &'static str,
    webgl_renderer: &'static str,
}

impl CompiledPersona {
    pub fn preset(&self) -> PersonaPreset {
        self.preset
    }

    pub fn route_ref(&self) -> &RouteRef {
        &self.route_ref
    }

    pub fn device_class(&self) -> PersonaDeviceClass {
        self.preset.device_class()
    }

    pub fn width(&self) -> u16 {
        self.width
    }

    pub fn height(&self) -> u16 {
        self.height
    }

    pub fn device_scale_milli(&self) -> u16 {
        self.device_scale_milli
    }

    pub fn device_scale_factor(&self) -> f64 {
        f64::from(self.device_scale_milli) / 1000.0
    }

    pub fn max_touch_points(&self) -> u8 {
        self.max_touch_points
    }

    pub fn locale(&self) -> &'static str {
        self.locale
    }

    pub fn timezone(&self) -> Option<&'static str> {
        self.timezone
    }

    pub fn platform(&self) -> &'static str {
        match self.device_class() {
            PersonaDeviceClass::Desktop => "Windows",
            PersonaDeviceClass::MobileWeb => "Android",
        }
    }

    pub fn platform_version(&self) -> &'static str {
        self.platform_version
    }

    pub fn architecture(&self) -> &'static str {
        match self.device_class() {
            PersonaDeviceClass::Desktop => "x86",
            PersonaDeviceClass::MobileWeb => "",
        }
    }

    pub fn model(&self) -> &'static str {
        self.model
    }

    pub fn hardware_concurrency(&self) -> u8 {
        self.hardware_concurrency
    }

    pub fn device_memory_gb(&self) -> u8 {
        self.device_memory_gb
    }

    pub fn webgl_vendor(&self) -> &'static str {
        self.webgl_vendor
    }

    pub fn webgl_renderer(&self) -> &'static str {
        self.webgl_renderer
    }

    pub fn is_mobile(&self) -> bool {
        self.device_class() == PersonaDeviceClass::MobileWeb
    }
}

/// Dependency-free compiler for stable browser persona presets.
pub struct PersonaCompiler;

impl PersonaCompiler {
    pub fn compile(preset: PersonaPreset, route_ref: RouteRef) -> CompiledPersona {
        let (
            width,
            height,
            device_scale_milli,
            max_touch_points,
            platform_version,
            model,
        ) = match preset.device_class() {
            PersonaDeviceClass::Desktop => (1920, 1080, 1000, 0, "15.0.0", ""),
            PersonaDeviceClass::MobileWeb => {
                (393, 852, 3000, 5, "13.0.0", "Pixel 7")
            }
        };
        let device_class = preset.device_class();
        CompiledPersona {
            preset,
            route_ref,
            width,
            height,
            device_scale_milli,
            max_touch_points,
            locale: "en-US",
            timezone: Some("UTC"),
            platform_version,
            model,
            hardware_concurrency: device_class.hardware_concurrency(),
            device_memory_gb: device_class.device_memory_gb(),
            webgl_vendor: device_class.webgl_vendor(),
            webgl_renderer: device_class.webgl_renderer(),
        }
    }
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
    /// Runtime-owned web session state survives worker recreation.
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
    NoScriptExecution,
    NoVisualRendering,
    NoInteractiveDom,
    NoSubresourceLoading,
    NoPersonaEmulation,
    Utf8HtmlOnly,
    NoBrowserSessionState,
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

    #[test]
    fn persona_compiler_presets_are_stable_and_runtime_compatible() {
        let route = RouteRef::host_direct();
        let cases = [
            (
                PersonaPreset::ChromiumDesktopPrivacyCohortV1,
                "chromium-desktop-privacy-cohort-v1",
                PersonaMode::PrivacyCohort,
                PersonaDeviceClass::Desktop,
                None,
            ),
            (
                PersonaPreset::ChromeWindowsDesktopV1,
                "chrome-windows-desktop-v1",
                PersonaMode::NamedCompatibility,
                PersonaDeviceClass::Desktop,
                Some(RuntimeKind::Chrome),
            ),
            (
                PersonaPreset::EdgeWindowsDesktopV1,
                "edge-windows-desktop-v1",
                PersonaMode::NamedCompatibility,
                PersonaDeviceClass::Desktop,
                Some(RuntimeKind::Edge),
            ),
            (
                PersonaPreset::FirefoxWindowsDesktopV1,
                "firefox-windows-desktop-v1",
                PersonaMode::NamedCompatibility,
                PersonaDeviceClass::Desktop,
                Some(RuntimeKind::Firefox),
            ),
            (
                PersonaPreset::ChromeAndroidPixel7MobileWebV1,
                "chrome-android-pixel7-mobile-web-v1",
                PersonaMode::NamedCompatibility,
                PersonaDeviceClass::MobileWeb,
                Some(RuntimeKind::Chrome),
            ),
        ];

        assert_eq!(PersonaPreset::ALL, cases.map(|case| case.0));
        for (preset, name, mode, device_class, required_runtime) in cases {
            assert_eq!(preset.as_str(), name);
            assert_eq!(preset.mode(), mode);
            assert_eq!(preset.device_class(), device_class);
            assert_eq!(preset.required_runtime(), required_runtime);
            let compiled = PersonaCompiler::compile(preset, route.clone());
            assert_eq!(compiled.preset(), preset);
            assert_eq!(compiled.route_ref(), &route);
            assert_eq!(compiled.locale(), "en-US");
            assert_eq!(compiled.timezone(), Some("UTC"));
            match device_class {
                PersonaDeviceClass::Desktop => {
                    assert_eq!(compiled.width(), 1920);
                    assert_eq!(compiled.height(), 1080);
                    assert_eq!(compiled.device_scale_milli(), 1000);
                    assert_eq!(compiled.device_scale_factor(), 1.0);
                    assert_eq!(compiled.max_touch_points(), 0);
                    assert_eq!(compiled.platform(), "Windows");
                    assert_eq!(compiled.platform_version(), "15.0.0");
                    assert_eq!(compiled.architecture(), "x86");
                    assert_eq!(compiled.model(), "");
                    assert_eq!(compiled.hardware_concurrency(), 8);
                    assert_eq!(compiled.device_memory_gb(), 8);
                    assert_eq!(compiled.webgl_vendor(), "Google Inc. (NVIDIA)");
                    assert_eq!(
                        compiled.webgl_renderer(),
                        "ANGLE (NVIDIA, NVIDIA GeForce GTX 1080 Direct3D11 vs_5_0 ps_5_0, D3D11)"
                    );
                    assert!(!compiled.is_mobile());
                }
                PersonaDeviceClass::MobileWeb => {
                    assert_eq!(compiled.width(), 393);
                    assert_eq!(compiled.height(), 852);
                    assert_eq!(compiled.device_scale_milli(), 3000);
                    assert_eq!(compiled.device_scale_factor(), 3.0);
                    assert_eq!(compiled.max_touch_points(), 5);
                    assert_eq!(compiled.platform(), "Android");
                    assert_eq!(compiled.platform_version(), "13.0.0");
                    assert_eq!(compiled.architecture(), "");
                    assert_eq!(compiled.model(), "Pixel 7");
                    assert_eq!(compiled.hardware_concurrency(), 8);
                    assert_eq!(compiled.device_memory_gb(), 8);
                    assert_eq!(compiled.webgl_vendor(), "ARM");
                    assert_eq!(compiled.webgl_renderer(), "Mali-G710");
                    assert!(compiled.is_mobile());
                }
            }
        }

        assert!(PersonaPreset::ChromiumDesktopPrivacyCohortV1
            .supports_runtime(RuntimeKind::Chrome));
        assert!(PersonaPreset::ChromiumDesktopPrivacyCohortV1
            .supports_runtime(RuntimeKind::Edge));
        assert!(!PersonaPreset::ChromiumDesktopPrivacyCohortV1
            .supports_runtime(RuntimeKind::Firefox));
        assert!(PersonaPreset::ChromeWindowsDesktopV1
            .supports_runtime(RuntimeKind::Chrome));
        assert!(!PersonaPreset::ChromeWindowsDesktopV1
            .supports_runtime(RuntimeKind::Edge));
        assert!(PersonaPreset::EdgeWindowsDesktopV1
            .supports_runtime(RuntimeKind::Edge));
        assert!(!PersonaPreset::EdgeWindowsDesktopV1
            .supports_runtime(RuntimeKind::Chrome));
        assert!(PersonaPreset::FirefoxWindowsDesktopV1
            .supports_runtime(RuntimeKind::Firefox));
        assert!(!PersonaPreset::FirefoxWindowsDesktopV1
            .supports_runtime(RuntimeKind::Chrome));
        assert!(PersonaPreset::ChromeAndroidPixel7MobileWebV1
            .supports_runtime(RuntimeKind::Chrome));
        assert!(!PersonaPreset::ChromeAndroidPixel7MobileWebV1
            .supports_runtime(RuntimeKind::Android));
    }

    #[test]
    fn route_references_reject_url_and_delimiter_injection() {
        assert_eq!(RouteRef::host_direct().as_str(), HOST_DIRECT);
        for valid in ["A", "host.direct", "Proxy_01-west"] {
            assert_eq!(RouteRef::new(valid).expect("valid route").as_str(), valid);
        }
        assert!(RouteRef::new("a".repeat(64)).is_ok());
        for malicious in [
            "",
            "https://proxy.test",
            "proxy:8080",
            "user@proxy",
            "path/to/proxy",
            "proxy route",
            "line\nbreak",
            "proxy-ё",
        ] {
            assert!(RouteRef::new(malicious).is_err(), "accepted {malicious:?}");
        }
        assert!(RouteRef::new("a".repeat(65)).is_err());
    }

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
