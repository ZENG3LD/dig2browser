//! Typed, bounded observations for a controlled browser probe origin.
//!
//! A transcript attests only to the allowlisted values observed by the probe.
//! It does not attest to GPU identity, TLS fingerprint, egress IP, native
//! Android behavior, physical-device equivalence, carrier state, or hardware
//! attestation. Exact viewport checks assume the controlled page supplies a
//! viewport meta tag and does not alter its own layout viewport.

use std::fmt;

use dig2browser_core::{
    ControlTransport, EngineFamily, PersonaPreset, PersonaWebrtc, RuntimeFeature, RuntimeKind,
};
use dig2browser_protocol::{BrowserPersona, ResolvedRuntimeRecord};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PROBE_SCHEMA_ID: &str = "dig2browser.controlled-origin-probe.v1";
pub const MAX_PROBE_JSON_BYTES: usize = 64 * 1024;

const MAX_USER_AGENT_BYTES: usize = 1024;
const MAX_LANGUAGE_BYTES: usize = 35;
const MAX_TIMEZONE_BYTES: usize = 64;
const MAX_PLATFORM_BYTES: usize = 64;
const MAX_ACCEPT_LANGUAGE_BYTES: usize = 512;
const MAX_RUNTIME_VERSION_BYTES: usize = 128;
const MAX_DIMENSION: u16 = 16_384;
const MAX_DPR_MILLI: u16 = 10_000;
const MAX_TOUCH_POINTS: u8 = 20;
const MAX_COLOR_DEPTH: u8 = 64;
const MAX_HARDWARE_CONCURRENCY: u8 = 128;
/// `navigator.deviceMemory` is spec-capped at 8 GB for fingerprinting
/// mitigation (real Chrome never reports higher regardless of installed
/// RAM), so this is an honest ceiling, not an arbitrary probe limit.
const MAX_DEVICE_MEMORY_GB: u8 = 8;
const MAX_WEBGL_STRING_BYTES: usize = 256;

/// Browser-visible fields collected by the controlled probe page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserObservationV1 {
    pub user_agent: String,
    pub platform: String,
    pub language: String,
    pub timezone: String,
    pub ua_mobile: bool,
    pub ua_platform: String,
    pub inner_width: u16,
    pub inner_height: u16,
    pub screen_width: u16,
    pub screen_height: u16,
    pub dpr_milli: u16,
    pub max_touch_points: u8,
    pub coarse_pointer: bool,
    pub hover: bool,
    pub webdriver: bool,
    pub color_depth: u8,
    pub hardware_concurrency: u8,
    pub device_memory: u8,
    pub webgl_vendor: String,
    pub webgl_renderer: String,
    /// `typeof RTCPeerConnection !== 'undefined'` — presence check only, no
    /// ICE-candidate/IP-leak gathering.
    pub webrtc_present: bool,
}

/// Server-visible request values normalized by the controlled probe origin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServerObservationV1 {
    pub user_agent: String,
    pub accept_language: String,
    pub sec_ch_ua_mobile: String,
    pub sec_ch_ua_platform: String,
}

/// The complete allowlisted input accepted from the controlled origin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProbeObservationV1 {
    pub browser: BrowserObservationV1,
    pub server: ServerObservationV1,
}

impl ProbeObservationV1 {
    pub fn decode_json(json: &str) -> Result<Self, ProbeError> {
        if json.len() > MAX_PROBE_JSON_BYTES {
            return Err(ProbeError::ObservationTooLarge {
                actual: json.len(),
                maximum: MAX_PROBE_JSON_BYTES,
            });
        }
        let observation: Self = serde_json::from_str(json)
            .map_err(ProbeError::InvalidJson)?;
        observation.validate_bounds()?;
        Ok(observation)
    }

    fn validate_bounds(&self) -> Result<(), ProbeError> {
        validate_text("browser.userAgent", &self.browser.user_agent, MAX_USER_AGENT_BYTES)?;
        validate_text("browser.platform", &self.browser.platform, MAX_PLATFORM_BYTES)?;
        validate_text("browser.language", &self.browser.language, MAX_LANGUAGE_BYTES)?;
        validate_text("browser.timezone", &self.browser.timezone, MAX_TIMEZONE_BYTES)?;
        validate_text("browser.uaPlatform", &self.browser.ua_platform, MAX_PLATFORM_BYTES)?;
        validate_text("server.userAgent", &self.server.user_agent, MAX_USER_AGENT_BYTES)?;
        validate_text(
            "server.acceptLanguage",
            &self.server.accept_language,
            MAX_ACCEPT_LANGUAGE_BYTES,
        )?;
        validate_text("server.secChUaMobile", &self.server.sec_ch_ua_mobile, 8)?;
        validate_text(
            "server.secChUaPlatform",
            &self.server.sec_ch_ua_platform,
            MAX_PLATFORM_BYTES + 2,
        )?;
        validate_number("browser.innerWidth", self.browser.inner_width, 1, MAX_DIMENSION)?;
        validate_number("browser.innerHeight", self.browser.inner_height, 1, MAX_DIMENSION)?;
        validate_number("browser.screenWidth", self.browser.screen_width, 1, MAX_DIMENSION)?;
        validate_number("browser.screenHeight", self.browser.screen_height, 1, MAX_DIMENSION)?;
        validate_number("browser.dprMilli", self.browser.dpr_milli, 100, MAX_DPR_MILLI)?;
        validate_number(
            "browser.maxTouchPoints",
            self.browser.max_touch_points,
            0,
            MAX_TOUCH_POINTS,
        )?;
        validate_number("browser.colorDepth", self.browser.color_depth, 1, MAX_COLOR_DEPTH)?;
        validate_number(
            "browser.hardwareConcurrency",
            self.browser.hardware_concurrency,
            1,
            MAX_HARDWARE_CONCURRENCY,
        )?;
        validate_number(
            "browser.deviceMemory",
            self.browser.device_memory,
            1,
            MAX_DEVICE_MEMORY_GB,
        )?;
        validate_text("browser.webglVendor", &self.browser.webgl_vendor, MAX_WEBGL_STRING_BYTES)?;
        validate_text(
            "browser.webglRenderer",
            &self.browser.webgl_renderer,
            MAX_WEBGL_STRING_BYTES,
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProbeRuntimeKindV1 {
    Chrome,
    Edge,
    Firefox,
    Lightweight,
    Android,
    WebView2,
    Servo,
}

impl ProbeRuntimeKindV1 {
    fn as_str(self) -> &'static str {
        match self {
            Self::Chrome => "chrome",
            Self::Edge => "edge",
            Self::Firefox => "firefox",
            Self::Lightweight => "lightweight",
            Self::Android => "android",
            Self::WebView2 => "web-view2",
            Self::Servo => "servo",
        }
    }
}

impl From<RuntimeKind> for ProbeRuntimeKindV1 {
    fn from(value: RuntimeKind) -> Self {
        match value {
            RuntimeKind::Chrome => Self::Chrome,
            RuntimeKind::Edge => Self::Edge,
            RuntimeKind::Firefox => Self::Firefox,
            RuntimeKind::Lightweight => Self::Lightweight,
            RuntimeKind::Android => Self::Android,
            RuntimeKind::WebView2 => Self::WebView2,
            RuntimeKind::Servo => Self::Servo,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProbeEngineFamilyV1 {
    Chromium,
    Gecko,
    Dig2Lightweight,
    AndroidChromium,
    WebView2,
    Servo,
}

impl ProbeEngineFamilyV1 {
    fn as_str(self) -> &'static str {
        match self {
            Self::Chromium => "chromium",
            Self::Gecko => "gecko",
            Self::Dig2Lightweight => "dig2-lightweight",
            Self::AndroidChromium => "android-chromium",
            Self::WebView2 => "web-view2",
            Self::Servo => "servo",
        }
    }
}

impl From<EngineFamily> for ProbeEngineFamilyV1 {
    fn from(value: EngineFamily) -> Self {
        match value {
            EngineFamily::Chromium => Self::Chromium,
            EngineFamily::Gecko => Self::Gecko,
            EngineFamily::Dig2Lightweight => Self::Dig2Lightweight,
            EngineFamily::AndroidChromium => Self::AndroidChromium,
            EngineFamily::WebView2 => Self::WebView2,
            EngineFamily::Servo => Self::Servo,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProbeControlTransportV1 {
    Cdp,
    WebDriverBidi,
    Native,
    Adb,
    Embedder,
}

impl ProbeControlTransportV1 {
    fn as_str(self) -> &'static str {
        match self {
            Self::Cdp => "cdp",
            Self::WebDriverBidi => "web-driver-bidi",
            Self::Native => "native",
            Self::Adb => "adb",
            Self::Embedder => "embedder",
        }
    }
}

impl From<ControlTransport> for ProbeControlTransportV1 {
    fn from(value: ControlTransport) -> Self {
        match value {
            ControlTransport::Cdp => Self::Cdp,
            ControlTransport::WebDriverBidi => Self::WebDriverBidi,
            ControlTransport::Native => Self::Native,
            ControlTransport::Adb => Self::Adb,
            ControlTransport::Embedder => Self::Embedder,
        }
    }
}

/// Runtime identity embedded in a validated transcript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeRuntimeV1 {
    kind: ProbeRuntimeKindV1,
    engine: ProbeEngineFamilyV1,
    control: ProbeControlTransportV1,
    version: String,
}

impl ProbeRuntimeV1 {
    pub fn kind(&self) -> ProbeRuntimeKindV1 {
        self.kind
    }

    pub fn engine(&self) -> ProbeEngineFamilyV1 {
        self.engine
    }

    pub fn control(&self) -> ProbeControlTransportV1 {
        self.control
    }

    pub fn version(&self) -> &str {
        &self.version
    }
}

/// A validated persona/runtime/observation binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeTranscriptV1 {
    schema_id: &'static str,
    preset: String,
    route_ref: String,
    runtime: ProbeRuntimeV1,
    observation: ProbeObservationV1,
}

impl ProbeTranscriptV1 {
    pub fn from_observation(
        persona: &BrowserPersona,
        runtime: &ResolvedRuntimeRecord,
        json: &str,
    ) -> Result<Self, ProbeError> {
        if !persona.is_compiled() {
            return Err(ProbeError::UncompiledPersona);
        }
        let preset = persona.preset().ok_or(ProbeError::UncompiledPersona)?;
        let route_ref = persona
            .route_ref()
            .ok_or(ProbeError::UncompiledPersona)?;
        persona.validate().map_err(|_| ProbeError::InvalidPersona)?;

        let version = runtime.version().ok_or(ProbeError::MissingRuntimeVersion)?;
        validate_text("runtime.version", version, MAX_RUNTIME_VERSION_BYTES)?;
        if runtime.granted().is_empty() {
            return Err(ProbeError::MissingRuntimeGrants);
        }
        if let Some(required) = preset.required_runtime() {
            if runtime.kind() != required {
                return Err(ProbeError::RequiredRuntimeMismatch);
            }
        }
        if !preset.supports_runtime(runtime.kind()) {
            return Err(ProbeError::UnsupportedRuntime);
        }
        let required_grant = if persona.is_mobile() {
            RuntimeFeature::MobileWebEmulation
        } else {
            RuntimeFeature::DesktopWeb
        };
        if !runtime
            .granted()
            .iter()
            .any(|support| support.feature() == required_grant)
        {
            return Err(ProbeError::MissingRequiredGrant(required_grant));
        }

        let observation = ProbeObservationV1::decode_json(json)?;
        validate_matrix(persona, preset, runtime.kind(), &observation)?;

        Ok(Self {
            schema_id: PROBE_SCHEMA_ID,
            preset: preset.as_str().to_owned(),
            route_ref: route_ref.as_str().to_owned(),
            runtime: ProbeRuntimeV1 {
                kind: runtime.kind().into(),
                engine: runtime.engine().into(),
                control: runtime.control().into(),
                version: version.to_owned(),
            },
            observation,
        })
    }

    pub fn schema_id(&self) -> &'static str {
        self.schema_id
    }

    pub fn preset(&self) -> &str {
        &self.preset
    }

    pub fn route_ref(&self) -> &str {
        &self.route_ref
    }

    pub fn runtime(&self) -> &ProbeRuntimeV1 {
        &self.runtime
    }

    pub fn observation(&self) -> &ProbeObservationV1 {
        &self.observation
    }

    /// Stable field-tagged bytes. Every tag and value is length-prefixed.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        push_field(&mut bytes, "schemaId", self.schema_id.as_bytes());
        push_field(&mut bytes, "preset", self.preset.as_bytes());
        push_field(&mut bytes, "routeRef", self.route_ref.as_bytes());
        push_field(&mut bytes, "runtime.kind", self.runtime.kind.as_str().as_bytes());
        push_field(
            &mut bytes,
            "runtime.engine",
            self.runtime.engine.as_str().as_bytes(),
        );
        push_field(
            &mut bytes,
            "runtime.control",
            self.runtime.control.as_str().as_bytes(),
        );
        push_field(&mut bytes, "runtime.version", self.runtime.version.as_bytes());
        let browser = &self.observation.browser;
        push_field(&mut bytes, "browser.userAgent", browser.user_agent.as_bytes());
        push_field(&mut bytes, "browser.platform", browser.platform.as_bytes());
        push_field(&mut bytes, "browser.language", browser.language.as_bytes());
        push_field(&mut bytes, "browser.timezone", browser.timezone.as_bytes());
        push_bool(&mut bytes, "browser.uaMobile", browser.ua_mobile);
        push_field(&mut bytes, "browser.uaPlatform", browser.ua_platform.as_bytes());
        push_u16(&mut bytes, "browser.innerWidth", browser.inner_width);
        push_u16(&mut bytes, "browser.innerHeight", browser.inner_height);
        push_u16(&mut bytes, "browser.screenWidth", browser.screen_width);
        push_u16(&mut bytes, "browser.screenHeight", browser.screen_height);
        push_u16(&mut bytes, "browser.dprMilli", browser.dpr_milli);
        push_u8(&mut bytes, "browser.maxTouchPoints", browser.max_touch_points);
        push_bool(&mut bytes, "browser.coarsePointer", browser.coarse_pointer);
        push_bool(&mut bytes, "browser.hover", browser.hover);
        push_bool(&mut bytes, "browser.webdriver", browser.webdriver);
        push_u8(&mut bytes, "browser.colorDepth", browser.color_depth);
        push_u8(&mut bytes, "browser.hardwareConcurrency", browser.hardware_concurrency);
        push_u8(&mut bytes, "browser.deviceMemory", browser.device_memory);
        push_field(&mut bytes, "browser.webglVendor", browser.webgl_vendor.as_bytes());
        push_field(&mut bytes, "browser.webglRenderer", browser.webgl_renderer.as_bytes());
        push_bool(&mut bytes, "browser.webrtcPresent", browser.webrtc_present);
        let server = &self.observation.server;
        push_field(&mut bytes, "server.userAgent", server.user_agent.as_bytes());
        push_field(
            &mut bytes,
            "server.acceptLanguage",
            server.accept_language.as_bytes(),
        );
        push_field(
            &mut bytes,
            "server.secChUaMobile",
            server.sec_ch_ua_mobile.as_bytes(),
        );
        push_field(
            &mut bytes,
            "server.secChUaPlatform",
            server.sec_ch_ua_platform.as_bytes(),
        );
        bytes
    }

    pub fn sha256(&self) -> [u8; 32] {
        Sha256::digest(self.canonical_bytes()).into()
    }
}

#[derive(Debug)]
pub enum ProbeError {
    ObservationTooLarge { actual: usize, maximum: usize },
    InvalidJson(serde_json::Error),
    InvalidPersona,
    UncompiledPersona,
    MissingRuntimeVersion,
    MissingRuntimeGrants,
    RequiredRuntimeMismatch,
    UnsupportedRuntime,
    MissingRequiredGrant(RuntimeFeature),
    InvalidField(&'static str),
    Mismatch(&'static str),
}

impl fmt::Display for ProbeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ObservationTooLarge { actual, maximum } => write!(
                formatter,
                "probe observation is {actual} bytes; maximum is {maximum} bytes",
            ),
            Self::InvalidJson(error) => write!(formatter, "invalid probe JSON: {error}"),
            Self::InvalidPersona => formatter.write_str("browser persona is invalid"),
            Self::UncompiledPersona => {
                formatter.write_str("probe requires a compiled versioned persona")
            }
            Self::MissingRuntimeVersion => {
                formatter.write_str("resolved runtime version is missing")
            }
            Self::MissingRuntimeGrants => {
                formatter.write_str("resolved runtime has no granted capabilities")
            }
            Self::RequiredRuntimeMismatch => {
                formatter.write_str("runtime does not match the persona's required runtime")
            }
            Self::UnsupportedRuntime => {
                formatter.write_str("runtime is not supported by the persona preset")
            }
            Self::MissingRequiredGrant(feature) => {
                write!(formatter, "resolved runtime did not grant {feature:?}")
            }
            Self::InvalidField(field) => write!(formatter, "invalid probe field {field}"),
            Self::Mismatch(field) => write!(formatter, "probe field {field} mismatches persona"),
        }
    }
}

impl std::error::Error for ProbeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidJson(error) => Some(error),
            _ => None,
        }
    }
}

fn validate_matrix(
    persona: &BrowserPersona,
    preset: PersonaPreset,
    runtime_kind: RuntimeKind,
    observation: &ProbeObservationV1,
) -> Result<(), ProbeError> {
    let browser = &observation.browser;
    let server = &observation.server;
    validate_user_agent(preset, runtime_kind, &browser.user_agent)?;
    require_equal("browser.platform", &browser.platform, persona.platform())?;
    require_equal("browser.language", &browser.language, persona.locale())?;
    if let Some(timezone) = persona.timezone() {
        require_equal("browser.timezone", &browser.timezone, timezone)?;
    }
    if browser.ua_mobile != persona.is_mobile() {
        return Err(ProbeError::Mismatch("browser.uaMobile"));
    }
    require_equal("browser.uaPlatform", &browser.ua_platform, persona.platform())?;
    require_number("browser.innerWidth", browser.inner_width, persona.width())?;
    require_number("browser.innerHeight", browser.inner_height, persona.height())?;
    require_number("browser.screenWidth", browser.screen_width, persona.width())?;
    require_number("browser.screenHeight", browser.screen_height, persona.height())?;
    require_number("browser.dprMilli", browser.dpr_milli, persona.device_scale_milli())?;
    require_number(
        "browser.maxTouchPoints",
        browser.max_touch_points,
        persona.max_touch_points(),
    )?;
    require_number(
        "browser.hardwareConcurrency",
        browser.hardware_concurrency,
        persona.hardware_concurrency(),
    )?;
    require_number(
        "browser.deviceMemory",
        browser.device_memory,
        persona.device_memory_gb(),
    )?;
    require_equal("browser.webglVendor", &browser.webgl_vendor, persona.webgl_vendor())?;
    require_equal(
        "browser.webglRenderer",
        &browser.webgl_renderer,
        persona.webgl_renderer(),
    )?;
    // The probe verifies the persona's WebRTC realism invariant: presence
    // must match what the persona declares (`PersonaWebrtc::Retain` keeps
    // `RTCPeerConnection`, `PersonaWebrtc::Remove` deletes it).
    let expected_webrtc = matches!(persona.webrtc(), PersonaWebrtc::Retain);
    if browser.webrtc_present != expected_webrtc {
        return Err(ProbeError::Mismatch("browser.webrtcPresent"));
    }
    if browser.webdriver {
        return Err(ProbeError::Mismatch("browser.webdriver"));
    }

    if persona.is_mobile() {
        if !browser.coarse_pointer {
            return Err(ProbeError::Mismatch("browser.coarsePointer"));
        }
        if browser.hover {
            return Err(ProbeError::Mismatch("browser.hover"));
        }
    } else {
        if browser.max_touch_points != 0 {
            return Err(ProbeError::Mismatch("browser.maxTouchPoints"));
        }
        if browser.coarse_pointer {
            return Err(ProbeError::Mismatch("browser.coarsePointer"));
        }
        if !browser.hover {
            return Err(ProbeError::Mismatch("browser.hover"));
        }
    }

    if server.user_agent != browser.user_agent {
        return Err(ProbeError::Mismatch("server.userAgent"));
    }
    let first_language = server
        .accept_language
        .split(',')
        .next()
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or_default()
        .trim();
    if !first_language.eq_ignore_ascii_case(persona.locale()) {
        return Err(ProbeError::Mismatch("server.acceptLanguage"));
    }
    let expected_mobile = if persona.is_mobile() { "?1" } else { "?0" };
    if server.sec_ch_ua_mobile.trim() != expected_mobile {
        return Err(ProbeError::Mismatch("server.secChUaMobile"));
    }
    let expected_platform = format!("\"{}\"", persona.platform());
    if server.sec_ch_ua_platform.trim() != expected_platform {
        return Err(ProbeError::Mismatch("server.secChUaPlatform"));
    }
    Ok(())
}

fn validate_user_agent(
    preset: PersonaPreset,
    runtime_kind: RuntimeKind,
    user_agent: &str,
) -> Result<(), ProbeError> {
    let coherent = match preset {
        PersonaPreset::ChromeWindowsDesktopV1 => {
            runtime_kind == RuntimeKind::Chrome
                && is_windows_x64_chromium(user_agent)
                && !contains_edge_product(user_agent)
        }
        PersonaPreset::EdgeWindowsDesktopV1 => {
            runtime_kind == RuntimeKind::Edge
                && is_windows_x64_chromium(user_agent)
                && has_product_token(user_agent, "Edg/")
        }
        PersonaPreset::FirefoxWindowsDesktopV1 => {
            runtime_kind == RuntimeKind::Firefox
                && user_agent.contains("Windows NT ")
                && has_word(user_agent, "Win64")
                && has_word(user_agent, "x64")
                && has_product_token(user_agent, "Firefox/")
                && has_product_token(user_agent, "Gecko/")
                && !has_product_token(user_agent, "Chrome/")
                && !contains_edge_product(user_agent)
        }
        PersonaPreset::ChromiumDesktopPrivacyCohortV1 => {
            is_windows_x64_chromium(user_agent)
                && match runtime_kind {
                    RuntimeKind::Chrome => !contains_edge_product(user_agent),
                    RuntimeKind::Edge => has_product_token(user_agent, "Edg/"),
                    _ => false,
                }
        }
        PersonaPreset::ChromeAndroidPixel7MobileWebV1 => {
            runtime_kind == RuntimeKind::Chrome
                && has_word(user_agent, "Linux")
                && user_agent.contains("Android 13.0.0")
                && has_word(user_agent, "Android")
                && user_agent.contains("; Pixel 7")
                && has_product_token(user_agent, "Chrome/")
                && has_word(user_agent, "Mobile")
                && !contains_edge_product(user_agent)
        }
    };
    if !coherent {
        return Err(ProbeError::Mismatch("browser.userAgent.preset"));
    }
    Ok(())
}

fn is_windows_x64_chromium(user_agent: &str) -> bool {
    user_agent.contains("Windows NT ")
        && has_word(user_agent, "Win64")
        && has_word(user_agent, "x64")
        && has_product_token(user_agent, "Chrome/")
}

fn has_word(value: &str, expected: &str) -> bool {
    value
        .split(|character: char| {
            !character.is_ascii_alphanumeric()
                && character != '-'
                && character != '_'
        })
        .any(|word| word == expected)
}

fn contains_edge_product(user_agent: &str) -> bool {
    user_agent.split_ascii_whitespace().any(|token| {
        token.starts_with("Edg/")
            || token.starts_with("EdgA/")
            || token.starts_with("EdgiOS/")
    })
}

fn has_product_token(user_agent: &str, prefix: &str) -> bool {
    user_agent.match_indices(prefix).any(|(start, _)| {
        if start != 0
            && !user_agent.as_bytes()[start - 1].is_ascii_whitespace()
        {
            return false;
        }
        let remainder = &user_agent[start + prefix.len()..];
        let version_length = remainder
            .bytes()
            .take_while(|byte| byte.is_ascii_digit() || *byte == b'.')
            .count();
        if version_length == 0 || version_length > 32 {
            return false;
        }
        let version = &remainder[..version_length];
        if !version
            .split('.')
            .all(|component| !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit()))
        {
            return false;
        }
        match remainder.as_bytes().get(version_length) {
            None => true,
            Some(byte) => byte.is_ascii_whitespace(),
        }
    })
}

fn validate_text(
    field: &'static str,
    value: &str,
    maximum: usize,
) -> Result<(), ProbeError> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(ProbeError::InvalidField(field));
    }
    Ok(())
}

fn validate_number<T>(
    field: &'static str,
    value: T,
    minimum: T,
    maximum: T,
) -> Result<(), ProbeError>
where
    T: PartialOrd,
{
    if value < minimum || value > maximum {
        return Err(ProbeError::InvalidField(field));
    }
    Ok(())
}

fn require_equal(field: &'static str, actual: &str, expected: &str) -> Result<(), ProbeError> {
    if actual != expected {
        return Err(ProbeError::Mismatch(field));
    }
    Ok(())
}

fn require_number<T>(field: &'static str, actual: T, expected: T) -> Result<(), ProbeError>
where
    T: PartialEq,
{
    if actual != expected {
        return Err(ProbeError::Mismatch(field));
    }
    Ok(())
}

fn push_field(bytes: &mut Vec<u8>, tag: &str, value: &[u8]) {
    push_length(bytes, tag.len());
    bytes.extend_from_slice(tag.as_bytes());
    push_length(bytes, value.len());
    bytes.extend_from_slice(value);
}

fn push_length(bytes: &mut Vec<u8>, length: usize) {
    let length = u32::try_from(length)
        .expect("bounded probe transcript fields fit in u32");
    bytes.extend_from_slice(&length.to_le_bytes());
}

fn push_bool(bytes: &mut Vec<u8>, tag: &str, value: bool) {
    push_field(bytes, tag, &[u8::from(value)]);
}

fn push_u8(bytes: &mut Vec<u8>, tag: &str, value: u8) {
    push_field(bytes, tag, &[value]);
}

fn push_u16(bytes: &mut Vec<u8>, tag: &str, value: u16) {
    push_field(bytes, tag, &value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig2browser_core::{
        FeatureSupport, PersonaCompiler, RouteRef, RuntimeDescriptor,
        RuntimeRequirements, SupportLevel,
    };
    use serde_json::{json, Value};

    fn persona(preset: PersonaPreset) -> BrowserPersona {
        BrowserPersona::from_compiled(PersonaCompiler::compile(
            preset,
            RouteRef::new("probe.route-1").unwrap(),
        ))
        .unwrap()
    }

    fn runtime(
        kind: RuntimeKind,
        feature: RuntimeFeature,
        level: SupportLevel,
    ) -> ResolvedRuntimeRecord {
        let descriptor = RuntimeDescriptor::new(
            kind,
            EngineFamily::Chromium,
            ControlTransport::Cdp,
            vec![FeatureSupport::new(feature, level, Vec::new())],
        )
        .unwrap();
        let requirements = RuntimeRequirements::new(vec![feature], false).unwrap();
        let resolved = descriptor
            .negotiate(&requirements, Some("Chrome/134.0.0.0".to_owned()))
            .unwrap();
        ResolvedRuntimeRecord::from_resolved(&resolved).unwrap()
    }

    fn desktop_json() -> Value {
        json!({
            "browser": {
                "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
                "platform": "Windows",
                "language": "en-US",
                "timezone": "UTC",
                "uaMobile": false,
                "uaPlatform": "Windows",
                "innerWidth": 1920,
                "innerHeight": 1080,
                "screenWidth": 1920,
                "screenHeight": 1080,
                "dprMilli": 1000,
                "maxTouchPoints": 0,
                "coarsePointer": false,
                "hover": true,
                "webdriver": false,
                "colorDepth": 24,
                "hardwareConcurrency": 8,
                "deviceMemory": 8,
                "webglVendor": "Google Inc. (NVIDIA)",
                "webglRenderer": "ANGLE (NVIDIA, NVIDIA GeForce GTX 1080 Direct3D11 vs_5_0 ps_5_0, D3D11)",
                "webrtcPresent": true
            },
            "server": {
                "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
                "acceptLanguage": "en-US,en;q=0.9",
                "secChUaMobile": "?0",
                "secChUaPlatform": "\"Windows\""
            }
        })
    }

    fn mobile_json() -> Value {
        json!({
            "browser": {
                "userAgent": "Mozilla/5.0 (Linux; Android 13.0.0; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Mobile Safari/537.36",
                "platform": "Android",
                "language": "en-US",
                "timezone": "UTC",
                "uaMobile": true,
                "uaPlatform": "Android",
                "innerWidth": 393,
                "innerHeight": 852,
                "screenWidth": 393,
                "screenHeight": 852,
                "dprMilli": 3000,
                "maxTouchPoints": 5,
                "coarsePointer": true,
                "hover": false,
                "webdriver": false,
                "colorDepth": 24,
                "hardwareConcurrency": 8,
                "deviceMemory": 8,
                "webglVendor": "ARM",
                "webglRenderer": "Mali-G710",
                "webrtcPresent": true
            },
            "server": {
                "userAgent": "Mozilla/5.0 (Linux; Android 13.0.0; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Mobile Safari/537.36",
                "acceptLanguage": "en-US,en;q=0.9",
                "secChUaMobile": "?1",
                "secChUaPlatform": "\"Android\""
            }
        })
    }

    #[test]
    fn valid_desktop_observation_records_compiled_contract() {
        let persona = persona(PersonaPreset::ChromeWindowsDesktopV1);
        let desktop_runtime = runtime(
            RuntimeKind::Chrome,
            RuntimeFeature::DesktopWeb,
            SupportLevel::Native,
        );
        let transcript = ProbeTranscriptV1::from_observation(
            &persona,
            &desktop_runtime,
            &desktop_json().to_string(),
        )
        .unwrap();

        assert_eq!(transcript.schema_id, PROBE_SCHEMA_ID);
        assert_eq!(transcript.preset, "chrome-windows-desktop-v1");
        assert_eq!(transcript.route_ref, "probe.route-1");
        assert_eq!(transcript.runtime.kind, ProbeRuntimeKindV1::Chrome);
        assert_eq!(transcript.runtime.engine, ProbeEngineFamilyV1::Chromium);
        assert_eq!(transcript.runtime.control, ProbeControlTransportV1::Cdp);
    }

    #[test]
    fn valid_mobile_observation_requires_emulation_grant() {
        let persona = persona(PersonaPreset::ChromeAndroidPixel7MobileWebV1);
        let runtime = runtime(
            RuntimeKind::Chrome,
            RuntimeFeature::MobileWebEmulation,
            SupportLevel::Emulated,
        );
        let transcript = ProbeTranscriptV1::from_observation(
            &persona,
            &runtime,
            &mobile_json().to_string(),
        )
        .unwrap();

        assert!(transcript.observation.browser.ua_mobile);
        assert_eq!(transcript.observation.browser.max_touch_points, 5);
    }

    #[test]
    fn webrtc_presence_mismatch_is_rejected() {
        // A Retain persona (Chrome desktop) whose page reports RTCPeerConnection
        // absent is a persona-coherence failure — the probe rejects it. This
        // makes the WebRTC realism invariant non-vacuous.
        let persona = persona(PersonaPreset::ChromeWindowsDesktopV1);
        let desktop_runtime = runtime(
            RuntimeKind::Chrome,
            RuntimeFeature::DesktopWeb,
            SupportLevel::Native,
        );
        let mut absent = desktop_json();
        absent["browser"]["webrtcPresent"] = json!(false);
        assert!(matches!(
            ProbeTranscriptV1::from_observation(
                &persona,
                &desktop_runtime,
                &absent.to_string(),
            ),
            Err(ProbeError::Mismatch("browser.webrtcPresent"))
        ));
    }

    #[test]
    fn coherent_matrix_rejects_mismatches_and_uncompiled_personas() {
        let desktop_runtime = runtime(
            RuntimeKind::Chrome,
            RuntimeFeature::DesktopWeb,
            SupportLevel::Native,
        );
        let legacy = BrowserPersona::desktop_default();
        assert!(matches!(
            ProbeTranscriptV1::from_observation(
                &legacy,
                &desktop_runtime,
                &desktop_json().to_string(),
            ),
            Err(ProbeError::UncompiledPersona)
        ));

        let persona = persona(PersonaPreset::ChromeWindowsDesktopV1);
        let mut mismatched = desktop_json();
        mismatched["server"]["userAgent"] = json!("different");
        assert!(matches!(
            ProbeTranscriptV1::from_observation(
                &persona,
                &desktop_runtime,
                &mismatched.to_string(),
            ),
            Err(ProbeError::Mismatch("server.userAgent"))
        ));

        let wrong_grant = runtime(
            RuntimeKind::Chrome,
            RuntimeFeature::MobileWebEmulation,
            SupportLevel::Emulated,
        );
        assert!(matches!(
            ProbeTranscriptV1::from_observation(
                &persona,
                &wrong_grant,
                &desktop_json().to_string(),
            ),
            Err(ProbeError::MissingRequiredGrant(RuntimeFeature::DesktopWeb))
        ));
    }

    #[test]
    fn user_agent_contract_rejects_cross_runtime_and_mobile_tokens() {
        let chrome_persona = persona(PersonaPreset::ChromeWindowsDesktopV1);
        let chrome_runtime = runtime(
            RuntimeKind::Chrome,
            RuntimeFeature::DesktopWeb,
            SupportLevel::Native,
        );
        let edge_user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0";
        let mut chrome_with_edge = desktop_json();
        chrome_with_edge["browser"]["userAgent"] = json!(edge_user_agent);
        chrome_with_edge["server"]["userAgent"] = json!(edge_user_agent);
        assert!(matches!(
            ProbeTranscriptV1::from_observation(
                &chrome_persona,
                &chrome_runtime,
                &chrome_with_edge.to_string(),
            ),
            Err(ProbeError::Mismatch("browser.userAgent.preset"))
        ));

        let edge_persona = persona(PersonaPreset::EdgeWindowsDesktopV1);
        let edge_runtime = runtime(
            RuntimeKind::Edge,
            RuntimeFeature::DesktopWeb,
            SupportLevel::Native,
        );
        assert!(ProbeTranscriptV1::from_observation(
            &edge_persona,
            &edge_runtime,
            &chrome_with_edge.to_string(),
        )
        .is_ok());
        assert!(matches!(
            ProbeTranscriptV1::from_observation(
                &edge_persona,
                &edge_runtime,
                &desktop_json().to_string(),
            ),
            Err(ProbeError::Mismatch("browser.userAgent.preset"))
        ));

        let mobile_persona = persona(PersonaPreset::ChromeAndroidPixel7MobileWebV1);
        let mobile_runtime = runtime(
            RuntimeKind::Chrome,
            RuntimeFeature::MobileWebEmulation,
            SupportLevel::Emulated,
        );
        let mut wrong_model = mobile_json();
        let pixel_8 = wrong_model["browser"]["userAgent"]
            .as_str()
            .unwrap()
            .replace("Pixel 7", "Pixel 8");
        wrong_model["browser"]["userAgent"] = json!(&pixel_8);
        wrong_model["server"]["userAgent"] = json!(&pixel_8);
        assert!(matches!(
            ProbeTranscriptV1::from_observation(
                &mobile_persona,
                &mobile_runtime,
                &wrong_model.to_string(),
            ),
            Err(ProbeError::Mismatch("browser.userAgent.preset"))
        ));

        let mut mobile_edge = mobile_json();
        let edge_android = format!(
            "{} EdgA/134.0.0.0",
            mobile_edge["browser"]["userAgent"].as_str().unwrap(),
        );
        mobile_edge["browser"]["userAgent"] = json!(&edge_android);
        mobile_edge["server"]["userAgent"] = json!(&edge_android);
        assert!(matches!(
            ProbeTranscriptV1::from_observation(
                &mobile_persona,
                &mobile_runtime,
                &mobile_edge.to_string(),
            ),
            Err(ProbeError::Mismatch("browser.userAgent.preset"))
        ));
    }

    #[test]
    fn bounded_decoder_rejects_oversize_controls_and_extra_secret_fields() {
        let oversized = " ".repeat(MAX_PROBE_JSON_BYTES + 1);
        assert!(matches!(
            ProbeObservationV1::decode_json(&oversized),
            Err(ProbeError::ObservationTooLarge { .. })
        ));

        let mut controlled = desktop_json();
        controlled["browser"]["language"] = json!("en-US\nsecret");
        assert!(matches!(
            ProbeObservationV1::decode_json(&controlled.to_string()),
            Err(ProbeError::InvalidField("browser.language"))
        ));

        let mut secret = desktop_json();
        secret["server"]["authorization"] = json!("Bearer secret");
        assert!(matches!(
            ProbeObservationV1::decode_json(&secret.to_string()),
            Err(ProbeError::InvalidJson(_))
        ));
    }

    #[test]
    fn canonical_hash_is_deterministic_and_field_sensitive() {
        let persona = persona(PersonaPreset::ChromeWindowsDesktopV1);
        let runtime = runtime(
            RuntimeKind::Chrome,
            RuntimeFeature::DesktopWeb,
            SupportLevel::Native,
        );
        let first = ProbeTranscriptV1::from_observation(
            &persona,
            &runtime,
            &desktop_json().to_string(),
        )
        .unwrap();
        let second = ProbeTranscriptV1::from_observation(
            &persona,
            &runtime,
            &desktop_json().to_string(),
        )
        .unwrap();
        assert_eq!(first.canonical_bytes(), second.canonical_bytes());
        assert_eq!(first.sha256(), second.sha256());

        let mut changed = first.clone();
        changed.observation.browser.color_depth = 30;
        assert_ne!(first.sha256(), changed.sha256());
    }
}
