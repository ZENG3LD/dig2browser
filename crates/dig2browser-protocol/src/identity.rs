use crate::ProtocolError;
use dig2browser_core::{
    CompiledPersona, PersonaCompiler, PersonaDeviceClass, PersonaPreset, RouteRef,
};

const PERSONA_MAGIC: [u8; 4] = *b"D2IP";
const LEGACY_PERSONA_SCHEMA_VERSION: u16 = 1;
const COMPILED_PERSONA_SCHEMA_VERSION: u16 = 2;
const MAX_LOCALE_BYTES: usize = 35;
const MAX_TIMEZONE_BYTES: usize = 64;
const MAX_PLATFORM_VERSION_BYTES: usize = 32;
const MAX_MODEL_BYTES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PersonaKind {
    Desktop = 0,
    Mobile = 1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MobilePersonaConfig {
    pub width: u16,
    pub height: u16,
    pub device_scale_milli: u16,
    pub max_touch_points: u8,
    pub locale: String,
    pub timezone: Option<String>,
    pub platform_version: String,
    pub model: String,
}

impl PersonaKind {
    fn from_wire(value: u8) -> Result<Self, ProtocolError> {
        match value {
            0 => Ok(Self::Desktop),
            1 => Ok(Self::Mobile),
            _ => Err(ProtocolError::InvalidIdentityPayload),
        }
    }
}

/// Non-secret, durable browser fingerprint contract for one profile ID.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BrowserPersona {
    kind: PersonaKind,
    width: u16,
    height: u16,
    device_scale_milli: u16,
    max_touch_points: u8,
    locale: String,
    timezone: Option<String>,
    platform_version: String,
    model: String,
    preset: Option<PersonaPreset>,
    route_ref: Option<RouteRef>,
}

impl BrowserPersona {
    pub fn desktop_default() -> Self {
        Self::desktop(1920, 1080, 1000, "en-US", None)
            .expect("built-in desktop persona is valid")
    }

    pub fn mobile_default() -> Self {
        Self::mobile(MobilePersonaConfig {
            width: 393,
            height: 852,
            device_scale_milli: 3000,
            max_touch_points: 5,
            locale: "en-US".to_owned(),
            timezone: None,
            platform_version: "13.0.0".to_owned(),
            model: "Pixel 7".to_owned(),
        })
        .expect("built-in mobile persona is valid")
    }

    pub fn desktop(
        width: u16,
        height: u16,
        device_scale_milli: u16,
        locale: impl Into<String>,
        timezone: Option<String>,
    ) -> Result<Self, ProtocolError> {
        let persona = Self {
            kind: PersonaKind::Desktop,
            width,
            height,
            device_scale_milli,
            max_touch_points: 0,
            locale: locale.into(),
            timezone,
            platform_version: "15.0.0".to_owned(),
            model: String::new(),
            preset: None,
            route_ref: None,
        };
        persona.validate()?;
        Ok(persona)
    }

    pub fn mobile(config: MobilePersonaConfig) -> Result<Self, ProtocolError> {
        let persona = Self {
            kind: PersonaKind::Mobile,
            width: config.width,
            height: config.height,
            device_scale_milli: config.device_scale_milli,
            max_touch_points: config.max_touch_points,
            locale: config.locale,
            timezone: config.timezone,
            platform_version: config.platform_version,
            model: config.model,
            preset: None,
            route_ref: None,
        };
        persona.validate()?;
        Ok(persona)
    }

    /// Convert a core compiler result into the protocol persona contract.
    pub fn from_compiled(compiled: CompiledPersona) -> Result<Self, ProtocolError> {
        let persona = Self {
            kind: match compiled.device_class() {
                PersonaDeviceClass::Desktop => PersonaKind::Desktop,
                PersonaDeviceClass::MobileWeb => PersonaKind::Mobile,
            },
            width: compiled.width(),
            height: compiled.height(),
            device_scale_milli: compiled.device_scale_milli(),
            max_touch_points: compiled.max_touch_points(),
            locale: compiled.locale().to_owned(),
            timezone: compiled.timezone().map(str::to_owned),
            platform_version: compiled.platform_version().to_owned(),
            model: compiled.model().to_owned(),
            preset: Some(compiled.preset()),
            route_ref: Some(compiled.route_ref().clone()),
        };
        persona.validate()?;
        Ok(persona)
    }

    /// Compile a versioned preset directly into a protocol persona.
    pub fn compiled(
        preset: PersonaPreset,
        route_ref: RouteRef,
    ) -> Result<Self, ProtocolError> {
        Self::from_compiled(PersonaCompiler::compile(preset, route_ref))
    }

    pub fn kind(&self) -> PersonaKind {
        self.kind
    }

    pub fn width(&self) -> u16 {
        self.width
    }

    pub fn height(&self) -> u16 {
        self.height
    }

    pub fn device_scale_factor(&self) -> f64 {
        f64::from(self.device_scale_milli) / 1000.0
    }

    pub fn device_scale_milli(&self) -> u16 {
        self.device_scale_milli
    }

    pub fn max_touch_points(&self) -> u8 {
        self.max_touch_points
    }

    pub fn locale(&self) -> &str {
        &self.locale
    }

    pub fn timezone(&self) -> Option<&str> {
        self.timezone.as_deref()
    }

    pub fn platform(&self) -> &'static str {
        match self.kind {
            PersonaKind::Desktop => "Windows",
            PersonaKind::Mobile => "Android",
        }
    }

    pub fn platform_version(&self) -> &str {
        &self.platform_version
    }

    pub fn architecture(&self) -> &'static str {
        match self.kind {
            PersonaKind::Desktop => "x86",
            PersonaKind::Mobile => "",
        }
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    /// Core device class implied by `kind`. Computed, not a wire field —
    /// legacy (non-preset) personas get the same device-class-keyed
    /// hardware profile as compiled ones.
    fn device_class(&self) -> PersonaDeviceClass {
        match self.kind {
            PersonaKind::Desktop => PersonaDeviceClass::Desktop,
            PersonaKind::Mobile => PersonaDeviceClass::MobileWeb,
        }
    }

    /// Declared CPU thread count (`navigator.hardwareConcurrency`).
    pub fn hardware_concurrency(&self) -> u8 {
        self.device_class().hardware_concurrency()
    }

    /// Declared device memory in GB (`navigator.deviceMemory`).
    pub fn device_memory_gb(&self) -> u8 {
        self.device_class().device_memory_gb()
    }

    /// `WEBGL_debug_renderer_info` `UNMASKED_VENDOR_WEBGL` string.
    pub fn webgl_vendor(&self) -> &'static str {
        self.device_class().webgl_vendor()
    }

    /// `WEBGL_debug_renderer_info` `UNMASKED_RENDERER_WEBGL` string.
    pub fn webgl_renderer(&self) -> &'static str {
        self.device_class().webgl_renderer()
    }

    pub fn is_mobile(&self) -> bool {
        self.kind == PersonaKind::Mobile
    }

    pub fn preset(&self) -> Option<PersonaPreset> {
        self.preset
    }

    pub fn route_ref(&self) -> Option<&RouteRef> {
        self.route_ref.as_ref()
    }

    pub fn is_compiled(&self) -> bool {
        self.preset.is_some()
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        let viewport_valid = match self.kind {
            PersonaKind::Desktop => {
                (640..=7680).contains(&self.width)
                    && (480..=4320).contains(&self.height)
                    && self.max_touch_points == 0
                    && self.model.is_empty()
                    && self.platform_version == "15.0.0"
            }
            PersonaKind::Mobile => {
                (240..=1440).contains(&self.width)
                    && (320..=3200).contains(&self.height)
                    && (1..=10).contains(&self.max_touch_points)
                    && !self.model.is_empty()
            }
        };
        if !viewport_valid
            || !(1000..=4000).contains(&self.device_scale_milli)
            || !valid_locale(&self.locale)
            || self
                .timezone
                .as_deref()
                .is_some_and(|value| !valid_timezone(value))
            || !valid_platform_version(&self.platform_version)
            || self.model.len() > MAX_MODEL_BYTES
            || self.model.chars().any(char::is_control)
        {
            return Err(ProtocolError::InvalidIdentityPayload);
        }
        match (self.preset, self.route_ref.as_ref()) {
            (None, None) => {}
            (Some(preset), Some(route_ref)) => {
                let compiled = PersonaCompiler::compile(preset, route_ref.clone());
                let kind = match compiled.device_class() {
                    PersonaDeviceClass::Desktop => PersonaKind::Desktop,
                    PersonaDeviceClass::MobileWeb => PersonaKind::Mobile,
                };
                if self.kind != kind
                    || self.width != compiled.width()
                    || self.height != compiled.height()
                    || self.device_scale_milli != compiled.device_scale_milli()
                    || self.max_touch_points != compiled.max_touch_points()
                    || self.locale != compiled.locale()
                    || self.timezone.as_deref() != compiled.timezone()
                    || self.platform_version != compiled.platform_version()
                    || self.model != compiled.model()
                {
                    return Err(ProtocolError::InvalidIdentityPayload);
                }
            }
            _ => return Err(ProtocolError::InvalidIdentityPayload),
        }
        Ok(())
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        let timezone = self.timezone.as_deref().unwrap_or_default();
        let metadata_len = self
            .route_ref
            .as_ref()
            .map_or(0, |route_ref| 2 + route_ref.as_str().len());
        let mut output = Vec::with_capacity(
            22 + self.locale.len()
                + timezone.len()
                + self.platform_version.len()
                + self.model.len()
                + metadata_len,
        );
        output.extend_from_slice(&PERSONA_MAGIC);
        let schema = if self.is_compiled() {
            COMPILED_PERSONA_SCHEMA_VERSION
        } else {
            LEGACY_PERSONA_SCHEMA_VERSION
        };
        output.extend_from_slice(&schema.to_le_bytes());
        output.push(self.kind as u8);
        output.push(0);
        output.extend_from_slice(&self.width.to_le_bytes());
        output.extend_from_slice(&self.height.to_le_bytes());
        output.extend_from_slice(&self.device_scale_milli.to_le_bytes());
        output.push(self.max_touch_points);
        output.push(u8::try_from(self.locale.len()).map_err(|_| ProtocolError::InvalidIdentityPayload)?);
        output.push(u8::try_from(timezone.len()).map_err(|_| ProtocolError::InvalidIdentityPayload)?);
        output.push(u8::try_from(self.platform_version.len()).map_err(|_| ProtocolError::InvalidIdentityPayload)?);
        output.push(u8::try_from(self.model.len()).map_err(|_| ProtocolError::InvalidIdentityPayload)?);
        output.extend_from_slice(self.locale.as_bytes());
        output.extend_from_slice(timezone.as_bytes());
        output.extend_from_slice(self.platform_version.as_bytes());
        output.extend_from_slice(self.model.as_bytes());
        if let (Some(preset), Some(route_ref)) = (self.preset, self.route_ref.as_ref()) {
            output.push(preset_to_wire(preset));
            output.push(
                u8::try_from(route_ref.as_str().len())
                    .map_err(|_| ProtocolError::InvalidIdentityPayload)?,
            );
            output.extend_from_slice(route_ref.as_str().as_bytes());
        }
        Ok(output)
    }

    pub(crate) fn decode(payload: &[u8]) -> Result<(Self, usize), ProtocolError> {
        if payload.len() < 19 || payload[..4] != PERSONA_MAGIC || payload[7] != 0 {
            return Err(ProtocolError::InvalidIdentityPayload);
        }
        let schema = u16::from_le_bytes(payload[4..6].try_into().unwrap());
        if !matches!(schema, LEGACY_PERSONA_SCHEMA_VERSION | COMPILED_PERSONA_SCHEMA_VERSION) {
            return Err(ProtocolError::InvalidIdentityPayload);
        }
        let kind = PersonaKind::from_wire(payload[6])?;
        let width = u16::from_le_bytes(payload[8..10].try_into().unwrap());
        let height = u16::from_le_bytes(payload[10..12].try_into().unwrap());
        let device_scale_milli = u16::from_le_bytes(payload[12..14].try_into().unwrap());
        let max_touch_points = payload[14];
        let lengths = [payload[15], payload[16], payload[17], payload[18]];
        let total_strings = lengths
            .into_iter()
            .try_fold(0usize, |total, len| total.checked_add(usize::from(len)))
            .ok_or(ProtocolError::InvalidIdentityPayload)?;
        let legacy_consumed = 19usize
            .checked_add(total_strings)
            .ok_or(ProtocolError::InvalidIdentityPayload)?;
        if payload.len() < legacy_consumed {
            return Err(ProtocolError::InvalidIdentityPayload);
        }
        let mut offset = 19;
        let mut next = |len: u8| {
            let end = offset + usize::from(len);
            let value = std::str::from_utf8(&payload[offset..end])
                .map(str::to_owned)
                .map_err(|_| ProtocolError::InvalidIdentityPayload);
            offset = end;
            value
        };
        let locale = next(lengths[0])?;
        let timezone = match next(lengths[1])? {
            value if value.is_empty() => None,
            value => Some(value),
        };
        let platform_version = next(lengths[2])?;
        let model = next(lengths[3])?;
        let (preset, route_ref, consumed) = if schema == LEGACY_PERSONA_SCHEMA_VERSION {
            (None, None, legacy_consumed)
        } else {
            let metadata_header_end = legacy_consumed
                .checked_add(2)
                .ok_or(ProtocolError::InvalidIdentityPayload)?;
            if payload.len() < metadata_header_end {
                return Err(ProtocolError::InvalidIdentityPayload);
            }
            let preset = preset_from_wire(payload[legacy_consumed])?;
            let route_len = usize::from(payload[legacy_consumed + 1]);
            let consumed = metadata_header_end
                .checked_add(route_len)
                .ok_or(ProtocolError::InvalidIdentityPayload)?;
            let route_bytes = payload
                .get(metadata_header_end..consumed)
                .ok_or(ProtocolError::InvalidIdentityPayload)?;
            let route = std::str::from_utf8(route_bytes)
                .map_err(|_| ProtocolError::InvalidIdentityPayload)?;
            let route_ref = RouteRef::new(route)
                .map_err(|_| ProtocolError::InvalidIdentityPayload)?;
            (Some(preset), Some(route_ref), consumed)
        };
        let persona = Self {
            kind,
            width,
            height,
            device_scale_milli,
            max_touch_points,
            locale,
            timezone,
            platform_version,
            model,
            preset,
            route_ref,
        };
        persona.validate()?;
        Ok((persona, consumed))
    }
}

fn preset_to_wire(preset: PersonaPreset) -> u8 {
    match preset {
        PersonaPreset::ChromiumDesktopPrivacyCohortV1 => 1,
        PersonaPreset::ChromeWindowsDesktopV1 => 2,
        PersonaPreset::EdgeWindowsDesktopV1 => 3,
        PersonaPreset::ChromeAndroidPixel7MobileWebV1 => 4,
        PersonaPreset::FirefoxWindowsDesktopV1 => 5,
    }
}

fn preset_from_wire(value: u8) -> Result<PersonaPreset, ProtocolError> {
    match value {
        1 => Ok(PersonaPreset::ChromiumDesktopPrivacyCohortV1),
        2 => Ok(PersonaPreset::ChromeWindowsDesktopV1),
        3 => Ok(PersonaPreset::EdgeWindowsDesktopV1),
        4 => Ok(PersonaPreset::ChromeAndroidPixel7MobileWebV1),
        5 => Ok(PersonaPreset::FirefoxWindowsDesktopV1),
        _ => Err(ProtocolError::InvalidIdentityPayload),
    }
}

fn valid_locale(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_LOCALE_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn valid_timezone(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TIMEZONE_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'_' | b'-' | b'+')
        })
}

fn valid_platform_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PLATFORM_VERSION_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_default_personas_keep_exact_d2ip_v1_bytes() {
        let desktop = BrowserPersona::desktop_default();
        let expected_desktop = vec![
            b'D', b'2', b'I', b'P', 1, 0, 0, 0, 0x80, 0x07, 0x38, 0x04,
            0xe8, 0x03, 0, 5, 0, 6, 0, b'e', b'n', b'-', b'U', b'S', b'1',
            b'5', b'.', b'0', b'.', b'0',
        ];
        assert_eq!(desktop.encode().expect("encode desktop"), expected_desktop);
        assert!(!desktop.is_compiled());

        let mobile = BrowserPersona::mobile_default();
        let expected_mobile = vec![
            b'D', b'2', b'I', b'P', 1, 0, 1, 0, 0x89, 0x01, 0x54, 0x03,
            0xb8, 0x0b, 5, 5, 0, 6, 7, b'e', b'n', b'-', b'U', b'S', b'1',
            b'3', b'.', b'0', b'.', b'0', b'P', b'i', b'x', b'e', b'l', b' ',
            b'7',
        ];
        assert_eq!(mobile.encode().expect("encode mobile"), expected_mobile);
        assert!(!mobile.is_compiled());
    }

    #[test]
    fn legacy_custom_persona_round_trips_without_compiler_metadata() {
        let persona = BrowserPersona::mobile(MobilePersonaConfig {
            width: 412,
            height: 915,
            device_scale_milli: 2625,
            max_touch_points: 5,
            locale: "ru-RU".to_owned(),
            timezone: Some("Europe/Moscow".to_owned()),
            platform_version: "14.0.0".to_owned(),
            model: "Pixel 8".to_owned(),
        })
        .expect("custom mobile persona");
        let encoded = persona.encode().expect("encode persona");
        assert_eq!(&encoded[4..6], &LEGACY_PERSONA_SCHEMA_VERSION.to_le_bytes());
        let (decoded, consumed) = BrowserPersona::decode(&encoded).expect("decode persona");
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, persona);
    }

    #[test]
    fn compiled_persona_uses_d2ip_v2_and_round_trips_metadata() {
        let route_ref = RouteRef::new("Proxy_01.west").expect("route reference");
        let persona = BrowserPersona::compiled(
            PersonaPreset::ChromeAndroidPixel7MobileWebV1,
            route_ref.clone(),
        )
        .expect("compiled persona");
        let encoded = persona.encode().expect("encode compiled persona");
        assert_eq!(&encoded[4..6], &COMPILED_PERSONA_SCHEMA_VERSION.to_le_bytes());
        let (decoded, consumed) = BrowserPersona::decode(&encoded)
            .expect("decode compiled persona");
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, persona);
        assert_eq!(decoded.preset(), Some(PersonaPreset::ChromeAndroidPixel7MobileWebV1));
        assert_eq!(decoded.route_ref(), Some(&route_ref));
        assert!(decoded.is_compiled());

        let firefox_route = RouteRef::new("Firefox_01.west")
            .expect("Firefox route reference");
        let firefox = BrowserPersona::compiled(
            PersonaPreset::FirefoxWindowsDesktopV1,
            firefox_route.clone(),
        )
        .expect("compiled Firefox persona");
        let encoded = firefox.encode().expect("encode Firefox persona");
        let metadata_offset = encoded.len() - firefox_route.as_str().len() - 2;
        assert_eq!(encoded[metadata_offset], 5);
        let (decoded, consumed) = BrowserPersona::decode(&encoded)
            .expect("decode compiled Firefox persona");
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, firefox);
        assert_eq!(decoded.preset(), Some(PersonaPreset::FirefoxWindowsDesktopV1));
        assert_eq!(decoded.route_ref(), Some(&firefox_route));
    }

    #[test]
    fn compiled_persona_tampering_fails_closed() {
        let persona = BrowserPersona::compiled(
            PersonaPreset::ChromeWindowsDesktopV1,
            RouteRef::host_direct(),
        )
        .expect("compiled persona");
        let encoded = persona.encode().expect("encode compiled persona");
        let metadata_offset = encoded.len() - dig2browser_core::HOST_DIRECT.len() - 2;

        let mut field_tamper = encoded.clone();
        field_tamper[8] ^= 1;
        assert!(BrowserPersona::decode(&field_tamper).is_err());

        let mut preset_tamper = encoded.clone();
        preset_tamper[metadata_offset] =
            preset_to_wire(PersonaPreset::ChromeAndroidPixel7MobileWebV1);
        assert!(BrowserPersona::decode(&preset_tamper).is_err());

        let mut unknown_preset = encoded.clone();
        unknown_preset[metadata_offset] = u8::MAX;
        assert!(BrowserPersona::decode(&unknown_preset).is_err());

        let mut route_tamper = encoded.clone();
        route_tamper[metadata_offset + 2] = b':';
        assert!(BrowserPersona::decode(&route_tamper).is_err());

        let mut reserved_tamper = encoded.clone();
        reserved_tamper[7] = 1;
        assert!(BrowserPersona::decode(&reserved_tamper).is_err());

        let mut truncated = encoded.clone();
        truncated.pop();
        assert!(BrowserPersona::decode(&truncated).is_err());

        let mut incomplete_pair = persona;
        incomplete_pair.route_ref = None;
        assert!(incomplete_pair.validate().is_err());
    }

    #[test]
    fn outer_length_check_rejects_trailing_compiled_persona_bytes() {
        let persona = BrowserPersona::compiled(
            PersonaPreset::EdgeWindowsDesktopV1,
            RouteRef::host_direct(),
        )
        .expect("compiled persona");
        let encoded = persona.encode().expect("encode compiled persona");
        let mut with_trailing = encoded.clone();
        with_trailing.push(0);
        let (_, consumed) = BrowserPersona::decode(&with_trailing)
            .expect("persona decoder reports its consumed prefix");
        assert_eq!(consumed, encoded.len());
        assert_ne!(consumed, with_trailing.len());

        let task = crate::CollectionTask::new(vec![crate::TaskStep::Navigate {
            url: "https://example.test".to_owned(),
        }])
        .expect("collection task");
        let mut outer = crate::encode_task_identity_payload(
            crate::ProfileClass::Public,
            &persona,
            &task,
        )
        .expect("identity payload");
        let persona_len = usize::from(u16::from_le_bytes(outer[6..8].try_into().unwrap()));
        outer.insert(10 + persona_len, 0);
        outer[6..8].copy_from_slice(
            &u16::try_from(persona_len + 1)
                .expect("persona length")
                .to_le_bytes(),
        );
        assert!(crate::decode_task_identity_payload(&outer).is_err());
    }
}
