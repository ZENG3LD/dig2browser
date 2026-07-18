use crate::ProtocolError;

const PERSONA_MAGIC: [u8; 4] = *b"D2IP";
const PERSONA_SCHEMA_VERSION: u16 = 1;
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
        };
        persona.validate()?;
        Ok(persona)
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

    pub fn is_mobile(&self) -> bool {
        self.kind == PersonaKind::Mobile
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
        Ok(())
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        let timezone = self.timezone.as_deref().unwrap_or_default();
        let mut output = Vec::with_capacity(
            22 + self.locale.len()
                + timezone.len()
                + self.platform_version.len()
                + self.model.len(),
        );
        output.extend_from_slice(&PERSONA_MAGIC);
        output.extend_from_slice(&PERSONA_SCHEMA_VERSION.to_le_bytes());
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
        Ok(output)
    }

    pub(crate) fn decode(payload: &[u8]) -> Result<(Self, usize), ProtocolError> {
        if payload.len() < 19
            || payload[..4] != PERSONA_MAGIC
            || u16::from_le_bytes(payload[4..6].try_into().unwrap()) != PERSONA_SCHEMA_VERSION
            || payload[7] != 0
        {
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
        let consumed = 19usize
            .checked_add(total_strings)
            .ok_or(ProtocolError::InvalidIdentityPayload)?;
        if payload.len() < consumed {
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
        };
        persona.validate()?;
        Ok((persona, consumed))
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
    fn desktop_and_mobile_personas_round_trip() {
        for persona in [
            BrowserPersona::desktop_default(),
            BrowserPersona::mobile_default(),
            BrowserPersona::mobile(MobilePersonaConfig {
                width: 412,
                height: 915,
                device_scale_milli: 2625,
                max_touch_points: 5,
                locale: "ru-RU".to_owned(),
                timezone: Some("Europe/Moscow".to_owned()),
                platform_version: "14.0.0".to_owned(),
                model: "Pixel 8".to_owned(),
            })
            .expect("custom mobile persona"),
        ] {
            let encoded = persona.encode().expect("encode persona");
            let (decoded, consumed) = BrowserPersona::decode(&encoded).expect("decode persona");
            assert_eq!(consumed, encoded.len());
            assert_eq!(decoded, persona);
        }
    }
}
