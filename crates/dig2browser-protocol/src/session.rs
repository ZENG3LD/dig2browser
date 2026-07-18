use crate::ProtocolError;

const SESSION_UPDATE_MAGIC: [u8; 4] = *b"D2SU";
const SESSION_STATUS_MAGIC: [u8; 4] = *b"D2SS";
const SESSION_HEALTH_MAGIC: [u8; 4] = *b"D2HP";
const SESSION_SCHEMA_VERSION: u16 = 1;
const MAX_PROBE_SELECTOR_BYTES: usize = 1_024;
const MAX_PROBE_TTL_SECONDS: u32 = 24 * 60 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ProfileClass {
    Public = 0,
    Authenticated = 1,
}

impl ProfileClass {
    pub(crate) fn from_wire(value: u8) -> Result<Self, ProtocolError> {
        match value {
            0 => Ok(Self::Public),
            1 => Ok(Self::Authenticated),
            _ => Err(ProtocolError::InvalidSessionPayload),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionPhase {
    Unknown = 0,
    Ready = 1,
    ReauthRequired = 2,
    Expired = 3,
}

impl SessionPhase {
    fn from_wire(value: u8) -> Result<Self, ProtocolError> {
        match value {
            0 => Ok(Self::Unknown),
            1 => Ok(Self::Ready),
            2 => Ok(Self::ReauthRequired),
            3 => Ok(Self::Expired),
            _ => Err(ProtocolError::InvalidSessionPayload),
        }
    }
}

/// Operator-supplied, non-secret authenticated-session transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionStateUpdate {
    pub phase: SessionPhase,
    pub expires_at_unix_ms: Option<u64>,
}

/// Operator-defined, bounded evidence for classifying an authenticated page.
/// The station returns only the resulting lifecycle state, never page content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionHealthProbe {
    pub url: String,
    pub ready_selector: String,
    pub reauth_selector: String,
    pub ready_ttl_seconds: u32,
}

impl SessionHealthProbe {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        crate::validate_http_url(&self.url)?;
        if self.ready_selector == self.reauth_selector
            || !valid_probe_selector(&self.ready_selector)
            || !valid_probe_selector(&self.reauth_selector)
            || !(60..=MAX_PROBE_TTL_SECONDS).contains(&self.ready_ttl_seconds)
        {
            return Err(ProtocolError::InvalidSessionPayload);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        let url_len = u16::try_from(self.url.len())
            .map_err(|_| ProtocolError::InvalidSessionPayload)?;
        let ready_len = u16::try_from(self.ready_selector.len())
            .map_err(|_| ProtocolError::InvalidSessionPayload)?;
        let reauth_len = u16::try_from(self.reauth_selector.len())
            .map_err(|_| ProtocolError::InvalidSessionPayload)?;
        let mut output = Vec::with_capacity(
            16 + self.url.len() + self.ready_selector.len() + self.reauth_selector.len(),
        );
        output.extend_from_slice(&SESSION_HEALTH_MAGIC);
        output.extend_from_slice(&SESSION_SCHEMA_VERSION.to_le_bytes());
        output.extend_from_slice(&self.ready_ttl_seconds.to_le_bytes());
        output.extend_from_slice(&url_len.to_le_bytes());
        output.extend_from_slice(&ready_len.to_le_bytes());
        output.extend_from_slice(&reauth_len.to_le_bytes());
        output.extend_from_slice(self.url.as_bytes());
        output.extend_from_slice(self.ready_selector.as_bytes());
        output.extend_from_slice(self.reauth_selector.as_bytes());
        Ok(output)
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.len() < 16
            || payload[..4] != SESSION_HEALTH_MAGIC
            || u16::from_le_bytes(payload[4..6].try_into().unwrap())
                != SESSION_SCHEMA_VERSION
        {
            return Err(ProtocolError::InvalidSessionPayload);
        }
        let ready_ttl_seconds = u32::from_le_bytes(payload[6..10].try_into().unwrap());
        let url_len = usize::from(u16::from_le_bytes(payload[10..12].try_into().unwrap()));
        let ready_len = usize::from(u16::from_le_bytes(payload[12..14].try_into().unwrap()));
        let reauth_len = usize::from(u16::from_le_bytes(payload[14..16].try_into().unwrap()));
        let expected = 16usize
            .checked_add(url_len)
            .and_then(|value| value.checked_add(ready_len))
            .and_then(|value| value.checked_add(reauth_len))
            .ok_or(ProtocolError::InvalidSessionPayload)?;
        if payload.len() != expected {
            return Err(ProtocolError::InvalidSessionPayload);
        }
        let url_end = 16 + url_len;
        let ready_end = url_end + ready_len;
        let probe = Self {
            url: decode_probe_string(&payload[16..url_end])?,
            ready_selector: decode_probe_string(&payload[url_end..ready_end])?,
            reauth_selector: decode_probe_string(&payload[ready_end..])?,
            ready_ttl_seconds,
        };
        probe.validate()?;
        Ok(probe)
    }
}

fn valid_probe_selector(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PROBE_SELECTOR_BYTES
        && !value.chars().any(char::is_control)
}

fn decode_probe_string(bytes: &[u8]) -> Result<String, ProtocolError> {
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| ProtocolError::InvalidSessionPayload)
}

impl SessionStateUpdate {
    pub const ENCODED_LEN: usize = 16;

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.phase == SessionPhase::Unknown
            || (self.phase != SessionPhase::Ready && self.expires_at_unix_ms.is_some())
            || self.expires_at_unix_ms == Some(0)
        {
            return Err(ProtocolError::InvalidSessionPayload);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        let mut output = Vec::with_capacity(Self::ENCODED_LEN);
        output.extend_from_slice(&SESSION_UPDATE_MAGIC);
        output.extend_from_slice(&SESSION_SCHEMA_VERSION.to_le_bytes());
        output.push(self.phase as u8);
        output.push(u8::from(self.expires_at_unix_ms.is_some()));
        output.extend_from_slice(&self.expires_at_unix_ms.unwrap_or_default().to_le_bytes());
        Ok(output)
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.len() != Self::ENCODED_LEN
            || payload[..4] != SESSION_UPDATE_MAGIC
            || u16::from_le_bytes(payload[4..6].try_into().unwrap()) != SESSION_SCHEMA_VERSION
            || payload[7] > 1
        {
            return Err(ProtocolError::InvalidSessionPayload);
        }
        let raw_expiry = u64::from_le_bytes(payload[8..16].try_into().unwrap());
        let update = Self {
            phase: SessionPhase::from_wire(payload[6])?,
            expires_at_unix_ms: (payload[7] == 1).then_some(raw_expiry),
        };
        if payload[7] == 0 && raw_expiry != 0 {
            return Err(ProtocolError::InvalidSessionPayload);
        }
        update.validate()?;
        Ok(update)
    }
}

/// Non-secret state of one durable browser profile. Cookie names, cookie
/// values, tokens and credentials are deliberately absent from this schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentitySessionStatus {
    pub profile_exists: bool,
    pub persona_bound: bool,
    pub profile_class: Option<ProfileClass>,
    pub phase: SessionPhase,
    pub updated_at_unix_ms: u64,
    pub expires_at_unix_ms: Option<u64>,
}

impl IdentitySessionStatus {
    pub const ENCODED_LEN: usize = 26;

    pub fn unknown() -> Self {
        Self {
            profile_exists: false,
            persona_bound: false,
            profile_class: None,
            phase: SessionPhase::Unknown,
            updated_at_unix_ms: 0,
            expires_at_unix_ms: None,
        }
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if !self.profile_exists
            && (self.persona_bound
                || self.profile_class.is_some()
                || self.phase != SessionPhase::Unknown
                || self.updated_at_unix_ms != 0
                || self.expires_at_unix_ms.is_some())
        {
            return Err(ProtocolError::InvalidSessionPayload);
        }
        if self.persona_bound && self.profile_class.is_none() {
            return Err(ProtocolError::InvalidSessionPayload);
        }
        if self.phase != SessionPhase::Unknown && self.updated_at_unix_ms == 0 {
            return Err(ProtocolError::InvalidSessionPayload);
        }
        if self.expires_at_unix_ms == Some(0) {
            return Err(ProtocolError::InvalidSessionPayload);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        let mut output = Vec::with_capacity(Self::ENCODED_LEN);
        output.extend_from_slice(&SESSION_STATUS_MAGIC);
        output.extend_from_slice(&SESSION_SCHEMA_VERSION.to_le_bytes());
        output.push(self.profile_class.map_or(u8::MAX, |class| class as u8));
        output.push(self.phase as u8);
        let flags = u16::from(self.profile_exists)
            | (u16::from(self.persona_bound) << 1)
            | (u16::from(self.expires_at_unix_ms.is_some()) << 2);
        output.extend_from_slice(&flags.to_le_bytes());
        output.extend_from_slice(&self.updated_at_unix_ms.to_le_bytes());
        output.extend_from_slice(&self.expires_at_unix_ms.unwrap_or_default().to_le_bytes());
        Ok(output)
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.len() != Self::ENCODED_LEN
            || payload[..4] != SESSION_STATUS_MAGIC
            || u16::from_le_bytes(payload[4..6].try_into().unwrap()) != SESSION_SCHEMA_VERSION
        {
            return Err(ProtocolError::InvalidSessionPayload);
        }
        let flags = u16::from_le_bytes(payload[8..10].try_into().unwrap());
        if flags & !0b111 != 0 {
            return Err(ProtocolError::InvalidSessionPayload);
        }
        let raw_expiry = u64::from_le_bytes(payload[18..26].try_into().unwrap());
        let status = Self {
            profile_exists: flags & 1 != 0,
            persona_bound: flags & 0b10 != 0,
            profile_class: match payload[6] {
                u8::MAX => None,
                value => Some(ProfileClass::from_wire(value)?),
            },
            phase: SessionPhase::from_wire(payload[7])?,
            updated_at_unix_ms: u64::from_le_bytes(payload[10..18].try_into().unwrap()),
            expires_at_unix_ms: (flags & 0b100 != 0).then_some(raw_expiry),
        };
        if flags & 0b100 == 0 && raw_expiry != 0 {
            return Err(ProtocolError::InvalidSessionPayload);
        }
        status.validate()?;
        Ok(status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_update_and_status_round_trip_without_secret_fields() {
        let update = SessionStateUpdate {
            phase: SessionPhase::Ready,
            expires_at_unix_ms: Some(1_800_000_000_000),
        };
        assert_eq!(SessionStateUpdate::decode(&update.encode().unwrap()).unwrap(), update);

        let status = IdentitySessionStatus {
            profile_exists: true,
            persona_bound: true,
            profile_class: Some(ProfileClass::Authenticated),
            phase: SessionPhase::Ready,
            updated_at_unix_ms: 1_700_000_000_000,
            expires_at_unix_ms: Some(1_800_000_000_000),
        };
        let encoded = status.encode().unwrap();
        assert_eq!(encoded.len(), IdentitySessionStatus::ENCODED_LEN);
        assert_eq!(IdentitySessionStatus::decode(&encoded).unwrap(), status);

        let probe = SessionHealthProbe {
            url: "https://example.test/account".to_owned(),
            ready_selector: "main[data-authenticated]".to_owned(),
            reauth_selector: "form[action*='login']".to_owned(),
            ready_ttl_seconds: 900,
        };
        assert_eq!(
            SessionHealthProbe::decode(&probe.encode().unwrap()).unwrap(),
            probe
        );
    }
}
