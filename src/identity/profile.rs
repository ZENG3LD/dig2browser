use std::fmt;
use std::path::{Path, PathBuf};

/// Whether an identity may contain authenticated session material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdentityClass {
    Public,
    Authenticated,
}

/// Rendering backend assigned to an identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BrowserBackend {
    Chromium,
    Firefox,
    Lightweight,
}

/// Device-facing persona assigned to an identity.
///
/// `MobileLayout` is a declaration only. Browser emulation is intentionally
/// implemented separately so callers cannot mistake a viewport preset for a
/// real mobile device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DevicePersona {
    DesktopNative,
    MobileLayout,
}

/// A durable browser identity rooted below an operator-selected directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityProfile {
    id: String,
    class: IdentityClass,
    backend: BrowserBackend,
    device: DevicePersona,
    profile_dir: PathBuf,
}

impl IdentityProfile {
    pub fn new(
        profiles_root: impl AsRef<Path>,
        id: impl Into<String>,
        class: IdentityClass,
        backend: BrowserBackend,
        device: DevicePersona,
    ) -> Result<Self, IdentityError> {
        let id = id.into();
        validate_profile_id(&id)?;

        Ok(Self {
            profile_dir: profiles_root.as_ref().join(&id),
            id,
            class,
            backend,
            device,
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn class(&self) -> IdentityClass {
        self.class
    }

    pub fn backend(&self) -> BrowserBackend {
        self.backend
    }

    pub fn device(&self) -> DevicePersona {
        self.device
    }

    pub fn profile_dir(&self) -> &Path {
        &self.profile_dir
    }
}

/// Validate an identity ID before using it as a profile path component.
pub fn validate_profile_id(id: &str) -> Result<(), IdentityError> {
    if id.is_empty() || id.len() > 128 {
        return Err(IdentityError::InvalidProfileId(
            "profile ID must contain 1 to 128 ASCII characters".into(),
        ));
    }
    if !id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(IdentityError::InvalidProfileId(
            "profile ID may contain only ASCII letters, digits, '-', '_' and '.'".into(),
        ));
    }
    if id == "." || id == ".." || id.ends_with('.') {
        return Err(IdentityError::InvalidProfileId(
            "profile ID is not a safe path component".into(),
        ));
    }

    let stem = id.split('.').next().unwrap_or(id);
    let uppercase = stem.to_ascii_uppercase();
    let is_reserved = matches!(uppercase.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || reserved_numbered_name(&uppercase, "COM")
        || reserved_numbered_name(&uppercase, "LPT");
    if is_reserved {
        return Err(IdentityError::InvalidProfileId(
            "profile ID is a reserved Windows device name".into(),
        ));
    }

    Ok(())
}

fn reserved_numbered_name(value: &str, prefix: &str) -> bool {
    value
        .strip_prefix(prefix)
        .is_some_and(|suffix| suffix.len() == 1 && matches!(suffix.as_bytes()[0], b'1'..=b'9'))
}

#[derive(Debug)]
pub enum IdentityError {
    InvalidProfileId(String),
    ProfileAlreadyOwned {
        path: PathBuf,
        source: std::io::Error,
    },
    Io(std::io::Error),
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProfileId(reason) => write!(formatter, "invalid profile ID: {reason}"),
            Self::ProfileAlreadyOwned { path, source } => write!(
                formatter,
                "persistent profile '{}' is already owned: {source}",
                path.display()
            ),
            Self::Io(error) => write!(formatter, "identity profile I/O error: {error}"),
        }
    }
}

impl std::error::Error for IdentityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ProfileAlreadyOwned { source, .. } => Some(source),
            Self::Io(error) => Some(error),
            Self::InvalidProfileId(_) => None,
        }
    }
}

impl From<std::io::Error> for IdentityError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_stable_path_component() {
        assert!(validate_profile_id("telegram_public.v1").is_ok());
    }

    #[test]
    fn rejects_traversal_and_separators() {
        for id in ["", ".", "..", "../escape", r"folder\escape", "name."] {
            assert!(validate_profile_id(id).is_err(), "accepted {id:?}");
        }
    }

    #[test]
    fn rejects_windows_device_names_on_every_platform() {
        for id in ["CON", "nul.json", "Com1", "lpt9.profile"] {
            assert!(validate_profile_id(id).is_err(), "accepted {id:?}");
        }
    }

    #[test]
    fn profile_path_is_always_below_root() {
        let profile = IdentityProfile::new(
            "profiles",
            "public-one",
            IdentityClass::Public,
            BrowserBackend::Chromium,
            DevicePersona::DesktopNative,
        )
        .unwrap();

        assert_eq!(profile.profile_dir(), Path::new("profiles/public-one"));
    }
}
