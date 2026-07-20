//! Station-owned policy for explicit web navigation targets.

use std::fmt;

use url::Url;

pub const MAX_ALLOWED_ORIGINS: usize = 256;

/// Immutable policy applied to every explicit browser navigation.
///
/// `OpenWeb` preserves compatibility by accepting any valid HTTP(S) origin.
/// `ExactOrigins` is an operator-owned allowlist. This type validates
/// requested URLs; it does not claim DNS, peer-IP, subresource, redirect, or
/// child-target enforcement by every runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NavigationPolicy {
    mode: NavigationPolicyMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum NavigationPolicyMode {
    OpenWeb,
    ExactOrigins(Vec<String>),
}

impl NavigationPolicy {
    pub fn open_web() -> Self {
        Self {
            mode: NavigationPolicyMode::OpenWeb,
        }
    }

    pub fn exact_origins<I, S>(origins: I) -> Result<Self, NavigationPolicyError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut canonical = Vec::new();
        for origin in origins {
            if canonical.len() >= MAX_ALLOWED_ORIGINS {
                return Err(NavigationPolicyError::TooManyOrigins);
            }
            canonical.push(parse_exact_origin(origin.as_ref())?);
        }
        canonical.sort_unstable();
        canonical.dedup();
        if canonical.is_empty() {
            return Err(NavigationPolicyError::EmptyAllowlist);
        }
        Ok(Self {
            mode: NavigationPolicyMode::ExactOrigins(canonical),
        })
    }
}

impl NavigationPolicy {
    pub fn validate(&self, value: &str) -> Result<(), NavigationPolicyError> {
        let url = parse_navigation_url(value)?;
        match &self.mode {
            NavigationPolicyMode::OpenWeb => Ok(()),
            NavigationPolicyMode::ExactOrigins(origins) => {
                let origin = url.origin().ascii_serialization();
                if origins.binary_search(&origin).is_ok() {
                    Ok(())
                } else {
                    Err(NavigationPolicyError::OriginDenied)
                }
            }
        }
    }

    pub fn allows(&self, value: &str) -> bool {
        self.validate(value).is_ok()
    }

    pub fn is_exact(&self) -> bool {
        matches!(self.mode, NavigationPolicyMode::ExactOrigins(_))
    }

    pub fn allowed_origins(&self) -> &[String] {
        match &self.mode {
            NavigationPolicyMode::OpenWeb => &[],
            NavigationPolicyMode::ExactOrigins(origins) => origins,
        }
    }
}

impl Default for NavigationPolicy {
    fn default() -> Self {
        Self::open_web()
    }
}

fn parse_navigation_url(value: &str) -> Result<Url, NavigationPolicyError> {
    let url = Url::parse(value).map_err(|_| NavigationPolicyError::InvalidUrl)?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(NavigationPolicyError::InvalidUrl);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(NavigationPolicyError::CredentialsForbidden);
    }
    Ok(url)
}

fn parse_exact_origin(value: &str) -> Result<String, NavigationPolicyError> {
    let url = parse_navigation_url(value)?;
    if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
        return Err(NavigationPolicyError::InvalidOrigin);
    }
    Ok(url.origin().ascii_serialization())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NavigationPolicyError {
    EmptyAllowlist,
    TooManyOrigins,
    InvalidOrigin,
    InvalidUrl,
    CredentialsForbidden,
    OriginDenied,
}

impl fmt::Display for NavigationPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EmptyAllowlist => "exact-origin policy requires at least one origin",
            Self::TooManyOrigins => "exact-origin policy exceeds its origin bound",
            Self::InvalidOrigin => "allowed origin contains non-origin URL data",
            Self::InvalidUrl => "target is not an absolute HTTP(S) URL with a host",
            Self::CredentialsForbidden => "URL credentials are forbidden",
            Self::OriginDenied => "origin is not allowed by station policy",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for NavigationPolicyError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_origins_are_canonical_bounded_and_credential_free() {
        let policy = NavigationPolicy::exact_origins([
            "https://EXAMPLE.com:443/",
            "http://127.0.0.1:8080/",
            "https://example.com/",
        ])
        .expect("valid exact origins");

        assert_eq!(
            policy.allowed_origins(),
            ["http://127.0.0.1:8080", "https://example.com"]
        );
        assert!(policy.allows("https://example.com/path?q=1"));
        assert!(policy.allows("http://127.0.0.1:8080/capture"));
        assert!(!policy.allows("https://example.net/"));
        assert!(!policy.allows("https://user:secret@example.com/"));
        assert_eq!(
            NavigationPolicy::exact_origins(["https://example.com/path"]),
            Err(NavigationPolicyError::InvalidOrigin)
        );
    }
}
