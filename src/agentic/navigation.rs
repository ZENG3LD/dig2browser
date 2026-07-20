//! Station-owned policy for explicit web navigation targets.

use std::{fmt, net::IpAddr};

use url::{Host, Url};

pub const MAX_ALLOWED_ORIGINS: usize = 256;

/// Canonical HTTP(S) target accepted by a [`NavigationPolicy`].
///
/// This exposes the URL components needed by station-owned egress without
/// leaking the parser dependency through the public API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NavigationTarget {
    scheme: String,
    host: String,
    effective_port: u16,
    authority: String,
    origin_form: String,
    ip_addr: Option<IpAddr>,
}

impl NavigationTarget {
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn effective_port(&self) -> u16 {
        self.effective_port
    }

    pub fn authority(&self) -> &str {
        &self.authority
    }

    pub fn origin_form(&self) -> &str {
        &self.origin_form
    }

    pub fn ip_addr(&self) -> Option<IpAddr> {
        self.ip_addr
    }

    fn from_url(url: &Url) -> Self {
        let (host, ip_addr) = match url.host().expect("validated URL has a host") {
            Host::Domain(domain) => (domain.to_owned(), None),
            Host::Ipv4(address) => (address.to_string(), Some(IpAddr::V4(address))),
            Host::Ipv6(address) => (address.to_string(), Some(IpAddr::V6(address))),
        };
        let effective_port = url
            .port_or_known_default()
            .expect("validated HTTP(S) URL has a known port");
        let default_port = match url.scheme() {
            "http" => 80,
            "https" => 443,
            _ => unreachable!("validated URL has an HTTP(S) scheme"),
        };
        let authority_host = if matches!(ip_addr, Some(IpAddr::V6(_))) {
            format!("[{host}]")
        } else {
            host.clone()
        };
        let authority = if effective_port == default_port {
            authority_host
        } else {
            format!("{authority_host}:{effective_port}")
        };
        let mut origin_form = url.path().to_owned();
        if let Some(query) = url.query() {
            origin_form.push('?');
            origin_form.push_str(query);
        }

        Self {
            scheme: url.scheme().to_owned(),
            host,
            effective_port,
            authority,
            origin_form,
            ip_addr,
        }
    }
}

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
    pub fn parse_target(&self, value: &str) -> Result<NavigationTarget, NavigationPolicyError> {
        let url = parse_navigation_url(value)?;
        self.validate_parsed_url(&url)?;
        Ok(NavigationTarget::from_url(&url))
    }

    pub fn validate(&self, value: &str) -> Result<(), NavigationPolicyError> {
        let url = parse_navigation_url(value)?;
        self.validate_parsed_url(&url)
    }

    fn validate_parsed_url(&self, url: &Url) -> Result<(), NavigationPolicyError> {
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

    #[test]
    fn parsed_target_exposes_canonical_domain_components() {
        let target = NavigationPolicy::open_web()
            .parse_target("HTTPS://EXAMPLE.com:443/a%20b?x=1&empty=#fragment")
            .expect("valid target");

        assert_eq!(target.scheme(), "https");
        assert_eq!(target.host(), "example.com");
        assert_eq!(target.effective_port(), 443);
        assert_eq!(target.authority(), "example.com");
        assert_eq!(target.origin_form(), "/a%20b?x=1&empty=");
        assert_eq!(target.ip_addr(), None);
    }

    #[test]
    fn parsed_target_handles_ip_literals_and_non_default_ports() {
        let policy = NavigationPolicy::exact_origins([
            "http://192.0.2.1:8080/",
            "https://[2001:db8::1]:8443/",
        ])
        .expect("valid exact origins");

        let ipv4 = policy
            .parse_target("http://192.0.2.1:8080/path")
            .expect("allowed IPv4 target");
        assert_eq!(ipv4.host(), "192.0.2.1");
        assert_eq!(ipv4.effective_port(), 8080);
        assert_eq!(ipv4.authority(), "192.0.2.1:8080");
        assert_eq!(ipv4.ip_addr(), Some("192.0.2.1".parse().unwrap()));

        let ipv6 = policy
            .parse_target("https://[2001:0DB8:0:0::1]:8443/?")
            .expect("allowed IPv6 target");
        assert_eq!(ipv6.host(), "2001:db8::1");
        assert_eq!(ipv6.effective_port(), 8443);
        assert_eq!(ipv6.authority(), "[2001:db8::1]:8443");
        assert_eq!(ipv6.origin_form(), "/?");
        assert_eq!(ipv6.ip_addr(), Some("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn parsed_target_preserves_policy_rejections() {
        let policy = NavigationPolicy::exact_origins(["https://example.com/"])
            .expect("valid exact origin");

        assert_eq!(
            policy.parse_target("https://example.net/"),
            Err(NavigationPolicyError::OriginDenied)
        );
        assert_eq!(
            policy.parse_target("https://user@example.com/"),
            Err(NavigationPolicyError::CredentialsForbidden)
        );
    }
}
