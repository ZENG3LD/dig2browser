//! Core cookie types.

use std::fmt;
use std::path::Path;

use crate::CookieError;

/// A single HTTP cookie with its metadata.
#[derive(Clone)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    pub is_secure: bool,
    pub is_httponly: bool,
    pub expires_utc: Option<i64>,
}

/// A collection of cookies.
#[derive(Clone, Default)]
pub struct CookieJar(pub Vec<Cookie>);

impl fmt::Debug for Cookie {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Cookie")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .field("domain", &self.domain)
            .field("path", &self.path)
            .field("is_secure", &self.is_secure)
            .field("is_httponly", &self.is_httponly)
            .field("expires_utc", &self.expires_utc)
            .finish()
    }
}

impl fmt::Display for Cookie {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}=<redacted>; domain={}; path={}",
            self.name, self.domain, self.path
        )
    }
}

impl fmt::Debug for CookieJar {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("CookieJar").field(&self.0).finish()
    }
}

impl fmt::Display for CookieJar {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "CookieJar(len={}, values=<redacted>)",
            self.len()
        )
    }
}

impl CookieJar {
    /// Serialize cookie values for an HTTP `Cookie` header.
    ///
    /// The result is secret material and must not be logged or persisted.
    pub fn to_insecure_header_string(&self) -> String {
        self.0
            .iter()
            .map(|c| format!("{}={}", c.name, c.value))
            .collect::<Vec<_>>()
            .join("; ")
    }

    #[deprecated(note = "use to_insecure_header_string to acknowledge secret material")]
    pub fn to_header_string(&self) -> String {
        self.to_insecure_header_string()
    }

    pub fn for_domain(&self, domain: &str) -> CookieJar {
        let requested = domain.trim_start_matches('.').to_ascii_lowercase();
        CookieJar(
            self.0
                .iter()
                .filter(|cookie| {
                    let cookie_domain = cookie.domain.trim_start_matches('.').to_ascii_lowercase();
                    requested == cookie_domain
                        || requested
                            .strip_suffix(&cookie_domain)
                            .is_some_and(|prefix| prefix.ends_with('.'))
                })
                .cloned()
                .collect(),
        )
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Cookie> {
        self.0.iter()
    }

    /// Export plaintext cookies. The destination must be treated as a secret.
    ///
    /// This refuses to overwrite an existing path. On Unix, the new file is
    /// created with mode `0600`; on Windows it inherits the parent directory's
    /// ACL, so authenticated exports require a restricted parent directory.
    pub fn save_to_insecure_file(&self, path: &Path) -> Result<(), CookieError> {
        use std::fs::OpenOptions;
        use std::io::Write;

        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut f = options.open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        for c in &self.0 {
            writeln!(
                f,
                "{}={}\t{}\t{}\t{}\t{}",
                c.name,
                c.value,
                c.domain,
                c.path,
                if c.is_secure { "secure" } else { "" },
                if c.is_httponly { "httponly" } else { "" }
            )?;
        }
        Ok(())
    }

    #[deprecated(
        note = "plaintext cookie export is insecure; use save_to_insecure_file explicitly"
    )]
    pub fn save_to_file(&self, path: &Path) -> Result<(), CookieError> {
        self.save_to_insecure_file(path)
    }

    /// Import cookies from the legacy plaintext format.
    pub fn load_from_insecure_file(path: &Path) -> Result<Self, CookieError> {
        Self::load_plaintext(path)
    }

    #[deprecated(
        note = "plaintext cookie import is insecure; use load_from_insecure_file explicitly"
    )]
    pub fn load_from_file(path: &Path) -> Result<Self, CookieError> {
        Self::load_plaintext(path)
    }

    fn load_plaintext(path: &Path) -> Result<Self, CookieError> {
        let content = std::fs::read_to_string(path)?;
        let mut cookies = Vec::new();
        for line in content.lines() {
            let parts: Vec<&str> = line.splitn(6, '\t').collect();
            if parts.len() >= 4 {
                let nv: Vec<&str> = parts[0].splitn(2, '=').collect();
                if nv.len() == 2 {
                    cookies.push(Cookie {
                        name: nv[0].to_string(),
                        value: nv[1].to_string(),
                        domain: parts[1].to_string(),
                        path: parts[2].to_string(),
                        is_secure: parts.get(3).is_some_and(|s| s.contains("secure")),
                        is_httponly: parts.get(4).is_some_and(|s| s.contains("httponly")),
                        expires_utc: None,
                    });
                }
            }
        }
        Ok(CookieJar(cookies))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret_cookie() -> Cookie {
        Cookie {
            name: "session".into(),
            value: "do-not-log-this".into(),
            domain: "example.test".into(),
            path: "/".into(),
            is_secure: true,
            is_httponly: true,
            expires_utc: None,
        }
    }

    #[test]
    fn debug_and_display_redact_cookie_values() {
        let cookie = secret_cookie();
        let jar = CookieJar(vec![cookie.clone()]);

        for rendered in [
            format!("{cookie:?}"),
            cookie.to_string(),
            format!("{jar:?}"),
            jar.to_string(),
        ] {
            assert!(!rendered.contains(&cookie.value));
            assert!(rendered.contains("redacted"));
        }
    }

    #[test]
    fn insecure_header_is_explicit_and_preserves_wire_value() {
        let jar = CookieJar(vec![secret_cookie()]);
        assert_eq!(jar.to_insecure_header_string(), "session=do-not-log-this");
    }

    #[test]
    fn insecure_export_refuses_to_overwrite_existing_file() {
        let path = std::env::temp_dir().join(format!(
            "dig2browser-cookie-export-test-{}",
            uuid::Uuid::new_v4()
        ));
        let jar = CookieJar(vec![secret_cookie()]);

        jar.save_to_insecure_file(&path).unwrap();
        let imported = CookieJar::load_from_insecure_file(&path).unwrap();
        assert_eq!(imported.0[0].value, "do-not-log-this");

        let error = jar.save_to_insecure_file(&path).unwrap_err();
        assert!(matches!(
            error,
            CookieError::Io(ref source) if source.kind() == std::io::ErrorKind::AlreadyExists
        ));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn domain_filter_uses_cookie_domain_boundaries() {
        let mut parent = secret_cookie();
        parent.domain = ".example.test".into();
        let mut unrelated = secret_cookie();
        unrelated.domain = "notexample.test".into();
        let jar = CookieJar(vec![parent, unrelated]);

        assert_eq!(jar.for_domain("www.example.test").len(), 1);
        assert_eq!(jar.for_domain("example.test").len(), 1);
        assert!(jar.for_domain("badexample.test").is_empty());
    }
}
