//! Core cookie types.

use std::path::Path;

use crate::CookieError;

/// A single HTTP cookie with its metadata.
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone, Default)]
pub struct CookieJar(pub Vec<Cookie>);

impl CookieJar {
    pub fn to_header_string(&self) -> String {
        self.0
            .iter()
            .map(|c| format!("{}={}", c.name, c.value))
            .collect::<Vec<_>>()
            .join("; ")
    }

    pub fn for_domain(&self, domain: &str) -> CookieJar {
        CookieJar(
            self.0
                .iter()
                .filter(|c| c.domain.contains(domain))
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

    pub fn save_to_file(&self, path: &Path) -> Result<(), CookieError> {
        use std::io::Write;
        let mut f = std::fs::File::create(path)?;
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

    pub fn load_from_file(path: &Path) -> Result<Self, CookieError> {
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
                        is_secure: parts.get(3).map_or(false, |s| s.contains("secure")),
                        is_httponly: parts.get(4).map_or(false, |s| s.contains("httponly")),
                        expires_utc: None,
                    });
                }
            }
        }
        Ok(CookieJar(cookies))
    }
}
