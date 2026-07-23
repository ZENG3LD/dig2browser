//! Parsing of portable prepared-session cookie files for the gated
//! session-import flow (Phase B.1).
//!
//! An operator or agent prepares a session out of band and hands the station a
//! **local file path** (never the cookie bytes over IPC). The station reads and
//! parses that file locally into a `Vec<CookieSpec>` for the browser to install
//! via CDP `Network.setCookie`. The file is a self-describing typed set — the
//! portable equivalent of the `daemon4russian-parser` per-domain cookie dump,
//! but carrying each cookie's domain/path/flags so it transfers between machines
//! without an implied domain.

use dig2browser::agentic::CookieSpec;
use serde::Deserialize;

pub const SESSION_FILE_VERSION: u32 = 1;

// Mirror the worker-side bounds so a malformed file fails before any browser is
// leased (`src/agentic/worker.rs::validate_cookies`).
const MAX_IMPORT_COOKIES: usize = 512;
const MAX_COOKIE_NAME_BYTES: usize = 4 * 1024;
const MAX_COOKIE_VALUE_BYTES: usize = 8 * 1024;
const MAX_COOKIE_DOMAIN_BYTES: usize = 256;
const MAX_COOKIE_PATH_BYTES: usize = 4 * 1024;
const MAX_SESSION_FILE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Deserialize)]
struct SessionFile {
    version: u32,
    cookies: Vec<FileCookie>,
}

#[derive(Debug, Deserialize)]
struct FileCookie {
    name: String,
    value: String,
    domain: String,
    #[serde(default = "default_path")]
    path: String,
    #[serde(default)]
    secure: bool,
    #[serde(default)]
    http_only: bool,
    #[serde(default)]
    expires_unix: Option<i64>,
}

fn default_path() -> String {
    "/".to_owned()
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SessionImportError {
    #[error("session file exceeds the maximum size")]
    TooLarge,
    #[error("session file is not valid JSON")]
    Malformed,
    #[error("unsupported session file version {0}")]
    UnsupportedVersion(u32),
    #[error("session file cookie set is empty or exceeds bounds")]
    InvalidCookieSet,
}

/// Parse a portable session file into validated cookie specs.
///
/// Fail-closed: an empty set, an out-of-bounds field, embedded NUL, an
/// unexpected version, or malformed JSON all error rather than importing a
/// partial or unsafe set. The per-field bounds mirror the worker's
/// `validate_cookies` so a bad file fails before a browser is leased.
pub fn parse_session_cookies(bytes: &[u8]) -> Result<Vec<CookieSpec>, SessionImportError> {
    if bytes.len() > MAX_SESSION_FILE_BYTES {
        return Err(SessionImportError::TooLarge);
    }
    let file: SessionFile =
        serde_json::from_slice(bytes).map_err(|_| SessionImportError::Malformed)?;
    if file.version != SESSION_FILE_VERSION {
        return Err(SessionImportError::UnsupportedVersion(file.version));
    }
    if file.cookies.is_empty() || file.cookies.len() > MAX_IMPORT_COOKIES {
        return Err(SessionImportError::InvalidCookieSet);
    }
    let mut cookies = Vec::with_capacity(file.cookies.len());
    for cookie in file.cookies {
        if cookie.name.is_empty()
            || cookie.name.len() > MAX_COOKIE_NAME_BYTES
            || cookie.value.len() > MAX_COOKIE_VALUE_BYTES
            || cookie.domain.is_empty()
            || cookie.domain.len() > MAX_COOKIE_DOMAIN_BYTES
            || cookie.path.len() > MAX_COOKIE_PATH_BYTES
            || cookie.name.contains('\0')
            || cookie.value.contains('\0')
            || cookie.domain.contains('\0')
            || cookie.path.contains('\0')
        {
            return Err(SessionImportError::InvalidCookieSet);
        }
        cookies.push(CookieSpec {
            name: cookie.name,
            value: cookie.value,
            domain: cookie.domain,
            path: cookie.path,
            secure: cookie.secure,
            http_only: cookie.http_only,
            expires_unix: cookie.expires_unix,
        });
    }
    Ok(cookies)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_typed_session_file_with_defaults() {
        let json = br#"{"version":1,"cookies":[
            {"name":"sid","value":"abc","domain":".example.test","secure":true,"http_only":true},
            {"name":"csrf","value":"z","domain":"example.test","path":"/app","expires_unix":1750000000}
        ]}"#;
        let cookies = parse_session_cookies(json).expect("parse");
        assert_eq!(cookies.len(), 2);
        assert_eq!(cookies[0].name, "sid");
        assert_eq!(cookies[0].path, "/"); // default applied
        assert!(cookies[0].secure && cookies[0].http_only);
        assert_eq!(cookies[1].path, "/app");
        assert_eq!(cookies[1].expires_unix, Some(1_750_000_000));
        assert!(!cookies[1].secure); // default false
    }

    #[test]
    fn rejects_version_empty_malformed_and_out_of_bounds() {
        assert_eq!(
            parse_session_cookies(br#"{"version":2,"cookies":[]}"#),
            Err(SessionImportError::UnsupportedVersion(2))
        );
        assert_eq!(
            parse_session_cookies(br#"{"version":1,"cookies":[]}"#),
            Err(SessionImportError::InvalidCookieSet)
        );
        assert_eq!(
            parse_session_cookies(b"not json"),
            Err(SessionImportError::Malformed)
        );
        // Empty name is rejected.
        assert_eq!(
            parse_session_cookies(
                br#"{"version":1,"cookies":[{"name":"","value":"x","domain":"d"}]}"#
            ),
            Err(SessionImportError::InvalidCookieSet)
        );
        // An over-length value is rejected.
        let big_value = "x".repeat(MAX_COOKIE_VALUE_BYTES + 1);
        let big = format!(
            r#"{{"version":1,"cookies":[{{"name":"s","value":"{big_value}","domain":"d"}}]}}"#
        );
        assert_eq!(
            parse_session_cookies(big.as_bytes()),
            Err(SessionImportError::InvalidCookieSet)
        );
        // (Embedded-NUL rejection shares these bounds and is covered
        // deterministically by the worker's validate_cookies test.)
    }
}
