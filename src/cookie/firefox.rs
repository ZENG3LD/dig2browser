//! Firefox cookie reader — reads plaintext values from the `moz_cookies` SQLite table.
//!
//! Firefox stores cookie values in plaintext (no AES/DPAPI encryption).
//! The database is at `{profile}/cookies.sqlite` with a different schema than Chrome.
//!
//! Schema differences from Chrome:
//! - Table: `moz_cookies` (vs Chrome's `cookies`)
//! - Column: `host` (vs Chrome's `host_key`)
//! - Column: `value` plaintext (vs Chrome's `encrypted_value`)
//! - Column: `expiry` in Unix seconds (vs Chrome's `expires_utc` in Windows microseconds)
//! - Column: `isSecure` / `isHttpOnly` as INTEGER (0 or 1)

use std::path::{Path, PathBuf};

use crate::cookie::types::{Cookie, CookieJar};
use crate::error::CookieError;

/// Find the Firefox `cookies.sqlite` database inside a profile directory.
pub fn find_firefox_cookie_db(profile_dir: &Path) -> Option<PathBuf> {
    let path = profile_dir.join("cookies.sqlite");
    if path.exists() {
        Some(path)
    } else {
        None
    }
}

/// Read cookies matching `domain` from a Firefox profile directory.
///
/// Values are stored as plaintext — no decryption required.
/// Copies the database to a temp file first to avoid SQLite WAL locking.
pub fn read_firefox_cookies(
    profile_dir: &Path,
    domain: &str,
) -> Result<CookieJar, CookieError> {
    let db_path = find_firefox_cookie_db(profile_dir).ok_or_else(|| {
        CookieError::DbMissing {
            path: profile_dir.join("cookies.sqlite").display().to_string(),
        }
    })?;

    // Copy to temp to avoid WAL lock from a running Firefox process.
    let db_copy = std::env::temp_dir().join(format!(
        "dig2browser-ff-cookies-{}.db",
        uuid::Uuid::new_v4()
    ));
    std::fs::copy(&db_path, &db_copy).map_err(CookieError::Io)?;

    let result = read_moz_cookies(&db_copy, domain);
    let _ = std::fs::remove_file(&db_copy);
    result
}

fn read_moz_cookies(db_path: &Path, domain: &str) -> Result<CookieJar, CookieError> {
    use rusqlite::{Connection, OpenFlags};

    let conn = Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| CookieError::Sqlite(e.to_string()))?;

    let mut stmt = conn
        .prepare(
            "SELECT name, value, host, path, isSecure, isHttpOnly, expiry \
             FROM moz_cookies WHERE host LIKE ?",
        )
        .map_err(|e| CookieError::Sqlite(e.to_string()))?;

    let pattern = format!("%{}%", domain);

    let rows = stmt
        .query_map([&pattern], |row| {
            let name: String = row.get(0)?;
            let value: String = row.get(1)?;
            let host: String = row.get(2)?;
            let path: String = row.get(3)?;
            let is_secure: i32 = row.get(4)?;
            let is_httponly: i32 = row.get(5)?;
            let expiry: Option<i64> = row.get(6)?;
            Ok((name, value, host, path, is_secure, is_httponly, expiry))
        })
        .map_err(|e| CookieError::Sqlite(e.to_string()))?;

    let mut cookies = Vec::new();
    for row_result in rows {
        let (name, value, host, path, is_secure, is_httponly, expiry) =
            row_result.map_err(|e| CookieError::Sqlite(e.to_string()))?;

        cookies.push(Cookie {
            name,
            value,
            domain: host,
            path,
            is_secure: is_secure != 0,
            is_httponly: is_httponly != 0,
            // Firefox stores expiry as Unix seconds (i64).
            // Chrome stores expires_utc as microseconds since Windows epoch (1601-01-01).
            // Our Cookie type uses Unix seconds convention — store directly.
            expires_utc: expiry,
        });
    }

    Ok(CookieJar(cookies))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    /// Build a minimal `moz_cookies` SQLite database in a temp file.
    fn create_fixture_db() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "dig2browser-ff-test-{}.db",
            uuid::Uuid::new_v4()
        ));

        let conn = Connection::open(&path).expect("create test db");
        conn.execute_batch(
            "CREATE TABLE moz_cookies (
                name TEXT,
                value TEXT,
                host TEXT,
                path TEXT,
                isSecure INTEGER,
                isHttpOnly INTEGER,
                expiry INTEGER
            );
            INSERT INTO moz_cookies VALUES
                ('session', 'abc123', '.example.com', '/', 1, 0, 1700000000),
                ('pref',    'dark',  '.example.com', '/', 0, 1, 1800000000),
                ('other',   'xyz',   '.other.org',   '/', 0, 0, NULL);",
        )
        .expect("populate test db");
        path
    }

    #[test]
    fn read_moz_cookies_returns_matching_rows() {
        let db = create_fixture_db();
        let result = read_moz_cookies(&db, "example.com").expect("read cookies");
        let _ = std::fs::remove_file(&db);

        assert_eq!(result.len(), 2);
        let session = result.iter().find(|c| c.name == "session").expect("session cookie");
        assert_eq!(session.value, "abc123");
        assert_eq!(session.domain, ".example.com");
        assert!(session.is_secure);
        assert!(!session.is_httponly);
        assert_eq!(session.expires_utc, Some(1700000000));

        let pref = result.iter().find(|c| c.name == "pref").expect("pref cookie");
        assert!(!pref.is_secure);
        assert!(pref.is_httponly);
    }

    #[test]
    fn read_moz_cookies_excludes_other_domains() {
        let db = create_fixture_db();
        let result = read_moz_cookies(&db, "example.com").expect("read cookies");
        let _ = std::fs::remove_file(&db);

        assert!(result.iter().all(|c| !c.domain.contains("other.org")));
    }

    #[test]
    fn find_firefox_cookie_db_returns_none_when_missing() {
        let dir = std::env::temp_dir().join(format!("no-such-dir-{}", uuid::Uuid::new_v4()));
        assert!(find_firefox_cookie_db(&dir).is_none());
    }
}
