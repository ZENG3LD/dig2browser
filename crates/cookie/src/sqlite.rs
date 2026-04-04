//! Chrome cookie SQLite reader.

use std::path::{Path, PathBuf};

use crate::decrypt::{AesKey, decrypt_value};
use crate::types::{Cookie, CookieJar};
use crate::CookieError;

/// Find the Chrome cookie SQLite database inside a profile directory.
///
/// Chrome 120+ stores cookies at `Default/Network/Cookies`.
/// Older versions used `Default/Cookies`.
pub fn find_cookie_db(profile_dir: &Path) -> Option<PathBuf> {
    let new_path = profile_dir.join("Default").join("Network").join("Cookies");
    if new_path.exists() {
        return Some(new_path);
    }

    let old_path = profile_dir.join("Default").join("Cookies");
    if old_path.exists() {
        return Some(old_path);
    }

    None
}

/// Read and decrypt all cookies matching `domain` from the Chrome profile at `profile_dir`.
///
/// Copies the database to a temp file first to avoid SQLite WAL locking issues
/// when Chrome is still running.
pub fn read_cookies(
    profile_dir: &Path,
    domain: &str,
    key: &AesKey,
) -> Result<CookieJar, CookieError> {
    let db_path = find_cookie_db(profile_dir).ok_or_else(|| {
        let tried = profile_dir.join("Default").join("Network").join("Cookies");
        CookieError::DbMissing {
            path: tried.display().to_string(),
        }
    })?;

    // Copy the database to avoid "database is locked" from Chrome's WAL.
    let db_copy = std::env::temp_dir().join(format!(
        "dig2browser-cookies-{}.db",
        uuid::Uuid::new_v4()
    ));
    // Retry copy up to 10 times with 1 second sleep — Chrome may still hold WAL lock
    let mut last_err = None;
    for attempt in 0..10 {
        match std::fs::copy(&db_path, &db_copy) {
            Ok(_) => {
                last_err = None;
                break;
            }
            Err(e) => {
                tracing::debug!("[dig2browser] Cookie DB copy attempt {} failed: {}", attempt + 1, e);
                last_err = Some(e);
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
    }
    if let Some(e) = last_err {
        return Err(CookieError::Io(e));
    }

    let result = read_cookies_from_path(&db_copy, domain, key);

    // Always clean up the temp copy regardless of outcome.
    let _ = std::fs::remove_file(&db_copy);

    result
}

fn read_cookies_from_path(
    db_path: &Path,
    domain: &str,
    key: &AesKey,
) -> Result<CookieJar, CookieError> {
    use rusqlite::{Connection, OpenFlags};

    let conn = Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| CookieError::Sqlite(e.to_string()))?;

    let mut stmt = conn
        .prepare(
            "SELECT name, value, encrypted_value, host_key, path, is_secure, is_httponly, expires_utc \
             FROM cookies WHERE host_key LIKE ?",
        )
        .map_err(|e| CookieError::Sqlite(e.to_string()))?;

    let pattern = format!("%{}%", domain);

    let rows = stmt
        .query_map([&pattern], |row| {
            let name: String = row.get(0)?;
            let value: String = row.get(1)?;
            let encrypted_value: Vec<u8> = row.get(2)?;
            let host_key: String = row.get(3)?;
            let path: String = row.get(4)?;
            let is_secure: bool = row.get(5)?;
            let is_httponly: bool = row.get(6)?;
            let expires_utc: Option<i64> = row.get(7)?;
            Ok((name, value, encrypted_value, host_key, path, is_secure, is_httponly, expires_utc))
        })
        .map_err(|e| CookieError::Sqlite(e.to_string()))?;

    let mut cookies = Vec::new();

    for row_result in rows {
        let (name, value, encrypted_value, host_key, path, is_secure, is_httponly, expires_utc) =
            row_result.map_err(|e| CookieError::Sqlite(e.to_string()))?;

        let decrypted = if !encrypted_value.is_empty() {
            match decrypt_value(&encrypted_value, key) {
                Ok(v) => v,
                Err(e) => {
                    tracing::debug!("[dig2browser] Failed to decrypt cookie '{}': {}", name, e);
                    continue;
                }
            }
        } else {
            value
        };

        cookies.push(Cookie {
            name,
            value: decrypted,
            domain: host_key,
            path,
            is_secure,
            is_httponly,
            expires_utc,
        });
    }

    Ok(CookieJar(cookies))
}
