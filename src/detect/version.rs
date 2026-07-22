//! Browser version detection from the install directory structure.

use super::BrowserBinary;
use crate::detect::BrowserKind;

/// Query the installed browser version string.
///
/// Returns a 4-part version string like `"125.0.2535.92"` for Chrome/Edge.
/// Returns `None` for Firefox (geckodriver needs no version match) and on any
/// failure.
pub fn browser_version(bin: &BrowserBinary) -> Option<String> {
    match bin.kind {
        BrowserKind::Firefox => None,
        _ => detect_version_impl(bin),
    }
}

#[cfg(target_os = "windows")]
fn detect_version_impl(bin: &BrowserBinary) -> Option<String> {
    // PRIMARY: Chrome/Edge install layout is:
    //   ...\Application\<version>\chrome.exe  (version dir next to the exe)
    //   ...\Application\chrome.exe            (the binary itself)
    // So bin.path.parent() == Application dir; scan its subdirs for a
    // 4-part numeric version name.
    let app_dir = bin.path.parent()?;

    let mut candidates: Vec<[u32; 4]> = Vec::new();

    if let Ok(entries) = std::fs::read_dir(app_dir) {
        for entry in entries.flatten() {
            if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let name = entry.file_name();
            let s = name.to_string_lossy();
            if let Some(parts) = parse_version_4(&s) {
                candidates.push(parts);
            }
        }
    }

    if !candidates.is_empty() {
        candidates.sort_unstable();
        let best = candidates.last()?;
        return Some(format!("{}.{}.{}.{}", best[0], best[1], best[2], best[3]));
    }

    // FALLBACK: BLBeacon registry key.
    registry_version(bin.kind)
}

#[cfg(not(target_os = "windows"))]
fn detect_version_impl(_bin: &BrowserBinary) -> Option<String> {
    None
}

/// Parse a string like `"125.0.2535.92"` into `[125, 0, 2535, 92]`.
/// Returns `None` if the string is not exactly 4 dot-separated numbers.
fn parse_version_4(s: &str) -> Option<[u32; 4]> {
    let mut parts = s.split('.');
    let a: u32 = parts.next()?.parse().ok()?;
    let b: u32 = parts.next()?.parse().ok()?;
    let c: u32 = parts.next()?.parse().ok()?;
    let d: u32 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None; // more than 4 parts
    }
    Some([a, b, c, d])
}

#[cfg(target_os = "windows")]
fn registry_version(kind: BrowserKind) -> Option<String> {
    use std::os::windows::ffi::OsStrExt;

    use windows::core::PCWSTR;
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegGetValueW, RegOpenCurrentUser, HKEY, KEY_QUERY_VALUE,
        REG_SZ, REG_VALUE_TYPE, RRF_RT_REG_SZ,
    };

    struct OwnedRegistryKey(HKEY);

    impl Drop for OwnedRegistryKey {
        fn drop(&mut self) {
            unsafe {
                let _ = RegCloseKey(self.0);
            }
        }
    }

    fn wide(value: &str) -> Vec<u16> {
        std::ffi::OsStr::new(value)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    // Registry path and value for BLBeacon
    let subkey: &str = match kind {
        BrowserKind::Chrome | BrowserKind::Chromium => {
            r"Software\Google\Chrome\BLBeacon"
        }
        BrowserKind::Edge => r"SOFTWARE\Microsoft\Edge\BLBeacon",
        BrowserKind::Firefox => return None,
    };

    // Use RegOpenCurrentUser rather than the cached HKEY_CURRENT_USER alias so
    // an impersonating broker reads the pipe peer's hive. This path must never
    // spawn an external utility from an elevated process.
    let mut current_user = HKEY::default();
    if unsafe { RegOpenCurrentUser(KEY_QUERY_VALUE.0, &mut current_user) }
        != ERROR_SUCCESS
    {
        return None;
    }
    let current_user = OwnedRegistryKey(current_user);
    let subkey = wide(subkey);
    let value_name = wide("version");
    let mut value_type = REG_VALUE_TYPE::default();
    let mut byte_len = 0_u32;
    let status = unsafe {
        RegGetValueW(
            current_user.0,
            PCWSTR(subkey.as_ptr()),
            PCWSTR(value_name.as_ptr()),
            RRF_RT_REG_SZ,
            Some(&mut value_type),
            None,
            Some(&mut byte_len),
        )
    };
    if status != ERROR_SUCCESS
        || value_type != REG_SZ
        || !(2..=256).contains(&byte_len)
        || byte_len & 1 != 0
    {
        return None;
    }
    let mut value = vec![0_u16; byte_len as usize / 2];
    let status = unsafe {
        RegGetValueW(
            current_user.0,
            PCWSTR(subkey.as_ptr()),
            PCWSTR(value_name.as_ptr()),
            RRF_RT_REG_SZ,
            Some(&mut value_type),
            Some(value.as_mut_ptr().cast()),
            Some(&mut byte_len),
        )
    };
    if status != ERROR_SUCCESS || value_type != REG_SZ || byte_len & 1 != 0 {
        return None;
    }
    let returned_units = (byte_len as usize / 2).min(value.len());
    value.truncate(returned_units);
    if value.last() == Some(&0) {
        value.pop();
    }
    let version = String::from_utf16(&value).ok()?;
    let parsed = parse_version_4(&version)?;
    Some(format!(
        "{}.{}.{}.{}",
        parsed[0], parsed[1], parsed[2], parsed[3]
    ))
}
