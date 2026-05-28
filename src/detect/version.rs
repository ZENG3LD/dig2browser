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
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    // Registry path and value for BLBeacon
    let subkey: &str = match kind {
        BrowserKind::Chrome | BrowserKind::Chromium => {
            r"Software\Google\Chrome\BLBeacon"
        }
        BrowserKind::Edge => r"SOFTWARE\Microsoft\Edge\BLBeacon",
        BrowserKind::Firefox => return None,
    };

    // Use windows-sys / raw registry API via the `windows` crate features.
    // Win32_System_Registry is not in our feature set, so we fall back to
    // std::process::Command on `reg query` which is universally available
    // and avoids adding a new windows feature.
    let output = std::process::Command::new("reg")
        .args([
            "query",
            &format!("HKCU\\{}", subkey),
            "/v",
            "version",
        ])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    // reg query output looks like:
    //     version    REG_SZ    125.0.2535.92
    let stdout = OsString::from_wide(
        &output
            .stdout
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect::<Vec<_>>(),
    );
    // stdout is likely plain UTF-8 on modern Windows; try that first.
    let text = String::from_utf8(output.stdout).ok()?;
    parse_reg_query_version(&text)
        .or_else(|| parse_reg_query_version(&stdout.to_string_lossy()))
}

/// Extract the version token from `reg query` output.
fn parse_reg_query_version(text: &str) -> Option<String> {
    // Line format: `    version    REG_SZ    125.0.2535.92`
    for line in text.lines() {
        if line.contains("REG_SZ") {
            let token = line.split_whitespace().last()?;
            if parse_version_4(token).is_some() {
                return Some(token.to_owned());
            }
        }
    }
    None
}
