//! wasm-bindgen shim generation — wraps `wasm_bindgen_cli_support::Bindgen`.

use std::path::Path;

use super::WasmTestError;

/// The wasm-bindgen schema version this crate is pinned to.
pub const EXPECTED_SCHEMA: &str = "0.2.114";

/// Paths of the generated shim files inside `out_dir`.
pub struct ShimOutput {
    /// The JS glue file, e.g. `my_crate.js`.
    pub js_filename: String,
    /// The processed wasm file, e.g. `my_crate_bg.wasm`.
    pub wasm_filename: String,
}

// ---------------------------------------------------------------------------
// Minimal WASM binary section walker
// ---------------------------------------------------------------------------

const WASM_MAGIC: &[u8; 4] = b"\0asm";
const WASM_VERSION: &[u8; 4] = &[0x01, 0x00, 0x00, 0x00];

/// Decode one unsigned LEB128 value from `buf` starting at `*pos`.
/// Advances `*pos` past the consumed bytes. Returns `None` on truncation.
fn read_uleb(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    loop {
        let byte = *buf.get(*pos)?;
        *pos += 1;
        result |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some(result);
        }
        shift += 7;
        // u64 has 64 bits; after 10 groups of 7 we've covered 70 bits — stop.
        if shift >= 70 {
            return None;
        }
    }
}

/// Read a WASM length-prefixed name (LEB128 length + UTF-8 bytes).
/// Returns a `&str` into `buf`. Returns `None` on truncation or invalid UTF-8.
fn read_name<'a>(buf: &'a [u8], pos: &mut usize) -> Option<&'a str> {
    let len = read_uleb(buf, pos)? as usize;
    let end = pos.checked_add(len)?;
    let bytes = buf.get(*pos..end)?;
    *pos = end;
    std::str::from_utf8(bytes).ok()
}

/// Validate the WASM header (first 8 bytes). Returns `Err` on bad magic,
/// `Ok(8)` on success.
fn check_header(wasm: &[u8]) -> Result<usize, WasmTestError> {
    if wasm.len() < 8 {
        return Err(WasmTestError::Bindgen("not a valid wasm module".into()));
    }
    if &wasm[..4] != WASM_MAGIC {
        return Err(WasmTestError::Bindgen("not a valid wasm module".into()));
    }
    if &wasm[4..8] != WASM_VERSION {
        return Err(WasmTestError::Bindgen("unsupported wasm version".into()));
    }
    Ok(8)
}

/// Walk all sections in `wasm`, calling `visitor(id, section_bytes)` for each.
/// Stops early (no error) when the visitor returns `false`.
/// Returns `Err` only on structural malformation.
fn walk_sections<F>(wasm: &[u8], mut visitor: F) -> Result<(), WasmTestError>
where
    F: FnMut(u8, &[u8]) -> bool,
{
    let mut pos = check_header(wasm)?;
    while pos < wasm.len() {
        let id = *wasm
            .get(pos)
            .ok_or_else(|| WasmTestError::Bindgen("truncated wasm section id".into()))?;
        pos += 1;
        let size = read_uleb(wasm, &mut pos)
            .ok_or_else(|| WasmTestError::Bindgen("truncated wasm section size".into()))?
            as usize;
        let end = pos
            .checked_add(size)
            .filter(|&e| e <= wasm.len())
            .ok_or_else(|| WasmTestError::Bindgen("wasm section extends past end of file".into()))?;
        let contents = &wasm[pos..end];
        pos = end;
        if !visitor(id, contents) {
            break;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Return all export names with the `__wbgt_` prefix (wasm-bindgen-test fns).
///
/// These are discovered by parsing the export section (id 7).  If there is no
/// export section, returns an empty `Vec`.  Malformed wasm returns `Err`.
pub fn test_exports(wasm: &[u8]) -> Result<Vec<String>, WasmTestError> {
    let mut exports = Vec::new();
    walk_sections(wasm, |id, contents| {
        if id != 7 {
            return true; // keep walking
        }
        // Export section found — parse it.
        let mut pos = 0usize;
        if let Some(count) = read_uleb(contents, &mut pos) {
            for _ in 0..count {
                // name
                let name = match read_name(contents, &mut pos) {
                    Some(n) => n,
                    None => break,
                };
                // kind byte
                if pos >= contents.len() {
                    break;
                }
                pos += 1; // skip kind
                // index (LEB128)
                if read_uleb(contents, &mut pos).is_none() {
                    break;
                }
                if name.starts_with("__wbgt_") {
                    exports.push(name.to_owned());
                }
            }
        }
        false // stop walking — only one export section
    })?;
    Ok(exports)
}

/// Best-effort: read the `schema_version` embedded in a wasm-bindgen binary.
///
/// Scans the custom section named `__wasm_bindgen_unstable` and attempts to
/// extract the first semver string (`\d+\.\d+\.\d+`).  Returns `Ok(None)` if
/// the section is absent or the version cannot be located — this is not an
/// error; the authoritative check is done in `generate_shim`.
pub fn read_schema_version(wasm: &[u8]) -> Result<Option<String>, WasmTestError> {
    // best-effort
    let mut found: Option<String> = None;
    walk_sections(wasm, |id, contents| {
        if id != 0 {
            return true;
        }
        // Custom section: name then payload.
        let mut pos = 0usize;
        let name = match read_name(contents, &mut pos) {
            Some(n) => n,
            None => return true,
        };
        if name != "__wasm_bindgen_unstable" {
            return true;
        }
        // Payload = &contents[pos..]
        let payload = &contents[pos..];
        // Scan for first semver-looking run: maximal [0-9.] with exactly 2 dots
        // and all non-dot segments non-empty and purely numeric.
        let bytes = payload;
        let mut i = 0usize;
        while i < bytes.len() {
            if bytes[i].is_ascii_digit() {
                // Start of a potential semver — collect [0-9.] run.
                let start = i;
                while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
                    i += 1;
                }
                if let Ok(s) = std::str::from_utf8(&bytes[start..i]) {
                    if looks_like_semver(s) {
                        found = Some(s.to_owned());
                        return false; // stop
                    }
                }
            } else {
                i += 1;
            }
        }
        false // stop after this custom section regardless
    })?;
    Ok(found)
}

/// Returns `true` iff `s` looks like `\d+\.\d+\.\d+` (no pre/post-release).
fn looks_like_semver(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    parts.iter().all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}

/// Generate JS + wasm shim files into `out_dir` using `wasm_bindgen_cli_support`.
///
/// # Real `Bindgen` API (confirmed against 0.2.114 source)
///
/// ```text
/// // All &mut self methods — builder pattern with mutation, not consume-and-return.
/// // Mode methods return Result<&mut Bindgen, anyhow::Error>.
/// // Scalar flag methods return &mut Bindgen (infallible).
///
/// let mut b = Bindgen::new();
/// b.web(true)?;            // Result<&mut Bindgen, anyhow::Error>
/// b.input_path(path);      // &mut Bindgen
/// b.debug(false);          // &mut Bindgen
/// b.keep_debug(false);     // &mut Bindgen
/// b.emit_start(false);     // &mut Bindgen
/// b.generate(out_dir)?;    // Result<(), anyhow::Error>
///
/// Output layout written by generate():
///   {stem}.js          — JS glue (ES module)
///   {stem}_bg.wasm     — processed wasm
/// ```
pub fn generate_shim(wasm_path: &Path, out_dir: &Path) -> Result<ShimOutput, WasmTestError> {
    use wasm_bindgen_cli_support::Bindgen;

    // Derive output stem from the wasm filename (same logic as Bindgen::stem()).
    let stem = wasm_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("output")
        .to_owned();

    // Read the raw wasm bytes now so we can inspect them on schema errors.
    let wasm_bytes = std::fs::read(wasm_path)?;

    let mut b = Bindgen::new();
    b.web(true)
        .map_err(|e| WasmTestError::Bindgen(e.to_string()))?;
    b.input_path(wasm_path);
    b.debug(false);
    b.keep_debug(false);
    b.emit_start(false);

    match b.generate(out_dir) {
        Ok(()) => {}
        Err(e) => {
            let msg = e.to_string();
            let lower = msg.to_lowercase();
            if lower.contains("schema version") || lower.contains("bindgen format") {
                let found = read_schema_version(&wasm_bytes)
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| "unknown".to_owned());
                return Err(WasmTestError::SchemaMismatch {
                    expected: EXPECTED_SCHEMA.to_owned(),
                    found,
                });
            }
            return Err(WasmTestError::Bindgen(msg));
        }
    }

    Ok(ShimOutput {
        js_filename: format!("{stem}.js"),
        wasm_filename: format!("{stem}_bg.wasm"),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal valid wasm: magic + version, no sections.
    const MINIMAL_WASM: &[u8] = &[0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];

    #[test]
    fn test_exports_empty_for_minimal_wasm() {
        let exports = test_exports(MINIMAL_WASM).unwrap();
        assert!(exports.is_empty());
    }

    #[test]
    fn test_uleb128_multibyte() {
        // 300 encoded as LEB128 = [0xAC, 0x02]
        let buf = [0xACu8, 0x02];
        let mut pos = 0usize;
        let val = read_uleb(&buf, &mut pos).unwrap();
        assert_eq!(val, 300);
        assert_eq!(pos, 2);
    }

    #[test]
    fn test_uleb128_single_byte() {
        let buf = [0x7Fu8]; // 127
        let mut pos = 0usize;
        assert_eq!(read_uleb(&buf, &mut pos).unwrap(), 127);
        assert_eq!(pos, 1);
    }

    #[test]
    fn invalid_magic_returns_error() {
        let bad: &[u8] = &[0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
        let err = test_exports(bad).unwrap_err();
        match err {
            WasmTestError::Bindgen(msg) => assert!(msg.contains("not a valid wasm module")),
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn read_schema_version_minimal_wasm_returns_none() {
        let result = read_schema_version(MINIMAL_WASM).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn looks_like_semver_valid() {
        assert!(looks_like_semver("0.2.114"));
        assert!(looks_like_semver("1.0.0"));
    }

    #[test]
    fn looks_like_semver_invalid() {
        assert!(!looks_like_semver("1.0"));
        assert!(!looks_like_semver("1.0.0.0"));
        assert!(!looks_like_semver("1..0"));
        assert!(!looks_like_semver(".1.0"));
        assert!(!looks_like_semver("1.0.0-alpha"));
    }
}
