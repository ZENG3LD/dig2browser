//! Test-name filter parsing and matching for the wasm test runner.
//!
//! Mirrors the behaviour of native `cargo test -- [filters] [flags]`:
//!
//! - Positional arguments (not starting with `--`) are name filters.
//! - `--exact`            — exact match instead of substring.
//! - `--nocapture`        — route console output to `#output`.
//! - `--include-ignored`  — also run `#[ignore]`d tests.
//! - `--ignored`          — run *only* `#[ignore]`d tests (implies include-ignored).
//!
//! Export → matchable-name mapping
//! --------------------------------
//! wasm-bindgen-test emits exports like `__wbgt_ws_binance_a1b2c3` where:
//!   - `__wbgt_` is the fixed prefix,
//!   - the trailing `_<hash>` is a short hex suffix added by wasm-bindgen,
//!   - the middle part is the test function name (with `::` replaced by `_`).
//!
//! `export_to_name` strips `__wbgt_` to yield the full mangled name
//! (`ws_binance_a1b2c3`).  For substring matching this is sufficient.
//! For `--exact` we additionally strip the trailing `_<hex>` segment so that
//! `ws_binance` matches `__wbgt_ws_binance_a1b2c3`.

/// Parsed flags extracted from `filter_args`.
#[derive(Debug, Default, Clone)]
pub struct FilterSpec {
    /// Positional name filters (substring match, or exact when `exact` is set).
    pub name_filters: Vec<String>,
    /// `--exact`: require full name equality (minus the trailing hash).
    pub exact: bool,
    /// `--nocapture`: route console.log to `#output`.
    pub nocapture: bool,
    /// `--include-ignored` OR `--ignored`: pass `true` to `cx.include_ignored`.
    pub include_ignored: bool,
}

impl FilterSpec {
    /// Parse raw `filter_args` (everything after `--` on the cargo test command
    /// line, or the direct args passed to the runner binary).
    pub fn parse(args: &[String]) -> Self {
        let mut spec = Self::default();
        for arg in args {
            match arg.as_str() {
                "--exact" => spec.exact = true,
                "--nocapture" => spec.nocapture = true,
                "--include-ignored" => spec.include_ignored = true,
                "--ignored" => spec.include_ignored = true,
                // Unknown flags starting with `--` are silently skipped.
                s if s.starts_with("--") => {}
                // Positional argument → name filter.
                name => spec.name_filters.push(name.to_owned()),
            }
        }
        spec
    }

    /// Return `true` if `export` passes this filter spec.
    ///
    /// `export` is a raw `__wbgt_*` symbol name.  With no name filters every
    /// export is included.
    pub fn matches(&self, export: &str) -> bool {
        if self.name_filters.is_empty() {
            return true;
        }
        let derived = export_to_name(export);
        if self.exact {
            let bare = strip_hash_suffix(derived);
            self.name_filters.iter().any(|f| bare == f.as_str())
        } else {
            self.name_filters.iter().any(|f| derived.contains(f.as_str()))
        }
    }

    /// Filter `exports` into (included, filtered_count).
    pub fn apply<'a>(&self, exports: &'a [String]) -> (Vec<&'a String>, usize) {
        let included: Vec<&'a String> = exports.iter().filter(|e| self.matches(e)).collect();
        let filtered_count = exports.len() - included.len();
        (included, filtered_count)
    }
}

/// Derive a matchable name from a `__wbgt_*` export symbol.
///
/// Strips the `__wbgt_` prefix; the result is the mangled test name including
/// the trailing hash (e.g. `ws_binance_a1b2c3`).
pub fn export_to_name(export: &str) -> &str {
    export.strip_prefix("__wbgt_").unwrap_or(export)
}

/// Strip the trailing `_<hex>` hash segment from a derived name.
///
/// Looks for the last `_` and checks whether the suffix after it looks like a
/// short hex string (1–16 hex chars).  If so, returns the name without that
/// suffix.  Otherwise returns the full name unchanged.
///
/// Example: `ws_binance_a1b2c3` → `ws_binance`.
fn strip_hash_suffix(name: &str) -> &str {
    if let Some(pos) = name.rfind('_') {
        let suffix = &name[pos + 1..];
        // Consider it a hash if it is 1–16 chars and all hex digits.
        if !suffix.is_empty()
            && suffix.len() <= 16
            && suffix.chars().all(|c| c.is_ascii_hexdigit())
        {
            return &name[..pos];
        }
    }
    name
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── FilterSpec::parse ─────────────────────────────────────────────────────

    #[test]
    fn parse_empty() {
        let spec = FilterSpec::parse(&[]);
        assert!(spec.name_filters.is_empty());
        assert!(!spec.exact);
        assert!(!spec.nocapture);
        assert!(!spec.include_ignored);
    }

    #[test]
    fn parse_positional_filters() {
        let args = ["ws_binance".to_string(), "my_test".to_string()];
        let spec = FilterSpec::parse(&args);
        assert_eq!(spec.name_filters, &["ws_binance", "my_test"]);
        assert!(!spec.exact);
    }

    #[test]
    fn parse_flags_only() {
        let args = [
            "--nocapture".to_string(),
            "--exact".to_string(),
            "--include-ignored".to_string(),
        ];
        let spec = FilterSpec::parse(&args);
        assert!(spec.name_filters.is_empty());
        assert!(spec.exact);
        assert!(spec.nocapture);
        assert!(spec.include_ignored);
    }

    #[test]
    fn parse_ignored_sets_include_ignored() {
        let args = ["--ignored".to_string()];
        let spec = FilterSpec::parse(&args);
        assert!(spec.include_ignored);
    }

    #[test]
    fn parse_mixed() {
        let args = [
            "ws_binance".to_string(),
            "--nocapture".to_string(),
            "other".to_string(),
        ];
        let spec = FilterSpec::parse(&args);
        assert_eq!(spec.name_filters, &["ws_binance", "other"]);
        assert!(spec.nocapture);
        assert!(!spec.exact);
    }

    #[test]
    fn parse_unknown_flag_ignored() {
        let args = ["--some-future-flag".to_string(), "filter".to_string()];
        let spec = FilterSpec::parse(&args);
        assert_eq!(spec.name_filters, &["filter"]);
    }

    // ── export_to_name ────────────────────────────────────────────────────────

    #[test]
    fn export_to_name_strips_prefix() {
        assert_eq!(export_to_name("__wbgt_ws_binance_a1b2c3"), "ws_binance_a1b2c3");
    }

    #[test]
    fn export_to_name_no_prefix_unchanged() {
        assert_eq!(export_to_name("something_else"), "something_else");
    }

    // ── strip_hash_suffix ─────────────────────────────────────────────────────

    #[test]
    fn strip_hash_suffix_removes_hex_tail() {
        assert_eq!(strip_hash_suffix("ws_binance_a1b2c3"), "ws_binance");
    }

    #[test]
    fn strip_hash_suffix_no_change_when_non_hex() {
        // "test" is not hex-only (contains 't', 's')
        assert_eq!(strip_hash_suffix("ws_binance_test"), "ws_binance_test");
    }

    #[test]
    fn strip_hash_suffix_no_change_when_too_long() {
        // 17 hex chars → not treated as hash
        assert_eq!(
            strip_hash_suffix("ws_binance_12345678901234567"),
            "ws_binance_12345678901234567"
        );
    }

    #[test]
    fn strip_hash_suffix_single_char_hex() {
        assert_eq!(strip_hash_suffix("my_test_f"), "my_test");
    }

    // ── FilterSpec::matches ───────────────────────────────────────────────────

    #[test]
    fn matches_no_filters_includes_all() {
        let spec = FilterSpec::parse(&[]);
        assert!(spec.matches("__wbgt_anything_abc123"));
    }

    #[test]
    fn matches_substring_hit() {
        let args = ["ws_binance".to_string()];
        let spec = FilterSpec::parse(&args);
        assert!(spec.matches("__wbgt_ws_binance_a1b2c3"));
    }

    #[test]
    fn matches_substring_miss() {
        let args = ["other_test".to_string()];
        let spec = FilterSpec::parse(&args);
        assert!(!spec.matches("__wbgt_ws_binance_a1b2c3"));
    }

    #[test]
    fn matches_exact_hit() {
        let args = ["--exact".to_string(), "ws_binance".to_string()];
        let spec = FilterSpec::parse(&args);
        // export: __wbgt_ws_binance_a1b2c3 → name: ws_binance_a1b2c3 → bare: ws_binance
        assert!(spec.matches("__wbgt_ws_binance_a1b2c3"));
    }

    #[test]
    fn matches_exact_miss() {
        let args = ["--exact".to_string(), "ws_bina".to_string()];
        let spec = FilterSpec::parse(&args);
        assert!(!spec.matches("__wbgt_ws_binance_a1b2c3"));
    }

    #[test]
    fn matches_exact_with_non_hex_suffix_unchanged() {
        // If the last segment looks like a real name part (not hex), exact
        // match compares against the full derived name.
        let args = ["--exact".to_string(), "ws_binance_test".to_string()];
        let spec = FilterSpec::parse(&args);
        // export: __wbgt_ws_binance_test → name: ws_binance_test → bare: ws_binance_test (no hash)
        assert!(spec.matches("__wbgt_ws_binance_test"));
    }

    // ── FilterSpec::apply ─────────────────────────────────────────────────────

    #[test]
    fn apply_filters_and_counts() {
        let exports = vec![
            "__wbgt_ws_binance_a1b2c3".to_string(),
            "__wbgt_http_test_d4e5f6".to_string(),
            "__wbgt_ws_okx_789abc".to_string(),
        ];
        let args = ["ws_".to_string()];
        let spec = FilterSpec::parse(&args);
        let (included, filtered_count) = spec.apply(&exports);
        assert_eq!(included.len(), 2);
        assert_eq!(filtered_count, 1);
    }

    #[test]
    fn apply_no_filter_includes_all() {
        let exports = vec![
            "__wbgt_a_abc123".to_string(),
            "__wbgt_b_def456".to_string(),
        ];
        let spec = FilterSpec::parse(&[]);
        let (included, filtered_count) = spec.apply(&exports);
        assert_eq!(included.len(), 2);
        assert_eq!(filtered_count, 0);
    }
}
