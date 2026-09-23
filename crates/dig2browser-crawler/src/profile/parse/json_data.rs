//! Extractor for embedded JSON data from SPA framework script tags.
//!
//! Handles patterns like `__NEXT_DATA__`, `__NUXT_DATA__`, `window.__NUXT__`,
//! and `window.__INITIAL_STATE__` that Next.js, Nuxt, and similar frameworks
//! inject into HTML pages as inline script payloads.

use regex::Regex;
use serde::{Deserialize, Serialize};

/// The SPA framework / injection pattern that produced a JSON block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpaSource {
    /// `<script id="__NEXT_DATA__">…</script>` (Next.js)
    NextData,
    /// `<script id="__NUXT_DATA__">…</script>` (Nuxt 3)
    NuxtData,
    /// `window.__NUXT__ = {…}` (Nuxt 2)
    NuxtWindow,
    /// `window.__INITIAL_STATE__ = …` (various frameworks)
    InitialState,
    /// Any other pattern identified by name.
    Other(String),
}

impl SpaSource {
    /// Human-readable display name used in prompts and logs.
    pub fn display_name(&self) -> &str {
        match self {
            SpaSource::NextData => "__NEXT_DATA__",
            SpaSource::NuxtData => "__NUXT_DATA__",
            SpaSource::NuxtWindow => "window.__NUXT__",
            SpaSource::InitialState => "window.__INITIAL_STATE__",
            SpaSource::Other(name) => name.as_str(),
        }
    }
}

/// A successfully-parsed SPA JSON block extracted from raw HTML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpaJsonBlock {
    /// Which framework pattern produced this block.
    pub source: SpaSource,
    /// Parsed JSON value.
    pub data: serde_json::Value,
    /// Size in bytes of the raw JSON string before parsing.
    pub raw_size: usize,
}

/// Scan `html` for known SPA framework JSON injection patterns and return all
/// successfully-parsed blocks.
///
/// Blocks whose captured content is not valid JSON are skipped with a warning
/// log (tracing). The order of results mirrors the order patterns appear in
/// the HTML.
pub fn extract_spa_json(html: &str) -> Vec<SpaJsonBlock> {
    let patterns: &[(&str, SpaSource)] = &[
        (
            r#"(?i)<script[^>]*id="__NEXT_DATA__"[^>]*>([\s\S]*?)</script>"#,
            SpaSource::NextData,
        ),
        (
            r#"(?i)<script[^>]*id="__NUXT_DATA__"[^>]*>([\s\S]*?)</script>"#,
            SpaSource::NuxtData,
        ),
        (
            r#"window\.__NUXT__\s*=\s*(\{[\s\S]*?\});\s*(?:</script>|$)"#,
            SpaSource::NuxtWindow,
        ),
        (
            r#"window\.__INITIAL_STATE__\s*=\s*([\s\S]*?);\s*(?:</script>|$)"#,
            SpaSource::InitialState,
        ),
    ];

    let mut blocks = Vec::new();

    for (pattern, source) in patterns {
        let re = match Regex::new(pattern) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(pattern, error = %e, "SPA JSON regex compile error");
                continue;
            }
        };

        for caps in re.captures_iter(html) {
            let raw = match caps.get(1) {
                Some(m) => m.as_str(),
                None => continue,
            };

            let raw_trimmed = raw.trim();
            match serde_json::from_str::<serde_json::Value>(raw_trimmed) {
                Ok(data) => {
                    tracing::debug!(
                        source = source.display_name(),
                        bytes = raw_trimmed.len(),
                        "SPA JSON block extracted"
                    );
                    blocks.push(SpaJsonBlock {
                        source: source.clone(),
                        data,
                        raw_size: raw_trimmed.len(),
                    });
                }
                Err(e) => {
                    tracing::warn!(
                        source = source.display_name(),
                        bytes = raw_trimmed.len(),
                        error = %e,
                        "SPA JSON block found but failed to parse"
                    );
                }
            }
        }
    }

    blocks
}

/// Build a concise text summary of SPA JSON blocks for injection into an
/// agent prompt.
///
/// For each block this shows the source type and a structural skeleton of the
/// JSON (keys only, no leaf values) truncated to `max_chars` total. This keeps
/// the token budget predictable while still giving the agent enough context
/// to navigate the tree.
pub fn summarize_spa_json(blocks: &[SpaJsonBlock], max_chars: usize) -> String {
    if blocks.is_empty() {
        return String::new();
    }

    let mut out = String::new();
    let per_block = (max_chars / blocks.len()).max(200);

    for block in blocks {
        let header = format!(
            "\n### SPA JSON: {} ({} bytes)\n",
            block.source.display_name(),
            block.raw_size
        );
        out.push_str(&header);

        let skeleton = json_skeleton(&block.data, 0, 3);
        let truncated = if skeleton.len() > per_block {
            format!("{}… (truncated)", &skeleton[..per_block])
        } else {
            skeleton
        };
        out.push_str(&truncated);
        out.push('\n');
    }

    if out.len() > max_chars {
        out.truncate(max_chars);
        out.push_str("… (truncated)");
    }

    out
}

/// Recursively build a key-skeleton of a JSON value (no leaf values).
///
/// `depth` is the current recursion depth; `max_depth` limits how deep we go.
fn json_skeleton(value: &serde_json::Value, depth: usize, max_depth: usize) -> String {
    if depth > max_depth {
        return "…".to_string();
    }

    let indent = "  ".repeat(depth);
    let inner_indent = "  ".repeat(depth + 1);

    match value {
        serde_json::Value::Object(map) => {
            if map.is_empty() {
                return "{}".to_string();
            }
            let mut parts = Vec::new();
            for (key, val) in map.iter().take(20) {
                let child = json_skeleton(val, depth + 1, max_depth);
                parts.push(format!("{inner_indent}\"{key}\": {child}"));
            }
            if map.len() > 20 {
                parts.push(format!("{inner_indent}… ({} more keys)", map.len() - 20));
            }
            format!("{{\n{}\n{indent}}}", parts.join(",\n"))
        }
        serde_json::Value::Array(arr) => {
            if arr.is_empty() {
                return "[]".to_string();
            }
            let first = json_skeleton(arr.first().unwrap(), depth + 1, max_depth);
            if arr.len() == 1 {
                format!("[{first}]")
            } else {
                format!("[{first}, … ({} items)]", arr.len())
            }
        }
        serde_json::Value::String(_) => "<string>".to_string(),
        serde_json::Value::Number(_) => "<number>".to_string(),
        serde_json::Value::Bool(_) => "<bool>".to_string(),
        serde_json::Value::Null => "null".to_string(),
    }
}

/// Navigate a JSON value using a dot-separated path string.
///
/// Supports array index access with `[N]` notation, e.g.
/// `"props.pageProps.items[0].price"`.
///
/// Returns `None` if any segment of the path is missing.
pub fn navigate_json_path<'a>(
    root: &'a serde_json::Value,
    path: &str,
) -> Option<&'a serde_json::Value> {
    if path.is_empty() {
        return Some(root);
    }

    let mut current = root;

    for raw_segment in path.split('.') {
        let mut seg = raw_segment;

        let bracket_pos = seg.find('[');
        let key = match bracket_pos {
            Some(pos) => &seg[..pos],
            None => seg,
        };

        if !key.is_empty() {
            current = current.get(key)?;
        }

        if let Some(pos) = bracket_pos {
            seg = &seg[pos..];
            let mut remaining = seg;
            while let Some(close) = remaining.find(']') {
                let index_str = remaining.get(1..close)?;
                let index: usize = index_str.parse().ok()?;
                current = current.get(index)?;
                remaining = remaining.get(close + 1..).unwrap_or("");
            }
        }
    }

    Some(current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_extract_next_data() {
        let html = r#"<html><head><script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"plans":[{"name":"Basic","price":9}]}}}</script></head></html>"#;
        let blocks = extract_spa_json(html);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].source, SpaSource::NextData);
        assert!(blocks[0].data.get("props").is_some());
    }

    #[test]
    fn test_extract_nuxt_window() {
        let html = r#"<script>window.__NUXT__ = {"state":{"plans":[]}};</script>"#;
        let blocks = extract_spa_json(html);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].source, SpaSource::NuxtWindow);
    }

    #[test]
    fn test_malformed_json_skipped() {
        let html = r#"<script id="__NEXT_DATA__">{not valid json}</script>"#;
        let blocks = extract_spa_json(html);
        assert!(blocks.is_empty());
    }

    #[test]
    fn test_navigate_simple_path() {
        let data = json!({"props": {"pageProps": {"price": 42}}});
        let result = navigate_json_path(&data, "props.pageProps.price");
        assert_eq!(result, Some(&json!(42)));
    }

    #[test]
    fn test_navigate_array_index() {
        let data = json!({"items": [{"name": "A"}, {"name": "B"}]});
        let result = navigate_json_path(&data, "items[1].name");
        assert_eq!(result, Some(&json!("B")));
    }

    #[test]
    fn test_navigate_missing_key() {
        let data = json!({"a": 1});
        assert!(navigate_json_path(&data, "b.c").is_none());
    }

    #[test]
    fn test_navigate_empty_path() {
        let data = json!({"a": 1});
        assert_eq!(navigate_json_path(&data, ""), Some(&data));
    }
}
