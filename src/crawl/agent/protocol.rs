//! Wire types for an agent's discovery/validation/interactive/visual
//! response, collected as text from [`super::session::AgentSession`] and
//! parsed as JSON.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Agent response — parsed from the collected session text.
///
/// Version 2 adds `field_configs`, `pagination`, and `validation_result`
/// while keeping all v1 fields intact for backward compatibility.
#[derive(Debug, Serialize, Deserialize)]
pub struct AgentResponse {
    pub version: String,
    pub task_id: String,
    pub status: AgentStatus,
    #[serde(default)]
    pub records: Vec<serde_json::Value>,
    #[serde(default)]
    pub next_urls: Vec<NextUrlEntry>,
    pub updated_memory: Option<SiteMemorySnapshot>,
    pub confidence: Option<f32>,
    #[serde(default)]
    pub logs: Vec<String>,

    // ── v2 additions ──────────────────────────────────────────────────────────
    /// Rich per-field extraction config discovered by the agent (Phase 1).
    /// When present, callers should prefer this over the flat `updated_memory.selectors`.
    #[serde(default)]
    pub field_configs: Vec<FieldConfig>,

    /// Pagination strategy discovered for this page (Phase 1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pagination: Option<PaginationConfig>,

    /// Result from Phase 2 validation — present only when the agent was asked
    /// to validate previously discovered selectors against real extracted data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_result: Option<ValidationResult>,

    // ── v3 additions ──────────────────────────────────────────────────────────
    /// Browser actions the agent wants executed (L2 interactive mode). Empty
    /// in L1 CSS-only responses.
    #[serde(default)]
    pub browser_actions: Vec<super::actions::BrowserAction>,

    /// Whether the agent believes a visual (L3) pass is needed.
    #[serde(default)]
    pub needs_visual_pass: bool,

    /// Visual actions from L3 mode.
    #[serde(default)]
    pub visual_actions: Vec<super::actions::VisualAction>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentStatus {
    Success,
    Partial,
    PartialSuccess,
    NoData,
    Failed,
    Failure,
    Blocked,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NextUrl {
    pub url: String,
    pub priority: String,
    pub reason: String,
}

/// Accepts either a plain URL string or a full `NextUrl` object.
///
/// An agent sometimes returns `"next_urls": ["https://..."]` instead of the
/// structured form. This enum handles both via `#[serde(untagged)]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum NextUrlEntry {
    /// Plain string: `"https://example.com/page2"`
    Simple(String),
    /// Full object: `{"url": "...", "priority": "high", "reason": "..."}`
    Full(NextUrl),
}

impl NextUrlEntry {
    /// Convert into a `NextUrl`, supplying defaults for the simple case.
    pub fn into_next_url(self) -> NextUrl {
        match self {
            NextUrlEntry::Simple(url) => NextUrl {
                url,
                priority: "normal".to_string(),
                reason: String::new(),
            },
            NextUrlEntry::Full(n) => n,
        }
    }

    /// Borrow the URL string regardless of variant.
    pub fn url(&self) -> &str {
        match self {
            NextUrlEntry::Simple(u) => u,
            NextUrlEntry::Full(n) => &n.url,
        }
    }
}

/// A URL pattern value in site memory — an agent may return either a single
/// string or a list of strings for the same key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum UrlPattern {
    /// Single URL or URL template: `"https://example.com/page/{n}"`
    Single(String),
    /// Multiple URLs or templates.
    Multiple(Vec<String>),
}

impl UrlPattern {
    /// Return all URLs contained in this pattern as an owned `Vec<String>`.
    pub fn into_vec(self) -> Vec<String> {
        match self {
            UrlPattern::Single(s) => vec![s],
            UrlPattern::Multiple(v) => v,
        }
    }

    /// Iterate over URL strings without consuming `self`.
    pub fn as_slice(&self) -> &[String] {
        match self {
            UrlPattern::Single(s) => std::slice::from_ref(s),
            UrlPattern::Multiple(v) => v.as_slice(),
        }
    }
}

/// Per-domain knowledge accumulated by the agent.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SiteMemorySnapshot {
    pub domain: String,
    pub selectors: HashMap<String, LearnedSelectors>,
    pub url_patterns: HashMap<String, UrlPattern>,
    pub pages_seen: usize,
    pub records_found: usize,
    pub requires_browser: bool,
    #[serde(default)]
    pub notes: Vec<String>,

    // ── v2 additions ──────────────────────────────────────────────────────────
    /// Anti-bot behaviour observed on the site (rate-limiting, CAPTCHAs, etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub antibot_notes: Option<String>,

    /// URLs that the agent flagged as promising but has not yet visited.
    #[serde(default)]
    pub pending_urls: Vec<String>,

    /// URLs that failed extraction with reasons — used to avoid retrying bad paths.
    #[serde(default)]
    pub failed_urls: Vec<FailedUrl>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearnedSelectors {
    pub container_selector: Option<String>,
    /// v1: flat map from field name -> CSS selector string.
    /// An agent may also return richer objects here — we accept any JSON value.
    pub fields: HashMap<String, serde_json::Value>,
    pub confidence: f32,
    pub validated_on_pages: usize,
}

// ── v2 types ─────────────────────────────────────────────────────────────────

/// Rich per-field extraction spec returned by Phase 1 discovery.
///
/// Carries not just the CSS selector but also *how* to extract from the matched
/// element and an optional transform to apply to the raw string.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldConfig {
    /// Name of the field as specified in the original goal.
    pub name: String,
    /// CSS selector targeting the element that holds this field's value.
    /// `None` when the agent could not find a matching element on the page —
    /// the field should be skipped during extraction in that case.
    pub selector: Option<String>,
    /// How to read the value from the matched element.
    pub extract: ExtractMode,
    /// Prepend this string to the extracted value (e.g. domain for relative URLs).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    /// Optional post-processing transform.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transform: Option<Transform>,
}

/// Controls how a value is read from a matched DOM element.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtractMode {
    /// `element.text_content()` trimmed of whitespace.
    Text,
    /// `element.attr(name)` — the inner `String` is the attribute name.
    Attribute(String),
    /// `element.inner_html()` — serialised inner HTML.
    Html,
    /// `element.outer_html()` — serialised outer HTML including the element itself.
    OuterHtml,
}

/// Optional post-processing applied to the raw extracted string.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transform {
    Trim,
    Lowercase,
    Uppercase,
    /// Apply a regex and return capture group 1.
    Regex(String),
    /// Replace all occurrences: `(from, to)`.
    Replace(String, String),
    ParseNumber,
}

/// Pagination strategy discovered by the agent for this site.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PaginationConfig {
    /// Classic "Next" button with a fixed CSS selector.
    NextButton { selector: String },
    /// URL contains a page number placeholder `{n}`.
    UrlPattern {
        template: String,
        start: u32,
        end: Option<u32>,
        step: u32,
    },
    /// Infinite scroll — trigger when within `trigger_px` of the bottom.
    InfiniteScroll { trigger_px: u32, max_scrolls: u32 },
    /// "Load more" button clicked up to `max_clicks` times.
    LoadMore {
        button_selector: String,
        max_clicks: u32,
    },
    /// Offset-based query parameter (`?offset=0`, `?offset=20`, …).
    OffsetParam {
        param_name: String,
        page_size: u32,
        max_pages: Option<u32>,
    },
}

/// Result from Phase 2 validation — the agent's assessment of whether the
/// selectors discovered in Phase 1 actually work on real page data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    /// Whether the selectors are considered valid and production-ready.
    pub passed: bool,
    /// How many sample items were successfully extracted during validation.
    pub items_extracted: usize,
    /// Per-field validation status — field name -> `true` if the selector worked.
    pub field_status: HashMap<String, bool>,
    /// Human-readable summary of what was checked and whether it passed.
    pub summary: String,
    /// Confidence that the config generalises beyond the sample pages.
    pub confidence: f32,
    /// Issues found during validation (empty on full pass).
    #[serde(default)]
    pub issues: Vec<String>,
}

/// Record of a URL that failed extraction, stored to avoid re-attempting bad paths.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailedUrl {
    pub url: String,
    pub reason: String,
    pub attempts: usize,
}
