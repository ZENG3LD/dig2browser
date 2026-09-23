//! Domain types for agent-discovered site profiles, recurring-job specs, and
//! record extraction — ported from `dig2crawl` (`core/types.rs`).
//!
//! These types are browser-agnostic: they describe *what* to extract and
//! *how a job is going*, not how a page was fetched.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---- Fetch method (recorded, not executed, by this crate) ----

/// How a page was (or should be) fetched. This crate never fetches — it only
/// carries the choice made by a caller (e.g. `dig2browser`'s crawler feature).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FetchMethod {
    Http,
    Browser { wait_selector: Option<String> },
}

// ---- Site profile (learned by an agent, consumed by `SelectorExtractor`) ----

/// Controls how records are extracted from a page.
///
/// `CssSelectors` is the default (and the only mode supported by
/// [`crate::profile::parse::SelectorExtractor`]). `JsonPath` is used when the
/// page embeds its data inside a SPA framework JSON block.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum ExtractionMode {
    /// Standard CSS-selector-based extraction (default).
    #[default]
    CssSelectors,
    /// Data lives inside an embedded SPA JSON block; navigate with dot-paths.
    JsonPath {
        /// Which SPA source to read from, e.g. `"__NEXT_DATA__"`.
        json_source: String,
        /// Dot-path to the array of records inside the JSON tree.
        base_path: String,
    },
}

/// What an agent discovers about a site's structure. Persisted as JSON so it
/// can be reused on future runs without re-running discovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteProfile {
    pub domain: String,
    /// CSS selector for the repeating container element.
    pub container_selector: String,
    /// One entry per field in the extraction goal.
    pub fields: Vec<FieldConfig>,
    pub pagination: Option<PaginationConfig>,
    pub requires_browser: bool,
    /// Confidence after validation, `[0.0, 1.0]`.
    pub confidence: f64,
    /// Whether validation was completed.
    pub validated: bool,
    pub created_at: DateTime<Utc>,
    pub last_used_at: DateTime<Utc>,
    /// How to extract records from a fetched page.
    #[serde(default)]
    pub extraction_mode: ExtractionMode,
}

/// Rich per-field extraction spec consumed by `SelectorExtractor`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldConfig {
    pub name: String,
    pub selector: String,
    pub extract: ExtractMode,
    /// Prepend a prefix for relative URLs (e.g. `"https://example.com"`).
    pub prefix: Option<String>,
    pub transform: Option<Transform>,
}

/// How to extract the value from a matched element.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtractMode {
    /// Trimmed text content of the element.
    Text,
    /// Value of the named HTML attribute.
    Attribute(String),
    /// Inner HTML of the element (excludes the element tag itself).
    Html,
    /// Outer HTML of the element (includes the element tag).
    OuterHtml,
}

/// Optional post-extraction string transformation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transform {
    Trim,
    Lowercase,
    Uppercase,
    /// Extract regex capture group 1.
    Regex(String),
    /// Replace `from` with `to`.
    Replace(String, String),
    /// Strip non-numeric chars, parse as an f64 string.
    ParseNumber,
}

/// How the crawler should follow pages.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PaginationConfig {
    NextButton {
        selector: String,
    },
    UrlPattern {
        /// e.g. `"https://example.com/page/{n}"`.
        template: String,
        start: u32,
        end: Option<u32>,
        step: u32,
    },
    InfiniteScroll {
        trigger_px: u32,
        max_scrolls: u32,
    },
    LoadMore {
        button_selector: String,
        max_clicks: u32,
    },
    /// Offset query parameter: `?offset=0`, `?offset=20`, …
    OffsetParam {
        param_name: String,
        page_size: u32,
        max_pages: Option<u32>,
    },
}

// ---- Daemon spec ----

/// Daemon-ready config for a recurring crawl job — fully self-contained, no
/// agent needed at runtime.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonSpec {
    pub name: String,
    pub domain: String,
    pub seed_urls: Vec<String>,
    pub site_profile: SiteProfile,
    pub schedule: CronSchedule,
    pub fetch_method: FetchMethod,
    pub rate_limit: RateLimitConfig,
    pub output_format: OutputFormat,
    pub created_at: DateTime<Utc>,
    /// Semver string, e.g. `"1.0"`.
    pub spec_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronSchedule {
    /// Standard 5-field cron expression.
    pub expression: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub requests_per_second: f64,
    pub min_delay_ms: u64,
    pub concurrent_requests: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputFormat {
    Jsonl,
    Json,
    Csv,
    Sqlite,
}

// ---- Job / config (persisted by `SqliteStorage`) ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlConfig {
    /// Human-readable name for this crawl job.
    pub name: String,
    /// Allowed domains (crawl stays within these).
    pub domains: Vec<String>,
    pub start_urls: Vec<url::Url>,
    pub max_depth: Option<usize>,
    pub max_pages: Option<usize>,
    pub rate: RateConfig,
    pub fetch_method: FetchMethod,
    /// Optional extra HTTP headers to send with every request.
    pub headers: Option<std::collections::HashMap<String, String>>,
    pub follow_links: bool,
    pub link_patterns: Option<Vec<String>>,
    pub exclude_patterns: Option<Vec<String>>,
    /// Goal description passed to an agent. `None` disables agent mode.
    pub agent_goal: Option<AgentGoal>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateConfig {
    pub requests_per_second: f64,
    pub min_delay_ms: u64,
    pub concurrent_requests: usize,
}

/// Generic, domain-agnostic extraction goal description.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentGoal {
    /// One-line description of what to extract, e.g. "job listings".
    pub target: String,
    /// Field names to extract, e.g. `["title", "date", "body", "author"]`.
    pub fields: Vec<String>,
    /// Optional extra notes / constraints for the agent.
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlJob {
    pub id: Uuid,
    pub config: CrawlConfig,
    pub started_at: DateTime<Utc>,
    pub status: JobStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JobStatus {
    Pending,
    Running,
    Completed,
    Failed { reason: String },
    Cancelled,
}

/// A single extracted record. `data` is an arbitrary JSON object whose keys
/// are whatever the agent or built-in extractor produced — there is no
/// product-specific schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedRecord {
    pub job_id: Uuid,
    pub url: url::Url,
    pub data: serde_json::Value,
    pub extracted_at: DateTime<Utc>,
    /// Confidence `[0.0, 1.0]` reported by the agent, `None` for built-in
    /// extraction.
    pub confidence: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlStats {
    pub job_id: Uuid,
    pub pages_fetched: u64,
    pub records_extracted: u64,
    pub errors: u64,
    pub queue_size: usize,
    pub elapsed_secs: u64,
}
