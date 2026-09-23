//! Agent-discovered site profiles, recurring-job specs, structured-record
//! extraction, and their SQLite storage — ported from `dig2crawl`.
//!
//! This module is unrelated to the frontier/lease crawl model at the crate
//! root (`CrawlSpec`/`CrawlEngine`/`FrontierEntry`); it models *what* an
//! agent learned about a site and *what it extracted*, not page scheduling.

pub mod parse;
pub mod store;
pub mod types;

pub use types::{
    AgentGoal, CrawlConfig, CrawlJob, CrawlStats, CronSchedule, DaemonSpec, ExtractMode,
    ExtractedRecord, ExtractionMode, FetchMethod, FieldConfig, JobStatus, OutputFormat,
    PaginationConfig, RateConfig, RateLimitConfig, SiteProfile, Transform,
};
