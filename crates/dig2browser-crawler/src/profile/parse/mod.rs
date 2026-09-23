//! Generic, domain-agnostic HTML/structured-data extraction primitives.
//!
//! - [`selector`] — CSS selector-based item extraction (fast path, no agent)
//! - [`jsonld`]   — JSON-LD and microdata extraction
//! - [`antibot`]  — CAPTCHA / challenge page detection
//! - [`metadata`] — page title, description, Open Graph, canonical URL
//! - [`json_data`] — embedded SPA framework JSON (`__NEXT_DATA__` etc.)

pub mod antibot;
pub mod json_data;
pub mod jsonld;
pub mod metadata;
pub mod selector;

pub use antibot::{AntiBotDetector, AntiBotResult};
pub use json_data::{extract_spa_json, summarize_spa_json, SpaJsonBlock, SpaSource};
pub use jsonld::JsonLdExtractor;
pub use metadata::{MetadataExtractor, PageMetadata};
pub use selector::SelectorExtractor;
