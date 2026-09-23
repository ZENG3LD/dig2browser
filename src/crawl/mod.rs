//! Optional crawler feature: browser-driven and plain-HTTP fetch, an
//! agent-driven CSS-selector discovery loop, and the `dig2crawl` CLI binary
//! (`src/bin/dig2crawl.rs`). Ported from the retired `dig2crawl` crate.
//!
//! Off by default — enable with `--features crawler`. The site-profile
//! model, structured-record parsers, and SQLite storage this module builds
//! on live in the browser-agnostic `dig2browser-crawler` crate
//! (`dig2browser_crawler::profile`); this module adds the parts that need a
//! real browser (`fetch::browser`) or an agent CLI transport (`agent`).

pub mod agent;
pub mod fetch;
