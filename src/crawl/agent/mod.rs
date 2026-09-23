//! Agent-driven CSS-selector discovery: a multi-turn Claude session
//! ([`session::AgentSession`]) drives progressively escalating extraction
//! levels (CSS -> interactive -> visual), building a
//! [`dig2browser_crawler::profile::SiteProfile`] the fast-path
//! `SelectorExtractor` can then run without an agent.

pub mod actions;
pub mod prompts;
pub mod protocol;
pub mod session;
pub mod visual;

/// An agent-related failure: session spawn/transport failure, or a response
/// that could not be parsed within the expected time.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("spawn failed: {0}")]
    Spawn(String),
    #[error("timeout after {secs}s")]
    Timeout { secs: u64 },
}
