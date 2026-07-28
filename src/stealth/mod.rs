//! Anti-detection stealth scripts and injection strategy trait.
//!
//! Zero protocol dependencies — safe to import from any crate without
//! pulling in CDP or WebDriver clients.

pub mod config;
pub mod inject;
pub mod persona_source;
pub mod scripts;

pub use config::{
    ClientHintsProfile, LocaleProfile, StealthConfig, StealthLevel, WebrtcPolicy,
    DEFAULT_USER_AGENT,
};
pub use inject::InjectionStrategy;
pub use persona_source::{
    generate_random, CatalogKind, PersonaRecord, PersonaSource, PersonaSourceError,
};
pub use scripts::get_scripts;

use thiserror::Error;

/// Errors produced by stealth injection.
#[derive(Debug, Error)]
pub enum StealthError {
    #[error("Stealth injection failed: {0}")]
    Inject(String),
}
