mod canonical_url;
mod engine;
mod html;
mod model;
mod spec;
mod store;

pub use canonical_url::{CanonicalUrl, CanonicalUrlError, MAX_URL_BYTES};
pub use engine::{CrawlEngine, EngineError};
pub use html::{extract_links, extract_links_bounded};
pub use model::{
    Cancellation, Completion, CompletionReport, CrawlEvent, CrawlEventKind, CrawlStatus,
    EntryState, Failure, FrontierEntry, JobFailure, JobState, Lease, LeaseRecovery,
    LeaseToken, RecoveryReport, MAX_DISCOVERED_LINKS_PER_COMPLETION, MAX_EVENTS,
    MAX_JOB_FAILURE_REASON_BYTES,
};
pub use spec::{
    CrawlBudget, CrawlSpec, Scope, SpecError, MAX_ATTEMPTS_PER_URL, MAX_DEPTH,
    MAX_FAILURES, MAX_PAGES, MAX_SCOPE_ENTRIES,
};
pub use store::{CrawlStore, FileStore, MemoryStore, StoreError, MAX_SNAPSHOT_BYTES};
