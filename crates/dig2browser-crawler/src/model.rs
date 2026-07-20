use crate::{CanonicalUrl, CrawlSpec};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const MAX_DISCOVERED_LINKS_PER_COMPLETION: usize = 10_000;
pub const MAX_EVENTS: usize = 250_000;
pub const MAX_JOB_FAILURE_REASON_BYTES: usize = 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Lease {
    pub(crate) id: String,
    pub(crate) worker_id: String,
    pub(crate) acquired_at_ms: u64,
    pub(crate) expires_at_ms: u64,
    pub(crate) attempt: u32,
}

impl Lease {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn worker_id(&self) -> &str {
        &self.worker_id
    }

    pub fn acquired_at_ms(&self) -> u64 {
        self.acquired_at_ms
    }

    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    pub fn attempt(&self) -> u32 {
        self.attempt
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaseToken {
    pub(crate) url: CanonicalUrl,
    pub(crate) lease: Lease,
}

impl LeaseToken {
    pub fn url(&self) -> &CanonicalUrl {
        &self.url
    }

    pub fn lease(&self) -> &Lease {
        &self.lease
    }

    pub(crate) fn new(url: CanonicalUrl, lease: Lease) -> Self {
        Self { url, lease }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum EntryState {
    Pending { enqueued_at_ms: u64 },
    InFlight { lease: Lease },
    Completed {
        completed_at_ms: u64,
        status_code: Option<u16>,
        artifact_ref: Option<String>,
    },
    Failed {
        failed_at_ms: u64,
        error: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FrontierEntry {
    pub(crate) url: CanonicalUrl,
    pub(crate) depth: u32,
    pub(crate) discovered_from: Option<CanonicalUrl>,
    pub(crate) discovery_sequence: u64,
    pub(crate) attempts: u32,
    pub(crate) state: EntryState,
}

impl FrontierEntry {
    pub fn url(&self) -> &CanonicalUrl {
        &self.url
    }

    pub fn depth(&self) -> u32 {
        self.depth
    }

    pub fn discovered_from(&self) -> Option<&CanonicalUrl> {
        self.discovered_from.as_ref()
    }

    pub fn attempts(&self) -> u32 {
        self.attempts
    }

    pub fn state(&self) -> &EntryState {
        &self.state
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Completion {
    pub(crate) status_code: Option<u16>,
    pub(crate) artifact_ref: Option<String>,
    pub(crate) discovered_links: Vec<CanonicalUrl>,
    pub(crate) discovered_links_truncated: bool,
}

impl Completion {
    pub fn new(status_code: Option<u16>) -> Self {
        Self {
            status_code,
            artifact_ref: None,
            discovered_links: Vec::new(),
            discovered_links_truncated: false,
        }
    }

    pub fn with_artifact_ref(mut self, artifact_ref: impl Into<String>) -> Self {
        self.artifact_ref = Some(artifact_ref.into());
        self
    }

    pub fn with_discovered_links<I>(mut self, links: I) -> Self
    where
        I: IntoIterator<Item = CanonicalUrl>,
    {
        let mut links = links.into_iter();
        self.discovered_links = links
            .by_ref()
            .take(MAX_DISCOVERED_LINKS_PER_COMPLETION)
            .collect();
        self.discovered_links_truncated = links.next().is_some();
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Failure {
    pub(crate) message: String,
    pub(crate) retryable: bool,
}

impl Failure {
    pub fn terminal(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            retryable: false,
        }
    }

    pub fn retryable(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            retryable: true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Cancellation {
    pub(crate) cancelled_at_ms: u64,
    pub(crate) reason: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct JobFailure {
    pub(crate) failed_at_ms: u64,
    pub(crate) reason: String,
}

impl JobFailure {
    pub fn failed_at_ms(&self) -> u64 {
        self.failed_at_ms
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl Cancellation {
    pub fn cancelled_at_ms(&self) -> u64 {
        self.cancelled_at_ms
    }

    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeaseRecovery {
    None,
    Expired,
    All,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryReport {
    pub requeued: usize,
    pub failed: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletionReport {
    pub enqueued: usize,
    pub duplicate: usize,
    pub outside_scope: usize,
    pub depth_limited: usize,
    pub budget_limited: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CrawlEvent {
    pub(crate) sequence: u64,
    pub(crate) at_ms: u64,
    pub(crate) kind: CrawlEventKind,
}

impl CrawlEvent {
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn at_ms(&self) -> u64 {
        self.at_ms
    }

    pub fn kind(&self) -> &CrawlEventKind {
        &self.kind
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum CrawlEventKind {
    JobCreated,
    Enqueued { url: CanonicalUrl, depth: u32 },
    Claimed {
        url: CanonicalUrl,
        lease_id: String,
        worker_id: String,
        attempt: u32,
        expires_at_ms: u64,
    },
    LeaseRenewed {
        url: CanonicalUrl,
        lease_id: String,
        expires_at_ms: u64,
    },
    Completed {
        url: CanonicalUrl,
        depth: u32,
        attempt: u32,
        status_code: Option<u16>,
        artifact_ref: Option<String>,
    },
    Failed {
        url: CanonicalUrl,
        depth: u32,
        attempt: u32,
        error: String,
    },
    Requeued {
        url: CanonicalUrl,
        depth: u32,
        attempt: u32,
        reason: String,
    },
    JobFailed { reason: String },
    Cancelled { reason: Option<String> },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobState {
    Running,
    Completed,
    CompletedWithFailures,
    FailureBudgetExhausted,
    Failed,
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrawlStatus {
    pub job_id: String,
    pub state: JobState,
    pub pending: usize,
    pub in_flight: usize,
    pub completed: usize,
    pub failed: usize,
    pub total: usize,
    pub remaining_page_capacity: usize,
    pub revision: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Snapshot {
    pub schema_version: u32,
    pub revision: u64,
    pub spec: CrawlSpec,
    pub frontier: BTreeMap<CanonicalUrl, FrontierEntry>,
    pub next_discovery_sequence: u64,
    pub events: Vec<CrawlEvent>,
    pub next_event_sequence: u64,
    pub cancellation: Option<Cancellation>,
    #[serde(default)]
    pub failure: Option<JobFailure>,
}

impl Snapshot {
    pub(crate) fn push_event(&mut self, at_ms: u64, kind: CrawlEventKind) {
        let sequence = self.next_event_sequence;
        self.next_event_sequence += 1;
        self.events.push(CrawlEvent {
            sequence,
            at_ms,
            kind,
        });
    }
}
