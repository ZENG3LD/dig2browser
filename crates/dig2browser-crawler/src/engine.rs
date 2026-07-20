use crate::model::{Snapshot, *};
use crate::{
    CanonicalUrl, CrawlSpec, CrawlStore, SpecError, StoreError, MAX_SNAPSHOT_BYTES,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{self, Write};

pub struct CrawlEngine<S> {
    store: S,
    state: Snapshot,
}

impl<S: CrawlStore> CrawlEngine<S> {
    pub fn create(mut store: S, spec: CrawlSpec, now_ms: u64) -> Result<Self, EngineError> {
        if store.load()?.is_some() {
            return Err(EngineError::StoreAlreadyInitialized);
        }

        let mut state = Snapshot {
            schema_version: 1,
            revision: 1,
            spec,
            frontier: BTreeMap::new(),
            next_discovery_sequence: 1,
            events: Vec::new(),
            next_event_sequence: 1,
            cancellation: None,
            failure: None,
        };
        state.push_event(now_ms, CrawlEventKind::JobCreated);
        for seed in state.spec.seeds().to_vec() {
            insert_pending(&mut state, seed.clone(), 0, None, now_ms);
            state.push_event(
                now_ms,
                CrawlEventKind::Enqueued {
                    url: seed,
                    depth: 0,
                },
            );
        }
        validate_snapshot(&state)?;
        persist(&mut store, &state)?;
        Ok(Self { store, state })
    }

    pub fn open(
        store: S,
        now_ms: u64,
        recovery: LeaseRecovery,
    ) -> Result<Self, EngineError> {
        let mut engine = Self::open_without_recovery(store)?;
        if recovery != LeaseRecovery::None {
            engine.recover_leases(now_ms, recovery)?;
        }
        Ok(engine)
    }

    pub fn open_without_recovery(mut store: S) -> Result<Self, EngineError> {
        let bytes = store.load()?.ok_or(EngineError::StoreNotInitialized)?;
        let state: Snapshot = serde_json::from_slice(&bytes)
            .map_err(|error| EngineError::InvalidSnapshot(error.to_string()))?;
        validate_snapshot(&state)?;
        Ok(Self { store, state })
    }

    pub fn spec(&self) -> &CrawlSpec {
        &self.state.spec
    }

    pub fn entry(&self, url: &CanonicalUrl) -> Option<&FrontierEntry> {
        self.state.frontier.get(url)
    }

    pub fn frontier(&self) -> impl Iterator<Item = &FrontierEntry> {
        self.state.frontier.values()
    }

    pub fn active_lease_tokens(&self) -> impl Iterator<Item = LeaseToken> + '_ {
        self.state.frontier.values().filter_map(|entry| {
            if let EntryState::InFlight { lease } = &entry.state {
                Some(LeaseToken::new(entry.url.clone(), lease.clone()))
            } else {
                None
            }
        })
    }

    pub fn events_after(&self, sequence: u64) -> impl Iterator<Item = &CrawlEvent> {
        self.state
            .events
            .iter()
            .filter(move |event| event.sequence > sequence)
    }

    pub fn into_store(self) -> S {
        self.store
    }

    pub fn claim_next(
        &mut self,
        worker_id: impl Into<String>,
        lease_id: impl Into<String>,
        now_ms: u64,
        lease_duration_ms: u64,
    ) -> Result<Option<LeaseToken>, EngineError> {
        self.ensure_job_mutable()?;
        let worker_id = worker_id.into();
        validate_opaque_id("worker_id", &worker_id)?;
        let lease_id = lease_id.into();
        validate_opaque_id("lease_id", &lease_id)?;
        if lease_duration_ms == 0 {
            return Err(EngineError::InvalidInput(
                "lease duration must be positive".to_owned(),
            ));
        }
        if terminal_failures(&self.state) >= self.state.spec.budget().max_failures() {
            return Ok(None);
        }
        let expires_at_ms = now_ms
            .checked_add(lease_duration_ms)
            .ok_or_else(|| EngineError::InvalidInput("lease expiry overflow".to_owned()))?;
        let candidate = self
            .state
            .frontier
            .values()
            .filter(|entry| matches!(&entry.state, EntryState::Pending { .. }))
            .filter(|entry| entry.attempts < self.state.spec.budget().max_attempts_per_url())
            .min_by_key(|entry| entry.discovery_sequence)
            .map(|entry| entry.url.clone());
        let Some(url) = candidate else {
            return Ok(None);
        };

        let mut next = self.state.clone();
        let entry = next.frontier.get_mut(&url).expect("candidate exists");
        entry.attempts += 1;
        let lease = Lease {
            id: lease_id.clone(),
            worker_id: worker_id.clone(),
            acquired_at_ms: now_ms,
            expires_at_ms,
            attempt: entry.attempts,
        };
        entry.state = EntryState::InFlight {
            lease: lease.clone(),
        };
        next.push_event(
            now_ms,
            CrawlEventKind::Claimed {
                url: url.clone(),
                lease_id,
                worker_id,
                attempt: lease.attempt,
                expires_at_ms,
            },
        );
        self.commit(next)?;
        Ok(Some(LeaseToken::new(url, lease)))
    }

    pub fn renew_lease(
        &mut self,
        token: &LeaseToken,
        now_ms: u64,
        lease_duration_ms: u64,
    ) -> Result<LeaseToken, EngineError> {
        self.ensure_job_mutable()?;
        if lease_duration_ms == 0 {
            return Err(EngineError::InvalidInput(
                "lease duration must be positive".to_owned(),
            ));
        }
        let expires_at_ms = now_ms
            .checked_add(lease_duration_ms)
            .ok_or_else(|| EngineError::InvalidInput("lease expiry overflow".to_owned()))?;
        let mut next = self.state.clone();
        let lease = active_lease_mut(&mut next, token)?;
        if lease.expires_at_ms <= now_ms {
            return Err(EngineError::LeaseExpired);
        }
        lease.expires_at_ms = expires_at_ms;
        let renewed = lease.clone();
        next.push_event(
            now_ms,
            CrawlEventKind::LeaseRenewed {
                url: token.url.clone(),
                lease_id: renewed.id.clone(),
                expires_at_ms,
            },
        );
        self.commit(next)?;
        Ok(LeaseToken::new(token.url.clone(), renewed))
    }

    pub fn complete(
        &mut self,
        token: &LeaseToken,
        completion: Completion,
        now_ms: u64,
    ) -> Result<CompletionReport, EngineError> {
        self.complete_inner(token, completion, now_ms, true)
    }

    pub fn complete_recovered(
        &mut self,
        token: &LeaseToken,
        completion: Completion,
        now_ms: u64,
    ) -> Result<CompletionReport, EngineError> {
        self.complete_inner(token, completion, now_ms, false)
    }

    fn complete_inner(
        &mut self,
        token: &LeaseToken,
        completion: Completion,
        now_ms: u64,
        enforce_expiry: bool,
    ) -> Result<CompletionReport, EngineError> {
        self.ensure_job_mutable()?;
        validate_completion(&completion)?;
        let source = active_entry(&self.state, token)?.clone();
        if enforce_expiry && source_lease(&source).expires_at_ms <= now_ms {
            return Err(EngineError::LeaseExpired);
        }
        let mut next = self.state.clone();
        let entry = next.frontier.get_mut(&source.url).expect("active entry exists");
        entry.state = EntryState::Completed {
            completed_at_ms: now_ms,
            status_code: completion.status_code,
            artifact_ref: completion.artifact_ref.clone(),
        };
        next.push_event(
            now_ms,
            CrawlEventKind::Completed {
                url: source.url.clone(),
                depth: source.depth,
                attempt: source.attempts,
                status_code: completion.status_code,
                artifact_ref: completion.artifact_ref,
            },
        );

        let mut report = CompletionReport {
            enqueued: 0,
            duplicate: 0,
            outside_scope: 0,
            depth_limited: 0,
            budget_limited: 0,
        };
        if completion.discovered_links_truncated {
            report.budget_limited = 1;
        }
        let child_depth = source.depth.saturating_add(1);
        for link in completion.discovered_links {
            if next.frontier.contains_key(&link) {
                report.duplicate += 1;
            } else if !next.spec.allows(&link) {
                report.outside_scope += 1;
            } else if source.depth >= next.spec.budget().max_depth() {
                report.depth_limited += 1;
            } else if next.frontier.len() >= next.spec.budget().max_pages() {
                report.budget_limited += 1;
            } else {
                insert_pending(
                    &mut next,
                    link.clone(),
                    child_depth,
                    Some(source.url.clone()),
                    now_ms,
                );
                next.push_event(
                    now_ms,
                    CrawlEventKind::Enqueued {
                        url: link,
                        depth: child_depth,
                    },
                );
                report.enqueued += 1;
            }
        }
        self.commit(next)?;
        Ok(report)
    }

    pub fn fail(
        &mut self,
        token: &LeaseToken,
        failure: Failure,
        now_ms: u64,
    ) -> Result<bool, EngineError> {
        self.ensure_job_mutable()?;
        validate_message("failure message", &failure.message, 4096)?;
        let source = active_entry(&self.state, token)?.clone();
        if source_lease(&source).expires_at_ms <= now_ms {
            return Err(EngineError::LeaseExpired);
        }
        let may_retry = failure.retryable
            && source.attempts < self.state.spec.budget().max_attempts_per_url()
            && terminal_failures(&self.state) < self.state.spec.budget().max_failures();
        let mut next = self.state.clone();
        let entry = next.frontier.get_mut(&source.url).expect("active entry exists");
        if may_retry {
            entry.state = EntryState::Pending {
                enqueued_at_ms: now_ms,
            };
            next.push_event(
                now_ms,
                CrawlEventKind::Requeued {
                    url: source.url,
                    depth: source.depth,
                    attempt: source.attempts,
                    reason: failure.message,
                },
            );
        } else {
            entry.state = EntryState::Failed {
                failed_at_ms: now_ms,
                error: failure.message.clone(),
            };
            next.push_event(
                now_ms,
                CrawlEventKind::Failed {
                    url: source.url,
                    depth: source.depth,
                    attempt: source.attempts,
                    error: failure.message,
                },
            );
        }
        self.commit(next)?;
        Ok(may_retry)
    }

    pub fn requeue_failed(
        &mut self,
        url: &CanonicalUrl,
        now_ms: u64,
    ) -> Result<(), EngineError> {
        self.ensure_job_mutable()?;
        let current = self
            .state
            .frontier
            .get(url)
            .ok_or(EngineError::UnknownUrl)?;
        if !matches!(&current.state, EntryState::Failed { .. }) {
            return Err(EngineError::InvalidTransition(
                "only a failed URL can be requeued".to_owned(),
            ));
        }
        if current.attempts >= self.state.spec.budget().max_attempts_per_url() {
            return Err(EngineError::AttemptsExhausted);
        }
        let mut next = self.state.clone();
        next.frontier.get_mut(url).expect("entry exists").state = EntryState::Pending {
            enqueued_at_ms: now_ms,
        };
        next.push_event(
            now_ms,
            CrawlEventKind::Requeued {
                url: url.clone(),
                depth: current.depth,
                attempt: current.attempts,
                reason: "operator requeue".to_owned(),
            },
        );
        self.commit(next)
    }

    pub fn recover_leases(
        &mut self,
        now_ms: u64,
        recovery: LeaseRecovery,
    ) -> Result<RecoveryReport, EngineError> {
        if recovery == LeaseRecovery::None
            || self.state.cancellation.is_some()
            || self.state.failure.is_some()
        {
            return Ok(RecoveryReport {
                requeued: 0,
                failed: 0,
            });
        }
        let recoverable = self
            .state
            .frontier
            .values()
            .filter_map(|entry| match &entry.state {
                EntryState::InFlight { lease }
                    if recovery == LeaseRecovery::All || lease.expires_at_ms <= now_ms =>
                {
                    Some(entry.url.clone())
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        if recoverable.is_empty() {
            return Ok(RecoveryReport {
                requeued: 0,
                failed: 0,
            });
        }

        let mut next = self.state.clone();
        let mut report = RecoveryReport {
            requeued: 0,
            failed: 0,
        };
        for url in recoverable {
            let entry = next.frontier.get_mut(&url).expect("entry exists");
            let depth = entry.depth;
            let attempt = entry.attempts;
            if entry.attempts >= next.spec.budget().max_attempts_per_url() {
                let error = "lease lost after final attempt".to_owned();
                entry.state = EntryState::Failed {
                    failed_at_ms: now_ms,
                    error: error.clone(),
                };
                next.push_event(
                    now_ms,
                    CrawlEventKind::Failed {
                        url,
                        depth,
                        attempt,
                        error,
                    },
                );
                report.failed += 1;
            } else {
                entry.state = EntryState::Pending {
                    enqueued_at_ms: now_ms,
                };
                next.push_event(
                    now_ms,
                    CrawlEventKind::Requeued {
                        url,
                        depth,
                        attempt,
                        reason: "lease recovery".to_owned(),
                    },
                );
                report.requeued += 1;
            }
        }
        self.commit(next)?;
        Ok(report)
    }

    pub fn cancel(
        &mut self,
        now_ms: u64,
        reason: Option<String>,
    ) -> Result<(), EngineError> {
        if self.state.cancellation.is_some() {
            return Ok(());
        }
        if self.status().state != JobState::Running {
            return Ok(());
        }
        if let Some(reason) = &reason {
            validate_message("cancellation reason", reason, 1024)?;
        }
        let mut next = self.state.clone();
        next.cancellation = Some(Cancellation {
            cancelled_at_ms: now_ms,
            reason: reason.clone(),
        });
        next.push_event(now_ms, CrawlEventKind::Cancelled { reason });
        self.commit(next)
    }

    pub fn cancellation(&self) -> Option<&Cancellation> {
        self.state.cancellation.as_ref()
    }

    pub fn fail_job(
        &mut self,
        now_ms: u64,
        reason: impl AsRef<str>,
    ) -> Result<(), EngineError> {
        if self.state.failure.is_some() {
            return Ok(());
        }
        if self.status().state != JobState::Running {
            return Ok(());
        }
        let reason = sanitize_job_failure_reason(reason.as_ref());
        let mut next = self.state.clone();
        next.failure = Some(JobFailure {
            failed_at_ms: now_ms,
            reason: reason.clone(),
        });
        next.push_event(now_ms, CrawlEventKind::JobFailed { reason });
        self.commit(next)
    }

    pub fn failure(&self) -> Option<&JobFailure> {
        self.state.failure.as_ref()
    }

    pub fn status(&self) -> CrawlStatus {
        let mut pending = 0;
        let mut in_flight = 0;
        let mut completed = 0;
        let mut failed = 0;
        for entry in self.state.frontier.values() {
            match &entry.state {
                EntryState::Pending { .. } => pending += 1,
                EntryState::InFlight { .. } => in_flight += 1,
                EntryState::Completed { .. } => completed += 1,
                EntryState::Failed { .. } => failed += 1,
            }
        }
        let state = if self.state.failure.is_some() {
            JobState::Failed
        } else if self.state.cancellation.is_some() {
            JobState::Cancelled
        } else if failed >= self.state.spec.budget().max_failures() {
            JobState::FailureBudgetExhausted
        } else if pending == 0 && in_flight == 0 && failed == 0 {
            JobState::Completed
        } else if pending == 0 && in_flight == 0 {
            JobState::CompletedWithFailures
        } else {
            JobState::Running
        };
        CrawlStatus {
            job_id: self.state.spec.job_id().to_owned(),
            state,
            pending,
            in_flight,
            completed,
            failed,
            total: self.state.frontier.len(),
            remaining_page_capacity: self
                .state
                .spec
                .budget()
                .max_pages()
                .saturating_sub(self.state.frontier.len()),
            revision: self.state.revision,
        }
    }

    fn commit(&mut self, mut next: Snapshot) -> Result<(), EngineError> {
        next.revision = self
            .state
            .revision
            .checked_add(1)
            .ok_or_else(|| EngineError::InvalidSnapshot("revision overflow".to_owned()))?;
        validate_snapshot(&next)?;
        persist(&mut self.store, &next)?;
        self.state = next;
        Ok(())
    }

    fn ensure_job_mutable(&self) -> Result<(), EngineError> {
        if self.state.failure.is_some() {
            return Err(EngineError::JobFailed);
        }
        if self.state.cancellation.is_some() {
            return Err(EngineError::JobCancelled);
        }
        Ok(())
    }
}

fn insert_pending(
    state: &mut Snapshot,
    url: CanonicalUrl,
    depth: u32,
    discovered_from: Option<CanonicalUrl>,
    now_ms: u64,
) {
    let sequence = state.next_discovery_sequence;
    state.next_discovery_sequence += 1;
    state.frontier.insert(
        url.clone(),
        FrontierEntry {
            url,
            depth,
            discovered_from,
            discovery_sequence: sequence,
            attempts: 0,
            state: EntryState::Pending {
                enqueued_at_ms: now_ms,
            },
        },
    );
}

fn active_entry<'a>(
    state: &'a Snapshot,
    token: &LeaseToken,
) -> Result<&'a FrontierEntry, EngineError> {
    let entry = state
        .frontier
        .get(&token.url)
        .ok_or(EngineError::UnknownUrl)?;
    match &entry.state {
        EntryState::InFlight { lease } if lease == &token.lease => Ok(entry),
        EntryState::InFlight { .. } => Err(EngineError::LeaseMismatch),
        _ => Err(EngineError::InvalidTransition(
            "URL is not in flight".to_owned(),
        )),
    }
}

fn active_lease_mut<'a>(
    state: &'a mut Snapshot,
    token: &LeaseToken,
) -> Result<&'a mut Lease, EngineError> {
    let entry = state
        .frontier
        .get_mut(&token.url)
        .ok_or(EngineError::UnknownUrl)?;
    match &mut entry.state {
        EntryState::InFlight { lease } if *lease == token.lease => Ok(lease),
        EntryState::InFlight { .. } => Err(EngineError::LeaseMismatch),
        _ => Err(EngineError::InvalidTransition(
            "URL is not in flight".to_owned(),
        )),
    }
}

fn source_lease(entry: &FrontierEntry) -> &Lease {
    match &entry.state {
        EntryState::InFlight { lease } => lease,
        _ => unreachable!("active_entry only returns an in-flight entry"),
    }
}

fn validate_completion(completion: &Completion) -> Result<(), EngineError> {
    if let Some(status_code) = completion.status_code {
        if !(100..=599).contains(&status_code) {
            return Err(EngineError::InvalidInput(
                "status code must be in 100..=599".to_owned(),
            ));
        }
    }
    if let Some(artifact_ref) = &completion.artifact_ref {
        validate_message("artifact reference", artifact_ref, 4096)?;
    }
    if completion.discovered_links.len() > MAX_DISCOVERED_LINKS_PER_COMPLETION {
        return Err(EngineError::InvalidInput(format!(
            "completion exceeds {MAX_DISCOVERED_LINKS_PER_COMPLETION} discovered links"
        )));
    }
    Ok(())
}

fn validate_opaque_id(name: &str, value: &str) -> Result<(), EngineError> {
    if value.trim().is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(EngineError::InvalidInput(format!(
            "{name} must be 1..=256 non-control characters"
        )));
    }
    Ok(())
}

fn validate_message(name: &str, value: &str, max_len: usize) -> Result<(), EngineError> {
    if value.trim().is_empty() || value.len() > max_len {
        return Err(EngineError::InvalidInput(format!(
            "{name} must be 1..={max_len} bytes"
        )));
    }
    Ok(())
}

fn sanitize_job_failure_reason(value: &str) -> String {
    let mut sanitized = String::with_capacity(value.len().min(MAX_JOB_FAILURE_REASON_BYTES));
    let mut pending_space = false;
    for character in value.chars() {
        if character.is_control() || character.is_whitespace() {
            pending_space = !sanitized.is_empty();
            continue;
        }
        if pending_space {
            if sanitized.len() == MAX_JOB_FAILURE_REASON_BYTES {
                break;
            }
            sanitized.push(' ');
            pending_space = false;
        }
        if sanitized.len() + character.len_utf8() > MAX_JOB_FAILURE_REASON_BYTES {
            break;
        }
        sanitized.push(character);
    }
    if sanitized.is_empty() {
        "crawl job failed".to_owned()
    } else {
        sanitized
    }
}

fn terminal_failures(state: &Snapshot) -> usize {
    state
        .frontier
        .values()
        .filter(|entry| matches!(&entry.state, EntryState::Failed { .. }))
        .count()
}

fn persist<S: CrawlStore>(store: &mut S, state: &Snapshot) -> Result<(), EngineError> {
    let mut bytes = BoundedSnapshot::new();
    serde_json::to_writer(&mut bytes, state)
        .map_err(|error| EngineError::InvalidSnapshot(error.to_string()))?;
    store.save(&bytes.bytes)?;
    Ok(())
}

struct BoundedSnapshot {
    bytes: Vec<u8>,
}

impl BoundedSnapshot {
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(64 * 1024),
        }
    }
}

impl Write for BoundedSnapshot {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let next_len = self
            .bytes
            .len()
            .checked_add(buffer.len())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "snapshot size overflow"))?;
        if next_len > MAX_SNAPSHOT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("snapshot exceeds {MAX_SNAPSHOT_BYTES} bytes"),
            ));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn validate_snapshot(state: &Snapshot) -> Result<(), EngineError> {
    if state.schema_version != 1 {
        return Err(EngineError::InvalidSnapshot(format!(
            "unsupported schema version {}",
            state.schema_version
        )));
    }
    if state.revision == 0 {
        return Err(EngineError::InvalidSnapshot(
            "revision must be positive".to_owned(),
        ));
    }
    state.spec.validate()?;
    if state.frontier.len() > state.spec.budget().max_pages() {
        return Err(EngineError::InvalidSnapshot(
            "frontier exceeds page budget".to_owned(),
        ));
    }
    if state.events.len() > MAX_EVENTS {
        return Err(EngineError::InvalidSnapshot(format!(
            "event log exceeds {MAX_EVENTS} entries"
        )));
    }
    if state.cancellation.is_some() && state.failure.is_some() {
        return Err(EngineError::InvalidSnapshot(
            "job cannot be both cancelled and failed".to_owned(),
        ));
    }
    if let Some(failure) = &state.failure {
        if failure.reason.trim().is_empty()
            || failure.reason.len() > MAX_JOB_FAILURE_REASON_BYTES
            || failure.reason.chars().any(char::is_control)
        {
            return Err(EngineError::InvalidSnapshot(
                "invalid job failure reason".to_owned(),
            ));
        }
    }
    let mut discovery_sequences = BTreeSet::new();
    for (key, entry) in &state.frontier {
        if key != &entry.url {
            return Err(EngineError::InvalidSnapshot(
                "frontier key does not match entry URL".to_owned(),
            ));
        }
        if !state.spec.allows(&entry.url) {
            return Err(EngineError::InvalidSnapshot(
                "frontier contains an out-of-scope URL".to_owned(),
            ));
        }
        if entry.depth > state.spec.budget().max_depth() {
            return Err(EngineError::InvalidSnapshot(
                "frontier depth exceeds budget".to_owned(),
            ));
        }
        if entry.discovery_sequence == 0
            || !discovery_sequences.insert(entry.discovery_sequence)
            || entry.discovery_sequence >= state.next_discovery_sequence
        {
            return Err(EngineError::InvalidSnapshot(
                "invalid frontier discovery sequence".to_owned(),
            ));
        }
        if let EntryState::InFlight { lease } = &entry.state {
            if lease.attempt != entry.attempts
                || lease.attempt == 0
                || lease.expires_at_ms <= lease.acquired_at_ms
            {
                return Err(EngineError::InvalidSnapshot(
                    "invalid active lease".to_owned(),
                ));
            }
        }
    }
    for seed in state.spec.seeds() {
        let entry = state.frontier.get(seed).ok_or_else(|| {
            EngineError::InvalidSnapshot("frontier is missing a seed URL".to_owned())
        })?;
        if entry.depth != 0 || entry.discovered_from.is_some() {
            return Err(EngineError::InvalidSnapshot(
                "seed entry has invalid provenance".to_owned(),
            ));
        }
    }
    let mut expected_event_sequence = 1u64;
    let mut job_failure_event = None;
    for event in &state.events {
        if event.sequence != expected_event_sequence {
            return Err(EngineError::InvalidSnapshot(
                "event sequence is not contiguous".to_owned(),
            ));
        }
        if let CrawlEventKind::JobFailed { reason } = &event.kind {
            if job_failure_event.replace((event.at_ms, reason.as_str())).is_some() {
                return Err(EngineError::InvalidSnapshot(
                    "event log contains multiple job failures".to_owned(),
                ));
            }
        }
        expected_event_sequence += 1;
    }
    if state.next_event_sequence != expected_event_sequence {
        return Err(EngineError::InvalidSnapshot(
            "next event sequence is invalid".to_owned(),
        ));
    }
    match (&state.failure, job_failure_event) {
        (Some(failure), Some((at_ms, reason)))
            if failure.failed_at_ms == at_ms
                && failure.reason == reason
                && matches!(
                    state.events.last().map(CrawlEvent::kind),
                    Some(CrawlEventKind::JobFailed { .. })
                ) => {}
        (None, None) => {}
        _ => {
            return Err(EngineError::InvalidSnapshot(
                "job failure state and terminal event do not match".to_owned(),
            ))
        }
    }
    Ok(())
}

#[derive(Debug)]
pub enum EngineError {
    Store(StoreError),
    Spec(SpecError),
    StoreAlreadyInitialized,
    StoreNotInitialized,
    InvalidSnapshot(String),
    InvalidInput(String),
    InvalidTransition(String),
    UnknownUrl,
    LeaseMismatch,
    LeaseExpired,
    AttemptsExhausted,
    JobFailed,
    JobCancelled,
}

impl fmt::Display for EngineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => error.fmt(formatter),
            Self::Spec(error) => error.fmt(formatter),
            Self::StoreAlreadyInitialized => formatter.write_str("crawl store is already initialized"),
            Self::StoreNotInitialized => formatter.write_str("crawl store is not initialized"),
            Self::InvalidSnapshot(message) => write!(formatter, "invalid crawl snapshot: {message}"),
            Self::InvalidInput(message) => write!(formatter, "invalid crawler input: {message}"),
            Self::InvalidTransition(message) => write!(formatter, "invalid crawl transition: {message}"),
            Self::UnknownUrl => formatter.write_str("URL is not in the crawl frontier"),
            Self::LeaseMismatch => formatter.write_str("lease token does not match the active lease"),
            Self::LeaseExpired => formatter.write_str("lease has expired"),
            Self::AttemptsExhausted => formatter.write_str("URL has exhausted its attempt budget"),
            Self::JobFailed => formatter.write_str("crawl job has failed"),
            Self::JobCancelled => formatter.write_str("crawl job is cancelled"),
        }
    }
}

impl std::error::Error for EngineError {}

impl From<StoreError> for EngineError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

impl From<SpecError> for EngineError {
    fn from(error: SpecError) -> Self {
        Self::Spec(error)
    }
}

#[cfg(test)]
mod tests {
    use super::CrawlEngine;
    use crate::{
        CanonicalUrl, Completion, CrawlBudget, CrawlEventKind, CrawlSpec, EntryState,
        Failure, JobState, LeaseRecovery, MemoryStore, Scope,
    };

    fn spec() -> CrawlSpec {
        CrawlSpec::new(
            "crawl-1",
            ["https://example.com/"],
            Scope::seed_origins(),
            CrawlBudget::new(4, 2, 2, 2).unwrap(),
        )
        .unwrap()
        .with_execution_binding(vec![1, 2, 3])
        .unwrap()
    }

    #[test]
    fn durable_frontier_deduplicates_and_recovers_a_lease() {
        let mut engine = CrawlEngine::create(MemoryStore::new(), spec(), 10).unwrap();
        let _lease = engine.claim_next("worker-1", "lease-1", 20, 10).unwrap().unwrap();
        let store = engine.into_store();

        let mut engine = CrawlEngine::open(store, 31, LeaseRecovery::Expired).unwrap();
        assert_eq!(engine.spec().execution_binding(), &[1, 2, 3]);
        assert_eq!(engine.status().pending, 1);
        let lease = engine.claim_next("worker-1", "lease-2", 32, 10).unwrap().unwrap();
        let child = CanonicalUrl::parse("https://example.com/child#fragment").unwrap();
        let duplicate = CanonicalUrl::parse("https://EXAMPLE.com:443/child").unwrap();
        let report = engine
            .complete(
                &lease,
                Completion::new(Some(200)).with_discovered_links([child.clone(), duplicate]),
                33,
            )
            .unwrap();

        assert_eq!(report.enqueued, 1);
        assert_eq!(report.duplicate, 1);
        assert!(matches!(engine.entry(&child).unwrap().state(), EntryState::Pending { .. }));
    }

    #[test]
    fn retry_budget_and_cancellation_are_visible_in_status() {
        let mut engine = CrawlEngine::create(MemoryStore::new(), spec(), 10).unwrap();
        let first = engine.claim_next("worker", "lease-1", 20, 10).unwrap().unwrap();
        assert!(engine.fail(&first, Failure::retryable("timeout"), 21).unwrap());
        let second = engine.claim_next("worker", "lease-2", 22, 10).unwrap().unwrap();
        assert!(!engine.fail(&second, Failure::retryable("timeout"), 23).unwrap());
        assert_eq!(engine.status().failed, 1);
        engine.cancel(24, Some("operator stop".to_owned())).unwrap();
        assert_eq!(engine.status().state, JobState::Cancelled);
    }

    #[test]
    fn expired_lease_cannot_complete_or_fail() {
        let mut engine = CrawlEngine::create(MemoryStore::new(), spec(), 10).unwrap();
        let lease = engine.claim_next("worker", "lease", 20, 10).unwrap().unwrap();
        let revision = engine.status().revision;

        assert!(matches!(
            engine.complete(&lease, Completion::new(Some(200)), 30),
            Err(super::EngineError::LeaseExpired)
        ));
        assert!(matches!(
            engine.fail(&lease, Failure::terminal("late"), 31),
            Err(super::EngineError::LeaseExpired)
        ));
        assert_eq!(engine.status().revision, revision);
        assert_eq!(engine.status().in_flight, 1);
    }

    #[test]
    fn terminal_job_with_a_failed_page_is_not_successful() {
        let partial_spec = CrawlSpec::new(
            "partial",
            ["https://example.com/"],
            Scope::seed_origins(),
            CrawlBudget::new(1, 0, 2, 1).unwrap(),
        )
        .unwrap();
        let mut engine = CrawlEngine::create(MemoryStore::new(), partial_spec, 10).unwrap();
        let lease = engine.claim_next("worker", "lease", 20, 10).unwrap().unwrap();
        assert!(!engine.fail(&lease, Failure::terminal("failed"), 21).unwrap());

        assert_eq!(engine.status().state, JobState::CompletedWithFailures);
    }

    #[test]
    fn cancel_does_not_rewrite_a_terminal_job() {
        let completed_spec = CrawlSpec::new(
            "completed",
            ["https://example.com/"],
            Scope::seed_origins(),
            CrawlBudget::new(1, 0, 1, 1).unwrap(),
        )
        .unwrap();
        let mut engine = CrawlEngine::create(MemoryStore::new(), completed_spec, 10).unwrap();
        let lease = engine.claim_next("worker", "lease", 20, 10).unwrap().unwrap();
        engine.complete(&lease, Completion::new(Some(200)), 21).unwrap();
        let revision = engine.status().revision;

        engine.cancel(22, Some("late cancel".to_owned())).unwrap();

        assert_eq!(engine.status().state, JobState::Completed);
        assert_eq!(engine.status().revision, revision);
        assert!(engine.cancellation().is_none());
    }

    #[test]
    fn fatal_job_failure_is_sanitized_durable_and_not_recovered() {
        let mut engine = CrawlEngine::create(MemoryStore::new(), spec(), 10).unwrap();
        let _lease = engine.claim_next("worker", "lease", 20, 10).unwrap().unwrap();

        engine.fail_job(21, " fatal\r\nreason\t").unwrap();
        assert_eq!(engine.status().state, JobState::Failed);
        assert_eq!(engine.failure().unwrap().reason(), "fatal reason");
        let terminal_sequence = engine.events_after(0).last().unwrap().sequence();
        assert!(matches!(
            engine.events_after(0).last().unwrap().kind(),
            CrawlEventKind::JobFailed { reason } if reason == "fatal reason"
        ));

        let store = engine.into_store();
        let mut reopened = CrawlEngine::open(store, 1_000, LeaseRecovery::All).unwrap();
        assert_eq!(reopened.status().state, JobState::Failed);
        assert_eq!(reopened.status().in_flight, 1);
        assert_eq!(
            reopened.events_after(0).last().unwrap().sequence(),
            terminal_sequence
        );
        assert_eq!(
            reopened.recover_leases(1_001, LeaseRecovery::All).unwrap(),
            crate::RecoveryReport { requeued: 0, failed: 0 }
        );
        assert!(matches!(
            reopened.claim_next("worker", "next", 1_002, 10),
            Err(super::EngineError::JobFailed)
        ));
    }

    #[test]
    fn recovered_completion_requires_exact_token_and_is_durable_once() {
        let mut engine = CrawlEngine::create(MemoryStore::new(), spec(), 10).unwrap();
        let stale = engine.claim_next("worker", "lease", 20, 10).unwrap().unwrap();
        let mut other = CrawlEngine::create(MemoryStore::new(), spec(), 10).unwrap();
        let foreign = other
            .claim_next("other-worker", "other-lease", 20, 10)
            .unwrap()
            .unwrap();
        assert!(matches!(
            engine.complete_recovered(&foreign, Completion::new(Some(200)), 21),
            Err(super::EngineError::LeaseMismatch)
        ));
        let current = engine.renew_lease(&stale, 21, 10).unwrap();
        let revision = engine.status().revision;

        assert!(matches!(
            engine.complete_recovered(&stale, Completion::new(Some(200)), 40),
            Err(super::EngineError::LeaseMismatch)
        ));
        assert_eq!(engine.status().revision, revision);

        let store = engine.into_store();
        let mut reopened = CrawlEngine::open_without_recovery(store).unwrap();
        assert_eq!(
            reopened.active_lease_tokens().collect::<Vec<_>>(),
            vec![current.clone()]
        );
        reopened
            .complete_recovered(&current, Completion::new(Some(200)), 100)
            .unwrap();
        assert_eq!(reopened.status().state, JobState::Completed);
        let completed_revision = reopened.status().revision;
        assert!(matches!(
            reopened.complete_recovered(&current, Completion::new(Some(200)), 101),
            Err(super::EngineError::InvalidTransition(_))
        ));
        assert_eq!(reopened.status().revision, completed_revision);
        assert_eq!(
            reopened
                .events_after(0)
                .filter(|event| matches!(event.kind(), CrawlEventKind::Completed { .. }))
                .count(),
            1
        );

        let reopened = CrawlEngine::open_without_recovery(reopened.into_store()).unwrap();
        assert_eq!(reopened.status().state, JobState::Completed);
        assert_eq!(reopened.active_lease_tokens().count(), 0);
    }
}
