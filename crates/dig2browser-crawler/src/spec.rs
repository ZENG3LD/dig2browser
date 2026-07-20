use crate::{CanonicalUrl, CanonicalUrlError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use url::Host;

pub const MAX_PAGES: usize = 10_000;
pub const MAX_DEPTH: u32 = 64;
pub const MAX_FAILURES: usize = MAX_PAGES;
pub const MAX_ATTEMPTS_PER_URL: u32 = 8;
pub const MAX_SCOPE_ENTRIES: usize = 4_096;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CrawlBudget {
    max_pages: usize,
    max_depth: u32,
    max_failures: usize,
    max_attempts_per_url: u32,
}

impl CrawlBudget {
    pub fn new(
        max_pages: usize,
        max_depth: u32,
        max_failures: usize,
        max_attempts_per_url: u32,
    ) -> Result<Self, SpecError> {
        let budget = Self {
            max_pages,
            max_depth,
            max_failures,
            max_attempts_per_url,
        };
        budget.validate()?;
        Ok(budget)
    }

    pub fn max_pages(&self) -> usize {
        self.max_pages
    }

    pub fn max_depth(&self) -> u32 {
        self.max_depth
    }

    pub fn max_failures(&self) -> usize {
        self.max_failures
    }

    pub fn max_attempts_per_url(&self) -> u32 {
        self.max_attempts_per_url
    }

    pub(crate) fn validate(&self) -> Result<(), SpecError> {
        if self.max_pages == 0 {
            return Err(SpecError::InvalidBudget("max_pages must be positive"));
        }
        if self.max_pages > MAX_PAGES {
            return Err(SpecError::InvalidBudget("max_pages exceeds the core limit"));
        }
        if self.max_depth > MAX_DEPTH {
            return Err(SpecError::InvalidBudget("max_depth exceeds the core limit"));
        }
        if self.max_failures == 0 {
            return Err(SpecError::InvalidBudget("max_failures must be positive"));
        }
        if self.max_failures > MAX_FAILURES || self.max_failures > self.max_pages {
            return Err(SpecError::InvalidBudget(
                "max_failures must not exceed max_pages or the core limit",
            ));
        }
        if self.max_attempts_per_url == 0 {
            return Err(SpecError::InvalidBudget(
                "max_attempts_per_url must be positive",
            ));
        }
        if self.max_attempts_per_url > MAX_ATTEMPTS_PER_URL {
            return Err(SpecError::InvalidBudget(
                "max_attempts_per_url exceeds the core limit",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Scope {
    rule: ScopeRule,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum ScopeRule {
    SeedOrigins,
    Origins { origins: BTreeSet<String> },
    Hosts {
        hosts: BTreeSet<String>,
        include_subdomains: bool,
    },
    AnyHttp,
}

impl Scope {
    pub fn seed_origins() -> Self {
        Self {
            rule: ScopeRule::SeedOrigins,
        }
    }

    pub fn any_http() -> Self {
        Self {
            rule: ScopeRule::AnyHttp,
        }
    }

    pub fn origins<I, S>(origins: I) -> Result<Self, SpecError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut normalized = BTreeSet::new();
        for origin in origins {
            if normalized.len() >= MAX_SCOPE_ENTRIES {
                return Err(SpecError::InvalidScope(format!(
                    "origin scope exceeds {MAX_SCOPE_ENTRIES} entries"
                )));
            }
            if origin.as_ref().len() > crate::MAX_URL_BYTES {
                return Err(SpecError::InvalidScope(format!(
                    "origin exceeds {} bytes",
                    crate::MAX_URL_BYTES
                )));
            }
            let raw = url::Url::parse(origin.as_ref())
                .map_err(|error| SpecError::InvalidScope(error.to_string()))?;
            if raw.fragment().is_some() {
                return Err(SpecError::InvalidScope(
                    "origin must not contain a fragment".to_owned(),
                ));
            }
            let canonical = CanonicalUrl::parse(origin.as_ref())?;
            let parsed = canonical.parsed();
            if parsed.path() != "/" || parsed.query().is_some() {
                return Err(SpecError::InvalidScope(
                    "origin must not contain a path or query".to_owned(),
                ));
            }
            normalized.insert(parsed.origin().ascii_serialization());
        }
        if normalized.is_empty() {
            return Err(SpecError::InvalidScope(
                "origin scope must contain at least one origin".to_owned(),
            ));
        }
        Ok(Self {
            rule: ScopeRule::Origins {
                origins: normalized,
            },
        })
    }

    pub fn hosts<I, S>(hosts: I, include_subdomains: bool) -> Result<Self, SpecError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut normalized = BTreeSet::new();
        for host in hosts {
            if normalized.len() >= MAX_SCOPE_ENTRIES {
                return Err(SpecError::InvalidScope(format!(
                    "host scope exceeds {MAX_SCOPE_ENTRIES} entries"
                )));
            }
            let raw = host.as_ref().trim();
            if raw.is_empty() {
                return Err(SpecError::InvalidScope("host must not be empty".to_owned()));
            }
            if raw.len() > 255 {
                return Err(SpecError::InvalidScope(
                    "host exceeds 255 bytes".to_owned(),
                ));
            }
            let host = Host::parse(raw)
                .map_err(|error| SpecError::InvalidScope(error.to_string()))?
                .to_string()
                .to_ascii_lowercase();
            normalized.insert(host);
        }
        if normalized.is_empty() {
            return Err(SpecError::InvalidScope(
                "host scope must contain at least one host".to_owned(),
            ));
        }
        Ok(Self {
            rule: ScopeRule::Hosts {
                hosts: normalized,
                include_subdomains,
            },
        })
    }

    pub(crate) fn allows(&self, candidate: &CanonicalUrl, seeds: &[CanonicalUrl]) -> bool {
        match &self.rule {
            ScopeRule::AnyHttp => true,
            ScopeRule::SeedOrigins => {
                let candidate_origin = candidate.parsed().origin().ascii_serialization();
                seeds.iter().any(|seed| {
                    seed.parsed().origin().ascii_serialization() == candidate_origin
                })
            }
            ScopeRule::Origins { origins } => origins.contains(
                &candidate.parsed().origin().ascii_serialization(),
            ),
            ScopeRule::Hosts {
                hosts,
                include_subdomains,
            } => {
                let parsed = candidate.parsed();
                let Some(candidate_host) = parsed.host_str() else {
                    return false;
                };
                let candidate_host = candidate_host.to_ascii_lowercase();
                hosts.iter().any(|allowed| {
                    candidate_host == *allowed
                        || (*include_subdomains
                            && candidate_host
                                .strip_suffix(allowed)
                                .is_some_and(|prefix| prefix.ends_with('.')))
                })
            }
        }
    }

    pub(crate) fn validate(&self) -> Result<(), SpecError> {
        match &self.rule {
            ScopeRule::Origins { origins } if origins.is_empty() => {
                return Err(SpecError::InvalidScope(
                    "origin scope must contain at least one origin".to_owned(),
                ))
            }
            ScopeRule::Origins { origins } if origins.len() > MAX_SCOPE_ENTRIES => {
                return Err(SpecError::InvalidScope(format!(
                    "origin scope exceeds {MAX_SCOPE_ENTRIES} entries"
                )))
            }
            ScopeRule::Hosts { hosts, .. } if hosts.is_empty() => {
                return Err(SpecError::InvalidScope(
                    "host scope must contain at least one host".to_owned(),
                ))
            }
            ScopeRule::Hosts { hosts, .. } if hosts.len() > MAX_SCOPE_ENTRIES => {
                return Err(SpecError::InvalidScope(format!(
                    "host scope exceeds {MAX_SCOPE_ENTRIES} entries"
                )))
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CrawlSpec {
    job_id: String,
    seeds: Vec<CanonicalUrl>,
    scope: Scope,
    budget: CrawlBudget,
    execution_binding: Vec<u8>,
}

impl CrawlSpec {
    pub fn new<I, S>(
        job_id: impl Into<String>,
        seeds: I,
        scope: Scope,
        budget: CrawlBudget,
    ) -> Result<Self, SpecError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut canonical_seeds = BTreeSet::new();
        for seed in seeds {
            canonical_seeds.insert(CanonicalUrl::parse(seed.as_ref())?);
        }
        let spec = Self {
            job_id: job_id.into(),
            seeds: canonical_seeds.into_iter().collect(),
            scope,
            budget,
            execution_binding: Vec::new(),
        };
        spec.validate()?;
        Ok(spec)
    }

    pub fn job_id(&self) -> &str {
        &self.job_id
    }

    pub fn seeds(&self) -> &[CanonicalUrl] {
        &self.seeds
    }

    pub fn scope(&self) -> &Scope {
        &self.scope
    }

    pub fn budget(&self) -> &CrawlBudget {
        &self.budget
    }

    pub fn with_execution_binding(mut self, binding: Vec<u8>) -> Result<Self, SpecError> {
        self.execution_binding = binding;
        self.validate()?;
        Ok(self)
    }

    pub fn execution_binding(&self) -> &[u8] {
        &self.execution_binding
    }

    pub fn allows(&self, candidate: &CanonicalUrl) -> bool {
        self.scope.allows(candidate, &self.seeds)
    }

    pub(crate) fn validate(&self) -> Result<(), SpecError> {
        let job_id = self.job_id.trim();
        if job_id.is_empty() || job_id.len() > 256 || job_id.chars().any(char::is_control) {
            return Err(SpecError::InvalidJobId);
        }
        if self.seeds.is_empty() {
            return Err(SpecError::NoSeeds);
        }
        if self.execution_binding.len() > 64 * 1024 {
            return Err(SpecError::ExecutionBindingTooLarge);
        }
        self.scope.validate()?;
        self.budget.validate()?;
        if self.seeds.len() > self.budget.max_pages {
            return Err(SpecError::SeedsExceedPageBudget);
        }
        if self.seeds.iter().any(|seed| !self.allows(seed)) {
            return Err(SpecError::SeedOutsideScope);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SpecError {
    InvalidJobId,
    NoSeeds,
    InvalidUrl(CanonicalUrlError),
    InvalidScope(String),
    InvalidBudget(&'static str),
    SeedsExceedPageBudget,
    SeedOutsideScope,
    ExecutionBindingTooLarge,
}

impl fmt::Display for SpecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidJobId => formatter.write_str("job_id must be 1..=256 non-control characters"),
            Self::NoSeeds => formatter.write_str("crawl spec must contain at least one seed"),
            Self::InvalidUrl(error) => write!(formatter, "invalid seed URL: {error}"),
            Self::InvalidScope(message) => write!(formatter, "invalid crawl scope: {message}"),
            Self::InvalidBudget(message) => write!(formatter, "invalid crawl budget: {message}"),
            Self::SeedsExceedPageBudget => formatter.write_str("seed count exceeds max_pages"),
            Self::SeedOutsideScope => formatter.write_str("a seed URL is outside the crawl scope"),
            Self::ExecutionBindingTooLarge => {
                formatter.write_str("execution binding exceeds 65536 bytes")
            }
        }
    }
}

impl std::error::Error for SpecError {}

impl From<CanonicalUrlError> for SpecError {
    fn from(error: CanonicalUrlError) -> Self {
        Self::InvalidUrl(error)
    }
}

#[cfg(test)]
mod tests {
    use super::{CrawlBudget, CrawlSpec, Scope};

    #[test]
    fn spec_deduplicates_canonical_seeds_and_enforces_origin_scope() {
        let budget = CrawlBudget::new(10, 2, 3, 2).unwrap();
        let spec = CrawlSpec::new(
            "job-1",
            ["https://example.com:443/#one", "https://EXAMPLE.com/#two"],
            Scope::seed_origins(),
            budget,
        )
        .unwrap();

        assert_eq!(spec.seeds().len(), 1);
        assert!(spec.allows(&CanonicalUrl::parse("https://example.com/next").unwrap()));
        assert!(!spec.allows(&CanonicalUrl::parse("http://example.com/next").unwrap()));
    }

    #[test]
    fn explicit_origins_preserve_scheme_and_effective_port() {
        let scope = Scope::origins(["https://example.com", "http://example.com:8080"])
            .unwrap();
        let budget = CrawlBudget::new(10, 1, 2, 1).unwrap();
        let spec = CrawlSpec::new(
            "job-2",
            ["http://example.com:8080/seed"],
            scope,
            budget,
        )
        .unwrap();

        assert!(spec.allows(&CanonicalUrl::parse("https://example.com/page").unwrap()));
        assert!(spec.allows(&CanonicalUrl::parse("http://example.com:8080/page").unwrap()));
        assert!(!spec.allows(&CanonicalUrl::parse("http://example.com/page").unwrap()));
    }

    use crate::CanonicalUrl;
}
