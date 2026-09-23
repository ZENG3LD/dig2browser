//! SQLite-backed crawl job / record storage.
//!
//! Schema: `crawl_jobs` (one row per named job), `visited_urls` (dedup +
//! depth/status per job), `records` (extracted data), `site_memory`
//! (per-domain agent notes). Ported from `dig2crawl` (`storage/db.rs`); the
//! `Storage` trait indirection was dropped in favor of plain inherent async
//! methods since `SqliteStorage` is the crate's only implementation.

use crate::profile::store::error::StorageError;
use crate::profile::types::{CrawlJob, CrawlStats, ExtractedRecord, JobStatus};
use ahash::RandomState;
use chrono::Utc;
use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;
use url::Url;
use uuid::Uuid;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS crawl_jobs (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    config_json TEXT NOT NULL,
    goal_json TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    started_at TEXT NOT NULL,
    completed_at TEXT,
    pages_fetched INTEGER NOT NULL DEFAULT 0,
    records_found INTEGER NOT NULL DEFAULT 0,
    errors INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS visited_urls (
    job_id TEXT NOT NULL REFERENCES crawl_jobs(id),
    url TEXT NOT NULL,
    url_hash INTEGER NOT NULL,
    depth INTEGER NOT NULL DEFAULT 0,
    status_code INTEGER,
    visited_at TEXT NOT NULL,
    PRIMARY KEY (job_id, url_hash)
);

CREATE TABLE IF NOT EXISTS records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL REFERENCES crawl_jobs(id),
    url TEXT NOT NULL,
    data_json TEXT NOT NULL,
    confidence REAL,
    extracted_at TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'agent'
);

CREATE TABLE IF NOT EXISTS site_memory (
    job_id TEXT NOT NULL REFERENCES crawl_jobs(id),
    domain TEXT NOT NULL,
    memory_json TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (job_id, domain)
);

CREATE INDEX IF NOT EXISTS idx_records_job ON records(job_id);
CREATE INDEX IF NOT EXISTS idx_visited_job ON visited_urls(job_id);
";

/// Compute a deterministic 64-bit hash of a URL string.
/// Uses fixed seeds so the hash is consistent across calls.
fn url_hash(url: &str) -> i64 {
    let state = RandomState::with_seeds(0xdead_beef, 0xcafe_babe, 0x1234_5678, 0xabcd_ef01);
    state.hash_one(url) as i64
}

fn job_status_str(status: &JobStatus) -> &'static str {
    match status {
        JobStatus::Pending => "pending",
        JobStatus::Running => "running",
        JobStatus::Completed => "completed",
        JobStatus::Failed { .. } => "failed",
        JobStatus::Cancelled => "cancelled",
    }
}

/// SQLite-backed crawl storage with WAL mode.
pub struct SqliteStorage {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteStorage {
    /// Open (or create) a SQLite database at the given path.
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        let conn =
            Connection::open(path).map_err(|e| StorageError::Database(format!("open: {e}")))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA foreign_keys = ON;",
        )
        .map_err(|e| StorageError::Database(format!("pragmas: {e}")))?;
        Self::init_schema(&conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Open an in-memory SQLite database (useful for testing).
    pub fn open_in_memory() -> Result<Self, StorageError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| StorageError::Database(format!("open_in_memory: {e}")))?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")
            .map_err(|e| StorageError::Database(format!("pragmas: {e}")))?;
        Self::init_schema(&conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    fn init_schema(conn: &Connection) -> Result<(), StorageError> {
        conn.execute_batch(SCHEMA)
            .map_err(|e| StorageError::Database(format!("init schema: {e}")))?;
        Ok(())
    }

    /// Insert a new crawl job record into the database.
    pub async fn create_job(&self, job: &CrawlJob) -> Result<(), StorageError> {
        let conn = self.conn.lock().await;
        let config_json = serde_json::to_string(&job.config)?;
        let goal_json = job
            .config
            .agent_goal
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let status_str = job_status_str(&job.status);
        conn.execute(
            "INSERT INTO crawl_jobs (id, name, config_json, goal_json, status, started_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                job.id.to_string(),
                job.config.name.as_str(),
                config_json,
                goal_json,
                status_str,
                job.started_at.to_rfc3339(),
            ],
        )
        .map_err(|e| StorageError::Database(format!("create_job: {e}")))?;
        Ok(())
    }

    /// Update the status (and optional completed_at timestamp) for a job.
    pub async fn update_job_status(
        &self,
        job_id: Uuid,
        status: &str,
        completed_at: Option<&str>,
    ) -> Result<(), StorageError> {
        let conn = self.conn.lock().await;
        conn.execute(
            "UPDATE crawl_jobs SET status = ?1, completed_at = ?2 WHERE id = ?3",
            params![status, completed_at, job_id.to_string()],
        )
        .map_err(|e| StorageError::Database(format!("update_job_status: {e}")))?;
        Ok(())
    }

    /// Persist agent site-memory for a domain (upsert).
    pub async fn save_memory(
        &self,
        job_id: Uuid,
        domain: &str,
        memory_json: &str,
    ) -> Result<(), StorageError> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT OR REPLACE INTO site_memory (job_id, domain, memory_json, updated_at) \
             VALUES (?1, ?2, ?3, ?4)",
            params![
                job_id.to_string(),
                domain,
                memory_json,
                Utc::now().to_rfc3339(),
            ],
        )
        .map_err(|e| StorageError::Database(format!("save_memory: {e}")))?;
        Ok(())
    }

    /// Load agent site-memory for a domain. Returns `None` if not found.
    pub async fn load_memory(
        &self,
        job_id: Uuid,
        domain: &str,
    ) -> Result<Option<String>, StorageError> {
        let conn = self.conn.lock().await;
        let result = conn.query_row(
            "SELECT memory_json FROM site_memory WHERE job_id = ?1 AND domain = ?2",
            params![job_id.to_string(), domain],
            |row| row.get::<_, String>(0),
        );
        match result {
            Ok(json) => Ok(Some(json)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(StorageError::Database(format!("load_memory: {e}"))),
        }
    }

    /// Persist one extracted record and bump the job's `records_found` counter.
    pub async fn save_record(&self, record: &ExtractedRecord) -> Result<(), StorageError> {
        let conn = self.conn.lock().await;
        let data_json = serde_json::to_string(&record.data)?;
        conn.execute(
            "INSERT INTO records (job_id, url, data_json, confidence, extracted_at, source) \
             VALUES (?1, ?2, ?3, ?4, ?5, 'agent')",
            params![
                record.job_id.to_string(),
                record.url.as_str(),
                data_json,
                record.confidence,
                record.extracted_at.to_rfc3339(),
            ],
        )
        .map_err(|e| StorageError::Database(format!("save_record: {e}")))?;
        conn.execute(
            "UPDATE crawl_jobs SET records_found = records_found + 1 WHERE id = ?1",
            params![record.job_id.to_string()],
        )
        .map_err(|e| StorageError::Database(format!("increment records: {e}")))?;
        Ok(())
    }

    /// Overwrite a job's aggregate counters with a fresh `CrawlStats` snapshot.
    pub async fn save_stats(&self, stats: &CrawlStats) -> Result<(), StorageError> {
        let conn = self.conn.lock().await;
        conn.execute(
            "UPDATE crawl_jobs SET pages_fetched = ?1, records_found = ?2, errors = ?3 \
             WHERE id = ?4",
            params![
                stats.pages_fetched as i64,
                stats.records_extracted as i64,
                stats.errors as i64,
                stats.job_id.to_string(),
            ],
        )
        .map_err(|e| StorageError::Database(format!("save_stats: {e}")))?;
        Ok(())
    }

    /// Record a visited URL (deduplicated by hash) and bump `pages_fetched`.
    pub async fn mark_visited(
        &self,
        job_id: Uuid,
        url: &Url,
        status: Option<u16>,
    ) -> Result<(), StorageError> {
        let hash = url_hash(url.as_str());
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT OR IGNORE INTO visited_urls \
             (job_id, url, url_hash, status_code, visited_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                job_id.to_string(),
                url.as_str(),
                hash,
                status.map(i64::from),
                Utc::now().to_rfc3339(),
            ],
        )
        .map_err(|e| StorageError::Database(format!("mark_visited: {e}")))?;
        conn.execute(
            "UPDATE crawl_jobs SET pages_fetched = pages_fetched + 1 WHERE id = ?1",
            params![job_id.to_string()],
        )
        .map_err(|e| StorageError::Database(format!("increment pages: {e}")))?;
        Ok(())
    }

    /// Whether `url` was already recorded as visited for `job_id`.
    pub async fn is_visited(&self, job_id: Uuid, url: &Url) -> Result<bool, StorageError> {
        let hash = url_hash(url.as_str());
        let conn = self.conn.lock().await;
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM visited_urls WHERE job_id = ?1 AND url_hash = ?2",
                params![job_id.to_string(), hash],
                |row| row.get(0),
            )
            .map_err(|e| StorageError::Database(format!("is_visited: {e}")))?;
        Ok(count > 0)
    }

    /// Borrow the underlying connection (e.g. for [`super::export`]).
    pub fn connection(&self) -> Arc<Mutex<Connection>> {
        Arc::clone(&self.conn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::types::{CrawlConfig, FetchMethod, RateConfig};

    fn sample_job() -> CrawlJob {
        CrawlJob {
            id: Uuid::new_v4(),
            config: CrawlConfig {
                name: "test-job".to_owned(),
                domains: vec!["example.com".to_owned()],
                start_urls: vec![Url::parse("https://example.com/").unwrap()],
                max_depth: Some(2),
                max_pages: Some(10),
                rate: RateConfig {
                    requests_per_second: 1.0,
                    min_delay_ms: 500,
                    concurrent_requests: 1,
                },
                fetch_method: FetchMethod::Http,
                headers: None,
                follow_links: true,
                link_patterns: None,
                exclude_patterns: None,
                agent_goal: None,
            },
            started_at: Utc::now(),
            status: JobStatus::Pending,
        }
    }

    #[tokio::test]
    async fn create_job_and_mark_visited_round_trip() {
        let storage = SqliteStorage::open_in_memory().expect("open in-memory db");
        let job = sample_job();
        storage.create_job(&job).await.expect("create job");

        let url = Url::parse("https://example.com/page").unwrap();
        assert!(!storage.is_visited(job.id, &url).await.expect("is_visited"));
        storage
            .mark_visited(job.id, &url, Some(200))
            .await
            .expect("mark_visited");
        assert!(storage.is_visited(job.id, &url).await.expect("is_visited"));
    }

    #[tokio::test]
    async fn save_record_increments_job_counter() {
        let storage = SqliteStorage::open_in_memory().expect("open in-memory db");
        let job = sample_job();
        storage.create_job(&job).await.expect("create job");

        let record = ExtractedRecord {
            job_id: job.id,
            url: Url::parse("https://example.com/item/1").unwrap(),
            data: serde_json::json!({"title": "Widget"}),
            extracted_at: Utc::now(),
            confidence: Some(0.9),
        };
        storage.save_record(&record).await.expect("save_record");

        let conn = storage.connection();
        let conn = conn.lock().await;
        let count: i64 = conn
            .query_row(
                "SELECT records_found FROM crawl_jobs WHERE id = ?1",
                params![job.id.to_string()],
                |row| row.get(0),
            )
            .expect("read records_found");
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn site_memory_round_trip() {
        let storage = SqliteStorage::open_in_memory().expect("open in-memory db");
        let job = sample_job();
        storage.create_job(&job).await.expect("create job");

        assert!(storage
            .load_memory(job.id, "example.com")
            .await
            .expect("load_memory")
            .is_none());
        storage
            .save_memory(job.id, "example.com", "{\"notes\":[]}")
            .await
            .expect("save_memory");
        assert_eq!(
            storage
                .load_memory(job.id, "example.com")
                .await
                .expect("load_memory"),
            Some("{\"notes\":[]}".to_owned())
        );
    }
}
