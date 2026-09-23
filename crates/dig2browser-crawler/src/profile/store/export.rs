//! CSV / JSON / JSONL export of extracted records from a [`super::db`] connection.

use crate::profile::store::error::StorageError;
use rusqlite::Connection;
use std::io::Write;

/// Export all records for `job_id` as newline-delimited JSON (one JSON object
/// per line). Returns the number of records written.
pub fn export_jsonl(
    conn: &Connection,
    job_id: &str,
    writer: &mut dyn Write,
) -> Result<usize, StorageError> {
    let mut stmt = conn
        .prepare("SELECT data_json FROM records WHERE job_id = ?1")
        .map_err(|e| StorageError::Database(format!("export prepare: {e}")))?;
    let rows = stmt
        .query_map([job_id], |row| row.get::<_, String>(0))
        .map_err(|e| StorageError::Database(format!("export query: {e}")))?;
    let mut count = 0;
    for row in rows {
        let json = row.map_err(|e| StorageError::Database(format!("export row: {e}")))?;
        writeln!(writer, "{json}")?;
        count += 1;
    }
    Ok(count)
}

/// Export all records for `job_id` as a pretty-printed JSON array. Returns
/// the number of records written.
pub fn export_json(
    conn: &Connection,
    job_id: &str,
    writer: &mut dyn Write,
) -> Result<usize, StorageError> {
    let mut stmt = conn
        .prepare("SELECT data_json FROM records WHERE job_id = ?1")
        .map_err(|e| StorageError::Database(format!("export prepare: {e}")))?;
    let rows = stmt
        .query_map([job_id], |row| row.get::<_, String>(0))
        .map_err(|e| StorageError::Database(format!("export query: {e}")))?;
    let mut items: Vec<serde_json::Value> = Vec::new();
    for row in rows {
        let json = row.map_err(|e| StorageError::Database(format!("export row: {e}")))?;
        let val: serde_json::Value = serde_json::from_str(&json)?;
        items.push(val);
    }
    let count = items.len();
    serde_json::to_writer_pretty(writer, &items)?;
    Ok(count)
}

/// Export all records for `job_id` as CSV with columns: url, data,
/// confidence, extracted_at. Returns the number of records written.
pub fn export_csv(
    conn: &Connection,
    job_id: &str,
    writer: &mut dyn Write,
) -> Result<usize, StorageError> {
    let mut stmt = conn
        .prepare("SELECT url, data_json, confidence, extracted_at FROM records WHERE job_id = ?1")
        .map_err(|e| StorageError::Database(format!("export prepare: {e}")))?;
    let rows = stmt
        .query_map([job_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<f64>>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(|e| StorageError::Database(format!("export query: {e}")))?;

    let mut csv_writer = csv::Writer::from_writer(writer);
    csv_writer
        .write_record(["url", "data", "confidence", "extracted_at"])
        .map_err(|e| StorageError::Io(std::io::Error::other(e.to_string())))?;

    let mut count = 0;
    for row in rows {
        let (url, data, conf, at) =
            row.map_err(|e| StorageError::Database(format!("export row: {e}")))?;
        let conf_str = conf.map(|c| format!("{c:.2}")).unwrap_or_default();
        csv_writer
            .write_record([&url, &data, &conf_str, &at])
            .map_err(|e| StorageError::Io(std::io::Error::other(e.to_string())))?;
        count += 1;
    }
    csv_writer
        .flush()
        .map_err(|e| StorageError::Io(std::io::Error::other(e.to_string())))?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::store::db::SqliteStorage;
    use crate::profile::types::{CrawlConfig, CrawlJob, FetchMethod, JobStatus, RateConfig};
    use chrono::Utc;
    use uuid::Uuid;

    async fn seeded_storage() -> (SqliteStorage, Uuid) {
        let storage = SqliteStorage::open_in_memory().expect("open in-memory db");
        let job_id = Uuid::new_v4();
        let job = CrawlJob {
            id: job_id,
            config: CrawlConfig {
                name: "export-test".to_owned(),
                domains: vec!["example.com".to_owned()],
                start_urls: vec![url::Url::parse("https://example.com/").unwrap()],
                max_depth: None,
                max_pages: None,
                rate: RateConfig {
                    requests_per_second: 1.0,
                    min_delay_ms: 0,
                    concurrent_requests: 1,
                },
                fetch_method: FetchMethod::Http,
                headers: None,
                follow_links: false,
                link_patterns: None,
                exclude_patterns: None,
                agent_goal: None,
            },
            started_at: Utc::now(),
            status: JobStatus::Running,
        };
        storage.create_job(&job).await.expect("create job");
        let record = crate::profile::types::ExtractedRecord {
            job_id,
            url: url::Url::parse("https://example.com/item").unwrap(),
            data: serde_json::json!({"title": "Widget"}),
            extracted_at: Utc::now(),
            confidence: Some(0.75),
        };
        storage.save_record(&record).await.expect("save_record");
        (storage, job_id)
    }

    #[tokio::test]
    async fn exports_jsonl_json_and_csv() {
        let (storage, job_id) = seeded_storage().await;
        let conn = storage.connection();
        let conn = conn.lock().await;

        let mut jsonl = Vec::new();
        let jsonl_count = export_jsonl(&conn, &job_id.to_string(), &mut jsonl).unwrap();
        assert_eq!(jsonl_count, 1);
        assert!(String::from_utf8(jsonl).unwrap().contains("Widget"));

        let mut json = Vec::new();
        let json_count = export_json(&conn, &job_id.to_string(), &mut json).unwrap();
        assert_eq!(json_count, 1);
        assert!(String::from_utf8(json).unwrap().contains("Widget"));

        let mut csv_out = Vec::new();
        let csv_count = export_csv(&conn, &job_id.to_string(), &mut csv_out).unwrap();
        assert_eq!(csv_count, 1);
        let csv_text = String::from_utf8(csv_out).unwrap();
        assert!(csv_text.starts_with("url,data,confidence,extracted_at"));
    }
}
