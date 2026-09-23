//! Error type for [`super::db`] and [`super::export`].

/// Storage-layer failure: SQLite errors, (de)serialisation, or I/O.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("database error: {0}")]
    Database(String),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
