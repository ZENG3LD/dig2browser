use std::ffi::OsString;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

pub const MAX_SNAPSHOT_BYTES: usize = 128 * 1024 * 1024;
const MAX_STORE_FILE_BYTES: u64 = (MAX_SNAPSHOT_BYTES as u64 * 2) + (64 * 1024);

pub trait CrawlStore {
    fn load(&mut self) -> Result<Option<Vec<u8>>, StoreError>;

    fn save(&mut self, snapshot: &[u8]) -> Result<(), StoreError>;
}

#[derive(Clone, Debug, Default)]
pub struct MemoryStore {
    snapshot: Option<Vec<u8>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl CrawlStore for MemoryStore {
    fn load(&mut self) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.snapshot.clone())
    }

    fn save(&mut self, snapshot: &[u8]) -> Result<(), StoreError> {
        validate_snapshot_size(snapshot)?;
        self.snapshot = Some(snapshot.to_vec());
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct FileStore {
    path: PathBuf,
}

impl FileStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn slot_path(&self, slot: usize) -> PathBuf {
        let mut path = OsString::from(self.path.as_os_str());
        path.push(format!(".slot{slot}"));
        PathBuf::from(path)
    }

    fn candidates(&self) -> [PathBuf; 3] {
        [self.path.clone(), self.slot_path(0), self.slot_path(1)]
    }

    fn load_latest(&self) -> Result<LoadResult, StoreError> {
        let mut latest: Option<StoredRecord> = None;
        let mut any_file = false;
        for path in self.candidates() {
            let candidate = read_candidate(&path)?;
            any_file |= candidate.existed;
            if let Some(record) = candidate.record {
                match latest.as_ref() {
                    Some(current) if record.generation == current.generation => {
                        if record.snapshot != current.snapshot {
                            return Err(StoreError::Corrupt(
                                "conflicting snapshots share a generation".to_owned(),
                            ));
                        }
                    }
                    Some(current) if record.generation < current.generation => {}
                    _ => latest = Some(record),
                }
            }
        }
        Ok(LoadResult { latest, any_file })
    }
}

impl CrawlStore for FileStore {
    fn load(&mut self) -> Result<Option<Vec<u8>>, StoreError> {
        let loaded = self.load_latest()?;
        match loaded.latest {
            Some(record) => Ok(Some(record.snapshot)),
            None if loaded.any_file => Err(StoreError::Corrupt(
                "journal contains no complete snapshot".to_owned(),
            )),
            None => Ok(None),
        }
    }

    fn save(&mut self, snapshot: &[u8]) -> Result<(), StoreError> {
        validate_snapshot_size(snapshot)?;
        let loaded = self.load_latest()?;
        let generation = loaded
            .latest
            .as_ref()
            .map_or(Ok(1), |record| {
                record.generation.checked_add(1).ok_or_else(|| {
                    StoreError::Corrupt("journal generation overflow".to_owned())
                })
            })?;

        if loaded.latest.is_none() {
            if loaded.any_file {
                return Err(StoreError::Corrupt(
                    "journal contains no complete snapshot".to_owned(),
                ));
            }
            write_record(&self.path, generation, snapshot, true)?;
        } else {
            let slot = (generation as usize) & 1;
            write_record(&self.slot_path(slot), generation, snapshot, false)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct LoadResult {
    latest: Option<StoredRecord>,
    any_file: bool,
}

#[derive(Debug)]
struct Candidate {
    record: Option<StoredRecord>,
    existed: bool,
}

#[derive(Debug)]
struct StoredRecord {
    generation: u64,
    snapshot: Vec<u8>,
}

fn read_candidate(path: &Path) -> Result<Candidate, StoreError> {
    let mut file = match OpenOptions::new().read(true).write(true).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(Candidate {
                record: None,
                existed: false,
            })
        }
        Err(error) => return Err(error.into()),
    };
    if file.metadata()?.len() > MAX_STORE_FILE_BYTES {
        return Err(StoreError::Corrupt(format!(
            "journal file exceeds {MAX_STORE_FILE_BYTES} bytes"
        )));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let mut cursor = 0usize;
    let mut latest = None;
    let mut legacy_generation = 0u64;

    while cursor < bytes.len() {
        let Some(relative_header_end) = bytes[cursor..].iter().position(|byte| *byte == b'\n')
        else {
            break;
        };
        let header_end = cursor + relative_header_end;
        let header = std::str::from_utf8(&bytes[cursor..header_end])
            .map_err(|_| StoreError::Corrupt("journal header is not UTF-8".to_owned()))?;
        let parsed = parse_header(header, legacy_generation)?;
        if parsed.generation <= legacy_generation {
            return Err(StoreError::Corrupt(
                "journal generations are not strictly increasing".to_owned(),
            ));
        }
        legacy_generation = parsed.generation;
        if parsed.length > MAX_SNAPSHOT_BYTES {
            return Err(StoreError::Corrupt(format!(
                "journal snapshot exceeds {MAX_SNAPSHOT_BYTES} bytes"
            )));
        }

        let body_start = header_end + 1;
        let body_end = body_start
            .checked_add(parsed.length)
            .ok_or_else(|| StoreError::Corrupt("journal length overflow".to_owned()))?;
        if body_end >= bytes.len() {
            break;
        }
        if bytes[body_end] != b'\n' {
            return Err(StoreError::Corrupt(
                "complete journal record has an invalid terminator".to_owned(),
            ));
        }
        let body = &bytes[body_start..body_end];
        if checksum(body) != parsed.checksum {
            return Err(StoreError::Corrupt(
                "complete journal record checksum mismatch".to_owned(),
            ));
        }
        latest = Some(StoredRecord {
            generation: parsed.generation,
            snapshot: body.to_vec(),
        });
        cursor = body_end + 1;
    }

    if cursor < bytes.len() {
        file.set_len(cursor as u64)?;
        file.sync_data()?;
    }
    Ok(Candidate {
        record: latest,
        existed: true,
    })
}

struct ParsedHeader {
    generation: u64,
    length: usize,
    checksum: u64,
}

fn parse_header(header: &str, legacy_generation: u64) -> Result<ParsedHeader, StoreError> {
    let mut parts = header.split_whitespace();
    let magic = parts
        .next()
        .ok_or_else(|| StoreError::Corrupt("journal magic is missing".to_owned()))?;
    let generation = match magic {
        "D2CRAWL2" => parse_decimal(parts.next(), "generation")?,
        "D2CRAWL1" => legacy_generation
            .checked_add(1)
            .ok_or_else(|| StoreError::Corrupt("journal generation overflow".to_owned()))?,
        _ => return Err(StoreError::Corrupt("unknown journal record".to_owned())),
    };
    if generation == 0 {
        return Err(StoreError::Corrupt(
            "journal generation must be positive".to_owned(),
        ));
    }
    let length = parse_decimal(parts.next(), "length")?;
    let checksum = u64::from_str_radix(
        parts
            .next()
            .ok_or_else(|| StoreError::Corrupt("journal checksum is missing".to_owned()))?,
        16,
    )
    .map_err(|_| StoreError::Corrupt("journal checksum is invalid".to_owned()))?;
    if parts.next().is_some() {
        return Err(StoreError::Corrupt(
            "journal header has unexpected fields".to_owned(),
        ));
    }
    Ok(ParsedHeader {
        generation,
        length,
        checksum,
    })
}

fn parse_decimal<T>(value: Option<&str>, name: &str) -> Result<T, StoreError>
where
    T: std::str::FromStr,
{
    value
        .ok_or_else(|| StoreError::Corrupt(format!("journal {name} is missing")))?
        .parse()
        .map_err(|_| StoreError::Corrupt(format!("journal {name} is invalid")))
}

fn write_record(
    path: &Path,
    generation: u64,
    snapshot: &[u8],
    create_new: bool,
) -> Result<(), StoreError> {
    let entry_created = if create_new {
        true
    } else {
        match fs::metadata(path) {
            Ok(_) => false,
            Err(error) if error.kind() == io::ErrorKind::NotFound => true,
            Err(error) => return Err(error.into()),
        }
    };
    let mut options = OpenOptions::new();
    options.write(true);
    if create_new {
        options.create_new(true);
    } else {
        options.create(true).truncate(true);
    }
    let mut file = options.open(path)?;
    let header = format!(
        "D2CRAWL2 {generation} {} {:016x}\n",
        snapshot.len(),
        checksum(snapshot)
    );
    file.write_all(header.as_bytes())?;
    file.write_all(snapshot)?;
    file.write_all(b"\n")?;
    if entry_created {
        file.sync_all()?;
        sync_parent_directory(path)?;
    } else {
        file.sync_data()?;
    }
    Ok(())
}

fn sync_parent_directory(path: &Path) -> Result<(), StoreError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;

        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        let directory = OpenOptions::new()
            .write(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(parent)?;
        match directory.sync_all() {
            Ok(()) => Ok(()),
            // Some Windows filesystems accept a directory handle but do not
            // implement FlushFileBuffers for it. The newly created file was
            // already sync_all'ed; this is the only best-effort fallback.
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::InvalidInput | io::ErrorKind::Unsupported
                ) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    #[cfg(not(windows))]
    {
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    }
}

fn validate_snapshot_size(snapshot: &[u8]) -> Result<(), StoreError> {
    if snapshot.is_empty() {
        return Err(StoreError::Corrupt(
            "refusing to persist an empty snapshot".to_owned(),
        ));
    }
    if snapshot.len() > MAX_SNAPSHOT_BYTES {
        return Err(StoreError::Corrupt(format!(
            "snapshot exceeds {MAX_SNAPSHOT_BYTES} bytes"
        )));
    }
    Ok(())
}

fn checksum(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[derive(Debug)]
pub enum StoreError {
    Io(io::Error),
    Corrupt(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "crawl store I/O error: {error}"),
            Self::Corrupt(message) => write!(formatter, "corrupt crawl store: {message}"),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Corrupt(_) => None,
        }
    }
}

impl From<io::Error> for StoreError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[cfg(test)]
mod tests {
    use super::{CrawlStore, FileStore, StoreError};
    use std::fs::{self, OpenOptions};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn path(name: &str) -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "dig2browser-crawler-{name}-{}-{unique}.journal",
            std::process::id()
        ))
    }

    fn cleanup(path: &std::path::Path) {
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(format!("{}.slot0", path.display()));
        let _ = fs::remove_file(format!("{}.slot1", path.display()));
    }

    #[test]
    fn file_store_ignores_a_torn_trailing_record() {
        let path = path("torn");
        let mut store = FileStore::new(&path);
        store.save(br#"{"revision":1}"#).unwrap();
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"D2CRAWL2 2 100 deadbeef\npartial").unwrap();
        file.sync_data().unwrap();

        assert_eq!(store.load().unwrap(), Some(br#"{"revision":1}"#.to_vec()));
        cleanup(&path);
    }

    #[test]
    fn complete_record_checksum_corruption_is_a_hard_failure() {
        let path = path("checksum");
        let mut store = FileStore::new(&path);
        store.save(br#"{"revision":1}"#).unwrap();
        let mut file = OpenOptions::new().read(true).write(true).open(&path).unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        let body = bytes.iter().position(|byte| *byte == b'\n').unwrap() + 1;
        bytes[body] ^= 1;
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(&bytes).unwrap();
        file.sync_data().unwrap();

        assert!(matches!(store.load(), Err(StoreError::Corrupt(_))));
        cleanup(&path);
    }

    #[test]
    fn file_store_rotates_bounded_snapshots_and_keeps_latest() {
        let path = path("rotate");
        let mut store = FileStore::new(&path);
        for revision in 1..=100u32 {
            store.save(&revision.to_le_bytes()).unwrap();
        }

        assert_eq!(store.load().unwrap(), Some(100u32.to_le_bytes().to_vec()));
        for candidate in [
            path.clone(),
            std::path::PathBuf::from(format!("{}.slot0", path.display())),
            std::path::PathBuf::from(format!("{}.slot1", path.display())),
        ] {
            assert!(fs::metadata(candidate).unwrap().len() < 128);
        }
        cleanup(&path);
    }
}
