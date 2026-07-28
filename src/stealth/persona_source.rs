//! Where a browsing identity comes from — the three persona modes.
//!
//! A "persona" is the identity a page sees: User-Agent + Client Hints,
//! locale/timezone, viewport + device scale, declared hardware. This module
//! answers the question *who supplies it*, which is a separate axis from
//! *what it contains* ([`StealthConfig`]):
//!
//! | Mode | Variant | Identity source |
//! |---|---|---|
//! | 1 | [`PersonaSource::Random`] | generated per run from coherent pools (optionally seeded → reproducible) |
//! | 2 | [`PersonaSource::Catalog`] | a curated record read from a JSON file or a SQLite table |
//! | 3 | [`PersonaSource::User`] **(default)** | the browser's OWN identity — its real UA, timezone and window-driven viewport, used as-is |
//!
//! Mode 3 is the default because the common case — driving a browser this
//! process did not launch (`dev-attach` on a developer's own window) — must
//! observe, never repaint. Overriding device metrics there pins the page's
//! viewport and it stops following the real window (live incident
//! 2026-07-29). Modes 1 and 2 are for flows that OWN the target browser's
//! identity (crawler workers) and must be requested explicitly.
//!
//! Coherence rule for mode 1: fields are never rolled independently — a
//! record is drawn as a whole (UA ↔ platform ↔ client hints ↔ viewport ↔
//! locale/timezone stay consistent), because an incoherent combination is
//! more detectable than no persona at all.

use std::path::{Path, PathBuf};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};

use super::config::{ClientHintsProfile, LocaleProfile, StealthConfig};

/// One concrete identity record — the wire/JSON/SQL shape shared by the
/// catalog (mode 2) and the generator (mode 1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PersonaRecord {
    /// Stable identifier — the key `--persona catalog:<path>#<id>` selects.
    pub id: String,
    pub user_agent: String,
    /// `[width, height]` in CSS pixels.
    pub viewport: [u32; 2],
    #[serde(default = "default_dsf")]
    pub device_scale_factor: f64,
    /// BCP-47 locale, e.g. `"ru-RU"`.
    pub locale: String,
    /// IANA timezone, e.g. `"Europe/Moscow"`. `None` leaves the host's.
    #[serde(default)]
    pub timezone: Option<String>,
    /// `Sec-CH-UA-Platform`, e.g. `"Windows"`, `"macOS"`.
    pub platform: String,
    #[serde(default = "default_platform_version")]
    pub platform_version: String,
    #[serde(default = "default_architecture")]
    pub architecture: String,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub mobile: bool,
    #[serde(default = "default_cores")]
    pub hardware_concurrency: u32,
    #[serde(default = "default_memory")]
    pub device_memory_gb: u32,
}

fn default_dsf() -> f64 { 1.0 }
fn default_platform_version() -> String { "15.0.0".to_owned() }
fn default_architecture() -> String { "x86".to_owned() }
fn default_cores() -> u32 { 8 }
fn default_memory() -> u32 { 8 }

impl PersonaRecord {
    /// Materialize this record into a full stealth configuration.
    pub fn to_stealth_config(&self) -> StealthConfig {
        let base = StealthConfig::default();
        StealthConfig {
            transparent: false,
            locale: LocaleProfile {
                locale: self.locale.clone(),
                timezone: self.timezone.clone(),
            },
            viewport: (self.viewport[0], self.viewport[1]),
            device_scale_factor: super::config::DeviceScaleFactor::new(self.device_scale_factor)
                .unwrap_or_default(),
            hardware_concurrency: self.hardware_concurrency,
            device_memory_gb: self.device_memory_gb,
            max_touch_points: if self.mobile { 5 } else { 0 },
            user_agent: self.user_agent.clone(),
            client_hints: ClientHintsProfile::custom(
                &self.platform,
                &self.platform_version,
                &self.architecture,
                &self.model,
                self.mobile,
            ),
            ..base
        }
    }
}

/// The catalog file kind, picked from the path extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogKind {
    /// `.json` — `{"version":1,"personas":[PersonaRecord, …]}` or a bare array.
    Json,
    /// `.sqlite` / `.db` — table `personas` with one column per
    /// [`PersonaRecord`] field.
    Sqlite,
}

/// Which of the three modes supplies the identity. Default: [`Self::User`].
#[derive(Debug, Clone, PartialEq)]
pub enum PersonaSource {
    /// **Mode 3 (default)** — the browser's own identity, used as-is. No
    /// UA / timezone / device-metrics overrides are applied at all, so the
    /// page keeps following the real window.
    User,
    /// **Mode 1** — a coherent persona generated at resolve time. `seed`
    /// makes the draw reproducible; `None` draws from entropy.
    Random { seed: Option<u64> },
    /// **Mode 2** — a curated record from a JSON file or SQLite table.
    /// `id: None` takes the first record.
    Catalog {
        path: PathBuf,
        kind: CatalogKind,
        id: Option<String>,
    },
}

impl Default for PersonaSource {
    fn default() -> Self {
        Self::User
    }
}

impl PersonaSource {
    /// Parse a CLI/config spec:
    ///
    /// - `user` (or empty) → [`Self::User`]
    /// - `random` / `random:<seed>` → [`Self::Random`]
    /// - `catalog:<path>` / `catalog:<path>#<id>` → [`Self::Catalog`]
    pub fn parse(spec: &str) -> Result<Self, PersonaSourceError> {
        let spec = spec.trim();
        if spec.is_empty() || spec.eq_ignore_ascii_case("user") {
            return Ok(Self::User);
        }
        if let Some(rest) = spec.strip_prefix("random") {
            let seed = match rest.strip_prefix(':') {
                Some(s) if !s.is_empty() => Some(
                    s.parse::<u64>()
                        .map_err(|_| PersonaSourceError::Spec(format!("bad random seed '{s}'")))?,
                ),
                _ => None,
            };
            return Ok(Self::Random { seed });
        }
        if let Some(rest) = spec.strip_prefix("catalog:") {
            let (path_str, id) = match rest.split_once('#') {
                Some((p, i)) => (p, Some(i.to_owned())),
                None => (rest, None),
            };
            let path = PathBuf::from(path_str);
            let kind = Self::kind_for(&path)?;
            return Ok(Self::Catalog { path, kind, id });
        }
        Err(PersonaSourceError::Spec(format!(
            "unknown persona spec '{spec}' (expected: user | random[:seed] | catalog:<path>[#id])"
        )))
    }

    fn kind_for(path: &Path) -> Result<CatalogKind, PersonaSourceError> {
        match path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase())
            .as_deref()
        {
            Some("json") => Ok(CatalogKind::Json),
            Some("sqlite") | Some("sqlite3") | Some("db") => Ok(CatalogKind::Sqlite),
            other => Err(PersonaSourceError::Spec(format!(
                "catalog path must end in .json or .sqlite/.db (got {other:?})"
            ))),
        }
    }

    /// Resolve the identity to apply.
    ///
    /// `Ok(None)` means mode 3 — apply nothing, the browser keeps its own
    /// identity. `Ok(Some(cfg))` is the persona to push over CDP.
    pub fn resolve(&self) -> Result<Option<StealthConfig>, PersonaSourceError> {
        match self {
            Self::User => Ok(None),
            Self::Random { seed } => Ok(Some(generate_random(*seed).to_stealth_config())),
            Self::Catalog { path, kind, id } => {
                let record = match kind {
                    CatalogKind::Json => load_json(path, id.as_deref())?,
                    CatalogKind::Sqlite => load_sqlite(path, id.as_deref())?,
                };
                Ok(Some(record.to_stealth_config()))
            }
        }
    }

    /// Human-readable mode name for logs.
    pub fn mode_name(&self) -> &'static str {
        match self {
            Self::User => "user (browser's own identity)",
            Self::Random { .. } => "random (generated)",
            Self::Catalog { .. } => "catalog",
        }
    }
}

// ── Mode 1: generation ────────────────────────────────────────────────────

/// Coherent desktop pools. Each tuple is drawn as a WHOLE so UA, platform
/// and client hints never contradict each other.
const UA_POOL: &[(&str, &str, &str, &str)] = &[
    // (user_agent, platform, platform_version, architecture)
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "Windows", "15.0.0", "x86",
    ),
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
        "Windows", "14.0.0", "x86",
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "macOS", "14.6.0", "arm",
    ),
    (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "Linux", "6.8.0", "x86",
    ),
];

/// Common desktop viewports (CSS px) — real-world browser window sizes.
const VIEWPORT_POOL: &[[u32; 2]] = &[
    [1920, 1080],
    [1680, 1050],
    [1600, 900],
    [1536, 864],
    [1440, 900],
    [1366, 768],
];

/// Locale ↔ timezone pairs (never mixed across entries).
const LOCALE_POOL: &[(&str, &str)] = &[
    ("en-US", "America/New_York"),
    ("en-GB", "Europe/London"),
    ("de-DE", "Europe/Berlin"),
    ("ru-RU", "Europe/Moscow"),
    ("fr-FR", "Europe/Paris"),
];

const CORES_POOL: &[u32] = &[4, 8, 12, 16];
const MEMORY_POOL: &[u32] = &[4, 8, 16];

/// Draw a coherent random persona. With `seed` the draw is reproducible.
pub fn generate_random(seed: Option<u64>) -> PersonaRecord {
    let mut rng = match seed {
        Some(s) => StdRng::seed_from_u64(s),
        None => StdRng::from_entropy(),
    };
    let (ua, platform, platform_version, architecture) = UA_POOL[rng.gen_range(0..UA_POOL.len())];
    let viewport = VIEWPORT_POOL[rng.gen_range(0..VIEWPORT_POOL.len())];
    let (locale, timezone) = LOCALE_POOL[rng.gen_range(0..LOCALE_POOL.len())];
    let cores = CORES_POOL[rng.gen_range(0..CORES_POOL.len())];
    let memory = MEMORY_POOL[rng.gen_range(0..MEMORY_POOL.len())];
    let tag: u32 = rng.gen();

    PersonaRecord {
        id: format!("random-{tag:08x}"),
        user_agent: ua.to_owned(),
        viewport,
        device_scale_factor: 1.0,
        locale: locale.to_owned(),
        timezone: Some(timezone.to_owned()),
        platform: platform.to_owned(),
        platform_version: platform_version.to_owned(),
        architecture: architecture.to_owned(),
        model: String::new(),
        mobile: false,
        hardware_concurrency: cores,
        device_memory_gb: memory,
    }
}

// ── Mode 2: catalog ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum CatalogFile {
    Wrapped {
        #[allow(dead_code)]
        version: u32,
        personas: Vec<PersonaRecord>,
    },
    Bare(Vec<PersonaRecord>),
}

fn load_json(path: &Path, id: Option<&str>) -> Result<PersonaRecord, PersonaSourceError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| PersonaSourceError::Io(format!("{}: {e}", path.display())))?;
    let file: CatalogFile = serde_json::from_str(&text)
        .map_err(|e| PersonaSourceError::Parse(format!("{}: {e}", path.display())))?;
    let personas = match file {
        CatalogFile::Wrapped { personas, .. } => personas,
        CatalogFile::Bare(v) => v,
    };
    pick(personas, id, path)
}

fn load_sqlite(path: &Path, id: Option<&str>) -> Result<PersonaRecord, PersonaSourceError> {
    let conn = rusqlite::Connection::open(path)
        .map_err(|e| PersonaSourceError::Io(format!("{}: {e}", path.display())))?;
    let sql = "SELECT id, user_agent, viewport_w, viewport_h, device_scale_factor, locale, \
               timezone, platform, platform_version, architecture, model, mobile, \
               hardware_concurrency, device_memory_gb FROM personas";
    let mut stmt = conn
        .prepare(sql)
        .map_err(|e| PersonaSourceError::Parse(format!("{}: {e}", path.display())))?;
    let rows = stmt
        .query_map([], |row| {
            Ok(PersonaRecord {
                id: row.get(0)?,
                user_agent: row.get(1)?,
                viewport: [row.get(2)?, row.get(3)?],
                device_scale_factor: row.get::<_, Option<f64>>(4)?.unwrap_or(1.0),
                locale: row.get(5)?,
                timezone: row.get(6)?,
                platform: row.get(7)?,
                platform_version: row
                    .get::<_, Option<String>>(8)?
                    .unwrap_or_else(default_platform_version),
                architecture: row
                    .get::<_, Option<String>>(9)?
                    .unwrap_or_else(default_architecture),
                model: row.get::<_, Option<String>>(10)?.unwrap_or_default(),
                mobile: row.get::<_, Option<bool>>(11)?.unwrap_or(false),
                hardware_concurrency: row.get::<_, Option<u32>>(12)?.unwrap_or_else(default_cores),
                device_memory_gb: row.get::<_, Option<u32>>(13)?.unwrap_or_else(default_memory),
            })
        })
        .map_err(|e| PersonaSourceError::Parse(format!("{}: {e}", path.display())))?;
    let personas = rows
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| PersonaSourceError::Parse(format!("{}: {e}", path.display())))?;
    pick(personas, id, path)
}

fn pick(
    personas: Vec<PersonaRecord>,
    id: Option<&str>,
    path: &Path,
) -> Result<PersonaRecord, PersonaSourceError> {
    match id {
        Some(want) => personas
            .into_iter()
            .find(|p| p.id == want)
            .ok_or_else(|| PersonaSourceError::NotFound(format!("{want} in {}", path.display()))),
        None => personas
            .into_iter()
            .next()
            .ok_or_else(|| PersonaSourceError::NotFound(format!("no personas in {}", path.display()))),
    }
}

// ── Errors ────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum PersonaSourceError {
    Spec(String),
    Io(String),
    Parse(String),
    NotFound(String),
}

impl std::fmt::Display for PersonaSourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Spec(m) => write!(f, "persona spec: {m}"),
            Self::Io(m) => write!(f, "persona catalog io: {m}"),
            Self::Parse(m) => write!(f, "persona catalog parse: {m}"),
            Self::NotFound(m) => write!(f, "persona not found: {m}"),
        }
    }
}

impl std::error::Error for PersonaSourceError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_mode_is_user_and_applies_nothing() {
        let src = PersonaSource::default();
        assert_eq!(src, PersonaSource::User);
        assert!(src.resolve().unwrap().is_none(), "user mode must apply no overrides");
    }

    #[test]
    fn parses_the_three_modes() {
        assert_eq!(PersonaSource::parse("").unwrap(), PersonaSource::User);
        assert_eq!(PersonaSource::parse("user").unwrap(), PersonaSource::User);
        assert_eq!(
            PersonaSource::parse("random").unwrap(),
            PersonaSource::Random { seed: None }
        );
        assert_eq!(
            PersonaSource::parse("random:42").unwrap(),
            PersonaSource::Random { seed: Some(42) }
        );
        match PersonaSource::parse("catalog:/tmp/p.json#alpha").unwrap() {
            PersonaSource::Catalog { path, kind, id } => {
                assert_eq!(kind, CatalogKind::Json);
                assert_eq!(id.as_deref(), Some("alpha"));
                assert!(path.ends_with("p.json"));
            }
            other => panic!("expected catalog, got {other:?}"),
        }
        assert!(PersonaSource::parse("nonsense").is_err());
    }

    #[test]
    fn seeded_random_is_reproducible_and_coherent() {
        let a = generate_random(Some(7));
        let b = generate_random(Some(7));
        assert_eq!(a, b, "same seed must draw the same persona");

        // Coherence: a macOS UA never carries a Windows platform hint.
        for seed in 0..64u64 {
            let p = generate_random(Some(seed));
            let ua_mac = p.user_agent.contains("Mac OS X");
            let ua_win = p.user_agent.contains("Windows NT");
            if ua_mac {
                assert_eq!(p.platform, "macOS", "seed {seed}");
            }
            if ua_win {
                assert_eq!(p.platform, "Windows", "seed {seed}");
            }
            assert!(p.viewport[0] >= 1366 && p.viewport[1] >= 768, "seed {seed}");
        }
    }

    #[test]
    fn json_catalog_roundtrip() {
        let dir = std::env::temp_dir().join("d2b-persona-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("catalog.json");
        let json = r#"{"version":1,"personas":[
            {"id":"alpha","user_agent":"UA-A","viewport":[1280,800],"locale":"en-US","platform":"Windows"},
            {"id":"beta","user_agent":"UA-B","viewport":[1920,1080],"locale":"ru-RU","timezone":"Europe/Moscow","platform":"Linux"}
        ]}"#;
        std::fs::write(&path, json).unwrap();

        let src = PersonaSource::parse(&format!("catalog:{}#beta", path.display())).unwrap();
        let cfg = src.resolve().unwrap().expect("catalog persona applies overrides");
        assert_eq!(cfg.user_agent, "UA-B");
        assert_eq!(cfg.viewport, (1920, 1080));
        assert_eq!(cfg.locale.timezone.as_deref(), Some("Europe/Moscow"));
        assert!(!cfg.transparent);

        let first = PersonaSource::parse(&format!("catalog:{}", path.display()))
            .unwrap()
            .resolve()
            .unwrap()
            .unwrap();
        assert_eq!(first.user_agent, "UA-A");
    }
}
