//! Automatic WebDriver binary download and caching.

use std::io::{Cursor, Read};
use std::path::PathBuf;

use serde::Deserialize;

use super::DriverKind;
use crate::wasmtest::WasmTestError;

// ── public entry point ──────────────────────────────────────────────────────

/// Ensure the correct WebDriver binary for `kind` is present in the local
/// cache, downloading it if absent.
///
/// `browser_version` — pass the full 4-part browser version string
/// (`"125.0.2535.92"`) for Chromedriver / Msedgedriver so the driver version
/// can be matched.  Pass `None` for Geckodriver (latest is always used).
///
/// Returns the path to the cached binary.
pub async fn ensure_driver(
    kind: DriverKind,
    browser_version: Option<&str>,
) -> Result<PathBuf, WasmTestError> {
    let version_label = browser_version.unwrap_or("latest");
    let cache = cache_dir(kind, version_label)?;

    std::fs::create_dir_all(&cache)?;

    let exe_name = driver_exe_name(kind);
    let cached_exe = cache.join(exe_name);

    if cached_exe.exists() {
        return Ok(cached_exe);
    }

    let url = resolve_download_url(kind, browser_version).await?;
    let bytes = download_bytes(&url).await?;
    extract_exe_from_zip(&bytes, exe_name, &cached_exe)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&cached_exe)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&cached_exe, perms)?;
    }

    Ok(cached_exe)
}

// ── cache layout ─────────────────────────────────────────────────────────────

/// `~/.cache/dig2browser/drivers/<kind>/<version-or-"latest">/`
fn cache_dir(kind: DriverKind, version_label: &str) -> Result<PathBuf, WasmTestError> {
    let home = cache_root()?;
    Ok(home
        .join("dig2browser")
        .join("drivers")
        .join(kind_slug(kind))
        .join(version_label))
}

fn cache_root() -> Result<PathBuf, WasmTestError> {
    // On Windows use %USERPROFILE%\.cache; elsewhere $HOME/.cache
    #[cfg(target_os = "windows")]
    let home_var = "USERPROFILE";
    #[cfg(not(target_os = "windows"))]
    let home_var = "HOME";

    let home = std::env::var(home_var).map_err(|_| {
        WasmTestError::DriverDownload(format!("{} environment variable not set", home_var))
    })?;
    Ok(PathBuf::from(home).join(".cache"))
}

fn kind_slug(kind: DriverKind) -> &'static str {
    match kind {
        DriverKind::Chromedriver => "chromedriver",
        DriverKind::Geckodriver => "geckodriver",
        DriverKind::Msedgedriver => "msedgedriver",
    }
}

/// Platform-correct driver executable filename.
pub fn driver_exe_name(kind: DriverKind) -> &'static str {
    #[cfg(target_os = "windows")]
    match kind {
        DriverKind::Chromedriver => "chromedriver.exe",
        DriverKind::Geckodriver => "geckodriver.exe",
        DriverKind::Msedgedriver => "msedgedriver.exe",
    }
    #[cfg(not(target_os = "windows"))]
    match kind {
        DriverKind::Chromedriver => "chromedriver",
        DriverKind::Geckodriver => "geckodriver",
        DriverKind::Msedgedriver => "msedgedriver",
    }
}

// ── URL resolution ────────────────────────────────────────────────────────────

async fn resolve_download_url(
    kind: DriverKind,
    browser_version: Option<&str>,
) -> Result<String, WasmTestError> {
    match kind {
        DriverKind::Chromedriver => {
            let ver = browser_version.ok_or_else(|| {
                WasmTestError::DriverDownload(
                    "browser_version required for chromedriver".into(),
                )
            })?;
            chromedriver_url(ver).await
        }
        DriverKind::Geckodriver => geckodriver_url().await,
        DriverKind::Msedgedriver => {
            let ver = browser_version.ok_or_else(|| {
                WasmTestError::DriverDownload(
                    "browser_version required for msedgedriver".into(),
                )
            })?;
            Ok(msedgedriver_url(ver))
        }
    }
}

// ── Chromedriver (Chrome-for-Testing JSON) ───────────────────────────────────

/// JSON root of known-good-versions-with-downloads.json
#[derive(Deserialize)]
struct CftRoot {
    versions: Vec<CftVersion>,
}

#[derive(Deserialize)]
struct CftVersion {
    version: String,
    downloads: CftDownloads,
}

#[derive(Deserialize)]
struct CftDownloads {
    chromedriver: Option<Vec<CftAsset>>,
}

#[derive(Deserialize)]
struct CftAsset {
    platform: String,
    url: String,
}

async fn chromedriver_url(browser_version: &str) -> Result<String, WasmTestError> {
    let json_url =
        "https://googlechromelabs.github.io/chrome-for-testing/known-good-versions-with-downloads.json";

    let client = reqwest_client()?;
    let root: CftRoot = client
        .get(json_url)
        .send()
        .await
        .map_err(|e| WasmTestError::DriverDownload(e.to_string()))?
        .json()
        .await
        .map_err(|e| WasmTestError::DriverDownload(e.to_string()))?;

    // Prefer exact match; fall back to matching by major.minor.build prefix
    // and picking the highest patch among those.
    let build_prefix = build_prefix_3(browser_version);

    // Collect all entries that have a win64 chromedriver asset.
    let mut exact: Option<String> = None;
    let mut prefix_candidates: Vec<(String, String)> = Vec::new(); // (version_str, url)

    for v in &root.versions {
        let assets = match &v.downloads.chromedriver {
            Some(a) => a,
            None => continue,
        };
        let url = match assets.iter().find(|a| a.platform == "win64") {
            Some(a) => &a.url,
            None => continue,
        };
        if v.version == browser_version {
            exact = Some(url.clone());
            break;
        }
        if build_prefix_3(&v.version) == build_prefix {
            prefix_candidates.push((v.version.clone(), url.clone()));
        }
    }

    if let Some(url) = exact {
        return Ok(url);
    }

    if prefix_candidates.is_empty() {
        return Err(WasmTestError::DriverDownload(format!(
            "no chromedriver found for browser version {}",
            browser_version
        )));
    }

    // Pick highest patch among prefix matches.
    prefix_candidates.sort_by(|a, b| {
        version_tuple(&a.0).cmp(&version_tuple(&b.0))
    });
    Ok(prefix_candidates.last().unwrap().1.clone())
}

/// First 3 dot-parts of a version string, e.g. `"125.0.2535.92"` → `"125.0.2535"`.
fn build_prefix_3(v: &str) -> &str {
    let mut dot_count = 0;
    for (i, c) in v.char_indices() {
        if c == '.' {
            dot_count += 1;
            if dot_count == 3 {
                return &v[..i];
            }
        }
    }
    v
}

/// Parse up to 4 numeric version parts for comparison.
fn version_tuple(v: &str) -> [u32; 4] {
    let mut parts = v.split('.');
    let a = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let b = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let c = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let d = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    [a, b, c, d]
}

// ── Geckodriver (GitHub releases API) ────────────────────────────────────────

#[derive(Deserialize)]
struct GhRelease {
    assets: Vec<GhAsset>,
}

#[derive(Deserialize)]
struct GhAsset {
    name: String,
    browser_download_url: String,
}

async fn geckodriver_url() -> Result<String, WasmTestError> {
    let api_url = "https://api.github.com/repos/mozilla/geckodriver/releases/latest";

    let client = reqwest_client()?;
    let release: GhRelease = client
        .get(api_url)
        .header("User-Agent", "dig2browser")
        .send()
        .await
        .map_err(|e| WasmTestError::DriverDownload(e.to_string()))?
        .json()
        .await
        .map_err(|e| WasmTestError::DriverDownload(e.to_string()))?;

    release
        .assets
        .iter()
        .find(|a| a.name.ends_with("-win64.zip"))
        .map(|a| a.browser_download_url.clone())
        .ok_or_else(|| {
            WasmTestError::DriverDownload(
                "no geckodriver win64 asset in latest GitHub release".into(),
            )
        })
}

// ── Msedgedriver (microsoft.com) ─────────────────────────────────────────────

fn msedgedriver_url(browser_version: &str) -> String {
    format!(
        "https://msedgedriver.microsoft.com/{}/edgedriver_win64.zip",
        browser_version
    )
}

// ── HTTP helper ───────────────────────────────────────────────────────────────

fn reqwest_client() -> Result<reqwest::Client, WasmTestError> {
    reqwest::Client::builder()
        .build()
        .map_err(|e| WasmTestError::DriverDownload(e.to_string()))
}

async fn download_bytes(url: &str) -> Result<Vec<u8>, WasmTestError> {
    let client = reqwest_client()?;
    let bytes = client
        .get(url)
        .header("User-Agent", "dig2browser")
        .send()
        .await
        .map_err(|e| WasmTestError::DriverDownload(format!("GET {}: {}", url, e)))?
        .bytes()
        .await
        .map_err(|e| WasmTestError::DriverDownload(e.to_string()))?;
    Ok(bytes.to_vec())
}

// ── ZIP extraction ────────────────────────────────────────────────────────────

/// Find the zip entry whose name ends with `exe_name`, extract its bytes to
/// `dest`.
fn extract_exe_from_zip(
    zip_bytes: &[u8],
    exe_name: &str,
    dest: &std::path::Path,
) -> Result<(), WasmTestError> {
    let cursor = Cursor::new(zip_bytes);
    let mut archive = zip::ZipArchive::new(cursor)
        .map_err(|e| WasmTestError::DriverDownload(format!("zip open: {}", e)))?;

    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| WasmTestError::DriverDownload(format!("zip entry {}: {}", i, e)))?;

        // Match entries whose last path component equals the target exe name.
        let entry_name = entry.name().to_owned();
        let last_component = entry_name
            .rsplit('/')
            .next()
            .unwrap_or(&entry_name);

        if last_component == exe_name {
            let mut buf = Vec::with_capacity(entry.size() as usize);
            entry
                .read_to_end(&mut buf)
                .map_err(|e| WasmTestError::DriverDownload(format!("zip read: {}", e)))?;
            std::fs::write(dest, &buf)?;
            return Ok(());
        }
    }

    Err(WasmTestError::DriverDownload(format!(
        "{} not found inside the downloaded zip",
        exe_name
    )))
}
