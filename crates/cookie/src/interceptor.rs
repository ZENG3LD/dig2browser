//! Cookie interception via visible browser session.

use std::path::PathBuf;

use dig2browser_detect::{BrowserPreference, detect_browser};

use crate::decrypt::derive_aes_key;
use crate::sqlite::read_cookies;
use crate::types::CookieJar;
use crate::CookieError;

/// Configuration for the cookie interception flow.
#[derive(Debug, Clone)]
pub struct InterceptConfig {
    /// URL the browser should open so the user can log in.
    pub start_url: String,
    /// Domain to filter cookies by (e.g. `"rusprofile.ru"`).
    pub domain: String,
    /// Browser preference — Auto, ChromeOnly, or EdgeOnly.
    pub browser_pref: BrowserPreference,
    /// If `Some`, use this persistent profile directory.
    /// If `None`, a fresh temp profile is created and deleted after extraction.
    pub profile_dir: Option<PathBuf>,
    /// How long to wait after the browser closes before reading cookies
    /// (gives Chrome time to flush its SQLite WAL).
    pub flush_wait: std::time::Duration,
}

impl InterceptConfig {
    /// Create a config with sensible defaults.
    pub fn new(start_url: impl Into<String>, domain: impl Into<String>) -> Self {
        Self {
            start_url: start_url.into(),
            domain: domain.into(),
            browser_pref: BrowserPreference::Auto,
            profile_dir: None,
            flush_wait: std::time::Duration::from_millis(2000),
        }
    }
}

/// Open a visible browser for the user to log in, then close.
/// Profile is saved to `profile_dir` — no cookie reading needed.
/// Use this when the headless daemon will reuse the same profile directory.
pub async fn open_auth_session(
    start_url: &str,
    profile_dir: &std::path::Path,
    browser_pref: BrowserPreference,
) -> Result<(), CookieError> {
    let binary = detect_browser(browser_pref).map_err(CookieError::Detect)?;

    std::fs::create_dir_all(profile_dir)?;

    let args: Vec<String> = vec![
        "--no-first-run".into(),
        "--disable-default-apps".into(),
        format!("--user-data-dir={}", profile_dir.display()),
        start_url.to_string(),
    ];

    println!("[dig2browser] Opening browser at: {}", start_url);
    println!("[dig2browser] Log in, pass captchas, then CLOSE the browser window.");
    println!("[dig2browser] Profile: {}", profile_dir.display());

    let binary_path = binary.path.clone();
    tokio::task::spawn_blocking(move || {
        std::process::Command::new(&binary_path)
            .args(&args)
            .status()
    })
    .await
    .map_err(|e| CookieError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))??;

    println!("[dig2browser] Browser closed. Profile saved.");
    Ok(())
}

/// Open a visible browser window at `config.start_url`, wait for the user to
/// log in and close the window, then read and decrypt their cookies.
///
/// Steps:
/// 1. Detect browser binary.
/// 2. Resolve (or create) a profile directory.
/// 3. Launch visible (non-headless) browser.
/// 4. Wait for exit.
/// 5. Sleep `flush_wait` for WAL flush.
/// 6. Derive AES key from `Local State`.
/// 7. Read + decrypt cookies from SQLite.
/// 8. Clean up temp profile if ephemeral.
/// 9. Return `CookieJar`.
pub async fn intercept_cookies(config: &InterceptConfig) -> Result<CookieJar, CookieError> {
    // Step 1: find browser binary.
    let binary = detect_browser(config.browser_pref)
        .map_err(CookieError::Detect)?;

    // Step 2: resolve profile directory.
    let (profile_dir, is_ephemeral) = match &config.profile_dir {
        Some(dir) => {
            std::fs::create_dir_all(dir)?;
            (dir.clone(), false)
        }
        None => {
            let dir = std::env::temp_dir()
                .join(format!("dig2browser-cookie-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&dir)?;
            (dir, true)
        }
    };

    // Step 3: build args for visible (non-headless) browser.
    let args: Vec<String> = vec![
        "--no-first-run".into(),
        "--disable-default-apps".into(),
        format!("--user-data-dir={}", profile_dir.display()),
        config.start_url.clone(),
    ];

    // Step 4: print instructions and launch.
    println!("[dig2browser] Opening browser at: {}", config.start_url);
    println!("[dig2browser] Log in, pass captchas, then CLOSE the browser window.");
    println!("[dig2browser] Profile: {}", profile_dir.display());

    let binary_path = binary.path.clone();
    tokio::task::spawn_blocking(move || {
        std::process::Command::new(&binary_path)
            .args(&args)
            .status()
    })
    .await
    .map_err(|e| CookieError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))??;

    // Step 5: kill lingering browser processes that hold the cookie DB lock.
    // Edge/Chrome spawn background tasks that outlive the main window.
    // We need them dead before we can copy the SQLite file.
    let exe_name = binary.path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("chrome.exe")
        .to_string();
    tracing::debug!("[dig2browser] Killing lingering {} processes", exe_name);
    let _ = std::process::Command::new("taskkill")
        .args(["/IM", &exe_name, "/F"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    // Wait for processes to fully exit and release file locks.
    tokio::time::sleep(config.flush_wait).await;

    // Step 6: derive AES key.
    let key = derive_aes_key(&profile_dir)?;

    // Step 7: read and decrypt cookies.
    let jar = read_cookies(&profile_dir, &config.domain, &key)?;

    // Step 8: clean up ephemeral profile.
    if is_ephemeral {
        let _ = std::fs::remove_dir_all(&profile_dir);
    }

    // Step 9: guard against empty result.
    if jar.is_empty() {
        return Err(CookieError::NoCookies {
            domain: config.domain.clone(),
        });
    }

    Ok(jar)
}
