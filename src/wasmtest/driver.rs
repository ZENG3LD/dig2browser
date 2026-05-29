//! WebDriver subprocess management (chromedriver / geckodriver / msedgedriver).

use std::path::Path;
use std::process::Stdio;

use serde_json::json;
use tokio::process::Child;

use crate::detect::BrowserKind;
use crate::webdriver::Capabilities;

use super::WasmTestError;

/// Which WebDriver binary variant to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverKind {
    Chromedriver,
    Geckodriver,
    Msedgedriver,
}

impl DriverKind {
    /// Map a detected browser kind to the appropriate driver variant.
    pub fn for_browser(kind: BrowserKind) -> Self {
        match kind {
            BrowserKind::Chrome | BrowserKind::Chromium => DriverKind::Chromedriver,
            BrowserKind::Edge => DriverKind::Msedgedriver,
            BrowserKind::Firefox => DriverKind::Geckodriver,
        }
    }
}

/// A spawned WebDriver process with its listen port.
pub struct SpawnedDriver {
    /// Port the driver is listening on.
    pub port: u16,
    /// The child process — kept alive while this struct is in scope.
    /// `kill_on_drop(true)` ensures the driver dies when dropped.
    child: Child,
}

impl SpawnedDriver {
    /// Base URL for this driver instance.
    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// Attempt to kill the driver process immediately.
    ///
    /// The process will also be killed when `SpawnedDriver` is dropped
    /// (via `kill_on_drop(true)`), so calling this is optional.
    pub fn kill(&mut self) {
        let _ = self.child.start_kill();
    }
}

/// Pick a free ephemeral port by binding `:0` and immediately releasing it.
fn pick_free_port() -> Result<u16, WasmTestError> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
    // listener dropped here
}

/// Spawn a WebDriver subprocess and wait until it is ready.
///
/// `driver_path` — path to the driver binary on disk.
/// `kind` — which driver variant (used to select the correct ready-signal).
///
/// The bind-and-drop port-pick has an inherent TOCTOU race: after a quick
/// `taskkill` the old driver's port may sit in `TIME_WAIT` and the new driver
/// fails to bind.  To handle back-to-back runs robustly the spawn + ready-wait
/// is retried up to **3 times**, picking a fresh port each attempt.  Only the
/// error from the last attempt is returned.
pub async fn spawn(
    driver_path: &Path,
    _kind: DriverKind,
) -> Result<SpawnedDriver, WasmTestError> {
    const MAX_SPAWN_RETRIES: u32 = 3;
    let mut last_err = WasmTestError::Driver("spawn not attempted".into());

    for attempt in 0..MAX_SPAWN_RETRIES {
        if attempt > 0 {
            // Brief back-off before retry — lets TIME_WAIT sockets expire.
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }

        let port = match pick_free_port() {
            Ok(p) => p,
            Err(e) => {
                last_err = e;
                continue;
            }
        };

        let mut cmd = tokio::process::Command::new(driver_path);
        cmd.arg(format!("--port={port}"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);

        #[cfg(windows)]
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW

        let child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                last_err = WasmTestError::Driver(format!(
                    "failed to spawn {}: {e}",
                    driver_path.display()
                ));
                continue;
            }
        };

        match wait_ready(child, port).await {
            Ok(driver) => return Ok(driver),
            Err(e) => {
                last_err = e;
                // Retry with a fresh port.
            }
        }
    }

    Err(last_err)
}

/// Poll the driver's `/status` endpoint until it reports ready or 10s elapses.
async fn wait_ready(mut child: Child, port: u16) -> Result<SpawnedDriver, WasmTestError> {
    let status_url = format!("http://127.0.0.1:{port}/status");
    let client = reqwest::Client::new();

    const MAX_ATTEMPTS: u32 = 100;
    const POLL_MS: u64 = 100;

    for _ in 0..MAX_ATTEMPTS {
        // Check whether the child already exited (crash during startup).
        match child.try_wait() {
            Ok(Some(_)) => {
                return Err(WasmTestError::Driver(
                    "driver process exited during startup".into(),
                ));
            }
            Ok(None) => {} // still running
            Err(e) => {
                return Err(WasmTestError::Driver(format!(
                    "failed to poll driver process: {e}"
                )));
            }
        }

        if let Ok(resp) = client.get(&status_url).send().await {
            if resp.status().is_success() {
                // Try to parse W3C /status body: {"value":{"ready":true,...}}
                // If parse fails or `ready` is missing, treat as ready (geckodriver compat).
                let ready = match resp.json::<serde_json::Value>().await {
                    Ok(body) => body
                        .get("value")
                        .and_then(|v| v.get("ready"))
                        .and_then(|r| r.as_bool())
                        .unwrap_or(true), // missing key → assume ready
                    Err(_) => true, // parse error → assume ready
                };

                if ready {
                    return Ok(SpawnedDriver { port, child });
                }
            }
        }

        tokio::time::sleep(std::time::Duration::from_millis(POLL_MS)).await;
    }

    // Timeout — kill the driver and return an error.
    let _ = child.start_kill();
    Err(WasmTestError::Driver(
        "driver did not become ready within 10s".into(),
    ))
}

/// Build W3C capabilities for a wasm test run.
///
/// `kind` — driver variant (selects capability namespace).
/// `browser_binary` — path to the browser executable.
/// `headless` — when `true` (default), adds the headless flag(s) appropriate
///   for the browser.  When `false` (env `DIG2_WASM_HEADLESS=0`), the browser
///   opens a visible window — useful for debugging a hung test.
/// `profile_dir` — unique temporary directory for the browser profile.
///   Chrome and Edge each hold a lock on their user-data-dir; passing a unique
///   per-run path prevents back-to-back or overlapping runs from colliding on
///   the default profile.  For Firefox, geckodriver manages its own temp
///   profile internally so this parameter is ignored.
pub fn headless_caps(
    kind: DriverKind,
    browser_binary: &Path,
    headless: bool,
    profile_dir: &Path,
) -> Capabilities {
    let binary_str = browser_binary.to_string_lossy();

    match kind {
        DriverKind::Chromedriver => {
            let mut caps = Capabilities::chrome();
            if let Some(am) = caps.always_match.as_mut() {
                am["goog:chromeOptions"]["binary"] = json!(binary_str);
                let mut args = vec![
                    format!("--user-data-dir={}", profile_dir.display()),
                    "--disable-gpu".to_string(),
                    "--no-sandbox".to_string(),
                    "--disable-dev-shm-usage".to_string(),
                ];
                if headless {
                    args.insert(0, "--headless=new".to_string());
                }
                am["goog:chromeOptions"]["args"] = json!(args);
            }
            caps
        }
        DriverKind::Msedgedriver => {
            let mut caps = Capabilities::edge();
            if let Some(am) = caps.always_match.as_mut() {
                am["ms:edgeOptions"]["binary"] = json!(binary_str);
                let mut args = vec![
                    format!("--user-data-dir={}", profile_dir.display()),
                    "--disable-gpu".to_string(),
                    "--no-sandbox".to_string(),
                    "--disable-dev-shm-usage".to_string(),
                ];
                if headless {
                    args.insert(0, "--headless=new".to_string());
                }
                am["ms:edgeOptions"]["args"] = json!(args);
            }
            caps
        }
        DriverKind::Geckodriver => {
            // geckodriver creates and cleans up its own temporary profile;
            // no --user-data-dir equivalent is needed here.
            let mut caps = Capabilities::firefox();
            if let Some(am) = caps.always_match.as_mut() {
                am["moz:firefoxOptions"]["binary"] = json!(binary_str);
                let args: Vec<&str> = if headless { vec!["-headless"] } else { vec![] };
                am["moz:firefoxOptions"]["args"] = json!(args);
            }
            caps
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn for_browser_mapping() {
        assert_eq!(
            DriverKind::for_browser(BrowserKind::Chrome),
            DriverKind::Chromedriver
        );
        assert_eq!(
            DriverKind::for_browser(BrowserKind::Chromium),
            DriverKind::Chromedriver
        );
        assert_eq!(
            DriverKind::for_browser(BrowserKind::Edge),
            DriverKind::Msedgedriver
        );
        assert_eq!(
            DriverKind::for_browser(BrowserKind::Firefox),
            DriverKind::Geckodriver
        );
    }

    #[test]
    fn headless_caps_chrome_has_correct_keys() {
        let profile = Path::new("/tmp/dig2wasm-profile-test");
        let caps = headless_caps(
            DriverKind::Chromedriver,
            Path::new("/usr/bin/google-chrome"),
            true,
            profile,
        );
        let val = serde_json::to_value(&caps).expect("serialize caps");
        let opts = &val["alwaysMatch"]["goog:chromeOptions"];
        assert_eq!(opts["binary"], "/usr/bin/google-chrome");
        let args = opts["args"].as_array().expect("args is array");
        let has_headless = args.iter().any(|a| a == "--headless=new");
        assert!(has_headless, "expected --headless=new in chrome args");
        let has_profile = args
            .iter()
            .any(|a| a.as_str().map_or(false, |s| s.starts_with("--user-data-dir=")));
        assert!(has_profile, "expected --user-data-dir in chrome args");
    }

    #[test]
    fn headless_caps_chrome_no_headless_flag_when_false() {
        let profile = Path::new("/tmp/dig2wasm-profile-test");
        let caps = headless_caps(
            DriverKind::Chromedriver,
            Path::new("/usr/bin/google-chrome"),
            false,
            profile,
        );
        let val = serde_json::to_value(&caps).expect("serialize caps");
        let args = val["alwaysMatch"]["goog:chromeOptions"]["args"]
            .as_array()
            .expect("args is array");
        let has_headless = args.iter().any(|a| a == "--headless=new");
        assert!(!has_headless, "should NOT have --headless=new when headless=false");
    }

    #[test]
    fn headless_caps_firefox_has_correct_keys() {
        let profile = Path::new("/tmp/dig2wasm-profile-test");
        let caps = headless_caps(
            DriverKind::Geckodriver,
            Path::new("/usr/bin/firefox"),
            true,
            profile,
        );
        let val = serde_json::to_value(&caps).expect("serialize caps");
        let opts = &val["alwaysMatch"]["moz:firefoxOptions"];
        assert_eq!(opts["binary"], "/usr/bin/firefox");
        let args = opts["args"].as_array().expect("args is array");
        let has_headless = args.iter().any(|a| a == "-headless");
        assert!(has_headless, "expected -headless in firefox args");
    }

    #[test]
    fn headless_caps_firefox_no_headless_flag_when_false() {
        let profile = Path::new("/tmp/dig2wasm-profile-test");
        let caps = headless_caps(
            DriverKind::Geckodriver,
            Path::new("/usr/bin/firefox"),
            false,
            profile,
        );
        let val = serde_json::to_value(&caps).expect("serialize caps");
        let args = val["alwaysMatch"]["moz:firefoxOptions"]["args"]
            .as_array()
            .expect("args is array");
        let has_headless = args.iter().any(|a| a == "-headless");
        assert!(!has_headless, "should NOT have -headless when headless=false");
    }

    #[test]
    fn headless_caps_edge_has_correct_keys() {
        let profile = Path::new(r"C:\Temp\dig2wasm-profile-test");
        let caps = headless_caps(
            DriverKind::Msedgedriver,
            Path::new(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
            true,
            profile,
        );
        let val = serde_json::to_value(&caps).expect("serialize caps");
        let opts = &val["alwaysMatch"]["ms:edgeOptions"];
        assert_eq!(
            opts["binary"],
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"
        );
        let args = opts["args"].as_array().expect("args is array");
        let has_headless = args.iter().any(|a| a == "--headless=new");
        assert!(has_headless, "expected --headless=new in edge args");
        let has_profile = args
            .iter()
            .any(|a| a.as_str().map_or(false, |s| s.starts_with("--user-data-dir=")));
        assert!(has_profile, "expected --user-data-dir in edge args");
    }
}
