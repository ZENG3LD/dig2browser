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

/// Spawn a WebDriver subprocess and wait until it is ready.
///
/// `driver_path` — path to the driver binary on disk.
/// `kind` — which driver variant (used to select the correct ready-signal).
pub async fn spawn(
    driver_path: &Path,
    _kind: DriverKind,
) -> Result<SpawnedDriver, WasmTestError> {
    // Pick a free ephemeral port.
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        listener.local_addr()?.port()
        // listener is dropped here, freeing the port for the driver.
    };

    let mut cmd = tokio::process::Command::new(driver_path);
    cmd.arg(format!("--port={port}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);

    #[cfg(windows)]
    cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW

    let child = cmd.spawn().map_err(|e| {
        WasmTestError::Driver(format!(
            "failed to spawn {}: {e}",
            driver_path.display()
        ))
    })?;

    wait_ready(child, port).await
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

/// Build W3C capabilities for a headless wasm test run.
///
/// Sets the browser binary path and the correct headless arguments for
/// the given driver kind.
pub fn headless_caps(kind: DriverKind, browser_binary: &Path) -> Capabilities {
    let binary_str = browser_binary.to_string_lossy();

    match kind {
        DriverKind::Chromedriver => {
            let mut caps = Capabilities::chrome();
            if let Some(am) = caps.always_match.as_mut() {
                am["goog:chromeOptions"]["binary"] = json!(binary_str);
                am["goog:chromeOptions"]["args"] = json!([
                    "--headless=new",
                    "--disable-gpu",
                    "--no-sandbox",
                    "--disable-dev-shm-usage"
                ]);
            }
            caps
        }
        DriverKind::Msedgedriver => {
            let mut caps = Capabilities::edge();
            if let Some(am) = caps.always_match.as_mut() {
                am["ms:edgeOptions"]["binary"] = json!(binary_str);
                am["ms:edgeOptions"]["args"] = json!([
                    "--headless=new",
                    "--disable-gpu",
                    "--no-sandbox",
                    "--disable-dev-shm-usage"
                ]);
            }
            caps
        }
        DriverKind::Geckodriver => {
            let mut caps = Capabilities::firefox();
            if let Some(am) = caps.always_match.as_mut() {
                am["moz:firefoxOptions"]["binary"] = json!(binary_str);
                am["moz:firefoxOptions"]["args"] = json!(["-headless"]);
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
        let caps = headless_caps(
            DriverKind::Chromedriver,
            Path::new("/usr/bin/google-chrome"),
        );
        let val = serde_json::to_value(&caps).expect("serialize caps");
        let opts = &val["alwaysMatch"]["goog:chromeOptions"];
        assert_eq!(opts["binary"], "/usr/bin/google-chrome");
        let args = opts["args"].as_array().expect("args is array");
        let has_headless = args.iter().any(|a| a == "--headless=new");
        assert!(has_headless, "expected --headless=new in chrome args");
    }

    #[test]
    fn headless_caps_firefox_has_correct_keys() {
        let caps = headless_caps(
            DriverKind::Geckodriver,
            Path::new("/usr/bin/firefox"),
        );
        let val = serde_json::to_value(&caps).expect("serialize caps");
        let opts = &val["alwaysMatch"]["moz:firefoxOptions"];
        assert_eq!(opts["binary"], "/usr/bin/firefox");
        let args = opts["args"].as_array().expect("args is array");
        let has_headless = args.iter().any(|a| a == "-headless");
        assert!(has_headless, "expected -headless in firefox args");
    }

    #[test]
    fn headless_caps_edge_has_correct_keys() {
        let caps = headless_caps(
            DriverKind::Msedgedriver,
            Path::new(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
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
    }
}
