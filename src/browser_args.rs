use std::path::{Path, PathBuf};
use crate::browser_detect::BrowserPreference;
use crate::error::BrowserError;

#[derive(Debug, Clone)]
pub enum BrowserProfile {
    /// Fresh temp dir, deleted on drop.
    Ephemeral,
    /// Persistent directory — survives restarts (for reusing login sessions).
    Persistent(PathBuf),
}

#[derive(Debug, Clone)]
pub struct LaunchConfig {
    pub headless: bool,
    pub window_size: (u32, u32),
    pub profile: BrowserProfile,
    pub debug_port: Option<u16>,
    pub extra_args: Vec<String>,
    pub browser_pref: BrowserPreference,
}

impl Default for LaunchConfig {
    fn default() -> Self {
        Self {
            headless: true,
            window_size: (1920, 1080),
            profile: BrowserProfile::Ephemeral,
            debug_port: None,
            extra_args: Vec::new(),
            browser_pref: BrowserPreference::Auto,
        }
    }
}

impl BrowserProfile {
    /// Resolve profile to a concrete directory path + whether it's ephemeral.
    pub fn resolve(&self) -> Result<(PathBuf, bool), BrowserError> {
        match self {
            BrowserProfile::Ephemeral => {
                let dir = std::env::temp_dir()
                    .join(format!("dig2browser-{}", uuid::Uuid::new_v4()));
                std::fs::create_dir_all(&dir)?;
                Ok((dir, true))
            }
            BrowserProfile::Persistent(path) => {
                std::fs::create_dir_all(path)?;
                Ok((path.clone(), false))
            }
        }
    }
}

impl LaunchConfig {
    /// Build Chrome/Edge CLI arguments.
    pub fn build_args(&self, profile_dir: &Path, port: u16) -> Vec<String> {
        let mut args = Vec::new();

        if self.headless {
            args.push("--headless=new".into());
        }

        // Anti-detection flags
        args.push("--disable-blink-features=AutomationControlled".into());
        args.push("--disable-infobars".into());
        args.push("--disable-extensions".into());
        args.push("--disable-background-networking".into());
        args.push("--no-first-run".into());
        args.push("--disable-sync".into());
        args.push("--disable-default-apps".into());
        args.push("--disable-gpu".into());
        args.push("--no-sandbox".into());
        args.push("--disable-dev-shm-usage".into());
        args.push("--metrics-recording-only".into());

        args.push(format!("--window-size={},{}", self.window_size.0, self.window_size.1));
        args.push(format!("--remote-debugging-port={}", port));
        args.push(format!("--user-data-dir={}", profile_dir.display()));

        args.extend(self.extra_args.iter().cloned());

        args
    }

    /// Find a free TCP port for remote debugging.
    pub fn find_free_port() -> u16 {
        // Try to bind port 0 — OS assigns a free port
        std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|listener| listener.local_addr())
            .map(|addr| addr.port())
            .unwrap_or(9222) // fallback
    }
}
