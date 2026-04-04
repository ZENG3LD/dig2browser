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
    /// Restart Chrome after this many page navigations to reclaim leaked memory.
    /// Set to `0` to disable automatic restarts.
    pub restart_after_pages: u32,
    /// GeckoDriver URL. Only used when `browser_pref = Firefox`.
    /// Default: `"http://localhost:4444"`.
    pub geckodriver_url: String,
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
            restart_after_pages: 500,
            geckodriver_url: "http://localhost:4444".into(),
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
    ///
    /// `locale` is an optional BCP-47 tag (e.g. `"ru-RU"` or `"en-US"`) used to
    /// set `--lang` / `--accept-lang` so that HTTP `Accept-Language` headers
    /// match the JS `navigator.languages` override.
    pub fn build_args(&self, profile_dir: &Path, port: u16, locale: Option<&str>) -> Vec<String> {
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
        // Do NOT use --disable-gpu: it exposes headless mode via WebGPU/WebGL absence.
        // Use ANGLE (hardware-accelerated via D3D11) — same as real Chrome on Windows.
        // SwiftShader is too slow for heavy WebGL SPAs like 2GIS maps.
        args.push("--use-angle=d3d11".into());
        args.push("--no-sandbox".into());
        args.push("--disable-dev-shm-usage".into());
        // Cap the on-disk cache to 100 MB so long-running daemons don't accumulate GBs.
        args.push("--disk-cache-size=104857600".into());
        // Override the default User-Agent which contains "HeadlessChrome" —
        // many sites reject it at the HTTP level before any JS runs.
        args.push("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".into());

        // Locale flags ensure HTTP Accept-Language matches navigator.languages.
        let effective_locale = locale.unwrap_or("en-US");
        let lang_base = effective_locale.split('-').next().unwrap_or("en");
        args.push(format!("--lang={}", effective_locale));
        args.push(format!(
            "--accept-lang={},{};q=0.9,en;q=0.7",
            effective_locale, lang_base
        ));

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
