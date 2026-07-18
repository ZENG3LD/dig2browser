//! Browser launch argument builder.

use std::path::{Path, PathBuf};

use crate::detect::binary::BrowserPreference;
use crate::detect::DetectError;

/// Renderer sandbox policy for Chromium-family browsers.
///
/// The control plane itself is trusted, but pages are not. Disabling the
/// renderer sandbox is therefore an explicit compatibility choice rather than
/// an automatic launch fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RendererSandboxMode {
    /// Keep the browser's renderer sandbox enabled.
    #[default]
    Enabled,
    /// Launch with `--no-sandbox` for environments where Chromium's sandbox
    /// cannot start. Callers must opt into this mode explicitly.
    CompatibilityDisabled,
}

/// Where to store the browser profile data.
#[derive(Debug, Clone)]
pub enum BrowserProfile {
    /// Fresh temp dir, deleted on drop.
    Ephemeral,
    /// Persistent directory — survives restarts (for reusing login sessions).
    Persistent(PathBuf),
}

/// Configuration for launching a browser process.
#[derive(Debug, Clone)]
pub struct LaunchConfig {
    pub headless: bool,
    pub window_size: (u32, u32),
    pub profile: BrowserProfile,
    pub debug_port: Option<u16>,
    pub extra_args: Vec<String>,
    pub browser_pref: BrowserPreference,
    /// Renderer sandbox policy. Defaults to [`RendererSandboxMode::Enabled`].
    pub renderer_sandbox: RendererSandboxMode,
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
            renderer_sandbox: RendererSandboxMode::Enabled,
            restart_after_pages: 500,
            geckodriver_url: "http://localhost:4444".into(),
        }
    }
}

impl BrowserProfile {
    /// Resolve profile to a concrete directory path + whether it's ephemeral.
    pub fn resolve(&self) -> Result<(PathBuf, bool), DetectError> {
        match self {
            BrowserProfile::Ephemeral => {
                let dir =
                    std::env::temp_dir().join(format!("dig2browser-{}", uuid::Uuid::new_v4()));
                std::fs::create_dir_all(&dir).map_err(DetectError::Io)?;
                Ok((dir, true))
            }
            BrowserProfile::Persistent(path) => {
                std::fs::create_dir_all(path).map_err(DetectError::Io)?;
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
        if self.renderer_sandbox == RendererSandboxMode::CompatibilityDisabled {
            args.push("--no-sandbox".into());
        }
        args.push("--disable-dev-shm-usage".into());
        // Cap the on-disk cache to 100 MB so long-running daemons don't accumulate GBs.
        args.push("--disk-cache-size=104857600".into());
        // Locale flags ensure HTTP Accept-Language matches navigator.languages.
        let effective_locale = locale.unwrap_or("en-US");
        let lang_base = effective_locale.split('-').next().unwrap_or("en");
        args.push(format!("--lang={}", effective_locale));
        args.push(format!(
            "--accept-lang={},{};q=0.9,en;q=0.7",
            effective_locale, lang_base
        ));

        args.push(format!(
            "--window-size={},{}",
            self.window_size.0, self.window_size.1
        ));
        // Caller-provided flags are useful for feature and proxy tuning, but
        // lifecycle/profile/security ownership remains with dig2browser.
        args.extend(sanitized_extra_args(&self.extra_args));

        // Keep protected arguments last as a second line of defence against
        // Chromium's last-flag-wins parsing.
        args.push("--remote-debugging-address=127.0.0.1".into());
        args.push(format!("--remote-debugging-port={}", port));
        args.push(format!("--user-data-dir={}", profile_dir.display()));

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

fn is_protected_argument(argument: &str) -> bool {
    let name = argument
        .split_once('=')
        .map_or(argument, |(name, _)| name)
        .to_ascii_lowercase();

    matches!(
        name.as_str(),
        "--remote-debugging-address"
            | "--remote-debugging-port"
            | "--remote-debugging-pipe"
            | "--user-data-dir"
            | "--no-sandbox"
            | "--disable-setuid-sandbox"
            | "--disable-gpu-sandbox"
            | "--disable-seccomp-filter-sandbox"
            | "--no-zygote"
    )
}

fn sanitized_extra_args(extra_args: &[String]) -> Vec<String> {
    let mut sanitized = Vec::with_capacity(extra_args.len());
    let mut index = 0;
    while index < extra_args.len() {
        let argument = &extra_args[index];
        if is_protected_argument(argument) {
            let name = argument
                .split_once('=')
                .map_or(argument.as_str(), |(name, _)| name)
                .to_ascii_lowercase();
            if !argument.contains('=')
                && matches!(
                    name.as_str(),
                    "--remote-debugging-address"
                        | "--remote-debugging-port"
                        | "--user-data-dir"
                )
            {
                index += 1;
            }
        } else {
            sanitized.push(argument.clone());
        }
        index += 1;
    }
    sanitized
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_launch_binds_debugging_to_loopback() {
        let config = LaunchConfig::default();
        let args = config.build_args(Path::new("profile"), 9_222, None);

        assert!(args
            .iter()
            .any(|argument| argument == "--remote-debugging-address=127.0.0.1"));
        assert!(args
            .iter()
            .any(|argument| argument == "--remote-debugging-port=9222"));
    }

    #[test]
    fn renderer_sandbox_is_enabled_by_default() {
        let args = LaunchConfig::default().build_args(Path::new("profile"), 9_222, None);
        assert!(!args.iter().any(|argument| argument == "--no-sandbox"));
    }

    #[test]
    fn renderer_sandbox_compatibility_mode_is_explicit() {
        let config = LaunchConfig {
            renderer_sandbox: RendererSandboxMode::CompatibilityDisabled,
            ..LaunchConfig::default()
        };
        let args = config.build_args(Path::new("profile"), 9_222, None);
        assert!(args.iter().any(|argument| argument == "--no-sandbox"));
    }

    #[test]
    fn extra_args_cannot_override_owned_launch_flags() {
        let config = LaunchConfig {
            extra_args: vec![
                "--remote-debugging-address=0.0.0.0".into(),
                "--remote-debugging-port=4444".into(),
                "--user-data-dir=attacker-profile".into(),
                "--remote-debugging-port".into(),
                "5555".into(),
                "--no-sandbox".into(),
                "--proxy-server=http://127.0.0.1:8080".into(),
            ],
            ..LaunchConfig::default()
        };
        let args = config.build_args(Path::new("owned-profile"), 9_222, None);

        assert!(!args.iter().any(|argument| argument.contains("0.0.0.0")));
        assert!(!args.iter().any(|argument| argument.contains("4444")));
        assert!(!args.iter().any(|argument| argument == "5555"));
        assert!(!args
            .iter()
            .any(|argument| argument.contains("attacker-profile")));
        assert!(!args.iter().any(|argument| argument == "--no-sandbox"));
        assert!(args
            .iter()
            .any(|argument| argument == "--proxy-server=http://127.0.0.1:8080"));
    }
}
