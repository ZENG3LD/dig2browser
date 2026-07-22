//! Browser launch argument builder.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

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

/// Browser-level outbound proxy selection.
///
/// This configures the browser runtime only. Process-level containment is a
/// separate boundary and must not be inferred from this setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserProxy {
    /// Use the browser's direct connection mode.
    Direct,
    /// Route HTTP and HTTPS traffic through an HTTP proxy.
    Http(SocketAddr),
    /// Route browser traffic through a SOCKS5 proxy.
    Socks5(SocketAddr),
}

/// Configuration for launching a browser process.
#[derive(Debug, Clone)]
pub struct LaunchConfig {
    pub headless: bool,
    pub window_size: (u32, u32),
    pub profile: BrowserProfile,
    pub debug_port: Option<u16>,
    pub extra_args: Vec<String>,
    /// Browser-owned outbound proxy selection. `None` preserves caller-supplied
    /// proxy arguments for backwards compatibility.
    pub browser_proxy: Option<BrowserProxy>,
    pub browser_pref: BrowserPreference,
    /// Renderer sandbox policy. Defaults to [`RendererSandboxMode::Enabled`].
    pub renderer_sandbox: RendererSandboxMode,
    /// Restart Chrome after this many page navigations to reclaim leaked memory.
    /// Set to `0` to disable automatic restarts.
    pub restart_after_pages: u32,
    /// GeckoDriver URL. Only used when `browser_pref = Firefox`.
    /// Default: `"http://localhost:4444"`.
    pub geckodriver_url: String,
    /// Station-owned GeckoDriver executable. When set, one isolated driver is
    /// launched for this browser worker and `geckodriver_url` is ignored.
    pub geckodriver_binary: Option<PathBuf>,
    /// Maximum time to wait for an owned GeckoDriver listener.
    pub geckodriver_startup_timeout: Duration,
}

impl Default for LaunchConfig {
    fn default() -> Self {
        Self {
            headless: true,
            window_size: (1920, 1080),
            profile: BrowserProfile::Ephemeral,
            debug_port: None,
            extra_args: Vec::new(),
            browser_proxy: None,
            browser_pref: BrowserPreference::Auto,
            renderer_sandbox: RendererSandboxMode::Enabled,
            restart_after_pages: 500,
            geckodriver_url: "http://localhost:4444".into(),
            geckodriver_binary: None,
            geckodriver_startup_timeout: Duration::from_secs(15),
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
        args.push("--disable-background-mode".into());
        args.push("--no-first-run".into());
        args.push("--disable-sync".into());
        args.push("--disable-default-apps".into());
        // Keep GPU support enabled, but let Chromium select its native ANGLE
        // backend. A forced backend disables Chromium's compatibility fallback
        // and can make an otherwise healthy installed browser fail at GPU init.
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

        // Typed route selection is station-owned and intentionally follows
        // caller-provided flags so consumer args cannot replace it by order.
        if let Some(browser_proxy) = self.browser_proxy {
            match browser_proxy {
                BrowserProxy::Direct => args.push("--no-proxy-server".into()),
                BrowserProxy::Http(endpoint) => {
                    args.push(format!("--proxy-server=http://{endpoint}"));
                    add_proxied_runtime_args(&mut args);
                }
                BrowserProxy::Socks5(endpoint) => {
                    args.push(format!("--proxy-server=socks5://{endpoint}"));
                    add_proxied_runtime_args(&mut args);
                }
            }
        }

        // Keep protected arguments last as a second line of defence against
        // Chromium's last-flag-wins parsing.
        args.push("--remote-debugging-address=127.0.0.1".into());
        args.push(format!("--remote-debugging-port={}", port));
        args.push(format!("--user-data-dir={}", profile_dir.display()));

        args
    }

    /// Build Chrome/Edge arguments for an inherited ASCIIZ DevTools pipe.
    ///
    /// The numeric handles are created and owned by the Windows process
    /// launcher. They are protected from caller overrides just like the
    /// loopback debugging endpoint.
    #[cfg(windows)]
    pub(crate) fn build_pipe_args(
        &self,
        profile_dir: &Path,
        locale: Option<&str>,
        browser_read_handle: u32,
        browser_write_handle: u32,
    ) -> Vec<String> {
        let mut args = self.build_args(profile_dir, 0, locale);
        args.retain(|argument| {
            let name = argument
                .split_once('=')
                .map_or(argument.as_str(), |(name, _)| name);
            !matches!(
                name,
                "--remote-debugging-address" | "--remote-debugging-port"
            )
        });
        args.push("--remote-debugging-pipe".to_owned());
        args.push(format!(
            "--remote-debugging-io-pipes={browser_read_handle},{browser_write_handle}"
        ));
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

fn add_proxied_runtime_args(args: &mut Vec<String>) {
    args.push("--proxy-bypass-list=<-loopback>".into());
    args.push("--disable-quic".into());
    args.push("--force-webrtc-ip-handling-policy=disable_non_proxied_udp".into());
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
            | "--remote-debugging-io-pipes"
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
                        | "--remote-debugging-pipe"
                        | "--remote-debugging-io-pipes"
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
                "--remote-debugging-pipe".into(),
                "CBOR".into(),
                "--remote-debugging-io-pipes".into(),
                "123,456".into(),
                "--no-sandbox".into(),
                "--proxy-server=http://127.0.0.1:8080".into(),
            ],
            ..LaunchConfig::default()
        };
        let args = config.build_args(Path::new("owned-profile"), 9_222, None);

        assert!(!args.iter().any(|argument| argument.contains("0.0.0.0")));
        assert!(!args.iter().any(|argument| argument.contains("4444")));
        assert!(!args.iter().any(|argument| argument == "5555"));
        assert!(!args.iter().any(|argument| argument == "CBOR"));
        assert!(!args.iter().any(|argument| argument == "123,456"));
        assert!(!args
            .iter()
            .any(|argument| argument.contains("attacker-profile")));
        assert!(!args.iter().any(|argument| argument == "--no-sandbox"));
        assert!(args
            .iter()
            .any(|argument| argument == "--proxy-server=http://127.0.0.1:8080"));
    }

    #[test]
    fn browser_launch_disables_background_process_lifecycle() {
        let args = LaunchConfig::default().build_args(Path::new("profile"), 9_222, None);
        assert!(args
            .iter()
            .any(|argument| argument == "--disable-background-mode"));
    }

    #[test]
    fn typed_http_proxy_follows_and_overrides_consumer_route_flags() {
        let config = LaunchConfig {
            extra_args: vec![
                "--no-proxy-server".into(),
                "--proxy-server=socks5://127.0.0.1:19050".into(),
                "--proxy-bypass-list=*".into(),
            ],
            browser_proxy: Some(BrowserProxy::Http("127.0.0.1:28080".parse().unwrap())),
            ..LaunchConfig::default()
        };
        let args = config.build_args(Path::new("profile"), 9_222, None);

        let owned_proxy_index = args
            .iter()
            .position(|argument| argument == "--proxy-server=http://127.0.0.1:28080")
            .unwrap();
        let consumer_proxy_index = args
            .iter()
            .position(|argument| argument == "--proxy-server=socks5://127.0.0.1:19050")
            .unwrap();
        let owned_bypass_index = args
            .iter()
            .position(|argument| argument == "--proxy-bypass-list=<-loopback>")
            .unwrap();
        let consumer_bypass_index = args
            .iter()
            .position(|argument| argument == "--proxy-bypass-list=*")
            .unwrap();

        assert!(owned_proxy_index > consumer_proxy_index);
        assert!(owned_bypass_index > consumer_bypass_index);
        assert!(args.iter().any(|argument| argument == "--disable-quic"));
        assert!(args.iter().any(|argument| {
            argument == "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"
        }));
    }

    #[test]
    fn typed_direct_and_socks5_render_owned_chromium_routes() {
        let direct = LaunchConfig {
            extra_args: vec!["--proxy-server=http://127.0.0.1:18080".into()],
            browser_proxy: Some(BrowserProxy::Direct),
            ..LaunchConfig::default()
        }
        .build_args(Path::new("profile"), 9_222, None);
        assert!(direct.iter().rposition(|argument| argument == "--no-proxy-server")
            > direct.iter().rposition(|argument| argument.starts_with("--proxy-server=")));

        let socks = LaunchConfig {
            browser_proxy: Some(BrowserProxy::Socks5("127.0.0.1:19050".parse().unwrap())),
            ..LaunchConfig::default()
        }
        .build_args(Path::new("profile"), 9_222, None);
        assert!(socks
            .iter()
            .any(|argument| argument == "--proxy-server=socks5://127.0.0.1:19050"));
    }

    #[cfg(windows)]
    #[test]
    fn pipe_launch_owns_inherited_handles_without_tcp_debugging() {
        let config = LaunchConfig {
            extra_args: vec![
                "--remote-debugging-pipe=CBOR".into(),
                "--remote-debugging-io-pipes=1,2".into(),
            ],
            ..LaunchConfig::default()
        };
        let args = config.build_pipe_args(Path::new("profile"), None, 123, 456);

        assert!(args.iter().any(|argument| argument == "--remote-debugging-pipe"));
        assert!(args
            .iter()
            .any(|argument| argument == "--remote-debugging-io-pipes=123,456"));
        assert!(!args
            .iter()
            .any(|argument| argument.starts_with("--remote-debugging-address")));
        assert!(!args
            .iter()
            .any(|argument| argument.starts_with("--remote-debugging-port")));
        assert!(!args.iter().any(|argument| argument.contains("CBOR")));
        assert!(!args.iter().any(|argument| argument.ends_with("=1,2")));
    }
}
