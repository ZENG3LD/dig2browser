//! dev-launch-debug — launch Chrome/Edge with --remote-debugging-port and an
//! isolated user-data-dir, then print the DevTools WebSocket URL on stdout.
//!
//! # Usage
//!
//!   dev-launch-debug --port 9222
//!   dev-launch-debug --port 9222 --url http://127.0.0.1:17499/index.html
//!   dev-launch-debug --port 9222 --profile /tmp/myprofile
//!   dev-launch-debug --port 9333 --profile /tmp/spare --tor --url http://example.onion/
//!   dev-launch-debug --port 9334 --profile /tmp/edge --browser edge --tor --url http://example.onion/
//!   dev-launch-debug --port 9335 --profile /tmp/ff --browser firefox --tor --url http://example.onion/
//!
//! `--tor` is accepted only when this binary is built with `--features tor`.
//! It bootstraps an in-process Arti client, listens for SOCKS5 on
//! `127.0.0.1:0`, and routes Chrome through `BrowserProxy::Socks5`.
//! Without `--tor` the Chrome arguments are unchanged. There is no `tor.exe`.
//!
//! On Ctrl-C the launched browser is killed and the Arti client is dropped.
//! Its state directory is removed with the launch.
//! The discovered DevTools ws:// URL is printed on stdout so it can be
//! consumed by scripts:
//!
//!   WS=$(dev-launch-debug --port 9222)
//!   dev-attach --port 9222 --target http://127.0.0.1:17499 --watch-console

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use clap::{Parser, ValueEnum};
use dig2browser::{discover_ws_url, BrowserProxy};

#[cfg(feature = "tor")]
const TOR_BOOTSTRAP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(180);

/// Used when this binary was built without `--features tor`. The feature
/// build does not call it; the text stays so both binaries share one error.
#[cfg_attr(feature = "tor", allow(dead_code))]
const TOR_FEATURE_REQUIRED: &str =
    "dev-launch-debug was built without the tor feature. Rebuild with --features tor.";

const TOR_CONFIG_REJECTED: &str =
    "--tor-config is not accepted. This launcher embeds Arti and does not load a torrc or bridges.";

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "dev-launch-debug",
    about = "Launch Chrome/Edge with --remote-debugging-port and an isolated profile"
)]
struct Cli {
    /// Remote debugging port (default: 9222)
    #[arg(long, default_value = "9222")]
    port: u16,

    /// User-data-dir for the isolated profile.
    /// Default: $TEMP/dig2browser-debug-<PORT>
    #[arg(long, value_name = "DIR")]
    profile: Option<PathBuf>,

    /// URL to open after launch (optional).
    #[arg(long)]
    url: Option<String>,

    /// Bootstrap an in-process Arti client for this launch and route Chrome
    /// through its loopback SOCKS port. Requires a binary built with
    /// `--features tor`. Without this flag the launch is direct.
    #[arg(long)]
    tor: bool,

    /// Rejected. Bridges and torrc files are not loaded by this launcher.
    #[arg(long, value_name = "FILE")]
    tor_config: Option<PathBuf>,

    /// Which browser this launch owns. Omitted, the launcher keeps the old
    /// search: Chrome, then Edge. Firefox is only started when named.
    #[arg(long, value_enum)]
    browser: Option<BrowserKind>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum BrowserKind {
    Chrome,
    Edge,
    Firefox,
}

// ── Browser detection (lightweight re-use of dig2browser::detect) ─────────────

fn browser_candidates(kind: BrowserKind) -> Vec<String> {
    let mut candidates: Vec<String> = Vec::new();
    if cfg!(target_os = "windows") {
        match kind {
            BrowserKind::Chrome => {
                candidates.push(r"C:\Program Files\Google\Chrome\Application\chrome.exe".into());
                candidates.push(r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe".into());
                if let Ok(local) = std::env::var("LOCALAPPDATA") {
                    candidates.push(format!(r"{}\Google\Chrome\Application\chrome.exe", local));
                }
            }
            BrowserKind::Edge => {
                candidates.push(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe".into());
                candidates.push(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe".into());
                if let Ok(local) = std::env::var("LOCALAPPDATA") {
                    candidates.push(format!(r"{}\Microsoft\Edge\Application\msedge.exe", local));
                }
            }
            BrowserKind::Firefox => {
                candidates.push(r"C:\Program Files\Mozilla Firefox\firefox.exe".into());
                candidates.push(r"C:\Program Files (x86)\Mozilla Firefox\firefox.exe".into());
            }
        }
    } else if cfg!(target_os = "macos") {
        match kind {
            BrowserKind::Chrome => {
                candidates.push("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome".into());
                candidates.push("/Applications/Chromium.app/Contents/MacOS/Chromium".into());
            }
            BrowserKind::Edge => {
                candidates.push("/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge".into());
            }
            BrowserKind::Firefox => {
                candidates.push("/Applications/Firefox.app/Contents/MacOS/firefox".into());
            }
        }
    } else {
        match kind {
            BrowserKind::Chrome => {
                candidates.push("/usr/bin/google-chrome".into());
                candidates.push("/usr/bin/chromium-browser".into());
                candidates.push("/usr/bin/chromium".into());
            }
            BrowserKind::Edge => {
                candidates.push("/usr/bin/microsoft-edge".into());
            }
            BrowserKind::Firefox => {
                candidates.push("/usr/bin/firefox".into());
            }
        }
    }
    candidates
}

fn env_override(kind: BrowserKind) -> &'static str {
    match kind {
        BrowserKind::Chrome => "CHROME_PATH",
        BrowserKind::Edge => "EDGE_PATH",
        BrowserKind::Firefox => "FIREFOX_PATH",
    }
}

fn find_kind(kind: BrowserKind) -> Result<PathBuf, String> {
    if let Ok(value) = std::env::var(env_override(kind)) {
        let path = PathBuf::from(&value);
        if path.exists() {
            return Ok(path);
        }
    }
    let candidates = browser_candidates(kind);
    for path in &candidates {
        if std::path::Path::new(path).exists() {
            return Ok(PathBuf::from(path));
        }
    }
    Err(format!(
        "no {kind:?} binary found. Tried: {}. Set {}.",
        candidates.join(", "),
        env_override(kind)
    ))
}

/// Chrome if it is installed, otherwise Edge. Firefox is never implicit.
fn find_browser() -> Result<(BrowserKind, PathBuf), String> {
    if let Ok(value) = std::env::var("CHROME_PATH") {
        let path = PathBuf::from(&value);
        if path.exists() {
            return Ok((BrowserKind::Chrome, path));
        }
    }
    if let Ok(value) = std::env::var("EDGE_PATH") {
        let path = PathBuf::from(&value);
        if path.exists() {
            return Ok((BrowserKind::Edge, path));
        }
    }
    if let Ok(path) = find_kind(BrowserKind::Chrome) {
        return Ok((BrowserKind::Chrome, path));
    }
    find_kind(BrowserKind::Edge).map(|path| (BrowserKind::Edge, path))
}

/// `http://*.onion` is not a secure context. Chrome's
/// `--unsafely-treat-insecure-origin-as-secure` is a bad flag and paints
/// the unsupported-flag bar, so the launcher does not pass it.
fn http_onion_page(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    if rest.contains('@') {
        return false;
    }
    let hostport = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    if hostport.is_empty() {
        return false;
    }
    let host = match hostport.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()) => host,
        _ => hostport,
    };
    !host.is_empty()
        && host.ends_with(".onion")
        && host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-')
}

/// Firefox has no Chromium proxy flags. DNS goes through SOCKS
/// (`socks_remote_dns`) and DoH is off (`trr.mode` 5) so an onion name is
/// not resolved on the clearnet. HTTPS-First is off so `http://` is not
/// upgraded to a port the hidden service does not publish. Background
/// clearnet (safe browsing, captive portal, prefetch) stays off so it does
/// not fill the one Tor client before the page loads.
fn firefox_proxy_user_js(socks: SocketAddr) -> String {
    format!(
        "user_pref(\"network.proxy.type\", 1);\n\
         user_pref(\"network.proxy.socks\", \"{ip}\");\n\
         user_pref(\"network.proxy.socks_port\", {port});\n\
         user_pref(\"network.proxy.socks_version\", 5);\n\
         user_pref(\"network.proxy.socks_remote_dns\", true);\n\
         user_pref(\"network.trr.mode\", 5);\n\
         user_pref(\"network.dns.blockDotOnion\", false);\n\
         user_pref(\"dom.security.https_only_mode\", false);\n\
         user_pref(\"dom.security.https_first\", false);\n\
         user_pref(\"dom.security.https_first_pbm\", false);\n\
         user_pref(\"network.http.http3.enable\", false);\n\
         user_pref(\"network.captive-portal-service.enabled\", false);\n\
         user_pref(\"network.connectivity-service.enabled\", false);\n\
         user_pref(\"network.prefetch-next\", false);\n\
         user_pref(\"network.predictor.enabled\", false);\n\
         user_pref(\"browser.safebrowsing.malware.enabled\", false);\n\
         user_pref(\"browser.safebrowsing.phishing.enabled\", false);\n\
         user_pref(\"browser.safebrowsing.downloads.enabled\", false);\n",
        ip = socks.ip(),
        port = socks.port(),
    )
}

fn firefox_launch_args(profile_dir: &Path, url: Option<&str>) -> Vec<String> {
    let mut args = vec![
        "-no-remote".to_owned(),
        "-profile".to_owned(),
        profile_dir.display().to_string(),
    ];
    if let Some(url) = url {
        args.push(url.to_owned());
    }
    args
}

fn debug_launch_args(
    port: u16,
    profile_dir: &Path,
    url: Option<&str>,
    tor_socks: Option<SocketAddr>,
) -> Vec<String> {
    let mut args = vec![
        format!("--remote-debugging-port={}", port),
        format!("--user-data-dir={}", profile_dir.display()),
        "--no-first-run".to_owned(),
        "--no-default-browser-check".to_owned(),
        "--disable-background-networking".to_owned(),
        "--disable-sync".to_owned(),
        "--disable-translate".to_owned(),
        "--safebrowsing-disable-auto-update".to_owned(),
        "--metrics-recording-only".to_owned(),
        "--disable-extensions".to_owned(),
    ];

    if let Some(socks) = tor_socks {
        BrowserProxy::Socks5(socks).append_launch_args(&mut args);
    }

    if let Some(url) = url {
        args.push(url.to_owned());
    }

    args
}

// ── Tor owned by this launch ──────────────────────────────────────────────────

#[cfg(feature = "tor")]
const SOCKS_SUCCEEDED: u8 = 0x00;
const SOCKS_GENERAL_FAILURE: u8 = 0x01;
const SOCKS_COMMAND_UNSUPPORTED: u8 = 0x07;
const SOCKS_ATYP_UNSUPPORTED: u8 = 0x08;
#[cfg(feature = "tor")]
const SOCKS_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Decode one SOCKS5 CONNECT request.
///
/// IPv4 and IPv6 are rejected, and so is a domain that is an IP literal.
/// Chrome is told not to resolve names itself. A raw address here means that
/// rule failed, and sending it to Tor would confirm the clearnet lookup.
fn decode_socks_connect(request: &[u8]) -> Result<(String, u16), u8> {
    if request.first().copied() != Some(5) {
        return Err(SOCKS_GENERAL_FAILURE);
    }
    if request.get(1).copied() != Some(0x01) {
        eprintln!(
            "[dev-launch-debug] socks: reject cmd={:#04x}",
            request.get(1).copied().unwrap_or(0)
        );
        let _ = std::io::Write::flush(&mut std::io::stderr());
        return Err(SOCKS_COMMAND_UNSUPPORTED);
    }
    match request.get(3).copied() {
        Some(atyp @ (0x01 | 0x04)) => {
            eprintln!("[dev-launch-debug] socks: reject atyp={atyp:#04x}");
            let _ = std::io::Write::flush(&mut std::io::stderr());
            Err(SOCKS_ATYP_UNSUPPORTED)
        }
        Some(0x03) => {
            let Some(len) = request.get(4).copied() else {
                return Err(SOCKS_GENERAL_FAILURE);
            };
            let len = usize::from(len);
            if len == 0 || request.len() != 5 + len + 2 {
                return Err(SOCKS_GENERAL_FAILURE);
            }
            let host = std::str::from_utf8(&request[5..5 + len]).map_err(|_| {
                eprintln!("[dev-launch-debug] socks: reject host-encoding");
                let _ = std::io::Write::flush(&mut std::io::stderr());
                SOCKS_ATYP_UNSUPPORTED
            })?;
            if !host_is_dns_name(host) {
                eprintln!("[dev-launch-debug] socks: reject host-shape len={}", host.len());
                let _ = std::io::Write::flush(&mut std::io::stderr());
                return Err(SOCKS_ATYP_UNSUPPORTED);
            }
            let port = u16::from_be_bytes([request[5 + len], request[6 + len]]);
            if port == 0 {
                return Err(SOCKS_GENERAL_FAILURE);
            }
            Ok((host.to_owned(), port))
        }
        _ => Err(SOCKS_ATYP_UNSUPPORTED),
    }
}

fn host_is_dns_name(host: &str) -> bool {
    if host.is_empty() || host.len() > 255 || host.parse::<IpAddr>().is_ok() {
        return false;
    }
    host.split('.').all(|label| {
        let bytes = label.as_bytes();
        !bytes.is_empty()
            && bytes.len() <= 63
            && bytes[0] != b'-'
            && bytes[bytes.len() - 1] != b'-'
            && bytes.iter().all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
    })
}

#[cfg(feature = "tor")]
async fn remove_data_dir(path: &Path) {
    for _ in 0..25 {
        if !path.exists() || std::fs::remove_dir_all(path).is_ok() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    eprintln!(
        "[dev-launch-debug] tor data directory was not removed: {}",
        path.display()
    );
}

#[cfg(feature = "tor")]
mod embedded_tor {
    use std::sync::Arc;

    use arti_client::config::TorClientConfigBuilder;
    use arti_client::TorClient;
    use tor_rtcompat::PreferredRuntime;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    use super::{
        decode_socks_connect, remove_data_dir, SOCKS_ATYP_UNSUPPORTED, SOCKS_GENERAL_FAILURE,
        SOCKS_HANDSHAKE_TIMEOUT, SOCKS_SUCCEEDED, TOR_BOOTSTRAP_TIMEOUT,
    };

    pub(super) struct OwnedTor {
        data_dir: std::path::PathBuf,
        client: Option<Arc<TorClient<PreferredRuntime>>>,
        accept_task: tokio::task::JoinHandle<()>,
        released: bool,
    }

    impl OwnedTor {
        pub(super) async fn shutdown(&mut self) {
            if self.released {
                return;
            }
            eprintln!("[dev-launch-debug] stopping tor…");
            self.accept_task.abort();
            let _ = (&mut self.accept_task).await;
            self.client.take();
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            remove_data_dir(&self.data_dir).await;
            self.released = true;
        }

        /// Open the hidden-service circuit before Chrome asks. The first
        /// introduction is the slow part. Chrome abandons a proxy navigation
        /// that is still pending at about 30s, so that work has to be done
        /// while the browser is not yet waiting.
        pub(super) async fn preflight_onion(&self, host: &str, port: u16) -> Result<(), String> {
            let Some(client) = self.client.as_ref() else {
                return Err("tor client is gone".into());
            };
            let started = std::time::Instant::now();
            eprintln!("[dev-launch-debug] tor preflight: class=onion port={port}");
            let _ = std::io::Write::flush(&mut std::io::stderr());
            match client.connect((host, port)).await {
                Ok(_stream) => {
                    eprintln!(
                        "[dev-launch-debug] tor preflight: up {}s",
                        started.elapsed().as_secs()
                    );
                    let _ = std::io::Write::flush(&mut std::io::stderr());
                    Ok(())
                }
                Err(error) => {
                    eprintln!(
                        "[dev-launch-debug] tor preflight: failed {}s: {error}",
                        started.elapsed().as_secs()
                    );
                    let _ = std::io::Write::flush(&mut std::io::stderr());
                    Err(error.to_string())
                }
            }
        }
    }

    impl Drop for OwnedTor {
        fn drop(&mut self) {
            if self.released {
                return;
            }
            self.accept_task.abort();
            self.client.take();
            let _ = std::fs::remove_dir_all(&self.data_dir);
        }
    }

    pub(super) async fn start() -> Result<(OwnedTor, std::net::SocketAddr), Box<dyn std::error::Error>>
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.map_err(|error| {
            format!("failed to listen on 127.0.0.1 for arti socks: {error}")
        })?;
        let socks = listener
            .local_addr()
            .map_err(|error| format!("failed to read the arti socks port: {error}"))?;
        if !socks.ip().is_loopback() {
            return Err("arti socks listener is not on loopback".into());
        }

        let data_dir = std::env::temp_dir().join(format!(
            "dig2browser-tor-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let state_dir = data_dir.join("state");
        let cache_dir = data_dir.join("cache");
        if let Err(error) = std::fs::create_dir_all(&state_dir)
            .and_then(|_| std::fs::create_dir_all(&cache_dir))
        {
            return Err(format!(
                "failed to create tor state directory {}: {error}",
                data_dir.display()
            )
            .into());
        }

        let client = match bootstrap(&state_dir, &cache_dir).await {
            Ok(client) => client,
            Err(error) => {
                remove_data_dir(&data_dir).await;
                return Err(error.into());
            }
        };

        eprintln!("[dev-launch-debug] tor:        arti-client 0.47.0 (in-process)");
        eprintln!("[dev-launch-debug] tor socks:  {socks}");
        eprintln!(
            "[dev-launch-debug] tor data:   {}",
            data_dir.display()
        );

        let task_client = Arc::clone(&client);
        let accept_task = tokio::spawn(async move {
            accept_loop(listener, task_client).await;
        });

        Ok((
            OwnedTor {
                data_dir,
                client: Some(client),
                accept_task,
                released: false,
            },
            socks,
        ))
    }

    struct FlushStderr;

    impl std::io::Write for FlushStderr {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let mut err = std::io::stderr();
            let n = err.write(buf)?;
            err.flush()?;
            Ok(n)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            std::io::stderr().flush()
        }
    }

    fn init_tor_tracing() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let filter = tracing_subscriber::EnvFilter::new(
                "warn,tor_dirmgr=info,tor_dirclient=info,tor_circmgr=info,tor_hsclient=info",
            );
            // stderr is block-buffered when this process is launched with a
            // redirected handle. Flush each record so a killed bootstrap
            // still leaves the directory error on disk.
            let _ = tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_target(true)
                .with_ansi(false)
                .with_writer(|| FlushStderr)
                .try_init();
        });
    }

    fn install_ring_provider() {
        // Arti 0.47 panics while building its TLS runtime if no rustls
        // CryptoProvider is installed. ring is selected here, once.
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    async fn bootstrap(
        state_dir: &std::path::Path,
        cache_dir: &std::path::Path,
    ) -> Result<Arc<TorClient<PreferredRuntime>>, String> {
        install_ring_provider();
        init_tor_tracing();
        let mut builder = TorClientConfigBuilder::from_directories(state_dir, cache_dir);
        builder.address_filter().allow_onion_addrs(true);
        // Chrome gives up on a hung proxy navigation at about 30s. The
        // Arti default of 10s aborts the hidden-service stream first.
        builder
            .stream_timeouts()
            .connect_timeout(std::time::Duration::from_secs(90));
        // This directory was created by this process under the user temp dir
        // and is removed on exit. Windows temp ACLs fail Arti's Unix
        // owner-only check.
        builder.storage().permissions().dangerously_trust_everyone();
        let config = builder
            .build()
            .map_err(|error| format!("arti config: {error}"))?;
        let runtime = PreferredRuntime::current().map_err(|error| format!("arti runtime: {error}"))?;
        let client = TorClient::with_runtime(runtime)
            .config(config)
            .create_unbootstrapped_async()
            .await
            .map_err(|error| format!("arti client: {error}"))?;
        let watched = Arc::clone(&client);
        let mut boot = std::pin::pin!(watched.bootstrap());
        // One listener for the whole bootstrap. A new listener per loop
        // iteration drops the signal that arrived during the previous wait.
        let mut break_sig = std::pin::pin!(super::console_break());
        let mut ctrlc = std::pin::pin!(super::ctrl_c_or_pending());
        let started = std::time::Instant::now();
        let mut last_report = String::new();
        let mut next_heartbeat = std::time::Duration::from_secs(15);
        loop {
            tokio::select! {
                result = &mut boot => {
                    return match result {
                        Ok(()) => Ok(client),
                        Err(error) => Err(format!("arti bootstrap failed: {error}")),
                    };
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
                    let status = client.bootstrap_status();
                    let blocked = match status.blocked() {
                        Some(blockage) => blockage.to_string(),
                        None => "working".to_owned(),
                    };
                    let line = format!("{:.0}% {blocked}", status.as_frac() * 100.0);
                    let elapsed = started.elapsed();
                    if line != last_report || elapsed >= next_heartbeat {
                        eprintln!(
                            "[dev-launch-debug] tor bootstrap: {line} ({}s)",
                            elapsed.as_secs()
                        );
                        let _ = std::io::Write::flush(&mut std::io::stderr());
                        last_report = line.clone();
                        if elapsed >= next_heartbeat {
                            next_heartbeat += std::time::Duration::from_secs(15);
                        }
                    }
                    if elapsed >= TOR_BOOTSTRAP_TIMEOUT {
                        return Err(format!(
                            "arti did not bootstrap within {}s ({line})",
                            TOR_BOOTSTRAP_TIMEOUT.as_secs()
                        ));
                    }
                }
                _ = &mut break_sig => return Err("arti bootstrap interrupted".into()),
                _ = &mut ctrlc => return Err("arti bootstrap interrupted".into()),
            }
        }
    }

    async fn accept_loop(listener: tokio::net::TcpListener, client: Arc<TorClient<PreferredRuntime>>) {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    match accepted {
                        Ok((stream, peer)) => {
                            if !peer.ip().is_loopback() {
                                continue;
                            }
                            let client = Arc::clone(&client);
                            tasks.spawn(async move {
                                if let Err(error) = handle_socks(stream, client).await {
                                    eprintln!("[dev-launch-debug] socks: {error}");
                                }
                            });
                        }
                        Err(error) => {
                            eprintln!("[dev-launch-debug] socks accept failed: {error}");
                            break;
                        }
                    }
                }
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
    }

    async fn handle_socks(
        mut local: TcpStream,
        client: Arc<TorClient<PreferredRuntime>>,
    ) -> Result<(), String> {
        read_greeting(&mut local).await?;
        let target = match read_connect(&mut local).await {
            Ok(target) => target,
            Err(status) => {
                let _ = write_reply(&mut local, status).await;
                return Err(format!("socks request rejected status={status:#04x}"));
            }
        };
        let class = if target.0.to_ascii_lowercase().ends_with(".onion") {
            "onion"
        } else {
            "dns"
        };
        eprintln!(
            "[dev-launch-debug] socks: connect class={class} port={}",
            target.1
        );
        let _ = std::io::Write::flush(&mut std::io::stderr());
        let started = std::time::Instant::now();
        let mut remote = match client.connect((target.0.as_str(), target.1)).await {
            Ok(remote) => remote,
            Err(error) => {
                eprintln!(
                    "[dev-launch-debug] socks: connect class={class} port={} failed {}s: {error}",
                    target.1,
                    started.elapsed().as_secs()
                );
                let _ = std::io::Write::flush(&mut std::io::stderr());
                let _ = write_reply(&mut local, SOCKS_GENERAL_FAILURE).await;
                return Ok(());
            }
        };
        eprintln!(
            "[dev-launch-debug] socks: connect class={class} port={} up {}s",
            target.1,
            started.elapsed().as_secs()
        );
        let _ = std::io::Write::flush(&mut std::io::stderr());
        write_reply(&mut local, SOCKS_SUCCEEDED).await?;
        let copied = tokio::io::copy_bidirectional(&mut local, &mut remote).await;
        match copied {
            Ok((down, up)) => {
                eprintln!(
                    "[dev-launch-debug] socks: closed class={class} port={} down={down} up={up}",
                    target.1
                );
            }
            Err(error) => {
                eprintln!(
                    "[dev-launch-debug] socks: copy class={class} port={} failed: {error}",
                    target.1
                );
            }
        }
        let _ = std::io::Write::flush(&mut std::io::stderr());
        Ok(())
    }

    async fn read_greeting(stream: &mut TcpStream) -> Result<(), String> {
        let mut head = [0u8; 2];
        read_exact(stream, &mut head, "socks greeting").await?;
        if head[0] != 5 || head[1] == 0 || head[1] > 8 {
            return Err("socks greeting rejected".into());
        }
        let mut methods = vec![0u8; usize::from(head[1])];
        read_exact(stream, &mut methods, "socks methods").await?;
        if !methods.contains(&0x00) {
            let _ = stream.write_all(&[5, 0xff]).await;
            return Err("socks auth rejected".into());
        }
        stream
            .write_all(&[5, 0x00])
            .await
            .map_err(|error| format!("socks greeting reply failed: {error}"))
    }

    async fn read_connect(stream: &mut TcpStream) -> Result<(String, u16), u8> {
        let mut head = [0u8; 4];
        if read_exact(stream, &mut head, "socks request").await.is_err() {
            return Err(SOCKS_GENERAL_FAILURE);
        }
        let mut request = head.to_vec();
        let rest_len = match head[3] {
            0x01 => 6,
            0x04 => 18,
            0x03 => {
                let mut len_buf = [0u8; 1];
                if read_exact(stream, &mut len_buf, "socks address").await.is_err() {
                    return Err(SOCKS_GENERAL_FAILURE);
                }
                request.push(len_buf[0]);
                usize::from(len_buf[0]) + 2
            }
            _ => return Err(SOCKS_ATYP_UNSUPPORTED),
        };
        let mut rest = vec![0u8; rest_len];
        if read_exact(stream, &mut rest, "socks address").await.is_err() {
            return Err(SOCKS_GENERAL_FAILURE);
        }
        request.extend_from_slice(&rest);
        decode_socks_connect(&request)
    }

    async fn read_exact(stream: &mut TcpStream, buf: &mut [u8], what: &str) -> Result<(), String> {
        tokio::time::timeout(SOCKS_HANDSHAKE_TIMEOUT, stream.read_exact(buf))
            .await
            .map_err(|_| format!("{what} timed out"))?
            .map_err(|error| format!("{what} failed: {error}"))?;
        Ok(())
    }

    async fn write_reply(stream: &mut TcpStream, status: u8) -> Result<(), String> {
        stream
            .write_all(&[0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .map_err(|error| format!("socks reply failed: {error}"))
    }
}

// ── Main ──────────────────────────────────────────────────────────────────────

/// Host and port of an `.onion` http(s) URL. Anything else is skipped.
/// The host is not logged.
#[cfg(feature = "tor")]
fn onion_preflight_target(url: &str) -> Option<(&str, u16)> {
    let https = url.starts_with("https://");
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    if authority.is_empty() || authority.starts_with('[') {
        return None;
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()) => {
            (host, port.parse().ok()?)
        }
        _ if https => (authority, 443),
        _ => (authority, 80),
    };
    if host.to_ascii_lowercase().ends_with(".onion") {
        Some((host, port))
    } else {
        None
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    if cli.tor_config.is_some() {
        return Err(TOR_CONFIG_REJECTED.into());
    }

    // Resolve profile directory.
    let profile_dir = match cli.profile {
        Some(p) => p,
        None => {
            let mut tmp = std::env::temp_dir();
            tmp.push(format!("dig2browser-debug-{}", cli.port));
            tmp
        }
    };

    // Create profile dir if it doesn't exist.
    std::fs::create_dir_all(&profile_dir)?;

    let (kind, browser) = match cli.browser {
        Some(kind) => (
            kind,
            find_kind(kind).map_err(|error| format!("browser not found: {error}"))?,
        ),
        None => find_browser().map_err(|error| format!("browser not found: {error}"))?,
    };

    #[cfg(feature = "tor")]
    let mut owned_tor = None;
    #[cfg(feature = "tor")]
    let mut tor_socks = None;
    #[cfg(not(feature = "tor"))]
    let tor_socks = None;
    if cli.tor {
        #[cfg(not(feature = "tor"))]
        {
            return Err(TOR_FEATURE_REQUIRED.into());
        }
        #[cfg(feature = "tor")]
        {
            let (tor, socks) = embedded_tor::start().await?;
            if let Some(url) = cli.url.as_deref() {
                if let Some((host, port)) = onion_preflight_target(url) {
                    if let Err(error) = tor.preflight_onion(host, port).await {
                        eprintln!("[dev-launch-debug] tor preflight continued after error: {error}");
                        let _ = std::io::Write::flush(&mut std::io::stderr());
                    }
                }
            }
            tor_socks = Some(socks);
            owned_tor = Some(tor);
        }
    }

    eprintln!("[dev-launch-debug] launching: {}", browser.display());
    eprintln!("[dev-launch-debug] profile:   {}", profile_dir.display());
    eprintln!("[dev-launch-debug] port:      {}", cli.port);

    let outcome = run_browser(
        kind,
        &browser,
        &profile_dir,
        cli.port,
        cli.url.as_deref(),
        tor_socks,
    )
    .await;
    #[cfg(feature = "tor")]
    if let Some(tor) = owned_tor.as_mut() {
        tor.shutdown().await;
    }
    outcome
}

/// Windows Ctrl-Break. A parent that starts this process in its own group
/// delivers CTRL_BREAK_EVENT; tokio's ctrl_c listens only for CTRL_C_EVENT.
/// A missing console handler must not fail the launch: the future then waits
/// forever and the other select arms stay live.
#[cfg(windows)]
async fn console_break() {
    match tokio::signal::windows::ctrl_break() {
        Ok(mut signal) => {
            signal.recv().await;
        }
        Err(_) => std::future::pending::<()>().await,
    }
}

#[cfg(not(windows))]
async fn console_break() {
    std::future::pending::<()>().await;
}

async fn ctrl_c_or_pending() {
    match tokio::signal::ctrl_c().await {
        Ok(()) => {}
        Err(_) => std::future::pending::<()>().await,
    }
}

/// `crypto.getRandomValues` exists off a secure context. `randomUUID` does not,
/// and the wasm glue calls it during init (`arg1.randomUUID is not a function`).
/// The binding lives only as long as the CDP socket that registered it. Closing
/// that socket before the reloaded document starts leaves the page without it.
const ONION_RANDOM_UUID_SOURCE: &str = r#"(function(){
  var c = globalThis.crypto;
  if (!c || typeof c.randomUUID === "function") return;
  c.randomUUID = function() {
    var bytes = new Uint8Array(16);
    c.getRandomValues(bytes);
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    var hex = "";
    for (var i = 0; i < 16; i++) hex += bytes[i].toString(16).padStart(2, "0");
    return hex.slice(0,8)+"-"+hex.slice(8,12)+"-"+hex.slice(12,16)+"-"+hex.slice(16,20)+"-"+hex.slice(20);
  };
})();"#;

async fn page_debugger_urls(port: u16) -> Result<Vec<String>, String> {
    let list: serde_json::Value = reqwest::get(format!("http://127.0.0.1:{port}/json/list"))
        .await
        .map_err(|error| error.to_string())?
        .json()
        .await
        .map_err(|error| error.to_string())?;
    let Some(tabs) = list.as_array() else {
        return Ok(Vec::new());
    };
    Ok(tabs
        .iter()
        .filter(|tab| tab.get("type").and_then(|value| value.as_str()) == Some("page"))
        .filter_map(|tab| {
            tab.get("webSocketDebuggerUrl")
                .and_then(|value| value.as_str())
                .map(str::to_owned)
        })
        .collect())
}

/// Register the shim and reload this page. The returned socket must stay open
/// for the life of the page: Edge drops the script when the client disconnects.
async fn arm_onion_page(
    ws_url: &str,
) -> Result<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    String,
> {
    use futures::{SinkExt, StreamExt};
    let (mut ws, _) = tokio_tungstenite::connect_async(ws_url)
        .await
        .map_err(|error| error.to_string())?;
    let enable = serde_json::json!({ "id": 1, "method": "Page.enable" });
    let script = serde_json::json!({
        "id": 2,
        "method": "Page.addScriptToEvaluateOnNewDocument",
        "params": {
            "source": ONION_RANDOM_UUID_SOURCE,
            "runImmediately": true
        }
    });
    ws.send(tokio_tungstenite::tungstenite::Message::Text(enable.to_string().into()))
        .await
        .map_err(|error| error.to_string())?;
    ws.send(tokio_tungstenite::tungstenite::Message::Text(script.to_string().into()))
        .await
        .map_err(|error| error.to_string())?;
    let ack_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let remaining = ack_deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err("shim ack timed out".into());
        }
        let next = tokio::time::timeout(remaining, ws.next())
            .await
            .map_err(|_| "shim ack timed out".to_owned())?
            .ok_or_else(|| "cdp closed".to_owned())?
            .map_err(|error| error.to_string())?;
        let text = match next {
            tokio_tungstenite::tungstenite::Message::Text(text) => text.to_string(),
            _ => continue,
        };
        let value: serde_json::Value = match serde_json::from_str(&text) {
            Ok(value) => value,
            Err(_) => continue,
        };
        if value.get("id").and_then(|id| id.as_u64()) != Some(2) {
            continue;
        }
        if value.get("error").is_some() {
            return Err(format!("shim rejected: {text}"));
        }
        break;
    }
    let reload = serde_json::json!({
        "id": 3,
        "method": "Page.reload",
        "params": { "ignoreCache": true }
    });
    ws.send(tokio_tungstenite::tungstenite::Message::Text(reload.to_string().into()))
        .await
        .map_err(|error| error.to_string())?;
    Ok(ws)
}

fn hold_debugger_socket(
    mut ws: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) {
    use futures::StreamExt;
    tokio::spawn(async move {
        while let Some(message) = ws.next().await {
            if message.is_err() {
                break;
            }
        }
    });
}

async fn install_onion_random_uuid(port: u16) -> Result<(), String> {
    let mut armed = std::collections::HashSet::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(8);
    let mut last_error = String::from("no page target");
    let mut quiet_since: Option<std::time::Instant> = None;
    loop {
        if std::time::Instant::now() >= deadline {
            break;
        }
        let urls = match page_debugger_urls(port).await {
            Ok(urls) => urls,
            Err(error) => {
                last_error = error;
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                continue;
            }
        };
        let mut fresh = false;
        for url in urls {
            if armed.contains(&url) {
                continue;
            }
            match arm_onion_page(&url).await {
                Ok(ws) => {
                    hold_debugger_socket(ws);
                    armed.insert(url);
                    fresh = true;
                }
                Err(error) => last_error = error,
            }
        }
        if armed.is_empty() {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            continue;
        }
        if fresh {
            quiet_since = Some(std::time::Instant::now());
        }
        // Edge opens a second page target just after the first.
        if quiet_since.is_some_and(|since| {
            since.elapsed() >= std::time::Duration::from_millis(1500)
        }) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    if armed.is_empty() {
        return Err(last_error);
    }
    eprintln!(
        "[dev-launch-debug] onion randomUUID shim holding {} page session(s)",
        armed.len()
    );
    Ok(())
}

async fn wait_for_child(mut child: tokio::process::Child) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("[dev-launch-debug] Ctrl-C to quit and kill the browser");
    tokio::select! {
        _ = ctrl_c_or_pending() => {
            eprintln!("[dev-launch-debug] shutting down…");
            let _ = child.kill().await;
        }
        _ = console_break() => {
            eprintln!("[dev-launch-debug] shutting down…");
            let _ = child.kill().await;
        }
        status = child.wait() => {
            match status {
                Ok(s) => eprintln!("[dev-launch-debug] browser exited: {s}"),
                Err(e) => eprintln!("[dev-launch-debug] browser wait error: {e}"),
            }
        }
    }
    Ok(())
}

async fn run_firefox(
    browser: &Path,
    profile_dir: &Path,
    url: Option<&str>,
    tor_socks: Option<SocketAddr>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(socks) = tor_socks {
        let path = profile_dir.join("user.js");
        std::fs::write(&path, firefox_proxy_user_js(socks))
            .map_err(|error| format!("firefox user.js: {error}"))?;
        eprintln!("[dev-launch-debug] firefox proxy user.js written");
    }
    let args = firefox_launch_args(profile_dir, url);
    let child = tokio::process::Command::new(browser)
        .args(&args)
        .stderr(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| format!("failed to spawn browser: {error}"))?;
    eprintln!(
        "[dev-launch-debug] browser spawned (pid {:?})",
        child.id()
    );
    eprintln!("[dev-launch-debug] ready — firefox");
    wait_for_child(child).await
}

async fn run_browser(
    kind: BrowserKind,
    browser: &Path,
    profile_dir: &Path,
    port: u16,
    url: Option<&str>,
    tor_socks: Option<SocketAddr>,
) -> Result<(), Box<dyn std::error::Error>> {
    if kind == BrowserKind::Firefox {
        return run_firefox(browser, profile_dir, url, tor_socks).await;
    }
    let args = debug_launch_args(port, profile_dir, url, tor_socks);

    let mut child = tokio::process::Command::new(browser)
        .args(&args)
        .stderr(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("failed to spawn browser: {e}"))?;

    eprintln!(
        "[dev-launch-debug] browser spawned (pid {:?}), waiting for DevTools URL…",
        child.id()
    );

    // Poll discover_ws_url until the browser is ready (up to 30 s).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let ws_url = loop {
        if std::time::Instant::now() >= deadline {
            let _ = child.kill().await;
            return Err("timed out waiting for Chrome DevTools to become available".into());
        }
        match discover_ws_url(port).await {
            Ok(url) => break url,
            Err(_) => {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        }
    };

    // Print the URL on stdout (for script consumption).
    if tor_socks.is_some() && url.is_some_and(http_onion_page) {
        match install_onion_random_uuid(port).await {
            Ok(()) => eprintln!("[dev-launch-debug] onion randomUUID shim installed"),
            Err(error) => eprintln!("[dev-launch-debug] onion randomUUID shim failed: {error}"),
        }
    }

    println!("{ws_url}");
    eprintln!("[dev-launch-debug] ready — DevTools ws URL printed on stdout");
    wait_for_child(child).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_launch_without_tor_has_no_proxy_arguments() {
        let args = debug_launch_args(
            9222,
            Path::new("profile"),
            Some("https://mylittlechart.org/"),
            None,
        );
        assert!(args.iter().all(|argument| {
            !argument.contains("socks5://")
                && !argument.starts_with("--proxy-")
                && argument != "--disable-quic"
                && !argument.starts_with("--force-webrtc-ip-handling-policy=")
                && !argument.starts_with("--host-resolver-rules=")
                && !argument.starts_with("--unsafely-treat-insecure-origin-as-secure=")
                && argument != "--no-proxy-server"
        }));
        assert_eq!(
            args.last().map(String::as_str),
            Some("https://mylittlechart.org/")
        );
        assert!(args
            .iter()
            .any(|argument| argument == "--remote-debugging-port=9222"));
        assert!(args
            .iter()
            .any(|argument| argument == "--user-data-dir=profile"));
    }

    #[test]
    fn debug_launch_tor_renders_one_loopback_socks5() {
        let socks: SocketAddr = "127.0.0.1:19050".parse().unwrap();
        let plain = debug_launch_args(9333, Path::new("profile"), Some("http://example.onion/"), None);
        let tor = debug_launch_args(
            9333,
            Path::new("profile"),
            Some("http://example.onion/"),
            Some(socks),
        );

        let socks_args: Vec<_> = tor
            .iter()
            .filter(|argument| argument.contains("socks5://127.0.0.1:"))
            .collect();
        assert_eq!(socks_args.len(), 1);
        assert_eq!(
            socks_args[0],
            "--proxy-server=socks5://127.0.0.1:19050"
        );
        assert_eq!(
            tor.iter()
                .filter(|argument| argument.starts_with("--proxy-server="))
                .count(),
            1
        );

        let proxy_at = tor
            .iter()
            .position(|argument| argument == "--proxy-server=socks5://127.0.0.1:19050")
            .unwrap();
        assert_eq!(tor[proxy_at + 1], "--proxy-bypass-list=<-loopback>");
        assert_eq!(tor[proxy_at + 2], "--disable-quic");
        assert_eq!(
            tor[proxy_at + 3],
            "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"
        );
        assert!(tor.iter().all(|argument| !argument.starts_with("--host-resolver-rules=")));
        assert!(tor.iter().all(|argument| {
            !argument.starts_with("--unsafely-treat-insecure-origin-as-secure=")
        }));
        assert_eq!(tor[proxy_at + 4], "http://example.onion/");
        let https = debug_launch_args(
            9333,
            Path::new("profile"),
            Some("https://example.onion/"),
            Some(socks),
        );
        assert!(https.iter().all(|argument| {
            !argument.starts_with("--unsafely-treat-insecure-origin-as-secure=")
        }));
        assert_eq!(https.last().map(String::as_str), Some("https://example.onion/"));

        let plain_prefix: Vec<_> = plain
            .iter()
            .filter(|argument| argument.as_str() != "http://example.onion/")
            .cloned()
            .collect();
        assert_eq!(&tor[..proxy_at], plain_prefix.as_slice());
    }

    #[test]
    fn firefox_tor_uses_remote_dns_and_no_chromium_proxy_flags() {
        let socks: SocketAddr = "127.0.0.1:19050".parse().unwrap();
        let prefs = firefox_proxy_user_js(socks);
        assert!(prefs.contains("network.proxy.socks_remote_dns\", true"));
        assert!(prefs.contains("network.proxy.socks_port\", 19050"));
        assert!(prefs.contains("network.trr.mode\", 5"));
        assert!(prefs.contains("network.dns.blockDotOnion\", false"));
        assert!(prefs.contains("dom.security.https_first\", false"));
        assert!(prefs.contains("dom.security.https_only_mode\", false"));
        assert!(!prefs.contains(".onion"));
        assert!(!prefs.contains("host-resolver"));
        let args = firefox_launch_args(Path::new("profile"), Some("http://example.onion/"));
        assert_eq!(args[0], "-no-remote");
        assert_eq!(args[1], "-profile");
        assert_eq!(args[2], "profile");
        assert_eq!(args[3], "http://example.onion/");
        assert!(args.iter().all(|argument| {
            !argument.contains("socks5://")
                && !argument.starts_with("--proxy-")
                && !argument.starts_with("--host-resolver-rules=")
                && !argument.starts_with("--unsafely-treat-insecure-origin-as-secure=")
        }));
    }

    #[test]
    fn debug_launch_tor_feature_and_config_messages_are_explicit() {
        assert!(TOR_FEATURE_REQUIRED.contains("--features tor"));
        assert!(TOR_CONFIG_REJECTED.contains("Arti"));
        assert!(!TOR_CONFIG_REJECTED.contains("D2B_TOR_EXE"));
    }

    #[test]
    fn socks_connect_accepts_a_domain_and_rejects_raw_addresses() {
        let domain = decode_socks_connect(b"\x05\x01\x00\x03\x0dexample.onion\x01\xbb").unwrap();
        assert_eq!(domain, ("example.onion".to_owned(), 443));

        let ipv4 = decode_socks_connect(b"\x05\x01\x00\x01\x01\x02\x03\x04\x00\x50").unwrap_err();
        assert_eq!(ipv4, 0x08);

        let mut ipv6 = vec![0x05, 0x01, 0x00, 0x04];
        ipv6.extend_from_slice(&[0u8; 16]);
        ipv6.extend_from_slice(&[0x01, 0xbb]);
        assert_eq!(decode_socks_connect(&ipv6).unwrap_err(), 0x08);

        let literal = decode_socks_connect(b"\x05\x01\x00\x03\x09\x31\x32\x37\x2e\x30\x2e\x30\x2e\x31\x01\xbb")
            .unwrap_err();
        assert_eq!(literal, 0x08);

        let bind = decode_socks_connect(b"\x05\x02\x00\x03\x0dexample.onion\x01\xbb").unwrap_err();
        assert_eq!(bind, 0x07);
    }
}
