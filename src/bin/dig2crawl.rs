//! `dig2crawl` — agent-driven CSS-selector discovery + fast-path extraction
//! CLI, ported from the retired standalone `dig2crawl` crate onto
//! `dig2browser`'s `crawler` feature (browser fetch: `dig2browser::crawl`;
//! site-profile model, parsers, storage: `dig2browser_crawler::profile`).

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use dig2browser::crawl::agent;
use dig2browser::crawl::fetch::{self, FetchedPage, Fetcher};
use std::path::PathBuf;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "dig2crawl", version, about = "Generic stealth web crawler with AI extraction")]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Enable verbose (debug) logging
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Enable Web Bot Auth signing with this JWKS URL
    #[arg(long, global = true)]
    bot_auth: Option<String>,

    /// Path to Ed25519 private key for bot auth (default: keys/bot.key)
    #[arg(long, global = true, default_value = "keys/bot.key")]
    bot_key: String,

    /// Launch browser in visible (non-headless) mode
    #[arg(long, global = true)]
    headed: bool,

    /// Use a persistent browser profile directory (reuses cookies/sessions)
    #[arg(long, global = true, value_name = "PATH")]
    browser_profile: Option<PathBuf>,

    /// Path to fingerprint JSON config (locale, timezone, viewport, stealth level, etc.)
    #[arg(long, global = true, value_name = "PATH")]
    fingerprint: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    /// Discover site structure with an agent: fetch page, extract selectors, validate
    Discover {
        /// URL of the page to analyse
        url: String,
        /// Natural-language goal describing what data to extract
        #[arg(short, long)]
        goal: String,
        /// Use plain HTTP instead of browser
        #[arg(long)]
        http_only: bool,
        /// CSS selector to wait for (browser mode only)
        #[arg(long)]
        wait_selector: Option<String>,
        /// Claude model to use
        #[arg(long, default_value = "claude-sonnet-4-6")]
        model: String,
        /// Directory to save discovered profile (default: output/<domain>/)
        #[arg(short, long)]
        output_dir: Option<PathBuf>,
        /// Maximum extraction level (1=CSS, 2=interactive, 3=visual, 4=captcha)
        #[arg(long, default_value = "3")]
        max_level: u8,
        /// Minimum records before considering extraction successful
        #[arg(long, default_value = "1")]
        min_records: usize,
        /// Minimum confidence before considering extraction successful
        #[arg(long, default_value = "0.5")]
        min_confidence: f64,
    },

    /// Extract data from a URL using a saved site profile
    Extract {
        /// URL to extract data from
        url: String,
        /// Path to profile.json produced by `discover`
        #[arg(short, long)]
        profile: PathBuf,
        /// Use plain HTTP instead of browser
        #[arg(long)]
        http_only: bool,
        /// Follow pagination up to this many pages (default: 1)
        #[arg(long, default_value = "1")]
        max_pages: usize,
        /// Save output to this file (JSONL); prints to stdout if omitted
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Build a DaemonSpec from a profile and export it as JSON or TOML
    ExportSpec {
        /// Path to profile.json
        profile: PathBuf,
        /// Cron expression, e.g. "0 6 * * *"
        #[arg(short, long)]
        schedule: String,
        /// Output path (.json or .toml)
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Fetch a single page and print its HTML (debug tool)
    Fetch {
        /// URL to fetch
        url: String,
        /// Use plain HTTP instead of browser
        #[arg(long)]
        http_only: bool,
        /// CSS selector to wait for (browser mode only)
        #[arg(long)]
        wait_selector: Option<String>,
        /// Save HTML to this file instead of printing to stdout
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Show page metadata (title, description, canonical)
        #[arg(long)]
        metadata: bool,
        /// Show JSON-LD blocks
        #[arg(long)]
        jsonld: bool,
        /// Show antibot detection result
        #[arg(long)]
        antibot: bool,
    },

    /// Apply a CSS selector to a page and print matches (debug tool)
    TestSelector {
        /// URL to fetch
        url: String,
        /// Container CSS selector
        #[arg(short, long)]
        selector: String,
        /// Additional field selectors in "name:css" format
        #[arg(short, long = "field")]
        fields: Vec<String>,
        /// Use plain HTTP instead of browser
        #[arg(long)]
        http_only: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let filter = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(filter))
        .with_target(false)
        .init();

    let signer: Option<Arc<dig2browser::bot_auth::RequestSigner>> =
        if let Some(jwks_url) = &cli.bot_auth {
            let identity = dig2browser::bot_auth::BotIdentity::new(
                "dig2browser",
                "https://github.com/ZENG3LD/dig2browser",
                jwks_url.clone(),
                &cli.bot_key,
            );
            let s = dig2browser::bot_auth::RequestSigner::from_identity(identity)
                .context("Failed to initialise bot auth signer")?;
            Some(Arc::new(s))
        } else {
            None
        };

    let browser_opts = BrowserOpts {
        headed: cli.headed,
        profile: cli.browser_profile,
        fingerprint: cli.fingerprint,
    };

    match cli.command {
        Command::Discover {
            url,
            goal,
            http_only,
            wait_selector,
            model,
            output_dir,
            max_level,
            min_records,
            min_confidence,
        } => {
            cmd_discover(DiscoverArgs {
                url,
                goal,
                browser: !http_only,
                wait_selector,
                model,
                output_dir,
                signer,
                browser_opts,
                max_level,
                min_records,
                min_confidence,
            })
            .await
        }

        Command::Extract {
            url,
            profile,
            http_only,
            max_pages,
            output,
        } => cmd_extract(url, profile, !http_only, max_pages, output, signer, browser_opts).await,

        Command::ExportSpec {
            profile,
            schedule,
            output,
        } => cmd_export_spec(profile, schedule, output),

        Command::Fetch {
            url,
            http_only,
            wait_selector,
            output,
            metadata,
            jsonld,
            antibot,
        } => {
            cmd_fetch(FetchArgs {
                url,
                browser: !http_only,
                wait_selector,
                output,
                show_metadata: metadata,
                show_jsonld: jsonld,
                show_antibot: antibot,
                signer,
                browser_opts,
            })
            .await
        }

        Command::TestSelector {
            url,
            selector,
            fields,
            http_only,
        } => cmd_test_selector(url, selector, fields, !http_only, signer, browser_opts).await,
    }
}

// ─── helpers ─────────────────────────────────────────────────────────────────

/// Arguments for [`cmd_discover`], grouped to keep the function signature
/// under clippy's `too_many_arguments` threshold.
struct DiscoverArgs {
    url: String,
    goal: String,
    browser: bool,
    wait_selector: Option<String>,
    model: String,
    output_dir: Option<PathBuf>,
    signer: Option<Arc<dig2browser::bot_auth::RequestSigner>>,
    browser_opts: BrowserOpts,
    max_level: u8,
    min_records: usize,
    min_confidence: f64,
}

/// Arguments for [`cmd_fetch`], grouped to keep the function signature under
/// clippy's `too_many_arguments` threshold.
struct FetchArgs {
    url: String,
    browser: bool,
    wait_selector: Option<String>,
    output: Option<PathBuf>,
    show_metadata: bool,
    show_jsonld: bool,
    show_antibot: bool,
    signer: Option<Arc<dig2browser::bot_auth::RequestSigner>>,
    browser_opts: BrowserOpts,
}

/// Browser-specific options collected from global CLI flags.
struct BrowserOpts {
    /// When `true`, launches Chrome in visible (non-headless) mode.
    headed: bool,
    /// When `Some(path)`, uses a persistent profile directory to reuse cookies/sessions.
    profile: Option<PathBuf>,
    /// Path to fingerprint JSON config.
    fingerprint: Option<PathBuf>,
}

impl BrowserOpts {
    /// Resolve the profile directory. If no explicit `--browser-profile` was given,
    /// auto-creates `<TEMP>/dig2crawl-profiles/<domain>/`.
    fn resolve_profile(&mut self, url_str: &str) {
        if self.profile.is_none() {
            if let Ok(parsed) = url::Url::parse(url_str) {
                if let Some(domain) = parsed.host_str() {
                    let dir = std::env::temp_dir()
                        .join("dig2crawl-profiles")
                        .join(domain);
                    let _ = std::fs::create_dir_all(&dir);
                    let lockfile = dir.join("lockfile");
                    if lockfile.exists() {
                        let _ = std::fs::remove_file(&lockfile);
                    }
                    self.profile = Some(dir);
                }
            }
        }
    }
}

/// JSON-serialisable fingerprint configuration.
/// All fields are optional — omitted fields use `StealthConfig::default()` values.
#[derive(serde::Deserialize, Default)]
struct FingerprintConfig {
    /// Stealth level: "basic", "standard_no_webgl", "standard", "full"
    level: Option<String>,
    /// BCP-47 locale (e.g. "ru-RU", "en-US")
    locale: Option<String>,
    /// IANA timezone (e.g. "Europe/Moscow")
    timezone: Option<String>,
    /// Viewport [width, height]
    viewport: Option<[u32; 2]>,
    /// navigator.hardwareConcurrency
    hardware_concurrency: Option<u32>,
    /// navigator.deviceMemory (GB)
    device_memory_gb: Option<u32>,
    /// Custom User-Agent string
    user_agent: Option<String>,
    /// Browser preference: "auto", "chrome", "edge", "firefox"
    browser: Option<String>,
}

impl FingerprintConfig {
    fn into_configs(self) -> (dig2browser::StealthConfig, dig2browser::BrowserPreference) {
        let mut cfg = dig2browser::StealthConfig::default();
        if let Some(level) = self.level {
            cfg.level = match level.as_str() {
                "basic" => dig2browser::stealth::StealthLevel::Basic,
                "standard_no_webgl" => dig2browser::stealth::StealthLevel::StandardNoWebGL,
                "standard" => dig2browser::stealth::StealthLevel::Standard,
                "full" => dig2browser::stealth::StealthLevel::Full,
                _ => cfg.level,
            };
        }
        if let Some(locale) = self.locale {
            cfg.locale.locale = locale;
        }
        if let Some(tz) = self.timezone {
            cfg.locale.timezone = Some(tz);
        }
        if let Some([w, h]) = self.viewport {
            cfg.viewport = (w, h);
        }
        if let Some(hc) = self.hardware_concurrency {
            cfg.hardware_concurrency = hc;
        }
        if let Some(dm) = self.device_memory_gb {
            cfg.device_memory_gb = dm;
        }
        if let Some(ua) = self.user_agent {
            cfg.user_agent = ua;
        }
        let browser_pref = match self.browser.as_deref() {
            Some("chrome") => dig2browser::BrowserPreference::ChromeOnly,
            Some("edge") => dig2browser::BrowserPreference::EdgeOnly,
            Some("firefox") => dig2browser::BrowserPreference::Firefox,
            _ => dig2browser::BrowserPreference::Auto,
        };
        (cfg, browser_pref)
    }
}

fn load_fingerprint(
    path: &Option<PathBuf>,
) -> Result<(dig2browser::StealthConfig, dig2browser::BrowserPreference)> {
    match path {
        Some(p) => {
            let json = std::fs::read_to_string(p)
                .with_context(|| format!("Failed to read fingerprint config: {}", p.display()))?;
            let cfg: FingerprintConfig = serde_json::from_str(&json)
                .with_context(|| format!("Failed to parse fingerprint config: {}", p.display()))?;
            Ok(cfg.into_configs())
        }
        None => Ok((
            dig2browser::StealthConfig::default(),
            dig2browser::BrowserPreference::Auto,
        )),
    }
}

/// Owns either a browser or HTTP fetcher and shuts the browser down on exit.
enum FetcherHandle {
    Browser(fetch::browser::BrowserFetcher),
    Http(fetch::http::HttpFetcher),
}

impl FetcherHandle {
    fn as_fetcher(&self) -> &dyn Fetcher {
        match self {
            Self::Browser(f) => f,
            Self::Http(f) => f,
        }
    }

    /// Shuts down the browser process if one was started.
    async fn shutdown(self) {
        if let Self::Browser(f) = self {
            let _ = f.shutdown().await;
        }
    }
}

async fn make_fetcher(
    browser: bool,
    wait_selector: Option<String>,
    signer: Option<Arc<dig2browser::bot_auth::RequestSigner>>,
    opts: BrowserOpts,
) -> Result<FetcherHandle> {
    if browser {
        let (stealth, browser_pref) = load_fingerprint(&opts.fingerprint)?;
        let mut launch = dig2browser::LaunchConfig {
            headless: !opts.headed,
            browser_pref,
            ..dig2browser::LaunchConfig::default()
        };
        if let Some(path) = opts.profile {
            launch.profile = dig2browser::BrowserProfile::Persistent(path);
        }
        let fetcher = fetch::browser::BrowserFetcher::new(launch, stealth, wait_selector, signer)
            .await
            .context("Failed to start browser")?;
        Ok(FetcherHandle::Browser(fetcher))
    } else {
        let fetcher = fetch::http::HttpFetcher::new(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 dig2crawl/0.1",
            signer,
        )
        .context("Failed to create HTTP client")?;
        Ok(FetcherHandle::Http(fetcher))
    }
}

async fn fetch_page(fetcher: &dyn Fetcher, url_str: &str) -> Result<FetchedPage> {
    use url::Url;
    let url = Url::parse(url_str).with_context(|| format!("Invalid URL: {url_str}"))?;
    fetcher
        .fetch(&url)
        .await
        .with_context(|| format!("Failed to fetch {url_str}"))
        .map_err(anyhow::Error::from)
}

/// Parse the raw agent response string into `AgentResponse`.
///
/// Claude sometimes wraps JSON in a markdown code fence — we strip those.
/// The sanitizer also fixes invalid JSON escape sequences (e.g. `\d`, `\s`)
/// that Claude emits inside regex strings.
fn parse_agent_response(raw: &str) -> Result<agent::protocol::AgentResponse> {
    let json_str = extract_json_block(raw);
    let sanitized = sanitize_json_escapes(json_str);
    serde_json::from_str(&sanitized)
        .with_context(|| format!("Failed to parse agent response as JSON:\n{sanitized}"))
}

/// Fix invalid JSON escape sequences that Claude sometimes emits inside strings.
///
/// JSON only allows `\"`, `\\`, `\/`, `\b`, `\f`, `\n`, `\r`, `\t`, and `\uXXXX`.
/// Any other `\x` sequence (e.g. `\d`, `\s`, `\w` from regex patterns) is invalid
/// and will cause `serde_json` to reject the document.
///
/// This function scans the raw JSON text character-by-character. When inside a
/// JSON string it doubles any backslash that is followed by an unrecognised escape
/// character, turning `\d` -> `\\d` so the string survives round-trip through the
/// JSON parser unchanged.
fn sanitize_json_escapes(s: &str) -> String {
    fn is_valid_json_escape(c: char) -> bool {
        matches!(c, '"' | '\\' | '/' | 'b' | 'f' | 'n' | 'r' | 't' | 'u')
    }

    let mut out = String::with_capacity(s.len() + 32);
    let mut chars = s.chars().peekable();
    let mut in_string = false;

    while let Some(c) = chars.next() {
        match c {
            '"' if !in_string => {
                in_string = true;
                out.push(c);
            }
            '"' if in_string => {
                in_string = false;
                out.push(c);
            }
            '\\' if in_string => match chars.peek().copied() {
                Some(next) if is_valid_json_escape(next) => {
                    out.push('\\');
                    out.push(chars.next().unwrap());
                    if next == 'u' {
                        for _ in 0..4 {
                            if let Some(h) = chars.next() {
                                out.push(h);
                            }
                        }
                    }
                }
                Some(_) => {
                    out.push('\\');
                    out.push('\\');
                }
                None => {
                    out.push('\\');
                }
            },
            other => out.push(other),
        }
    }

    out
}

/// Extract the first JSON object from a string that may contain markdown fences.
fn extract_json_block(s: &str) -> &str {
    if let Some(start) = s.find("```json") {
        let inner = &s[start + 7..];
        if let Some(end) = inner.find("```") {
            return inner[..end].trim();
        }
    }
    if let Some(start) = s.find("```") {
        let inner = &s[start + 3..];
        if let Some(end) = inner.find("```") {
            return inner[..end].trim();
        }
    }
    if let (Some(start), Some(end)) = (s.find('{'), s.rfind('}')) {
        if start <= end {
            return &s[start..=end];
        }
    }
    s.trim()
}

/// Check if a raw agent response string signals auto-navigation.
///
/// Claude may return `{"status": "navigate", "target_url": "https://..."}` when
/// it determines the current page does not contain the goal data. Returns the
/// target URL if found, or `None` if this is a normal response.
fn extract_navigate_target(raw: &str) -> Option<String> {
    let json_str = extract_json_block(raw);
    let val: serde_json::Value = serde_json::from_str(json_str).ok()?;
    let status = val.get("status").and_then(|v| v.as_str())?;
    if status != "navigate" {
        return None;
    }
    val.get("target_url")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Extract `ExtractionMode::JsonPath` from an `AgentResponse` if Claude returned
/// `"extraction_mode": "json_path"` with `json_source` and `json_base_path`.
fn extract_json_path_mode(
    response: &agent::protocol::AgentResponse,
) -> Option<dig2browser_crawler::profile::ExtractionMode> {
    use dig2browser_crawler::profile::ExtractionMode;

    let raw_val = serde_json::to_value(response).ok()?;
    let mode_str = raw_val.get("extraction_mode").and_then(|v| v.as_str())?;
    if mode_str != "json_path" {
        return None;
    }
    let json_source = raw_val.get("json_source")?.as_str()?.to_string();
    let base_path = raw_val
        .get("json_base_path")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    Some(ExtractionMode::JsonPath {
        json_source,
        base_path,
    })
}

/// Build a `dig2browser_crawler::profile::SiteProfile` from an `AgentResponse`.
///
/// The discovery response contains `field_configs` (v2) and `updated_memory`
/// with the container selector. We prefer the v2 field configs when present.
fn build_site_profile(
    domain: &str,
    response: &agent::protocol::AgentResponse,
    browser_required: bool,
) -> Result<dig2browser_crawler::profile::SiteProfile> {
    use chrono::Utc;
    use dig2browser_crawler::profile::{ExtractMode, FieldConfig, SiteProfile};

    let container_selector = response
        .updated_memory
        .as_ref()
        .and_then(|m| m.selectors.values().next())
        .and_then(|s| s.container_selector.clone())
        .unwrap_or_else(|| "div".to_string());

    let fields: Vec<FieldConfig> = if !response.field_configs.is_empty() {
        response
            .field_configs
            .iter()
            .filter(|fc| fc.selector.is_some())
            .map(|fc| FieldConfig {
                name: fc.name.clone(),
                selector: fc.selector.clone().unwrap_or_default(),
                extract: match &fc.extract {
                    agent::protocol::ExtractMode::Text => ExtractMode::Text,
                    agent::protocol::ExtractMode::Attribute(a) => ExtractMode::Attribute(a.clone()),
                    agent::protocol::ExtractMode::Html => ExtractMode::Html,
                    agent::protocol::ExtractMode::OuterHtml => ExtractMode::OuterHtml,
                },
                prefix: fc.prefix.clone(),
                transform: fc.transform.as_ref().map(|t| match t {
                    agent::protocol::Transform::Trim => dig2browser_crawler::profile::Transform::Trim,
                    agent::protocol::Transform::Lowercase => {
                        dig2browser_crawler::profile::Transform::Lowercase
                    }
                    agent::protocol::Transform::Uppercase => {
                        dig2browser_crawler::profile::Transform::Uppercase
                    }
                    agent::protocol::Transform::Regex(p) => {
                        dig2browser_crawler::profile::Transform::Regex(p.clone())
                    }
                    agent::protocol::Transform::Replace(f, t) => {
                        dig2browser_crawler::profile::Transform::Replace(f.clone(), t.clone())
                    }
                    agent::protocol::Transform::ParseNumber => {
                        dig2browser_crawler::profile::Transform::ParseNumber
                    }
                }),
            })
            .collect()
    } else {
        response
            .updated_memory
            .as_ref()
            .and_then(|m| m.selectors.values().next())
            .map(|s| {
                s.fields
                    .iter()
                    .filter_map(|(name, sel)| {
                        let selector_str = match sel {
                            serde_json::Value::String(s) => Some(s.clone()),
                            serde_json::Value::Object(obj) => obj
                                .get("selector")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string()),
                            _ => None,
                        };
                        selector_str.map(|s| FieldConfig {
                            name: name.clone(),
                            selector: s,
                            extract: ExtractMode::Text,
                            prefix: None,
                            transform: None,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    };

    let confidence = response.confidence.map(|c| c as f64).unwrap_or(0.5);
    let now = Utc::now();

    Ok(SiteProfile {
        domain: domain.to_string(),
        container_selector,
        fields,
        pagination: None,
        requires_browser: browser_required,
        confidence,
        validated: false,
        created_at: now,
        last_used_at: now,
        extraction_mode: dig2browser_crawler::profile::ExtractionMode::default(),
    })
}

// ─── commands ────────────────────────────────────────────────────────────────

/// Decide whether L1 results are insufficient and we should try a higher level.
fn should_escalate(records: usize, confidence: f64, min_records: usize, min_confidence: f64) -> bool {
    records < min_records || confidence < min_confidence
}

/// Extract records from SPA JSON blocks using the `JsonPath` extraction mode
/// stored in the profile.
///
/// Walks to `base_path` inside the matching JSON block and returns the array
/// of JSON objects found there. Returns an empty vec if anything is missing.
fn extract_via_json_path(
    json_blocks: &[dig2browser_crawler::profile::parse::SpaJsonBlock],
    profile: &dig2browser_crawler::profile::SiteProfile,
) -> Vec<serde_json::Value> {
    use dig2browser_crawler::profile::ExtractionMode;

    let (json_source, base_path) = match &profile.extraction_mode {
        ExtractionMode::JsonPath {
            json_source,
            base_path,
        } => (json_source.as_str(), base_path.as_str()),
        ExtractionMode::CssSelectors => return Vec::new(),
    };

    let block = json_blocks
        .iter()
        .find(|b| b.source.display_name() == json_source);
    let block = block.or_else(|| {
        if json_blocks.len() == 1 {
            json_blocks.first()
        } else {
            None
        }
    });

    let block = match block {
        Some(b) => b,
        None => {
            tracing::warn!(json_source, "No SPA JSON block found for json_path extraction");
            return Vec::new();
        }
    };

    let node =
        dig2browser_crawler::profile::parse::json_data::navigate_json_path(&block.data, base_path);
    match node {
        Some(serde_json::Value::Array(arr)) => arr.iter().filter(|v| v.is_object()).cloned().collect(),
        Some(other) if other.is_object() => vec![other.clone()],
        _ => {
            tracing::warn!(base_path, "base_path did not resolve to an array in SPA JSON");
            Vec::new()
        }
    }
}

/// Strip noise from HTML to stay within Claude Code's Read tool token limit (~10 000 tokens).
///
/// Removes `<script>`, `<style>`, `<svg>`, `<noscript>`, HTML comments,
/// and collapses consecutive whitespace. Preserves the DOM structure that
/// Claude needs for CSS selector discovery.
fn strip_html_noise(html: &str) -> String {
    let mut cleaned = std::borrow::Cow::Borrowed(html);
    for tag in &["script", "style", "svg", "noscript"] {
        let re = regex::Regex::new(&format!(r"(?is)<{tag}\b[^>]*>.*?</{tag}\s*>")).unwrap();
        cleaned = std::borrow::Cow::Owned(re.replace_all(&cleaned, "").into_owned());
    }

    let re_comments = regex::Regex::new(r"(?s)<!--.*?-->").unwrap();
    let cleaned = re_comments.replace_all(&cleaned, "");

    let re_data = regex::Regex::new(r#"\s+data-[\w-]+="[^"]{100,}""#).unwrap();
    let mut cleaned = re_data.replace_all(&cleaned, "");

    let re_empty_attr = regex::Regex::new(r#"\s+(class|id)="""#).unwrap();
    cleaned = std::borrow::Cow::Owned(re_empty_attr.replace_all(&cleaned, "").into_owned());

    let re_ws = regex::Regex::new(r"\s{2,}").unwrap();
    let cleaned = re_ws.replace_all(&cleaned, " ");

    cleaned.into_owned()
}

async fn cmd_discover(args: DiscoverArgs) -> Result<()> {
    let DiscoverArgs {
        url: url_str,
        goal,
        browser,
        wait_selector,
        model,
        output_dir,
        signer,
        mut browser_opts,
        max_level,
        min_records,
        min_confidence,
    } = args;
    println!("Discovering site structure for: {url_str}");
    println!("Goal: {goal}");
    println!();

    println!("[1/5] Fetching page...");
    browser_opts.resolve_profile(&url_str);
    let handle = make_fetcher(browser, wait_selector, signer, browser_opts).await?;
    let page = fetch_page(handle.as_fetcher(), &url_str).await?;
    println!("      OK — {} bytes, {}ms", page.body.len(), page.fetch_ms);

    println!("[2/5] Checking for anti-bot protection...");
    let antibot = dig2browser_crawler::profile::parse::AntiBotDetector::new().detect(&page.body);
    if antibot.detected {
        eprintln!(
            "WARNING: Anti-bot detected! Provider: {}, Type: {}",
            antibot.provider.as_deref().unwrap_or("unknown"),
            antibot.challenge_type.as_deref().unwrap_or("unknown")
        );
        eprintln!("         Extraction may fail or produce empty results.");
    } else {
        println!("      Clean (no anti-bot detected)");
    }

    let spa_blocks = dig2browser_crawler::profile::parse::extract_spa_json(&page.body);
    if !spa_blocks.is_empty() {
        println!(
            "      SPA JSON: {} block(s) found ({})",
            spa_blocks.len(),
            spa_blocks
                .iter()
                .map(|b| b.source.display_name())
                .collect::<Vec<_>>()
                .join(", "),
        );
    }

    println!("[3/5] Extracting JSON-LD and metadata...");
    let jsonld_items = dig2browser_crawler::profile::parse::JsonLdExtractor::extract_jsonld(&page.body);
    let parsed_url = url::Url::parse(&url_str)?;
    let metadata =
        dig2browser_crawler::profile::parse::MetadataExtractor::new().extract(&page.body, Some(&parsed_url));
    if !jsonld_items.is_empty() {
        println!("      JSON-LD: {} block(s) found", jsonld_items.len());
    }
    if let Some(title) = &metadata.title {
        println!("      Title: {title}");
    }

    println!("[4/5] Starting Claude session...");
    let mut session = agent::session::AgentSession::start()
        .await
        .context("Failed to start Claude agent session. Is `claude` CLI installed?")?
        .with_model(model);

    let temp_base = std::env::var("USERPROFILE")
        .map(|p| PathBuf::from(p).join("AppData").join("Local").join("Temp"))
        .unwrap_or_else(|_| std::env::temp_dir());
    let job_dir = temp_base.join(format!("dig2crawl_{}", std::process::id()));
    tokio::fs::create_dir_all(&job_dir)
        .await
        .with_context(|| format!("Failed to create job dir: {}", job_dir.display()))?;

    let spa_json_path: Option<std::path::PathBuf> = if !spa_blocks.is_empty() {
        let path = job_dir.join("spa_data.json");
        let combined: Vec<serde_json::Value> = spa_blocks
            .iter()
            .map(|b| {
                serde_json::json!({
                    "source": b.source.display_name(),
                    "data": &b.data,
                })
            })
            .collect();
        let json_bytes = serde_json::to_string_pretty(&combined).unwrap_or_default();
        tokio::fs::write(&path, &json_bytes)
            .await
            .with_context(|| format!("Failed to write SPA JSON to {}", path.display()))?;
        println!("      SPA JSON saved to: {}", path.display());
        Some(path)
    } else {
        None
    };

    let spa_source_name: Option<String> = spa_blocks
        .first()
        .map(|b| b.source.display_name().to_string());

    let html_path = job_dir.join("page.html");
    let cleaned_html = strip_html_noise(&page.body);
    tokio::fs::write(&html_path, &cleaned_html)
        .await
        .with_context(|| format!("Failed to write HTML to {}", html_path.display()))?;
    if cleaned_html.len() < page.body.len() {
        println!(
            "      HTML cleaned: {} -> {} bytes ({:.0}% reduction)",
            page.body.len(),
            cleaned_html.len(),
            (1.0 - cleaned_html.len() as f64 / page.body.len() as f64) * 100.0,
        );
    }

    let jsonld_context = if !jsonld_items.is_empty() {
        let jsonld_str = serde_json::to_string_pretty(&jsonld_items).unwrap_or_default();
        format!("\n\n## JSON-LD structured data found on page\n```json\n{jsonld_str}\n```")
    } else {
        String::new()
    };
    let full_goal = format!("{goal}{jsonld_context}");

    let discovery_prompt = agent::prompts::build_discovery_prompt(
        &html_path,
        &full_goal,
        spa_json_path.as_deref(),
        spa_source_name.as_deref(),
    );

    println!(
        "      Sending discovery prompt ({} chars, HTML: {} bytes)...",
        discovery_prompt.len(),
        page.body.len(),
    );

    let discovery_raw = session
        .send_prompt(&discovery_prompt)
        .await
        .context("Discovery prompt failed")?;

    tracing::debug!(response_len = discovery_raw.len(), "Discovery response received");

    let (discovery_response, page, _url_str_final) = {
        let mut resp_raw = discovery_raw;
        let mut current_page = page;
        let mut current_url = url_str.clone();
        let mut nav_count = 0u8;

        loop {
            let nav_target = extract_navigate_target(&resp_raw);

            if let Some(target_url) = nav_target {
                if nav_count >= 2 {
                    println!("      Auto-navigation limit reached (max 2) — stopping at {current_url}");
                    break;
                }
                println!("      Auto-navigate -> {target_url}");
                nav_count += 1;
                current_url = target_url.clone();

                match fetch_page(handle.as_fetcher(), &target_url).await {
                    Ok(new_page) => {
                        current_page = new_page;

                        let new_html_cleaned = strip_html_noise(&current_page.body);
                        let _ = tokio::fs::write(&html_path, &new_html_cleaned).await;

                        let new_prompt = agent::prompts::build_discovery_prompt(
                            &html_path,
                            &full_goal,
                            spa_json_path.as_deref(),
                            spa_source_name.as_deref(),
                        );
                        match session.send_prompt(&new_prompt).await {
                            Ok(raw) => {
                                resp_raw = raw;
                            }
                            Err(e) => {
                                eprintln!("      Discovery re-prompt after navigate failed: {e}");
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("      Auto-navigate fetch failed: {e}");
                        break;
                    }
                }
            } else {
                break;
            }
        }

        let resp = parse_agent_response(&resp_raw).context("Could not parse discovery response")?;
        (resp, current_page, current_url)
    };

    let domain = parsed_url.host_str().unwrap_or("unknown").to_string();

    let extraction_mode = extract_json_path_mode(&discovery_response);

    let mut profile = build_site_profile(&domain, &discovery_response, browser)?;

    if let Some(mode) = extraction_mode {
        profile.extraction_mode = mode;
        println!("      Extraction mode: JsonPath (SPA JSON)");
    }

    println!(
        "      Discovered {} field(s), container: {:?}, confidence: {:.2}",
        profile.fields.len(),
        profile.container_selector,
        profile.confidence,
    );

    println!("[5/5] Validating selectors on fetched page...");
    let extractor = dig2browser_crawler::profile::parse::SelectorExtractor::new();
    let mut extracted_records = match &profile.extraction_mode {
        dig2browser_crawler::profile::ExtractionMode::JsonPath { .. } => {
            let records = extract_via_json_path(&spa_blocks, &profile);
            println!("      JsonPath extraction: {} record(s)", records.len());
            records
        }
        dig2browser_crawler::profile::ExtractionMode::CssSelectors => {
            extractor.extract(&page.body, &profile)
        }
    };

    println!(
        "      Extracted {} record(s) with discovered selectors",
        extracted_records.len()
    );

    if !extracted_records.is_empty() {
        let snapshot = discovery_response.updated_memory.clone().unwrap_or_default();
        let validation_prompt = agent::prompts::build_validation_prompt(&extracted_records, &snapshot);

        println!("      Sending validation prompt...");
        match session.send_prompt(&validation_prompt).await {
            Ok(validation_raw) => {
                if let Ok(validation_response) = parse_agent_response(&validation_raw) {
                    if let Some(vr) = &validation_response.validation_result {
                        println!(
                            "      Validation: {} — {} items extracted, confidence {:.2}",
                            if vr.passed { "PASSED" } else { "FAILED" },
                            vr.items_extracted,
                            vr.confidence,
                        );
                        if !vr.issues.is_empty() {
                            println!("      Issues:");
                            for issue in &vr.issues {
                                println!("        - {issue}");
                            }
                        }
                        profile.validated = vr.passed;
                        if vr.confidence > 0.0 {
                            profile.confidence = vr.confidence as f64;
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("      Validation prompt failed: {e}");
            }
        }
    } else {
        println!("      No records extracted — validation skipped");
    }

    let mut current_level: u8 = 1;

    if browser
        && max_level >= 2
        && should_escalate(extracted_records.len(), profile.confidence, min_records, min_confidence)
    {
        println!();
        println!("[L2] Escalating to interactive extraction (clicks/scrolls)...");
        current_level = 2;

        let l1_failure_reason = format!(
            "only {} record(s) extracted (need {}, confidence {:.2} below {:.2})",
            extracted_records.len(),
            min_records,
            profile.confidence,
            min_confidence,
        );
        let interactive_prompt =
            agent::prompts::build_interactive_prompt(&html_path, &goal, &l1_failure_reason);

        match session.send_prompt(&interactive_prompt).await {
            Ok(l2_raw) => {
                if l2_raw.is_empty() {
                    eprintln!("      L2 response is empty — Claude produced no output");
                } else {
                    match parse_agent_response(&l2_raw) {
                        Ok(l2_resp) => {
                            if !l2_resp.browser_actions.is_empty() {
                                println!(
                                    "      Claude suggested {} browser action(s)",
                                    l2_resp.browser_actions.len()
                                );
                                for (i, action) in l2_resp.browser_actions.iter().enumerate() {
                                    println!(
                                        "        [{}/{}] {:?}",
                                        i + 1,
                                        l2_resp.browser_actions.len(),
                                        action
                                    );
                                }

                                if let FetcherHandle::Browser(ref browser_fetcher) = handle {
                                    let parsed = url::Url::parse(&url_str)?;
                                    match browser_fetcher
                                        .fetch_with_actions(&parsed, &l2_resp.browser_actions)
                                        .await
                                    {
                                        Ok(actioned_page) => {
                                            println!("      Actions executed — re-extracting...");

                                            let l2_html_path = job_dir.join("l2_page.html");
                                            let l2_cleaned = strip_html_noise(&actioned_page.body);
                                            if let Err(e) =
                                                tokio::fs::write(&l2_html_path, &l2_cleaned).await
                                            {
                                                eprintln!("      Warning: failed to save L2 HTML: {e}");
                                            }

                                            let l2_records = extractor.extract(&actioned_page.body, &profile);
                                            println!(
                                                "      L2 extracted {} record(s) (was {})",
                                                l2_records.len(),
                                                extracted_records.len()
                                            );
                                            if l2_records.len() > extracted_records.len() {
                                                extracted_records = l2_records;
                                            } else {
                                                let actions_json =
                                                    serde_json::to_string_pretty(&l2_resp.browser_actions)
                                                        .unwrap_or_else(|_| "[]".to_string());
                                                let post_action_prompt = agent::prompts::build_post_action_prompt(
                                                    &l2_html_path,
                                                    &goal,
                                                    &actions_json,
                                                );
                                                println!("      Sending post-action re-extraction prompt...");
                                                match session.send_prompt(&post_action_prompt).await {
                                                    Ok(reextract_raw) => {
                                                        if let Ok(reextract_resp) =
                                                            parse_agent_response(&reextract_raw)
                                                        {
                                                            if !reextract_resp.field_configs.is_empty() {
                                                                if let Ok(new_profile) = build_site_profile(
                                                                    &domain,
                                                                    &reextract_resp,
                                                                    browser,
                                                                ) {
                                                                    let new_records = extractor
                                                                        .extract(&actioned_page.body, &new_profile);
                                                                    println!(
                                                                        "      Post-action re-discovery: {} record(s)",
                                                                        new_records.len()
                                                                    );
                                                                    if new_records.len() > extracted_records.len() {
                                                                        extracted_records = new_records;
                                                                        profile = new_profile;
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                    Err(e) => {
                                                        eprintln!("      Post-action re-extraction failed: {e}");
                                                    }
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            eprintln!("      L2 action execution failed: {e}");
                                        }
                                    }
                                }
                            } else {
                                println!("      Claude suggested no browser actions — skipping L2");
                            }
                            if !l2_resp.logs.is_empty() {
                                for log in &l2_resp.logs {
                                    println!("      [claude] {log}");
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("      L2 JSON parse error: {e}");
                            eprintln!("      Raw (first 500 chars): {}", &l2_raw[..l2_raw.len().min(500)]);
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("      L2 Claude session failed: {e}");
            }
        }
    }

    if browser
        && max_level >= 3
        && current_level < 3
        && should_escalate(extracted_records.len(), profile.confidence, min_records, min_confidence)
    {
        println!();
        println!("[L3] Escalating to visual extraction (screenshot + Claude Vision)...");

        if let FetcherHandle::Browser(ref browser_fetcher) = handle {
            let parsed = url::Url::parse(&url_str)?;
            match browser_fetcher.open_page(&parsed).await {
                Ok(live_page) => {
                    let screenshot = live_page.screenshot().await.unwrap_or_default();
                    if !screenshot.is_empty() {
                        let screenshot_path = job_dir.join("l3_screenshot.png");
                        tokio::fs::write(&screenshot_path, &screenshot).await?;
                        println!("      Screenshot captured ({} bytes)", screenshot.len());

                        let visual_prompt =
                            agent::prompts::build_visual_prompt(&screenshot_path, &goal, &page.body);

                        match session.send_prompt(&visual_prompt).await {
                            Ok(l3_raw) => {
                                if let Ok(l3_resp) = parse_agent_response(&l3_raw) {
                                    if !l3_resp.visual_actions.is_empty() {
                                        println!(
                                            "      Claude Vision suggested {} action(s)",
                                            l3_resp.visual_actions.len()
                                        );
                                        let browser_actions: Vec<agent::actions::BrowserAction> = l3_resp
                                            .visual_actions
                                            .iter()
                                            .filter_map(|va| va.to_browser_action())
                                            .collect();
                                        let outcome =
                                            fetch::interactive::execute_actions(&live_page, &browser_actions)
                                                .await;
                                        match outcome {
                                            Ok(result) => {
                                                println!("      Visual actions executed — re-extracting...");
                                                let l3_records = extractor.extract(&result.html, &profile);
                                                println!(
                                                    "      L3 extracted {} record(s) (was {})",
                                                    l3_records.len(),
                                                    extracted_records.len()
                                                );
                                                if l3_records.len() > extracted_records.len() {
                                                    extracted_records = l3_records;
                                                }
                                            }
                                            Err(e) => eprintln!("      L3 visual action execution failed: {e}"),
                                        }
                                    } else {
                                        println!("      Claude Vision suggested no actions");
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("      L3 Claude session failed: {e}");
                            }
                        }
                    }
                }
                Err(e) => eprintln!("      L3 page open failed: {e}"),
            }
        }
    }

    if max_level >= 4 && antibot.detected {
        println!();
        println!("[L4] Captcha/anti-bot detected but L4 solver is not implemented.");
    }

    session.close().await;
    handle.shutdown().await;

    let _ = tokio::fs::remove_dir_all(&job_dir).await;

    let out_dir = output_dir.unwrap_or_else(|| PathBuf::from("output").join(&domain));
    std::fs::create_dir_all(&out_dir)
        .with_context(|| format!("Failed to create output directory: {}", out_dir.display()))?;

    let profile_path = out_dir.join("profile.json");
    let profile_json = serde_json::to_string_pretty(&profile)?;
    std::fs::write(&profile_path, &profile_json)
        .with_context(|| format!("Failed to write profile: {}", profile_path.display()))?;

    println!();
    println!("Profile saved to: {}", profile_path.display());
    println!();
    println!("Summary:");
    println!("  Domain:     {}", profile.domain);
    println!("  Container:  {}", profile.container_selector);
    println!("  Fields:     {}", profile.fields.len());
    for f in &profile.fields {
        println!("    - {} ({})", f.name, f.selector);
    }
    println!("  Confidence: {:.2}", profile.confidence);
    println!("  Validated:  {}", profile.validated);
    if !extracted_records.is_empty() {
        println!();
        println!("Sample extracted data ({} record(s)):", extracted_records.len().min(3));
        for record in extracted_records.iter().take(3) {
            println!("  {}", serde_json::to_string(record).unwrap_or_default());
        }
    }

    Ok(())
}

async fn cmd_extract(
    url_str: String,
    profile_path: PathBuf,
    browser: bool,
    max_pages: usize,
    output: Option<PathBuf>,
    signer: Option<Arc<dig2browser::bot_auth::RequestSigner>>,
    mut browser_opts: BrowserOpts,
) -> Result<()> {
    let profile_json = std::fs::read_to_string(&profile_path)
        .with_context(|| format!("Failed to read profile: {}", profile_path.display()))?;
    let profile: dig2browser_crawler::profile::SiteProfile = serde_json::from_str(&profile_json)
        .with_context(|| format!("Failed to parse profile: {}", profile_path.display()))?;

    browser_opts.resolve_profile(&url_str);
    let handle = make_fetcher(browser || profile.requires_browser, None, signer, browser_opts).await?;
    let extractor = dig2browser_crawler::profile::parse::SelectorExtractor::new();

    let mut all_records: Vec<serde_json::Value> = Vec::new();
    let mut current_url = url_str.clone();
    let mut pages_done = 0;

    while pages_done < max_pages {
        println!("Fetching page {}/{}: {current_url}", pages_done + 1, max_pages);
        let page = fetch_page(handle.as_fetcher(), &current_url).await?;
        let records = extractor.extract(&page.body, &profile);
        println!("  Extracted {} record(s)", records.len());
        all_records.extend(records);
        pages_done += 1;

        if pages_done < max_pages {
            if let Some(dig2browser_crawler::profile::PaginationConfig::NextButton { selector }) =
                &profile.pagination
            {
                let nav_profile = dig2browser_crawler::profile::SiteProfile {
                    domain: profile.domain.clone(),
                    container_selector: selector.clone(),
                    fields: vec![dig2browser_crawler::profile::FieldConfig {
                        name: "href".to_string(),
                        selector: selector.clone(),
                        extract: dig2browser_crawler::profile::ExtractMode::Attribute("href".to_string()),
                        prefix: None,
                        transform: None,
                    }],
                    pagination: None,
                    requires_browser: browser || profile.requires_browser,
                    confidence: 1.0,
                    validated: true,
                    created_at: profile.created_at,
                    last_used_at: profile.last_used_at,
                    extraction_mode: dig2browser_crawler::profile::ExtractionMode::default(),
                };
                let nav_extractor = dig2browser_crawler::profile::parse::SelectorExtractor::new();
                let nav_records = nav_extractor.extract(&page.body, &nav_profile);
                if let Some(rec) = nav_records.first() {
                    if let Some(href) = rec.get("href").and_then(|v| v.as_str()) {
                        let base = url::Url::parse(&current_url)?;
                        let next = base.join(href)?;
                        current_url = next.to_string();
                        continue;
                    }
                }
            }
        }
        break;
    }

    println!("\nTotal records: {}", all_records.len());

    handle.shutdown().await;

    match output {
        Some(path) => {
            let mut writer = std::io::BufWriter::new(std::fs::File::create(&path)?);
            use std::io::Write;
            for rec in &all_records {
                writeln!(writer, "{}", serde_json::to_string(rec)?)?;
            }
            println!("Saved to: {}", path.display());
        }
        None => {
            for rec in &all_records {
                println!("{}", serde_json::to_string(rec)?);
            }
        }
    }

    Ok(())
}

fn cmd_export_spec(profile_path: PathBuf, schedule: String, output: PathBuf) -> Result<()> {
    let profile_json = std::fs::read_to_string(&profile_path)
        .with_context(|| format!("Failed to read profile: {}", profile_path.display()))?;
    let site_profile: dig2browser_crawler::profile::SiteProfile =
        serde_json::from_str(&profile_json).context("Failed to parse profile JSON")?;

    let spec = dig2browser_crawler::profile::DaemonSpec {
        name: format!("{}-crawler", site_profile.domain),
        domain: site_profile.domain.clone(),
        seed_urls: vec![format!("https://{}/", site_profile.domain)],
        site_profile,
        schedule: dig2browser_crawler::profile::CronSchedule { expression: schedule },
        fetch_method: dig2browser_crawler::profile::FetchMethod::Http,
        rate_limit: dig2browser_crawler::profile::RateLimitConfig {
            requests_per_second: 1.0,
            min_delay_ms: 1000,
            concurrent_requests: 1,
        },
        output_format: dig2browser_crawler::profile::OutputFormat::Jsonl,
        created_at: chrono::Utc::now(),
        spec_version: "1.0".to_string(),
    };

    let ext = output.extension().and_then(|e| e.to_str()).unwrap_or("json");
    if ext == "toml" {
        let toml_str = toml::to_string_pretty(&spec).context("Failed to serialize spec to TOML")?;
        std::fs::write(&output, toml_str)?;
    } else {
        let json_str = serde_json::to_string_pretty(&spec)?;
        std::fs::write(&output, json_str)?;
    }

    println!("DaemonSpec saved to: {}", output.display());
    Ok(())
}

async fn cmd_fetch(args: FetchArgs) -> Result<()> {
    let FetchArgs {
        url: url_str,
        browser,
        wait_selector,
        output,
        show_metadata,
        show_jsonld,
        show_antibot,
        signer,
        mut browser_opts,
    } = args;
    browser_opts.resolve_profile(&url_str);
    let handle = make_fetcher(browser, wait_selector, signer, browser_opts).await?;
    let page = fetch_page(handle.as_fetcher(), &url_str).await?;

    eprintln!(
        "Fetched: {} ({} bytes, {}ms, status {:?})",
        url_str,
        page.body.len(),
        page.fetch_ms,
        page.status_code,
    );

    if show_antibot {
        let result = dig2browser_crawler::profile::parse::AntiBotDetector::new().detect(&page.body);
        if result.detected {
            eprintln!(
                "Anti-bot: {} ({})",
                result.provider.as_deref().unwrap_or("unknown"),
                result.challenge_type.as_deref().unwrap_or("unknown"),
            );
        } else {
            eprintln!("Anti-bot: none detected");
        }
    }

    if show_metadata {
        let parsed_url = url::Url::parse(&url_str)?;
        let meta = dig2browser_crawler::profile::parse::MetadataExtractor::new()
            .extract(&page.body, Some(&parsed_url));
        eprintln!("Metadata:");
        if let Some(t) = &meta.title {
            eprintln!("  title: {t}");
        }
        if let Some(d) = &meta.description {
            eprintln!("  description: {d}");
        }
        if let Some(lang) = &meta.language {
            eprintln!("  language: {lang}");
        }
    }

    if show_jsonld {
        let items = dig2browser_crawler::profile::parse::JsonLdExtractor::extract_jsonld(&page.body);
        eprintln!("JSON-LD ({} blocks):", items.len());
        for item in &items {
            eprintln!("  {}", serde_json::to_string(item).unwrap_or_default());
        }
    }

    match output {
        Some(path) => {
            std::fs::write(&path, &page.body)?;
            eprintln!("HTML saved to: {}", path.display());
        }
        None => print!("{}", page.body),
    }

    handle.shutdown().await;
    Ok(())
}

async fn cmd_test_selector(
    url_str: String,
    selector: String,
    field_specs: Vec<String>,
    browser: bool,
    signer: Option<Arc<dig2browser::bot_auth::RequestSigner>>,
    mut browser_opts: BrowserOpts,
) -> Result<()> {
    use chrono::Utc;
    use dig2browser_crawler::profile::{ExtractMode, ExtractionMode, FieldConfig, SiteProfile};

    browser_opts.resolve_profile(&url_str);
    let handle = make_fetcher(browser, None, signer, browser_opts).await?;
    let page = fetch_page(handle.as_fetcher(), &url_str).await?;

    let fields: Vec<FieldConfig> = field_specs
        .iter()
        .filter_map(|spec| {
            let mut parts = spec.splitn(2, ':');
            let name = parts.next()?.to_string();
            let sel = parts.next()?.to_string();
            Some(FieldConfig {
                name,
                selector: sel,
                extract: ExtractMode::Text,
                prefix: None,
                transform: None,
            })
        })
        .collect();

    if fields.is_empty() {
        let document = scraper::Html::parse_document(&page.body);
        let sel = scraper::Selector::parse(&selector)
            .map_err(|e| anyhow::anyhow!("Invalid selector '{selector}': {e:?}"))?;
        let matches: Vec<_> = document.select(&sel).collect();
        println!("Selector: {selector}");
        println!("Matches: {}", matches.len());
        for (i, el) in matches.iter().enumerate() {
            let text: String = el.text().collect::<String>();
            let trimmed = text.trim();
            if trimmed.len() > 200 {
                println!("[{i}] {}...", &trimmed[..200]);
            } else {
                println!("[{i}] {trimmed}");
            }
        }
        handle.shutdown().await;
        return Ok(());
    }

    let parsed_url = url::Url::parse(&url_str)?;
    let domain = parsed_url.host_str().unwrap_or("unknown").to_string();

    let now = Utc::now();
    let profile = SiteProfile {
        domain,
        container_selector: selector.clone(),
        fields,
        pagination: None,
        requires_browser: browser,
        confidence: 1.0,
        validated: true,
        created_at: now,
        last_used_at: now,
        extraction_mode: ExtractionMode::default(),
    };

    let extractor = dig2browser_crawler::profile::parse::SelectorExtractor::new();
    let records = extractor.extract(&page.body, &profile);

    println!("Selector: {selector}");
    println!("Matches: {}", records.len());
    for (i, rec) in records.iter().enumerate() {
        println!("[{i}] {}", serde_json::to_string(rec).unwrap_or_default());
    }

    handle.shutdown().await;
    Ok(())
}
