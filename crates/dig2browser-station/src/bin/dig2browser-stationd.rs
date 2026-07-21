#[cfg(windows)]
use std::net::{IpAddr, SocketAddr};
#[cfg(windows)]
use std::path::PathBuf;
#[cfg(windows)]
use std::process::ExitCode;
#[cfg(windows)]
use std::time::Duration;

#[cfg(all(windows, feature = "tls-test-hooks"))]
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
#[cfg(windows)]
use clap::{Parser, ValueEnum};
#[cfg(windows)]
use dig2browser::agentic::{
    BrowserWorkerConfig, NavigationPolicy, NavigationPolicyError,
};
#[cfg(windows)]
use dig2browser_core::{RouteRef, RouteRefError};
#[cfg(windows)]
use dig2browser_protocol::DEFAULT_STATION_PIPE;
#[cfg(windows)]
use dig2browser_station::ipc::{
    run_station_server, ConfigError as ServerConfigError, ServerConfig, ServerError,
    ServerReport,
};
#[cfg(windows)]
use dig2browser_station::{
    BrowserStation, CollectionError, ConfigError as StationConfigError, CrawlError, EgressError,
    EgressPeerPolicy, EgressPeerPolicyError, EgressProxy, EgressReport,
    EgressRouteError, ProfilesRootError, ProfilesRootOwnership, RouteDescriptor,
    RouteRegistry, RouteRegistryError, RuntimeKind, RuntimeSelector, StationConfig,
};

#[cfg(windows)]
#[derive(Debug, Clone, Copy, ValueEnum)]
enum RuntimeArg {
    Auto,
    Chrome,
    Edge,
    Lightweight,
}

#[cfg(windows)]
impl RuntimeArg {
    fn selector(self) -> RuntimeSelector {
        match self {
            Self::Auto => RuntimeSelector::Auto,
            Self::Chrome => RuntimeSelector::Exact(RuntimeKind::Chrome),
            Self::Edge => RuntimeSelector::Exact(RuntimeKind::Edge),
            Self::Lightweight => RuntimeSelector::Exact(RuntimeKind::Lightweight),
        }
    }
}

#[cfg(windows)]
#[derive(Debug, Parser)]
#[command(name = "dig2browser-stationd")]
struct Cli {
    #[arg(long, default_value = DEFAULT_STATION_PIPE)]
    pipe_name: String,
    #[arg(long)]
    profiles_root: PathBuf,
    #[arg(long)]
    trace_root: Option<PathBuf>,
    #[arg(
        long,
        help = "Own this durable crawl root and resume unfinished crawl jobs"
    )]
    crawl_root: Option<PathBuf>,
    #[arg(long, default_value_t = 16)]
    max_resident: usize,
    #[arg(long, default_value_t = 32)]
    max_in_flight: usize,
    #[arg(long, value_enum, default_value_t = RuntimeArg::Auto)]
    runtime: RuntimeArg,
    #[arg(long = "direct-route-ref", default_value = "host.direct")]
    direct_route_refs: Vec<String>,
    #[arg(
        long = "allow-origin",
        help = "Allow an HTTP(S) origin; exact mode routes runtime HTTP(S) through the station peer-policy proxy"
    )]
    allowed_origins: Vec<String>,
    #[arg(
        long = "allow-private-peer",
        help = "Allow one exact non-global peer IP only for its matching IP-literal origin"
    )]
    allowed_private_peers: Vec<IpAddr>,
    #[cfg(feature = "tls-test-hooks")]
    #[arg(
        long = "test-chrome-certificate-error-spki-sha256",
        value_name = "BASE64_SHA256",
        help = "Test-only Chrome certificate-error exception for one exact SPKI SHA-256; requires an exact HTTPS origin policy"
    )]
    test_chrome_certificate_error_spki_sha256: Option<String>,
    #[arg(long, default_value_t = 64)]
    max_connections: usize,
    #[arg(long, default_value_t = 90)]
    timeout_seconds: u64,
    #[arg(long, default_value_t = 15)]
    drain_seconds: u64,
    #[arg(long, default_value_t = false)]
    allow_remote_shutdown: bool,
    #[arg(long, default_value_t = false)]
    allow_interactive_tasks: bool,
    #[arg(long, default_value_t = false)]
    allow_scripted_tasks: bool,
    #[arg(long, default_value_t = false)]
    allow_session_state_updates: bool,
    #[arg(long, default_value_t = false)]
    allow_identity_status: bool,
    #[arg(long, default_value_t = false)]
    allow_headful_auth: bool,
    #[arg(long, default_value_t = false)]
    allow_session_health: bool,
    #[arg(long, default_value_t = false)]
    allow_durable_read: bool,
    #[arg(long, default_value_t = false)]
    allow_durable_write: bool,
    #[arg(long, default_value_t = false)]
    allow_crawl_read: bool,
    #[arg(long, default_value_t = false)]
    allow_crawl_write: bool,
}

#[cfg(windows)]
#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(report) => {
            print_report(report);
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!(
                "{{\"schema_version\":1,\"event\":\"station_exit\",\"outcome\":\"error\",\"error_class\":\"{}\"}}",
                error.class()
            );
            ExitCode::FAILURE
        }
    }
}

#[cfg(windows)]
async fn run(cli: Cli) -> Result<DaemonReport, DaemonError> {
    let navigation_policy = if cli.allowed_origins.is_empty() {
        NavigationPolicy::default()
    } else {
        NavigationPolicy::exact_origins(&cli.allowed_origins)?
    };
    if !navigation_policy.is_exact() && !cli.allowed_private_peers.is_empty() {
        return Err(DaemonError::PrivatePeersRequireExactPolicy);
    }
    #[cfg(feature = "tls-test-hooks")]
    let test_chrome_certificate_error_argument = test_chrome_certificate_error_launch_argument(
        cli.test_chrome_certificate_error_spki_sha256.as_deref(),
        cli.runtime,
        &navigation_policy,
    )?;
    let profiles_owner = ProfilesRootOwnership::acquire(&cli.profiles_root)?;
    let egress_proxy = if navigation_policy.is_exact() {
        let peer_policy =
            EgressPeerPolicy::with_exact_exceptions(cli.allowed_private_peers)?;
        Some(EgressProxy::bind(navigation_policy.clone(), peer_policy).await?)
    } else {
        None
    };
    let egress_endpoint = egress_proxy.as_ref().map(EgressProxy::local_addr);
    let route_registry =
        direct_route_registry(&cli.direct_route_refs, egress_endpoint)?;
    let command_timeout = Duration::from_secs(cli.timeout_seconds);
    let worker = BrowserWorkerConfig {
        command_timeout,
        ..BrowserWorkerConfig::default()
    };
    #[cfg(feature = "tls-test-hooks")]
    let worker = {
        let mut worker = worker;
        if let Some(argument) = test_chrome_certificate_error_argument {
            worker.launch.extra_args.push(argument);
        }
        worker
    };
    let station_config = StationConfig::new(
        profiles_owner.root(),
        cli.max_resident,
        cli.max_in_flight,
    )?
    .with_runtime_selector(cli.runtime.selector())
    .with_route_registry(route_registry)
    .with_navigation_policy(navigation_policy)
    .with_worker_config(worker);
    let mut server_config = ServerConfig::new(
        cli.pipe_name,
        cli.max_connections,
        Duration::from_secs(cli.drain_seconds),
    )?
    .allow_remote_shutdown(cli.allow_remote_shutdown)
    .allow_interactive_tasks(cli.allow_interactive_tasks)
    .allow_scripted_tasks(cli.allow_scripted_tasks)
    .allow_identity_status(cli.allow_identity_status)
    .allow_session_state_updates(cli.allow_session_state_updates)
    .allow_headful_auth(cli.allow_headful_auth)
    .allow_session_health(cli.allow_session_health)
    .allow_durable_read(cli.allow_durable_read)
    .allow_durable_write(cli.allow_durable_write)
    .allow_crawl_read(cli.allow_crawl_read)
    .allow_crawl_write(cli.allow_crawl_write);
    if let Some(trace_root) = cli.trace_root {
        server_config = server_config.trace_root(trace_root)?;
    }
    if let Some(crawl_root) = cli.crawl_root {
        server_config = server_config.crawl_root(crawl_root)?;
    }
    let station = BrowserStation::new(station_config);
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let ctrl_shutdown_tx = shutdown_tx.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        ctrl_shutdown_tx.send_replace(true);
    });
    let server = run_station_server(
        station,
        server_config,
        shutdown_rx.clone(),
    );
    tokio::pin!(server);
    let (server_report, egress_report) = if let Some(egress_proxy) = egress_proxy {
        let egress = egress_proxy.run(shutdown_rx.clone());
        tokio::pin!(egress);
        tokio::select! {
            server_result = &mut server => {
                shutdown_tx.send_replace(true);
                let egress_report = egress.await?;
                (server_result?, Some(egress_report))
            }
            egress_result = &mut egress => {
                let expected_shutdown = *shutdown_rx.borrow();
                shutdown_tx.send_replace(true);
                let server_result = server.await;
                match egress_result {
                    Ok(egress_report) if expected_shutdown => {
                        (server_result?, Some(egress_report))
                    }
                    Ok(_) => return Err(DaemonError::EgressUnexpectedExit),
                    Err(error) => {
                        let _ = server_result;
                        return Err(DaemonError::Egress(error));
                    }
                }
            }
        }
    } else {
        (server.await?, None)
    };
    drop(profiles_owner);
    Ok(DaemonReport {
        server: server_report,
        egress: egress_report,
    })
}

#[cfg(all(windows, feature = "tls-test-hooks"))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct TestChromeCertificateErrorSpkiSha256(String);

#[cfg(all(windows, feature = "tls-test-hooks"))]
impl TestChromeCertificateErrorSpkiSha256 {
    fn parse(value: &str) -> Result<Self, TestChromeCertificateErrorSpkiSha256Error> {
        let decoded = BASE64_STANDARD
            .decode(value)
            .map_err(|_| TestChromeCertificateErrorSpkiSha256Error::InvalidBase64)?;
        if decoded.len() != 32 {
            return Err(TestChromeCertificateErrorSpkiSha256Error::WrongDigestLength);
        }
        if BASE64_STANDARD.encode(decoded) != value {
            return Err(TestChromeCertificateErrorSpkiSha256Error::NonCanonicalBase64);
        }
        Ok(Self(value.to_owned()))
    }

    fn launch_argument(&self) -> String {
        format!("--ignore-certificate-errors-spki-list={}", self.0)
    }
}

#[cfg(all(windows, feature = "tls-test-hooks"))]
fn test_chrome_certificate_error_launch_argument(
    value: Option<&str>,
    runtime: RuntimeArg,
    navigation_policy: &NavigationPolicy,
) -> Result<Option<String>, DaemonError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let exception = TestChromeCertificateErrorSpkiSha256::parse(value)?;
    if !matches!(runtime, RuntimeArg::Chrome)
        || !navigation_policy.is_exact()
        || navigation_policy
            .allowed_origins()
            .iter()
            .any(|origin| !origin.starts_with("https://"))
    {
        return Err(DaemonError::TestChromeCertificateErrorScope);
    }
    Ok(Some(exception.launch_argument()))
}

#[cfg(windows)]
fn direct_route_registry(
    references: &[String],
    egress_proxy: Option<SocketAddr>,
) -> Result<RouteRegistry, DaemonError> {
    if references.is_empty() {
        return Err(DaemonError::NoDirectRoutes);
    }
    let mut registry = RouteRegistry::empty();
    for reference in references {
        let reference = RouteRef::new(reference.clone())?;
        let descriptor = match egress_proxy {
            Some(endpoint) => RouteDescriptor::guarded_host_direct(reference, endpoint)?,
            None => RouteDescriptor::host_direct(reference),
        };
        registry.register(descriptor)?;
    }
    Ok(registry)
}

#[cfg(windows)]
struct DaemonReport {
    server: ServerReport,
    egress: Option<EgressReport>,
}

#[cfg(windows)]
fn print_report(report: DaemonReport) {
    let outcome = if report.server.drain_timed_out
        || report.egress.is_some_and(|egress| egress.drain_timed_out)
    {
        "drain_timeout"
    } else {
        "clean"
    };
    let egress = report.egress.unwrap_or_default();
    println!(
        "{{\"schema_version\":1,\"event\":\"station_exit\",\"outcome\":\"{outcome}\",\"stop_reason\":\"{}\",\"accepted_connections\":{},\"completed_connections\":{},\"aborted_connections\":{},\"stopped_workers\":{},\"drain_timed_out\":{},\"egress_accepted_connections\":{},\"egress_completed_connections\":{},\"egress_denied_connections\":{},\"egress_invalid_connections\":{},\"egress_failed_connections\":{},\"egress_timed_out_connections\":{},\"egress_aborted_connections\":{},\"egress_drain_timed_out\":{}}}",
        report.server.stop_reason.as_str(),
        report.server.accepted_connections,
        report.server.completed_connections,
        report.server.aborted_connections,
        report.server.stopped_workers,
        report.server.drain_timed_out,
        egress.accepted_connections,
        egress.completed_connections,
        egress.denied_connections,
        egress.invalid_connections,
        egress.failed_connections,
        egress.timed_out_connections,
        egress.aborted_connections,
        egress.drain_timed_out
    );
}

#[cfg(all(windows, feature = "tls-test-hooks"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
enum TestChromeCertificateErrorSpkiSha256Error {
    #[error("test Chrome certificate-error SPKI digest is not canonical base64")]
    InvalidBase64,
    #[error("test Chrome certificate-error SPKI digest must decode to exactly 32 bytes")]
    WrongDigestLength,
    #[error("test Chrome certificate-error SPKI digest is not canonical base64")]
    NonCanonicalBase64,
}

#[cfg(windows)]
#[derive(Debug, thiserror::Error)]
enum DaemonError {
    #[error(transparent)]
    ProfilesRoot(#[from] ProfilesRootError),
    #[error(transparent)]
    StationConfig(#[from] StationConfigError),
    #[error("at least one direct route reference must be configured")]
    NoDirectRoutes,
    #[error("private peer exceptions require an exact-origin policy")]
    PrivatePeersRequireExactPolicy,
    #[cfg(feature = "tls-test-hooks")]
    #[error("test Chrome certificate-error SPKI exception requires exact Chrome and an exact HTTPS-only origin policy")]
    TestChromeCertificateErrorScope,
    #[cfg(feature = "tls-test-hooks")]
    #[error(transparent)]
    TestChromeCertificateErrorSpki(#[from] TestChromeCertificateErrorSpkiSha256Error),
    #[error(transparent)]
    RouteRef(#[from] RouteRefError),
    #[error(transparent)]
    RouteRegistry(#[from] RouteRegistryError),
    #[error(transparent)]
    EgressRoute(#[from] EgressRouteError),
    #[error(transparent)]
    NavigationPolicy(#[from] NavigationPolicyError),
    #[error(transparent)]
    EgressPeerPolicy(#[from] EgressPeerPolicyError),
    #[error(transparent)]
    Egress(#[from] EgressError),
    #[error("station egress proxy exited before station shutdown")]
    EgressUnexpectedExit,
    #[error(transparent)]
    ServerConfig(#[from] ServerConfigError),
    #[error(transparent)]
    Server(#[from] ServerError),
}

#[cfg(windows)]
impl DaemonError {
    fn class(&self) -> &'static str {
        match self {
            Self::ProfilesRoot(ProfilesRootError::AlreadyOwned) => "profiles_root_owned",
            Self::ProfilesRoot(_) => "profiles_root_unavailable",
            #[cfg(feature = "tls-test-hooks")]
            Self::TestChromeCertificateErrorScope
            | Self::TestChromeCertificateErrorSpki(_) => "invalid_config",
            Self::StationConfig(_)
            | Self::NoDirectRoutes
            | Self::PrivatePeersRequireExactPolicy
            | Self::RouteRef(_)
            | Self::RouteRegistry(_)
            | Self::EgressRoute(_)
            | Self::NavigationPolicy(_)
            | Self::EgressPeerPolicy(_)
            | Self::Egress(EgressError::PolicyConfiguration)
            | Self::ServerConfig(_) => "invalid_config",
            Self::Egress(EgressError::Bind | EgressError::Accept)
            | Self::EgressUnexpectedExit => "egress_unavailable",
            Self::Server(ServerError::UnsupportedPlatform) => "unsupported_platform",
            Self::Server(ServerError::Io(_)) => "station_endpoint_unavailable",
            Self::Server(ServerError::Frame(_)) => "station_protocol_failure",
            Self::Server(ServerError::CrawlTraceRequired) => "invalid_config",
            Self::Server(ServerError::Collection(
                CollectionError::Ledger(dig2browser_trace::LedgerError::WriterLocked),
            )) => "trace_root_owned",
            Self::Server(ServerError::Collection(
                CollectionError::TraceRootNotAbsolute
                | CollectionError::TraceRootOverlap,
            )) => "invalid_config",
            Self::Server(ServerError::Collection(
                CollectionError::CorruptTrace
                | CollectionError::ManagerStatePoisoned
                | CollectionError::LedgerPoisoned
                | CollectionError::Protocol(_)
                | CollectionError::Ledger(
                    dig2browser_trace::LedgerError::Protocol(_)
                    | dig2browser_trace::LedgerError::InvalidTransition(_)
                    | dig2browser_trace::LedgerError::Corrupt(_),
                ),
            )) => "trace_corrupt",
            Self::Server(ServerError::Collection(_)) => "trace_root_unavailable",
            Self::Server(ServerError::Crawl(CrawlError::RootLocked)) => "crawl_root_owned",
            Self::Server(ServerError::Crawl(
                CrawlError::RootNotAbsolute | CrawlError::RootOverlap,
            )) => "invalid_config",
            Self::Server(ServerError::Crawl(
                CrawlError::InvalidJournalName
                | CrawlError::InvalidBinding
                | CrawlError::InvalidProfileId
                | CrawlError::InvalidBudget
                | CrawlError::CorruptState(_)
                | CrawlError::MissingHtmlCapture
                | CrawlError::InvalidArtifactReference
                | CrawlError::InvalidHex
                | CrawlError::CountOverflow
                | CrawlError::ManagerStatePoisoned
                | CrawlError::Protocol(_)
                | CrawlError::Crawler(_)
                | CrawlError::Spec(_)
                | CrawlError::CanonicalUrl(_),
            )) => "crawl_corrupt",
            Self::Server(ServerError::Crawl(_)) => "crawl_root_unavailable",
            Self::Server(ServerError::Station(_)) => "station_shutdown_failure",
        }
    }
}

#[cfg(all(test, windows, feature = "tls-test-hooks"))]
mod tests {
    use super::*;

    const ZERO_SHA256_BASE64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    #[test]
    fn test_chrome_certificate_error_spki_requires_canonical_sha256_base64() {
        assert_eq!(
            TestChromeCertificateErrorSpkiSha256::parse(ZERO_SHA256_BASE64)
                .expect("canonical 32-byte pin")
                .launch_argument(),
            format!("--ignore-certificate-errors-spki-list={ZERO_SHA256_BASE64}")
        );
        assert_eq!(
            TestChromeCertificateErrorSpkiSha256::parse("AA=="),
            Err(TestChromeCertificateErrorSpkiSha256Error::WrongDigestLength)
        );
        assert_eq!(
            TestChromeCertificateErrorSpkiSha256::parse(
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            ),
            Err(TestChromeCertificateErrorSpkiSha256Error::InvalidBase64)
        );
    }

    #[test]
    fn test_chrome_certificate_error_spki_is_scoped_to_exact_chrome_https_policy() {
        let https = NavigationPolicy::exact_origins(["https://127.0.0.1:8443"])
            .expect("exact HTTPS policy");
        assert!(test_chrome_certificate_error_launch_argument(
            Some(ZERO_SHA256_BASE64),
            RuntimeArg::Chrome,
            &https,
        )
        .expect("valid scoped pin")
        .is_some());

        let http = NavigationPolicy::exact_origins(["http://127.0.0.1:8080"])
            .expect("exact HTTP policy");
        for (runtime, policy) in [
            (RuntimeArg::Edge, &https),
            (RuntimeArg::Auto, &https),
            (RuntimeArg::Chrome, &http),
        ] {
            let error = test_chrome_certificate_error_launch_argument(
                Some(ZERO_SHA256_BASE64),
                runtime,
                policy,
            )
            .expect_err("mis-scoped pin must fail");
            assert_eq!(error.class(), "invalid_config");
        }
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("dig2browser-stationd requires Windows named pipes");
    std::process::exit(1);
}
