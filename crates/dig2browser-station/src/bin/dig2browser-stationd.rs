#[cfg(windows)]
#[path = "dig2browser_stationd/windows_wfp_provider.rs"]
mod windows_wfp_provider;

#[cfg(windows)]
use std::io;
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
use dig2browser::BrowserProcessIsolation;
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
use dig2browser_station::containment::{
    ContainmentAssurance, ContainmentContractError, ContainmentRequest,
    ContainmentRequirements, NetworkCoverage, NetworkPermit, NetworkPolicy,
    NetworkProtocol, NetworkSubjectScope, ProviderCrashBehavior,
};
#[cfg(windows)]
use dig2browser_station::windows_wfp_broker::{
    BrokerBrowser, WindowsWfpBrokerCapability, WindowsWfpBrokerError,
    WindowsWfpBrokerRejectCode, WindowsWfpLeaseLoss,
};
#[cfg(windows)]
use dig2browser_station::{
    BrowserStation, CollectionError, ConfigError as StationConfigError, CrawlError, EgressError,
    EgressPeerPolicy, EgressPeerPolicyError, EgressProxy, EgressReport,
    EgressRouteError, ProfilesRootError, ProfilesRootOwnership, RouteDescriptor,
    RouteRegistry, RouteRegistryError, RuntimeKind, RuntimeSelector, StationConfig,
};
#[cfg(windows)]
use windows_wfp_provider::{
    WindowsWfpContainment, WindowsWfpProvider, WindowsWfpProviderError,
};

#[cfg(windows)]
#[derive(Debug, Clone, Copy, ValueEnum)]
enum RuntimeArg {
    Auto,
    Chrome,
    Edge,
    Firefox,
    Lightweight,
}

#[cfg(windows)]
impl RuntimeArg {
    fn selector(self) -> RuntimeSelector {
        match self {
            Self::Auto => RuntimeSelector::Auto,
            Self::Chrome => RuntimeSelector::Exact(RuntimeKind::Chrome),
            Self::Edge => RuntimeSelector::Exact(RuntimeKind::Edge),
            Self::Firefox => RuntimeSelector::Exact(RuntimeKind::Firefox),
            Self::Lightweight => RuntimeSelector::Exact(RuntimeKind::Lightweight),
        }
    }

    fn broker_browser(self) -> Option<BrokerBrowser> {
        match self {
            Self::Chrome => Some(BrokerBrowser::Chrome),
            Self::Edge => Some(BrokerBrowser::Edge),
            Self::Auto | Self::Firefox | Self::Lightweight => None,
        }
    }
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, ValueEnum, Default)]
enum WindowsContainmentArg {
    #[default]
    Off,
    Required,
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
    #[arg(
        long,
        help = "Own this durable monitor root (<root>/cas + <root>/journals) and reconcile crash-left-open monitors; gated by --allow-durable-read/write"
    )]
    monitor_root: Option<PathBuf>,
    #[arg(long, default_value_t = 16)]
    max_resident: usize,
    #[arg(long, default_value_t = 32)]
    max_in_flight: usize,
    #[arg(long, value_enum, default_value_t = RuntimeArg::Auto)]
    runtime: RuntimeArg,
    #[arg(long, value_name = "PATH")]
    geckodriver_path: Option<PathBuf>,
    #[arg(long, value_name = "URL")]
    geckodriver_url: Option<String>,
    #[arg(
        long = "windows-containment",
        value_enum,
        default_value_t = WindowsContainmentArg::Off,
        help = "Require station-owned runtime-path WFP containment and read its one-time binary capability from stdin"
    )]
    windows_containment: WindowsContainmentArg,
    #[arg(
        long = "windows-wfp-broker-pipe",
        value_name = "LAUNCH_SCOPED_NAME",
        required_if_eq("windows_containment", "required"),
        help = "Launcher-scoped local elevated WFP broker pipe used by required Windows containment"
    )]
    windows_wfp_broker_pipe: Option<String>,
    #[arg(long = "direct-route-ref")]
    direct_route_refs: Vec<String>,
    #[arg(
        long = "http-proxy-route",
        value_name = "REF=IP:PORT",
        help = "Register an external HTTP proxy route"
    )]
    http_proxy_routes: Vec<String>,
    #[arg(
        long = "socks5-proxy-route",
        value_name = "REF=IP:PORT",
        help = "Register an external SOCKS5 proxy route"
    )]
    socks5_proxy_routes: Vec<String>,
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
    #[arg(
        long = "close-timeout-seconds",
        value_name = "SECONDS",
        help = "Worker close/drain teardown budget, distinct from --timeout-seconds \
            (task/command execution budget). Defaults to --timeout-seconds when unset."
    )]
    close_timeout_seconds: Option<u64>,
    #[cfg(feature = "geckodriver-test-hooks")]
    #[arg(long, hide = true)]
    test_geckodriver_startup_timeout_millis: Option<u64>,
    #[cfg(feature = "containment-test-hooks")]
    #[arg(
        long = "test-chromium-close-delay-millis",
        value_name = "MILLIS",
        hide = true
    )]
    test_chromium_close_delay_millis: Option<u64>,
    #[arg(long, default_value_t = 500)]
    restart_after_pages: u32,
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
    #[arg(
        long,
        default_value_t = false,
        help = "Allow a crawl to run under an Authenticated profile (reuse a harvested session); subordinate to --allow-crawl-*/--allow-durable-*"
    )]
    allow_authenticated_crawl: bool,
    #[arg(
        long,
        default_value_t = false,
        help = "Allow the RAW (unsanitized real URLs, WS/SSE frame payloads) live DevTools event subscription"
    )]
    allow_live_events: bool,
    #[arg(
        long,
        default_value_t = false,
        help = "Allow importing a prepared session from a local file into an authenticated profile (cookie bytes are read locally, never over the pipe)"
    )]
    allow_session_import: bool,
    #[arg(
        long,
        default_value_t = false,
        help = "Allow an UploadFile task step to set a file <input> from a local path (the browser reads the file; bytes never cross the pipe)"
    )]
    allow_file_upload: bool,
}

#[cfg(windows)]
enum GeckodriverSource {
    Owned(PathBuf),
    External(String),
}

#[cfg(windows)]
fn select_geckodriver_source(
    runtime: RuntimeArg,
    cli_path: Option<PathBuf>,
    cli_url: Option<String>,
    environment_path: Option<std::ffi::OsString>,
) -> Result<Option<GeckodriverSource>, DaemonError> {
    if !matches!(runtime, RuntimeArg::Firefox) {
        if cli_path.is_some() || cli_url.is_some() {
            return Err(DaemonError::GeckodriverScope);
        }
        return Ok(None);
    }
    if cli_path.is_some() && cli_url.is_some() {
        return Err(DaemonError::GeckodriverSourceConflict);
    }
    if let Some(path) = cli_path {
        return Ok(Some(GeckodriverSource::Owned(path)));
    }
    if let Some(path) = environment_path.filter(|path| !path.is_empty()) {
        return Ok(Some(GeckodriverSource::Owned(PathBuf::from(path))));
    }
    if let Some(url) = cli_url.filter(|url| !url.trim().is_empty()) {
        return Ok(Some(GeckodriverSource::External(
            canonical_loopback_geckodriver_url(&url)?,
        )));
    }
    Err(DaemonError::GeckodriverRequired)
}

#[cfg(windows)]
fn canonical_loopback_geckodriver_url(value: &str) -> Result<String, DaemonError> {
    let endpoint = value
        .strip_prefix("http://")
        .ok_or(DaemonError::GeckodriverExternalUrl)?
        .parse::<SocketAddr>()
        .map_err(|_| DaemonError::GeckodriverExternalUrl)?;
    if !endpoint.ip().is_loopback() || endpoint.port() == 0 {
        return Err(DaemonError::GeckodriverExternalUrl);
    }
    Ok(format!("http://{endpoint}"))
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
            report_station_failure(&error);
            eprintln!(
                "{{\"schema_version\":1,\"event\":\"station_exit\",\"outcome\":\"error\",\"error_class\":\"{}\"}}",
                error.class()
            );
            ExitCode::FAILURE
        }
    }
}

#[cfg(feature = "containment-test-hooks")]
fn report_station_diagnostic(event: &str, detail: serde_json::Value) {
    use std::io::Write as _;

    let Some(path) = std::env::var_os("DIG2BROWSER_STATION_DIAGNOSTIC_LOG") else {
        return;
    };
    if path.is_empty() {
        return;
    }
    let record = serde_json::json!({
        "schema_version": 1,
        "at_unix_ms": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64,
        "process_id": std::process::id(),
        "event": event,
        "detail": detail,
    });
    if let Ok(mut log) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        if let Ok(mut encoded) = serde_json::to_vec(&record) {
            encoded.push(b'\n');
            let _ = log.write_all(&encoded);
        }
    }
}

#[cfg(not(feature = "containment-test-hooks"))]
fn report_station_diagnostic(_event: &str, _detail: serde_json::Value) {}

fn report_station_failure(error: &DaemonError) {
    report_station_diagnostic(
        "station_failure",
        serde_json::json!({
            "error_class": error.class(),
            "message": error.to_string(),
            "debug": format!("{error:?}"),
        }),
    );
}

#[cfg(windows)]
async fn run(cli: Cli) -> Result<DaemonReport, DaemonError> {
    report_station_diagnostic(
        "startup_started",
        serde_json::json!({
            "runtime": format!("{:?}", cli.runtime),
            "windows_containment": format!("{:?}", cli.windows_containment),
            "profiles_root": cli.profiles_root,
        }),
    );
    let geckodriver_source = select_geckodriver_source(
        cli.runtime,
        cli.geckodriver_path,
        cli.geckodriver_url,
        std::env::var_os("GECKODRIVER"),
    )?;
    let navigation_policy = if cli.allowed_origins.is_empty() {
        NavigationPolicy::default()
    } else {
        NavigationPolicy::exact_origins(&cli.allowed_origins)?
    };
    validate_external_route_policy(
        &navigation_policy,
        &cli.http_proxy_routes,
        &cli.socks5_proxy_routes,
    )?;
    if !navigation_policy.is_exact() && !cli.allowed_private_peers.is_empty() {
        return Err(DaemonError::PrivatePeersRequireExactPolicy);
    }
    #[cfg(feature = "tls-test-hooks")]
    let test_chrome_certificate_error_argument = test_chrome_certificate_error_launch_argument(
        cli.test_chrome_certificate_error_spki_sha256.as_deref(),
        cli.runtime,
        &navigation_policy,
    )?;
    #[cfg(feature = "containment-test-hooks")]
    let close_timeout_seconds = cli.close_timeout_seconds.unwrap_or(cli.timeout_seconds);
    #[cfg(feature = "containment-test-hooks")]
    let test_chromium_close_delay_argument = containment_test_close_delay_argument(
        cli.test_chromium_close_delay_millis,
        cli.windows_containment,
        cli.runtime,
        &navigation_policy,
        close_timeout_seconds,
    )?;
    let profiles_owner = ProfilesRootOwnership::acquire(&cli.profiles_root)?;
    report_station_diagnostic(
        "profiles_root_acquired",
        serde_json::json!({ "profiles_root": profiles_owner.root() }),
    );
    let egress_proxy = if navigation_policy.is_exact() {
        let peer_policy =
            EgressPeerPolicy::with_exact_exceptions(cli.allowed_private_peers)?;
        Some(EgressProxy::bind(navigation_policy.clone(), peer_policy).await?)
    } else {
        None
    };
    let egress_endpoint = egress_proxy.as_ref().map(EgressProxy::local_addr);
    report_station_diagnostic(
        "egress_ready",
        serde_json::json!({ "endpoint": egress_endpoint.map(|value| value.to_string()) }),
    );
    report_station_diagnostic(
        "containment_acquire_started",
        serde_json::json!({
            "required": matches!(cli.windows_containment, WindowsContainmentArg::Required),
            "runtime": format!("{:?}", cli.runtime),
        }),
    );
    let windows_containment = prepare_windows_containment(
        cli.windows_containment,
        cli.runtime,
        &navigation_policy,
        profiles_owner.root(),
        egress_endpoint,
        cli.windows_wfp_broker_pipe.as_deref(),
    )
    .await?;
    report_station_diagnostic(
        "containment_acquire_finished",
        serde_json::json!({ "active": windows_containment.is_some() }),
    );
    let containment_assurance = windows_containment
        .as_ref()
        .map(WindowsWfpContainment::assurance);
    let process_isolation = windows_containment
        .as_ref()
        .map(WindowsWfpContainment::process_isolation)
        .unwrap_or(BrowserProcessIsolation::Native);
    let service_result = async {
        let route_registry = route_registry(
            &cli.direct_route_refs,
            &cli.http_proxy_routes,
            &cli.socks5_proxy_routes,
            egress_endpoint,
        )?;
        let command_timeout = Duration::from_secs(cli.timeout_seconds);
        let close_timeout = cli.close_timeout_seconds.map(Duration::from_secs);
        let mut worker = BrowserWorkerConfig {
            command_timeout,
            close_timeout,
            ..BrowserWorkerConfig::default()
        };
        match geckodriver_source {
            Some(GeckodriverSource::Owned(binary)) => {
                worker.launch.geckodriver_binary = Some(binary);
            }
            Some(GeckodriverSource::External(url)) => {
                worker.launch.geckodriver_url = url;
            }
            None => {}
        }
        worker.launch.geckodriver_startup_timeout = command_timeout.clamp(
            Duration::from_secs(1),
            Duration::from_secs(15),
        );
        #[cfg(feature = "geckodriver-test-hooks")]
        if let Some(timeout_millis) = cli.test_geckodriver_startup_timeout_millis {
            worker.launch.geckodriver_startup_timeout =
                Duration::from_millis(timeout_millis);
        }
        worker.launch.restart_after_pages = cli.restart_after_pages;
        #[cfg(feature = "tls-test-hooks")]
        let worker = {
            let mut worker = worker;
            if let Some(argument) = test_chrome_certificate_error_argument {
                worker.launch.extra_args.push(argument);
            }
            worker
        };
        #[cfg(feature = "containment-test-hooks")]
        let worker = {
            let mut worker = worker;
            if matches!(cli.windows_containment, WindowsContainmentArg::Required) {
                worker.launch.extra_args.push("--enable-logging=stderr".to_owned());
                worker.launch.extra_args.push("--v=1".to_owned());
            }
            if let Some(argument) = test_chromium_close_delay_argument {
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
        .with_process_isolation(process_isolation)
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
        .allow_crawl_write(cli.allow_crawl_write)
        .allow_authenticated_crawl(cli.allow_authenticated_crawl)
        .allow_live_events(cli.allow_live_events)
        .allow_session_import(cli.allow_session_import)
        .allow_file_upload(cli.allow_file_upload);
        if let Some(trace_root) = cli.trace_root {
            server_config = server_config.trace_root(trace_root)?;
        }
        if let Some(crawl_root) = cli.crawl_root {
            server_config = server_config.crawl_root(crawl_root)?;
        }
        if let Some(monitor_root) = cli.monitor_root {
            server_config = server_config.monitor_root(monitor_root)?;
        }
        let station = BrowserStation::new(station_config);
        report_station_diagnostic(
            "station_service_starting",
            serde_json::json!({ "containment_active": windows_containment.is_some() }),
        );
        let emergency_station = station.clone();
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let ctrl_shutdown_tx = shutdown_tx.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            ctrl_shutdown_tx.send_replace(true);
        });
        let service = run_station_and_egress(
            station,
            server_config,
            egress_proxy,
            shutdown_tx.clone(),
            shutdown_rx,
        );
        tokio::pin!(service);
        if let Some(containment) = windows_containment.as_ref() {
            tokio::select! {
                result = &mut service => result,
                loss = containment.wait_for_unexpected_loss() => {
                    let _ = emergency_station.emergency_shutdown().await;
                    shutdown_tx.send_replace(true);
                    let _ = service.await;
                    Err(DaemonError::WindowsWfpLeaseLost(loss))
                }
            }
        } else {
            service.await
        }
    }
    .await
    .map(|mut report| {
        report.containment = containment_assurance;
        report
    });
    let containment_result = if service_result.is_ok() {
        match windows_containment {
            Some(containment) => containment.close().await.map_err(DaemonError::from),
            None => Ok(()),
        }
    } else {
        // A failed station shutdown does not prove that every contained
        // process has exited. Dropping the client lease disconnects from the
        // broker without authorizing filter or mirror removal; the next broker
        // reconciles them only after exact process-liveness checks.
        drop(windows_containment);
        Ok(())
    };
    drop(profiles_owner);
    if matches!(&service_result, Err(DaemonError::WindowsWfpLeaseLost(_))) {
        return service_result;
    }
    containment_result?;
    service_result
}

#[cfg(windows)]
async fn prepare_windows_containment(
    mode: WindowsContainmentArg,
    runtime: RuntimeArg,
    navigation_policy: &NavigationPolicy,
    profiles_root: &std::path::Path,
    egress_proxy: Option<SocketAddr>,
    broker_pipe: Option<&str>,
) -> Result<Option<WindowsWfpContainment>, DaemonError> {
    if matches!(mode, WindowsContainmentArg::Off) {
        return Ok(None);
    }
    if !navigation_policy.is_exact()
        || !matches!(runtime, RuntimeArg::Chrome | RuntimeArg::Edge)
    {
        return Err(DaemonError::WindowsContainmentScope);
    }
    let endpoint = match egress_proxy.ok_or(DaemonError::WindowsContainmentScope)? {
        SocketAddr::V4(endpoint) => endpoint,
        SocketAddr::V6(_) => return Err(DaemonError::WindowsContainmentScope),
    };
    let browser = runtime
        .broker_browser()
        .ok_or(DaemonError::WindowsContainmentScope)?;
    let broker_pipe = broker_pipe.ok_or(DaemonError::WindowsWfpBrokerPipeRequired)?;
    let request = ContainmentRequest::required(
        NetworkPolicy::deny_by_default([NetworkPermit::new(
            NetworkProtocol::Tcp,
            SocketAddr::V4(endpoint),
        )?])?,
        ContainmentRequirements {
            required_subject_scope: NetworkSubjectScope::KnownExecutableSet,
            require_station_instance_exclusive: true,
            coverage: NetworkCoverage::attributed_inet(),
            retain_on_provider_crash: true,
        },
    )?;
    let broker_capability = WindowsWfpBrokerCapability::read_from(
        std::io::stdin().lock(),
    )
    .map_err(DaemonError::WindowsWfpCapabilityStdin)?;
    let provider = WindowsWfpProvider::new(
        broker_pipe.to_owned(),
        browser,
        profiles_root,
        broker_capability,
    );
    Ok(Some(provider.acquire(&request).await?))
}

#[cfg(all(windows, feature = "containment-test-hooks"))]
fn containment_test_close_delay_argument(
    delay_millis: Option<u64>,
    containment: WindowsContainmentArg,
    runtime: RuntimeArg,
    navigation_policy: &NavigationPolicy,
    close_timeout_seconds: u64,
) -> Result<Option<String>, DaemonError> {
    let Some(delay_millis) = delay_millis else {
        return Ok(None);
    };
    // The injected delay must outlast the worker close/teardown budget
    // (not the task-execution budget) so the close path actually times
    // out and proves WFP retention until the real process tree exits.
    let close_timeout_millis = close_timeout_seconds
        .checked_mul(1_000)
        .ok_or(DaemonError::ContainmentTestHookScope)?;
    if !matches!(containment, WindowsContainmentArg::Required)
        || !matches!(runtime, RuntimeArg::Chrome | RuntimeArg::Edge)
        || !navigation_policy.is_exact()
        || !(1..=60_000).contains(&delay_millis)
        || delay_millis <= close_timeout_millis
    {
        return Err(DaemonError::ContainmentTestHookScope);
    }
    Ok(Some(format!(
        "--dig2browser-internal-test-cdp-close-delay-ms={delay_millis}"
    )))
}

#[cfg(windows)]
async fn run_station_and_egress(
    station: BrowserStation,
    server_config: ServerConfig,
    egress_proxy: Option<EgressProxy>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<DaemonReport, DaemonError> {
    let server = run_station_server(station, server_config, shutdown_rx.clone());
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
    Ok(DaemonReport {
        server: server_report,
        egress: egress_report,
        containment: None,
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
fn route_registry(
    direct_references: &[String],
    http_proxy_routes: &[String],
    socks5_proxy_routes: &[String],
    egress_proxy: Option<SocketAddr>,
) -> Result<RouteRegistry, DaemonError> {
    if egress_proxy.is_some()
        && (!http_proxy_routes.is_empty() || !socks5_proxy_routes.is_empty())
    {
        return Err(DaemonError::ExternalProxyWithExactPolicy);
    }
    let mut registry = RouteRegistry::empty();
    if direct_references.is_empty()
        && http_proxy_routes.is_empty()
        && socks5_proxy_routes.is_empty()
    {
        let reference = RouteRef::host_direct();
        let descriptor = match egress_proxy {
            Some(endpoint) => RouteDescriptor::guarded_host_direct(reference, endpoint)?,
            None => RouteDescriptor::host_direct(reference),
        };
        registry.register(descriptor)?;
    }
    for reference in direct_references {
        let reference = RouteRef::new(reference.clone())?;
        let descriptor = match egress_proxy {
            Some(endpoint) => RouteDescriptor::guarded_host_direct(reference, endpoint)?,
            None => RouteDescriptor::host_direct(reference),
        };
        registry.register(descriptor)?;
    }
    for route in http_proxy_routes {
        let (reference, endpoint) = parse_external_proxy_route(route)?;
        registry.register(RouteDescriptor::external_http(reference, endpoint)?)?;
    }
    for route in socks5_proxy_routes {
        let (reference, endpoint) = parse_external_proxy_route(route)?;
        registry.register(RouteDescriptor::external_socks5(reference, endpoint)?)?;
    }
    Ok(registry)
}

#[cfg(windows)]
fn parse_external_proxy_route(value: &str) -> Result<(RouteRef, SocketAddr), DaemonError> {
    let (reference, endpoint) = value
        .split_once('=')
        .ok_or(DaemonError::InvalidExternalProxyRoute)?;
    if reference.is_empty() || endpoint.is_empty() || endpoint.contains('=') {
        return Err(DaemonError::InvalidExternalProxyRoute);
    }
    let reference = RouteRef::new(reference.to_owned())?;
    let endpoint = endpoint
        .parse()
        .map_err(|_| DaemonError::InvalidExternalProxyRoute)?;
    Ok((reference, endpoint))
}

#[cfg(windows)]
fn validate_external_route_policy(
    navigation_policy: &NavigationPolicy,
    http_proxy_routes: &[String],
    socks5_proxy_routes: &[String],
) -> Result<(), DaemonError> {
    if navigation_policy.is_exact()
        && (!http_proxy_routes.is_empty() || !socks5_proxy_routes.is_empty())
    {
        return Err(DaemonError::ExternalProxyWithExactPolicy);
    }
    Ok(())
}

#[cfg(windows)]
struct DaemonReport {
    server: ServerReport,
    egress: Option<EgressReport>,
    containment: Option<ContainmentAssurance>,
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
    let (containment_scope, containment_station_instance_exclusive,
        containment_provider_crash, containment_tcp,
        containment_udp, containment_raw_ip, containment_system_name_resolution,
        containment_ipv4, containment_ipv6) = match report.containment {
        Some(assurance) => (
            match assurance.subject_scope {
                NetworkSubjectScope::KnownExecutableSet => "known_executable_set",
                NetworkSubjectScope::SignedApplicationAndHelpers => {
                    "signed_application_and_helpers"
                }
                NetworkSubjectScope::InheritedProcessTree => "inherited_process_tree",
            },
            assurance.station_instance_exclusive,
            match assurance.provider_crash {
                ProviderCrashBehavior::EnforcementLost => "enforcement_lost",
                ProviderCrashBehavior::EnforcementRetained => "enforcement_retained",
            },
            assurance.coverage.tcp,
            assurance.coverage.udp,
            assurance.coverage.raw_ip,
            assurance.coverage.system_name_resolution,
            assurance.coverage.ipv4,
            assurance.coverage.ipv6,
        ),
        None => (
            "disabled",
            false,
            "not_applicable",
            false,
            false,
            false,
            false,
            false,
            false,
        ),
    };
    println!(
        "{{\"schema_version\":1,\"event\":\"station_exit\",\"outcome\":\"{outcome}\",\"stop_reason\":\"{}\",\"accepted_connections\":{},\"completed_connections\":{},\"aborted_connections\":{},\"stopped_workers\":{},\"drain_timed_out\":{},\"egress_accepted_connections\":{},\"egress_completed_connections\":{},\"egress_denied_connections\":{},\"egress_invalid_connections\":{},\"egress_idle_connections\":{},\"egress_failed_connections\":{},\"egress_timed_out_connections\":{},\"egress_aborted_connections\":{},\"egress_drain_timed_out\":{},\"containment_subject_scope\":\"{containment_scope}\",\"containment_station_instance_exclusive\":{containment_station_instance_exclusive},\"containment_provider_crash\":\"{containment_provider_crash}\",\"containment_tcp\":{containment_tcp},\"containment_udp\":{containment_udp},\"containment_raw_ip\":{containment_raw_ip},\"containment_system_name_resolution\":{containment_system_name_resolution},\"containment_ipv4\":{containment_ipv4},\"containment_ipv6\":{containment_ipv6}}}",
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
        egress.idle_connections,
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
    #[error("external proxy route must use REF=IP:PORT")]
    InvalidExternalProxyRoute,
    #[error("external proxy routes cannot be combined with exact-origin policy")]
    ExternalProxyWithExactPolicy,
    #[error("private peer exceptions require an exact-origin policy")]
    PrivatePeersRequireExactPolicy,
    #[error("geckodriver path and URL cannot be configured together")]
    GeckodriverSourceConflict,
    #[error("geckodriver options require the exact Firefox runtime")]
    GeckodriverScope,
    #[error("the exact Firefox runtime requires --geckodriver-path, GECKODRIVER, or explicit --geckodriver-url")]
    GeckodriverRequired,
    #[error("external geckodriver URL must be an exact loopback HTTP socket address")]
    GeckodriverExternalUrl,
    #[error("required Windows containment needs an exact Chrome or Edge runtime")]
    WindowsContainmentScope,
    #[error("required Windows containment needs a launcher-scoped WFP broker pipe")]
    WindowsWfpBrokerPipeRequired,
    #[error(transparent)]
    ContainmentContract(#[from] ContainmentContractError),
    #[error(transparent)]
    BrowserDetect(#[from] dig2browser::detect::DetectError),
    #[error(transparent)]
    WindowsWfpProvider(#[from] WindowsWfpProviderError),
    #[error("cannot read required Windows containment capability from stdin")]
    WindowsWfpCapabilityStdin(#[source] io::Error),
    #[error("Windows WFP broker lease was lost: {0}")]
    WindowsWfpLeaseLost(WindowsWfpLeaseLoss),
    #[cfg(feature = "containment-test-hooks")]
    #[error("test Chromium close delay requires exact contained Chrome or Edge and must exceed the command timeout")]
    ContainmentTestHookScope,
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
            Self::BrowserDetect(_)
            | Self::WindowsWfpProvider(WindowsWfpProviderError::Mirror(_)) => {
                "containment_unavailable"
            }
            Self::WindowsWfpProvider(WindowsWfpProviderError::Broker(
                WindowsWfpBrokerError::Rejected {
                code: WindowsWfpBrokerRejectCode::InvalidProxy
                    | WindowsWfpBrokerRejectCode::InvalidScope
                    | WindowsWfpBrokerRejectCode::InvalidMirror
                    | WindowsWfpBrokerRejectCode::Protocol,
                ..
                },
            ))
            | Self::WindowsWfpProvider(WindowsWfpProviderError::Broker(
                WindowsWfpBrokerError::InvalidPipeName,
            ))
            | Self::WindowsWfpProvider(
                WindowsWfpProviderError::UnsupportedRequest(_)
                    | WindowsWfpProviderError::Contract(_),
            ) => {
                "invalid_config"
            }
            Self::WindowsWfpProvider(WindowsWfpProviderError::Broker(_))
            | Self::WindowsWfpCapabilityStdin(_) => {
                "containment_unavailable"
            }
            Self::WindowsWfpLeaseLost(_) => "containment_lost",
            #[cfg(feature = "tls-test-hooks")]
            Self::TestChromeCertificateErrorScope
            | Self::TestChromeCertificateErrorSpki(_) => "invalid_config",
            #[cfg(feature = "containment-test-hooks")]
            Self::ContainmentTestHookScope => "invalid_config",
            Self::StationConfig(_)
            | Self::InvalidExternalProxyRoute
            | Self::ExternalProxyWithExactPolicy
            | Self::PrivatePeersRequireExactPolicy
            | Self::GeckodriverSourceConflict
            | Self::GeckodriverScope
            | Self::GeckodriverRequired
            | Self::GeckodriverExternalUrl
            | Self::WindowsContainmentScope
            | Self::WindowsWfpBrokerPipeRequired
            | Self::ContainmentContract(_)
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
            // `ServerError::Live` can only arise from the live-capture
            // manager's shutdown-time lease drain, not a boot-time
            // misconfiguration — same class as a station shutdown failure.
            Self::Server(ServerError::Live(_)) => "station_shutdown_failure",
            // A durable-monitor error at boot is a monitor-root setup failure
            // (open/reconcile); at shutdown it is a lease-drain failure — both
            // surface as the monitor root being unavailable.
            Self::Server(ServerError::Monitor(_)) => "monitor_root_unavailable",
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

#[cfg(all(test, windows))]
mod route_cli_tests {
    use super::*;

    #[cfg(feature = "containment-test-hooks")]
    #[test]
    fn containment_close_delay_hook_is_strictly_scoped_and_exceeds_timeout() {
        let exact = NavigationPolicy::exact_origins(&[
            "http://127.0.0.1:18080".to_owned(),
        ])
        .expect("exact policy");
        let argument = containment_test_close_delay_argument(
            Some(30_000),
            WindowsContainmentArg::Required,
            RuntimeArg::Chrome,
            &exact,
            1,
        )
        .expect("valid close-delay hook");
        assert_eq!(
            argument.as_deref(),
            Some("--dig2browser-internal-test-cdp-close-delay-ms=30000")
        );

        for (delay, containment, runtime, policy, timeout) in [
            (1_000, WindowsContainmentArg::Required, RuntimeArg::Chrome,
                exact.clone(), 1),
            (60_001, WindowsContainmentArg::Required, RuntimeArg::Chrome,
                exact.clone(), 1),
            (30_000, WindowsContainmentArg::Off, RuntimeArg::Chrome,
                exact.clone(), 1),
            (30_000, WindowsContainmentArg::Required, RuntimeArg::Firefox,
                exact.clone(), 1),
            (30_000, WindowsContainmentArg::Required, RuntimeArg::Chrome,
                NavigationPolicy::default(), 1),
        ] {
            assert!(matches!(
                containment_test_close_delay_argument(
                    Some(delay), containment, runtime, &policy, timeout,
                ),
                Err(DaemonError::ContainmentTestHookScope)
            ));
        }
    }

    #[test]
    fn firefox_geckodriver_source_is_owned_by_default_and_external_only_when_explicit() {
        let cli_path = PathBuf::from(r"C:\tools\cli-geckodriver.exe");
        let environment_path = std::ffi::OsString::from(r"C:\tools\env-geckodriver.exe");
        let source = select_geckodriver_source(
            RuntimeArg::Firefox,
            Some(cli_path.clone()),
            None,
            Some(environment_path.clone()),
        )
        .expect("CLI path source");
        assert!(matches!(source, Some(GeckodriverSource::Owned(path)) if path == cli_path));

        let source = select_geckodriver_source(
            RuntimeArg::Firefox,
            None,
            Some("http://127.0.0.1:4444".into()),
            Some(environment_path.clone()),
        )
        .expect("environment source precedes rollback URL");
        assert!(matches!(
            source,
            Some(GeckodriverSource::Owned(path))
                if path.as_os_str() == environment_path.as_os_str()
        ));

        let source = select_geckodriver_source(
            RuntimeArg::Firefox,
            None,
            Some("http://127.0.0.1:4444".into()),
            None,
        )
        .expect("explicit rollback URL");
        assert!(matches!(
            source,
            Some(GeckodriverSource::External(url)) if url == "http://127.0.0.1:4444"
        ));
    }

    #[test]
    fn firefox_geckodriver_source_rejects_missing_conflicting_and_misscoped_config() {
        assert!(matches!(
            select_geckodriver_source(RuntimeArg::Firefox, None, None, None),
            Err(DaemonError::GeckodriverRequired)
        ));
        assert!(matches!(
            select_geckodriver_source(
                RuntimeArg::Firefox,
                Some(PathBuf::from("geckodriver.exe")),
                Some("http://127.0.0.1:4444".into()),
                None,
            ),
            Err(DaemonError::GeckodriverSourceConflict)
        ));
        assert!(matches!(
            select_geckodriver_source(
                RuntimeArg::Chrome,
                Some(PathBuf::from("geckodriver.exe")),
                None,
                None,
            ),
            Err(DaemonError::GeckodriverScope)
        ));

        for invalid in [
            "https://127.0.0.1:4444",
            "http://localhost:4444",
            "http://192.0.2.1:4444",
            "http://127.0.0.1:0",
            "http://127.0.0.1:4444/status",
        ] {
            assert!(matches!(
                select_geckodriver_source(
                    RuntimeArg::Firefox,
                    None,
                    Some(invalid.to_owned()),
                    None,
                ),
                Err(DaemonError::GeckodriverExternalUrl)
            ));
        }
    }

    #[test]
    fn external_proxy_route_requires_strict_reference_and_ip_endpoint() {
        let (reference, endpoint) = parse_external_proxy_route(
            "research.http=192.0.2.10:8080",
        )
        .expect("valid external proxy route");
        assert_eq!(reference.as_str(), "research.http");
        assert_eq!(endpoint, "192.0.2.10:8080".parse().expect("endpoint"));

        for malformed in [
            "research.http",
            "=192.0.2.10:8080",
            "research.http=",
            "research.http=proxy.example:8080",
            "research.http=192.0.2.10:8080=extra",
        ] {
            assert!(matches!(
                parse_external_proxy_route(malformed),
                Err(DaemonError::InvalidExternalProxyRoute)
                    | Err(DaemonError::RouteRef(_))
            ));
        }
    }

    #[test]
    fn containment_cli_requires_launcher_scoped_broker_pipe_only_when_enabled() {
        let cli = Cli::try_parse_from([
            "dig2browser-stationd",
            "--profiles-root",
            r"C:\dig2browser-containment-test",
        ])
        .expect("disabled containment CLI");
        assert!(cli.windows_wfp_broker_pipe.is_none());

        let missing = Cli::try_parse_from([
            "dig2browser-stationd",
            "--profiles-root",
            r"C:\dig2browser-containment-test",
            "--windows-containment",
            "required",
        ]);
        assert!(missing.is_err());

        let cli = Cli::try_parse_from([
            "dig2browser-stationd",
            "--profiles-root",
            r"C:\dig2browser-containment-test",
            "--windows-containment",
            "required",
            "--windows-wfp-broker-pipe",
            "dig2browser-wfp-broker-9d4e8a5907ee4fbf",
        ])
        .expect("required containment CLI");
        assert_eq!(
            cli.windows_wfp_broker_pipe.as_deref(),
            Some("dig2browser-wfp-broker-9d4e8a5907ee4fbf")
        );
    }

    #[test]
    fn route_catalog_rejects_duplicate_references_across_transports() {
        let error = route_registry(
            &["shared.route".to_owned()],
            &["shared.route=192.0.2.10:8080".to_owned()],
            &[],
            None,
        )
        .expect_err("duplicate route must fail closed");
        assert!(matches!(
            error,
            DaemonError::RouteRegistry(RouteRegistryError::DuplicateRoute)
        ));
    }

    #[test]
    fn proxy_only_cli_builds_external_only_catalog() {
        let cli = Cli::try_parse_from([
            "dig2browser-stationd",
            "--profiles-root",
            r"C:\dig2browser-route-test",
            "--http-proxy-route",
            "research.http=192.0.2.10:8080",
            "--socks5-proxy-route",
            "research.socks=198.51.100.20:1080",
        ])
        .expect("proxy-only CLI");
        assert!(cli.direct_route_refs.is_empty());

        let mut registry = route_registry(
            &cli.direct_route_refs,
            &cli.http_proxy_routes,
            &cli.socks5_proxy_routes,
            None,
        )
        .expect("external-only route catalog");
        registry
            .register(RouteDescriptor::host_direct(RouteRef::host_direct()))
            .expect("host.direct must remain unknown in proxy-only catalog");
    }

    #[test]
    fn route_free_cli_gets_implicit_host_direct_compatibility() {
        let cli = Cli::try_parse_from([
            "dig2browser-stationd",
            "--profiles-root",
            r"C:\dig2browser-route-test",
        ])
        .expect("route-free CLI");
        assert!(cli.direct_route_refs.is_empty());
        assert!(cli.http_proxy_routes.is_empty());
        assert!(cli.socks5_proxy_routes.is_empty());

        let mut registry = route_registry(
            &cli.direct_route_refs,
            &cli.http_proxy_routes,
            &cli.socks5_proxy_routes,
            None,
        )
        .expect("implicit host-direct catalog");
        assert_eq!(
            registry.register(RouteDescriptor::host_direct(RouteRef::host_direct())),
            Err(RouteRegistryError::DuplicateRoute)
        );
    }

    #[test]
    fn external_proxy_routes_reject_exact_origin_policy() {
        let exact = NavigationPolicy::exact_origins(["https://example.test"])
            .expect("exact policy");
        assert!(matches!(
            validate_external_route_policy(
                &exact,
                &["research.http=192.0.2.10:8080".to_owned()],
                &[],
            ),
            Err(DaemonError::ExternalProxyWithExactPolicy)
        ));
        assert!(validate_external_route_policy(
            &NavigationPolicy::default(),
            &["research.http=192.0.2.10:8080".to_owned()],
            &["research.socks=198.51.100.20:1080".to_owned()],
        )
        .is_ok());
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("dig2browser-stationd requires Windows named pipes");
    std::process::exit(1);
}
