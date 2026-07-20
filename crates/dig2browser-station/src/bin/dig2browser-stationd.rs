#[cfg(windows)]
use std::path::PathBuf;
#[cfg(windows)]
use std::process::ExitCode;
#[cfg(windows)]
use std::time::Duration;

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
    BrowserStation, CollectionError, ConfigError as StationConfigError, ProfilesRootError,
    ProfilesRootOwnership, RouteDescriptor, RouteRegistry, RouteRegistryError, RuntimeKind,
    RuntimeSelector, StationConfig,
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
        help = "Allow an HTTP(S) URL origin for explicit and page-target requests; this is not DNS or peer-IP isolation"
    )]
    allowed_origins: Vec<String>,
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
async fn run(cli: Cli) -> Result<ServerReport, DaemonError> {
    let profiles_owner = ProfilesRootOwnership::acquire(&cli.profiles_root)?;
    let route_registry = direct_route_registry(&cli.direct_route_refs)?;
    let navigation_policy = if cli.allowed_origins.is_empty() {
        NavigationPolicy::default()
    } else {
        NavigationPolicy::exact_origins(&cli.allowed_origins)?
    };
    let command_timeout = Duration::from_secs(cli.timeout_seconds);
    let worker = BrowserWorkerConfig {
        command_timeout,
        ..BrowserWorkerConfig::default()
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
    .allow_durable_write(cli.allow_durable_write);
    if let Some(trace_root) = cli.trace_root {
        server_config = server_config.trace_root(trace_root)?;
    }
    let station = BrowserStation::new(station_config);
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        shutdown_tx.send_replace(true);
    });
    let report = run_station_server(station, server_config, shutdown_rx).await?;
    drop(profiles_owner);
    Ok(report)
}

#[cfg(windows)]
fn direct_route_registry(references: &[String]) -> Result<RouteRegistry, DaemonError> {
    if references.is_empty() {
        return Err(DaemonError::NoDirectRoutes);
    }
    let mut registry = RouteRegistry::empty();
    for reference in references {
        let reference = RouteRef::new(reference.clone())?;
        registry.register(RouteDescriptor::host_direct(reference))?;
    }
    Ok(registry)
}

#[cfg(windows)]
fn print_report(report: ServerReport) {
    let outcome = if report.drain_timed_out {
        "drain_timeout"
    } else {
        "clean"
    };
    println!(
        "{{\"schema_version\":1,\"event\":\"station_exit\",\"outcome\":\"{outcome}\",\"stop_reason\":\"{}\",\"accepted_connections\":{},\"completed_connections\":{},\"aborted_connections\":{},\"stopped_workers\":{},\"drain_timed_out\":{}}}",
        report.stop_reason.as_str(),
        report.accepted_connections,
        report.completed_connections,
        report.aborted_connections,
        report.stopped_workers,
        report.drain_timed_out
    );
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
    #[error(transparent)]
    RouteRef(#[from] RouteRefError),
    #[error(transparent)]
    RouteRegistry(#[from] RouteRegistryError),
    #[error(transparent)]
    NavigationPolicy(#[from] NavigationPolicyError),
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
            Self::StationConfig(_)
            | Self::NoDirectRoutes
            | Self::RouteRef(_)
            | Self::RouteRegistry(_)
            | Self::NavigationPolicy(_)
            | Self::ServerConfig(_) => "invalid_config",
            Self::Server(ServerError::UnsupportedPlatform) => "unsupported_platform",
            Self::Server(ServerError::Io(_)) => "station_endpoint_unavailable",
            Self::Server(ServerError::Frame(_)) => "station_protocol_failure",
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
            Self::Server(ServerError::Station(_)) => "station_shutdown_failure",
        }
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("dig2browser-stationd requires Windows named pipes");
    std::process::exit(1);
}
