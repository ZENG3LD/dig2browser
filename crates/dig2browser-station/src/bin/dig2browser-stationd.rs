#[cfg(windows)]
use std::path::PathBuf;
#[cfg(windows)]
use std::process::ExitCode;
#[cfg(windows)]
use std::time::Duration;

#[cfg(windows)]
use clap::Parser;
#[cfg(windows)]
use dig2browser::agentic::BrowserWorkerConfig;
#[cfg(windows)]
use dig2browser_protocol::DEFAULT_STATION_PIPE;
#[cfg(windows)]
use dig2browser_station::ipc::{
    run_station_server, ConfigError as ServerConfigError, ServerConfig, ServerError,
    ServerReport,
};
#[cfg(windows)]
use dig2browser_station::{
    BrowserStation, ConfigError as StationConfigError, ProfilesRootError,
    ProfilesRootOwnership, StationConfig,
};

#[cfg(windows)]
#[derive(Debug, Parser)]
#[command(name = "dig2browser-stationd")]
struct Cli {
    #[arg(long, default_value = DEFAULT_STATION_PIPE)]
    pipe_name: String,
    #[arg(long)]
    profiles_root: PathBuf,
    #[arg(long, default_value_t = 16)]
    max_resident: usize,
    #[arg(long, default_value_t = 32)]
    max_in_flight: usize,
    #[arg(long, default_value_t = 64)]
    max_connections: usize,
    #[arg(long, default_value_t = 90)]
    timeout_seconds: u64,
    #[arg(long, default_value_t = 15)]
    drain_seconds: u64,
    #[arg(long, default_value_t = false)]
    allow_remote_shutdown: bool,
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
    .with_worker_config(worker);
    let server_config = ServerConfig::new(
        cli.pipe_name,
        cli.max_connections,
        Duration::from_secs(cli.drain_seconds),
    )?
    .allow_remote_shutdown(cli.allow_remote_shutdown);
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
            Self::StationConfig(_) | Self::ServerConfig(_) => "invalid_config",
            Self::Server(ServerError::UnsupportedPlatform) => "unsupported_platform",
            Self::Server(ServerError::Io(_)) => "station_endpoint_unavailable",
            Self::Server(ServerError::Frame(_)) => "station_protocol_failure",
            Self::Server(ServerError::Station(_)) => "station_shutdown_failure",
        }
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("dig2browser-stationd requires Windows named pipes");
    std::process::exit(1);
}
