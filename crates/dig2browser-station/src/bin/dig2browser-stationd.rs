#[cfg(windows)]
use std::path::PathBuf;
#[cfg(windows)]
use std::time::Duration;

#[cfg(windows)]
use clap::Parser;
#[cfg(windows)]
use dig2browser::agentic::BrowserWorkerConfig;
#[cfg(windows)]
use dig2browser_station::ipc::{run_station_server, ServerConfig};
#[cfg(windows)]
use dig2browser_station::{BrowserStation, StationConfig};

#[cfg(windows)]
#[derive(Debug, Parser)]
#[command(name = "dig2browser-stationd")]
struct Cli {
    #[arg(long)]
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
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let command_timeout = Duration::from_secs(cli.timeout_seconds);
    let worker = BrowserWorkerConfig {
        command_timeout,
        ..BrowserWorkerConfig::default()
    };
    let station_config = StationConfig::new(
        &cli.profiles_root,
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
    let _report = run_station_server(station, server_config, shutdown_rx).await?;
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("dig2browser-stationd requires Windows named pipes");
    std::process::exit(1);
}
