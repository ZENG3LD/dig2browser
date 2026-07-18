#[cfg(windows)]
use std::path::PathBuf;
#[cfg(windows)]
use std::time::Duration;

#[cfg(windows)]
use clap::Parser;
#[cfg(windows)]
use dig2browser::worker_ipc::{run_worker_server, WorkerIpcConfig};

#[cfg(windows)]
#[derive(Debug, Parser)]
#[command(name = "dig2browser-worker")]
struct Cli {
    #[arg(long)]
    pipe_name: String,
    #[arg(long)]
    profiles_root: PathBuf,
    #[arg(long, default_value_t = 90)]
    timeout_seconds: u64,
    #[arg(long, default_value_t = 4)]
    max_resident: usize,
}

#[cfg(windows)]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let config = WorkerIpcConfig::new(
        cli.pipe_name,
        cli.profiles_root,
        Duration::from_secs(cli.timeout_seconds),
        cli.max_resident,
    )?;
    run_worker_server(config).await?;
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("dig2browser-worker requires Windows named pipes");
    std::process::exit(1);
}
