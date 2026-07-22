#[cfg(windows)]
use std::path::PathBuf;
#[cfg(windows)]
use std::process::ExitCode;

#[cfg(windows)]
use clap::Parser;
#[cfg(windows)]
use dig2browser_station::windows_wfp_broker::{
    run_windows_wfp_broker, WindowsWfpBrokerCapability,
};
#[cfg(windows)]
use serde::Serialize;

#[cfg(windows)]
#[derive(Debug, Parser)]
#[command(name = "dig2browser-wfp-broker")]
struct Cli {
    #[arg(long)]
    pipe_name: String,
    #[arg(long)]
    allowed_runtime_root: PathBuf,
}

#[cfg(windows)]
#[derive(Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
enum CliFailure<'a> {
    InvalidArguments { version: u16, message: &'a str },
    SerializationFailed { version: u16 },
}

#[cfg(windows)]
#[tokio::main]
async fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            emit_json(&CliFailure::InvalidArguments {
                version: 3,
                message: &error.to_string(),
            });
            return ExitCode::FAILURE;
        }
    };
    let capability = match WindowsWfpBrokerCapability::read_from(std::io::stdin().lock()) {
        Ok(capability) => capability,
        Err(error) => {
            emit_json(&CliFailure::InvalidArguments {
                version: 3,
                message: &format!("cannot read broker launch capability from stdin: {error}"),
            });
            return ExitCode::FAILURE;
        }
    };
    let outcome = run_windows_wfp_broker(
        &cli.pipe_name,
        &cli.allowed_runtime_root,
        capability,
    )
    .await;
    let clean = outcome.is_clean_close();
    emit_json(&outcome);
    if clean {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(windows)]
fn emit_json<T: Serialize>(value: &T) {
    match serde_json::to_string(value) {
        Ok(encoded) => println!("{encoded}"),
        Err(_) => {
            let fallback = CliFailure::SerializationFailed { version: 3 };
            if let Ok(encoded) = serde_json::to_string(&fallback) {
                println!("{encoded}");
            }
        }
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn broker_cli_requires_launcher_scoped_pipe_name() {
        let parsed = Cli::try_parse_from([
            "dig2browser-wfp-broker",
            "--allowed-runtime-root",
            r"C:\Users\operator\AppData\Local\dig2browser\runtime-mirrors",
        ]);
        assert!(parsed.is_err());

        let cli = Cli::try_parse_from([
            "dig2browser-wfp-broker",
            "--pipe-name",
            "dig2browser-wfp-broker-9d4e8a5907ee4fbf",
            "--allowed-runtime-root",
            r"C:\Users\operator\AppData\Local\dig2browser\runtime-mirrors",
        ])
        .expect("launcher-scoped broker CLI");
        assert_eq!(
            cli.pipe_name,
            "dig2browser-wfp-broker-9d4e8a5907ee4fbf"
        );
    }

    #[test]
    fn broker_cli_does_not_accept_capability_in_argv() {
        let parsed = Cli::try_parse_from([
            "dig2browser-wfp-broker",
            "--allowed-runtime-root",
            r"C:\Users\operator\AppData\Local\dig2browser\runtime-mirrors",
            "--capability",
            "not-a-secret-channel",
        ]);
        assert!(parsed.is_err());
    }
}

#[cfg(not(windows))]
fn main() {
    println!(r#"{{"outcome":"unsupported_platform","version":3}}"#);
}
