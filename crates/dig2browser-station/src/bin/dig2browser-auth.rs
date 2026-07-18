#[cfg(windows)]
use std::process::ExitCode;
#[cfg(windows)]
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(windows)]
use clap::{Parser, Subcommand, ValueEnum};
#[cfg(windows)]
use dig2browser_client::{
    BrowserPersona, ClientConfig, SessionPhase, SessionStateUpdate,
    SessionHealthProbe, StationClient, DEFAULT_STATION_PIPE,
};

#[cfg(windows)]
#[derive(Debug, Parser)]
#[command(name = "dig2browser-auth")]
struct Cli {
    #[arg(long, default_value = DEFAULT_STATION_PIPE)]
    pipe_name: String,
    #[arg(long, default_value_t = 15)]
    connect_timeout_seconds: u64,
    #[arg(long, default_value_t = 90)]
    request_timeout_seconds: u64,
    #[command(subcommand)]
    command: Command,
}

#[cfg(windows)]
#[derive(Debug, Subcommand)]
enum Command {
    Begin {
        #[arg(long)]
        profile_id: String,
        #[arg(long)]
        url: String,
        #[arg(long, value_enum, default_value_t = PersonaPreset::Desktop)]
        persona: PersonaPreset,
    },
    Finish {
        #[arg(long)]
        profile_id: String,
    },
    Status {
        #[arg(long)]
        profile_id: String,
    },
    Ready {
        #[arg(long)]
        profile_id: String,
        #[arg(long)]
        ttl_seconds: u64,
    },
    Check {
        #[arg(long)]
        profile_id: String,
        #[arg(long)]
        url: String,
        #[arg(long)]
        ready_selector: String,
        #[arg(long)]
        reauth_selector: String,
        #[arg(long, default_value_t = 900)]
        ready_ttl_seconds: u32,
        #[arg(long, value_enum, default_value_t = PersonaPreset::Desktop)]
        persona: PersonaPreset,
    },
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, ValueEnum)]
enum PersonaPreset {
    Desktop,
    Mobile,
}

#[cfg(windows)]
impl PersonaPreset {
    fn persona(self) -> BrowserPersona {
        match self {
            Self::Desktop => BrowserPersona::desktop_default(),
            Self::Mobile => BrowserPersona::mobile_default(),
        }
    }
}

#[cfg(windows)]
#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(class) => {
            eprintln!(
                "{{\"schema_version\":1,\"event\":\"auth_command\",\"outcome\":\"error\",\"error_class\":\"{class}\"}}"
            );
            ExitCode::FAILURE
        }
    }
}

#[cfg(windows)]
async fn run(cli: Cli) -> Result<(), &'static str> {
    let config = ClientConfig::new(
        cli.pipe_name,
        Duration::from_secs(cli.connect_timeout_seconds),
        Duration::from_secs(cli.request_timeout_seconds),
    )
    .map_err(|_| "invalid_config")?;
    let client = StationClient::connect(config)
        .await
        .map_err(|_| "station_unavailable")?;
    match cli.command {
        Command::Begin {
            profile_id,
            url,
            persona,
        } => {
            client
                .begin_auth_session(profile_id, persona.persona(), url)
                .await
                .map_err(|_| "begin_failed")?;
            println!(
                "{{\"schema_version\":1,\"event\":\"auth_session\",\"state\":\"open\"}}"
            );
        }
        Command::Finish { profile_id } => {
            client
                .finish_auth_session(profile_id)
                .await
                .map_err(|_| "finish_failed")?;
            println!(
                "{{\"schema_version\":1,\"event\":\"auth_session\",\"state\":\"closed\"}}"
            );
        }
        Command::Status { profile_id } => {
            let status = client
                .identity_status(profile_id)
                .await
                .map_err(|_| "status_failed")?;
            println!(
                "{{\"schema_version\":1,\"event\":\"auth_status\",\"phase\":\"{}\",\"updated_at_unix_ms\":{},\"expires_at_unix_ms\":{}}}",
                phase_name(status.phase),
                status.updated_at_unix_ms,
                status
                    .expires_at_unix_ms
                    .map_or_else(|| "null".to_owned(), |value| value.to_string())
            );
        }
        Command::Ready {
            profile_id,
            ttl_seconds,
        } => {
            if ttl_seconds == 0 {
                return Err("invalid_ttl");
            }
            let expires_at_unix_ms = unix_time_ms()
                .checked_add(
                    ttl_seconds
                        .checked_mul(1_000)
                        .ok_or("invalid_ttl")?,
                )
                .ok_or("invalid_ttl")?;
            client
                .update_identity_state(
                    profile_id,
                    SessionStateUpdate {
                        phase: SessionPhase::Ready,
                        expires_at_unix_ms: Some(expires_at_unix_ms),
                    },
                )
                .await
                .map_err(|_| "ready_failed")?;
            println!(
                "{{\"schema_version\":1,\"event\":\"auth_status\",\"phase\":\"ready\",\"expires_at_unix_ms\":{expires_at_unix_ms}}}"
            );
        }
        Command::Check {
            profile_id,
            url,
            ready_selector,
            reauth_selector,
            ready_ttl_seconds,
            persona,
        } => {
            let status = client
                .check_auth_session(
                    profile_id,
                    persona.persona(),
                    SessionHealthProbe {
                        url,
                        ready_selector,
                        reauth_selector,
                        ready_ttl_seconds,
                    },
                )
                .await
                .map_err(|_| "check_failed")?;
            println!(
                "{{\"schema_version\":1,\"event\":\"auth_status\",\"phase\":\"{}\",\"updated_at_unix_ms\":{},\"expires_at_unix_ms\":{}}}",
                phase_name(status.phase),
                status.updated_at_unix_ms,
                status
                    .expires_at_unix_ms
                    .map_or_else(|| "null".to_owned(), |value| value.to_string())
            );
        }
    }
    Ok(())
}

#[cfg(windows)]
fn phase_name(phase: SessionPhase) -> &'static str {
    match phase {
        SessionPhase::Unknown => "unknown",
        SessionPhase::Ready => "ready",
        SessionPhase::ReauthRequired => "reauth_required",
        SessionPhase::Expired => "expired",
    }
}

#[cfg(windows)]
fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or_default()
}

#[cfg(not(windows))]
fn main() {
    eprintln!("dig2browser-auth is supported only on Windows");
}
