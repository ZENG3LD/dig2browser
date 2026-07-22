use std::ffi::OsString;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::sync::atomic::{compiler_fence, Ordering};
use std::time::Duration;

use dig2browser::detect::{BrowserBinary, BrowserKind};
use dig2browser::{
    WindowsBrowserRuntimeMirror, WindowsRuntimeMirrorScope,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::{self, Instant};
use windows::core::{GUID, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY,
    ERROR_PIPE_NOT_CONNECTED, FILETIME, GENERIC_ALL, HANDLE, WAIT_FAILED,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::Security::{
    AddAccessAllowedAceEx, CreateWellKnownSid, GetLengthSid,
    GetTokenInformation, InitializeAcl, InitializeSecurityDescriptor,
    IsValidSecurityDescriptor, RevertToSelf, SetSecurityDescriptorDacl,
    SetSecurityDescriptorOwner, TokenElevation, TokenUser, ACL,
    ACL_REVISION, ACCESS_ALLOWED_ACE, NO_INHERITANCE, PSECURITY_DESCRIPTOR,
    PSID, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, SECURITY_MAX_SID_SIZE,
    TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_USER, WinLocalSystemSid,
};
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::System::Pipes::{
    GetNamedPipeClientProcessId, GetNamedPipeServerProcessId,
    ImpersonateNamedPipeClient,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetProcessId, GetProcessTimes, OpenProcess,
    OpenProcessToken, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SYNCHRONIZE,
};
use windows::Win32::UI::Shell::{
    FOLDERID_LocalAppData, FOLDERID_ProgramFiles, FOLDERID_ProgramFilesX86,
    KF_FLAG_DEFAULT, SHGetKnownFolderPath,
};

use crate::windows_containment::{WindowsContainmentError, WindowsContainmentGuard};

const PROTOCOL_VERSION: u16 = 3;
const CAPABILITY_BYTES: usize = 32;
const MAX_FRAME_BYTES: usize = 64 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(60);
const PREAUTH_FRAME_TIMEOUT: Duration = Duration::from_secs(2);
const PREAUTH_REJECT_TIMEOUT: Duration = Duration::from_millis(250);
const PREAUTH_RETRY_DELAY: Duration = Duration::from_millis(25);
const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);
const SECURITY_DESCRIPTOR_REVISION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum ClientFrame {
    Acquire {
        version: u16,
        client_pid: u32,
        client_creation_filetime: u64,
        #[serde(default)]
        capability: Option<WindowsWfpBrokerCapability>,
        browser: BrokerBrowser,
        mirror_scope: String,
        proxy: SocketAddrV4,
    },
    Close {
        version: u16,
    },
}

/// A one-use secret shared only by the broker launcher and its intended client.
///
/// Use [`Self::generate_pair`] immediately before launching the elevated broker,
/// write the broker copy to its stdin, and move the client copy into
/// [`acquire_windows_wfp_lease`]. The value is deliberately not `Clone` and its
/// debug representation never contains secret bytes.
#[derive(Serialize, Deserialize)]
pub struct WindowsWfpBrokerCapability([u8; CAPABILITY_BYTES]);

impl WindowsWfpBrokerCapability {
    pub fn generate_pair() -> (Self, Self) {
        let mut first = uuid::Uuid::new_v4().into_bytes();
        let mut second = uuid::Uuid::new_v4().into_bytes();
        let mut bytes = [0_u8; CAPABILITY_BYTES];
        bytes[..16].copy_from_slice(&first);
        bytes[16..].copy_from_slice(&second);
        let broker = Self(bytes);
        let client = Self(bytes);
        zeroize_bytes(&mut first);
        zeroize_bytes(&mut second);
        zeroize_bytes(&mut bytes);
        (broker, client)
    }

    /// Reads the raw fixed-width capability transported over an inherited pipe.
    pub fn read_from(mut reader: impl io::Read) -> io::Result<Self> {
        let mut bytes = [0_u8; CAPABILITY_BYTES];
        match reader.read_exact(&mut bytes) {
            Ok(()) => Ok(Self(bytes)),
            Err(error) => {
                zeroize_bytes(&mut bytes);
                Err(error)
            }
        }
    }

    /// Writes and consumes the raw capability without placing it in argv or text.
    pub fn write_to(mut self, mut writer: impl io::Write) -> io::Result<()> {
        let result = writer.write_all(&self.0);
        zeroize_bytes(&mut self.0);
        result
    }

    /// Writes and consumes the raw capability through an async child-stdin pipe.
    pub async fn write_to_async<W>(mut self, writer: &mut W) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let result = async {
            writer.write_all(&self.0).await?;
            writer.flush().await
        }
        .await;
        zeroize_bytes(&mut self.0);
        result
    }

    fn constant_time_matches(&self, other: &Self) -> bool {
        let mut difference = 0_u8;
        for index in 0..CAPABILITY_BYTES {
            difference |= self.0[index] ^ other.0[index];
        }
        difference == 0
    }
}

impl std::fmt::Debug for WindowsWfpBrokerCapability {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("WindowsWfpBrokerCapability([REDACTED])")
    }
}

impl Drop for WindowsWfpBrokerCapability {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.0);
    }
}

struct OneTimeBrokerCapability(Option<WindowsWfpBrokerCapability>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CapabilityAuthorizationError {
    Missing,
    Invalid,
    Consumed,
}

impl OneTimeBrokerCapability {
    fn new(capability: WindowsWfpBrokerCapability) -> Self {
        Self(Some(capability))
    }

    fn authorize(
        &mut self,
        presented: Option<WindowsWfpBrokerCapability>,
    ) -> Result<(), CapabilityAuthorizationError> {
        let expected = self.0.as_ref()
            .ok_or(CapabilityAuthorizationError::Consumed)?;
        let presented = presented
            .ok_or(CapabilityAuthorizationError::Missing)?;
        if expected.constant_time_matches(&presented) {
            self.0.take();
            Ok(())
        } else {
            Err(CapabilityAuthorizationError::Invalid)
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum BrokerFrame {
    Granted {
        version: u16,
        mirror_root: PathBuf,
        mirror_scope: String,
        app_id_count: u16,
    },
    Closed {
        version: u16,
    },
    Rejected {
        version: u16,
        code: WindowsWfpBrokerRejectCode,
        message: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerBrowser {
    Chrome,
    Edge,
}

impl BrokerBrowser {
    fn kind(self) -> BrowserKind {
        match self {
            Self::Chrome => BrowserKind::Chrome,
            Self::Edge => BrowserKind::Edge,
        }
    }

    fn executable_name(self) -> &'static str {
        match self {
            Self::Chrome => "chrome.exe",
            Self::Edge => "msedge.exe",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsWfpBrokerRejectCode {
    Protocol,
    PeerIdentity,
    Capability,
    InvalidProxy,
    InvalidScope,
    BrowserUnavailable,
    InvalidMirror,
    PolicyInstall,
    PolicyClose,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum WindowsWfpBrokerOutcome {
    Closed {
        version: u16,
    },
    ClientDisconnected {
        version: u16,
        message: String,
    },
    Rejected {
        version: u16,
        code: WindowsWfpBrokerRejectCode,
        message: String,
    },
    Failed {
        version: u16,
        message: String,
    },
}

impl WindowsWfpBrokerOutcome {
    pub fn is_clean_close(&self) -> bool {
        matches!(self, Self::Closed { .. })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WindowsWfpBrokerError {
    #[error("invalid local named-pipe name")]
    InvalidPipeName,
    #[error("broker pipe {operation} failed")]
    Pipe {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("broker protocol error: {0}")]
    Protocol(String),
    #[error("broker server identity is invalid: {0}")]
    BrokerIdentity(String),
    #[error("broker rejected the lease ({code:?}): {message}")]
    Rejected {
        code: WindowsWfpBrokerRejectCode,
        message: String,
    },
    #[error("timed out while {0}")]
    Timeout(&'static str),
    #[error("broker lease was lost: {0}")]
    LeaseLost(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsWfpLeaseLoss {
    message: String,
}

impl WindowsWfpLeaseLoss {
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for WindowsWfpLeaseLoss {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

enum LeaseState {
    Active,
    Lost(WindowsWfpLeaseLoss),
    Closed,
}

enum ClientCommand {
    Close(oneshot::Sender<Result<(), WindowsWfpBrokerError>>),
}

/// A live station-to-broker policy lease.
///
/// Construction completes only after the elevated broker has installed WFP
/// policy and replied with `Granted`. Dropping or losing the lease does not
/// authorize policy removal; only an acknowledged clean close does.
pub struct WindowsWfpLease {
    command_tx: mpsc::Sender<ClientCommand>,
    state_rx: watch::Receiver<LeaseState>,
    task: Option<JoinHandle<()>>,
    app_id_count: usize,
}

pub struct WindowsWfpAcquisition {
    lease: WindowsWfpLease,
    mirror: WindowsBrowserRuntimeMirror,
}

impl WindowsWfpAcquisition {
    pub fn into_parts(self) -> (WindowsWfpLease, WindowsBrowserRuntimeMirror) {
        (self.lease, self.mirror)
    }
}

impl WindowsWfpLease {
    pub fn app_id_count(&self) -> usize {
        self.app_id_count
    }

    pub async fn wait_for_unexpected_loss(&self) -> WindowsWfpLeaseLoss {
        let mut state = self.state_rx.clone();
        loop {
            match &*state.borrow_and_update() {
                LeaseState::Lost(loss) => return loss.clone(),
                LeaseState::Active | LeaseState::Closed => {}
            }
            if state.changed().await.is_err() {
                return WindowsWfpLeaseLoss {
                    message: "broker lease monitor stopped".to_owned(),
                };
            }
        }
    }

    pub async fn close(mut self) -> Result<(), WindowsWfpBrokerError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(ClientCommand::Close(reply_tx))
            .await
            .map_err(|_| current_lease_error(&self.state_rx))?;
        let result = reply_rx
            .await
            .map_err(|_| current_lease_error(&self.state_rx))?;
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
        result
    }
}

impl Drop for WindowsWfpLease {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// Acquires a single WFP lease from an already-started elevated broker.
pub async fn acquire_windows_wfp_lease(
    pipe_name: &str,
    browser: BrokerBrowser,
    mirror_scope: WindowsRuntimeMirrorScope,
    proxy: SocketAddrV4,
    capability: WindowsWfpBrokerCapability,
) -> Result<WindowsWfpAcquisition, WindowsWfpBrokerError> {
    let pipe_name = local_pipe_name(pipe_name)?;
    validate_proxy(proxy).map_err(WindowsWfpBrokerError::Protocol)?;
    let client_creation_filetime = process_creation_filetime(unsafe { GetCurrentProcess() })
        .map_err(WindowsWfpBrokerError::BrokerIdentity)?;
    let requested_scope = mirror_scope.as_hex();
    let mut pipe = connect_client(&pipe_name).await?;
    verify_elevated_broker_server(&pipe)
        .map_err(WindowsWfpBrokerError::BrokerIdentity)?;
    write_frame(
        &mut pipe,
        &ClientFrame::Acquire {
            version: PROTOCOL_VERSION,
            client_pid: std::process::id(),
            client_creation_filetime,
            capability: Some(capability),
            browser,
            mirror_scope: requested_scope.clone(),
            proxy,
        },
    )
    .await?;

    let response = time::timeout(ACQUIRE_TIMEOUT, read_frame::<_, BrokerFrame>(&mut pipe))
        .await
        .map_err(|_| WindowsWfpBrokerError::Timeout("waiting for lease grant"))??
        .ok_or_else(|| WindowsWfpBrokerError::LeaseLost(
            "broker disconnected before granting the lease".to_owned(),
        ))?;
    let (mirror_root, granted_scope, app_id_count) = match response {
        BrokerFrame::Granted {
            version,
            mirror_root,
            mirror_scope,
            app_id_count,
        } if version == PROTOCOL_VERSION && (1..=64).contains(&app_id_count) => {
            (mirror_root, mirror_scope, usize::from(app_id_count))
        }
        BrokerFrame::Rejected {
            version,
            code,
            message,
        } if version == PROTOCOL_VERSION => {
            return Err(WindowsWfpBrokerError::Rejected { code, message });
        }
        _ => {
            return Err(WindowsWfpBrokerError::Protocol(
                "unexpected or unsupported grant response".to_owned(),
            ));
        }
    };
    if granted_scope != requested_scope {
        let close_result = close_client_lease(&mut pipe).await;
        return Err(match close_result {
            Ok(()) => WindowsWfpBrokerError::Protocol(
                "broker returned a runtime mirror for a different scope".to_owned(),
            ),
            Err(close_error) => WindowsWfpBrokerError::LeaseLost(format!(
                "runtime mirror scope mismatch and policy close was not acknowledged ({close_error})"
            )),
        });
    }

    let mirror = match WindowsBrowserRuntimeMirror::inspect(&mirror_root) {
        Ok(mirror) => mirror,
        Err(error) => {
            let close_result = close_client_lease(&mut pipe).await;
            return Err(match close_result {
                Ok(()) => WindowsWfpBrokerError::Protocol(format!(
                    "broker returned an invalid runtime mirror: {error}"
                )),
                Err(close_error) => WindowsWfpBrokerError::LeaseLost(format!(
                    "runtime mirror validation failed ({error}) and policy close was not acknowledged ({close_error})"
                )),
            });
        }
    };
    if mirror.browser_binary().kind != browser.kind() {
        let close_result = close_client_lease(&mut pipe).await;
        return Err(match close_result {
            Ok(()) => WindowsWfpBrokerError::Protocol(
                "broker returned a runtime mirror for a different browser".to_owned(),
            ),
            Err(close_error) => WindowsWfpBrokerError::LeaseLost(format!(
                "broker returned the wrong runtime mirror and policy close was not acknowledged ({close_error})"
            )),
        });
    }

    let (command_tx, command_rx) = mpsc::channel(1);
    let (state_tx, state_rx) = watch::channel(LeaseState::Active);
    let task = tokio::spawn(run_client_lease(pipe, command_rx, state_tx));
    Ok(WindowsWfpAcquisition {
        lease: WindowsWfpLease {
            command_tx,
            state_rx,
            task: Some(task),
            app_id_count,
        },
        mirror,
    })
}

/// Accepts bounded pre-auth connections, serves one authenticated local lease,
/// and exits when that lease ends.
pub async fn run_windows_wfp_broker(
    pipe_name: &str,
    allowed_runtime_root: &Path,
    capability: WindowsWfpBrokerCapability,
) -> WindowsWfpBrokerOutcome {
    match run_windows_wfp_broker_inner(pipe_name, allowed_runtime_root, capability).await {
        Ok(outcome) => outcome,
        Err(error) => WindowsWfpBrokerOutcome::Failed {
            version: PROTOCOL_VERSION,
            message: error.to_string(),
        },
    }
}

async fn run_windows_wfp_broker_inner(
    pipe_name: &str,
    allowed_runtime_root: &Path,
    capability: WindowsWfpBrokerCapability,
) -> Result<WindowsWfpBrokerOutcome, WindowsWfpBrokerError> {
    let mut capability = OneTimeBrokerCapability::new(capability);
    let pipe_name = local_pipe_name(pipe_name)?;
    let elevated = process_token_is_elevated(unsafe { GetCurrentProcess() })
        .map_err(WindowsWfpBrokerError::BrokerIdentity)?;
    if !elevated {
        return Err(WindowsWfpBrokerError::BrokerIdentity(
            "WFP broker token is not elevated".to_owned(),
        ));
    }
    let mut pipe = create_owner_restricted_pipe(&pipe_name)?;
    let acquire_deadline = Instant::now() + ACQUIRE_TIMEOUT;
    let (
        peer,
        client_pid,
        client_creation_filetime,
        browser,
        mirror_scope,
        proxy,
    ) = loop {
        time::timeout_at(acquire_deadline, pipe.connect())
            .await
            .map_err(|_| WindowsWfpBrokerError::Timeout(
                "waiting for an authorized broker client",
            ))?
            .map_err(|source| WindowsWfpBrokerError::Pipe {
                operation: "connect",
                source,
            })?;

        let peer = match PeerProcess::from_pipe(&pipe) {
            Ok(peer) => peer,
            Err(message) => {
                reject_pre_auth_and_rearm(
                    &mut pipe,
                    WindowsWfpBrokerRejectCode::PeerIdentity,
                    message,
                    acquire_deadline,
                )
                .await?;
                continue;
            }
        };

        let frame_deadline = std::cmp::min(
            acquire_deadline,
            Instant::now() + PREAUTH_FRAME_TIMEOUT,
        );
        let request = match time::timeout_at(
            frame_deadline,
            read_frame::<_, ClientFrame>(&mut pipe),
        )
        .await
        {
            Ok(Ok(Some(frame))) => frame,
            Ok(Ok(None)) => {
                rearm_pre_auth_pipe(&pipe, acquire_deadline).await?;
                continue;
            }
            Ok(Err(error)) => {
                reject_pre_auth_and_rearm(
                    &mut pipe,
                    WindowsWfpBrokerRejectCode::Protocol,
                    error.to_string(),
                    acquire_deadline,
                )
                .await?;
                continue;
            }
            Err(_) => {
                reject_pre_auth_and_rearm(
                    &mut pipe,
                    WindowsWfpBrokerRejectCode::Protocol,
                    "timed out waiting for acquire frame".to_owned(),
                    acquire_deadline,
                )
                .await?;
                continue;
            }
        };

        let (
            client_pid,
            client_creation_filetime,
            presented_capability,
            browser,
            mirror_scope,
            proxy,
        ) = match request {
            ClientFrame::Acquire {
                version,
                client_pid,
                client_creation_filetime,
                capability,
                browser,
                mirror_scope,
                proxy,
            } if version == PROTOCOL_VERSION => (
                client_pid,
                client_creation_filetime,
                capability,
                browser,
                mirror_scope,
                proxy,
            ),
            _ => {
                reject_pre_auth_and_rearm(
                    &mut pipe,
                    WindowsWfpBrokerRejectCode::Protocol,
                    "first frame must be a version 3 acquire request".to_owned(),
                    acquire_deadline,
                )
                .await?;
                continue;
            }
        };

        if let Err(message) = peer.verify_claimed_identity(
            client_pid,
            client_creation_filetime,
        ) {
            reject_pre_auth_and_rearm(
                &mut pipe,
                WindowsWfpBrokerRejectCode::PeerIdentity,
                message,
                acquire_deadline,
            )
            .await?;
            continue;
        }
        if capability.authorize(presented_capability).is_err() {
            reject_pre_auth_and_rearm(
                &mut pipe,
                WindowsWfpBrokerRejectCode::Capability,
                "broker launch capability is missing or invalid".to_owned(),
                acquire_deadline,
            )
            .await?;
            continue;
        }
        break (
            peer,
            client_pid,
            client_creation_filetime,
            browser,
            mirror_scope,
            proxy,
        );
    };
    if let Err(message) = validate_proxy(proxy) {
        return reject(
            &mut pipe,
            WindowsWfpBrokerRejectCode::InvalidProxy,
            message,
        )
        .await;
    }
    let mirror_scope = match mirror_scope.parse::<WindowsRuntimeMirrorScope>() {
        Ok(scope) => scope,
        Err(error) => {
            return reject(
                &mut pipe,
                WindowsWfpBrokerRejectCode::InvalidScope,
                error.to_string(),
            )
            .await;
        }
    };
    let peer_identity = match peer.containment_identity() {
        Ok(identity) => identity,
        Err(error) => {
            return reject(
                &mut pipe,
                WindowsWfpBrokerRejectCode::PeerIdentity,
                containment_message(error),
            )
            .await;
        }
    };
    if let Err(error) = WindowsContainmentGuard::reconcile_stale_leases() {
        return reject(
            &mut pipe,
            WindowsWfpBrokerRejectCode::PolicyInstall,
            format!("stale WFP lease reconciliation failed: {}", containment_message(error)),
        )
        .await;
    }
    let mirror = match prepare_mirror_as_peer(
        &pipe,
        allowed_runtime_root,
        browser,
        mirror_scope,
    ) {
        Ok(mirror) => mirror,
        Err((code, message)) => return reject(&mut pipe, code, message).await,
    };
    cleanup_stale_mirrors_as_peer(&pipe, mirror.root());
    if let Err(message) = peer.verify_claimed_identity(client_pid, client_creation_filetime) {
        let message = match remove_mirror_as_peer(&pipe, mirror) {
            Ok(()) => message,
            Err(cleanup_error) => format!(
                "{message}; runtime mirror cleanup after peer identity loss failed: {cleanup_error}"
            ),
        };
        return reject(
            &mut pipe,
            WindowsWfpBrokerRejectCode::PeerIdentity,
            message,
        )
        .await;
    }
    let guard = match WindowsContainmentGuard::install_paths_for_peer(
        mirror.executable_paths(),
        proxy.into(),
        peer_identity,
    ) {
        Ok(guard) => guard,
        Err(error) => {
            let message = match remove_mirror_as_peer(&pipe, mirror) {
                Ok(()) => containment_message(error),
                Err(cleanup_error) => format!(
                    "{}; runtime mirror cleanup failed: {cleanup_error}",
                    containment_message(error)
                ),
            };
            return reject(
                &mut pipe,
                WindowsWfpBrokerRejectCode::PolicyInstall,
                message,
            )
            .await;
        }
    };
    let app_id_count = guard.app_id_count() as u16;
    let mirror_root = mirror.root().to_path_buf();
    if let Err(error) = write_frame(
        &mut pipe,
        &BrokerFrame::Granted {
            version: PROTOCOL_VERSION,
            mirror_root,
            mirror_scope: mirror_scope.as_hex(),
            app_id_count,
        },
    )
    .await
    {
        return match guard.close() {
            Ok(()) => match remove_mirror_as_peer(&pipe, mirror) {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(WindowsWfpBrokerError::Protocol(format!(
                    "lease grant failed ({error}) and runtime mirror cleanup failed ({cleanup_error})"
                ))),
            },
            Err(close_error) => {
                drop(mirror);
                Err(WindowsWfpBrokerError::LeaseLost(format!(
                    "lease grant failed ({error}) and policy close failed ({close_error}); runtime mirror was retained"
                )))
            }
        };
    }
    drop(mirror);

    hold_broker_lease(pipe, peer, guard).await
}

async fn hold_broker_lease(
    mut pipe: NamedPipeServer,
    _peer: PeerProcess,
    guard: WindowsContainmentGuard,
) -> Result<WindowsWfpBrokerOutcome, WindowsWfpBrokerError> {
    match read_frame::<_, ClientFrame>(&mut pipe).await {
        Ok(Some(ClientFrame::Close { version })) if version == PROTOCOL_VERSION => {
            let close_result = guard.close();
            if let Err(error) = close_result {
                return reject(
                    &mut pipe,
                    WindowsWfpBrokerRejectCode::PolicyClose,
                    containment_message(error),
                ).await;
            }
            write_frame(
                &mut pipe,
                &BrokerFrame::Closed { version: PROTOCOL_VERSION },
            ).await?;
            Ok(WindowsWfpBrokerOutcome::Closed {
                version: PROTOCOL_VERSION,
            })
        }
        Ok(None) => {
            drop(guard);
            Ok(WindowsWfpBrokerOutcome::ClientDisconnected {
                version: PROTOCOL_VERSION,
                message: "client disconnected while policy was active".to_owned(),
            })
        }
        Ok(Some(_)) => {
            drop(guard);
            reject(
                &mut pipe,
                WindowsWfpBrokerRejectCode::Protocol,
                "unexpected frame while lease was active".to_owned(),
            ).await
        }
        Err(error) => {
            drop(guard);
            Ok(WindowsWfpBrokerOutcome::ClientDisconnected {
                version: PROTOCOL_VERSION,
                message: error.to_string(),
            })
        }
    }
}

async fn run_client_lease(
    mut pipe: NamedPipeClient,
    mut commands: mpsc::Receiver<ClientCommand>,
    state: watch::Sender<LeaseState>,
) {
    tokio::select! {
        command = commands.recv() => {
            let Some(ClientCommand::Close(reply)) = command else {
                return;
            };
            let result = close_client_lease(&mut pipe).await;
            match &result {
                Ok(()) => {
                    state.send_replace(LeaseState::Closed);
                }
                Err(error) => {
                    state.send_replace(LeaseState::Lost(WindowsWfpLeaseLoss {
                        message: error.to_string(),
                    }));
                }
            }
            let _ = reply.send(result);
        }
        frame = read_frame::<_, BrokerFrame>(&mut pipe) => {
            let message = match frame {
                Ok(None) => "broker disconnected while policy was active".to_owned(),
                Ok(Some(frame)) => format!("broker sent an unsolicited frame: {frame:?}"),
                Err(error) => error.to_string(),
            };
            state.send_replace(LeaseState::Lost(WindowsWfpLeaseLoss { message }));
        }
    }
}

async fn close_client_lease(
    pipe: &mut NamedPipeClient,
) -> Result<(), WindowsWfpBrokerError> {
    write_frame(
        pipe,
        &ClientFrame::Close {
            version: PROTOCOL_VERSION,
        },
    )
    .await?;
    let response = time::timeout(CLOSE_TIMEOUT, read_frame::<_, BrokerFrame>(pipe))
        .await
        .map_err(|_| WindowsWfpBrokerError::Timeout("waiting for close acknowledgement"))??
        .ok_or_else(|| WindowsWfpBrokerError::LeaseLost(
            "broker disconnected before close acknowledgement".to_owned(),
        ))?;
    match response {
        BrokerFrame::Closed { version } if version == PROTOCOL_VERSION => Ok(()),
        BrokerFrame::Rejected {
            version,
            code,
            message,
        } if version == PROTOCOL_VERSION => {
            Err(WindowsWfpBrokerError::Rejected { code, message })
        }
        _ => Err(WindowsWfpBrokerError::Protocol(
            "unexpected or unsupported close response".to_owned(),
        )),
    }
}

struct OwnerRestrictedPipeSecurity {
    descriptor: Box<SECURITY_DESCRIPTOR>,
    _acl: Vec<usize>,
    _owner_sid: Vec<usize>,
}

impl OwnerRestrictedPipeSecurity {
    fn for_current_process() -> io::Result<Self> {
        let owner_sid_bytes = process_user_sid(unsafe { GetCurrentProcess() })
            .map_err(|message| pipe_security_error("read broker owner SID", message))?;
        let mut owner_sid = aligned_security_buffer(owner_sid_bytes.len());
        unsafe {
            std::ptr::copy_nonoverlapping(
                owner_sid_bytes.as_ptr(),
                owner_sid.as_mut_ptr().cast::<u8>(),
                owner_sid_bytes.len(),
            );
        }
        let owner_sid_ptr = PSID(owner_sid.as_mut_ptr().cast());

        let mut system_sid = aligned_security_buffer(SECURITY_MAX_SID_SIZE as usize);
        let mut system_sid_length = SECURITY_MAX_SID_SIZE;
        unsafe {
            CreateWellKnownSid(
                WinLocalSystemSid,
                PSID::default(),
                PSID(system_sid.as_mut_ptr().cast()),
                &mut system_sid_length,
            )
        }
        .map_err(|error| pipe_security_error("create LocalSystem SID", error))?;

        let owner_ace_bytes = access_allowed_ace_size(owner_sid_bytes.len())?;
        let system_ace_bytes = access_allowed_ace_size(system_sid_length as usize)?;
        let acl_bytes = std::mem::size_of::<ACL>()
            .checked_add(owner_ace_bytes)
            .and_then(|bytes| bytes.checked_add(system_ace_bytes))
            .ok_or_else(|| pipe_security_error("size pipe DACL", "size overflow"))?;
        let acl_length = u32::try_from(acl_bytes)
            .map_err(|_| pipe_security_error("size pipe DACL", "size exceeds u32"))?;
        let mut acl = aligned_security_buffer(acl_bytes);
        let acl_ptr = acl.as_mut_ptr().cast::<ACL>();
        unsafe { InitializeAcl(acl_ptr, acl_length, ACL_REVISION) }
            .map_err(|error| pipe_security_error("initialize pipe DACL", error))?;
        for sid in [owner_sid_ptr, PSID(system_sid.as_mut_ptr().cast())] {
            unsafe {
                AddAccessAllowedAceEx(
                    acl_ptr,
                    ACL_REVISION,
                    NO_INHERITANCE,
                    GENERIC_ALL.0,
                    sid,
                )
            }
            .map_err(|error| pipe_security_error("add pipe DACL entry", error))?;
        }

        let mut descriptor = Box::new(SECURITY_DESCRIPTOR::default());
        let descriptor_ptr = PSECURITY_DESCRIPTOR(
            (&mut *descriptor as *mut SECURITY_DESCRIPTOR).cast(),
        );
        unsafe {
            InitializeSecurityDescriptor(
                descriptor_ptr,
                SECURITY_DESCRIPTOR_REVISION,
            )
        }
        .map_err(|error| pipe_security_error("initialize pipe security descriptor", error))?;
        unsafe { SetSecurityDescriptorOwner(descriptor_ptr, owner_sid_ptr, false) }
            .map_err(|error| pipe_security_error("set pipe security owner", error))?;
        unsafe { SetSecurityDescriptorDacl(descriptor_ptr, true, Some(acl_ptr), false) }
            .map_err(|error| pipe_security_error("set pipe DACL", error))?;
        if !unsafe { IsValidSecurityDescriptor(descriptor_ptr) }.as_bool() {
            return Err(pipe_security_error(
                "validate pipe security descriptor",
                "Windows rejected the constructed descriptor",
            ));
        }

        Ok(Self {
            descriptor,
            _acl: acl,
            _owner_sid: owner_sid,
        })
    }

    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: (&*self.descriptor as *const SECURITY_DESCRIPTOR)
                .cast_mut()
                .cast(),
            bInheritHandle: false.into(),
        }
    }
}

fn create_owner_restricted_pipe(
    pipe_name: &str,
) -> Result<NamedPipeServer, WindowsWfpBrokerError> {
    let security = OwnerRestrictedPipeSecurity::for_current_process()
        .map_err(|source| WindowsWfpBrokerError::Pipe {
            operation: "secure",
            source,
        })?;
    let mut attributes = security.attributes();
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(true)
        .reject_remote_clients(true)
        .max_instances(1);
    // CreateNamedPipeW consumes SECURITY_ATTRIBUTES synchronously. `security`
    // owns the descriptor, DACL, and owner SID until this call returns.
    unsafe {
        options.create_with_security_attributes_raw(
            pipe_name,
            (&mut attributes as *mut SECURITY_ATTRIBUTES).cast(),
        )
    }
    .map_err(|source| WindowsWfpBrokerError::Pipe {
        operation: "create",
        source,
    })
}

fn aligned_security_buffer(byte_length: usize) -> Vec<usize> {
    let words = byte_length
        .saturating_add(std::mem::size_of::<usize>() - 1)
        / std::mem::size_of::<usize>();
    vec![0_usize; words]
}

fn access_allowed_ace_size(sid_length: usize) -> io::Result<usize> {
    std::mem::size_of::<ACCESS_ALLOWED_ACE>()
        .checked_sub(std::mem::size_of::<u32>())
        .and_then(|header| header.checked_add(sid_length))
        .ok_or_else(|| pipe_security_error("size pipe DACL entry", "size overflow"))
}

fn pipe_security_error(
    operation: &'static str,
    source: impl std::fmt::Display,
) -> io::Error {
    io::Error::other(format!("{operation}: {source}"))
}

async fn connect_client(pipe_name: &str) -> Result<NamedPipeClient, WindowsWfpBrokerError> {
    let deadline = Instant::now() + CONNECT_TIMEOUT;
    loop {
        match ClientOptions::new().open(pipe_name) {
            Ok(pipe) => return Ok(pipe),
            Err(source) if retryable_connect_error(&source) && Instant::now() < deadline => {
                time::sleep(Duration::from_millis(25)).await;
            }
            Err(source) => {
                return Err(WindowsWfpBrokerError::Pipe {
                    operation: "open",
                    source,
                });
            }
        }
    }
}

fn retryable_connect_error(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error().map(|code| code as u32),
        Some(code) if code == ERROR_FILE_NOT_FOUND.0 || code == ERROR_PIPE_BUSY.0
    )
}

async fn reject_pre_auth_and_rearm(
    pipe: &mut NamedPipeServer,
    code: WindowsWfpBrokerRejectCode,
    message: String,
    acquire_deadline: Instant,
) -> Result<(), WindowsWfpBrokerError> {
    let _ = time::timeout(
        PREAUTH_REJECT_TIMEOUT,
        write_frame(
            pipe,
            &BrokerFrame::Rejected {
                version: PROTOCOL_VERSION,
                code,
                message,
            },
        ),
    )
    .await;
    rearm_pre_auth_pipe(pipe, acquire_deadline).await
}

async fn rearm_pre_auth_pipe(
    pipe: &NamedPipeServer,
    acquire_deadline: Instant,
) -> Result<(), WindowsWfpBrokerError> {
    disconnect_pre_auth_pipe(pipe)?;
    let now = Instant::now();
    if now < acquire_deadline {
        time::sleep(std::cmp::min(
            PREAUTH_RETRY_DELAY,
            acquire_deadline - now,
        ))
        .await;
    }
    Ok(())
}

fn disconnect_pre_auth_pipe(
    pipe: &NamedPipeServer,
) -> Result<(), WindowsWfpBrokerError> {
    match pipe.disconnect() {
        Ok(()) => Ok(()),
        Err(source)
            if source.raw_os_error().map(|code| code as u32)
                == Some(ERROR_PIPE_NOT_CONNECTED.0) => Ok(()),
        Err(source) => Err(WindowsWfpBrokerError::Pipe {
            operation: "disconnect unauthorized client",
            source,
        }),
    }
}

async fn reject(
    pipe: &mut NamedPipeServer,
    code: WindowsWfpBrokerRejectCode,
    message: String,
) -> Result<WindowsWfpBrokerOutcome, WindowsWfpBrokerError> {
    write_frame(
        pipe,
        &BrokerFrame::Rejected {
            version: PROTOCOL_VERSION,
            code,
            message: message.clone(),
        },
    )
    .await?;
    Ok(WindowsWfpBrokerOutcome::Rejected {
        version: PROTOCOL_VERSION,
        code,
        message,
    })
}

async fn write_frame<W, T>(
    writer: &mut W,
    value: &T,
) -> Result<(), WindowsWfpBrokerError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let mut payload = serde_json::to_vec(value).map_err(|error| {
        WindowsWfpBrokerError::Protocol(format!("cannot serialize frame: {error}"))
    })?;
    if payload.is_empty() || payload.len() > MAX_FRAME_BYTES {
        zeroize_bytes(&mut payload);
        return Err(WindowsWfpBrokerError::Protocol(
            "outbound frame exceeds protocol bounds".to_owned(),
        ));
    }
    let payload_length = (payload.len() as u32).to_le_bytes();
    let result = async {
        writer
            .write_all(&payload_length)
            .await
            .map_err(|source| WindowsWfpBrokerError::Pipe {
                operation: "write frame length",
                source,
            })?;
        writer
            .write_all(&payload)
            .await
            .map_err(|source| WindowsWfpBrokerError::Pipe {
                operation: "write frame payload",
                source,
            })?;
        writer
            .flush()
            .await
            .map_err(|source| WindowsWfpBrokerError::Pipe {
                operation: "flush frame",
                source,
            })
    }
    .await;
    zeroize_bytes(&mut payload);
    result
}

async fn read_frame<R, T>(
    reader: &mut R,
) -> Result<Option<T>, WindowsWfpBrokerError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut length = [0_u8; 4];
    match reader.read_exact(&mut length).await {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(source) => {
            return Err(WindowsWfpBrokerError::Pipe {
                operation: "read frame length",
                source,
            });
        }
    }
    let length = u32::from_le_bytes(length) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(WindowsWfpBrokerError::Protocol(
            "inbound frame exceeds protocol bounds".to_owned(),
        ));
    }
    let mut payload = vec![0_u8; length];
    if let Err(source) = reader.read_exact(&mut payload).await {
        zeroize_bytes(&mut payload);
        return Err(WindowsWfpBrokerError::Pipe {
            operation: "read frame payload",
            source,
        });
    }
    let decoded = serde_json::from_slice(&payload)
        .map(Some)
        .map_err(|error| WindowsWfpBrokerError::Protocol(format!("invalid JSON frame: {error}")));
    zeroize_bytes(&mut payload);
    decoded
}

fn local_pipe_name(pipe_name: &str) -> Result<String, WindowsWfpBrokerError> {
    const PREFIX: &str = r"\\.\pipe\";
    if pipe_name.contains('\0') {
        return Err(WindowsWfpBrokerError::InvalidPipeName);
    }
    let full = if pipe_name
        .get(..PREFIX.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(PREFIX))
    {
        pipe_name.to_owned()
    } else if !pipe_name.contains(['\\', '/']) && !pipe_name.is_empty() {
        format!(r"\\.\pipe\{pipe_name}")
    } else {
        return Err(WindowsWfpBrokerError::InvalidPipeName);
    };
    let suffix = &full[PREFIX.len()..];
    if suffix.is_empty() || suffix.contains(['\\', '/']) {
        return Err(WindowsWfpBrokerError::InvalidPipeName);
    }
    Ok(full)
}

fn canonical_directory(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err("allowed runtime root must be absolute".to_owned());
    }
    let canonical = std::fs::canonicalize(path)
        .map_err(|error| format!("cannot canonicalize allowed runtime root: {error}"))?;
    let metadata = std::fs::metadata(&canonical)
        .map_err(|error| format!("cannot inspect allowed runtime root: {error}"))?;
    if !metadata.is_dir() {
        return Err("allowed runtime root is not a directory".to_owned());
    }
    Ok(canonical)
}

fn validate_allowed_mirror(
    allowed_runtime_root: &Path,
    mirror: &WindowsBrowserRuntimeMirror,
    browser: BrokerBrowser,
) -> Result<(), String> {
    let requested_root = mirror.root();
    if !requested_root.is_absolute() {
        return Err("runtime mirror root must be absolute".to_owned());
    }
    let canonical = std::fs::canonicalize(requested_root)
        .map_err(|error| format!("cannot canonicalize runtime mirror root: {error}"))?;
    if canonical.parent() != Some(allowed_runtime_root) {
        return Err(
            "runtime mirror root is not an exact direct child of the allowed runtime root"
                .to_owned(),
        );
    }
    let inspected = WindowsBrowserRuntimeMirror::inspect(&canonical)
        .map_err(|error| format!("runtime mirror validation failed: {error}"))?;
    if inspected.browser_binary().kind != browser.kind() {
        return Err("runtime mirror browser kind does not match the acquire request".to_owned());
    }
    if inspected.executable_paths().is_empty() || inspected.executable_paths().len() > 64 {
        return Err("runtime mirror executable set is outside protocol bounds".to_owned());
    }
    Ok(())
}

struct PipeClientImpersonation {
    active: bool,
}

impl PipeClientImpersonation {
    fn begin(pipe: &NamedPipeServer) -> Result<Self, String> {
        unsafe { ImpersonateNamedPipeClient(HANDLE(pipe.as_raw_handle())) }
            .map_err(|error| format!("cannot impersonate named-pipe client: {error}"))?;
        Ok(Self { active: true })
    }

    fn revert_or_abort(mut self) {
        if unsafe { RevertToSelf() }.is_err() {
            // The thread token is now unknown. Returning this Tokio worker to
            // the runtime could execute later privileged work as the client.
            std::process::abort();
        }
        self.active = false;
    }
}

impl Drop for PipeClientImpersonation {
    fn drop(&mut self) {
        if self.active && unsafe { RevertToSelf() }.is_err() {
            std::process::abort();
        }
    }
}

fn with_impersonated_client<T>(
    pipe: &NamedPipeServer,
    operation: impl FnOnce() -> T,
) -> Result<T, String> {
    let impersonation = PipeClientImpersonation::begin(pipe)?;
    let result = operation();
    // This synchronous helper cannot cross an await or change Tokio threads.
    impersonation.revert_or_abort();
    Ok(result)
}

fn prepare_mirror_as_peer(
    pipe: &NamedPipeServer,
    allowed_runtime_root: &Path,
    browser: BrokerBrowser,
    mirror_scope: WindowsRuntimeMirrorScope,
) -> Result<WindowsBrowserRuntimeMirror, (WindowsWfpBrokerRejectCode, String)> {
    with_impersonated_client(pipe, || {
        let allowed_runtime_root = canonical_directory(allowed_runtime_root)
            .map_err(|message| (WindowsWfpBrokerRejectCode::InvalidMirror, message))?;
        let source = resolve_standard_browser(browser).map_err(|message| {
            (WindowsWfpBrokerRejectCode::BrowserUnavailable, message)
        })?;
        let mirror = WindowsBrowserRuntimeMirror::materialize_scoped(&source, mirror_scope)
            .map_err(|error| {
                (
                    WindowsWfpBrokerRejectCode::InvalidMirror,
                    format!("runtime mirror materialization failed: {error}"),
                )
            })?;
        if let Err(message) = validate_allowed_mirror(&allowed_runtime_root, &mirror, browser) {
            let message = match mirror.remove() {
                Ok(()) => message,
                Err(error) => format!(
                    "{message}; invalid runtime mirror cleanup also failed: {error}"
                ),
            };
            return Err((WindowsWfpBrokerRejectCode::InvalidMirror, message));
        }
        Ok(mirror)
    })
    .map_err(|message| (WindowsWfpBrokerRejectCode::PeerIdentity, message))?
}

fn remove_mirror_as_peer(
    pipe: &NamedPipeServer,
    mirror: WindowsBrowserRuntimeMirror,
) -> Result<(), String> {
    let removal = match with_impersonated_client(pipe, || {
        mirror
            .remove()
            .map_err(|error| format!("runtime mirror removal failed: {error}"))
    }) {
        Ok(removal) => removal,
        Err(message) => {
            return Err(format!(
                "{message}; runtime mirror was retained to avoid elevated deletion"
            ));
        }
    };
    removal
}

fn cleanup_stale_mirrors_as_peer(
    pipe: &NamedPipeServer,
    active_mirror_root: &Path,
) {
    let mirrors = match with_impersonated_client(pipe, || {
        WindowsBrowserRuntimeMirror::inventory()
            .map_err(|error| format!("runtime mirror inventory failed: {error}"))
    }) {
        Ok(Ok(mirrors)) => mirrors,
        Ok(Err(_)) | Err(_) => return,
    };
    for mirror in mirrors {
        if mirror.root() == active_mirror_root {
            continue;
        }
        let cleanup_guard = match WindowsContainmentGuard::guard_stale_mirror_cleanup(
            mirror.executable_paths(),
        ) {
            Ok(Some(guard)) => guard,
            Ok(None) | Err(WindowsContainmentError::UnverifiableMirrorProcesses) => continue,
            Err(_) => continue,
        };
        // Cleanup is best-effort: every uncertainty retains the old mirror and
        // must not weaken or prevent the newly authenticated lease.
        let _ = remove_mirror_as_peer(pipe, mirror);
        drop(cleanup_guard);
    }
}

fn resolve_standard_browser(browser: BrokerBrowser) -> Result<BrowserBinary, String> {
    let expected_name = browser.executable_name();
    let mut attempted = Vec::new();
    for candidate in standard_browser_candidates(browser)? {
        attempted.push(candidate.clone());
        if !candidate.is_file() {
            continue;
        }
        let canonical = std::fs::canonicalize(&candidate).map_err(|error| {
            format!(
                "cannot canonicalize standard browser candidate '{}': {error}",
                candidate.display()
            )
        })?;
        let basename_matches = canonical
            .file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value.eq_ignore_ascii_case(expected_name));
        let application_layout = canonical
            .parent()
            .and_then(Path::file_name)
            .and_then(|value| value.to_str())
            .is_some_and(|value| value.eq_ignore_ascii_case("Application"));
        if !basename_matches || !application_layout {
            return Err(format!(
                "standard browser candidate resolved outside the expected Application layout: '{}'",
                canonical.display()
            ));
        }
        return Ok(BrowserBinary {
            path: canonical,
            kind: browser.kind(),
        });
    }
    let attempted = attempted
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    Err(format!(
        "no standard {} installation was found; tried: {attempted}",
        match browser {
            BrokerBrowser::Chrome => "Chrome",
            BrokerBrowser::Edge => "Edge",
        }
    ))
}

fn standard_browser_candidates(browser: BrokerBrowser) -> Result<Vec<PathBuf>, String> {
    let (program_files_relative, local_relative) = match browser {
        BrokerBrowser::Chrome => (
            r"Google\Chrome\Application\chrome.exe",
            r"Google\Chrome\Application\chrome.exe",
        ),
        BrokerBrowser::Edge => (
            r"Microsoft\Edge\Application\msedge.exe",
            r"Microsoft\Edge\Application\msedge.exe",
        ),
    };
    let mut candidates = Vec::new();
    for (folder_id, name) in [
        (&FOLDERID_ProgramFiles, "ProgramFiles"),
        (&FOLDERID_ProgramFilesX86, "ProgramFilesX86"),
    ] {
        let candidate = known_folder_path(folder_id, name)?.join(program_files_relative);
        if !candidates.contains(&candidate) {
            candidates.push(candidate);
        }
    }
    let candidate = known_folder_path(&FOLDERID_LocalAppData, "LocalAppData")?
        .join(local_relative);
    if !candidates.contains(&candidate) {
        candidates.push(candidate);
    }
    Ok(candidates)
}

fn known_folder_path(folder_id: &GUID, name: &'static str) -> Result<PathBuf, String> {
    let value = unsafe { SHGetKnownFolderPath(folder_id, KF_FLAG_DEFAULT, None) }
        .map_err(|error| format!("cannot resolve Windows known folder {name}: {error}"))?;
    if value.0.is_null() {
        return Err(format!(
            "Windows known folder {name} returned a null path"
        ));
    }
    let value = CoTaskMemWideString(value);
    let wide = unsafe { value.0.as_wide() };
    Ok(PathBuf::from(OsString::from_wide(wide)))
}

fn validate_proxy(proxy: SocketAddrV4) -> Result<(), String> {
    if proxy.port() == 0 || !proxy.ip().is_loopback() {
        return Err("proxy must be an exact IPv4 loopback endpoint with a nonzero port".to_owned());
    }
    if *proxy.ip() == Ipv4Addr::UNSPECIFIED {
        return Err("proxy address cannot be unspecified".to_owned());
    }
    Ok(())
}

fn verify_elevated_broker_server(pipe: &NamedPipeClient) -> Result<(), String> {
    let pipe_handle = HANDLE(pipe.as_raw_handle());
    let mut pid = 0_u32;
    unsafe { GetNamedPipeServerProcessId(pipe_handle, &mut pid) }
        .map_err(|error| format!("cannot identify named-pipe server: {error}"))?;
    if pid == 0 {
        return Err("named-pipe server returned an invalid process ID".to_owned());
    }
    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            false,
            pid,
        )
    }
    .map(OwnedHandle)
    .map_err(|error| format!("cannot open named-pipe server process: {error}"))?;
    if unsafe { GetProcessId(handle.0) } != pid {
        return Err("named-pipe server process identity changed".to_owned());
    }
    if unsafe { WaitForSingleObject(handle.0, 0) } != WAIT_TIMEOUT {
        return Err("named-pipe server process is not live".to_owned());
    }
    let server_sid = process_user_sid(handle.0)?;
    let client_sid = process_user_sid(unsafe { GetCurrentProcess() })?;
    if server_sid != client_sid {
        return Err("named-pipe server belongs to a different Windows user".to_owned());
    }
    if !process_token_is_elevated(handle.0)? {
        return Err("named-pipe server token is not elevated".to_owned());
    }
    Ok(())
}

fn containment_message(error: WindowsContainmentError) -> String {
    error.to_string()
}

fn current_lease_error(state: &watch::Receiver<LeaseState>) -> WindowsWfpBrokerError {
    match &*state.borrow() {
        LeaseState::Lost(loss) => WindowsWfpBrokerError::LeaseLost(loss.message.clone()),
        LeaseState::Active => WindowsWfpBrokerError::LeaseLost(
            "broker lease driver stopped unexpectedly".to_owned(),
        ),
        LeaseState::Closed => WindowsWfpBrokerError::LeaseLost(
            "broker lease is already closed".to_owned(),
        ),
    }
}

struct OwnedHandle(HANDLE);

struct CoTaskMemWideString(PWSTR);

impl Drop for CoTaskMemWideString {
    fn drop(&mut self) {
        unsafe { CoTaskMemFree(Some(self.0.as_ptr().cast())) };
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.0) };
    }
}

struct PeerProcess {
    pid: u32,
    creation_filetime: u64,
    handle: OwnedHandle,
}

impl PeerProcess {
    fn from_pipe(pipe: &NamedPipeServer) -> Result<Self, String> {
        let pipe_handle = HANDLE(pipe.as_raw_handle());
        let mut pid = 0_u32;
        unsafe { GetNamedPipeClientProcessId(pipe_handle, &mut pid) }
            .map_err(|error| format!("cannot identify named-pipe client: {error}"))?;
        if pid == 0 {
            return Err("named-pipe client returned an invalid process ID".to_owned());
        }
        let handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                false,
                pid,
            )
        }
        .map(OwnedHandle)
        .map_err(|error| format!("cannot open named-pipe client process: {error}"))?;
        let opened_pid = unsafe { GetProcessId(handle.0) };
        if opened_pid != pid {
            return Err("named-pipe client process identity changed".to_owned());
        }
        if unsafe { WaitForSingleObject(handle.0, 0) } != WAIT_TIMEOUT {
            return Err("named-pipe client process is not live".to_owned());
        }
        let creation_filetime = process_creation_filetime(handle.0)?;
        let peer_sid = process_user_sid(handle.0)?;
        let broker_sid = process_user_sid(unsafe { GetCurrentProcess() })?;
        if peer_sid != broker_sid {
            return Err("named-pipe client belongs to a different Windows user".to_owned());
        }
        Ok(Self {
            pid,
            creation_filetime,
            handle,
        })
    }

    fn verify_claimed_identity(
        &self,
        claimed_pid: u32,
        claimed_creation_filetime: u64,
    ) -> Result<(), String> {
        if claimed_pid != self.pid {
            return Err("acquire request process ID does not match pipe peer".to_owned());
        }
        if claimed_creation_filetime == 0
            || claimed_creation_filetime != self.creation_filetime
        {
            return Err(
                "acquire request process incarnation does not match pipe peer".to_owned()
            );
        }
        self.is_alive().and_then(|alive| {
            if alive {
                Ok(())
            } else {
                Err("named-pipe client exited before policy installation".to_owned())
            }
        })
    }

    fn containment_identity(
        &self,
    ) -> Result<crate::windows_containment::WindowsContainmentPeerIdentity, WindowsContainmentError>
    {
        crate::windows_containment::WindowsContainmentPeerIdentity::capture_from_handle(
            self.pid,
            self.handle.0,
        )
    }

    fn is_alive(&self) -> Result<bool, String> {
        let wait = unsafe { WaitForSingleObject(self.handle.0, 0) };
        if wait == WAIT_TIMEOUT {
            Ok(true)
        } else if wait == WAIT_OBJECT_0 {
            Ok(false)
        } else if wait == WAIT_FAILED {
            Err(format!(
                "cannot query named-pipe client liveness: {}",
                windows::core::Error::from_win32()
            ))
        } else {
            Err(format!("unexpected client process wait result: {}", wait.0))
        }
    }
}

fn process_creation_filetime(process: HANDLE) -> Result<u64, String> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    unsafe {
        GetProcessTimes(
            process,
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    }
    .map_err(|error| format!("cannot read process creation time: {error}"))?;
    let creation_filetime =
        ((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64;
    if creation_filetime == 0 {
        return Err("Windows returned an invalid process creation time".to_owned());
    }
    Ok(creation_filetime)
}

fn zeroize_bytes(bytes: &mut [u8]) {
    for byte in bytes {
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

fn process_user_sid(process: HANDLE) -> Result<Vec<u8>, String> {
    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }
        .map_err(|error| format!("cannot open process token: {error}"))?;
    let token = OwnedHandle(token);
    let mut required = 0_u32;
    let _ = unsafe {
        GetTokenInformation(token.0, TokenUser, None, 0, &mut required)
    };
    if required < std::mem::size_of::<TOKEN_USER>() as u32 {
        return Err("Windows returned an invalid token-user size".to_owned());
    }
    let words = (required as usize)
        .saturating_add(std::mem::size_of::<usize>() - 1)
        / std::mem::size_of::<usize>();
    let mut buffer = vec![0_usize; words];
    unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            required,
            &mut required,
        )
    }
    .map_err(|error| format!("cannot read process token user: {error}"))?;
    let token_user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
    let sid_length = unsafe { GetLengthSid(token_user.User.Sid) } as usize;
    if sid_length == 0 || token_user.User.Sid.0.is_null() {
        return Err("Windows returned an invalid token-user SID".to_owned());
    }
    let sid = unsafe {
        std::slice::from_raw_parts(token_user.User.Sid.0.cast::<u8>(), sid_length)
    };
    Ok(sid.to_vec())
}

fn process_token_is_elevated(process: HANDLE) -> Result<bool, String> {
    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }
        .map_err(|error| format!("cannot open process token: {error}"))?;
    let token = OwnedHandle(token);
    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0_u32;
    unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            Some((&mut elevation as *mut TOKEN_ELEVATION).cast()),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    }
    .map_err(|error| format!("cannot read process-token elevation: {error}"))?;
    if returned != std::mem::size_of::<TOKEN_ELEVATION>() as u32 {
        return Err("Windows returned an invalid token-elevation size".to_owned());
    }
    Ok(elevation.TokenIsElevated != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncWriteExt};

    struct EnvironmentRestore(Vec<(&'static str, Option<OsString>)>);

    impl EnvironmentRestore {
        fn mutate(values: &[(&'static str, &str)]) -> Self {
            let previous = values
                .iter()
                .map(|(name, _)| (*name, std::env::var_os(name)))
                .collect();
            for (name, value) in values {
                std::env::set_var(name, value);
            }
            Self(previous)
        }
    }

    impl Drop for EnvironmentRestore {
        fn drop(&mut self) {
            for (name, value) in self.0.drain(..) {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
    }

    #[test]
    fn pipe_name_accepts_only_local_single_component_names() {
        assert_eq!(
            local_pipe_name("dig2browser-test").expect("simple local pipe"),
            r"\\.\pipe\dig2browser-test"
        );
        assert!(local_pipe_name(r"\\server\pipe\bad").is_err());
        assert!(local_pipe_name(r"\\.\pipe\nested\bad").is_err());
        assert!(local_pipe_name("").is_err());
    }

    #[test]
    fn pipe_security_dacl_allows_only_owner_and_local_system() {
        use windows::Win32::Security::{GetAce, IsValidAcl};

        let security = OwnerRestrictedPipeSecurity::for_current_process()
            .expect("build owner-restricted pipe security");
        let owner_sid = PSID(security._owner_sid.as_ptr().cast_mut().cast());
        assert_eq!(security.descriptor.Owner, owner_sid);
        assert_eq!(security.descriptor.Dacl, security._acl.as_ptr().cast_mut().cast());
        assert!(unsafe { IsValidAcl(security.descriptor.Dacl) }.as_bool());
        let acl = unsafe { &*security.descriptor.Dacl };
        assert_eq!(acl.AceCount, 2);

        let expected_owner = process_user_sid(unsafe { GetCurrentProcess() })
            .expect("read current process owner SID");
        let mut expected_system = aligned_security_buffer(SECURITY_MAX_SID_SIZE as usize);
        let mut expected_system_length = SECURITY_MAX_SID_SIZE;
        unsafe {
            CreateWellKnownSid(
                WinLocalSystemSid,
                PSID::default(),
                PSID(expected_system.as_mut_ptr().cast()),
                &mut expected_system_length,
            )
        }
        .expect("create expected LocalSystem SID");
        let expected_system = unsafe {
            std::slice::from_raw_parts(
                expected_system.as_ptr().cast::<u8>(),
                expected_system_length as usize,
            )
        };

        for (index, expected_sid) in [expected_owner.as_slice(), expected_system]
            .into_iter()
            .enumerate()
        {
            let mut ace = std::ptr::null_mut();
            unsafe { GetAce(security.descriptor.Dacl, index as u32, &mut ace) }
                .expect("read pipe DACL entry");
            let ace = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
            assert_eq!(ace.Header.AceType, 0, "entry must be access-allowed");
            assert_eq!(ace.Header.AceFlags, NO_INHERITANCE.0 as u8);
            assert_eq!(ace.Mask, GENERIC_ALL.0);
            let sid = PSID((&ace.SidStart as *const u32).cast_mut().cast());
            let sid_length = unsafe { GetLengthSid(sid) } as usize;
            assert_eq!(sid_length, expected_sid.len());
            let sid = unsafe {
                std::slice::from_raw_parts(sid.0.cast::<u8>(), sid_length)
            };
            assert_eq!(sid, expected_sid);
        }
    }

    #[tokio::test]
    async fn owner_restricted_pipe_accepts_owner_client() {
        let name = format!("dig2browser-owner-acl-{}", uuid::Uuid::new_v4());
        let full_name = local_pipe_name(&name).expect("valid test pipe name");
        let server = create_owner_restricted_pipe(&full_name)
            .expect("create owner-restricted pipe");
        let server_task = tokio::spawn(async move {
            server.connect().await.expect("accept owner client");
        });
        let client = ClientOptions::new()
            .open(&full_name)
            .expect("owner opens restricted pipe");
        server_task.await.expect("join restricted pipe server");
        drop(client);
    }

    #[test]
    fn proxy_validation_is_ipv4_loopback_only() {
        assert!(validate_proxy("127.0.0.1:18080".parse().expect("proxy")).is_ok());
        assert!(validate_proxy("127.0.0.1:0".parse().expect("proxy")).is_err());
        assert!(validate_proxy("192.0.2.1:18080".parse().expect("proxy")).is_err());
    }

    #[test]
    fn missing_capability_is_rejected_without_consuming_launch_authorization() {
        let mut authorization = OneTimeBrokerCapability::new(
            WindowsWfpBrokerCapability([0x11; CAPABILITY_BYTES]),
        );
        assert_eq!(
            authorization.authorize(None),
            Err(CapabilityAuthorizationError::Missing)
        );
        assert_eq!(
            authorization.authorize(Some(WindowsWfpBrokerCapability(
                [0x11; CAPABILITY_BYTES],
            ))),
            Ok(())
        );
    }

    #[test]
    fn wrong_capability_is_rejected_without_consuming_launch_authorization() {
        let mut authorization = OneTimeBrokerCapability::new(
            WindowsWfpBrokerCapability([0x22; CAPABILITY_BYTES]),
        );
        assert_eq!(
            authorization.authorize(Some(WindowsWfpBrokerCapability(
                [0x33; CAPABILITY_BYTES],
            ))),
            Err(CapabilityAuthorizationError::Invalid)
        );
        assert_eq!(
            authorization.authorize(Some(WindowsWfpBrokerCapability(
                [0x22; CAPABILITY_BYTES],
            ))),
            Ok(())
        );
    }

    #[test]
    fn accepted_capability_cannot_be_replayed() {
        let mut authorization = OneTimeBrokerCapability::new(
            WindowsWfpBrokerCapability([0x44; CAPABILITY_BYTES]),
        );
        assert_eq!(
            authorization.authorize(Some(WindowsWfpBrokerCapability(
                [0x44; CAPABILITY_BYTES],
            ))),
            Ok(())
        );
        assert_eq!(
            authorization.authorize(Some(WindowsWfpBrokerCapability(
                [0x44; CAPABILITY_BYTES],
            ))),
            Err(CapabilityAuthorizationError::Consumed)
        );
    }

    #[tokio::test]
    async fn capability_async_transport_round_trips_exact_raw_width() {
        let (broker_capability, expected) = WindowsWfpBrokerCapability::generate_pair();
        let (mut writer, mut reader) = duplex(CAPABILITY_BYTES);
        broker_capability
            .write_to_async(&mut writer)
            .await
            .expect("write capability to child stdin pipe");
        let mut encoded = [0_u8; CAPABILITY_BYTES];
        reader
            .read_exact(&mut encoded)
            .await
            .expect("read raw capability bytes");
        let actual = WindowsWfpBrokerCapability(encoded);
        zeroize_bytes(&mut encoded);
        assert!(expected.constant_time_matches(&actual));
    }

    #[tokio::test]
    async fn bounded_v3_frame_round_trips() {
        let (mut writer, mut reader) = duplex(4096);
        let expected = ClientFrame::Close {
            version: PROTOCOL_VERSION,
        };
        write_frame(&mut writer, &expected)
            .await
            .expect("write bounded frame");
        let decoded = read_frame::<_, ClientFrame>(&mut reader)
            .await
            .expect("read bounded frame")
            .expect("frame present");
        assert!(matches!(
            decoded,
            ClientFrame::Close { version: PROTOCOL_VERSION }
        ));
    }

    #[tokio::test]
    async fn oversized_frame_is_rejected_before_allocation() {
        let (mut writer, mut reader) = duplex(16);
        writer
            .write_all(&((MAX_FRAME_BYTES as u32) + 1).to_le_bytes())
            .await
            .expect("write oversize prefix");
        let error = read_frame::<_, ClientFrame>(&mut reader)
            .await
            .expect_err("oversize frame must fail");
        assert!(matches!(error, WindowsWfpBrokerError::Protocol(_)));
    }

    #[tokio::test]
    async fn non_elevated_pipe_server_is_rejected_before_acquire() {
        if process_token_is_elevated(unsafe { GetCurrentProcess() })
            .expect("query current token elevation")
        {
            return;
        }
        let name = format!("dig2browser-unprivileged-broker-{}", uuid::Uuid::new_v4());
        let full_name = local_pipe_name(&name).expect("valid test pipe name");
        let mut server = ServerOptions::new()
            .first_pipe_instance(true)
            .reject_remote_clients(true)
            .max_instances(1)
            .create(&full_name)
            .expect("create unprivileged test pipe");
        let server_task = tokio::spawn(async move {
            server.connect().await.expect("connect unprivileged test pipe");
            let frame = time::timeout(
                Duration::from_secs(2),
                read_frame::<_, ClientFrame>(&mut server),
            )
            .await
            .expect("client disconnect timeout")
            .expect("read unprivileged pipe");
            assert!(frame.is_none(), "client sent Acquire to an unprivileged server");
        });

        let (broker_capability, client_capability) =
            WindowsWfpBrokerCapability::generate_pair();
        drop(broker_capability);
        let error = match acquire_windows_wfp_lease(
            &name,
            BrokerBrowser::Chrome,
            WindowsRuntimeMirrorScope::for_profiles_root(Path::new(
                r"C:\unused-dig2browser-profiles",
            )),
            "127.0.0.1:18080".parse().expect("proxy"),
            client_capability,
        )
        .await {
            Ok(_) => panic!("unprivileged pipe server received a lease request"),
            Err(error) => error,
        };
        assert!(matches!(error, WindowsWfpBrokerError::BrokerIdentity(_)));
        server_task.await.expect("join unprivileged server task");
    }

    #[test]
    fn acquire_v3_wire_contains_capability_but_no_source_or_destination_path() {
        let frame = ClientFrame::Acquire {
            version: PROTOCOL_VERSION,
            client_pid: 42,
            client_creation_filetime: 123_456,
            capability: Some(WindowsWfpBrokerCapability([0x55; CAPABILITY_BYTES])),
            browser: BrokerBrowser::Edge,
            mirror_scope: WindowsRuntimeMirrorScope::for_profiles_root(Path::new(
                r"C:\Profiles",
            ))
            .as_hex(),
            proxy: "127.0.0.1:18080".parse().expect("proxy"),
        };
        let encoded = serde_json::to_value(frame).expect("serialize acquire v3 frame");
        let object = encoded.as_object().expect("acquire frame object");
        assert_eq!(object.get("version"), Some(&serde_json::json!(3)));
        assert_eq!(object.get("browser"), Some(&serde_json::json!("edge")));
        assert_eq!(
            object.get("client_creation_filetime"),
            Some(&serde_json::json!(123_456))
        );
        assert!(object.contains_key("capability"));
        assert!(object.contains_key("mirror_scope"));
        assert!(!object.contains_key("source"));
        assert!(!object.contains_key("source_path"));
        assert!(!object.contains_key("mirror_root"));
        assert!(!object.contains_key("destination"));
    }

    #[test]
    fn acquire_v3_wire_missing_capability_reaches_fail_closed_authorizer() {
        let encoded = serde_json::json!({
            "type": "acquire",
            "version": 3,
            "client_pid": 42,
            "client_creation_filetime": 123_456,
            "browser": "edge",
            "mirror_scope": "a".repeat(64),
            "proxy": "127.0.0.1:18080"
        });
        let decoded: ClientFrame =
            serde_json::from_value(encoded).expect("decode missing capability for rejection");
        let ClientFrame::Acquire { capability, .. } = decoded else {
            panic!("decoded frame is not Acquire");
        };
        let mut authorization = OneTimeBrokerCapability::new(
            WindowsWfpBrokerCapability([0x66; CAPABILITY_BYTES]),
        );
        assert_eq!(
            authorization.authorize(capability),
            Err(CapabilityAuthorizationError::Missing)
        );
    }

    #[test]
    fn acquire_v3_scope_is_strict_lowercase_hex() {
        let valid = WindowsRuntimeMirrorScope::for_profiles_root(Path::new(r"C:\Profiles"))
            .as_hex();
        assert!(valid.parse::<WindowsRuntimeMirrorScope>().is_ok());
        for invalid in [
            String::new(),
            "a".repeat(63),
            "a".repeat(65),
            "A".repeat(64),
            format!("{}g", "a".repeat(63)),
        ] {
            assert!(invalid.parse::<WindowsRuntimeMirrorScope>().is_err());
        }
    }

    #[test]
    fn granted_v3_commits_to_the_requested_mirror_scope() {
        let scope = WindowsRuntimeMirrorScope::for_profiles_root(Path::new(r"C:\Profiles"))
            .as_hex();
        let frame = BrokerFrame::Granted {
            version: PROTOCOL_VERSION,
            mirror_root: PathBuf::from(r"C:\runtime-mirrors\fixture"),
            mirror_scope: scope.clone(),
            app_id_count: 3,
        };
        let encoded = serde_json::to_value(frame).expect("serialize granted v3 frame");
        assert_eq!(encoded.get("mirror_scope"), Some(&serde_json::json!(scope)));
    }

    #[test]
    fn broker_browser_candidates_ignore_environment_overrides() {
        let untrusted_root = PathBuf::from(r"C:\dig2browser-env-override-never-trusted");
        let chrome_override = untrusted_root.join("chrome.exe");
        let edge_override = untrusted_root.join("msedge.exe");
        let program_files_override = untrusted_root.join("Program Files");
        let program_files_x86_override = untrusted_root.join("Program Files (x86)");
        let local_app_data_override = untrusted_root.join("LocalAppData");
        let _restore = EnvironmentRestore::mutate(&[
            ("CHROME_PATH", chrome_override.to_str().expect("Chrome override path")),
            ("EDGE_PATH", edge_override.to_str().expect("Edge override path")),
            (
                "ProgramFiles",
                program_files_override.to_str().expect("ProgramFiles override path"),
            ),
            (
                "ProgramFiles(x86)",
                program_files_x86_override
                    .to_str()
                    .expect("ProgramFilesX86 override path"),
            ),
            (
                "LOCALAPPDATA",
                local_app_data_override
                    .to_str()
                    .expect("LocalAppData override path"),
            ),
        ]);
        let chrome_candidates = standard_browser_candidates(BrokerBrowser::Chrome)
            .expect("resolve Chrome candidates after environment mutation");
        let edge_candidates = standard_browser_candidates(BrokerBrowser::Edge)
            .expect("resolve Edge candidates after environment mutation");
        assert!(!chrome_candidates.contains(&chrome_override));
        assert!(!edge_candidates.contains(&edge_override));
        assert!(chrome_candidates
            .iter()
            .chain(&edge_candidates)
            .all(|candidate| !candidate.starts_with(&untrusted_root)));

        for (browser, expected_name) in [
            (BrokerBrowser::Chrome, "chrome.exe"),
            (BrokerBrowser::Edge, "msedge.exe"),
        ] {
            let candidates = match browser {
                BrokerBrowser::Chrome => &chrome_candidates,
                BrokerBrowser::Edge => &edge_candidates,
            };
            assert!(!candidates.is_empty());
            assert!(candidates.iter().all(|path| {
                path.file_name()
                    .and_then(|value| value.to_str())
                    .is_some_and(|value| value.eq_ignore_ascii_case(expected_name))
                    && path
                        .parent()
                        .and_then(Path::file_name)
                        .and_then(|value| value.to_str())
                        .is_some_and(|value| value.eq_ignore_ascii_case("Application"))
            }));
        }
    }
}
