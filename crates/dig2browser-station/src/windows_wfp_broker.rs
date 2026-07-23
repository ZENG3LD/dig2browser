use std::ffi::OsString;
use std::io;
use std::io::Write as _;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::sync::atomic::{compiler_fence, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dig2browser::detect::{BrowserBinary, BrowserKind};
use dig2browser::{
    WindowsBrowserRuntimeMirror, WindowsRuntimeMirrorScope,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, WriteHalf};
use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::{self, Instant};
use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY,
    ERROR_PIPE_NOT_CONNECTED, FILETIME, GENERIC_ALL, HANDLE, STILL_ACTIVE,
    WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::Security::{
    AddAccessAllowedAceEx, CreateWellKnownSid, GetLengthSid,
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation,
    InitializeAcl, InitializeSecurityDescriptor, IsValidSecurityDescriptor,
    RevertToSelf, SetSecurityDescriptorDacl, SetSecurityDescriptorOwner,
    TokenElevation, TokenIntegrityLevel, TokenUser, ACL,
    ACL_REVISION, ACCESS_ALLOWED_ACE, NO_INHERITANCE, PSECURITY_DESCRIPTOR,
    PSID, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, SECURITY_MAX_SID_SIZE,
    TOKEN_ELEVATION, TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_USER,
    WinLocalSystemSid,
};
use windows::Win32::Storage::FileSystem::SECURITY_IMPERSONATION;
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::System::Pipes::{
    GetNamedPipeClientProcessId, GetNamedPipeServerProcessId,
    ImpersonateNamedPipeClient,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetExitCodeProcess, GetProcessId, GetProcessTimes,
    OpenProcess, OpenProcessToken, TerminateProcess, WaitForSingleObject,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    PROCESS_TERMINATE,
};
use windows::Win32::UI::Shell::{
    FOLDERID_LocalAppData, FOLDERID_ProgramFiles, FOLDERID_ProgramFilesX86,
    KF_FLAG_DEFAULT, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
    SHGetKnownFolderPath, ShellExecuteExW,
};

use crate::windows_containment::{WindowsContainmentError, WindowsContainmentGuard};

const PROTOCOL_VERSION: u16 = 3;
const CAPABILITY_BYTES: usize = 32;
const MAX_FRAME_BYTES: usize = 64 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(60);
const LEASE_GRANT_TIMEOUT: Duration = Duration::from_secs(180);
const PREAUTH_FRAME_TIMEOUT: Duration = Duration::from_secs(2);
const PREAUTH_REJECT_TIMEOUT: Duration = Duration::from_millis(250);
const PREAUTH_RETRY_DELAY: Duration = Duration::from_millis(25);
const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_BOOTSTRAP_FAILURE_CLASS_BYTES: usize = 64;
const MAX_BOOTSTRAP_FAILURE_MESSAGE_BYTES: usize = 1024;
const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
const SECURITY_MANDATORY_MEDIUM_RID: u32 = 0x0000_2000;
const SECURITY_MANDATORY_HIGH_RID: u32 = 0x0000_3000;
pub const WFP_BROKER_CRASH_EXIT_CODE: u32 = 86;

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
/// pass the broker copy to [`launch_elevated_windows_wfp_broker`] for transfer
/// over the authenticated bootstrap pipe, and move the client copy into
/// [`acquire_windows_wfp_lease`]. The value is deliberately not `Clone` and
/// its debug representation never contains secret bytes.
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum BootstrapLauncherFrame {
    Start {
        version: u16,
        capability: WindowsWfpBrokerCapability,
    },
    Crash {
        version: u16,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum BootstrapBrokerFrame {
    Diagnostic {
        version: u16,
        record: BootstrapEventRecord,
    },
    CrashAcknowledged {
        version: u16,
    },
    Outcome {
        version: u16,
        outcome: WindowsWfpBrokerOutcome,
    },
    Failed {
        version: u16,
        class: String,
        message: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct BootstrapEventRecord {
    schema_version: u16,
    at_unix_ms: u64,
    process_id: u32,
    event: String,
    detail: serde_json::Value,
}

struct BootstrapEventLogger {
    log: Option<std::fs::File>,
}

struct PendingElevatedWindowsWfpBroker {
    process: Option<OwnedHandle>,
    process_id: u32,
    event_logger: Option<BootstrapEventLogger>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowsProcessSecurity {
    pub process_id: u32,
    pub creation_filetime: u64,
    pub elevated: bool,
    pub integrity_rid: u32,
}

impl WindowsProcessSecurity {
    pub fn is_medium_integrity(self) -> bool {
        (SECURITY_MANDATORY_MEDIUM_RID..SECURITY_MANDATORY_HIGH_RID)
            .contains(&self.integrity_rid)
    }

    pub fn is_high_integrity(self) -> bool {
        self.integrity_rid >= SECURITY_MANDATORY_HIGH_RID
    }
}

#[derive(Debug)]
pub struct ElevatedWindowsWfpBrokerExit {
    pub exit_code: u32,
    pub outcome: Option<WindowsWfpBrokerOutcome>,
}

pub struct ElevatedWindowsWfpBroker {
    process: OwnedHandle,
    identity: WindowsProcessSecurity,
    bootstrap: WriteHalf<NamedPipeServer>,
    broker_frames: mpsc::UnboundedReceiver<
        Result<Option<BootstrapBrokerFrame>, WindowsWfpBrokerBootstrapError>,
    >,
    broker_reader: JoinHandle<()>,
    event_logger: Arc<Mutex<BootstrapEventLogger>>,
    completed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrappedWindowsWfpBrokerExit {
    Outcome { clean: bool },
    LauncherDisconnected,
}

#[derive(Debug, thiserror::Error)]
pub enum WindowsWfpBrokerBootstrapError {
    #[error("invalid WFP broker bootstrap configuration: {0}")]
    InvalidConfiguration(String),
    #[error("WFP broker bootstrap identity is invalid: {0}")]
    Identity(String),
    #[error("WFP broker elevation launch failed: {0}")]
    Launch(String),
    #[error("WFP broker bootstrap protocol failed: {0}")]
    Protocol(String),
    #[error("WFP broker bootstrap pipe {operation} failed")]
    Pipe {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("timed out while {0}")]
    Timeout(&'static str),
    #[error("elevated WFP broker bootstrap failed ({class}): {message}")]
    Remote { class: String, message: String },
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

impl ElevatedWindowsWfpBroker {
    pub fn id(&self) -> u32 {
        self.identity.process_id
    }

    pub fn security(&self) -> WindowsProcessSecurity {
        self.identity
    }

    pub async fn request_crash(
        &mut self,
    ) -> Result<ElevatedWindowsWfpBrokerExit, WindowsWfpBrokerBootstrapError> {
        report_shared_bootstrap_event(
            &self.event_logger,
            "crash_requested",
            serde_json::json!({ "process_id": self.identity.process_id }),
        );
        write_bootstrap_frame(
            &mut self.bootstrap,
            &BootstrapLauncherFrame::Crash {
                version: PROTOCOL_VERSION,
            },
        )
        .await?;
        let response = time::timeout(
            CLOSE_TIMEOUT,
            self.read_broker_frame(),
        )
        .await
        .map_err(|_| WindowsWfpBrokerBootstrapError::Timeout(
            "waiting for broker crash acknowledgement",
        ))??
        .ok_or_else(|| WindowsWfpBrokerBootstrapError::Protocol(
            "broker disconnected before acknowledging crash control".to_owned(),
        ))?;
        if !matches!(
            response,
            BootstrapBrokerFrame::CrashAcknowledged {
                version: PROTOCOL_VERSION
            }
        ) {
            return Err(WindowsWfpBrokerBootstrapError::Protocol(
                "broker returned an unexpected crash-control response".to_owned(),
            ));
        }
        let exit_code = wait_for_process_exit(&self.process).await?;
        self.completed = true;
        self.broker_reader.abort();
        report_shared_bootstrap_event(
            &self.event_logger,
            "crash_exit_observed",
            serde_json::json!({
                "process_id": self.identity.process_id,
                "exit_code": exit_code,
            }),
        );
        Ok(ElevatedWindowsWfpBrokerExit {
            exit_code,
            outcome: None,
        })
    }

    pub async fn wait(
        &mut self,
    ) -> Result<ElevatedWindowsWfpBrokerExit, WindowsWfpBrokerBootstrapError> {
        let response = time::timeout(
            ACQUIRE_TIMEOUT,
            self.read_broker_frame(),
        )
        .await
        .map_err(|_| WindowsWfpBrokerBootstrapError::Timeout(
            "waiting for broker outcome",
        ))??;
        let outcome = match response {
            Some(BootstrapBrokerFrame::Outcome {
                version: PROTOCOL_VERSION,
                outcome,
            }) => Some(outcome),
            None => None,
            Some(_) => {
                return Err(WindowsWfpBrokerBootstrapError::Protocol(
                    "broker returned an unexpected bootstrap response".to_owned(),
                ));
            }
        };
        let exit_code = wait_for_process_exit(&self.process).await?;
        self.completed = true;
        self.broker_reader.abort();
        report_shared_bootstrap_event(
            &self.event_logger,
            "outcome_exit_observed",
            serde_json::json!({
                "process_id": self.identity.process_id,
                "exit_code": exit_code,
                "outcome": format!("{outcome:?}"),
            }),
        );
        Ok(ElevatedWindowsWfpBrokerExit { exit_code, outcome })
    }

    async fn read_broker_frame(
        &mut self,
    ) -> Result<Option<BootstrapBrokerFrame>, WindowsWfpBrokerBootstrapError> {
        self.broker_frames.recv().await.unwrap_or_else(|| {
            Err(WindowsWfpBrokerBootstrapError::Protocol(
                "bootstrap broker reader stopped before delivering a terminal frame"
                    .to_owned(),
            ))
        })
    }
}

impl Drop for ElevatedWindowsWfpBroker {
    fn drop(&mut self) {
        self.broker_reader.abort();
        if self.completed {
            return;
        }

        match unsafe { WaitForSingleObject(self.process.0, 0) } {
            WAIT_OBJECT_0 => return,
            WAIT_TIMEOUT => {}
            WAIT_FAILED => {
                report_shared_bootstrap_event(
                    &self.event_logger,
                    "orphan_state_check_failed",
                    serde_json::json!({
                        "process_id": self.identity.process_id,
                        "error": windows::core::Error::from_win32().to_string(),
                    }),
                );
            }
            result => {
                report_shared_bootstrap_event(
                    &self.event_logger,
                    "orphan_state_check_failed",
                    serde_json::json!({
                        "process_id": self.identity.process_id,
                        "unexpected_wait_result": result.0,
                    }),
                );
            }
        }

        report_shared_bootstrap_event(
            &self.event_logger,
            "orphan_termination_requested",
            serde_json::json!({
                "process_id": self.identity.process_id,
                "exit_code": WFP_BROKER_CRASH_EXIT_CODE,
            }),
        );
        if let Err(error) = unsafe {
            TerminateProcess(self.process.0, WFP_BROKER_CRASH_EXIT_CODE)
        } {
            report_shared_bootstrap_event(
                &self.event_logger,
                "orphan_termination_failed",
                serde_json::json!({
                    "process_id": self.identity.process_id,
                    "error": error.to_string(),
                }),
            );
            return;
        }

        let wait_result = unsafe {
            WaitForSingleObject(self.process.0, CLOSE_TIMEOUT.as_millis() as u32)
        };
        report_shared_bootstrap_event(
            &self.event_logger,
            "orphan_termination_observed",
            serde_json::json!({
                "process_id": self.identity.process_id,
                "wait_result": wait_result.0,
                "terminated": wait_result == WAIT_OBJECT_0,
            }),
        );
    }
}

impl PendingElevatedWindowsWfpBroker {
    fn new(process: OwnedHandle, event_logger: BootstrapEventLogger) -> Self {
        let process_id = unsafe { GetProcessId(process.0) };
        Self {
            process: Some(process),
            process_id,
            event_logger: Some(event_logger),
        }
    }

    fn process(&self) -> &OwnedHandle {
        self.process
            .as_ref()
            .expect("pending elevated broker owns its process handle")
    }

    fn event_logger_mut(&mut self) -> &mut BootstrapEventLogger {
        self.event_logger
            .as_mut()
            .expect("pending elevated broker owns its event logger")
    }

    fn set_process_id(&mut self, process_id: u32) {
        self.process_id = process_id;
    }

    fn complete(
        mut self,
        identity: WindowsProcessSecurity,
        bootstrap: NamedPipeServer,
    ) -> ElevatedWindowsWfpBroker {
        let process = self
            .process
            .take()
            .expect("pending elevated broker owns its process handle");
        let event_logger = self
            .event_logger
            .take()
            .expect("pending elevated broker owns its event logger");
        let event_logger = Arc::new(Mutex::new(event_logger));
        let (bootstrap_reader, bootstrap) = tokio::io::split(bootstrap);
        let (broker_frame_tx, broker_frames) = mpsc::unbounded_channel();
        let broker_reader = tokio::spawn(read_live_bootstrap_broker_frame(
            bootstrap_reader,
            Arc::clone(&event_logger),
            broker_frame_tx,
        ));
        ElevatedWindowsWfpBroker {
            process,
            identity,
            bootstrap,
            broker_frames,
            broker_reader,
            event_logger,
            completed: false,
        }
    }
}

impl Drop for PendingElevatedWindowsWfpBroker {
    fn drop(&mut self) {
        let process_id = self.process_id;
        let (Some(process), Some(event_logger)) =
            (self.process.as_ref(), self.event_logger.as_mut())
        else {
            return;
        };

        match unsafe { WaitForSingleObject(process.0, 0) } {
            WAIT_OBJECT_0 => {
                let mut exit_code = STILL_ACTIVE.0 as u32;
                let exit_code = unsafe { GetExitCodeProcess(process.0, &mut exit_code) }
                    .ok()
                    .map(|()| exit_code);
                event_logger.report(
                    "pending_launch_exit_observed",
                    serde_json::json!({
                        "process_id": process_id,
                        "exit_code": exit_code,
                    }),
                );
                return;
            }
            WAIT_TIMEOUT => {}
            WAIT_FAILED => {
                event_logger.report(
                    "pending_launch_state_check_failed",
                    serde_json::json!({
                        "process_id": process_id,
                        "error": windows::core::Error::from_win32().to_string(),
                    }),
                );
            }
            result => {
                event_logger.report(
                    "pending_launch_state_check_failed",
                    serde_json::json!({
                        "process_id": process_id,
                        "unexpected_wait_result": result.0,
                    }),
                );
            }
        }

        event_logger.report(
            "pending_launch_termination_requested",
            serde_json::json!({
                "process_id": process_id,
                "exit_code": WFP_BROKER_CRASH_EXIT_CODE,
            }),
        );
        if let Err(error) = unsafe {
            TerminateProcess(process.0, WFP_BROKER_CRASH_EXIT_CODE)
        } {
            event_logger.report(
                "pending_launch_termination_failed",
                serde_json::json!({
                    "process_id": process_id,
                    "error": error.to_string(),
                }),
            );
            return;
        }

        let wait_result = unsafe {
            WaitForSingleObject(process.0, CLOSE_TIMEOUT.as_millis() as u32)
        };
        let mut exit_code = STILL_ACTIVE.0 as u32;
        let exit_code = if wait_result == WAIT_OBJECT_0 {
            unsafe { GetExitCodeProcess(process.0, &mut exit_code) }
                .ok()
                .map(|()| exit_code)
        } else {
            None
        };
        event_logger.report(
            "pending_launch_termination_observed",
            serde_json::json!({
                "process_id": process_id,
                "wait_result": wait_result.0,
                "terminated": wait_result == WAIT_OBJECT_0,
                "exit_code": exit_code,
            }),
        );
    }
}

async fn recover_handleless_elevated_broker(
    bootstrap: &mut NamedPipeServer,
    event_logger: &mut BootstrapEventLogger,
) -> String {
    match time::timeout(PREAUTH_FRAME_TIMEOUT, bootstrap.connect()).await {
        Err(_) => {
            event_logger.report(
                "handleless_recovery_no_client",
                serde_json::json!({ "outcome": "timeout" }),
            );
            return "handleless recovery observed no bootstrap client before timeout"
                .to_owned();
        }
        Ok(Err(error)) => {
            let message = bounded_sanitized_bootstrap_text(
                &error.to_string(),
                MAX_BOOTSTRAP_FAILURE_MESSAGE_BYTES,
            );
            event_logger.report(
                "handleless_recovery_no_client",
                serde_json::json!({
                    "outcome": "connect_failed",
                    "error": &message,
                }),
            );
            return format!(
                "handleless recovery bootstrap connection failed: {message}"
            );
        }
        Ok(Ok(())) => {}
    }

    let peer = match PeerProcess::from_pipe(bootstrap) {
        Ok(peer) => peer,
        Err(error) => {
            let message = bounded_sanitized_bootstrap_text(
                &error,
                MAX_BOOTSTRAP_FAILURE_MESSAGE_BYTES,
            );
            event_logger.report(
                "handleless_recovery_peer_rejected",
                serde_json::json!({ "error": &message }),
            );
            return format!(
                "handleless recovery rejected the bootstrap peer: {message}"
            );
        }
    };
    let security = match inspect_process_security_handle(peer.handle.0) {
        Ok(security) => security,
        Err(error) => {
            let message = bounded_sanitized_bootstrap_text(
                &error,
                MAX_BOOTSTRAP_FAILURE_MESSAGE_BYTES,
            );
            event_logger.report(
                "handleless_recovery_peer_rejected",
                serde_json::json!({
                    "process_id": peer.pid,
                    "error": &message,
                }),
            );
            return format!(
                "handleless recovery could not inspect bootstrap peer {}: {message}",
                peer.pid
            );
        }
    };
    if security.process_id != peer.pid
        || security.creation_filetime != peer.creation_filetime
        || !security.elevated
        || !security.is_high_integrity()
    {
        event_logger.report(
            "handleless_recovery_peer_rejected",
            serde_json::json!({
                "process_id": peer.pid,
                "creation_filetime": peer.creation_filetime,
                "observed_security": {
                    "process_id": security.process_id,
                    "creation_filetime": security.creation_filetime,
                    "elevated": security.elevated,
                    "integrity_rid": security.integrity_rid,
                },
            }),
        );
        return format!(
            "handleless recovery rejected bootstrap peer {} because it was not the same elevated high-integrity process incarnation",
            peer.pid
        );
    }

    if let Err(error) = await_handleless_broker_authentication(
        bootstrap,
        event_logger,
        peer.pid,
    )
    .await
    {
        let message = bounded_sanitized_bootstrap_text(
            &error,
            MAX_BOOTSTRAP_FAILURE_MESSAGE_BYTES,
        );
        event_logger.report(
            "handleless_recovery_peer_rejected",
            serde_json::json!({
                "process_id": peer.pid,
                "error": &message,
            }),
        );
        return format!(
            "handleless recovery rejected unauthenticated bootstrap peer {}: {message}",
            peer.pid
        );
    }
    event_logger.report(
        "handleless_recovery_peer_authenticated",
        serde_json::json!({
            "process_id": peer.pid,
            "creation_filetime": peer.creation_filetime,
            "integrity_rid": security.integrity_rid,
        }),
    );

    let process = match unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION
                | PROCESS_SYNCHRONIZE
                | PROCESS_TERMINATE,
            false,
            peer.pid,
        )
    }
    .map(OwnedHandle)
    {
        Ok(process) => process,
        Err(error) => {
            let message = bounded_sanitized_bootstrap_text(
                &error.to_string(),
                MAX_BOOTSTRAP_FAILURE_MESSAGE_BYTES,
            );
            event_logger.report(
                "handleless_recovery_termination_failed",
                serde_json::json!({
                    "process_id": peer.pid,
                    "operation": "open_terminate_handle",
                    "error": &message,
                }),
            );
            return format!(
                "handleless recovery could not open broker {} for termination: {message}",
                peer.pid
            );
        }
    };
    let opened_security = match inspect_process_security_handle(process.0) {
        Ok(security) => security,
        Err(error) => {
            let message = bounded_sanitized_bootstrap_text(
                &error,
                MAX_BOOTSTRAP_FAILURE_MESSAGE_BYTES,
            );
            event_logger.report(
                "handleless_recovery_peer_rejected",
                serde_json::json!({
                    "process_id": peer.pid,
                    "operation": "revalidate_terminate_handle",
                    "error": &message,
                }),
            );
            return format!(
                "handleless recovery could not revalidate broker {}: {message}",
                peer.pid
            );
        }
    };
    let same_user = process_user_sid(process.0)
        .and_then(|peer_sid| {
            process_user_sid(unsafe { GetCurrentProcess() })
                .map(|launcher_sid| peer_sid == launcher_sid)
        });
    let same_user_valid = matches!(&same_user, Ok(true));
    if opened_security.process_id != peer.pid
        || opened_security.creation_filetime != peer.creation_filetime
        || !opened_security.elevated
        || !opened_security.is_high_integrity()
        || !same_user_valid
    {
        let same_user_error = same_user.as_ref().err().map(|error| {
            bounded_sanitized_bootstrap_text(
                error,
                MAX_BOOTSTRAP_FAILURE_MESSAGE_BYTES,
            )
        });
        event_logger.report(
            "handleless_recovery_peer_rejected",
            serde_json::json!({
                "process_id": peer.pid,
                "operation": "revalidate_terminate_handle",
                "same_user": same_user_valid,
                "same_user_error": same_user_error,
                "observed_security": {
                    "process_id": opened_security.process_id,
                    "creation_filetime": opened_security.creation_filetime,
                    "elevated": opened_security.elevated,
                    "integrity_rid": opened_security.integrity_rid,
                },
            }),
        );
        return format!(
            "handleless recovery refused to terminate broker {} after identity revalidation failed",
            peer.pid
        );
    }
    match unsafe { WaitForSingleObject(process.0, 0) } {
        WAIT_OBJECT_0 => {
            let mut exit_code = STILL_ACTIVE.0 as u32;
            let exit_code = unsafe { GetExitCodeProcess(process.0, &mut exit_code) }
                .ok()
                .map(|()| exit_code);
            event_logger.report(
                "handleless_recovery_exit_observed",
                serde_json::json!({
                    "process_id": peer.pid,
                    "exit_code": exit_code,
                }),
            );
            return format!(
                "handleless recovery found broker {} already exited with code {exit_code:?}",
                peer.pid
            );
        }
        WAIT_TIMEOUT => {}
        WAIT_FAILED => {
            let message = windows::core::Error::from_win32().to_string();
            event_logger.report(
                "handleless_recovery_state_check_failed",
                serde_json::json!({
                    "process_id": peer.pid,
                    "error": &message,
                }),
            );
        }
        result => {
            event_logger.report(
                "handleless_recovery_state_check_failed",
                serde_json::json!({
                    "process_id": peer.pid,
                    "unexpected_wait_result": result.0,
                }),
            );
        }
    }

    event_logger.report(
        "handleless_recovery_termination_requested",
        serde_json::json!({
            "process_id": peer.pid,
            "exit_code": WFP_BROKER_CRASH_EXIT_CODE,
        }),
    );
    if let Err(error) = unsafe {
        TerminateProcess(process.0, WFP_BROKER_CRASH_EXIT_CODE)
    } {
        let message = bounded_sanitized_bootstrap_text(
            &error.to_string(),
            MAX_BOOTSTRAP_FAILURE_MESSAGE_BYTES,
        );
        event_logger.report(
            "handleless_recovery_termination_failed",
            serde_json::json!({
                "process_id": peer.pid,
                "operation": "terminate",
                "error": &message,
            }),
        );
        return format!(
            "handleless recovery could not terminate broker {}: {message}",
            peer.pid
        );
    }

    let wait_result = unsafe {
        WaitForSingleObject(process.0, CLOSE_TIMEOUT.as_millis() as u32)
    };
    let mut exit_code = STILL_ACTIVE.0 as u32;
    let exit_code = if wait_result == WAIT_OBJECT_0 {
        unsafe { GetExitCodeProcess(process.0, &mut exit_code) }
            .ok()
            .map(|()| exit_code)
    } else {
        None
    };
    event_logger.report(
        "handleless_recovery_termination_observed",
        serde_json::json!({
            "process_id": peer.pid,
            "wait_result": wait_result.0,
            "terminated": wait_result == WAIT_OBJECT_0,
            "exit_code": exit_code,
        }),
    );
    format!(
        "handleless recovery termination for broker {} completed with wait result {} and exit code {exit_code:?}",
        peer.pid,
        wait_result.0
    )
}

async fn await_handleless_broker_authentication(
    bootstrap: &mut NamedPipeServer,
    event_logger: &mut BootstrapEventLogger,
    peer_pid: u32,
) -> Result<(), String> {
    time::timeout(PREAUTH_FRAME_TIMEOUT, async {
        loop {
            let frame = read_bootstrap_frame::<_, BootstrapBrokerFrame>(bootstrap)
                .await
                .map_err(|error| error.to_string())?
                .ok_or_else(|| {
                    "bootstrap peer disconnected before authenticating its launcher"
                        .to_owned()
                })?;
            match frame {
                BootstrapBrokerFrame::Diagnostic {
                    version: PROTOCOL_VERSION,
                    record,
                } => {
                    if record.process_id != peer_pid {
                        return Err(
                            "bootstrap diagnostic process ID did not match the connected peer"
                                .to_owned(),
                        );
                    }
                    let launcher_authenticated =
                        record.event == "launcher_authenticated";
                    let expected_parent = record
                        .detail
                        .get("parent_process_id")
                        .and_then(serde_json::Value::as_u64)
                        == Some(std::process::id() as u64);
                    event_logger.append(&record);
                    if launcher_authenticated {
                        if expected_parent {
                            return Ok(());
                        }
                        return Err(
                            "bootstrap peer authenticated a different launcher process"
                                .to_owned(),
                        );
                    }
                }
                BootstrapBrokerFrame::Failed {
                    version: PROTOCOL_VERSION,
                    class,
                    message,
                } => {
                    let class = bounded_sanitized_bootstrap_text(
                        &class,
                        MAX_BOOTSTRAP_FAILURE_CLASS_BYTES,
                    );
                    let message = bounded_sanitized_bootstrap_text(
                        &message,
                        MAX_BOOTSTRAP_FAILURE_MESSAGE_BYTES,
                    );
                    return Err(format!(
                        "bootstrap peer failed before launcher authentication ({class}): {message}"
                    ));
                }
                BootstrapBrokerFrame::Diagnostic { .. }
                | BootstrapBrokerFrame::Failed { .. } => {
                    return Err(
                        "bootstrap peer used an unsupported pre-authentication frame version"
                            .to_owned(),
                    );
                }
                BootstrapBrokerFrame::CrashAcknowledged { .. }
                | BootstrapBrokerFrame::Outcome { .. } => {
                    return Err(
                        "bootstrap peer sent a terminal frame before launcher authentication"
                            .to_owned(),
                    );
                }
            }
        }
    })
    .await
    .map_err(|_| {
        "timed out waiting for bootstrap peer launcher authentication".to_owned()
    })?
}

/// Starts only the WFP broker elevated. The caller, station, and browser stay
/// at medium integrity. The one-use capability is transferred only after the
/// exact `runas` process has authenticated on an owner-restricted pipe.
pub async fn launch_elevated_windows_wfp_broker(
    executable: &Path,
    pipe_name: &str,
    allowed_runtime_root: &Path,
    capability: WindowsWfpBrokerCapability,
) -> Result<ElevatedWindowsWfpBroker, WindowsWfpBrokerBootstrapError> {
    let launcher = inspect_process_security_handle(unsafe { GetCurrentProcess() })
        .map_err(WindowsWfpBrokerBootstrapError::Identity)?;
    if launcher.elevated || !launcher.is_medium_integrity() {
        return Err(WindowsWfpBrokerBootstrapError::Identity(
            "WFP broker launcher must be a non-elevated medium-integrity process"
                .to_owned(),
        ));
    }
    let mut event_logger = BootstrapEventLogger::from_medium_launcher_environment();
    event_logger.report(
        "launch_requested",
        serde_json::json!({ "executable": executable }),
    );
    if !executable.is_file() {
        return Err(WindowsWfpBrokerBootstrapError::InvalidConfiguration(
            format!("broker executable does not exist: {}", executable.display()),
        ));
    }
    local_pipe_name(pipe_name)
        .map_err(|error| WindowsWfpBrokerBootstrapError::InvalidConfiguration(
            error.to_string(),
        ))?;

    let bootstrap_name = format!(
        "dig2browser-wfp-bootstrap-{}",
        uuid::Uuid::new_v4().simple()
    );
    let full_bootstrap_name = local_pipe_name(&bootstrap_name)
        .map_err(|error| WindowsWfpBrokerBootstrapError::InvalidConfiguration(
            error.to_string(),
        ))?;
    let mut bootstrap = create_owner_restricted_pipe(&full_bootstrap_name)
        .map_err(bootstrap_from_broker_error)?;

    let arguments = vec![
        "--bootstrap-pipe".to_owned(),
        bootstrap_name,
        "--bootstrap-parent-pid".to_owned(),
        launcher.process_id.to_string(),
        "--bootstrap-parent-creation-filetime".to_owned(),
        launcher.creation_filetime.to_string(),
        "--pipe-name".to_owned(),
        pipe_name.to_owned(),
        "--allowed-runtime-root".to_owned(),
        allowed_runtime_root.as_os_str().to_string_lossy().into_owned(),
    ];
    let parameters = arguments
        .into_iter()
        .map(|argument| quote_windows_argument(&argument))
        .collect::<Vec<_>>()
        .join(" ");
    let verb = wide_null("runas")?;
    let file = wide_null_os(executable.as_os_str())?;
    let parameters = wide_null(&parameters)?;
    let mut execute = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: PCWSTR(verb.as_ptr()),
        lpFile: PCWSTR(file.as_ptr()),
        lpParameters: PCWSTR(parameters.as_ptr()),
        nShow: 0,
        ..Default::default()
    };
    unsafe { ShellExecuteExW(&mut execute) }
        .map_err(|error| WindowsWfpBrokerBootstrapError::Launch(error.to_string()))?;
    if execute.hProcess.is_invalid() {
        event_logger.report(
            "handleless_recovery_started",
            serde_json::json!({ "bootstrap_pipe": full_bootstrap_name }),
        );
        let recovery = recover_handleless_elevated_broker(
            &mut bootstrap,
            &mut event_logger,
        )
        .await;
        return Err(WindowsWfpBrokerBootstrapError::Launch(
            format!(
                "ShellExecuteExW did not return a broker process handle; {recovery}"
            ),
        ));
    }
    let mut pending = PendingElevatedWindowsWfpBroker::new(
        OwnedHandle(execute.hProcess),
        event_logger,
    );
    let identity = inspect_process_security_handle(pending.process().0)
        .map_err(WindowsWfpBrokerBootstrapError::Identity)?;
    pending.set_process_id(identity.process_id);
    if !identity.elevated || !identity.is_high_integrity() {
        return Err(WindowsWfpBrokerBootstrapError::Identity(
            "runas broker is not elevated at high integrity".to_owned(),
        ));
    }
    pending.event_logger_mut().report(
        "elevated_process_started",
        serde_json::json!({
            "process_id": identity.process_id,
            "creation_filetime": identity.creation_filetime,
            "integrity_rid": identity.integrity_rid,
            "elevated": identity.elevated,
        }),
    );

    tokio::select! {
        biased;
        connect = time::timeout(ACQUIRE_TIMEOUT, bootstrap.connect()) => {
            connect
                .map_err(|_| WindowsWfpBrokerBootstrapError::Timeout(
                    "waiting for elevated broker bootstrap",
                ))?
                .map_err(|source| WindowsWfpBrokerBootstrapError::Pipe {
                    operation: "connect",
                    source,
                })?;
        }
        exit = wait_for_process_exit(pending.process()) => {
            let exit_code = exit?;
            return Err(WindowsWfpBrokerBootstrapError::Launch(format!(
                "elevated broker exited before bootstrap connection with code {exit_code}"
            )));
        }
    }
    let peer = PeerProcess::from_pipe(&bootstrap)
        .map_err(WindowsWfpBrokerBootstrapError::Identity)?;
    if peer.pid != identity.process_id
        || peer.creation_filetime != identity.creation_filetime
    {
        return Err(WindowsWfpBrokerBootstrapError::Identity(
            "bootstrap client is not the exact process returned by ShellExecuteExW"
                .to_owned(),
        ));
    }
    let peer_security = inspect_process_security_handle(peer.handle.0)
        .map_err(WindowsWfpBrokerBootstrapError::Identity)?;
    if !peer_security.elevated || !peer_security.is_high_integrity() {
        return Err(WindowsWfpBrokerBootstrapError::Identity(
            "bootstrap client is not an elevated high-integrity broker".to_owned(),
        ));
    }
    pending.event_logger_mut().report(
        "elevated_peer_authenticated",
        serde_json::json!({ "process_id": peer_security.process_id }),
    );

    let start_write = write_bootstrap_frame(
        &mut bootstrap,
        &BootstrapLauncherFrame::Start {
            version: PROTOCOL_VERSION,
            capability,
        },
    )
    .await;
    if let Err(write_error) = start_write {
        if let Ok(Err(remote_error @ WindowsWfpBrokerBootstrapError::Remote { .. })) =
            time::timeout(
                PREAUTH_REJECT_TIMEOUT,
                read_bootstrap_broker_frame(
                    &mut bootstrap,
                    pending.event_logger_mut(),
                ),
            )
            .await
        {
            return Err(remote_error);
        }
        return Err(write_error);
    }
    pending.event_logger_mut().report(
        "capability_transferred",
        serde_json::json!({ "process_id": identity.process_id }),
    );
    Ok(pending.complete(identity, bootstrap))
}

pub async fn run_bootstrapped_windows_wfp_broker(
    bootstrap_pipe_name: &str,
    expected_parent_pid: u32,
    expected_parent_creation_filetime: u64,
    pipe_name: &str,
    allowed_runtime_root: &Path,
) -> Result<BootstrappedWindowsWfpBrokerExit, WindowsWfpBrokerBootstrapError> {
    let full_bootstrap_name = local_pipe_name(bootstrap_pipe_name)
        .map_err(|error| WindowsWfpBrokerBootstrapError::InvalidConfiguration(
            error.to_string(),
        ))?;
    let mut bootstrap = connect_client(&full_bootstrap_name)
        .await
        .map_err(bootstrap_from_broker_error)?;
    report_elevated_bootstrap_event(
        &mut bootstrap,
        "broker_connected_to_launcher",
        serde_json::json!({ "process_id": std::process::id() }),
    ).await;
    if let Err(message) = verify_bootstrap_launcher(
        &bootstrap,
        expected_parent_pid,
        expected_parent_creation_filetime,
    ) {
        let error = WindowsWfpBrokerBootstrapError::Identity(message);
        report_elevated_bootstrap_failure(&mut bootstrap, &error).await;
        return Err(error);
    }
    report_elevated_bootstrap_event(
        &mut bootstrap,
        "launcher_authenticated",
        serde_json::json!({ "parent_process_id": expected_parent_pid }),
    ).await;
    let result = run_authenticated_windows_wfp_broker(
        &mut bootstrap,
        pipe_name,
        allowed_runtime_root,
    )
    .await;
    if let Err(error) = &result {
        report_elevated_bootstrap_failure(&mut bootstrap, error).await;
    }
    result
}

async fn run_authenticated_windows_wfp_broker(
    bootstrap: &mut NamedPipeClient,
    pipe_name: &str,
    allowed_runtime_root: &Path,
) -> Result<BootstrappedWindowsWfpBrokerExit, WindowsWfpBrokerBootstrapError> {
    let start = time::timeout(
        PREAUTH_FRAME_TIMEOUT,
        read_bootstrap_frame::<_, BootstrapLauncherFrame>(bootstrap),
    )
    .await
    .map_err(|_| WindowsWfpBrokerBootstrapError::Timeout(
        "waiting for bootstrap capability",
    ))??
    .ok_or_else(|| WindowsWfpBrokerBootstrapError::Protocol(
        "launcher disconnected before sending bootstrap capability".to_owned(),
    ))?;
    let capability = match start {
        BootstrapLauncherFrame::Start {
            version: PROTOCOL_VERSION,
            capability,
        } => capability,
        _ => {
            return Err(WindowsWfpBrokerBootstrapError::Protocol(
                "first bootstrap frame must be a version 3 start request".to_owned(),
            ));
        }
    };
    report_elevated_bootstrap_event(
        bootstrap,
        "capability_received",
        serde_json::json!({ "process_id": std::process::id() }),
    ).await;

    let broker = run_windows_wfp_broker(pipe_name, allowed_runtime_root, capability);
    tokio::pin!(broker);
    tokio::select! {
        outcome = &mut broker => {
            let clean = outcome.is_clean_close();
            report_elevated_bootstrap_event(
                bootstrap,
                "broker_outcome",
                serde_json::json!({
                    "clean": clean,
                    "outcome": format!("{outcome:?}"),
                }),
            ).await;
            write_bootstrap_frame(
                bootstrap,
                &BootstrapBrokerFrame::Outcome {
                    version: PROTOCOL_VERSION,
                    outcome,
                },
            ).await?;
            Ok(BootstrappedWindowsWfpBrokerExit::Outcome { clean })
        }
        control = read_bootstrap_frame::<_, BootstrapLauncherFrame>(bootstrap) => {
            match control? {
                Some(BootstrapLauncherFrame::Crash {
                    version: PROTOCOL_VERSION,
                }) => {
                    write_bootstrap_frame(
                        bootstrap,
                        &BootstrapBrokerFrame::CrashAcknowledged {
                            version: PROTOCOL_VERSION,
                        },
                    ).await?;
                    unsafe {
                        TerminateProcess(
                            GetCurrentProcess(),
                            WFP_BROKER_CRASH_EXIT_CODE,
                        )
                    }
                    .map_err(|error| WindowsWfpBrokerBootstrapError::Launch(
                        format!("cannot terminate WFP broker for crash proof: {error}"),
                    ))?;
                    loop {
                        std::thread::park();
                    }
                }
                None => Ok(
                    {
                        report_elevated_bootstrap_event(
                            bootstrap,
                            "launcher_disconnected",
                            serde_json::json!({ "process_id": std::process::id() }),
                        ).await;
                        BootstrappedWindowsWfpBrokerExit::LauncherDisconnected
                    },
                ),
                Some(_) => Err(WindowsWfpBrokerBootstrapError::Protocol(
                    "unexpected bootstrap control frame".to_owned(),
                )),
            }
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
    let mut pipe = connect_impersonable_client(&pipe_name).await?;
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

    let response = time::timeout(LEASE_GRANT_TIMEOUT, read_frame::<_, BrokerFrame>(&mut pipe))
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
    connect_client_with_security_qos(pipe_name, None).await
}

async fn connect_impersonable_client(
    pipe_name: &str,
) -> Result<NamedPipeClient, WindowsWfpBrokerError> {
    connect_client_with_security_qos(pipe_name, Some(SECURITY_IMPERSONATION.0)).await
}

async fn connect_client_with_security_qos(
    pipe_name: &str,
    security_qos_flags: Option<u32>,
) -> Result<NamedPipeClient, WindowsWfpBrokerError> {
    let deadline = Instant::now() + CONNECT_TIMEOUT;
    loop {
        let mut options = ClientOptions::new();
        if let Some(flags) = security_qos_flags {
            options.security_qos_flags(flags);
        }
        match options.open(pipe_name) {
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

async fn write_bootstrap_frame<W, T>(
    writer: &mut W,
    value: &T,
) -> Result<(), WindowsWfpBrokerBootstrapError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    write_frame(writer, value)
        .await
        .map_err(bootstrap_from_broker_error)
}

async fn read_bootstrap_frame<R, T>(
    reader: &mut R,
) -> Result<Option<T>, WindowsWfpBrokerBootstrapError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    read_frame(reader)
        .await
        .map_err(bootstrap_from_broker_error)
}

async fn read_bootstrap_broker_frame<R>(
    reader: &mut R,
    event_logger: &mut BootstrapEventLogger,
) -> Result<Option<BootstrapBrokerFrame>, WindowsWfpBrokerBootstrapError>
where
    R: AsyncRead + Unpin,
{
    loop {
        match read_bootstrap_frame::<_, BootstrapBrokerFrame>(reader).await? {
            Some(BootstrapBrokerFrame::Diagnostic {
                version: PROTOCOL_VERSION,
                record,
            }) => event_logger.append(&record),
            Some(BootstrapBrokerFrame::Diagnostic { .. }) => {
                return Err(WindowsWfpBrokerBootstrapError::Protocol(
                    "broker returned an unsupported diagnostic frame version"
                        .to_owned(),
                ));
            }
            Some(BootstrapBrokerFrame::Failed {
                version: PROTOCOL_VERSION,
                class,
                message,
            }) => {
                let class = bounded_sanitized_bootstrap_text(
                    &class,
                    MAX_BOOTSTRAP_FAILURE_CLASS_BYTES,
                );
                let message = bounded_sanitized_bootstrap_text(
                    &message,
                    MAX_BOOTSTRAP_FAILURE_MESSAGE_BYTES,
                );
                event_logger.report(
                    "broker_bootstrap_failed",
                    serde_json::json!({
                        "class": &class,
                        "message": &message,
                    }),
                );
                return Err(WindowsWfpBrokerBootstrapError::Remote {
                    class,
                    message,
                });
            }
            Some(BootstrapBrokerFrame::Failed { .. }) => {
                return Err(WindowsWfpBrokerBootstrapError::Protocol(
                    "broker returned an unsupported failure frame version"
                        .to_owned(),
                ));
            }
            frame => return Ok(frame),
        }
    }
}

async fn read_live_bootstrap_broker_frame<R>(
    mut reader: R,
    event_logger: Arc<Mutex<BootstrapEventLogger>>,
    broker_frame_tx: mpsc::UnboundedSender<
        Result<Option<BootstrapBrokerFrame>, WindowsWfpBrokerBootstrapError>,
    >,
) where
    R: AsyncRead + Unpin,
{
    loop {
        let frame = match read_bootstrap_frame::<_, BootstrapBrokerFrame>(&mut reader).await {
            Ok(frame) => frame,
            Err(error) => {
                let _ = broker_frame_tx.send(Err(error));
                return;
            }
        };
        match frame {
            Some(BootstrapBrokerFrame::Diagnostic {
                version: PROTOCOL_VERSION,
                record,
            }) => append_shared_bootstrap_record(&event_logger, &record),
            Some(BootstrapBrokerFrame::Diagnostic { .. }) => {
                let _ = broker_frame_tx.send(Err(
                    WindowsWfpBrokerBootstrapError::Protocol(
                        "broker returned an unsupported diagnostic frame version"
                            .to_owned(),
                    ),
                ));
                return;
            }
            Some(BootstrapBrokerFrame::Failed {
                version: PROTOCOL_VERSION,
                class,
                message,
            }) => {
                let class = bounded_sanitized_bootstrap_text(
                    &class,
                    MAX_BOOTSTRAP_FAILURE_CLASS_BYTES,
                );
                let message = bounded_sanitized_bootstrap_text(
                    &message,
                    MAX_BOOTSTRAP_FAILURE_MESSAGE_BYTES,
                );
                report_shared_bootstrap_event(
                    &event_logger,
                    "broker_bootstrap_failed",
                    serde_json::json!({
                        "class": &class,
                        "message": &message,
                    }),
                );
                let _ = broker_frame_tx.send(Err(
                    WindowsWfpBrokerBootstrapError::Remote { class, message },
                ));
                return;
            }
            Some(BootstrapBrokerFrame::Failed { .. }) => {
                let _ = broker_frame_tx.send(Err(
                    WindowsWfpBrokerBootstrapError::Protocol(
                        "broker returned an unsupported failure frame version"
                            .to_owned(),
                    ),
                ));
                return;
            }
            frame => {
                let _ = broker_frame_tx.send(Ok(frame));
                return;
            }
        }
    }
}

fn bootstrap_from_broker_error(
    error: WindowsWfpBrokerError,
) -> WindowsWfpBrokerBootstrapError {
    match error {
        WindowsWfpBrokerError::Pipe { operation, source } => {
            WindowsWfpBrokerBootstrapError::Pipe { operation, source }
        }
        WindowsWfpBrokerError::Timeout(operation) => {
            WindowsWfpBrokerBootstrapError::Timeout(operation)
        }
        other => WindowsWfpBrokerBootstrapError::Protocol(other.to_string()),
    }
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

pub fn inspect_windows_process_security(
    process_id: u32,
) -> Result<WindowsProcessSecurity, String> {
    if process_id == 0 {
        return Err("cannot inspect process ID zero".to_owned());
    }
    let process = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            false,
            process_id,
        )
    }
    .map(OwnedHandle)
    .map_err(|error| format!("cannot open process {process_id}: {error}"))?;
    inspect_process_security_handle(process.0)
}

fn inspect_process_security_handle(
    process: HANDLE,
) -> Result<WindowsProcessSecurity, String> {
    let process_id = unsafe { GetProcessId(process) };
    if process_id == 0 {
        return Err("Windows returned an invalid process ID".to_owned());
    }
    Ok(WindowsProcessSecurity {
        process_id,
        creation_filetime: process_creation_filetime(process)?,
        elevated: process_token_is_elevated(process)?,
        integrity_rid: process_integrity_rid(process)?,
    })
}

fn process_integrity_rid(process: HANDLE) -> Result<u32, String> {
    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }
        .map_err(|error| format!("cannot open process token: {error}"))?;
    let token = OwnedHandle(token);
    let mut required = 0_u32;
    let _ = unsafe {
        GetTokenInformation(token.0, TokenIntegrityLevel, None, 0, &mut required)
    };
    if required < std::mem::size_of::<TOKEN_MANDATORY_LABEL>() as u32 {
        return Err("Windows returned an invalid token-integrity size".to_owned());
    }
    let words = (required as usize)
        .saturating_add(std::mem::size_of::<usize>() - 1)
        / std::mem::size_of::<usize>();
    let mut buffer = vec![0_usize; words];
    unsafe {
        GetTokenInformation(
            token.0,
            TokenIntegrityLevel,
            Some(buffer.as_mut_ptr().cast()),
            required,
            &mut required,
        )
    }
    .map_err(|error| format!("cannot read process-token integrity: {error}"))?;
    let label = unsafe { &*(buffer.as_ptr().cast::<TOKEN_MANDATORY_LABEL>()) };
    let sid = label.Label.Sid;
    if sid.0.is_null() {
        return Err("Windows returned a null token-integrity SID".to_owned());
    }
    let subauthority_count = unsafe { *GetSidSubAuthorityCount(sid) } as u32;
    if subauthority_count == 0 {
        return Err("Windows returned an invalid token-integrity SID".to_owned());
    }
    let rid = unsafe { GetSidSubAuthority(sid, subauthority_count - 1) };
    if rid.is_null() {
        return Err("Windows returned a null token-integrity RID".to_owned());
    }
    Ok(unsafe { *rid })
}

fn verify_bootstrap_launcher(
    pipe: &NamedPipeClient,
    expected_pid: u32,
    expected_creation_filetime: u64,
) -> Result<(), String> {
    if expected_pid == 0 || expected_creation_filetime == 0 {
        return Err("bootstrap launcher identity is incomplete".to_owned());
    }
    let pipe_handle = HANDLE(pipe.as_raw_handle());
    let mut pid = 0_u32;
    unsafe { GetNamedPipeServerProcessId(pipe_handle, &mut pid) }
        .map_err(|error| format!("cannot identify bootstrap launcher: {error}"))?;
    if pid != expected_pid {
        return Err("bootstrap server process ID does not match the launcher".to_owned());
    }
    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            false,
            pid,
        )
    }
    .map(OwnedHandle)
    .map_err(|error| format!("cannot open bootstrap launcher process: {error}"))?;
    if process_creation_filetime(handle.0)? != expected_creation_filetime {
        return Err("bootstrap server process incarnation does not match the launcher"
            .to_owned());
    }
    if unsafe { WaitForSingleObject(handle.0, 0) } != WAIT_TIMEOUT {
        return Err("bootstrap launcher is not live".to_owned());
    }
    if process_user_sid(handle.0)?
        != process_user_sid(unsafe { GetCurrentProcess() })?
    {
        return Err("bootstrap launcher belongs to a different Windows user".to_owned());
    }
    let security = inspect_process_security_handle(handle.0)?;
    if security.elevated || !security.is_medium_integrity() {
        return Err("bootstrap launcher is not non-elevated medium integrity".to_owned());
    }
    Ok(())
}

async fn wait_for_process_exit(
    process: &OwnedHandle,
) -> Result<u32, WindowsWfpBrokerBootstrapError> {
    let deadline = Instant::now() + ACQUIRE_TIMEOUT;
    loop {
        match unsafe { WaitForSingleObject(process.0, 0) } {
            WAIT_OBJECT_0 => break,
            WAIT_TIMEOUT if Instant::now() < deadline => {
                time::sleep(PREAUTH_RETRY_DELAY).await;
            }
            WAIT_TIMEOUT => {
                return Err(WindowsWfpBrokerBootstrapError::Timeout(
                    "waiting for elevated broker process exit",
                ));
            }
            WAIT_FAILED => {
                return Err(WindowsWfpBrokerBootstrapError::Launch(format!(
                    "cannot wait for elevated broker: {}",
                    windows::core::Error::from_win32()
                )));
            }
            result => {
                return Err(WindowsWfpBrokerBootstrapError::Launch(format!(
                    "unexpected elevated broker wait result: {}",
                    result.0
                )));
            }
        }
    }
    let mut exit_code = STILL_ACTIVE.0 as u32;
    unsafe { GetExitCodeProcess(process.0, &mut exit_code) }
        .map_err(|error| WindowsWfpBrokerBootstrapError::Launch(format!(
            "cannot read elevated broker exit code: {error}"
        )))?;
    if exit_code == STILL_ACTIVE.0 as u32 {
        return Err(WindowsWfpBrokerBootstrapError::Launch(
            "elevated broker remained active after its process handle was signaled"
                .to_owned(),
        ));
    }
    Ok(exit_code)
}

fn quote_windows_argument(argument: &str) -> String {
    if !argument.is_empty()
        && !argument.chars().any(|character| {
            character.is_whitespace() || character == '"'
        })
    {
        return argument.to_owned();
    }
    let mut quoted = String::from("\"");
    let mut backslashes = 0_usize;
    for character in argument.chars() {
        if character == '\\' {
            backslashes += 1;
        } else if character == '"' {
            quoted.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
            quoted.push('"');
            backslashes = 0;
        } else {
            quoted.extend(std::iter::repeat_n('\\', backslashes));
            backslashes = 0;
            quoted.push(character);
        }
    }
    quoted.extend(std::iter::repeat_n('\\', backslashes * 2));
    quoted.push('"');
    quoted
}

fn wide_null(value: &str) -> Result<Vec<u16>, WindowsWfpBrokerBootstrapError> {
    wide_null_os(std::ffi::OsStr::new(value))
}

fn wide_null_os(
    value: &std::ffi::OsStr,
) -> Result<Vec<u16>, WindowsWfpBrokerBootstrapError> {
    let mut wide = value.encode_wide().collect::<Vec<_>>();
    if wide.contains(&0) {
        return Err(WindowsWfpBrokerBootstrapError::InvalidConfiguration(
            "broker launch argument contains NUL".to_owned(),
        ));
    }
    wide.push(0);
    Ok(wide)
}

impl BootstrapEventRecord {
    fn new(event: &str, detail: serde_json::Value) -> Self {
        let at_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis() as u64)
            .unwrap_or_default();
        Self {
            schema_version: 1,
            at_unix_ms,
            process_id: std::process::id(),
            event: event.to_owned(),
            detail,
        }
    }
}

impl BootstrapEventLogger {
    fn from_medium_launcher_environment() -> Self {
        let log = std::env::var_os("DIG2BROWSER_WFP_BROKER_LOG")
            .filter(|path| !path.is_empty())
            .and_then(|path| {
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .ok()
            });
        Self { log }
    }

    fn report(&mut self, event: &str, detail: serde_json::Value) {
        self.append(&BootstrapEventRecord::new(event, detail));
    }

    fn append(&mut self, record: &BootstrapEventRecord) {
        let Some(log) = self.log.as_mut() else {
            return;
        };
        if let Ok(mut encoded) = serde_json::to_vec(record) {
            encoded.push(b'\n');
            let _ = log.write_all(&encoded);
        }
    }
}

fn report_shared_bootstrap_event(
    event_logger: &Arc<Mutex<BootstrapEventLogger>>,
    event: &str,
    detail: serde_json::Value,
) {
    if let Ok(mut event_logger) = event_logger.lock() {
        event_logger.report(event, detail);
    }
}

fn append_shared_bootstrap_record(
    event_logger: &Arc<Mutex<BootstrapEventLogger>>,
    record: &BootstrapEventRecord,
) {
    if let Ok(mut event_logger) = event_logger.lock() {
        event_logger.append(record);
    }
}

async fn report_elevated_bootstrap_event(
    bootstrap: &mut NamedPipeClient,
    event: &str,
    detail: serde_json::Value,
) {
    let _ = write_bootstrap_frame(
        bootstrap,
        &BootstrapBrokerFrame::Diagnostic {
            version: PROTOCOL_VERSION,
            record: BootstrapEventRecord::new(event, detail),
        },
    )
    .await;
}

async fn report_elevated_bootstrap_failure(
    bootstrap: &mut NamedPipeClient,
    error: &WindowsWfpBrokerBootstrapError,
) {
    let class = match error {
        WindowsWfpBrokerBootstrapError::InvalidConfiguration(_) => {
            "invalid_configuration"
        }
        WindowsWfpBrokerBootstrapError::Identity(_) => "identity",
        WindowsWfpBrokerBootstrapError::Launch(_) => "launch",
        WindowsWfpBrokerBootstrapError::Protocol(_) => "protocol",
        WindowsWfpBrokerBootstrapError::Pipe { .. } => "pipe",
        WindowsWfpBrokerBootstrapError::Timeout(_) => "timeout",
        WindowsWfpBrokerBootstrapError::Remote { .. } => "remote",
    };
    let rendered = match error {
        WindowsWfpBrokerBootstrapError::Pipe {
            operation,
            source,
        } => format!(
            "WFP broker bootstrap pipe {operation} failed: {source}"
        ),
        _ => error.to_string(),
    };
    let message = bounded_sanitized_bootstrap_text(
        &rendered,
        MAX_BOOTSTRAP_FAILURE_MESSAGE_BYTES,
    );
    let frame = BootstrapBrokerFrame::Failed {
        version: PROTOCOL_VERSION,
        class: class.to_owned(),
        message,
    };
    let _ = time::timeout(
        PREAUTH_REJECT_TIMEOUT,
        write_bootstrap_frame(bootstrap, &frame),
    )
    .await;
}

fn bounded_sanitized_bootstrap_text(value: &str, max_bytes: usize) -> String {
    let mut sanitized = String::with_capacity(value.len().min(max_bytes));
    let mut truncated = false;
    for character in value.chars() {
        let character = if character.is_control() {
            ' '
        } else {
            character
        };
        if sanitized.len() + character.len_utf8() > max_bytes {
            truncated = true;
            break;
        }
        sanitized.push(character);
    }
    if truncated {
        const SUFFIX: &str = " [truncated]";
        while sanitized.len() + SUFFIX.len() > max_bytes {
            if sanitized.pop().is_none() {
                break;
            }
        }
        if SUFFIX.len() <= max_bytes {
            sanitized.push_str(SUFFIX);
        }
    }
    sanitized
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
