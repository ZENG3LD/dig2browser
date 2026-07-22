use std::ffi::c_void;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;

use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, E_ACCESSDENIED, ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER,
    ERROR_NO_MORE_FILES, ERROR_SUCCESS, FILETIME, FWP_E_ALREADY_EXISTS, HANDLE,
    STILL_ACTIVE,
};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0,
    FwpmFilterCreateEnumHandle0, FwpmFilterDeleteByKey0,
    FwpmFilterDestroyEnumHandle0, FwpmFilterEnum0, FwpmFreeMemory0,
    FwpmGetAppIdFromFileName0, FwpmProviderAdd0, FwpmProviderGetByKey0,
    FwpmSubLayerAdd0, FwpmSubLayerGetByKey0,
    FwpmTransactionAbort0, FwpmTransactionBegin0, FwpmTransactionCommit0,
    FWPM_ACTION0, FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_FLAGS,
    FWPM_CONDITION_IP_PROTOCOL,
    FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT,
    FWPM_DISPLAY_DATA0, FWPM_FILTER0, FWPM_FILTER_CONDITION0,
    FWPM_FILTER_ENUM_TEMPLATE0, FWPM_FILTER_FLAGS,
    FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4,
    FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6, FWPM_PROVIDER0, FWPM_SESSION0,
    FWPM_SUBLAYER0, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT,
    FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE, FWP_CONDITION_FLAG_IS_RAW_ENDPOINT,
    FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0, FWP_MATCH_EQUAL,
    FWP_MATCH_FLAGS_ANY_SET, FWP_UINT16, FWP_UINT32, FWP_UINT8,
    FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK, FWP_V6_ADDR_AND_MASK,
    FWP_V6_ADDR_MASK, FWP_VALUE0, FWP_VALUE0_0,
};
use windows::Win32::Security::PSECURITY_DESCRIPTOR;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
    TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Rpc::{
    UuidCreate, RPC_C_AUTHN_WINNT, RPC_S_OK, RPC_S_UUID_LOCAL_ONLY,
};
use windows::Win32::System::Threading::{
    GetExitCodeProcess, GetProcessTimes, OpenProcess, QueryFullProcessImageNameW,
    PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};

const TCP_PROTOCOL: u8 = 6;
const PERMIT_WEIGHT: u8 = 15;
const BLOCK_WEIGHT: u8 = 14;
const SUBLAYER_WEIGHT: u16 = 0x8000;
const MAX_APP_IDS: usize = 64;
const LEASE_TAG_MAGIC: &[u8; 8] = b"D2BWFP\0\0";
const LEASE_TAG_SCHEMA: u16 = 1;
const LEASE_TAG_LEN: usize = 40;
const FILTERS_PER_APP_ID: usize = 5;
const ENUM_BATCH_SIZE: u32 = 128;
const PRODUCT_OBJECT_DATA: &[u8] = b"dig2browser-wfp-lease-store-v1";

// Product identities. These are intentionally stable across broker processes.
const PRODUCT_PROVIDER_KEY: GUID =
    GUID::from_u128(0x90a2b981_50ae_4c93_b398_8778c9865d4e);
const PRODUCT_SUBLAYER_KEY: GUID =
    GUID::from_u128(0x26683698_5cf8_437c_9bf1_725c9dcf5a33);

/// Owns a fail-closed WFP egress policy scoped to station-owned executable paths.
///
/// `Drop` deliberately closes only the local engine handle. The non-dynamic WFP
/// filters remain fail-closed until explicit close or identity-safe reconciliation.
pub struct WindowsContainmentGuard {
    engine: Option<WfpEngine>,
    app_id_count: usize,
}

/// Holds an exclusive WFP transaction while one identity-bound runtime mirror
/// is removed. This prevents another broker from installing product filters
/// for the same App IDs between the protected/live check and filesystem
/// deletion.
#[must_use = "the cleanup guard must remain alive until mirror removal completes"]
pub struct WindowsContainmentMirrorCleanupGuard {
    _transaction: WfpTransaction,
    _engine: WfpEngine,
}

impl WindowsContainmentGuard {
    /// Installs a lease owned by the exact incarnation of `peer_pid`.
    pub fn install_paths_for_peer(
        executable_paths: &[PathBuf],
        proxy: SocketAddr,
        peer: WindowsContainmentPeerIdentity,
    ) -> Result<Self, WindowsContainmentError> {
        validate_path_count(executable_paths.len())?;
        let policy = ProxyPolicy::new(proxy)?;
        let mut app_ids = executable_paths
            .iter()
            .map(|path| OwnedAppId::from_path(path))
            .collect::<Result<Vec<_>, _>>()?;
        app_ids.sort_by(|left, right| left.bytes.cmp(&right.bytes));
        app_ids.dedup_by(|left, right| left.bytes == right.bytes);
        let app_id_count = app_ids.len();
        let engine = WfpEngine::install(&app_ids, &policy, peer)?;
        Ok(Self {
            engine: Some(engine),
            app_id_count,
        })
    }

    pub fn app_id_count(&self) -> usize {
        self.app_id_count
    }

    /// Transactionally removes every complete product lease whose exact owner
    /// incarnation is dead and whose App IDs have no matching live process.
    /// Live, unrelated, and unverifiable leases remain fail-closed.
    pub fn reconcile_stale_leases(
    ) -> Result<WindowsContainmentReconcileReport, WindowsContainmentError> {
        let mut engine = WfpEngine::open(0)?;
        let mut transaction = WfpTransaction::begin(engine.handle)?;
        ensure_provider(engine.handle)?;
        ensure_sublayer(engine.handle)?;
        let existing = enumerate_product_filters(engine.handle)?;
        let groups = validate_lease_groups(existing)?;
        let report = reconcile_overlaps(engine.handle, &groups, &BTreeSet::new())?;
        transaction.commit()?;
        engine.close_handle()?;
        Ok(report)
    }

    /// Returns a transaction guard only when none of the executable App IDs is
    /// referenced by a retained product lease and no matching process is live.
    pub fn guard_stale_mirror_cleanup(
        executable_paths: &[PathBuf],
    ) -> Result<Option<WindowsContainmentMirrorCleanupGuard>, WindowsContainmentError> {
        validate_path_count(executable_paths.len())?;
        let target_app_ids = executable_paths
            .iter()
            .map(|path| OwnedAppId::from_path(path).map(|app_id| app_id.bytes.to_vec()))
            .collect::<Result<BTreeSet<_>, _>>()?;
        let engine = WfpEngine::open(target_app_ids.len())?;
        let transaction = WfpTransaction::begin(engine.handle)?;
        let groups = validate_lease_groups(enumerate_product_filters(engine.handle)?)?;
        let protected = groups.iter().any(|group| {
            group
                .app_ids
                .iter()
                .any(|app_id| target_app_ids.contains(app_id))
        });
        let app_state = if protected {
            MatchingAppState::Unverifiable
        } else {
            matching_app_process_state(&target_app_ids)
        };
        match mirror_cleanup_decision(protected, app_state) {
            MirrorCleanupDecision::Retain => Ok(None),
            MirrorCleanupDecision::Cleanup => {
                Ok(Some(WindowsContainmentMirrorCleanupGuard {
                    _transaction: transaction,
                    _engine: engine,
                }))
            }
            MirrorCleanupDecision::RetainUnverifiable => {
                Err(WindowsContainmentError::UnverifiableMirrorProcesses)
            }
        }
    }

    /// Transactionally removes only this lease's filters.
    pub fn close(mut self) -> Result<(), WindowsContainmentError> {
        if let Some(engine) = self.engine.take() {
            engine.close()?;
        }
        Ok(())
    }

}

impl Drop for WindowsContainmentGuard {
    fn drop(&mut self) {
        if let Some(engine) = self.engine.take() {
            drop(engine);
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WindowsContainmentReconcileReport {
    pub removed_leases: usize,
    pub removed_filters: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum WindowsContainmentError {
    #[error("containment requires between 1 and {MAX_APP_IDS} executable paths")]
    InvalidExecutableCount,
    #[error("containment proxy must use a loopback address and a nonzero port")]
    InvalidProxy,
    #[error("browser executable path contains an embedded NUL")]
    InvalidBrowserPath,
    #[error("Windows returned an invalid WFP application ID")]
    InvalidAppId,
    #[error("peer process {pid} is not alive or cannot be identified exactly")]
    InvalidPeerProcess { pid: u32 },
    #[error("live containment lease owned by peer process {pid} overlaps requested executable paths")]
    LiveLeaseConflict { pid: u32 },
    #[error("containment lease owner process {pid} cannot be verified; policy was retained")]
    UnverifiableLeaseOwner { pid: u32 },
    #[error("runtime mirror process inventory cannot be verified; mirror was retained")]
    UnverifiableMirrorProcesses,
    #[error("existing dig2browser WFP lease store is malformed: {reason}")]
    MalformedLeaseStore { reason: &'static str },
    #[error("Windows denied access while performing {operation}")]
    AccessDenied { operation: &'static str },
    #[error("Windows operation {operation} failed with code 0x{code:08x}")]
    WindowsApi {
        operation: &'static str,
        code: u32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpFamily {
    V4,
    V6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PolicyAction {
    Permit,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PolicyLayer {
    Connect,
    RawEndpointAssignment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FilterSpec {
    family: IpFamily,
    layer: PolicyLayer,
    action: PolicyAction,
    endpoint: Option<SocketAddr>,
    weight: u8,
    clear_action_right: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProxyPolicy {
    filters: Vec<FilterSpec>,
}

impl ProxyPolicy {
    fn new(proxy: SocketAddr) -> Result<Self, WindowsContainmentError> {
        if !proxy.ip().is_loopback() || proxy.port() == 0 {
            return Err(WindowsContainmentError::InvalidProxy);
        }
        let proxy_family = family(proxy.ip());
        let other_family = match proxy_family {
            IpFamily::V4 => IpFamily::V6,
            IpFamily::V6 => IpFamily::V4,
        };
        Ok(Self {
            filters: vec![
                FilterSpec {
                    family: proxy_family,
                    layer: PolicyLayer::Connect,
                    action: PolicyAction::Permit,
                    endpoint: Some(proxy),
                    weight: PERMIT_WEIGHT,
                    clear_action_right: false,
                },
                FilterSpec {
                    family: proxy_family,
                    layer: PolicyLayer::Connect,
                    action: PolicyAction::Block,
                    endpoint: None,
                    weight: BLOCK_WEIGHT,
                    clear_action_right: true,
                },
                FilterSpec {
                    family: other_family,
                    layer: PolicyLayer::Connect,
                    action: PolicyAction::Block,
                    endpoint: None,
                    weight: BLOCK_WEIGHT,
                    clear_action_right: true,
                },
                FilterSpec {
                    family: IpFamily::V4,
                    layer: PolicyLayer::RawEndpointAssignment,
                    action: PolicyAction::Block,
                    endpoint: None,
                    weight: BLOCK_WEIGHT,
                    clear_action_right: true,
                },
                FilterSpec {
                    family: IpFamily::V6,
                    layer: PolicyLayer::RawEndpointAssignment,
                    action: PolicyAction::Block,
                    endpoint: None,
                    weight: BLOCK_WEIGHT,
                    clear_action_right: true,
                },
            ],
        })
    }
}

fn family(address: IpAddr) -> IpFamily {
    match address {
        IpAddr::V4(_) => IpFamily::V4,
        IpAddr::V6(_) => IpFamily::V6,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OwnedAppId {
    bytes: Box<[u8]>,
}

impl OwnedAppId {
    fn from_path(path: &Path) -> Result<Self, WindowsContainmentError> {
        let wide = nul_terminated_path(path)?;
        let mut raw = ptr::null_mut::<FWP_BYTE_BLOB>();
        let status = unsafe {
            FwpmGetAppIdFromFileName0(PCWSTR(wide.as_ptr()), &mut raw)
        };
        let allocation = WfpAllocation::new(raw);
        status_result(status, "FwpmGetAppIdFromFileName0")?;
        if raw.is_null() {
            return Err(WindowsContainmentError::InvalidAppId);
        }
        let app_id = unsafe { &*raw };
        if app_id.size == 0 || app_id.data.is_null() {
            return Err(WindowsContainmentError::InvalidAppId);
        }
        let bytes = unsafe {
            std::slice::from_raw_parts(app_id.data, app_id.size as usize)
        }
        .to_vec()
        .into_boxed_slice();
        drop(allocation);
        Ok(Self { bytes })
    }

    fn blob(&mut self) -> FWP_BYTE_BLOB {
        FWP_BYTE_BLOB {
            size: self.bytes.len() as u32,
            data: self.bytes.as_mut_ptr(),
        }
    }

    #[cfg(test)]
    fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

struct WfpAllocation {
    raw: *mut c_void,
}

impl WfpAllocation {
    fn new(raw: *mut FWP_BYTE_BLOB) -> Self {
        Self {
            raw: raw.cast::<c_void>(),
        }
    }
}

impl Drop for WfpAllocation {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe {
                FwpmFreeMemory0(&mut self.raw);
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowsContainmentPeerIdentity {
    pid: u32,
    creation_filetime: u64,
}

impl WindowsContainmentPeerIdentity {
    /// Captures identity from the broker's already-held peer process object.
    /// Holding that handle pins the process incarnation across PID reuse.
    pub(crate) fn capture_from_handle(
        pid: u32,
        handle: HANDLE,
    ) -> Result<Self, WindowsContainmentError> {
        let identity = process_identity_from_handle(handle, pid)?;
        let mut exit_code = 0u32;
        unsafe { GetExitCodeProcess(handle, &mut exit_code) }
            .map_err(|error| windows_core_error("GetExitCodeProcess", error))?;
        if exit_code != STILL_ACTIVE.0 as u32 {
            return Err(WindowsContainmentError::InvalidPeerProcess { pid });
        }
        Ok(identity)
    }

}

struct OwnedProcessHandle(HANDLE);

impl Drop for OwnedProcessHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

fn process_identity_from_handle(
    handle: HANDLE,
    pid: u32,
) -> Result<WindowsContainmentPeerIdentity, WindowsContainmentError> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    unsafe {
        GetProcessTimes(
            handle,
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    }
    .map_err(|error| windows_core_error("GetProcessTimes", error))?;
    let creation_filetime =
        ((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64;
    if creation_filetime == 0 {
        return Err(WindowsContainmentError::InvalidPeerProcess { pid });
    }
    Ok(WindowsContainmentPeerIdentity {
        pid,
        creation_filetime,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LeaseTag {
    lease_id: u128,
    peer: WindowsContainmentPeerIdentity,
}

impl LeaseTag {
    fn new(peer: WindowsContainmentPeerIdentity) -> Result<Self, WindowsContainmentError> {
        Ok(Self {
            lease_id: new_guid("UuidCreate(lease)")?.to_u128(),
            peer,
        })
    }

    fn encode(self) -> [u8; LEASE_TAG_LEN] {
        let mut bytes = [0u8; LEASE_TAG_LEN];
        bytes[..8].copy_from_slice(LEASE_TAG_MAGIC);
        bytes[8..10].copy_from_slice(&LEASE_TAG_SCHEMA.to_le_bytes());
        bytes[10..12].copy_from_slice(&0u16.to_le_bytes());
        bytes[12..28].copy_from_slice(&self.lease_id.to_le_bytes());
        bytes[28..32].copy_from_slice(&self.peer.pid.to_le_bytes());
        bytes[32..40].copy_from_slice(&self.peer.creation_filetime.to_le_bytes());
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, WindowsContainmentError> {
        if bytes.len() != LEASE_TAG_LEN {
            return Err(malformed("lease tag length is invalid"));
        }
        if &bytes[..8] != LEASE_TAG_MAGIC {
            return Err(malformed("lease tag magic is invalid"));
        }
        if u16::from_le_bytes([bytes[8], bytes[9]]) != LEASE_TAG_SCHEMA {
            return Err(malformed("lease tag schema is unsupported"));
        }
        if bytes[10] != 0 || bytes[11] != 0 {
            return Err(malformed("lease tag reserved bits are nonzero"));
        }
        let lease_id = u128::from_le_bytes(bytes[12..28].try_into().expect("tag lease slice"));
        let pid = u32::from_le_bytes(bytes[28..32].try_into().expect("tag pid slice"));
        let creation_filetime =
            u64::from_le_bytes(bytes[32..40].try_into().expect("tag time slice"));
        if lease_id == 0 || pid == 0 || creation_filetime == 0 {
            return Err(malformed("lease tag contains a zero identity field"));
        }
        Ok(Self {
            lease_id,
            peer: WindowsContainmentPeerIdentity {
                pid,
                creation_filetime,
            },
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum StoredFilterRole {
    Permit(SocketAddr),
    ConnectBlockV4,
    ConnectBlockV6,
    RawBlockV4,
    RawBlockV6,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredFilter {
    key: GUID,
    tag: LeaseTag,
    app_id: Vec<u8>,
    role: StoredFilterRole,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LeaseGroup {
    tag: LeaseTag,
    filter_keys: Vec<GUID>,
    app_ids: BTreeSet<Vec<u8>>,
}

fn validate_lease_groups(
    filters: Vec<StoredFilter>,
) -> Result<Vec<LeaseGroup>, WindowsContainmentError> {
    let mut grouped = BTreeMap::<u128, Vec<StoredFilter>>::new();
    let mut all_keys = BTreeSet::new();
    for filter in filters {
        if filter.key == GUID::from_u128(0) || !all_keys.insert(filter.key.to_u128()) {
            return Err(malformed("filter keys are zero or duplicated"));
        }
        grouped.entry(filter.tag.lease_id).or_default().push(filter);
    }

    let mut leases = Vec::with_capacity(grouped.len());
    for filters in grouped.into_values() {
        let tag = filters.first().expect("nonempty lease group").tag;
        if filters.iter().any(|filter| filter.tag != tag) {
            return Err(malformed("lease group has inconsistent peer identity"));
        }
        let mut roles = BTreeMap::<Vec<u8>, BTreeSet<StoredFilterRole>>::new();
        let mut permit = None;
        for filter in &filters {
            if filter.app_id.is_empty() {
                return Err(malformed("lease filter has an empty App ID"));
            }
            if app_id_basename(&filter.app_id).is_none() {
                return Err(malformed("lease filter App ID cannot be inventoried"));
            }
            if let StoredFilterRole::Permit(endpoint) = filter.role {
                if permit.replace(endpoint).is_some_and(|old| old != endpoint) {
                    return Err(malformed("lease group has inconsistent proxy endpoints"));
                }
            }
            if !roles
                .entry(filter.app_id.clone())
                .or_default()
                .insert(filter.role.clone())
            {
                return Err(malformed("lease group contains a duplicate filter role"));
            }
        }
        for app_roles in roles.values() {
            if app_roles.len() != FILTERS_PER_APP_ID
                || !app_roles.contains(&StoredFilterRole::ConnectBlockV4)
                || !app_roles.contains(&StoredFilterRole::ConnectBlockV6)
                || !app_roles.contains(&StoredFilterRole::RawBlockV4)
                || !app_roles.contains(&StoredFilterRole::RawBlockV6)
                || app_roles.iter().filter(|role| matches!(role, StoredFilterRole::Permit(_))).count() != 1
            {
                return Err(malformed("lease group does not contain one complete policy per App ID"));
            }
        }
        if permit.is_none() || filters.len() != roles.len() * FILTERS_PER_APP_ID {
            return Err(malformed("lease group filter cardinality is invalid"));
        }
        leases.push(LeaseGroup {
            tag,
            filter_keys: filters.iter().map(|filter| filter.key).collect(),
            app_ids: roles.into_keys().collect(),
        });
    }
    Ok(leases)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerState {
    Alive,
    Dead,
    Unverifiable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MatchingAppState {
    None,
    Live,
    Unverifiable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReconciliationDecision {
    Retain,
    Remove,
    Conflict,
    RetainUnverifiable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MirrorCleanupDecision {
    Retain,
    Cleanup,
    RetainUnverifiable,
}

fn mirror_cleanup_decision(
    protected: bool,
    app_state: MatchingAppState,
) -> MirrorCleanupDecision {
    if protected || app_state == MatchingAppState::Live {
        MirrorCleanupDecision::Retain
    } else if app_state == MatchingAppState::None {
        MirrorCleanupDecision::Cleanup
    } else {
        MirrorCleanupDecision::RetainUnverifiable
    }
}

fn reconciliation_decision(
    overlaps: bool,
    peer_state: PeerState,
    app_state: MatchingAppState,
) -> ReconciliationDecision {
    match (peer_state, app_state) {
        (PeerState::Dead, MatchingAppState::None) => ReconciliationDecision::Remove,
        (PeerState::Alive, _) | (_, MatchingAppState::Live) => {
            if overlaps {
                ReconciliationDecision::Conflict
            } else {
                ReconciliationDecision::Retain
            }
        }
        (PeerState::Unverifiable, _) | (_, MatchingAppState::Unverifiable) => {
            if overlaps {
                ReconciliationDecision::RetainUnverifiable
            } else {
                ReconciliationDecision::Retain
            }
        }
    }
}

fn query_peer_state(peer: WindowsContainmentPeerIdentity) -> PeerState {
    let handle = match unsafe {
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, peer.pid)
    } {
        Ok(handle) => OwnedProcessHandle(handle),
        Err(error) => {
            let code = error.code().0 as u32;
            let invalid_parameter = 0x80070000u32 | ERROR_INVALID_PARAMETER.0;
            return if code == invalid_parameter {
                PeerState::Dead
            } else {
                PeerState::Unverifiable
            };
        }
    };
    let actual = match process_identity_from_handle(handle.0, peer.pid) {
        Ok(identity) => identity,
        Err(_) => return PeerState::Unverifiable,
    };
    if actual.creation_filetime != peer.creation_filetime {
        return PeerState::Dead;
    }
    let mut exit_code = 0u32;
    if unsafe { GetExitCodeProcess(handle.0, &mut exit_code) }.is_err() {
        return PeerState::Unverifiable;
    }
    if exit_code == STILL_ACTIVE.0 as u32 {
        PeerState::Alive
    } else {
        PeerState::Dead
    }
}

fn matching_app_process_state(app_ids: &BTreeSet<Vec<u8>>) -> MatchingAppState {
    let mut basenames = BTreeSet::new();
    for app_id in app_ids {
        match app_id_basename(app_id) {
            Some(name) => {
                basenames.insert(name);
            }
            None => return MatchingAppState::Unverifiable,
        }
    }
    let snapshot = match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) } {
        Ok(handle) => OwnedProcessHandle(handle),
        Err(_) => return MatchingAppState::Unverifiable,
    };
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    match unsafe { Process32FirstW(snapshot.0, &mut entry) } {
        Ok(()) => {}
        Err(error) if is_win32_error(&error, ERROR_NO_MORE_FILES.0) => {
            return MatchingAppState::None;
        }
        Err(_) => return MatchingAppState::Unverifiable,
    }
    loop {
        let executable_name = match nul_terminated_utf16(&entry.szExeFile) {
            Some(name) => name.to_lowercase(),
            None => return MatchingAppState::Unverifiable,
        };
        if basenames.contains(&executable_name) {
            match process_matches_app_id(entry.th32ProcessID, app_ids) {
                MatchingAppState::None => {}
                state => return state,
            }
        }
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        match unsafe { Process32NextW(snapshot.0, &mut entry) } {
            Ok(()) => {}
            Err(error) if is_win32_error(&error, ERROR_NO_MORE_FILES.0) => break,
            Err(_) => return MatchingAppState::Unverifiable,
        }
    }
    MatchingAppState::None
}

fn process_matches_app_id(
    pid: u32,
    app_ids: &BTreeSet<Vec<u8>>,
) -> MatchingAppState {
    let handle = match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
        Ok(handle) => OwnedProcessHandle(handle),
        Err(error) if is_win32_error(&error, ERROR_INVALID_PARAMETER.0) => {
            return MatchingAppState::None;
        }
        Err(_) => return MatchingAppState::Unverifiable,
    };
    let mut exit_code = 0u32;
    if unsafe { GetExitCodeProcess(handle.0, &mut exit_code) }.is_err() {
        return MatchingAppState::Unverifiable;
    }
    if exit_code != STILL_ACTIVE.0 as u32 {
        return MatchingAppState::None;
    }
    let mut path_buffer = vec![0u16; 32_768];
    let mut path_len = path_buffer.len() as u32;
    if unsafe {
        QueryFullProcessImageNameW(
            handle.0,
            PROCESS_NAME_WIN32,
            PWSTR(path_buffer.as_mut_ptr()),
            &mut path_len,
        )
    }
    .is_err()
    {
        return MatchingAppState::Unverifiable;
    }
    if path_len == 0 || path_len as usize > path_buffer.len() {
        return MatchingAppState::Unverifiable;
    }
    path_buffer.truncate(path_len as usize);
    let path = match String::from_utf16(&path_buffer) {
        Ok(path) => PathBuf::from(path),
        Err(_) => return MatchingAppState::Unverifiable,
    };
    match OwnedAppId::from_path(&path) {
        Ok(app_id) if app_ids.contains(app_id.bytes.as_ref()) => MatchingAppState::Live,
        Ok(_) => MatchingAppState::None,
        Err(_) => MatchingAppState::Unverifiable,
    }
}

fn app_id_basename(app_id: &[u8]) -> Option<String> {
    if app_id.is_empty() || app_id.len() & 1 != 0 {
        return None;
    }
    let mut wide = Vec::with_capacity(app_id.len() / 2);
    for pair in app_id.chunks_exact(2) {
        let value = u16::from_le_bytes([pair[0], pair[1]]);
        if value == 0 {
            break;
        }
        wide.push(value);
    }
    let path = String::from_utf16(&wide).ok()?;
    Path::new(&path)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .map(str::to_lowercase)
}

fn nul_terminated_utf16(value: &[u16]) -> Option<String> {
    let len = value.iter().position(|character| *character == 0)?;
    String::from_utf16(&value[..len]).ok()
}

fn is_win32_error(error: &windows::core::Error, code: u32) -> bool {
    error.code().0 as u32 == (0x80070000u32 | code)
}

fn malformed(reason: &'static str) -> WindowsContainmentError {
    WindowsContainmentError::MalformedLeaseStore { reason }
}

struct WfpEngine {
    handle: HANDLE,
    lease_filter_keys: Vec<GUID>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LeaseTermination {
    ExplicitClose,
    UnexpectedDrop,
}

fn lease_deletion_keys(
    termination: LeaseTermination,
    keys: &[GUID],
) -> &[GUID] {
    match termination {
        LeaseTermination::ExplicitClose => keys,
        LeaseTermination::UnexpectedDrop => &[],
    }
}

impl WfpEngine {
    fn install(
        app_ids: &[OwnedAppId],
        policy: &ProxyPolicy,
        peer: WindowsContainmentPeerIdentity,
    ) -> Result<Self, WindowsContainmentError> {
        let mut engine = Self::open(app_ids.len())?;
        let tag = LeaseTag::new(peer)?;
        let target_app_ids = app_ids
            .iter()
            .map(|app_id| app_id.bytes.to_vec())
            .collect::<BTreeSet<_>>();
        let mut transaction = WfpTransaction::begin(engine.handle)?;
        ensure_provider(engine.handle)?;
        ensure_sublayer(engine.handle)?;
        let existing = enumerate_product_filters(engine.handle)?;
        let groups = validate_lease_groups(existing)?;
        let _ = reconcile_overlaps(engine.handle, &groups, &target_app_ids)?;
        for (app_index, app_id) in app_ids.iter().enumerate() {
            for (filter_index, filter) in policy.filters.iter().enumerate() {
                let key = add_filter(
                    engine.handle,
                    app_id,
                    *filter,
                    app_index * policy.filters.len() + filter_index,
                    tag,
                )?;
                engine.lease_filter_keys.push(key);
            }
        }
        transaction.commit()?;
        Ok(engine)
    }

    fn open(app_id_count: usize) -> Result<Self, WindowsContainmentError> {
        let session_key = new_guid("UuidCreate(session)")?;
        let mut session_name = wide(&format!(
            "dig2browser containment: {} executable App IDs",
            app_id_count
        ));
        let session = FWPM_SESSION0 {
            sessionKey: session_key,
            displayData: display_data(&mut session_name),
            ..Default::default()
        };
        let mut handle = HANDLE::default();
        let status = unsafe {
            FwpmEngineOpen0(
                PCWSTR::null(),
                RPC_C_AUTHN_WINNT,
                None,
                Some(&session),
                &mut handle,
            )
        };
        status_result(status, "FwpmEngineOpen0")?;
        Ok(Self {
            handle,
            lease_filter_keys: Vec::new(),
        })
    }

    fn close(mut self) -> Result<(), WindowsContainmentError> {
        if !self.lease_filter_keys.is_empty() {
            let mut transaction = WfpTransaction::begin(self.handle)?;
            for key in lease_deletion_keys(
                LeaseTermination::ExplicitClose,
                &self.lease_filter_keys,
            ) {
                status_result(
                    unsafe { FwpmFilterDeleteByKey0(self.handle, key) },
                    "FwpmFilterDeleteByKey0(close lease)",
                )?;
            }
            transaction.commit()?;
            self.lease_filter_keys.clear();
        }
        self.close_handle()
    }

    fn close_handle(&mut self) -> Result<(), WindowsContainmentError> {
        let handle = std::mem::take(&mut self.handle);
        if handle.is_invalid() {
            return Ok(());
        }
        status_result(unsafe { FwpmEngineClose0(handle) }, "FwpmEngineClose0")
    }
}

fn reconcile_overlaps(
    engine: HANDLE,
    groups: &[LeaseGroup],
    target_app_ids: &BTreeSet<Vec<u8>>,
) -> Result<WindowsContainmentReconcileReport, WindowsContainmentError> {
    let mut report = WindowsContainmentReconcileReport::default();
    for group in groups {
        let overlaps = group.app_ids.iter().any(|app_id| target_app_ids.contains(app_id));
        let peer_state = query_peer_state(group.tag.peer);
        let app_state = if peer_state == PeerState::Dead {
            matching_app_process_state(&group.app_ids)
        } else {
            MatchingAppState::Unverifiable
        };
        match reconciliation_decision(overlaps, peer_state, app_state) {
            ReconciliationDecision::Retain => {}
            ReconciliationDecision::Remove => {
                for key in &group.filter_keys {
                    status_result(
                        unsafe { FwpmFilterDeleteByKey0(engine, key) },
                        "FwpmFilterDeleteByKey0(reconcile lease)",
                    )?;
                }
                report.removed_leases += 1;
                report.removed_filters += group.filter_keys.len();
            }
            ReconciliationDecision::Conflict => {
                return Err(WindowsContainmentError::LiveLeaseConflict {
                    pid: group.tag.peer.pid,
                });
            }
            ReconciliationDecision::RetainUnverifiable => {
                return Err(WindowsContainmentError::UnverifiableLeaseOwner {
                    pid: group.tag.peer.pid,
                });
            }
        }
    }
    Ok(report)
}

fn validate_path_count(count: usize) -> Result<(), WindowsContainmentError> {
    if count == 0 || count > MAX_APP_IDS {
        Err(WindowsContainmentError::InvalidExecutableCount)
    } else {
        Ok(())
    }
}

impl Drop for WfpEngine {
    fn drop(&mut self) {
        debug_assert!(lease_deletion_keys(
            LeaseTermination::UnexpectedDrop,
            &self.lease_filter_keys,
        )
        .is_empty());
        if !self.handle.is_invalid() {
            unsafe {
                let _ = FwpmEngineClose0(self.handle);
            }
            self.handle = HANDLE::default();
        }
    }
}

struct WfpTransaction {
    engine: HANDLE,
    active: bool,
}

impl WfpTransaction {
    fn begin(engine: HANDLE) -> Result<Self, WindowsContainmentError> {
        status_result(
            unsafe { FwpmTransactionBegin0(engine, 0) },
            "FwpmTransactionBegin0",
        )?;
        Ok(Self {
            engine,
            active: true,
        })
    }

    fn commit(&mut self) -> Result<(), WindowsContainmentError> {
        status_result(
            unsafe { FwpmTransactionCommit0(self.engine) },
            "FwpmTransactionCommit0",
        )?;
        self.active = false;
        Ok(())
    }
}

impl Drop for WfpTransaction {
    fn drop(&mut self) {
        if self.active {
            unsafe {
                let _ = FwpmTransactionAbort0(self.engine);
            }
        }
    }
}

fn ensure_provider(engine: HANDLE) -> Result<(), WindowsContainmentError> {
    let mut name = wide("dig2browser executable containment provider");
    let mut product_data = PRODUCT_OBJECT_DATA.to_vec();
    let provider = FWPM_PROVIDER0 {
        providerKey: PRODUCT_PROVIDER_KEY,
        displayData: display_data(&mut name),
        providerData: FWP_BYTE_BLOB {
            size: product_data.len() as u32,
            data: product_data.as_mut_ptr(),
        },
        ..Default::default()
    };
    let status = unsafe {
        FwpmProviderAdd0(engine, &provider, PSECURITY_DESCRIPTOR::default())
    };
    if status == FWP_E_ALREADY_EXISTS.0 as u32 {
        validate_existing_provider(engine)
    } else {
        status_result(status, "FwpmProviderAdd0")
    }
}

fn ensure_sublayer(engine: HANDLE) -> Result<(), WindowsContainmentError> {
    let mut name = wide("dig2browser executable containment sublayer");
    let mut product_data = PRODUCT_OBJECT_DATA.to_vec();
    let sublayer = FWPM_SUBLAYER0 {
        subLayerKey: PRODUCT_SUBLAYER_KEY,
        displayData: display_data(&mut name),
        providerKey: &PRODUCT_PROVIDER_KEY as *const GUID as *mut GUID,
        providerData: FWP_BYTE_BLOB {
            size: product_data.len() as u32,
            data: product_data.as_mut_ptr(),
        },
        weight: SUBLAYER_WEIGHT,
        ..Default::default()
    };
    let status = unsafe {
        FwpmSubLayerAdd0(engine, &sublayer, PSECURITY_DESCRIPTOR::default())
    };
    if status == FWP_E_ALREADY_EXISTS.0 as u32 {
        validate_existing_sublayer(engine)
    } else {
        status_result(status, "FwpmSubLayerAdd0")
    }
}

fn validate_existing_provider(engine: HANDLE) -> Result<(), WindowsContainmentError> {
    let mut raw = ptr::null_mut::<FWPM_PROVIDER0>();
    status_result(
        unsafe { FwpmProviderGetByKey0(engine, &PRODUCT_PROVIDER_KEY, &mut raw) },
        "FwpmProviderGetByKey0",
    )?;
    let allocation = WfpRawAllocation::new(raw.cast::<c_void>());
    if raw.is_null() {
        return Err(malformed("product provider lookup returned null"));
    }
    let provider = unsafe { &*raw };
    let data = unsafe { copy_blob(&provider.providerData, PRODUCT_OBJECT_DATA.len()) }?;
    if provider.providerKey != PRODUCT_PROVIDER_KEY
        || provider.flags != 0
        || data.as_slice() != PRODUCT_OBJECT_DATA
    {
        return Err(malformed("stable product provider identity is invalid"));
    }
    drop(allocation);
    Ok(())
}

fn validate_existing_sublayer(engine: HANDLE) -> Result<(), WindowsContainmentError> {
    let mut raw = ptr::null_mut::<FWPM_SUBLAYER0>();
    status_result(
        unsafe { FwpmSubLayerGetByKey0(engine, &PRODUCT_SUBLAYER_KEY, &mut raw) },
        "FwpmSubLayerGetByKey0",
    )?;
    let allocation = WfpRawAllocation::new(raw.cast::<c_void>());
    if raw.is_null() {
        return Err(malformed("product sublayer lookup returned null"));
    }
    let sublayer = unsafe { &*raw };
    let data = unsafe { copy_blob(&sublayer.providerData, PRODUCT_OBJECT_DATA.len()) }?;
    if sublayer.subLayerKey != PRODUCT_SUBLAYER_KEY
        || sublayer.providerKey.is_null()
        || unsafe { *sublayer.providerKey } != PRODUCT_PROVIDER_KEY
        || sublayer.flags != 0
        || sublayer.weight != SUBLAYER_WEIGHT
        || data.as_slice() != PRODUCT_OBJECT_DATA
    {
        return Err(malformed("stable product sublayer identity is invalid"));
    }
    drop(allocation);
    Ok(())
}

fn add_filter(
    engine: HANDLE,
    app_id: &OwnedAppId,
    spec: FilterSpec,
    index: usize,
    tag: LeaseTag,
) -> Result<GUID, WindowsContainmentError> {
    let mut app_id = app_id.clone();
    let mut app_id_blob = app_id.blob();
    let mut conditions = vec![app_id_condition(&mut app_id_blob)];
    let mut v4_storage = None;
    let mut v6_storage = None;
    if let Some(endpoint) = spec.endpoint {
        conditions.push(u8_condition(FWPM_CONDITION_IP_PROTOCOL, TCP_PROTOCOL));
        match endpoint.ip() {
            IpAddr::V4(address) => {
                v4_storage = Some(Box::new(FWP_V4_ADDR_AND_MASK {
                    addr: u32::from(address),
                    mask: u32::MAX,
                }));
                conditions.push(v4_address_condition(
                    v4_storage.as_mut().expect("IPv4 storage"),
                ));
            }
            IpAddr::V6(address) => {
                v6_storage = Some(Box::new(FWP_V6_ADDR_AND_MASK {
                    addr: address.octets(),
                    prefixLength: 128,
                }));
                conditions.push(v6_address_condition(
                    v6_storage.as_mut().expect("IPv6 storage"),
                ));
            }
        }
        conditions.push(u16_condition(
            FWPM_CONDITION_IP_REMOTE_PORT,
            endpoint.port(),
        ));
    }
    if spec.layer == PolicyLayer::RawEndpointAssignment {
        conditions.push(raw_endpoint_condition());
    }

    let filter_key = new_guid("UuidCreate(filter)")?;
    let mut name = wide(&format!("dig2browser executable containment filter {index}"));
    let flags = if spec.clear_action_right {
        FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT
    } else {
        FWPM_FILTER_FLAGS::default()
    };
    let mut tag_bytes = tag.encode();
    let filter = FWPM_FILTER0 {
        filterKey: filter_key,
        displayData: display_data(&mut name),
        flags,
        providerKey: &PRODUCT_PROVIDER_KEY as *const GUID as *mut GUID,
        providerData: FWP_BYTE_BLOB {
            size: tag_bytes.len() as u32,
            data: tag_bytes.as_mut_ptr(),
        },
        layerKey: match (spec.layer, spec.family) {
            (PolicyLayer::Connect, IpFamily::V4) => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            (PolicyLayer::Connect, IpFamily::V6) => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            (PolicyLayer::RawEndpointAssignment, IpFamily::V4) => {
                FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4
            }
            (PolicyLayer::RawEndpointAssignment, IpFamily::V6) => {
                FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6
            }
        },
        subLayerKey: PRODUCT_SUBLAYER_KEY,
        weight: FWP_VALUE0 {
            r#type: FWP_UINT8,
            Anonymous: FWP_VALUE0_0 { uint8: spec.weight },
        },
        numFilterConditions: conditions.len() as u32,
        filterCondition: conditions.as_mut_ptr(),
        action: FWPM_ACTION0 {
            r#type: match spec.action {
                PolicyAction::Permit => FWP_ACTION_PERMIT,
                PolicyAction::Block => FWP_ACTION_BLOCK,
            },
            ..Default::default()
        },
        ..Default::default()
    };
    status_result(
        unsafe {
            FwpmFilterAdd0(
                engine,
                &filter,
                PSECURITY_DESCRIPTOR::default(),
                None,
            )
        },
        "FwpmFilterAdd0",
    )?;
    drop(v4_storage);
    drop(v6_storage);
    drop(app_id);
    Ok(filter_key)
}

struct FilterEnumHandle {
    engine: HANDLE,
    handle: HANDLE,
}

impl Drop for FilterEnumHandle {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            unsafe {
                let _ = FwpmFilterDestroyEnumHandle0(self.engine, self.handle);
            }
        }
    }
}

fn enumerate_product_filters(
    engine: HANDLE,
) -> Result<Vec<StoredFilter>, WindowsContainmentError> {
    let mut provider_key = PRODUCT_PROVIDER_KEY;
    let template = FWPM_FILTER_ENUM_TEMPLATE0 {
        providerKey: &mut provider_key,
        ..Default::default()
    };
    let mut enum_handle = HANDLE::default();
    status_result(
        unsafe {
            FwpmFilterCreateEnumHandle0(engine, Some(&template), &mut enum_handle)
        },
        "FwpmFilterCreateEnumHandle0",
    )?;
    let enum_handle = FilterEnumHandle {
        engine,
        handle: enum_handle,
    };
    let mut filters = Vec::new();
    loop {
        let mut entries = ptr::null_mut::<*mut FWPM_FILTER0>();
        let mut returned = 0u32;
        status_result(
            unsafe {
                FwpmFilterEnum0(
                    engine,
                    enum_handle.handle,
                    ENUM_BATCH_SIZE,
                    &mut entries,
                    &mut returned,
                )
            },
            "FwpmFilterEnum0",
        )?;
        let allocation = WfpRawAllocation::new(entries.cast::<c_void>());
        if returned == 0 {
            break;
        }
        if entries.is_null() {
            return Err(malformed("WFP returned a null filter enumeration"));
        }
        let batch = unsafe { std::slice::from_raw_parts(entries, returned as usize) };
        for entry in batch {
            if entry.is_null() {
                return Err(malformed("WFP returned a null product filter"));
            }
            filters.push(unsafe { stored_filter_from_wfp(&**entry) }?);
        }
        drop(allocation);
    }
    Ok(filters)
}

struct WfpRawAllocation {
    raw: *mut c_void,
}

impl WfpRawAllocation {
    fn new(raw: *mut c_void) -> Self {
        Self { raw }
    }
}

impl Drop for WfpRawAllocation {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe {
                FwpmFreeMemory0(&mut self.raw);
            }
        }
    }
}

unsafe fn stored_filter_from_wfp(
    filter: &FWPM_FILTER0,
) -> Result<StoredFilter, WindowsContainmentError> {
    if filter.providerKey.is_null() || *filter.providerKey != PRODUCT_PROVIDER_KEY {
        return Err(malformed("enumerated filter has the wrong provider"));
    }
    if filter.subLayerKey != PRODUCT_SUBLAYER_KEY {
        return Err(malformed("product filter has the wrong sublayer"));
    }
    let tag_bytes = copy_blob(&filter.providerData, LEASE_TAG_LEN)?;
    let tag = LeaseTag::decode(&tag_bytes)?;
    if filter.numFilterConditions == 0
        || filter.numFilterConditions > 8
        || filter.filterCondition.is_null()
    {
        return Err(malformed("product filter condition count is invalid"));
    }
    let conditions = std::slice::from_raw_parts(
        filter.filterCondition,
        filter.numFilterConditions as usize,
    );
    let app_id = extract_app_id(conditions)?;
    let role = classify_stored_filter(filter, conditions)?;
    Ok(StoredFilter {
        key: filter.filterKey,
        tag,
        app_id,
        role,
    })
}

unsafe fn copy_blob(
    blob: &FWP_BYTE_BLOB,
    maximum: usize,
) -> Result<Vec<u8>, WindowsContainmentError> {
    let size = blob.size as usize;
    if size == 0 || size > maximum || blob.data.is_null() {
        return Err(malformed("product filter byte blob is invalid"));
    }
    Ok(std::slice::from_raw_parts(blob.data, size).to_vec())
}

unsafe fn extract_app_id(
    conditions: &[FWPM_FILTER_CONDITION0],
) -> Result<Vec<u8>, WindowsContainmentError> {
    let mut app_id = None;
    for condition in conditions {
        if condition.fieldKey == FWPM_CONDITION_ALE_APP_ID {
            if app_id.is_some()
                || condition.matchType != FWP_MATCH_EQUAL
                || condition.conditionValue.r#type != FWP_BYTE_BLOB_TYPE
            {
                return Err(malformed("product filter App ID condition is invalid"));
            }
            let blob = condition.conditionValue.Anonymous.byteBlob;
            if blob.is_null() {
                return Err(malformed("product filter App ID is null"));
            }
            app_id = Some(copy_blob(&*blob, 1024 * 1024)?);
        }
    }
    app_id.ok_or_else(|| malformed("product filter has no App ID condition"))
}

unsafe fn classify_stored_filter(
    filter: &FWPM_FILTER0,
    conditions: &[FWPM_FILTER_CONDITION0],
) -> Result<StoredFilterRole, WindowsContainmentError> {
    if filter.weight.r#type != FWP_UINT8 {
        return Err(malformed("product filter weight type is invalid"));
    }
    let weight = filter.weight.Anonymous.uint8;
    let is_connect_v4 = filter.layerKey == FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    let is_connect_v6 = filter.layerKey == FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    let is_raw_v4 = filter.layerKey == FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4;
    let is_raw_v6 = filter.layerKey == FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6;

    if filter.action.r#type == FWP_ACTION_PERMIT {
        if (!is_connect_v4 && !is_connect_v6)
            || filter.flags != FWPM_FILTER_FLAGS::default()
            || weight != PERMIT_WEIGHT
            || conditions.len() != 4
        {
            return Err(malformed("product permit filter shape is invalid"));
        }
        return permit_endpoint(conditions, is_connect_v4)
            .map(StoredFilterRole::Permit);
    }

    if filter.action.r#type != FWP_ACTION_BLOCK
        || filter.flags != FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT
        || weight != BLOCK_WEIGHT
    {
        return Err(malformed("product block filter shape is invalid"));
    }
    if is_connect_v4 || is_connect_v6 {
        if conditions.len() != 1 {
            return Err(malformed("product connect block has extra conditions"));
        }
        return Ok(if is_connect_v4 {
            StoredFilterRole::ConnectBlockV4
        } else {
            StoredFilterRole::ConnectBlockV6
        });
    }
    if is_raw_v4 || is_raw_v6 {
        if conditions.len() != 2 || !has_exact_raw_flag(conditions) {
            return Err(malformed("product raw block condition is invalid"));
        }
        return Ok(if is_raw_v4 {
            StoredFilterRole::RawBlockV4
        } else {
            StoredFilterRole::RawBlockV6
        });
    }
    Err(malformed("product filter layer is invalid"))
}

unsafe fn permit_endpoint(
    conditions: &[FWPM_FILTER_CONDITION0],
    v4: bool,
) -> Result<SocketAddr, WindowsContainmentError> {
    let mut protocol = None;
    let mut port = None;
    let mut address = None;
    for condition in conditions {
        if condition.fieldKey == FWPM_CONDITION_ALE_APP_ID {
            continue;
        }
        if condition.matchType != FWP_MATCH_EQUAL {
            return Err(malformed("product permit condition is not an exact match"));
        }
        if condition.fieldKey == FWPM_CONDITION_IP_PROTOCOL
            && condition.conditionValue.r#type == FWP_UINT8
        {
            protocol = Some(condition.conditionValue.Anonymous.uint8);
        } else if condition.fieldKey == FWPM_CONDITION_IP_REMOTE_PORT
            && condition.conditionValue.r#type == FWP_UINT16
        {
            port = Some(condition.conditionValue.Anonymous.uint16);
        } else if condition.fieldKey == FWPM_CONDITION_IP_REMOTE_ADDRESS {
            address = Some(if v4 {
                if condition.conditionValue.r#type != FWP_V4_ADDR_MASK {
                    return Err(malformed("product permit IPv4 address type is invalid"));
                }
                let value = condition.conditionValue.Anonymous.v4AddrMask;
                if value.is_null() || (*value).mask != u32::MAX {
                    return Err(malformed("product permit IPv4 mask is invalid"));
                }
                IpAddr::V4(Ipv4Addr::from((*value).addr))
            } else {
                if condition.conditionValue.r#type != FWP_V6_ADDR_MASK {
                    return Err(malformed("product permit IPv6 address type is invalid"));
                }
                let value = condition.conditionValue.Anonymous.v6AddrMask;
                if value.is_null() || (*value).prefixLength != 128 {
                    return Err(malformed("product permit IPv6 prefix is invalid"));
                }
                IpAddr::V6(Ipv6Addr::from((*value).addr))
            });
        } else {
            return Err(malformed("product permit contains an unknown condition"));
        }
    }
    let port = port.filter(|port| *port != 0)
        .ok_or_else(|| malformed("product permit port is invalid"))?;
    if protocol != Some(TCP_PROTOCOL) {
        return Err(malformed("product permit protocol is invalid"));
    }
    let address = address
        .filter(IpAddr::is_loopback)
        .ok_or_else(|| malformed("product permit address is not loopback"))?;
    Ok(SocketAddr::new(address, port))
}

unsafe fn has_exact_raw_flag(conditions: &[FWPM_FILTER_CONDITION0]) -> bool {
    conditions.iter().any(|condition| {
        condition.fieldKey == FWPM_CONDITION_FLAGS
            && condition.matchType == FWP_MATCH_FLAGS_ANY_SET
            && condition.conditionValue.r#type == FWP_UINT32
            && condition.conditionValue.Anonymous.uint32
                == FWP_CONDITION_FLAG_IS_RAW_ENDPOINT
    })
}

fn app_id_condition(app_id: &mut FWP_BYTE_BLOB) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_ALE_APP_ID,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_BYTE_BLOB_TYPE,
            Anonymous: FWP_CONDITION_VALUE0_0 { byteBlob: app_id },
        },
    }
}

fn u8_condition(field: GUID, value: u8) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_UINT8,
            Anonymous: FWP_CONDITION_VALUE0_0 { uint8: value },
        },
    }
}

fn u16_condition(field: GUID, value: u16) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_UINT16,
            Anonymous: FWP_CONDITION_VALUE0_0 { uint16: value },
        },
    }
}

fn raw_endpoint_condition() -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_FLAGS,
        matchType: FWP_MATCH_FLAGS_ANY_SET,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_UINT32,
            Anonymous: FWP_CONDITION_VALUE0_0 {
                uint32: FWP_CONDITION_FLAG_IS_RAW_ENDPOINT,
            },
        },
    }
}

fn v4_address_condition(value: &mut FWP_V4_ADDR_AND_MASK) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_V4_ADDR_MASK,
            Anonymous: FWP_CONDITION_VALUE0_0 { v4AddrMask: value },
        },
    }
}

fn v6_address_condition(value: &mut FWP_V6_ADDR_AND_MASK) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_V6_ADDR_MASK,
            Anonymous: FWP_CONDITION_VALUE0_0 { v6AddrMask: value },
        },
    }
}

fn new_guid(operation: &'static str) -> Result<GUID, WindowsContainmentError> {
    let mut guid = GUID::from_u128(0);
    let status = unsafe { UuidCreate(&mut guid) };
    if status == RPC_S_OK || status == RPC_S_UUID_LOCAL_ONLY {
        Ok(guid)
    } else {
        Err(WindowsContainmentError::WindowsApi {
            operation,
            code: status.0 as u32,
        })
    }
}

fn nul_terminated_path(path: &Path) -> Result<Vec<u16>, WindowsContainmentError> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(WindowsContainmentError::InvalidBrowserPath);
    }
    wide.push(0);
    Ok(wide)
}

fn wide(value: &str) -> Vec<u16> {
    value
        .chars()
        .map(|character| if character == '\0' { '\u{fffd}' } else { character })
        .collect::<String>()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect()
}

fn display_data(name: &mut [u16]) -> FWPM_DISPLAY_DATA0 {
    FWPM_DISPLAY_DATA0 {
        name: PWSTR(name.as_mut_ptr()),
        description: PWSTR::null(),
    }
}

fn status_result(
    code: u32,
    operation: &'static str,
) -> Result<(), WindowsContainmentError> {
    if code == ERROR_SUCCESS.0 {
        Ok(())
    } else {
        Err(status_error(operation, code))
    }
}

fn windows_core_error(
    operation: &'static str,
    error: windows::core::Error,
) -> WindowsContainmentError {
    status_error(operation, error.code().0 as u32)
}

fn status_error(operation: &'static str, code: u32) -> WindowsContainmentError {
    if code == ERROR_ACCESS_DENIED.0 || code == E_ACCESSDENIED.0 as u32 {
        WindowsContainmentError::AccessDenied { operation }
    } else {
        WindowsContainmentError::WindowsApi { operation, code }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_tag(lease_id: u128, pid: u32) -> LeaseTag {
        LeaseTag {
            lease_id,
            peer: WindowsContainmentPeerIdentity {
                pid,
                creation_filetime: 123_456_789,
            },
        }
    }

    fn test_app_id(path: &str) -> Vec<u8> {
        path.encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(u16::to_le_bytes)
            .collect()
    }

    fn complete_stored_filters(tag: LeaseTag, app_ids: &[Vec<u8>]) -> Vec<StoredFilter> {
        let endpoint = "127.0.0.1:18080".parse().expect("endpoint");
        let roles = [
            StoredFilterRole::Permit(endpoint),
            StoredFilterRole::ConnectBlockV4,
            StoredFilterRole::ConnectBlockV6,
            StoredFilterRole::RawBlockV4,
            StoredFilterRole::RawBlockV6,
        ];
        let mut next_key = 1u128;
        let mut filters = Vec::new();
        for app_id in app_ids {
            for role in &roles {
                filters.push(StoredFilter {
                    key: GUID::from_u128(next_key),
                    tag,
                    app_id: app_id.clone(),
                    role: role.clone(),
                });
                next_key += 1;
            }
        }
        filters
    }

    #[test]
    fn lease_tag_codec_is_strict_and_round_trips_peer_incarnation() {
        let tag = test_tag(0x112233445566778899aabbccddeeff00, 4242);
        let encoded = tag.encode();
        assert_eq!(LeaseTag::decode(&encoded).expect("decode tag"), tag);

        let mut wrong_schema = encoded;
        wrong_schema[8..10].copy_from_slice(&2u16.to_le_bytes());
        assert!(LeaseTag::decode(&wrong_schema).is_err());

        let mut reserved = encoded;
        reserved[10] = 1;
        assert!(LeaseTag::decode(&reserved).is_err());
        assert!(LeaseTag::decode(&encoded[..encoded.len() - 1]).is_err());
    }

    #[test]
    fn lease_group_validation_requires_complete_consistent_policy() {
        let tag = test_tag(17, 101);
        let filters = complete_stored_filters(
            tag,
            &[
                test_app_id(r"\device\harddiskvolume1\app-a.exe"),
                test_app_id(r"\device\harddiskvolume1\app-b.exe"),
            ],
        );
        let groups = validate_lease_groups(filters.clone()).expect("valid group");
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].filter_keys.len(), 10);
        assert_eq!(groups[0].app_ids.len(), 2);

        let mut incomplete = filters.clone();
        incomplete.pop();
        assert!(validate_lease_groups(incomplete).is_err());

        let mut mixed_peer = filters;
        mixed_peer[0].tag.peer.creation_filetime += 1;
        assert!(validate_lease_groups(mixed_peer).is_err());
    }

    #[test]
    fn reconciliation_removes_dead_inactive_leases_across_runtime_versions() {
        assert_eq!(
            reconciliation_decision(
                false,
                PeerState::Dead,
                MatchingAppState::None,
            ),
            ReconciliationDecision::Remove
        );
        assert_eq!(
            reconciliation_decision(
                false,
                PeerState::Alive,
                MatchingAppState::None,
            ),
            ReconciliationDecision::Retain
        );
        assert_eq!(
            reconciliation_decision(
                false,
                PeerState::Dead,
                MatchingAppState::Live,
            ),
            ReconciliationDecision::Retain
        );
        assert_eq!(
            reconciliation_decision(
                false,
                PeerState::Unverifiable,
                MatchingAppState::None,
            ),
            ReconciliationDecision::Retain
        );
        assert_eq!(
            reconciliation_decision(
                true,
                PeerState::Alive,
                MatchingAppState::None,
            ),
            ReconciliationDecision::Conflict
        );
        assert_eq!(
            reconciliation_decision(
                true,
                PeerState::Dead,
                MatchingAppState::None,
            ),
            ReconciliationDecision::Remove
        );
        assert_eq!(
            reconciliation_decision(
                true,
                PeerState::Unverifiable,
                MatchingAppState::None,
            ),
            ReconciliationDecision::RetainUnverifiable
        );
        assert_eq!(
            reconciliation_decision(
                true,
                PeerState::Dead,
                MatchingAppState::Live,
            ),
            ReconciliationDecision::Conflict
        );
        assert_eq!(
            reconciliation_decision(
                true,
                PeerState::Dead,
                MatchingAppState::Unverifiable,
            ),
            ReconciliationDecision::RetainUnverifiable
        );
    }

    #[test]
    fn mirror_cleanup_requires_no_retained_filter_and_no_live_process() {
        assert_eq!(
            mirror_cleanup_decision(true, MatchingAppState::None),
            MirrorCleanupDecision::Retain
        );
        assert_eq!(
            mirror_cleanup_decision(false, MatchingAppState::Live),
            MirrorCleanupDecision::Retain
        );
        assert_eq!(
            mirror_cleanup_decision(false, MatchingAppState::None),
            MirrorCleanupDecision::Cleanup
        );
        assert_eq!(
            mirror_cleanup_decision(false, MatchingAppState::Unverifiable),
            MirrorCleanupDecision::RetainUnverifiable
        );
    }

    #[test]
    fn explicit_close_deletes_only_lease_keys_while_drop_retains_them() {
        let keys = [GUID::from_u128(1), GUID::from_u128(2)];
        assert_eq!(
            lease_deletion_keys(LeaseTermination::ExplicitClose, &keys),
            &keys
        );
        assert!(lease_deletion_keys(LeaseTermination::UnexpectedDrop, &keys).is_empty());
    }

    #[test]
    fn executable_app_id_set_is_bounded_and_nonempty() {
        assert!(matches!(
            validate_path_count(0),
            Err(WindowsContainmentError::InvalidExecutableCount)
        ));
        assert!(validate_path_count(1).is_ok());
        assert!(validate_path_count(MAX_APP_IDS).is_ok());
        assert!(matches!(
            validate_path_count(MAX_APP_IDS + 1),
            Err(WindowsContainmentError::InvalidExecutableCount)
        ));
    }

    #[test]
    fn proxy_validation_requires_loopback_and_nonzero_port() {
        assert!(matches!(
            ProxyPolicy::new("192.0.2.1:8080".parse().expect("address")),
            Err(WindowsContainmentError::InvalidProxy)
        ));
        assert!(matches!(
            ProxyPolicy::new("127.0.0.1:0".parse().expect("address")),
            Err(WindowsContainmentError::InvalidProxy)
        ));
        assert!(ProxyPolicy::new("[::1]:8080".parse().expect("address")).is_ok());
    }

    #[test]
    fn v4_policy_permits_only_tcp_proxy_then_blocks_both_families() {
        let endpoint = "127.0.0.1:18080".parse().expect("address");
        let policy = ProxyPolicy::new(endpoint).expect("valid policy");
        assert_eq!(policy.filters.len(), 5);
        assert_eq!(
            policy.filters[0],
            FilterSpec {
                family: IpFamily::V4,
                layer: PolicyLayer::Connect,
                action: PolicyAction::Permit,
                endpoint: Some(endpoint),
                weight: PERMIT_WEIGHT,
                clear_action_right: false,
            }
        );
        assert_eq!(policy.filters[1].family, IpFamily::V4);
        assert_eq!(policy.filters[2].family, IpFamily::V6);
        assert!(policy.filters[1..3].iter().all(|filter| {
            filter.action == PolicyAction::Block
                && filter.layer == PolicyLayer::Connect
                && filter.endpoint.is_none()
                && filter.weight < PERMIT_WEIGHT
                && filter.clear_action_right
        }));
        assert_eq!(policy.filters[3].family, IpFamily::V4);
        assert_eq!(policy.filters[4].family, IpFamily::V6);
        assert!(policy.filters[3..].iter().all(|filter| {
            filter.action == PolicyAction::Block
                && filter.layer == PolicyLayer::RawEndpointAssignment
                && filter.endpoint.is_none()
                && filter.weight < PERMIT_WEIGHT
                && filter.clear_action_right
        }));
    }

    #[test]
    fn v6_policy_is_symmetric() {
        let endpoint = "[::1]:18080".parse().expect("address");
        let policy = ProxyPolicy::new(endpoint).expect("valid policy");
        assert_eq!(policy.filters[0].family, IpFamily::V6);
        assert_eq!(policy.filters[0].endpoint, Some(endpoint));
        assert_eq!(policy.filters[1].family, IpFamily::V6);
        assert_eq!(policy.filters[2].family, IpFamily::V4);
        assert_eq!(policy.filters[3].family, IpFamily::V4);
        assert_eq!(policy.filters[4].family, IpFamily::V6);
    }

    #[test]
    fn endpoint_permit_has_strictly_higher_weight_than_all_blocks() {
        let policy = ProxyPolicy::new("127.0.0.1:18080".parse().expect("address"))
            .expect("valid policy");
        let permit = policy
            .filters
            .iter()
            .find(|filter| filter.action == PolicyAction::Permit)
            .expect("permit filter");
        assert!(policy.filters.iter().filter(|filter| {
            filter.action == PolicyAction::Block
        }).all(|filter| {
            filter.weight < permit.weight && filter.clear_action_right
        }));
    }

    #[test]
    fn app_id_condition_is_an_exact_byte_blob_match() {
        let mut app_id = OwnedAppId {
            bytes: vec![1, 2, 3, 4].into_boxed_slice(),
        };
        let mut blob = app_id.blob();
        let blob_ptr = &mut blob as *mut FWP_BYTE_BLOB;
        let condition = app_id_condition(&mut blob);
        assert_eq!(condition.fieldKey, FWPM_CONDITION_ALE_APP_ID);
        assert_eq!(condition.matchType, FWP_MATCH_EQUAL);
        assert_eq!(condition.conditionValue.r#type, FWP_BYTE_BLOB_TYPE);
        assert_eq!(
            unsafe { condition.conditionValue.Anonymous.byteBlob },
            blob_ptr
        );
    }

    #[test]
    fn raw_endpoint_condition_matches_any_raw_flag_bit() {
        let condition = raw_endpoint_condition();
        assert_eq!(condition.fieldKey, FWPM_CONDITION_FLAGS);
        assert_eq!(condition.matchType, FWP_MATCH_FLAGS_ANY_SET);
        assert_eq!(condition.conditionValue.r#type, FWP_UINT32);
        assert_eq!(
            unsafe { condition.conditionValue.Anonymous.uint32 },
            FWP_CONDITION_FLAG_IS_RAW_ENDPOINT
        );
    }

    #[test]
    #[ignore = "requires installed user-local Chrome and an NTFS volume supporting hardlinks"]
    fn wfp_app_id_distinguishes_station_owned_hardlink_path_e2e() {
        let browser = dig2browser::detect::detect_browser(
            dig2browser::detect::BrowserPreference::ChromeOnly,
        )
        .expect("detect installed Chrome");
        let root = std::env::temp_dir().join(format!(
            "dig2browser-wfp-appid-e2e-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).expect("create hardlink test root");
        let alias = root.join("station-browser.exe");
        std::fs::hard_link(&browser.path, &alias).expect("create browser hardlink");

        let original_id = OwnedAppId::from_path(&browser.path)
            .expect("query original WFP app ID");
        let alias_id = OwnedAppId::from_path(&alias)
            .expect("query hardlink WFP app ID");
        let remove_result = std::fs::remove_dir_all(&root);
        assert_ne!(
            original_id.bytes(),
            alias_id.bytes(),
            "WFP canonicalized two hardlink paths to one app ID"
        );
        remove_result.expect("remove hardlink test root");
    }
}
