//! Stable, station-owned Chromium runtime mirrors for Windows process policy.

use std::collections::BTreeMap;
use std::ffi::{c_void, OsStr, OsString};
use std::fs::File;
#[cfg(test)]
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{FromRawHandle, RawHandle};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Once;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, DuplicateHandle, GetLastError, LocalFree, HANDLE, HLOCAL,
    DUPLICATE_SAME_ACCESS, ERROR_INVALID_PARAMETER, ERROR_NO_MORE_FILES, ERROR_SUCCESS,
    FILETIME, STILL_ACTIVE,
};
use windows::Win32::Security::Authorization::{
    BuildTrusteeWithSidW, ConvertStringSidToSidW, GetSecurityInfo, SetEntriesInAclW,
    SetSecurityInfo, EXPLICIT_ACCESS_W, SE_FILE_OBJECT, SET_ACCESS,
};
use windows::Win32::Security::{
    ACE_FLAGS, ACL, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SUB_CONTAINERS_AND_OBJECTS_INHERIT,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, GetFileInformationByHandle, GetFileInformationByHandleEx,
    GetFinalPathNameByHandleW, SetFileInformationByHandle,
    BY_HANDLE_FILE_INFORMATION,
    FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_DISPOSITION_FLAG_DELETE,
    FILE_DISPOSITION_FLAG_POSIX_SEMANTICS, FILE_DISPOSITION_INFO_EX,
    FILE_DISPOSITION_INFO_EX_FLAGS,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAGS_AND_ATTRIBUTES,
    FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_ID_BOTH_DIR_INFO, FILE_LIST_DIRECTORY,
    FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_DELETE,
    FILE_SHARE_MODE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_DATA,
    FileDispositionInfoEx, FileIdBothDirectoryInfo, FileIdBothDirectoryRestartInfo,
    GETFINALPATHNAMEBYHANDLE_FLAGS, OPEN_EXISTING, READ_CONTROL, VOLUME_NAME_DOS,
    WRITE_DAC,
};
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetExitCodeProcess, GetProcessTimes, OpenProcess,
    PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::UI::Shell::{
    FOLDERID_LocalAppData, KF_FLAG_DEFAULT, SHGetKnownFolderPath,
};

use crate::detect::{BrowserBinary, BrowserKind};

const MIRROR_SCHEMA: u32 = 1;
const READY_MANIFEST: &str = ".dig2browser-runtime-ready.json";
const MAX_MANIFEST_BYTES: u64 = 4096;
const MAX_MIRROR_EXECUTABLES: usize = 64;
const MAX_MIRROR_ENTRIES: usize = 16_384;
const MAX_MIRROR_DEPTH: usize = 64;
const STAGING_ATTEMPTS: u64 = 64;
/// Versioned staging-name schema marker. A staging directory's creator
/// identity (PID + OS-reported process creation FILETIME) is only trusted
/// for reconciliation when the name carries this exact marker; anything
/// else (including pre-this-schema staging directories, which only embed a
/// wall-clock nonce rather than a verifiable creator identity) is retained
/// untouched.
const STAGING_NAME_SCHEMA: &str = "v2";
const DELETE_ACCESS: u32 = 0x0001_0000;
const SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;
const FILE_OPEN: u32 = 1;
const FILE_CREATE: u32 = 2;
const FILE_OPEN_IF: u32 = 3;
const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
const FILE_OPEN_REPARSE_POINT_OPTION: u32 = 0x0020_0000;
const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
const FILE_LINK_INFORMATION_CLASS: u32 = 11;
const FILE_RENAME_INFORMATION_CLASS: u32 = 10;
const STATUS_ACCESS_DENIED: i32 = 0xC000_0022u32 as i32;
const STATUS_SHARING_VIOLATION: i32 = 0xC000_0043u32 as i32;
const HRESULT_SHARING_VIOLATION: i32 = 0x8007_0020u32 as i32;
const DIRECTORY_BUFFER_BYTES: usize = 64 * 1024;
const REMOVAL_RETRY_INTERVAL: Duration = Duration::from_millis(50);

static STAGING_SEQUENCE: AtomicU64 = AtomicU64::new(0);
/// Runs orphaned staging reconciliation at most once per process. The
/// production catalog is process-lifetime-stable
/// (`%LOCALAPPDATA%\dig2browser\runtime-mirrors`), so a single best-effort
/// sweep per station/broker incarnation is sufficient to reclaim staging
/// directories left behind by a previous, now-dead incarnation without
/// repeating catalog enumeration on every materialization call.
static STAGING_RECONCILE_ONCE: Once = Once::new();

/// Opaque identity for the station-owned profiles scope associated with a
/// runtime mirror.
///
/// The digest can cross the elevated broker boundary without granting the
/// caller control over a privileged destination path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct WindowsRuntimeMirrorScope([u8; 32]);

impl WindowsRuntimeMirrorScope {
    pub fn for_profiles_root(profiles_root: &Path) -> Self {
        let mut digest = Sha256::new();
        digest.update(b"dig2browser-runtime-mirror-scope-v1\0");
        hash_path_into(&mut digest, profiles_root);
        Self(digest.finalize().into())
    }

    pub fn as_hex(&self) -> String {
        hex_digest(self.0)
    }
}

impl FromStr for WindowsRuntimeMirrorScope {
    type Err = WindowsRuntimeMirrorScopeParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 64
            || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
            || value.bytes().any(|byte| byte.is_ascii_uppercase())
        {
            return Err(WindowsRuntimeMirrorScopeParseError);
        }
        let mut bytes = [0u8; 32];
        for (index, slot) in bytes.iter_mut().enumerate() {
            let offset = index * 2;
            *slot = u8::from_str_radix(&value[offset..offset + 2], 16)
                .map_err(|_| WindowsRuntimeMirrorScopeParseError)?;
        }
        Ok(Self(bytes))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("runtime mirror scope must be exactly 64 lowercase hexadecimal characters")]
pub struct WindowsRuntimeMirrorScopeParseError;

/// Compact outcome of a bounded explicit runtime-mirror removal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowsRuntimeMirrorRemovalReport {
    /// Number of complete validation-and-removal attempts.
    pub attempts: u32,
    /// Total retry delay requested from the async runtime.
    pub waited: Duration,
}

/// A stable Chromium executable path owned by the local dig2browser station.
///
/// The mirror intentionally survives `Drop`: WFP policy and later station
/// sessions need the same ALE_APP_ID path. Stale mirrors require an explicit,
/// separately governed cleanup policy.
#[derive(Debug)]
pub struct WindowsBrowserRuntimeMirror {
    browser_binary: BrowserBinary,
    root: PathBuf,
    executable_paths: Vec<PathBuf>,
    identity: FileIdentity,
    materialization_mode: MaterializationMode,
    _lease_locks: Vec<OwnedHandle>,
}

impl WindowsBrowserRuntimeMirror {
    /// Returns every exact, ready direct-child mirror in the fixed station
    /// catalog. Returned values are identity-bound removal tokens; callers must
    /// decide liveness before invoking `remove`.
    pub fn inventory() -> Result<Vec<Self>, WindowsRuntimeMirrorError> {
        let base = existing_mirror_base()?;
        let mut mirrors = Vec::new();
        for entry in enumerate_directory(&base.handle, &base.path)? {
            let name = entry.name.to_string_lossy();
            if name.len() != 64
                || !name.bytes().all(|byte| byte.is_ascii_hexdigit())
                || name.bytes().any(|byte| byte.is_ascii_uppercase())
            {
                continue;
            }
            let root = base.path.join(&entry.name);
            if entry.attributes & FILE_ATTRIBUTE_DIRECTORY.0 == 0 {
                return Err(invalid_existing(&root, "catalog content key is not a directory"));
            }
            let mirror = inspect_ready_mirror_under_catalog(&root, &base)?;
            if mirror.identity.index != entry.file_id {
                return Err(invalid_existing(&root, "catalog mirror changed during inventory"));
            }
            mirrors.push(mirror);
        }
        mirrors.sort_by(|left, right| {
            normalized_windows_path(&left.root).cmp(&normalized_windows_path(&right.root))
        });
        Ok(mirrors)
    }

    /// Materializes or reuses a content-keyed mirror of the browser's complete
    /// `Application` directory. Protected installations fall back from hard
    /// links to handle-relative copies.
    pub fn materialize(
        source: &BrowserBinary,
        profiles_root: &Path,
    ) -> Result<Self, WindowsRuntimeMirrorError> {
        let profiles = open_verified_directory(
            profiles_root,
            FILE_READ_ATTRIBUTES.0,
            "open profiles root",
        )?;
        let scope = WindowsRuntimeMirrorScope::for_profiles_root(&profiles.path);
        Self::materialize_scoped(source, scope)
    }

    /// Materializes or reuses a content-keyed mirror for an opaque station
    /// scope. The destination is always selected from the fixed local catalog.
    pub fn materialize_scoped(
        source: &BrowserBinary,
        scope: WindowsRuntimeMirrorScope,
    ) -> Result<Self, WindowsRuntimeMirrorError> {
        if source.kind == BrowserKind::Firefox {
            return Err(WindowsRuntimeMirrorError::UnsupportedBrowser {
                kind: source.kind,
            });
        }

        let requested_source_root = source.path.parent().ok_or_else(|| {
            WindowsRuntimeMirrorError::InvalidSourceLayout {
                path: source.path.clone(),
            }
        })?;
        let source_root = open_verified_directory(
            requested_source_root,
            FILE_LIST_DIRECTORY.0 | FILE_READ_ATTRIBUTES.0,
            "open source browser root",
        )?;
        let binary_name = source.path.file_name().ok_or_else(|| {
            WindowsRuntimeMirrorError::InvalidSourceLayout {
                path: source.path.clone(),
            }
        })?;
        // FileLinkInformation does not require DELETE access on the source.
        // Keep protected Program Files installations read-only while the
        // destination remains handle-relative under our owned catalog.
        let binary_handle = open_relative(
            &source_root.handle,
            binary_name,
            FILE_READ_ATTRIBUTES.0,
            false,
            FILE_OPEN,
            &source.path,
            "open source browser",
        )?;
        let binary_information = handle_information(
            &binary_handle,
            &source.path,
            "read source browser identity",
        )?;
        ensure_handle_type(&binary_information, false, &source.path)?;
        let binary_identity = handle_identity(&binary_handle, &source.path)?;
        let canonical_source = source_root.path.join(binary_name);
        let binary_relative = PathBuf::from(binary_name);
        validate_relative_path(&binary_relative)?;

        let base = ensure_mirror_base()?;
        let source_volume = handle_identity(&source_root.handle, &source_root.path)?.volume;
        let mirror_volume = handle_identity(&base.handle, &base.path)?.volume;
        if source_volume != mirror_volume {
            return Err(WindowsRuntimeMirrorError::DifferentVolume {
                source_root: source_root.path,
                mirror_base: base.path,
            });
        }

        let source_tree = collect_source_tree(source_root)?;
        let source_binary_entry = source_tree
            .iter()
            .find(|entry| entry.relative == binary_relative)
            .ok_or_else(|| WindowsRuntimeMirrorError::SourceChanged {
                path: canonical_source.clone(),
                reason: "source browser binary disappeared from the collected tree".to_owned(),
            })?;
        if source_binary_entry.identity != binary_identity {
            return Err(WindowsRuntimeMirrorError::SourceChanged {
                path: canonical_source,
                reason: format!(
                    "source browser identity changed (expected volume={:#010x}, file_id={:#018x}; actual volume={:#010x}, file_id={:#018x})",
                    binary_identity.volume,
                    binary_identity.index,
                    source_binary_entry.identity.volume,
                    source_binary_entry.identity.index,
                ),
            });
        }
        let source_fingerprint = fingerprint_source_tree(&source_tree);
        // Version-resource APIs reopen by path and would reintroduce a source
        // traversal race. The handle-derived tree fingerprint already keys the
        // opened source tree layout and metadata.
        let version = None;
        let key = mirror_key(
            scope,
            &canonical_source,
            source.kind,
            version.as_deref(),
            &source_fingerprint,
        );
        let expected_manifest = ReadyManifest {
            schema: MIRROR_SCHEMA,
            key: key.clone(),
            source_fingerprint,
            browser_kind: browser_kind_name(source.kind).to_owned(),
            browser_version: version,
            binary_relative_hash: hash_path(&binary_relative),
            materialization_mode: MaterializationMode::LegacyUnknown,
        };
        let target = base.path.join(&key);

        if relative_exists(&base.handle, OsStr::new(&key), &target)? {
            return validate_ready_mirror(
                &target,
                &binary_relative,
                &expected_manifest,
                source.kind,
                true,
            );
        }

        let build_staging = |staging: OpenDirectory, mode: MaterializationMode| {
            let preparation = (|| {
                populate_staging(&source_tree, &staging, mode)?;
                let actual_fingerprint = fingerprint_open_source_tree(&source_tree)?;
                if actual_fingerprint != expected_manifest.source_fingerprint {
                    return Err(WindowsRuntimeMirrorError::SourceChanged {
                        path: requested_source_root.to_path_buf(),
                        reason: format!(
                            "opened source tree metadata changed (expected_sha256={}, actual_sha256={})",
                            expected_manifest.source_fingerprint,
                            actual_fingerprint,
                        ),
                    });
                }
                validate_source_tree_membership(&source_tree)?;
                let mut manifest = expected_manifest.clone();
                manifest.materialization_mode = mode;
                write_ready_manifest(&staging, &manifest)?;
                Ok(manifest)
            })();
            let manifest = match preparation {
                Ok(manifest) => manifest,
                Err(error) => return Err(cleanup_staging_after_error(&base, staging, error)),
            };
            publish_staging(
                &base,
                staging,
                &target,
                &binary_relative,
                &manifest,
                source.kind,
            )
        };

        let staging = create_staging_directory(&base, &key)?;
        match build_staging(staging, MaterializationMode::HardLinkV1) {
            Ok(mirror) => Ok(mirror),
            Err(error) if is_hard_link_policy_denial(&error) => {
                let copy_staging = create_staging_directory(&base, &key)?;
                build_staging(copy_staging, MaterializationMode::CopyV1)
            }
            Err(error) => Err(error),
        }
    }

    pub fn browser_binary(&self) -> &BrowserBinary {
        &self.browser_binary
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Opens an existing ready mirror without changing it.
    pub fn inspect(root: &Path) -> Result<Self, WindowsRuntimeMirrorError> {
        inspect_ready_mirror(root)
    }

    /// Every regular non-reparse-point executable in the published mirror.
    ///
    /// Paths are absolute, unique, and sorted by normalized Windows path.
    pub fn executable_paths(&self) -> &[PathBuf] {
        &self.executable_paths
    }

    /// Explicitly removes this ready mirror from the station-owned catalog.
    ///
    /// `Drop` remains non-destructive. Removal revalidates ownership, the
    /// readiness manifest, and the complete non-reparse tree before deleting
    /// entries without recursive traversal helpers.
    pub fn remove(self) -> Result<(), WindowsRuntimeMirrorError> {
        let inspected = Self::inspect(&self.root)?;
        if normalized_windows_path(&inspected.browser_binary.path)
            != normalized_windows_path(&self.browser_binary.path)
            || inspected.browser_binary.kind != self.browser_binary.kind
            || inspected.executable_paths != self.executable_paths
            || inspected.materialization_mode != self.materialization_mode
        {
            return Err(invalid_existing(
                &self.root,
                "runtime mirror changed before explicit removal",
            ));
        }
        if inspected.identity != self.identity {
            return Err(invalid_existing(
                &self.root,
                "runtime mirror identity changed before explicit removal",
            ));
        }
        let root = inspected.root.clone();
        let identity = inspected.identity;
        drop(inspected);
        drop(self);
        remove_validated_mirror_tree(&root, identity)
    }

    /// Explicitly removes this ready mirror, retrying bounded sharing conflicts.
    ///
    /// The mirror's lease handles are dropped before the first attempt. Every
    /// attempt then repeats the complete root, manifest, tree, and identity
    /// validation. Only sharing violations raised while acquiring the
    /// pre-mutation delete locks are retried; all other failures return
    /// immediately.
    pub async fn remove_with_retry(
        self,
        max_wait: Duration,
    ) -> Result<WindowsRuntimeMirrorRemovalReport, WindowsRuntimeMirrorError> {
        remove_runtime_mirror_with_retry(
            RuntimeMirrorRemovalToken::from_mirror(self),
            RuntimeMirrorCatalog::StationOwned,
            max_wait,
        )
        .await
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WindowsRuntimeMirrorError {
    #[error("browser kind {kind:?} cannot be materialized as a Chromium runtime mirror")]
    UnsupportedBrowser { kind: BrowserKind },
    #[error("source browser path has no Application parent: '{path}'", path = path.display())]
    InvalidSourceLayout { path: PathBuf },
    #[error("runtime mirror source contains a reparse point: '{path}'", path = path.display())]
    ReparsePoint { path: PathBuf },
    #[error("runtime mirror source entry is not a regular file or directory: '{path}'", path = path.display())]
    UnsupportedEntry { path: PathBuf },
    #[error("runtime mirror source uses the reserved readiness-manifest path: '{path}'", path = path.display())]
    ReservedEntry { path: PathBuf },
    #[error("runtime mirror path is not a safe relative path: '{path}'", path = path.display())]
    InvalidRelativePath { path: PathBuf },
    #[error("Windows LocalAppData known folder is unavailable")]
    LocalAppDataUnavailable(#[source] windows::core::Error),
    #[error("Windows LocalAppData known folder returned an invalid path")]
    LocalAppDataInvalid,
    #[error("runtime mirror base is on a different volume from source '{source_root}' (base '{mirror_base}')", source_root = source_root.display(), mirror_base = mirror_base.display())]
    DifferentVolume { source_root: PathBuf, mirror_base: PathBuf },
    #[error("existing runtime mirror is not an exact ready mirror at '{path}': {reason}", path = path.display())]
    ExistingMirrorInvalid { path: PathBuf, reason: String },
    #[error("source browser tree changed while its runtime mirror was being built at '{path}': {reason}", path = path.display())]
    SourceChanged { path: PathBuf, reason: String },
    #[error("runtime mirror manifest serialization failed")]
    Manifest(#[from] serde_json::Error),
    #[error("Windows operation '{operation}' failed for '{path}'", path = path.display())]
    Windows {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: windows::core::Error,
    },
    #[error("Windows native operation '{operation}' failed for '{path}' with NTSTATUS {status:#010x}", path = path.display())]
    WindowsNt {
        operation: &'static str,
        path: PathBuf,
        status: i32,
    },
    #[error("I/O operation '{operation}' failed for '{path}'", path = path.display())]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("runtime mirror build failed and staging cleanup also failed: build: {primary}; cleanup: {cleanup}")]
    BuildCleanup {
        primary: Box<WindowsRuntimeMirrorError>,
        cleanup: Box<WindowsRuntimeMirrorError>,
    },
    #[error("runtime mirror removal retry budget exhausted after {attempts} attempts and {waited:?} of retry delay: {source}")]
    RemovalRetryExhausted {
        attempts: u32,
        waited: Duration,
        #[source]
        source: Box<WindowsRuntimeMirrorError>,
    },
    #[error("runtime mirror removal blocking worker failed")]
    RemovalWorker(#[source] tokio::task::JoinError),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadyManifest {
    schema: u32,
    key: String,
    source_fingerprint: String,
    browser_kind: String,
    browser_version: Option<String>,
    binary_relative_hash: String,
    #[serde(default)]
    materialization_mode: MaterializationMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SourceEntryKind {
    Directory,
    File,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
enum MaterializationMode {
    #[default]
    LegacyUnknown,
    HardLinkV1,
    CopyV1,
}

#[derive(Debug)]
struct SourceEntry {
    source_path: PathBuf,
    relative: PathBuf,
    kind: SourceEntryKind,
    attributes: u32,
    size: u64,
    last_write_time: u64,
    identity: FileIdentity,
    handle: OwnedHandle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileIdentity {
    volume: u32,
    index: u64,
}

#[derive(Debug)]
struct CatalogDirectory {
    path: PathBuf,
    handle: OwnedHandle,
}

#[derive(Debug)]
struct OpenDirectory {
    path: PathBuf,
    handle: OwnedHandle,
}

#[derive(Clone)]
struct RuntimeMirrorRemovalToken {
    browser_binary: BrowserBinary,
    root: PathBuf,
    executable_paths: Vec<PathBuf>,
    identity: FileIdentity,
    materialization_mode: MaterializationMode,
}

impl RuntimeMirrorRemovalToken {
    fn from_mirror(mirror: WindowsBrowserRuntimeMirror) -> Self {
        let WindowsBrowserRuntimeMirror {
            browser_binary,
            root,
            executable_paths,
            identity,
            materialization_mode,
            _lease_locks,
        } = mirror;
        drop(_lease_locks);
        Self {
            browser_binary,
            root,
            executable_paths,
            identity,
            materialization_mode,
        }
    }

    fn validate_inspection(
        &self,
        inspected: &WindowsBrowserRuntimeMirror,
    ) -> Result<(), WindowsRuntimeMirrorError> {
        if normalized_windows_path(&inspected.browser_binary.path)
            != normalized_windows_path(&self.browser_binary.path)
            || inspected.browser_binary.kind != self.browser_binary.kind
            || inspected.executable_paths != self.executable_paths
            || inspected.materialization_mode != self.materialization_mode
        {
            return Err(invalid_existing(
                &self.root,
                "runtime mirror changed before explicit removal",
            ));
        }
        if inspected.identity != self.identity {
            return Err(invalid_existing(
                &self.root,
                "runtime mirror identity changed before explicit removal",
            ));
        }
        Ok(())
    }
}

#[derive(Clone)]
enum RuntimeMirrorCatalog {
    StationOwned,
    #[cfg(test)]
    Test(PathBuf),
}

enum RuntimeMirrorRemovalAttemptError {
    RetryableSharing(WindowsRuntimeMirrorError),
    Fatal(WindowsRuntimeMirrorError),
}

#[derive(Clone, Copy)]
enum RootShareMode {
    Shared,
    DeleteLocked,
    LeaseLocked,
}

#[derive(Debug)]
struct DirectoryEntry {
    name: OsString,
    attributes: u32,
    file_id: u64,
}

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: HANDLE,
    object_name: *mut UnicodeString,
    attributes: u32,
    security_descriptor: *mut c_void,
    security_quality_of_service: *mut c_void,
}

#[repr(C)]
struct IoStatusBlock {
    status: isize,
    information: usize,
}

#[repr(C)]
struct RelativeNameHeader {
    replace_if_exists: u8,
    root_directory: HANDLE,
    file_name_length: u32,
}

#[link(name = "ntdll")]
extern "system" {
    fn NtCreateFile(
        file_handle: *mut HANDLE,
        desired_access: u32,
        object_attributes: *mut ObjectAttributes,
        io_status_block: *mut IoStatusBlock,
        allocation_size: *mut i64,
        file_attributes: u32,
        share_access: u32,
        create_disposition: u32,
        create_options: u32,
        ea_buffer: *mut c_void,
        ea_length: u32,
    ) -> i32;
    fn NtSetInformationFile(
        file_handle: HANDLE,
        io_status_block: *mut IoStatusBlock,
        file_information: *mut c_void,
        length: u32,
        file_information_class: u32,
    ) -> i32;
}

fn ensure_mirror_base() -> Result<CatalogDirectory, WindowsRuntimeMirrorError> {
    let local_app_data = local_app_data_path()?;
    let local = open_verified_directory(
        &local_app_data,
        FILE_LIST_DIRECTORY.0 | FILE_ADD_SUBDIRECTORY.0 | FILE_READ_ATTRIBUTES.0,
        "open LOCALAPPDATA",
    )?;
    let product_path = local.path.join("dig2browser");
    let product = create_or_open_relative_directory(
        &local.handle,
        OsStr::new("dig2browser"),
        &product_path,
    )?;
    set_runtime_app_package_acl(
        &product,
        &product_path,
        FILE_GENERIC_EXECUTE.0,
        false,
    )?;
    let mirror_path = product_path.join("runtime-mirrors");
    let mirror = create_or_open_relative_directory(
        &product,
        OsStr::new("runtime-mirrors"),
        &mirror_path,
    )?;
    set_runtime_app_package_acl(
        &mirror,
        &mirror_path,
        FILE_GENERIC_EXECUTE.0,
        false,
    )?;
    let base = CatalogDirectory {
        path: mirror_path,
        handle: mirror,
    };
    // Best-effort, fail-closed reclamation of `.staging-*` directories
    // orphaned by a previous incarnation that was killed mid-materialize.
    // Never blocks or fails base setup: every internal error is logged and
    // swallowed, and any entry that cannot be positively identified as
    // dead is retained.
    STAGING_RECONCILE_ONCE.call_once(|| reconcile_orphaned_staging(&base));
    Ok(base)
}

fn existing_mirror_base() -> Result<CatalogDirectory, WindowsRuntimeMirrorError> {
    let local_app_data = local_app_data_path()?;
    let local = open_verified_directory(
        &local_app_data,
        FILE_LIST_DIRECTORY.0 | FILE_READ_ATTRIBUTES.0,
        "open LOCALAPPDATA",
    )?;
    let product_path = local.path.join("dig2browser");
    let product = open_relative_locked(
        &local.handle,
        OsStr::new("dig2browser"),
        FILE_LIST_DIRECTORY.0 | FILE_READ_ATTRIBUTES.0,
        true,
        &product_path,
        "open runtime mirror product root",
    )?;
    let mirror_path = product_path.join("runtime-mirrors");
    let mirror = open_relative_locked(
        &product,
        OsStr::new("runtime-mirrors"),
        FILE_LIST_DIRECTORY.0 | FILE_READ_ATTRIBUTES.0,
        true,
        &mirror_path,
        "open runtime mirror catalog",
    )?;
    Ok(CatalogDirectory {
        path: mirror_path,
        handle: mirror,
    })
}

fn local_app_data_path() -> Result<PathBuf, WindowsRuntimeMirrorError> {
    let value = unsafe {
        SHGetKnownFolderPath(&FOLDERID_LocalAppData, KF_FLAG_DEFAULT, None)
    }
    .map_err(WindowsRuntimeMirrorError::LocalAppDataUnavailable)?;
    if value.0.is_null() {
        return Err(WindowsRuntimeMirrorError::LocalAppDataInvalid);
    }
    let value = CoTaskMemWideString(value);
    let wide = unsafe { value.0.as_wide() };
    if wide.is_empty() {
        return Err(WindowsRuntimeMirrorError::LocalAppDataInvalid);
    }
    Ok(PathBuf::from(OsString::from_wide(wide)))
}

fn validate_owned_mirror_root_under_base(
    root: &Path,
    base: &CatalogDirectory,
    desired_access: u32,
    share_mode: RootShareMode,
) -> Result<OpenDirectory, WindowsRuntimeMirrorError> {
    if !root.is_absolute() {
        return Err(invalid_existing(root, "runtime mirror root is not absolute"));
    }
    if root.parent().is_none_or(|parent| {
        normalized_windows_path(parent) != normalized_windows_path(&base.path)
    })
    {
        return Err(invalid_existing(
            root,
            "runtime mirror root is not a direct non-reparse child of the owned catalog",
        ));
    }
    let name = root
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| invalid_existing(root, "runtime mirror directory name is not UTF-8"))?;
    if name.len() != 64
        || !name.bytes().all(|byte| byte.is_ascii_hexdigit())
        || name.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(invalid_existing(
            root,
            "runtime mirror directory name is not a lowercase content key",
        ));
    }
    let canonical_root = base.path.join(name);
    let handle = match share_mode {
        RootShareMode::DeleteLocked => open_relative_locked(
            &base.handle,
            OsStr::new(name),
            desired_access,
            true,
            &canonical_root,
            "lock station-owned runtime mirror root",
        )?,
        RootShareMode::LeaseLocked => open_relative_lease(
            &base.handle,
            OsStr::new(name),
            desired_access,
            true,
            &canonical_root,
            "lease-lock station-owned runtime mirror root",
        )?,
        RootShareMode::Shared => open_relative(
            &base.handle,
            OsStr::new(name),
            desired_access,
            true,
            FILE_OPEN,
            &canonical_root,
            "open station-owned runtime mirror root",
        )?,
    };
    Ok(OpenDirectory {
        path: canonical_root,
        handle,
    })
}

fn collect_source_tree(root: OpenDirectory) -> Result<Vec<SourceEntry>, WindowsRuntimeMirrorError> {
    let root_path = root.path.clone();
    let mut pending = vec![(PathBuf::new(), root.handle)];
    let mut entries = Vec::new();
    while let Some((relative, handle)) = pending.pop() {
        let path = root_path.join(&relative);
        validate_relative_path(&relative)?;
        if relative == Path::new(READY_MANIFEST) {
            return Err(WindowsRuntimeMirrorError::ReservedEntry { path });
        }
        let information = handle_information(
            &handle,
            &path,
            "inspect runtime mirror source entry",
        )?;
        let kind = if information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0 {
            for child in enumerate_directory(&handle, &path)? {
                let child_relative = relative.join(&child.name);
                let child_path = root_path.join(&child_relative);
                let child_is_directory = child.attributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0;
                let child_handle = if child_is_directory {
                    open_relative(
                        &handle,
                        &child.name,
                        FILE_LIST_DIRECTORY.0 | FILE_READ_ATTRIBUTES.0,
                        true,
                        FILE_OPEN,
                        &child_path,
                        "open runtime mirror source directory",
                    )?
                } else {
                    open_relative_without_write_share(
                        &handle,
                        &child.name,
                        FILE_READ_DATA.0 | FILE_READ_ATTRIBUTES.0,
                        &child_path,
                        "lock runtime mirror source file for snapshot",
                    )?
                };
                let identity = handle_identity(&child_handle, &child_path)?;
                if identity.index != child.file_id {
                    return Err(WindowsRuntimeMirrorError::SourceChanged {
                        path: child_path,
                        reason: format!(
                            "directory enumeration file identity changed (expected_file_id={:#018x}, actual_file_id={:#018x})",
                            child.file_id,
                            identity.index,
                        ),
                    });
                }
                pending.push((child_relative, child_handle));
            }
            SourceEntryKind::Directory
        } else {
            SourceEntryKind::File
        };
        entries.push(SourceEntry {
            source_path: path,
            relative,
            kind,
            attributes: information.dwFileAttributes,
            size: ((information.nFileSizeHigh as u64) << 32) | information.nFileSizeLow as u64,
            last_write_time: ((information.ftLastWriteTime.dwHighDateTime as u64) << 32)
                | information.ftLastWriteTime.dwLowDateTime as u64,
            identity: FileIdentity {
                volume: information.dwVolumeSerialNumber,
                index: ((information.nFileIndexHigh as u64) << 32)
                    | information.nFileIndexLow as u64,
            },
            handle,
        });
    }
    entries.sort_by(|left, right| {
        normalized_windows_path(&left.relative).cmp(&normalized_windows_path(&right.relative))
    });
    Ok(entries)
}

fn fingerprint_source_tree(entries: &[SourceEntry]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"dig2browser-source-tree-v2\0");
    for entry in entries {
        let kind = match entry.kind {
            SourceEntryKind::Directory => 0u8,
            SourceEntryKind::File => 1u8,
        };
        digest.update([kind]);
        hash_path_into(&mut digest, &entry.relative);
        digest.update(entry.attributes.to_le_bytes());
        digest.update(entry.size.to_le_bytes());
        digest.update(entry.last_write_time.to_le_bytes());
        digest.update(entry.identity.volume.to_le_bytes());
        digest.update(entry.identity.index.to_le_bytes());
    }
    hex_digest(digest.finalize())
}

fn fingerprint_open_source_tree(
    entries: &[SourceEntry],
) -> Result<String, WindowsRuntimeMirrorError> {
    let mut digest = Sha256::new();
    digest.update(b"dig2browser-source-tree-v2\0");
    for entry in entries {
        let kind = match entry.kind {
            SourceEntryKind::Directory => 0u8,
            SourceEntryKind::File => 1u8,
        };
        let information = handle_information(
            &entry.handle,
            &entry.source_path,
            "revalidate opened runtime mirror source entry",
        )?;
        let actual_is_directory =
            information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0;
        let expected_is_directory = entry.kind == SourceEntryKind::Directory;
        if actual_is_directory != expected_is_directory {
            return Err(source_metadata_changed(entry, &information, "kind"));
        }
        if information.dwFileAttributes != entry.attributes {
            return Err(source_metadata_changed(entry, &information, "attributes"));
        }
        let size = ((information.nFileSizeHigh as u64) << 32) | information.nFileSizeLow as u64;
        if size != entry.size {
            return Err(source_metadata_changed(entry, &information, "size"));
        }
        let last_write_time = ((information.ftLastWriteTime.dwHighDateTime as u64) << 32)
            | information.ftLastWriteTime.dwLowDateTime as u64;
        if last_write_time != entry.last_write_time {
            return Err(source_metadata_changed(
                entry,
                &information,
                "last_write_time",
            ));
        }
        if information.dwVolumeSerialNumber != entry.identity.volume {
            return Err(source_metadata_changed(entry, &information, "volume"));
        }
        let file_id = ((information.nFileIndexHigh as u64) << 32)
            | information.nFileIndexLow as u64;
        if file_id != entry.identity.index {
            return Err(source_metadata_changed(entry, &information, "file_id"));
        }
        digest.update([kind]);
        hash_path_into(&mut digest, &entry.relative);
        digest.update(information.dwFileAttributes.to_le_bytes());
        digest.update(size.to_le_bytes());
        digest.update(last_write_time.to_le_bytes());
        digest.update(information.dwVolumeSerialNumber.to_le_bytes());
        digest.update(file_id.to_le_bytes());
    }
    Ok(hex_digest(digest.finalize()))
}

fn source_metadata_changed(
    entry: &SourceEntry,
    actual: &BY_HANDLE_FILE_INFORMATION,
    field: &'static str,
) -> WindowsRuntimeMirrorError {
    let expected_kind = match entry.kind {
        SourceEntryKind::Directory => "directory",
        SourceEntryKind::File => "file",
    };
    let actual_kind = if actual.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0 {
        "directory"
    } else {
        "file"
    };
    let actual_size =
        ((actual.nFileSizeHigh as u64) << 32) | actual.nFileSizeLow as u64;
    let actual_last_write = ((actual.ftLastWriteTime.dwHighDateTime as u64) << 32)
        | actual.ftLastWriteTime.dwLowDateTime as u64;
    let actual_file_id =
        ((actual.nFileIndexHigh as u64) << 32) | actual.nFileIndexLow as u64;
    WindowsRuntimeMirrorError::SourceChanged {
        path: entry.source_path.clone(),
        reason: format!(
            "source entry metadata field '{field}' changed (expected kind={expected_kind}, attributes={:#010x}, size={}, last_write_time={:#018x}, volume={:#010x}, file_id={:#018x}; actual kind={actual_kind}, attributes={:#010x}, size={}, last_write_time={:#018x}, volume={:#010x}, file_id={:#018x})",
            entry.attributes,
            entry.size,
            entry.last_write_time,
            entry.identity.volume,
            entry.identity.index,
            actual.dwFileAttributes,
            actual_size,
            actual_last_write,
            actual.dwVolumeSerialNumber,
            actual_file_id,
        ),
    }
}

fn validate_source_tree_membership(
    entries: &[SourceEntry],
) -> Result<(), WindowsRuntimeMirrorError> {
    for directory in entries
        .iter()
        .filter(|entry| entry.kind == SourceEntryKind::Directory)
    {
        let mut expected = entries
            .iter()
            .filter(|entry| {
                !entry.relative.as_os_str().is_empty()
                    && entry.relative.parent().unwrap_or_else(|| Path::new(""))
                        == directory.relative
            })
            .map(|entry| {
                let name = entry.relative.file_name().ok_or_else(|| {
                    WindowsRuntimeMirrorError::InvalidRelativePath {
                        path: entry.relative.clone(),
                    }
                })?;
                Ok((
                    normalized_windows_path(Path::new(name)),
                    entry.identity.index,
                    entry.kind == SourceEntryKind::Directory,
                ))
            })
            .collect::<Result<Vec<_>, WindowsRuntimeMirrorError>>()?;
        let mut actual = enumerate_directory(&directory.handle, &directory.source_path)?
            .into_iter()
            .map(|entry| {
                (
                    normalized_windows_path(Path::new(&entry.name)),
                    entry.file_id,
                    entry.attributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0,
                )
            })
            .collect::<Vec<_>>();
        expected.sort();
        actual.sort();
        if actual != expected {
            let expected_summary = summarize_directory_membership(&expected);
            let actual_summary = summarize_directory_membership(&actual);
            let first_difference = expected
                .iter()
                .zip(actual.iter())
                .position(|(expected, actual)| expected != actual)
                .unwrap_or_else(|| expected.len().min(actual.len()));
            let expected_entry = summarize_directory_membership_entry(
                expected.get(first_difference),
            );
            let actual_entry = summarize_directory_membership_entry(actual.get(first_difference));
            return Err(WindowsRuntimeMirrorError::SourceChanged {
                path: directory.source_path.clone(),
                reason: format!(
                    "directory membership changed (expected_count={}, actual_count={}, expected_sha256={}, actual_sha256={}, first_difference_index={}, expected_entry={}, actual_entry={})",
                    expected.len(),
                    actual.len(),
                    expected_summary,
                    actual_summary,
                    first_difference,
                    expected_entry,
                    actual_entry,
                ),
            });
        }
    }
    Ok(())
}

fn summarize_directory_membership(entries: &[(Vec<u16>, u64, bool)]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"dig2browser-directory-membership-v1\0");
    for (name, file_id, is_directory) in entries {
        for unit in name {
            digest.update(unit.to_le_bytes());
        }
        digest.update([0, 0]);
        digest.update(file_id.to_le_bytes());
        digest.update([u8::from(*is_directory)]);
    }
    hex_digest(digest.finalize())
}

fn summarize_directory_membership_entry(entry: Option<&(Vec<u16>, u64, bool)>) -> String {
    let Some((name, file_id, is_directory)) = entry else {
        return "none".to_owned();
    };
    let mut digest = Sha256::new();
    digest.update(b"dig2browser-directory-member-name-v1\0");
    for unit in name {
        digest.update(unit.to_le_bytes());
    }
    format!(
        "name_sha256:{};file_id:{:#018x};kind:{}",
        hex_digest(digest.finalize()),
        file_id,
        if *is_directory { "directory" } else { "file" },
    )
}

fn mirror_key(
    scope: WindowsRuntimeMirrorScope,
    source_binary: &Path,
    kind: BrowserKind,
    version: Option<&str>,
    source_fingerprint: &str,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"dig2browser-runtime-mirror-key-v2\0");
    digest.update(scope.0);
    hash_path_into(&mut digest, source_binary);
    digest.update(browser_kind_name(kind).as_bytes());
    digest.update([0]);
    digest.update(version.unwrap_or("").as_bytes());
    digest.update([0]);
    digest.update(source_fingerprint.as_bytes());
    hex_digest(digest.finalize())
}

fn hash_path(path: &Path) -> String {
    let mut digest = Sha256::new();
    hash_path_into(&mut digest, path);
    hex_digest(digest.finalize())
}

fn hash_path_into(digest: &mut Sha256, path: &Path) {
    for unit in normalized_windows_path(path) {
        digest.update(unit.to_le_bytes());
    }
    digest.update([0, 0]);
}

fn normalized_windows_path(path: &Path) -> Vec<u16> {
    normalize_windows_path_units(path.as_os_str().encode_wide().collect())
}

fn normalize_windows_path_units(mut units: Vec<u16>) -> Vec<u16> {
    let verbatim = "\\\\?\\".encode_utf16().collect::<Vec<_>>();
    let verbatim_unc = "\\\\?\\UNC\\".encode_utf16().collect::<Vec<_>>();
    if starts_with_ascii_case_insensitive(&units, &verbatim_unc) {
        let mut unc = vec!['\\' as u16, '\\' as u16];
        unc.extend_from_slice(&units[verbatim_unc.len()..]);
        units = unc;
    } else if starts_with_ascii_case_insensitive(&units, &verbatim) {
        units.drain(..verbatim.len());
    }
    for unit in &mut units {
        if *unit == '/' as u16 {
            *unit = '\\' as u16;
        } else if *unit <= u8::MAX as u16 && (*unit as u8).is_ascii_uppercase() {
            *unit = (*unit as u8).to_ascii_lowercase() as u16;
        }
    }
    while units.len() > 3 && units.last() == Some(&('\\' as u16)) {
        units.pop();
    }
    units
}

fn starts_with_ascii_case_insensitive(value: &[u16], prefix: &[u16]) -> bool {
    value.len() >= prefix.len()
        && value.iter().zip(prefix).all(|(left, right)| {
            *left <= u8::MAX as u16
                && *right <= u8::MAX as u16
                && (*left as u8).eq_ignore_ascii_case(&(*right as u8))
        })
}

fn browser_kind_name(kind: BrowserKind) -> &'static str {
    match kind {
        BrowserKind::Chrome => "chrome",
        BrowserKind::Edge => "edge",
        BrowserKind::Chromium => "chromium",
        BrowserKind::Firefox => "firefox",
    }
}

fn browser_kind_from_name(name: &str) -> Option<BrowserKind> {
    match name {
        "chrome" => Some(BrowserKind::Chrome),
        "edge" => Some(BrowserKind::Edge),
        "chromium" => Some(BrowserKind::Chromium),
        "firefox" => Some(BrowserKind::Firefox),
        _ => None,
    }
}

fn create_staging_directory(
    base: &CatalogDirectory,
    key: &str,
) -> Result<OpenDirectory, WindowsRuntimeMirrorError> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let identity = current_process_staging_identity(&base.path)?;
    for _ in 0..STAGING_ATTEMPTS {
        let sequence = STAGING_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let name = format!(
            ".staging-{STAGING_NAME_SCHEMA}-{key}-{}-{:016x}-{nonce}-{sequence}",
            identity.pid, identity.creation_filetime,
        );
        let staging = base.path.join(&name);
        match open_relative(
            &base.handle,
            OsStr::new(&name),
            FILE_LIST_DIRECTORY.0
                | FILE_ADD_FILE.0
                | FILE_ADD_SUBDIRECTORY.0
                | FILE_READ_ATTRIBUTES.0
                | DELETE_ACCESS
                | READ_CONTROL.0
                | WRITE_DAC.0,
            true,
            FILE_CREATE,
            &staging,
            "create exclusive runtime mirror staging directory",
        ) {
            Ok(handle) => return Ok(OpenDirectory { path: staging, handle }),
            Err(WindowsRuntimeMirrorError::WindowsNt { status, .. })
                if status == 0xC000_0035u32 as i32 => continue,
            Err(error) => return Err(error),
        }
    }
    Err(WindowsRuntimeMirrorError::Io {
        operation: "allocate exclusive runtime mirror staging directory",
        path: base.path.clone(),
        source: io::Error::new(io::ErrorKind::AlreadyExists, "staging name space exhausted"),
    })
}

/// The identity of a staging directory's creating process incarnation, as
/// embedded in its `.staging-v2-...` name: the creator's PID and the exact
/// OS-reported FILETIME at which that PID's process was created. Comparing
/// both fields (not the PID alone) is what makes reconciliation safe across
/// PID reuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StagingCreatorIdentity {
    pid: u32,
    creation_filetime: u64,
}

/// Captures the current process's own verifiable identity for embedding in
/// a new staging directory name.
fn current_process_staging_identity(
    context_path: &Path,
) -> Result<StagingCreatorIdentity, WindowsRuntimeMirrorError> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    unsafe {
        GetProcessTimes(
            GetCurrentProcess(),
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    }
    .map_err(|source| WindowsRuntimeMirrorError::Windows {
        operation: "read current process creation time for runtime mirror staging identity",
        path: context_path.to_path_buf(),
        source,
    })?;
    let creation_filetime =
        ((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64;
    if creation_filetime == 0 {
        return Err(invalid_existing(
            context_path,
            "Windows returned an invalid process creation FILETIME for the current process",
        ));
    }
    Ok(StagingCreatorIdentity {
        pid: std::process::id(),
        creation_filetime,
    })
}

/// Parses a catalog entry name against the exact `.staging-v2-<key>-<pid>-
/// <creation_filetime>-<nonce>-<sequence>` structure produced by
/// [`create_staging_directory`]. Returns `None` for anything that does not
/// match field-for-field, including the legacy pre-`v2` staging names that
/// only embed a wall-clock nonce and therefore carry no verifiable creator
/// identity. Reconciliation must never touch what it cannot parse exactly.
fn parse_staging_creator_identity(name: &OsStr) -> Option<StagingCreatorIdentity> {
    let name = name.to_str()?;
    let rest = name.strip_prefix(".staging-")?;
    let mut fields = rest.split('-');
    if fields.next()? != STAGING_NAME_SCHEMA {
        return None;
    }
    let key = fields.next()?;
    if key.len() != 64
        || !key.bytes().all(|byte| byte.is_ascii_hexdigit())
        || key.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return None;
    }
    let pid = parse_canonical_decimal::<u32>(fields.next()?)?;
    if pid == 0 {
        return None;
    }
    let creation_filetime_field = fields.next()?;
    if creation_filetime_field.len() != 16
        || !creation_filetime_field.bytes().all(|byte| byte.is_ascii_hexdigit())
        || creation_filetime_field.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return None;
    }
    let creation_filetime = u64::from_str_radix(creation_filetime_field, 16).ok()?;
    if creation_filetime == 0 {
        return None;
    }
    // The nonce and sequence carry no identity information by themselves,
    // but the exact-structure contract still requires them to be present
    // and in canonical decimal form.
    parse_canonical_decimal::<u128>(fields.next()?)?;
    parse_canonical_decimal::<u64>(fields.next()?)?;
    if fields.next().is_some() {
        return None;
    }
    Some(StagingCreatorIdentity {
        pid,
        creation_filetime,
    })
}

fn parse_canonical_decimal<T>(value: &str) -> Option<T>
where
    T: FromStr + ToString,
{
    let parsed = value.parse::<T>().ok()?;
    (value == parsed.to_string()).then_some(parsed)
}

/// Liveness of a staging directory's creating process incarnation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StagingCreatorState {
    /// The exact same process incarnation (PID + creation FILETIME) is
    /// still running: the staging directory may be in-flight.
    Alive,
    /// The PID no longer exists, or now belongs to a different process
    /// incarnation (PID reuse), or has already exited.
    Dead,
    /// Liveness could not be established with confidence (ambiguous or
    /// failed Windows query). Fail-closed: treated the same as `Alive` by
    /// callers.
    Unverifiable,
}

struct ScopedProcessHandle(HANDLE);

impl Drop for ScopedProcessHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

/// Identity-safe liveness check for a staging directory's creator,
/// following the same `OpenProcess` + `GetProcessTimes` + exit-code idiom
/// used elsewhere in this codebase for orphan reconciliation.
fn staging_creator_state(identity: StagingCreatorIdentity) -> StagingCreatorState {
    let handle = match unsafe {
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, identity.pid)
    } {
        Ok(handle) => ScopedProcessHandle(handle),
        Err(error) => {
            let code = error.code().0 as u32;
            let invalid_parameter = 0x8007_0000u32 | ERROR_INVALID_PARAMETER.0;
            return if code == invalid_parameter {
                StagingCreatorState::Dead
            } else {
                StagingCreatorState::Unverifiable
            };
        }
    };
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    if unsafe {
        GetProcessTimes(handle.0, &mut creation, &mut exit, &mut kernel, &mut user)
    }
    .is_err()
    {
        return StagingCreatorState::Unverifiable;
    }
    let actual_creation_filetime =
        ((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64;
    if actual_creation_filetime == 0 || actual_creation_filetime != identity.creation_filetime {
        // Either Windows could not report a creation time for this PID, or
        // the PID now names a different process incarnation than the one
        // that created the staging directory. Either way the original
        // creator is provably gone.
        return StagingCreatorState::Dead;
    }
    let mut exit_code = 0u32;
    if unsafe { GetExitCodeProcess(handle.0, &mut exit_code) }.is_err() {
        return StagingCreatorState::Unverifiable;
    }
    if exit_code == STILL_ACTIVE.0 as u32 {
        StagingCreatorState::Alive
    } else {
        StagingCreatorState::Dead
    }
}

/// Best-effort entry point: reconciles orphaned `.staging-*` directories in
/// `base` and never propagates a failure to its caller.
fn reconcile_orphaned_staging(base: &CatalogDirectory) {
    if let Err(error) = reconcile_orphaned_staging_inner(base) {
        tracing::warn!(
            "dig2browser runtime mirror staging reconciliation skipped for '{}': {error}",
            base.path.display(),
        );
    }
}

fn reconcile_orphaned_staging_inner(
    base: &CatalogDirectory,
) -> Result<(), WindowsRuntimeMirrorError> {
    // `enumerate_directory` itself rejects reparse points anywhere in the
    // catalog (see its `FILE_ATTRIBUTE_REPARSE_POINT` check), so a reparse
    // point present under the catalog aborts this best-effort pass entirely
    // rather than being traversed or deleted.
    for entry in enumerate_directory(&base.handle, &base.path)? {
        let display_name = entry.name.to_string_lossy().into_owned();
        if !display_name.starts_with(".staging-") {
            continue;
        }
        if entry.attributes & FILE_ATTRIBUTE_DIRECTORY.0 == 0 {
            tracing::debug!(
                "dig2browser runtime mirror retaining staging-named catalog entry '{display_name}' (not a directory)"
            );
            continue;
        }
        let Some(identity) = parse_staging_creator_identity(&entry.name) else {
            tracing::debug!(
                "dig2browser runtime mirror retaining staging entry '{display_name}' (does not match the versioned staging name schema)"
            );
            continue;
        };
        match staging_creator_state(identity) {
            StagingCreatorState::Alive => {
                tracing::debug!(
                    "dig2browser runtime mirror retaining staging entry '{display_name}' (creator pid {} is still running this incarnation)",
                    identity.pid,
                );
            }
            StagingCreatorState::Unverifiable => {
                tracing::debug!(
                    "dig2browser runtime mirror retaining staging entry '{display_name}' (creator pid {} liveness is unverifiable)",
                    identity.pid,
                );
            }
            StagingCreatorState::Dead => {
                reclaim_orphaned_staging_entry(base, &entry.name, &display_name, identity.pid);
            }
        }
    }
    Ok(())
}

/// Reclaims a single provably-orphaned staging directory. Best-effort: any
/// failure to lock or remove it is logged and the entry is left behind for
/// a later reconciliation pass rather than propagated.
fn reclaim_orphaned_staging_entry(
    base: &CatalogDirectory,
    name: &OsStr,
    display_name: &str,
    creator_pid: u32,
) {
    let path = base.path.join(name);
    let handle = match open_relative_locked(
        &base.handle,
        name,
        FILE_LIST_DIRECTORY.0 | FILE_READ_ATTRIBUTES.0 | DELETE_ACCESS,
        true,
        &path,
        "lock orphaned runtime mirror staging entry for reclamation",
    ) {
        Ok(handle) => handle,
        Err(WindowsRuntimeMirrorError::WindowsNt { status, .. })
            if status == 0xC000_0034u32 as i32 || status == 0xC000_003Au32 as i32 =>
        {
            tracing::debug!(
                "dig2browser runtime mirror staging entry '{display_name}' was already gone before reclamation"
            );
            return;
        }
        Err(error) => {
            tracing::debug!(
                "dig2browser runtime mirror retaining staging entry '{display_name}' (could not lock for reclamation: {error})"
            );
            return;
        }
    };
    let staging = OpenDirectory { path, handle };
    match cleanup_owned_staging(base, &staging) {
        Ok(()) => {
            tracing::info!(
                "dig2browser runtime mirror reclaimed orphaned staging entry '{display_name}' (creator pid {creator_pid} is dead or its pid was reused)"
            );
        }
        Err(error) => {
            tracing::warn!(
                "dig2browser runtime mirror failed to reclaim orphaned staging entry '{display_name}': {error}"
            );
        }
    }
}

fn populate_staging(
    entries: &[SourceEntry],
    staging: &OpenDirectory,
    mode: MaterializationMode,
) -> Result<(), WindowsRuntimeMirrorError> {
    let mut destination_directories = BTreeMap::new();
    destination_directories.insert(Vec::<u16>::new(), duplicate_handle(&staging.handle, &staging.path)?);
    let mut directories = entries.iter().filter(|entry| {
        entry.kind == SourceEntryKind::Directory && !entry.relative.as_os_str().is_empty()
    }).collect::<Vec<_>>();
    directories.sort_by_key(|entry| entry.relative.components().count());
    for entry in directories {
        let parent_relative = entry.relative.parent().unwrap_or_else(|| Path::new(""));
        let parent = destination_directories.get(&normalized_windows_path(parent_relative))
            .ok_or_else(|| WindowsRuntimeMirrorError::InvalidRelativePath {
                path: entry.relative.clone(),
            })?;
        let name = entry.relative.file_name().ok_or_else(|| {
            WindowsRuntimeMirrorError::InvalidRelativePath { path: entry.relative.clone() }
        })?;
        let destination = staging.path.join(&entry.relative);
        let handle = open_relative(
            parent,
            name,
            FILE_LIST_DIRECTORY.0
                | FILE_ADD_FILE.0
                | FILE_ADD_SUBDIRECTORY.0
                | FILE_READ_ATTRIBUTES.0
                | DELETE_ACCESS,
            true,
            FILE_CREATE,
            &destination,
            "create runtime mirror directory",
        )?;
        destination_directories.insert(normalized_windows_path(&entry.relative), handle);
    }
    for entry in entries.iter().filter(|entry| entry.kind == SourceEntryKind::File) {
        let parent_relative = entry.relative.parent().unwrap_or_else(|| Path::new(""));
        let parent = destination_directories.get(&normalized_windows_path(parent_relative))
            .ok_or_else(|| WindowsRuntimeMirrorError::InvalidRelativePath {
                path: entry.relative.clone(),
            })?;
        let name = entry.relative.file_name().ok_or_else(|| {
            WindowsRuntimeMirrorError::InvalidRelativePath { path: entry.relative.clone() }
        })?;
        let target_path = staging.path.join(&entry.relative);
        match mode {
            MaterializationMode::HardLinkV1 => {
                create_hard_link_relative(&entry.handle, parent, name, &target_path)?;
            }
            MaterializationMode::CopyV1 => {
                copy_file_relative(entry, parent, name, &target_path)?;
            }
            MaterializationMode::LegacyUnknown => {
                return Err(invalid_existing(
                    &staging.path,
                    "legacy materialization mode cannot build a new runtime mirror",
                ));
            }
        }
    }
    Ok(())
}

fn is_hard_link_policy_denial(error: &WindowsRuntimeMirrorError) -> bool {
    matches!(
        error,
        WindowsRuntimeMirrorError::WindowsNt {
            operation: "hard-link runtime mirror file",
            status: STATUS_ACCESS_DENIED,
            ..
        }
    )
}

fn build_cleanup_error(
    primary: WindowsRuntimeMirrorError,
    cleanup: WindowsRuntimeMirrorError,
) -> WindowsRuntimeMirrorError {
    WindowsRuntimeMirrorError::BuildCleanup {
        primary: Box::new(primary),
        cleanup: Box::new(cleanup),
    }
}

fn cleanup_staging_after_error(
    base: &CatalogDirectory,
    staging: OpenDirectory,
    primary: WindowsRuntimeMirrorError,
) -> WindowsRuntimeMirrorError {
    let cleanup = cleanup_owned_staging(base, &staging);
    drop(staging);
    match cleanup {
        Ok(()) => primary,
        Err(cleanup) => build_cleanup_error(primary, cleanup),
    }
}

fn copy_file_relative(
    entry: &SourceEntry,
    target_parent: &OwnedHandle,
    target_name: &OsStr,
    target_path: &Path,
) -> Result<(), WindowsRuntimeMirrorError> {
    let source = duplicate_handle(&entry.handle, &entry.source_path)?;
    let mut source = unsafe { File::from_raw_handle(source.into_raw_handle()) };
    source
        .seek(SeekFrom::Start(0))
        .map_err(|source| WindowsRuntimeMirrorError::Io {
            operation: "rewind runtime mirror source file",
            path: entry.source_path.clone(),
            source,
        })?;

    let target = open_relative(
        target_parent,
        target_name,
        FILE_READ_DATA.0 | FILE_WRITE_DATA.0 | FILE_READ_ATTRIBUTES.0 | DELETE_ACCESS,
        false,
        FILE_CREATE,
        target_path,
        "create copied runtime mirror file",
    )?;
    let mut target = unsafe { File::from_raw_handle(target.into_raw_handle()) };
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut copied = 0u64;
    loop {
        let read = source.read(&mut buffer).map_err(|source| {
            WindowsRuntimeMirrorError::Io {
                operation: "read runtime mirror source file",
                path: entry.source_path.clone(),
                source,
            }
        })?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
        target.write_all(&buffer[..read]).map_err(|source| {
            WindowsRuntimeMirrorError::Io {
                operation: "write copied runtime mirror file",
                path: target_path.to_path_buf(),
                source,
            }
        })?;
        copied = copied.checked_add(read as u64).ok_or_else(|| {
            WindowsRuntimeMirrorError::SourceChanged {
                path: entry.source_path.clone(),
                reason: "copied byte counter overflowed u64".to_owned(),
            }
        })?;
    }
    if copied != entry.size {
        return Err(WindowsRuntimeMirrorError::SourceChanged {
            path: entry.source_path.clone(),
            reason: format!(
                "source file size changed while copying (expected_bytes={}, copied_bytes={})",
                entry.size,
                copied,
            ),
        });
    }
    target
        .sync_all()
        .map_err(|source| WindowsRuntimeMirrorError::Io {
            operation: "flush copied runtime mirror file",
            path: target_path.to_path_buf(),
            source,
        })?;
    let target_size = target
        .metadata()
        .map_err(|source| WindowsRuntimeMirrorError::Io {
            operation: "inspect copied runtime mirror file",
            path: target_path.to_path_buf(),
            source,
        })?
        .len();
    if target_size != entry.size {
        return Err(WindowsRuntimeMirrorError::SourceChanged {
            path: entry.source_path.clone(),
            reason: format!(
                "copied target size differs from source snapshot (expected_bytes={}, actual_bytes={})",
                entry.size,
                target_size,
            ),
        });
    }
    let copied_digest: [u8; 32] = digest.finalize().into();
    let target_digest = hash_open_file(
        &mut target,
        target_path,
        "hash copied runtime mirror file",
    )?;
    let stable_source_digest = hash_open_file(
        &mut source,
        &entry.source_path,
        "rehash runtime mirror source file",
    )?;
    if copied_digest != target_digest || copied_digest != stable_source_digest {
        return Err(WindowsRuntimeMirrorError::SourceChanged {
            path: entry.source_path.clone(),
            reason: format!(
                "source or target content changed while copying (stream_sha256={}, target_sha256={}, source_rehash_sha256={})",
                hex_digest(copied_digest),
                hex_digest(target_digest),
                hex_digest(stable_source_digest),
            ),
        });
    }
    Ok(())
}

fn hash_open_file(
    file: &mut File,
    path: &Path,
    operation: &'static str,
) -> Result<[u8; 32], WindowsRuntimeMirrorError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|source| WindowsRuntimeMirrorError::Io {
            operation,
            path: path.to_path_buf(),
            source,
        })?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|source| {
            WindowsRuntimeMirrorError::Io {
                operation,
                path: path.to_path_buf(),
                source,
            }
        })?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(digest.finalize().into())
}

fn write_ready_manifest(
    staging: &OpenDirectory,
    manifest: &ReadyManifest,
) -> Result<(), WindowsRuntimeMirrorError> {
    let path = staging.path.join(READY_MANIFEST);
    let bytes = serde_json::to_vec(manifest)?;
    let handle = open_relative(
        &staging.handle,
        OsStr::new(READY_MANIFEST),
        FILE_WRITE_DATA.0 | FILE_READ_ATTRIBUTES.0,
        false,
        FILE_CREATE,
        &path,
        "create runtime mirror readiness manifest",
    )?;
    let mut file = unsafe { File::from_raw_handle(handle.into_raw_handle()) };
    file.write_all(&bytes).map_err(|source| WindowsRuntimeMirrorError::Io {
        operation: "write runtime mirror readiness manifest",
        path: path.clone(),
        source,
    })?;
    file.sync_all().map_err(|source| WindowsRuntimeMirrorError::Io {
        operation: "flush runtime mirror readiness manifest",
        path,
        source,
    })
}

fn publish_staging(
    base: &CatalogDirectory,
    staging: OpenDirectory,
    target: &Path,
    binary_relative: &Path,
    manifest: &ReadyManifest,
    kind: BrowserKind,
) -> Result<WindowsBrowserRuntimeMirror, WindowsRuntimeMirrorError> {
    let target_name = match target.file_name() {
        Some(target_name) => target_name,
        None => {
            let error = WindowsRuntimeMirrorError::InvalidRelativePath {
                path: target.to_path_buf(),
            };
            return Err(cleanup_staging_after_error(base, staging, error));
        }
    };
    if let Err(error) = apply_staging_acl(&staging, manifest.materialization_mode) {
        return Err(cleanup_staging_after_error(base, staging, error));
    }
    let staging_identity = match handle_identity(&staging.handle, &staging.path) {
        Ok(identity) => identity,
        Err(error) => return Err(cleanup_staging_after_error(base, staging, error)),
    };
    match rename_relative(&staging.handle, &base.handle, target_name, target) {
        Ok(()) => {
            // The staging handle carries write/delete/WRITE_DAC access. Closing
            // it before inspection is required so the published mirror can be
            // reopened with a share-read-only active lease.
            drop(staging);
            let mirror = validate_ready_mirror(
                target,
                binary_relative,
                manifest,
                kind,
                false,
            )?;
            if mirror.identity != staging_identity {
                return Err(invalid_existing(target, "published mirror identity was replaced"));
            }
            Ok(mirror)
        }
        Err(rename_error) => {
            let cleanup = cleanup_owned_staging(base, &staging);
            drop(staging);
            if let Err(cleanup) = cleanup {
                return Err(build_cleanup_error(rename_error, cleanup));
            }
            match validate_ready_mirror(
                target,
                binary_relative,
                manifest,
                kind,
                true,
            ) {
                Ok(mirror) => Ok(mirror),
                Err(_) => Err(rename_error),
            }
        }
    }
}

fn apply_staging_acl(
    staging: &OpenDirectory,
    mode: MaterializationMode,
) -> Result<(), WindowsRuntimeMirrorError> {
    match mode {
        MaterializationMode::HardLinkV1 => {
            set_staging_tree_acls(staging, StagingAclScope::DirectoriesOnly)
        }
        MaterializationMode::CopyV1 => {
            set_staging_tree_acls(staging, StagingAclScope::DirectoriesAndFiles)
        }
        MaterializationMode::LegacyUnknown => Err(invalid_existing(
            &staging.path,
            "legacy materialization mode cannot be published",
        )),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StagingAclScope {
    DirectoriesOnly,
    DirectoriesAndFiles,
}

fn set_staging_tree_acls(
    staging: &OpenDirectory,
    scope: StagingAclScope,
) -> Result<(), WindowsRuntimeMirrorError> {
    set_runtime_app_package_acl(
        &staging.handle,
        &staging.path,
        FILE_GENERIC_READ.0 | FILE_GENERIC_EXECUTE.0,
        false,
    )?;
    let mut visited = 0usize;
    let mut pending = vec![(
        PathBuf::new(),
        duplicate_handle(&staging.handle, &staging.path)?,
        0usize,
    )];
    while let Some((relative, directory, depth)) = pending.pop() {
        let directory_path = staging.path.join(&relative);
        for entry in enumerate_directory(&directory, &directory_path)? {
            if visited == MAX_MIRROR_ENTRIES {
                return Err(invalid_existing(
                    &staging.path,
                    "runtime mirror ACL traversal exceeded entry bound",
                ));
            }
            visited += 1;
            let is_directory = entry.attributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0;
            let apply_acl = is_directory || scope == StagingAclScope::DirectoriesAndFiles;
            let child_depth = depth + 1;
            if child_depth > MAX_MIRROR_DEPTH {
                return Err(invalid_existing(
                    &staging.path,
                    "runtime mirror ACL traversal exceeded depth bound",
                ));
            }
            let child_relative = relative.join(&entry.name);
            let child_path = staging.path.join(&child_relative);
            let desired_access = FILE_READ_ATTRIBUTES.0
                | if is_directory { FILE_LIST_DIRECTORY.0 } else { 0 };
            let desired_access = desired_access
                | if apply_acl { READ_CONTROL.0 | WRITE_DAC.0 } else { 0 };
            let child = open_relative(
                &directory,
                &entry.name,
                desired_access,
                is_directory,
                FILE_OPEN,
                &child_path,
                "open runtime mirror entry for ACL",
            )?;
            if handle_identity(&child, &child_path)?.index != entry.file_id {
                return Err(invalid_existing(
                    &staging.path,
                    "runtime mirror entry changed during ACL application",
                ));
            }
            if apply_acl {
                set_runtime_app_package_acl(
                    &child,
                    &child_path,
                    FILE_GENERIC_READ.0 | FILE_GENERIC_EXECUTE.0,
                    false,
                )?;
            }
            if is_directory {
                pending.push((child_relative, child, child_depth));
            }
        }
    }
    Ok(())
}

fn validate_ready_mirror(
    root: &Path,
    binary_relative: &Path,
    expected: &ReadyManifest,
    kind: BrowserKind,
    accept_existing_mode: bool,
) -> Result<WindowsBrowserRuntimeMirror, WindowsRuntimeMirrorError> {
    let mirror = inspect_ready_mirror(root)?;
    let base = existing_mirror_base()?;
    let opened = validate_owned_mirror_root_under_base(
        &mirror.root,
        &base,
        FILE_LIST_DIRECTORY.0 | FILE_READ_ATTRIBUTES.0,
        RootShareMode::Shared,
    )?;
    if handle_identity(&opened.handle, &opened.path)? != mirror.identity {
        return Err(invalid_existing(&mirror.root, "runtime mirror changed during validation"));
    }
    let bytes = read_manifest_bytes_from_handle(&opened)?;
    let mut mode_aware_expected = expected.clone();
    if accept_existing_mode {
        if mirror.materialization_mode == MaterializationMode::LegacyUnknown {
            return Err(invalid_existing(
                &mirror.root,
                "legacy runtime mirror has no reusable materialization mode",
            ));
        }
        mode_aware_expected.materialization_mode = mirror.materialization_mode;
    }
    validate_manifest_bytes(&bytes, &mode_aware_expected).map_err(|reason| {
        invalid_existing(&mirror.root, reason)
    })?;
    let expected_binary = mirror.root.join(binary_relative);
    if mirror.browser_binary.kind != kind
        || normalized_windows_path(&mirror.browser_binary.path)
            != normalized_windows_path(&expected_binary)
    {
        return Err(invalid_existing(
            &mirror.root,
            "readiness manifest does not identify the requested main executable",
        ));
    }
    Ok(mirror)
}

fn validate_manifest_bytes(bytes: &[u8], expected: &ReadyManifest) -> Result<(), String> {
    let actual = parse_manifest_bytes(bytes)?;
    if &actual != expected {
        return Err("readiness manifest does not match the requested source".to_owned());
    }
    Ok(())
}

fn parse_manifest_bytes(bytes: &[u8]) -> Result<ReadyManifest, String> {
    let actual: ReadyManifest = serde_json::from_slice(bytes)
        .map_err(|error| format!("invalid readiness manifest: {error}"))?;
    if actual.schema != MIRROR_SCHEMA
        || actual.key.len() != 64
        || !actual.key.bytes().all(|byte| byte.is_ascii_hexdigit())
        || actual.source_fingerprint.len() != 64
        || !actual
            .source_fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || actual.binary_relative_hash.len() != 64
        || !actual
            .binary_relative_hash
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("readiness manifest hashes, key, or schema are invalid".to_owned());
    }
    browser_kind_from_name(&actual.browser_kind)
        .ok_or_else(|| "readiness manifest browser kind is invalid".to_owned())?;
    Ok(actual)
}

fn inspect_ready_mirror(
    requested_root: &Path,
) -> Result<WindowsBrowserRuntimeMirror, WindowsRuntimeMirrorError> {
    let base = existing_mirror_base()?;
    inspect_ready_mirror_under_catalog(requested_root, &base)
}

#[cfg(test)]
fn inspect_ready_mirror_under_base(
    requested_root: &Path,
    base: &Path,
) -> Result<WindowsBrowserRuntimeMirror, WindowsRuntimeMirrorError> {
    let base = open_verified_directory(
        base,
        FILE_LIST_DIRECTORY.0 | FILE_READ_ATTRIBUTES.0,
        "open test runtime mirror catalog",
    )?;
    let base = CatalogDirectory { path: base.path, handle: base.handle };
    inspect_ready_mirror_under_catalog(requested_root, &base)
}

fn inspect_ready_mirror_under_catalog(
    requested_root: &Path,
    base: &CatalogDirectory,
) -> Result<WindowsBrowserRuntimeMirror, WindowsRuntimeMirrorError> {
    let root = validate_owned_mirror_root_under_base(
        requested_root,
        base,
        FILE_LIST_DIRECTORY.0 | FILE_READ_ATTRIBUTES.0,
        RootShareMode::LeaseLocked,
    )?;
    let identity = handle_identity(&root.handle, &root.path)?;
    let tree = collect_mirror_entries_from_handle(&root)?;
    let executable_paths = tree.executable_paths;
    let manifest = parse_manifest_bytes(&read_manifest_bytes_from_handle(&root)?)
        .map_err(|reason| invalid_existing(&root.path, reason))?;
    if root.path.file_name().and_then(|name| name.to_str()) != Some(manifest.key.as_str()) {
        return Err(invalid_existing(
            &root.path,
            "readiness manifest key does not match the mirror directory",
        ));
    }
    let kind = browser_kind_from_name(&manifest.browser_kind).ok_or_else(|| {
        invalid_existing(&root.path, "readiness manifest browser kind is invalid")
    })?;
    if kind == BrowserKind::Firefox {
        return Err(invalid_existing(
            &root.path,
            "Firefox is not a supported Chromium runtime mirror",
        ));
    }
    let mut matching_main = executable_paths.iter().filter(|path| {
        path.strip_prefix(&root.path)
            .ok()
            .is_some_and(|relative| hash_path(relative) == manifest.binary_relative_hash)
    });
    let main = matching_main.next().cloned().ok_or_else(|| {
        invalid_existing(
            &root.path,
            "readiness manifest main executable is absent from the mirror",
        )
    })?;
    if matching_main.next().is_some() {
        return Err(invalid_existing(
            &root.path,
            "readiness manifest main executable path is ambiguous",
        ));
    }
    Ok(WindowsBrowserRuntimeMirror {
        browser_binary: BrowserBinary { path: main, kind },
        root: root.path,
        executable_paths,
        identity,
        materialization_mode: manifest.materialization_mode,
        _lease_locks: tree.entry_locks,
    })
}

fn read_manifest_bytes_from_handle(
    root: &OpenDirectory,
) -> Result<Vec<u8>, WindowsRuntimeMirrorError> {
    let manifest_path = root.path.join(READY_MANIFEST);
    let handle = open_relative(
        &root.handle,
        OsStr::new(READY_MANIFEST),
        windows::Win32::Storage::FileSystem::FILE_READ_DATA.0 | FILE_READ_ATTRIBUTES.0,
        false,
        FILE_OPEN,
        &manifest_path,
        "open runtime mirror readiness manifest",
    )?;
    let information = handle_information(&handle, &manifest_path, "inspect readiness manifest")?;
    let length = ((information.nFileSizeHigh as u64) << 32) | information.nFileSizeLow as u64;
    if length > MAX_MANIFEST_BYTES {
        return Err(invalid_existing(
            &root.path,
            "readiness manifest is not a small regular file",
        ));
    }
    let mut file = unsafe { File::from_raw_handle(handle.into_raw_handle()) };
    let mut bytes = Vec::with_capacity(length as usize);
    file.read_to_end(&mut bytes).map_err(|source| {
        invalid_existing(&root.path, format!("cannot read readiness manifest: {source}"))
    })?;
    if bytes.len() as u64 != length || bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(invalid_existing(&root.path, "readiness manifest changed while reading"));
    }
    Ok(bytes)
}

#[cfg(test)]
fn collect_mirror_executables(
    root: &Path,
) -> Result<Vec<PathBuf>, WindowsRuntimeMirrorError> {
    let directory = open_verified_directory(
        root,
        FILE_LIST_DIRECTORY.0 | FILE_READ_ATTRIBUTES.0,
        "open runtime mirror root",
    )?;
    Ok(collect_mirror_entries_from_handle(&directory)?.executable_paths)
}

struct MirrorTreeInspection {
    executable_paths: Vec<PathBuf>,
    entry_locks: Vec<OwnedHandle>,
}

fn collect_mirror_entries_from_handle(
    root: &OpenDirectory,
) -> Result<MirrorTreeInspection, WindowsRuntimeMirrorError> {
    let mut entry_locks = vec![duplicate_handle(&root.handle, &root.path)?];
    let mut pending = vec![(0usize, PathBuf::new(), 0usize)];
    let mut executable_paths = Vec::new();
    while let Some((depth, relative, directory_index)) = pending.pop() {
        if depth > MAX_MIRROR_DEPTH || entry_locks.len() > MAX_MIRROR_ENTRIES {
            return Err(invalid_existing(
                &root.path,
                "runtime mirror tree exceeds inspection bounds",
            ));
        }
        let path = root.path.join(&relative);
        for entry in enumerate_directory(&entry_locks[directory_index], &path)? {
            if entry_locks.len() == MAX_MIRROR_ENTRIES {
                return Err(invalid_existing(
                    &root.path,
                    "runtime mirror tree exceeds inspection bounds",
                ));
            }
            let child_relative = relative.join(&entry.name);
            let child_path = root.path.join(&child_relative);
            let is_directory = entry.attributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0;
            let child = open_relative_lease(
                &entry_locks[directory_index],
                &entry.name,
                (FILE_LIST_DIRECTORY.0 * u32::from(is_directory)) | FILE_READ_ATTRIBUTES.0,
                is_directory,
                &child_path,
                "lease-lock runtime mirror entry",
            )?;
            if handle_identity(&child, &child_path)?.index != entry.file_id {
                return Err(invalid_existing(&root.path, "mirror entry changed during inspection"));
            }
            let child_index = entry_locks.len();
            entry_locks.push(child);
            if is_directory {
                pending.push((depth + 1, child_relative, child_index));
            } else if is_executable_path(&child_path) {
                if executable_paths.len() == MAX_MIRROR_EXECUTABLES {
                    return Err(invalid_existing(
                        &root.path,
                        format!(
                            "mirror contains more than {MAX_MIRROR_EXECUTABLES} executable files"
                        ),
                    ));
                }
                executable_paths.push(child_path);
            }
        }
    }
    executable_paths.sort_by(|left, right| {
        normalized_windows_path(left).cmp(&normalized_windows_path(right))
    });
    executable_paths.dedup_by(|left, right| {
        normalized_windows_path(left) == normalized_windows_path(right)
    });
    Ok(MirrorTreeInspection {
        executable_paths,
        entry_locks,
    })
}

fn is_executable_path(path: &Path) -> bool {
    path.extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
}

fn invalid_existing(root: &Path, reason: impl Into<String>) -> WindowsRuntimeMirrorError {
    WindowsRuntimeMirrorError::ExistingMirrorInvalid {
        path: root.to_path_buf(),
        reason: reason.into(),
    }
}

fn remove_validated_mirror_tree(
    root: &Path,
    expected_identity: FileIdentity,
) -> Result<(), WindowsRuntimeMirrorError> {
    let base = existing_mirror_base()?;
    remove_validated_mirror_tree_under_catalog(root, &base, Some(expected_identity))
}

async fn remove_runtime_mirror_with_retry(
    token: RuntimeMirrorRemovalToken,
    catalog: RuntimeMirrorCatalog,
    max_wait: Duration,
) -> Result<WindowsRuntimeMirrorRemovalReport, WindowsRuntimeMirrorError> {
    let started = tokio::time::Instant::now();
    let mut report = WindowsRuntimeMirrorRemovalReport {
        attempts: 0,
        waited: Duration::ZERO,
    };
    loop {
        report.attempts = report.attempts.saturating_add(1);
        let attempt_token = token.clone();
        let attempt_catalog = catalog.clone();
        let attempt = tokio::task::spawn_blocking(move || {
            remove_runtime_mirror_once(&attempt_token, &attempt_catalog)
        })
        .await
        .map_err(WindowsRuntimeMirrorError::RemovalWorker)?;
        match attempt {
            Ok(()) => return Ok(report),
            Err(RuntimeMirrorRemovalAttemptError::Fatal(error)) => return Err(error),
            Err(RuntimeMirrorRemovalAttemptError::RetryableSharing(error)) => {
                let remaining = max_wait.saturating_sub(started.elapsed());
                if remaining.is_zero() {
                    return Err(WindowsRuntimeMirrorError::RemovalRetryExhausted {
                        attempts: report.attempts,
                        waited: report.waited,
                        source: Box::new(error),
                    });
                }
                let delay = REMOVAL_RETRY_INTERVAL.min(remaining);
                tokio::time::sleep(delay).await;
                report.waited = report.waited.saturating_add(delay);
            }
        }
    }
}

fn remove_runtime_mirror_once(
    token: &RuntimeMirrorRemovalToken,
    catalog: &RuntimeMirrorCatalog,
) -> Result<(), RuntimeMirrorRemovalAttemptError> {
    let inspected = match catalog {
        RuntimeMirrorCatalog::StationOwned => WindowsBrowserRuntimeMirror::inspect(&token.root),
        #[cfg(test)]
        RuntimeMirrorCatalog::Test(base) => inspect_ready_mirror_under_base(&token.root, base),
    }
    .map_err(RuntimeMirrorRemovalAttemptError::Fatal)?;
    token
        .validate_inspection(&inspected)
        .map_err(RuntimeMirrorRemovalAttemptError::Fatal)?;
    drop(inspected);

    let result = match catalog {
        RuntimeMirrorCatalog::StationOwned => {
            remove_validated_mirror_tree(&token.root, token.identity)
        }
        #[cfg(test)]
        RuntimeMirrorCatalog::Test(base) => {
            let base = open_verified_directory(
                base,
                FILE_LIST_DIRECTORY.0 | FILE_READ_ATTRIBUTES.0,
                "open test runtime mirror catalog",
            )
            .map_err(RuntimeMirrorRemovalAttemptError::Fatal)?;
            let base = CatalogDirectory {
                path: base.path,
                handle: base.handle,
            };
            remove_validated_mirror_tree_under_catalog(
                &token.root,
                &base,
                Some(token.identity),
            )
        }
    };
    result.map_err(|error| {
        if is_pre_mutation_removal_sharing_violation(&error) {
            RuntimeMirrorRemovalAttemptError::RetryableSharing(error)
        } else {
            RuntimeMirrorRemovalAttemptError::Fatal(error)
        }
    })
}

fn is_pre_mutation_removal_sharing_violation(error: &WindowsRuntimeMirrorError) -> bool {
    const ROOT_LOCK: &str = "lock station-owned runtime mirror root";
    const ENTRY_LOCK: &str = "lock runtime mirror entry for removal";
    match error {
        WindowsRuntimeMirrorError::WindowsNt {
            operation,
            status: STATUS_SHARING_VIOLATION,
            ..
        } => matches!(*operation, ROOT_LOCK | ENTRY_LOCK),
        WindowsRuntimeMirrorError::Windows {
            operation,
            source,
            ..
        } => {
            matches!(*operation, ROOT_LOCK | ENTRY_LOCK)
                && source.code().0 == HRESULT_SHARING_VIOLATION
        }
        _ => false,
    }
}

#[cfg(test)]
fn remove_validated_mirror_tree_under_base(
    root: &Path,
    base: &Path,
) -> Result<(), WindowsRuntimeMirrorError> {
    let base = open_verified_directory(
        base,
        FILE_LIST_DIRECTORY.0 | FILE_READ_ATTRIBUTES.0,
        "open test runtime mirror catalog",
    )?;
    let base = CatalogDirectory { path: base.path, handle: base.handle };
    remove_validated_mirror_tree_under_catalog(root, &base, None)
}

#[derive(Debug)]
struct RemovalEntry {
    depth: usize,
    path: PathBuf,
    handle: OwnedHandle,
    directory: bool,
}

fn remove_validated_mirror_tree_under_catalog(
    root: &Path,
    base: &CatalogDirectory,
    expected_identity: Option<FileIdentity>,
) -> Result<(), WindowsRuntimeMirrorError> {
    let root = validate_owned_mirror_root_under_base(
        root,
        base,
        FILE_LIST_DIRECTORY.0 | FILE_READ_ATTRIBUTES.0 | DELETE_ACCESS,
        RootShareMode::DeleteLocked,
    )?;
    let identity = handle_identity(&root.handle, &root.path)?;
    if expected_identity.is_some_and(|expected| expected != identity) {
        return Err(invalid_existing(&root.path, "runtime mirror identity changed before removal"));
    }
    let manifest = parse_manifest_bytes(&read_manifest_bytes_from_handle(&root)?)
        .map_err(|reason| invalid_existing(&root.path, reason))?;
    if root.path.file_name().and_then(|name| name.to_str()) != Some(manifest.key.as_str()) {
        return Err(invalid_existing(&root.path, "manifest key does not own this mirror root"));
    }
    remove_open_tree(root)
}

fn remove_open_tree(root: OpenDirectory) -> Result<(), WindowsRuntimeMirrorError> {
    let root_identity = handle_identity(&root.handle, &root.path)?;
    let mut pending = vec![(0usize, PathBuf::new(), duplicate_handle(&root.handle, &root.path)?)];
    let mut removals = Vec::new();
    while let Some((depth, relative, directory_handle)) = pending.pop() {
        if depth > MAX_MIRROR_DEPTH || removals.len() > MAX_MIRROR_ENTRIES {
            return Err(invalid_existing(&root.path, "runtime mirror tree exceeds removal bounds"));
        }
        let directory_path = root.path.join(&relative);
        for entry in enumerate_directory(&directory_handle, &directory_path)? {
            if removals.len() == MAX_MIRROR_ENTRIES {
                return Err(invalid_existing(&root.path, "runtime mirror tree exceeds removal bounds"));
            }
            let child_relative = relative.join(&entry.name);
            let child_path = root.path.join(&child_relative);
            let is_directory = entry.attributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0;
            let child = open_relative_locked(
                &directory_handle,
                &entry.name,
                (FILE_LIST_DIRECTORY.0 * u32::from(is_directory))
                    | FILE_READ_ATTRIBUTES.0
                    | DELETE_ACCESS,
                is_directory,
                &child_path,
                "lock runtime mirror entry for removal",
            )?;
            if handle_identity(&child, &child_path)?.index != entry.file_id {
                return Err(invalid_existing(&root.path, "runtime mirror changed during removal validation"));
            }
            if is_directory {
                pending.push((depth + 1, child_relative, duplicate_handle(&child, &child_path)?));
            }
            removals.push(RemovalEntry {
                depth: depth + 1,
                path: child_path,
                handle: child,
                directory: is_directory,
            });
        }
    }
    if handle_identity(&root.handle, &root.path)? != root_identity {
        return Err(invalid_existing(&root.path, "runtime mirror root changed during removal validation"));
    }
    removals.sort_by(|left, right| {
        left.directory.cmp(&right.directory)
            .then_with(|| right.depth.cmp(&left.depth))
            .then_with(|| normalized_windows_path(&right.path).cmp(&normalized_windows_path(&left.path)))
    });
    for entry in removals {
        delete_open_handle(&entry.handle, &entry.path)?;
    }
    delete_open_handle(&root.handle, &root.path)
}

fn cleanup_owned_staging(
    base: &CatalogDirectory,
    staging: &OpenDirectory,
) -> Result<(), WindowsRuntimeMirrorError> {
    if !is_owned_staging_path(&base.path, &staging.path) {
        return Err(invalid_existing(
            &staging.path,
            "runtime mirror staging directory escaped the owned catalog",
        ));
    }
    let handle = duplicate_handle(&staging.handle, &staging.path)?;
    remove_open_tree(OpenDirectory {
        path: staging.path.clone(),
        handle,
    })
}

fn is_owned_staging_path(base: &Path, staging: &Path) -> bool {
    staging.parent() == Some(base)
        && staging.file_name().is_some_and(|name| {
            name.to_string_lossy().starts_with(".staging-")
                && !name.to_string_lossy().contains(['/', '\\'])
        })
}

fn validate_relative_path(path: &Path) -> Result<(), WindowsRuntimeMirrorError> {
    use std::path::Component;
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(component, Component::Prefix(_) | Component::RootDir | Component::ParentDir)
        })
    {
        return Err(WindowsRuntimeMirrorError::InvalidRelativePath {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn open_verified_directory(
    path: &Path,
    desired_access: u32,
    operation: &'static str,
) -> Result<OpenDirectory, WindowsRuntimeMirrorError> {
    let wide = wide_nul(path)?;
    let share = FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0);
    let flags = FILE_FLAGS_AND_ATTRIBUTES(
        FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0,
    );
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            desired_access,
            share,
            None,
            OPEN_EXISTING,
            flags,
            HANDLE::default(),
        )
        .map_err(|source| WindowsRuntimeMirrorError::Windows {
            operation,
            path: path.to_path_buf(),
            source,
        })?
    };
    let handle = OwnedHandle(handle);
    let information = handle_information(&handle, path, operation)?;
    ensure_handle_type(&information, true, path)?;
    let final_path = final_path_for_handle(&handle, path)?;
    if normalized_windows_path(path) != normalized_windows_path(&final_path) {
        return Err(WindowsRuntimeMirrorError::ReparsePoint {
            path: path.to_path_buf(),
        });
    }
    Ok(OpenDirectory {
        path: final_path,
        handle,
    })
}

fn create_or_open_relative_directory(
    parent: &OwnedHandle,
    name: &OsStr,
    path: &Path,
) -> Result<OwnedHandle, WindowsRuntimeMirrorError> {
    open_relative_with_share(
        parent,
        name,
        RelativeOpen {
            desired_access: FILE_LIST_DIRECTORY.0
                | FILE_ADD_FILE.0
                | FILE_ADD_SUBDIRECTORY.0
                | FILE_READ_ATTRIBUTES.0
                | READ_CONTROL.0
                | WRITE_DAC.0,
            expect_directory: true,
            disposition: FILE_OPEN_IF,
            share_write: true,
            share_delete: false,
            path,
            operation: "create or open runtime mirror directory",
        },
    )
}

fn set_runtime_app_package_acl(
    handle: &OwnedHandle,
    path: &Path,
    access: u32,
    inherit_descendants: bool,
) -> Result<(), WindowsRuntimeMirrorError> {
    let all_app_packages = LocalSid::from_string("S-1-15-2-1", path)?;
    let all_restricted_app_packages = LocalSid::from_string("S-1-15-2-2", path)?;
    let mut entries = [EXPLICIT_ACCESS_W::default(); 2];
    for (entry, sid) in entries.iter_mut().zip([
        all_app_packages.value,
        all_restricted_app_packages.value,
    ]) {
        entry.grfAccessPermissions = access;
        entry.grfAccessMode = SET_ACCESS;
        entry.grfInheritance = if inherit_descendants {
            SUB_CONTAINERS_AND_OBJECTS_INHERIT
        } else {
            ACE_FLAGS(0)
        };
        unsafe {
            BuildTrusteeWithSidW(&mut entry.Trustee, sid);
        }
    }

    let mut old_acl: *mut ACL = std::ptr::null_mut();
    let mut security_descriptor = PSECURITY_DESCRIPTOR::default();
    let status = unsafe {
        GetSecurityInfo(
            handle.0,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut old_acl),
            None,
            Some(&mut security_descriptor),
        )
    };
    let _security_descriptor = LocalAllocation(HLOCAL(security_descriptor.0));
    ensure_win32_status(status.0, path, "read runtime mirror directory ACL")?;
    if old_acl.is_null() {
        return Err(invalid_existing(
            path,
            "runtime mirror directory has a NULL DACL",
        ));
    }

    let mut new_acl: *mut ACL = std::ptr::null_mut();
    let status = unsafe {
        SetEntriesInAclW(
            Some(&entries),
            (!old_acl.is_null()).then_some(old_acl as *const ACL),
            &mut new_acl,
        )
    };
    let _new_acl = LocalAllocation(HLOCAL(new_acl.cast()));
    ensure_win32_status(status.0, path, "build runtime mirror directory ACL")?;
    if new_acl.is_null() {
        return Err(invalid_existing(
            path,
            "runtime mirror ACL builder returned a NULL DACL",
        ));
    }

    let status = unsafe {
        SetSecurityInfo(
            handle.0,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            PSID::default(),
            PSID::default(),
            Some(new_acl as *const ACL),
            None,
        )
    };
    ensure_win32_status(status.0, path, "set runtime mirror directory ACL")
}

fn ensure_win32_status(
    status: u32,
    path: &Path,
    operation: &'static str,
) -> Result<(), WindowsRuntimeMirrorError> {
    if status == ERROR_SUCCESS.0 {
        return Ok(());
    }
    Err(WindowsRuntimeMirrorError::Io {
        operation,
        path: path.to_path_buf(),
        source: io::Error::from_raw_os_error(status as i32),
    })
}

fn open_relative(
    parent: &OwnedHandle,
    name: &OsStr,
    desired_access: u32,
    expect_directory: bool,
    disposition: u32,
    path: &Path,
    operation: &'static str,
) -> Result<OwnedHandle, WindowsRuntimeMirrorError> {
    open_relative_with_share(
        parent,
        name,
        RelativeOpen {
            desired_access,
            expect_directory,
            disposition,
            share_write: true,
            share_delete: true,
            path,
            operation,
        },
    )
}

fn open_relative_without_write_share(
    parent: &OwnedHandle,
    name: &OsStr,
    desired_access: u32,
    path: &Path,
    operation: &'static str,
) -> Result<OwnedHandle, WindowsRuntimeMirrorError> {
    open_relative_with_share(
        parent,
        name,
        RelativeOpen {
            desired_access,
            expect_directory: false,
            disposition: FILE_OPEN,
            share_write: false,
            share_delete: true,
            path,
            operation,
        },
    )
}

fn open_relative_locked(
    parent: &OwnedHandle,
    name: &OsStr,
    desired_access: u32,
    expect_directory: bool,
    path: &Path,
    operation: &'static str,
) -> Result<OwnedHandle, WindowsRuntimeMirrorError> {
    open_relative_with_share(
        parent,
        name,
        RelativeOpen {
            desired_access,
            expect_directory,
            disposition: FILE_OPEN,
            share_write: true,
            share_delete: false,
            path,
            operation,
        },
    )
}

fn open_relative_lease(
    parent: &OwnedHandle,
    name: &OsStr,
    desired_access: u32,
    expect_directory: bool,
    path: &Path,
    operation: &'static str,
) -> Result<OwnedHandle, WindowsRuntimeMirrorError> {
    open_relative_with_share(
        parent,
        name,
        RelativeOpen {
            desired_access,
            expect_directory,
            disposition: FILE_OPEN,
            share_write: false,
            share_delete: false,
            path,
            operation,
        },
    )
}

struct RelativeOpen<'a> {
    desired_access: u32,
    expect_directory: bool,
    disposition: u32,
    share_write: bool,
    share_delete: bool,
    path: &'a Path,
    operation: &'static str,
}

fn open_relative_with_share(
    parent: &OwnedHandle,
    name: &OsStr,
    options: RelativeOpen<'_>,
) -> Result<OwnedHandle, WindowsRuntimeMirrorError> {
    let RelativeOpen {
        desired_access,
        expect_directory,
        disposition,
        share_write,
        share_delete,
        path,
        operation,
    } = options;
    let mut name = simple_name_wide(name, path)?;
    let byte_length = name.len().checked_mul(2).and_then(|value| u16::try_from(value).ok())
        .ok_or_else(|| WindowsRuntimeMirrorError::InvalidRelativePath {
            path: path.to_path_buf(),
        })?;
    let mut unicode = UnicodeString {
        length: byte_length,
        maximum_length: byte_length,
        buffer: name.as_mut_ptr(),
    };
    let mut attributes = ObjectAttributes {
        length: std::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: parent.0,
        object_name: &mut unicode,
        attributes: OBJ_CASE_INSENSITIVE,
        security_descriptor: std::ptr::null_mut(),
        security_quality_of_service: std::ptr::null_mut(),
    };
    let mut io_status = IoStatusBlock { status: 0, information: 0 };
    let mut handle = HANDLE::default();
    let type_option = if expect_directory {
        FILE_DIRECTORY_FILE
    } else {
        FILE_NON_DIRECTORY_FILE
    };
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            desired_access | SYNCHRONIZE_ACCESS,
            &mut attributes,
            &mut io_status,
            std::ptr::null_mut(),
            0,
            FILE_SHARE_READ.0
                | (FILE_SHARE_WRITE.0 * u32::from(share_write))
                | (FILE_SHARE_DELETE.0 * u32::from(share_delete)),
            disposition,
            type_option | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT_OPTION,
            std::ptr::null_mut(),
            0,
        )
    };
    if status < 0 {
        return Err(WindowsRuntimeMirrorError::WindowsNt {
            operation,
            path: path.to_path_buf(),
            status,
        });
    }
    let handle = OwnedHandle(handle);
    let information = handle_information(&handle, path, operation)?;
    ensure_handle_type(&information, expect_directory, path)?;
    Ok(handle)
}

fn simple_name_wide(name: &OsStr, path: &Path) -> Result<Vec<u16>, WindowsRuntimeMirrorError> {
    let wide = name.encode_wide().collect::<Vec<_>>();
    if wide.is_empty()
        || wide.contains(&0)
        || wide.contains(&('/' as u16))
        || wide.contains(&('\\' as u16))
        || wide == ['.' as u16]
        || wide == ['.' as u16, '.' as u16]
    {
        return Err(WindowsRuntimeMirrorError::InvalidRelativePath {
            path: path.to_path_buf(),
        });
    }
    Ok(wide)
}

fn handle_information(
    handle: &OwnedHandle,
    path: &Path,
    operation: &'static str,
) -> Result<BY_HANDLE_FILE_INFORMATION, WindowsRuntimeMirrorError> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    unsafe {
        GetFileInformationByHandle(handle.0, &mut information).map_err(|source| {
            WindowsRuntimeMirrorError::Windows {
                operation,
                path: path.to_path_buf(),
                source,
            }
        })?;
    }
    Ok(information)
}

fn ensure_handle_type(
    information: &BY_HANDLE_FILE_INFORMATION,
    expect_directory: bool,
    path: &Path,
) -> Result<(), WindowsRuntimeMirrorError> {
    if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Err(WindowsRuntimeMirrorError::ReparsePoint {
            path: path.to_path_buf(),
        });
    }
    let is_directory = information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0;
    if is_directory != expect_directory {
        return Err(WindowsRuntimeMirrorError::UnsupportedEntry {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn handle_identity(
    handle: &OwnedHandle,
    path: &Path,
) -> Result<FileIdentity, WindowsRuntimeMirrorError> {
    let information = handle_information(handle, path, "read runtime mirror file identity")?;
    Ok(FileIdentity {
        volume: information.dwVolumeSerialNumber,
        index: ((information.nFileIndexHigh as u64) << 32) | information.nFileIndexLow as u64,
    })
}

fn final_path_for_handle(
    handle: &OwnedHandle,
    path: &Path,
) -> Result<PathBuf, WindowsRuntimeMirrorError> {
    let mut buffer = vec![0u16; 512];
    loop {
        let length = unsafe {
            GetFinalPathNameByHandleW(
                handle.0,
                &mut buffer,
                GETFINALPATHNAMEBYHANDLE_FLAGS(FILE_NAME_NORMALIZED.0 | VOLUME_NAME_DOS.0),
            )
        } as usize;
        if length == 0 {
            return Err(WindowsRuntimeMirrorError::Windows {
                operation: "resolve opened runtime mirror path",
                path: path.to_path_buf(),
                source: windows::core::Error::from_win32(),
            });
        }
        if length < buffer.len() {
            return Ok(PathBuf::from(OsString::from_wide(&buffer[..length])));
        }
        buffer.resize(length + 1, 0);
    }
}

fn enumerate_directory(
    handle: &OwnedHandle,
    path: &Path,
) -> Result<Vec<DirectoryEntry>, WindowsRuntimeMirrorError> {
    let words = DIRECTORY_BUFFER_BYTES.div_ceil(std::mem::size_of::<u64>());
    let mut buffer = vec![0u64; words];
    let mut entries = Vec::new();
    let mut restart = true;
    loop {
        let information_class = if restart {
            FileIdBothDirectoryRestartInfo
        } else {
            FileIdBothDirectoryInfo
        };
        restart = false;
        let result = unsafe {
            GetFileInformationByHandleEx(
                handle.0,
                information_class,
                buffer.as_mut_ptr().cast(),
                DIRECTORY_BUFFER_BYTES as u32,
            )
        };
        if let Err(source) = result {
            if unsafe { GetLastError() } == ERROR_NO_MORE_FILES {
                break;
            }
            return Err(WindowsRuntimeMirrorError::Windows {
                operation: "enumerate runtime mirror directory handle",
                path: path.to_path_buf(),
                source,
            });
        }
        let mut offset = 0usize;
        loop {
            if offset + std::mem::size_of::<FILE_ID_BOTH_DIR_INFO>() > DIRECTORY_BUFFER_BYTES {
                return Err(invalid_existing(path, "directory enumeration returned a truncated entry"));
            }
            let record = unsafe {
                &*(buffer.as_ptr().cast::<u8>().add(offset).cast::<FILE_ID_BOTH_DIR_INFO>())
            };
            let name_offset = std::mem::offset_of!(FILE_ID_BOTH_DIR_INFO, FileName);
            let name_bytes = record.FileNameLength as usize;
            if name_bytes & 1 != 0 || offset + name_offset + name_bytes > DIRECTORY_BUFFER_BYTES {
                return Err(invalid_existing(path, "directory enumeration returned an invalid name"));
            }
            let name_units = unsafe {
                std::slice::from_raw_parts(
                    buffer.as_ptr().cast::<u8>().add(offset + name_offset).cast::<u16>(),
                    name_bytes / 2,
                )
            };
            let name = OsString::from_wide(name_units);
            if name_units != ['.' as u16] && name_units != ['.' as u16, '.' as u16] {
                let name_path = path.join(&name);
                simple_name_wide(&name, &name_path)?;
                if record.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
                    return Err(WindowsRuntimeMirrorError::ReparsePoint { path: name_path });
                }
                entries.push(DirectoryEntry {
                    name,
                    attributes: record.FileAttributes,
                    file_id: record.FileId as u64,
                });
            }
            if record.NextEntryOffset == 0 {
                break;
            }
            let next = record.NextEntryOffset as usize;
            if next < name_offset + name_bytes || offset + next >= DIRECTORY_BUFFER_BYTES {
                return Err(invalid_existing(path, "directory enumeration returned an invalid offset"));
            }
            offset += next;
        }
    }
    Ok(entries)
}

fn relative_exists(
    parent: &OwnedHandle,
    name: &OsStr,
    path: &Path,
) -> Result<bool, WindowsRuntimeMirrorError> {
    match open_relative(
        parent,
        name,
        FILE_READ_ATTRIBUTES.0,
        true,
        FILE_OPEN,
        path,
        "inspect runtime mirror target",
    ) {
        Ok(_) => Ok(true),
        Err(WindowsRuntimeMirrorError::WindowsNt { status, .. })
            if status == 0xC000_0034u32 as i32 || status == 0xC000_003Au32 as i32 => Ok(false),
        Err(error) => Err(error),
    }
}

fn duplicate_handle(
    handle: &OwnedHandle,
    path: &Path,
) -> Result<OwnedHandle, WindowsRuntimeMirrorError> {
    let process = unsafe { GetCurrentProcess() };
    let mut duplicate = HANDLE::default();
    unsafe {
        DuplicateHandle(
            process,
            handle.0,
            process,
            &mut duplicate,
            0,
            false,
            DUPLICATE_SAME_ACCESS,
        )
        .map_err(|source| WindowsRuntimeMirrorError::Windows {
            operation: "duplicate runtime mirror directory handle",
            path: path.to_path_buf(),
            source,
        })?;
    }
    Ok(OwnedHandle(duplicate))
}

fn set_relative_name(
    source: &OwnedHandle,
    target_parent: &OwnedHandle,
    target_name: &OsStr,
    target_path: &Path,
    information_class: u32,
    operation: &'static str,
) -> Result<(), WindowsRuntimeMirrorError> {
    let name = simple_name_wide(target_name, target_path)?;
    let name_bytes = name.len().checked_mul(2).and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| WindowsRuntimeMirrorError::InvalidRelativePath {
            path: target_path.to_path_buf(),
        })?;
    let name_offset = std::mem::offset_of!(RelativeNameHeader, file_name_length)
        + std::mem::size_of::<u32>();
    let byte_length = name_offset + name_bytes as usize;
    let words = byte_length.div_ceil(std::mem::size_of::<usize>());
    let mut buffer = vec![0usize; words];
    let header = buffer.as_mut_ptr().cast::<RelativeNameHeader>();
    unsafe {
        (*header).replace_if_exists = 0;
        (*header).root_directory = target_parent.0;
        (*header).file_name_length = name_bytes;
        std::ptr::copy_nonoverlapping(
            name.as_ptr(),
            buffer.as_mut_ptr().cast::<u8>().add(name_offset).cast::<u16>(),
            name.len(),
        );
    }
    let mut io_status = IoStatusBlock { status: 0, information: 0 };
    let status = unsafe {
        NtSetInformationFile(
            source.0,
            &mut io_status,
            buffer.as_mut_ptr().cast(),
            byte_length as u32,
            information_class,
        )
    };
    if status < 0 {
        return Err(WindowsRuntimeMirrorError::WindowsNt {
            operation,
            path: target_path.to_path_buf(),
            status,
        });
    }
    Ok(())
}

fn create_hard_link_relative(
    source: &OwnedHandle,
    target_parent: &OwnedHandle,
    target_name: &OsStr,
    target_path: &Path,
) -> Result<(), WindowsRuntimeMirrorError> {
    set_relative_name(
        source,
        target_parent,
        target_name,
        target_path,
        FILE_LINK_INFORMATION_CLASS,
        "hard-link runtime mirror file",
    )
}

fn rename_relative(
    source: &OwnedHandle,
    target_parent: &OwnedHandle,
    target_name: &OsStr,
    target_path: &Path,
) -> Result<(), WindowsRuntimeMirrorError> {
    set_relative_name(
        source,
        target_parent,
        target_name,
        target_path,
        FILE_RENAME_INFORMATION_CLASS,
        "atomically publish runtime mirror",
    )
}

fn delete_open_handle(
    handle: &OwnedHandle,
    path: &Path,
) -> Result<(), WindowsRuntimeMirrorError> {
    let disposition = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_INFO_EX_FLAGS(
            FILE_DISPOSITION_FLAG_DELETE.0 | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS.0,
        ),
    };
    unsafe {
        SetFileInformationByHandle(
            handle.0,
            FileDispositionInfoEx,
            (&disposition as *const FILE_DISPOSITION_INFO_EX).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        )
        .map_err(|source| WindowsRuntimeMirrorError::Windows {
            operation: "delete opened runtime mirror entry",
            path: path.to_path_buf(),
            source,
        })
    }
}

fn wide_nul(path: &Path) -> Result<Vec<u16>, WindowsRuntimeMirrorError> {
    let mut wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if wide.contains(&0) {
        return Err(WindowsRuntimeMirrorError::Io {
            operation: "encode Windows runtime mirror path",
            path: path.to_path_buf(),
            source: io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"),
        });
    }
    wide.push(0);
    Ok(wide)
}

fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    let bytes = bytes.as_ref();
    let mut output = String::with_capacity(bytes.len() * 2);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[derive(Debug)]
struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn into_raw_handle(mut self) -> RawHandle {
        let handle = self.0;
        self.0 = HANDLE::default();
        handle.0 as RawHandle
    }
}

struct LocalAllocation(HLOCAL);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = LocalFree(self.0);
            }
        }
    }
}

struct LocalSid {
    value: PSID,
    _allocation: LocalAllocation,
}

impl LocalSid {
    fn from_string(value: &str, path: &Path) -> Result<Self, WindowsRuntimeMirrorError> {
        let wide = value.encode_utf16().chain(std::iter::once(0)).collect::<Vec<_>>();
        let mut sid = PSID::default();
        unsafe {
            ConvertStringSidToSidW(PCWSTR(wide.as_ptr()), &mut sid).map_err(|source| {
                WindowsRuntimeMirrorError::Windows {
                    operation: "parse runtime mirror package SID",
                    path: path.to_path_buf(),
                    source,
                }
            })?;
        }
        Ok(Self {
            value: sid,
            _allocation: LocalAllocation(HLOCAL(sid.0)),
        })
    }
}

struct CoTaskMemWideString(PWSTR);

impl Drop for CoTaskMemWideString {
    fn drop(&mut self) {
        unsafe { CoTaskMemFree(Some(self.0.as_ptr().cast())) };
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn effective_package_rights(handle: &OwnedHandle, path: &Path, sid: &str) -> u32 {
        let sid = LocalSid::from_string(sid, path).expect("parse test package SID");
        let mut acl: *mut ACL = std::ptr::null_mut();
        let mut security_descriptor = PSECURITY_DESCRIPTOR::default();
        let status = unsafe {
            GetSecurityInfo(
                handle.0,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(&mut acl),
                None,
                Some(&mut security_descriptor),
            )
        };
        let _security_descriptor = LocalAllocation(HLOCAL(security_descriptor.0));
        assert_eq!(status.0, ERROR_SUCCESS.0, "read test file DACL");
        assert!(!acl.is_null(), "test file unexpectedly has a NULL DACL");

        let mut trustee = windows::Win32::Security::Authorization::TRUSTEE_W::default();
        unsafe {
            BuildTrusteeWithSidW(&mut trustee, sid.value);
        }
        let mut rights = 0u32;
        let status = unsafe {
            windows::Win32::Security::Authorization::GetEffectiveRightsFromAclW(
                acl,
                &trustee,
                &mut rights,
            )
        };
        assert_eq!(status.0, ERROR_SUCCESS.0, "read effective test package rights");
        rights
    }

    fn temporary_catalog() -> (PathBuf, PathBuf, String) {
        let nonce = uuid::Uuid::new_v4().to_string();
        let key = hex_digest(Sha256::digest(nonce.as_bytes()));
        let base = std::env::temp_dir()
            .join(format!("dig2browser-runtime-mirror-test-{nonce}"));
        fs::create_dir(&base).expect("create test mirror catalog");
        let base = fs::canonicalize(base).expect("canonicalize test mirror catalog");
        let root = base.join(&key);
        fs::create_dir(&root).expect("create test mirror root");
        (base, root, key)
    }

    fn write_test_manifest(root: &Path, key: String, main: &Path) {
        let manifest = ReadyManifest {
            schema: MIRROR_SCHEMA,
            key,
            source_fingerprint: "b".repeat(64),
            browser_kind: "chrome".to_owned(),
            browser_version: Some("126.0.0.1".to_owned()),
            binary_relative_hash: hash_path(main),
            materialization_mode: MaterializationMode::LegacyUnknown,
        };
        let mut manifest = serde_json::to_value(manifest).expect("serialize legacy test manifest");
        manifest
            .as_object_mut()
            .expect("legacy test manifest is an object")
            .remove("materialization_mode");
        fs::write(
            root.join(READY_MANIFEST),
            serde_json::to_vec(&manifest).expect("serialize test manifest"),
        )
        .expect("write test manifest");
    }

    fn create_junction(link: &Path, target: &Path) {
        let output = Command::new("cmd")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .output()
            .expect("execute junction creation");
        assert!(
            output.status.success(),
            "create junction failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn manifest() -> ReadyManifest {
        ReadyManifest {
            schema: MIRROR_SCHEMA,
            key: "a".repeat(64),
            source_fingerprint: "b".repeat(64),
            browser_kind: "edge".to_owned(),
            browser_version: Some("126.0.0.1".to_owned()),
            binary_relative_hash: "c".repeat(64),
            materialization_mode: MaterializationMode::HardLinkV1,
        }
    }

    #[test]
    fn normalized_paths_are_case_separator_and_verbatim_prefix_stable() {
        assert_eq!(
            normalized_windows_path(Path::new(r"\\?\C:\Profiles\Root\")),
            normalized_windows_path(Path::new("c:/profiles/root"))
        );
        assert_eq!(
            normalized_windows_path(Path::new(r"\\?\UNC\Server\Share\Runtime")),
            normalized_windows_path(Path::new(r"\\server\share\runtime"))
        );
    }

    #[test]
    fn mirror_key_is_stable_and_binds_profiles_source_version_and_metadata() {
        let first_scope = WindowsRuntimeMirrorScope::for_profiles_root(Path::new(
            r"C:\Profiles",
        ));
        let equivalent_scope = WindowsRuntimeMirrorScope::for_profiles_root(Path::new(
            "c:/profiles/",
        ));
        let first = mirror_key(
            first_scope,
            Path::new(r"C:\Chrome\Application\chrome.exe"),
            BrowserKind::Chrome,
            Some("126.0.0.1"),
            "metadata-a",
        );
        let equivalent = mirror_key(
            equivalent_scope,
            Path::new("c:/chrome/application/chrome.exe"),
            BrowserKind::Chrome,
            Some("126.0.0.1"),
            "metadata-a",
        );
        let changed = mirror_key(
            first_scope,
            Path::new(r"C:\Chrome\Application\chrome.exe"),
            BrowserKind::Chrome,
            Some("126.0.0.2"),
            "metadata-a",
        );
        assert_eq!(first, equivalent);
        assert_ne!(first, changed);
        assert_eq!(first.len(), 64);
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    #[test]
    fn manifest_validation_requires_an_exact_known_schema() {
        let expected = manifest();
        let bytes = serde_json::to_vec(&expected).unwrap();
        assert_eq!(validate_manifest_bytes(&bytes, &expected), Ok(()));

        let mut wrong = expected.clone();
        wrong.source_fingerprint = "d".repeat(64);
        assert!(validate_manifest_bytes(&bytes, &wrong).is_err());

        let with_unknown = String::from_utf8(bytes).unwrap().replace(
            "{",
            "{\"unexpected\":true,",
        );
        assert!(validate_manifest_bytes(with_unknown.as_bytes(), &expected).is_err());
    }

    #[test]
    fn legacy_manifest_without_materialization_mode_defaults_to_unknown() {
        let mut value = serde_json::to_value(manifest()).expect("serialize manifest value");
        value
            .as_object_mut()
            .expect("manifest is an object")
            .remove("materialization_mode");
        let bytes = serde_json::to_vec(&value).expect("serialize legacy manifest JSON");
        let parsed = parse_manifest_bytes(&bytes).expect("parse legacy manifest JSON");
        assert_eq!(
            parsed.materialization_mode,
            MaterializationMode::LegacyUnknown
        );
    }

    #[test]
    fn path_guards_reject_escape_and_non_child_staging_paths() {
        assert!(validate_relative_path(Path::new(r"126.0.0.1\chrome.dll")).is_ok());
        assert!(validate_relative_path(Path::new(r"..\outside")).is_err());
        assert!(validate_relative_path(Path::new(r"C:\outside")).is_err());

        let base = Path::new(r"C:\Local\dig2browser\runtime-mirrors");
        assert!(is_owned_staging_path(
            base,
            &base.join(".staging-key-1")
        ));
        assert!(!is_owned_staging_path(base, &base.join("key")));
        assert!(!is_owned_staging_path(
            base,
            Path::new(r"C:\Local\dig2browser\.staging-key-1")
        ));
    }

    #[test]
    fn ready_mirror_inspector_retains_sorted_complete_executable_inventory() {
        let (base, root, key) = temporary_catalog();
        let nested = root.join("126.0.0.1");
        fs::create_dir(&nested).expect("create nested runtime directory");
        fs::write(root.join("chrome.exe"), b"main").expect("write main executable");
        fs::write(nested.join("helper.EXE"), b"helper").expect("write helper executable");
        fs::write(nested.join("chrome.dll"), b"library").expect("write non-executable");
        write_test_manifest(&root, key, Path::new("chrome.exe"));

        let mirror = inspect_ready_mirror_under_base(&root, &base)
            .expect("inspect ready runtime mirror");
        assert_eq!(mirror.browser_binary.path, root.join("chrome.exe"));
        assert_eq!(mirror.browser_binary.kind, BrowserKind::Chrome);
        assert_eq!(mirror.executable_paths.len(), 2);
        assert!(mirror
            .executable_paths
            .iter()
            .any(|path| path == &root.join("chrome.exe")));
        assert!(mirror
            .executable_paths
            .iter()
            .any(|path| path == &nested.join("helper.EXE")));
        assert!(mirror.executable_paths.windows(2).all(|paths| {
            normalized_windows_path(&paths[0]) < normalized_windows_path(&paths[1])
        }));

        drop(mirror);
        assert!(root.exists(), "Drop unexpectedly removed the runtime mirror");
        remove_validated_mirror_tree_under_base(&root, &base)
            .expect("explicitly remove ready runtime mirror");
        assert!(!root.exists());
        fs::remove_dir(&base).expect("remove empty test mirror catalog");
    }

    #[test]
    fn executable_inventory_fails_closed_above_bound() {
        let (base, root, _) = temporary_catalog();
        for index in 0..=MAX_MIRROR_EXECUTABLES {
            fs::write(root.join(format!("helper-{index}.exe")), b"exe")
                .expect("write bounded executable fixture");
        }
        let error = collect_mirror_executables(&root)
            .expect_err("oversized executable inventory must fail closed");
        assert!(error.to_string().contains("more than 64 executable files"));
        fs::remove_dir_all(&base).expect("remove oversized mirror fixture");
    }

    #[test]
    fn handle_relative_materialization_creates_only_the_opened_staging_tree() {
        let nonce = uuid::Uuid::new_v4().to_string();
        let root = std::env::current_dir().expect("read current directory").join("target").join(format!(
            "dig2browser-runtime-mirror-materialize-{nonce}"
        ));
        let source_path = root.join("source");
        let base_path = root.join("catalog");
        fs::create_dir_all(source_path.join("version")).expect("create source tree");
        fs::create_dir(&base_path).expect("create materialization catalog");
        fs::write(source_path.join("chrome.exe"), b"main").expect("write source executable");
        fs::write(source_path.join("version").join("chrome.dll"), b"library")
            .expect("write source library");
        let source = open_verified_directory(
            &source_path,
            FILE_LIST_DIRECTORY.0 | FILE_READ_ATTRIBUTES.0,
            "open test source",
        ).expect("open source by handle");
        let entries = collect_source_tree(source).expect("collect source by handles");
        let base = open_verified_directory(
            &base_path,
            FILE_LIST_DIRECTORY.0 | FILE_READ_ATTRIBUTES.0,
            "open test catalog",
        ).expect("open catalog by handle");
        let base = CatalogDirectory { path: base.path, handle: base.handle };
        let staging = create_staging_directory(&base, &"a".repeat(64))
            .expect("create staging relative to catalog handle");
        populate_staging(&entries, &staging, MaterializationMode::HardLinkV1)
            .expect("populate staging with handle-relative links");
        assert_eq!(
            fs::read(staging.path.join("chrome.exe")).expect("read staged executable"),
            b"main"
        );
        assert_eq!(
            fs::read(staging.path.join("version").join("chrome.dll"))
                .expect("read staged library"),
            b"library"
        );
        let cleanup_handle = duplicate_handle(&staging.handle, &staging.path)
            .expect("duplicate staging cleanup handle");
        remove_open_tree(OpenDirectory {
            path: staging.path.clone(),
            handle: cleanup_handle,
        }).expect("remove opened staging tree");
        let staging_path = staging.path.clone();
        drop(staging);
        assert!(!staging_path.exists(), "owned staging tree survived cleanup");
        drop(entries);
        drop(base);
        fs::remove_dir_all(&root).expect("remove materialization fixture");
    }

    #[test]
    fn published_root_requires_staging_handle_close_before_lease_open() {
        let nonce = uuid::Uuid::new_v4().to_string();
        let base_path = std::env::current_dir()
            .expect("read current directory")
            .join("target")
            .join(format!("dig2browser-runtime-mirror-publish-{nonce}"));
        fs::create_dir_all(&base_path).expect("create publish test catalog");
        let base = open_verified_directory(
            &base_path,
            FILE_LIST_DIRECTORY.0 | FILE_ADD_SUBDIRECTORY.0 | FILE_READ_ATTRIBUTES.0,
            "open publish test catalog",
        )
        .expect("open publish test catalog by handle");
        let base = CatalogDirectory {
            path: base.path,
            handle: base.handle,
        };
        let staging = create_staging_directory(&base, &"d".repeat(64))
            .expect("create publish test staging");
        let target_name = "e".repeat(64);
        let target = base.path.join(&target_name);
        rename_relative(
            &staging.handle,
            &base.handle,
            OsStr::new(&target_name),
            &target,
        )
        .expect("rename publish test staging");

        assert!(
            open_relative_lease(
                &base.handle,
                OsStr::new(&target_name),
                FILE_LIST_DIRECTORY.0 | FILE_READ_ATTRIBUTES.0,
                true,
                &target,
                "lease-lock published test root",
            )
            .is_err(),
            "write-capable staging handle unexpectedly allowed a share-read-only lease"
        );
        drop(staging);

        let lease = open_relative_lease(
            &base.handle,
            OsStr::new(&target_name),
            FILE_LIST_DIRECTORY.0 | FILE_READ_ATTRIBUTES.0,
            true,
            &target,
            "lease-lock published test root",
        )
        .expect("open lease after closing staging handle");
        drop(lease);
        let cleanup = open_relative_locked(
            &base.handle,
            OsStr::new(&target_name),
            FILE_LIST_DIRECTORY.0 | FILE_READ_ATTRIBUTES.0 | DELETE_ACCESS,
            true,
            &target,
            "open published test root for cleanup",
        )
        .expect("open published test root for cleanup");
        remove_open_tree(OpenDirectory {
            path: target,
            handle: cleanup,
        })
        .expect("remove published test root");
        drop(base);
        fs::remove_dir(&base_path).expect("remove publish test catalog");
    }

    #[test]
    fn copy_materialization_is_detached_from_the_locked_source_snapshot() {
        let nonce = uuid::Uuid::new_v4().to_string();
        let root = std::env::current_dir().expect("read current directory").join("target").join(format!(
            "dig2browser-runtime-mirror-copy-{nonce}"
        ));
        let source_path = root.join("source");
        let base_path = root.join("catalog");
        fs::create_dir_all(&source_path).expect("create copy source tree");
        fs::create_dir(&base_path).expect("create copy catalog");
        fs::write(source_path.join("chrome.exe"), b"main")
            .expect("write copy source executable");
        let source = open_verified_directory(
            &source_path,
            FILE_LIST_DIRECTORY.0 | FILE_READ_ATTRIBUTES.0,
            "open copy test source",
        ).expect("open copy source by handle");
        let entries = collect_source_tree(source).expect("collect locked copy source");
        assert!(
            fs::write(source_path.join("chrome.exe"), b"edit").is_err(),
            "source file remained writable while snapshot handle denied write sharing"
        );

        let base = open_verified_directory(
            &base_path,
            FILE_LIST_DIRECTORY.0 | FILE_READ_ATTRIBUTES.0,
            "open copy test catalog",
        ).expect("open copy catalog by handle");
        let base = CatalogDirectory { path: base.path, handle: base.handle };
        let staging = create_staging_directory(&base, &"b".repeat(64))
            .expect("create copy staging relative to catalog handle");
        populate_staging(&entries, &staging, MaterializationMode::CopyV1)
            .expect("populate staging with verified copies");

        let source_entry = entries
            .iter()
            .find(|entry| entry.relative == Path::new("chrome.exe"))
            .expect("find source executable entry");
        let target_path = staging.path.join("chrome.exe");
        let target = open_relative(
            &staging.handle,
            OsStr::new("chrome.exe"),
            FILE_READ_ATTRIBUTES.0,
            false,
            FILE_OPEN,
            &target_path,
            "open copied executable",
        ).expect("open copied executable by handle");
        assert_ne!(
            source_entry.identity,
            handle_identity(&target, &target_path).expect("read copied executable identity"),
            "copy unexpectedly reused the source file identity"
        );
        drop(target);
        drop(entries);

        fs::write(source_path.join("chrome.exe"), b"edit")
            .expect("mutate source after releasing snapshot handles");
        assert_eq!(
            fs::read(&target_path).expect("read detached copied executable"),
            b"main"
        );

        let cleanup_handle = duplicate_handle(&staging.handle, &staging.path)
            .expect("duplicate copy staging cleanup handle");
        remove_open_tree(OpenDirectory {
            path: staging.path.clone(),
            handle: cleanup_handle,
        }).expect("remove copied staging tree");
        drop(staging);
        drop(base);
        fs::remove_dir_all(&root).expect("remove copy materialization fixture");
    }

    #[test]
    fn copy_acl_reaches_already_created_nested_file_for_both_package_groups() {
        let nonce = uuid::Uuid::new_v4().to_string();
        let base_path = std::env::current_dir()
            .expect("read current directory")
            .join("target")
            .join(format!("dig2browser-runtime-mirror-copy-acl-{nonce}"));
        fs::create_dir_all(&base_path).expect("create copy ACL test catalog");
        let base = open_verified_directory(
            &base_path,
            FILE_LIST_DIRECTORY.0 | FILE_ADD_SUBDIRECTORY.0 | FILE_READ_ATTRIBUTES.0,
            "open copy ACL test catalog",
        )
        .expect("open copy ACL test catalog by handle");
        let base = CatalogDirectory {
            path: base.path,
            handle: base.handle,
        };
        let staging = create_staging_directory(&base, &"c".repeat(64))
            .expect("create copy ACL staging");
        let nested_path = staging.path.join("version");
        let file_path = nested_path.join("chrome.dll");
        fs::create_dir(&nested_path).expect("create nested copied directory");
        fs::write(&file_path, b"copied library").expect("create nested copied file");

        apply_staging_acl(&staging, MaterializationMode::CopyV1)
            .expect("apply copied runtime ACLs");

        let nested = open_relative(
            &staging.handle,
            OsStr::new("version"),
            FILE_LIST_DIRECTORY.0 | FILE_READ_ATTRIBUTES.0,
            true,
            FILE_OPEN,
            &nested_path,
            "open nested copied directory for ACL test",
        )
        .expect("open nested copied directory");
        let file = open_relative(
            &nested,
            OsStr::new("chrome.dll"),
            FILE_READ_ATTRIBUTES.0 | READ_CONTROL.0,
            false,
            FILE_OPEN,
            &file_path,
            "open nested copied file for ACL test",
        )
        .expect("open nested copied file");
        let required = FILE_GENERIC_READ.0 | FILE_GENERIC_EXECUTE.0;
        for sid in ["S-1-15-2-1", "S-1-15-2-2"] {
            let effective = effective_package_rights(&file, &file_path, sid);
            assert_eq!(
                effective & required,
                required,
                "nested copied file omitted required package rights for {sid}"
            );
        }

        drop(file);
        drop(nested);
        let cleanup_handle = duplicate_handle(&staging.handle, &staging.path)
            .expect("duplicate copy ACL staging cleanup handle");
        remove_open_tree(OpenDirectory {
            path: staging.path.clone(),
            handle: cleanup_handle,
        })
        .expect("remove copy ACL staging tree");
        drop(staging);
        drop(base);
        fs::remove_dir(&base_path).expect("remove copy ACL test catalog");
    }

    #[test]
    fn unchanged_source_tree_fingerprint_preserves_file_identity_byte_order() {
        let nonce = uuid::Uuid::new_v4().to_string();
        let root = std::env::current_dir().expect("read current directory").join("target").join(format!(
            "dig2browser-runtime-mirror-fingerprint-{nonce}"
        ));
        fs::create_dir_all(&root).expect("create fingerprint source tree");
        fs::write(root.join("chrome.exe"), b"main")
            .expect("write fingerprint source executable");
        let source = open_verified_directory(
            &root,
            FILE_LIST_DIRECTORY.0 | FILE_READ_ATTRIBUTES.0,
            "open fingerprint test source",
        ).expect("open fingerprint source by handle");
        let entries = collect_source_tree(source).expect("collect fingerprint source");

        assert_eq!(
            fingerprint_open_source_tree(&entries)
                .expect("revalidate unchanged source fingerprint"),
            fingerprint_source_tree(&entries),
            "unchanged source tree fingerprint must preserve u64 file identity byte order"
        );

        drop(entries);
        fs::remove_dir_all(&root).expect("remove fingerprint source fixture");
    }

    #[test]
    fn source_membership_revalidation_detects_new_entries() {
        let nonce = uuid::Uuid::new_v4().to_string();
        let root = std::env::current_dir().expect("read current directory").join("target").join(format!(
            "dig2browser-runtime-mirror-membership-{nonce}"
        ));
        fs::create_dir_all(&root).expect("create membership source tree");
        fs::write(root.join("chrome.exe"), b"main")
            .expect("write membership source executable");
        let source = open_verified_directory(
            &root,
            FILE_LIST_DIRECTORY.0 | FILE_READ_ATTRIBUTES.0,
            "open membership test source",
        ).expect("open membership source by handle");
        let entries = collect_source_tree(source).expect("collect membership source");
        fs::write(root.join("late.dll"), b"late").expect("add late source entry");
        let error = validate_source_tree_membership(&entries)
            .expect_err("late source entry must invalidate the snapshot");
        let (path, reason) = match error {
            WindowsRuntimeMirrorError::SourceChanged { path, reason } => (path, reason),
            other => panic!("unexpected membership revalidation error: {other:?}"),
        };
        assert_eq!(normalized_windows_path(&path), normalized_windows_path(&root));
        assert!(reason.contains("directory membership changed"));
        assert!(reason.contains("expected_count=1, actual_count=2"));
        assert!(reason.contains("first_difference_index=1"));
        assert!(reason.contains("expected_entry=none"));
        assert!(reason.contains("actual_entry=name_sha256:"));
        drop(entries);
        fs::remove_dir_all(&root).expect("remove membership source fixture");
    }

    #[test]
    fn removal_rejects_nested_junction_swap_without_touching_target() {
        let (base, root, key) = temporary_catalog();
        let nested = root.join("126.0.0.1");
        fs::create_dir(&nested).expect("create nested runtime directory");
        fs::write(root.join("chrome.exe"), b"main").expect("write main executable");
        fs::write(nested.join("helper.exe"), b"helper").expect("write helper executable");
        write_test_manifest(&root, key, Path::new("chrome.exe"));
        let mirror = inspect_ready_mirror_under_base(&root, &base)
            .expect("inspect mirror before junction swap");
        let identity = mirror.identity;
        drop(mirror);

        fs::remove_file(nested.join("helper.exe")).expect("remove nested fixture file");
        fs::remove_dir(&nested).expect("remove nested fixture directory");
        let target = std::env::temp_dir().join(format!(
            "dig2browser-runtime-mirror-junction-target-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&target).expect("create junction target");
        let sentinel = target.join("sentinel.txt");
        fs::write(&sentinel, b"must survive").expect("write target sentinel");
        create_junction(&nested, &target);

        let catalog = open_verified_directory(
            &base,
            FILE_LIST_DIRECTORY.0 | FILE_READ_ATTRIBUTES.0,
            "open test catalog",
        ).expect("open test catalog");
        let catalog = CatalogDirectory { path: catalog.path, handle: catalog.handle };
        let error = remove_validated_mirror_tree_under_catalog(
            &root,
            &catalog,
            Some(identity),
        ).expect_err("nested junction swap must fail closed");
        assert!(error.to_string().contains("reparse point"));
        assert_eq!(fs::read(&sentinel).expect("read surviving sentinel"), b"must survive");

        fs::remove_dir(&nested).expect("remove junction only");
        fs::remove_dir_all(&root).expect("remove rejected mirror fixture");
        fs::remove_dir(&base).expect("remove empty test catalog");
        fs::remove_dir_all(&target).expect("remove untouched junction target");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn explicit_removal_retry_releases_leases_and_waits_for_nested_sharing_lock() {
        let (base, root, key) = temporary_catalog();
        let nested = root.join("126.0.0.1");
        let nested_file = nested.join("chrome.dll");
        fs::create_dir(&nested).expect("create nested runtime directory");
        fs::write(root.join("chrome.exe"), b"main").expect("write main executable");
        fs::write(&nested_file, b"library").expect("write nested runtime file");
        write_test_manifest(&root, key, Path::new("chrome.exe"));
        let mirror = inspect_ready_mirror_under_base(&root, &base)
            .expect("inspect retry removal mirror");
        let token = RuntimeMirrorRemovalToken::from_mirror(mirror);

        let root_handle = open_verified_directory(
            &root,
            FILE_LIST_DIRECTORY.0 | FILE_READ_ATTRIBUTES.0,
            "open retry test mirror root",
        )
        .expect("open retry test mirror root");
        let blocker = open_relative_locked(
            &root_handle.handle,
            OsStr::new("126.0.0.1"),
            FILE_LIST_DIRECTORY.0 | FILE_READ_ATTRIBUTES.0,
            true,
            &nested,
            "hold retry test nested directory without delete sharing",
        )
        .expect("hold nested runtime directory without delete sharing");
        let blocker = unsafe { File::from_raw_handle(blocker.into_raw_handle()) };
        drop(root_handle);
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            drop(blocker);
        });

        let report = remove_runtime_mirror_with_retry(
            token,
            RuntimeMirrorCatalog::Test(base.clone()),
            Duration::from_secs(3),
        )
        .await
        .expect("remove mirror after nested sharing lock is released");
        release.join().expect("join nested sharing lock release");

        assert!(report.attempts >= 2, "removal unexpectedly skipped retry");
        assert!(report.waited >= REMOVAL_RETRY_INTERVAL);
        assert!(report.waited <= Duration::from_secs(3));
        assert!(!root.exists(), "retry removal left the mirror root behind");
        fs::remove_dir(&base).expect("remove empty retry test catalog");
    }

    #[test]
    fn removal_rejects_root_junction_swap_by_identity_without_touching_target() {
        let (base, root, key) = temporary_catalog();
        fs::write(root.join("chrome.exe"), b"main").expect("write main executable");
        write_test_manifest(&root, key, Path::new("chrome.exe"));
        let mirror = inspect_ready_mirror_under_base(&root, &base)
            .expect("inspect mirror before root swap");
        let identity = mirror.identity;
        drop(mirror);
        let parked = base.join("parked-owned-mirror");
        fs::rename(&root, &parked).expect("park inspected mirror");
        let target = std::env::temp_dir().join(format!(
            "dig2browser-runtime-mirror-root-target-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&target).expect("create root junction target");
        let sentinel = target.join("sentinel.txt");
        fs::write(&sentinel, b"must survive").expect("write target sentinel");
        create_junction(&root, &target);

        let catalog = open_verified_directory(
            &base,
            FILE_LIST_DIRECTORY.0 | FILE_READ_ATTRIBUTES.0,
            "open test catalog",
        ).expect("open test catalog");
        let catalog = CatalogDirectory { path: catalog.path, handle: catalog.handle };
        let error = remove_validated_mirror_tree_under_catalog(
            &root,
            &catalog,
            Some(identity),
        ).expect_err("root junction swap must fail closed");
        assert!(error.to_string().contains("reparse point"));
        assert_eq!(fs::read(&sentinel).expect("read surviving sentinel"), b"must survive");

        fs::remove_dir(&root).expect("remove root junction only");
        fs::rename(&parked, &root).expect("restore owned mirror root");
        remove_validated_mirror_tree_under_base(&root, &base)
            .expect("remove restored owned mirror");
        fs::remove_dir(&base).expect("remove empty test catalog");
        fs::remove_dir_all(&target).expect("remove untouched root target");
    }

    fn fixture_staging_name(
        key: &str,
        pid: u32,
        creation_filetime: u64,
        nonce: u128,
        sequence: u64,
    ) -> String {
        format!(".staging-{STAGING_NAME_SCHEMA}-{key}-{pid}-{creation_filetime:016x}-{nonce}-{sequence}")
    }

    #[test]
    fn staging_name_parser_accepts_only_the_exact_versioned_structure() {
        let identity = StagingCreatorIdentity {
            pid: 4242,
            creation_filetime: 0x0123_4567_89ab_cdef,
        };
        let name = fixture_staging_name(
            &"c".repeat(64),
            identity.pid,
            identity.creation_filetime,
            999,
            7,
        );
        assert_eq!(
            parse_staging_creator_identity(OsStr::new(&name)),
            Some(identity)
        );

        // Legacy pre-v2 staging names (bare wall-clock nonce, no schema
        // marker, no creation FILETIME) must never parse.
        let legacy = format!(".staging-{}-4242-123456789-1", "c".repeat(64));
        assert_eq!(parse_staging_creator_identity(OsStr::new(&legacy)), None);

        // Wrong-length / uppercase / non-canonical fields all fail closed.
        let bad_key = fixture_staging_name("C".repeat(63).as_str(), 4242, 1, 1, 1);
        assert_eq!(parse_staging_creator_identity(OsStr::new(&bad_key)), None);
        let leading_zero_pid =
            format!(".staging-{STAGING_NAME_SCHEMA}-{}-04242-0000000000000001-1-1", "c".repeat(64));
        assert_eq!(
            parse_staging_creator_identity(OsStr::new(&leading_zero_pid)),
            None
        );
        let trailing_garbage = format!("{name}-extra");
        assert_eq!(
            parse_staging_creator_identity(OsStr::new(&trailing_garbage)),
            None
        );
        assert_eq!(
            parse_staging_creator_identity(OsStr::new("not-a-staging-directory")),
            None
        );
    }

    #[test]
    fn staging_reconciliation_reclaims_only_provably_dead_creators() {
        let base = std::env::temp_dir().join(format!(
            "dig2browser-runtime-mirror-staging-reconcile-test-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&base).expect("create staging reconciliation test catalog");
        let base =
            fs::canonicalize(base).expect("canonicalize staging reconciliation test catalog");

        // A staging name whose embedded pid provably no longer exists.
        let mut dead_child = Command::new("cmd")
            .args(["/d", "/c", "exit", "0"])
            .spawn()
            .expect("spawn short-lived dead-pid fixture process");
        let dead_pid = dead_child.id();
        dead_child
            .wait()
            .expect("wait for dead-pid fixture process to exit");
        drop(dead_child);

        // A staging name whose embedded pid + creation FILETIME exactly
        // matches this still-running test process.
        let live_identity = current_process_staging_identity(&base)
            .expect("capture current process staging identity");

        let dead_name = fixture_staging_name(&"a".repeat(64), dead_pid, 1, 111, 1);
        let live_name = fixture_staging_name(
            &"b".repeat(64),
            live_identity.pid,
            live_identity.creation_filetime,
            222,
            1,
        );
        let malformed_name = ".staging-v2-not-a-valid-content-key-333-1".to_owned();
        let untouched_name = "not-a-staging-directory".to_owned();

        for name in [&dead_name, &live_name, &malformed_name, &untouched_name] {
            fs::create_dir(base.join(name))
                .expect("create staging reconciliation fixture directory");
        }

        let catalog = open_verified_directory(
            &base,
            FILE_LIST_DIRECTORY.0 | FILE_READ_ATTRIBUTES.0,
            "open staging reconciliation test catalog",
        )
        .expect("open staging reconciliation test catalog");
        let catalog = CatalogDirectory {
            path: catalog.path,
            handle: catalog.handle,
        };
        reconcile_orphaned_staging_inner(&catalog).expect("reconcile orphaned staging fixtures");

        assert!(
            !base.join(&dead_name).exists(),
            "dead-creator staging entry was not reclaimed"
        );
        assert!(
            base.join(&live_name).exists(),
            "live-creator staging entry was incorrectly reclaimed"
        );
        assert!(
            base.join(&malformed_name).exists(),
            "malformed staging entry was incorrectly reclaimed"
        );
        assert!(
            base.join(&untouched_name).exists(),
            "non-staging entry was incorrectly touched"
        );

        fs::remove_dir(base.join(&live_name)).expect("remove live fixture directory");
        fs::remove_dir(base.join(&malformed_name)).expect("remove malformed fixture directory");
        fs::remove_dir(base.join(&untouched_name)).expect("remove untouched fixture directory");
        fs::remove_dir(&base).expect("remove empty staging reconciliation test catalog");
    }
}
