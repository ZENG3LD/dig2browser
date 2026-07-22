//! Stable, station-owned Chromium runtime mirrors for Windows process policy.

use std::collections::BTreeMap;
use std::ffi::{c_void, OsStr, OsString};
use std::fs::File;
#[cfg(test)]
use std::fs;
use std::io::{self, Read, Write};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{FromRawHandle, RawHandle};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, DuplicateHandle, GetLastError, HANDLE, DUPLICATE_SAME_ACCESS,
    ERROR_NO_MORE_FILES,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, GetFileInformationByHandle, GetFileInformationByHandleEx,
    GetFinalPathNameByHandleW, SetFileInformationByHandle,
    BY_HANDLE_FILE_INFORMATION,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DISPOSITION_FLAG_DELETE,
    FILE_DISPOSITION_FLAG_POSIX_SEMANTICS, FILE_DISPOSITION_INFO_EX,
    FILE_DISPOSITION_INFO_EX_FLAGS,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAGS_AND_ATTRIBUTES,
    FILE_ID_BOTH_DIR_INFO, FILE_LIST_DIRECTORY, FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE, FILE_SHARE_MODE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FILE_WRITE_DATA, FileDispositionInfoEx, FileIdBothDirectoryInfo, OPEN_EXISTING,
    GETFINALPATHNAMEBYHANDLE_FLAGS, VOLUME_NAME_DOS,
};
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::System::Threading::GetCurrentProcess;
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
const DIRECTORY_BUFFER_BYTES: usize = 64 * 1024;

static STAGING_SEQUENCE: AtomicU64 = AtomicU64::new(0);

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

    /// Materializes or reuses a content-keyed hard-link mirror of the browser's
    /// complete `Application` directory.
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
        let binary_handle = open_relative(
            &source_root.handle,
            binary_name,
            FILE_READ_ATTRIBUTES.0 | DELETE_ACCESS,
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
        let canonical_source = source_root.path.join(binary_name);

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
        let source_fingerprint = fingerprint_source_tree(&source_tree);
        // Version-resource APIs reopen by path and would reintroduce a source
        // traversal race. The handle-derived tree fingerprint already keys the
        // opened source tree layout and metadata.
        let version = None;
        let binary_relative = PathBuf::from(binary_name);
        validate_relative_path(&binary_relative)?;
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
        };
        let target = base.path.join(&key);

        if relative_exists(&base.handle, OsStr::new(&key), &target)? {
            return validate_ready_mirror(
                &target,
                &binary_relative,
                &expected_manifest,
                source.kind,
            );
        }

        let staging = create_staging_directory(&base, &key)?;
        let build_result = (|| {
            populate_staging(&source_tree, &staging)?;
            if fingerprint_open_source_tree(&source_tree)? != expected_manifest.source_fingerprint {
                return Err(WindowsRuntimeMirrorError::SourceChanged {
                    path: requested_source_root.to_path_buf(),
                });
            }
            write_ready_manifest(&staging, &expected_manifest)?;
            publish_staging(
                &base,
                &staging,
                &target,
                &binary_relative,
                &expected_manifest,
                source.kind,
            )
        })();

        match build_result {
            Ok(mirror) => Ok(mirror),
            Err(error) => {
                cleanup_owned_staging(&base, &staging);
                Err(error)
            }
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
        remove_validated_mirror_tree(&inspected.root, inspected.identity)
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
    #[error("source browser tree changed while its runtime mirror was being built: '{path}'", path = path.display())]
    SourceChanged { path: PathBuf },
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SourceEntryKind {
    Directory,
    File,
}

#[derive(Debug)]
struct SourceEntry {
    relative: PathBuf,
    kind: SourceEntryKind,
    attributes: u32,
    size: u64,
    last_write_time: u64,
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
        FILE_LIST_DIRECTORY.0 | FILE_READ_ATTRIBUTES.0,
        "open LOCALAPPDATA",
    )?;
    let product_path = local.path.join("dig2browser");
    let product = create_or_open_relative_directory(
        &local.handle,
        OsStr::new("dig2browser"),
        &product_path,
    )?;
    let mirror_path = product_path.join("runtime-mirrors");
    let mirror = create_or_open_relative_directory(
        &product,
        OsStr::new("runtime-mirrors"),
        &mirror_path,
    )?;
    Ok(CatalogDirectory {
        path: mirror_path,
        handle: mirror,
    })
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
    lock_delete: bool,
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
    let handle = if lock_delete {
        open_relative_locked(
            &base.handle,
            OsStr::new(name),
            desired_access,
            true,
            &canonical_root,
            "lock station-owned runtime mirror root",
        )?
    } else {
        open_relative(
            &base.handle,
            OsStr::new(name),
            desired_access,
            true,
            FILE_OPEN,
            &canonical_root,
            "open station-owned runtime mirror root",
        )?
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
                let child_handle = open_relative(
                    &handle,
                    &child.name,
                    (FILE_LIST_DIRECTORY.0 * u32::from(child_is_directory))
                        | FILE_READ_ATTRIBUTES.0
                        | DELETE_ACCESS,
                    child_is_directory,
                    FILE_OPEN,
                    &child_path,
                    "open runtime mirror source entry",
                )?;
                let identity = handle_identity(&child_handle, &child_path)?;
                if identity.index != child.file_id {
                    return Err(WindowsRuntimeMirrorError::SourceChanged { path: child_path });
                }
                pending.push((child_relative, child_handle));
            }
            SourceEntryKind::Directory
        } else {
            SourceEntryKind::File
        };
        entries.push(SourceEntry {
            relative,
            kind,
            attributes: information.dwFileAttributes,
            size: ((information.nFileSizeHigh as u64) << 32) | information.nFileSizeLow as u64,
            last_write_time: ((information.ftLastWriteTime.dwHighDateTime as u64) << 32)
                | information.ftLastWriteTime.dwLowDateTime as u64,
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
    digest.update(b"dig2browser-source-tree-v1\0");
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
    }
    hex_digest(digest.finalize())
}

fn fingerprint_open_source_tree(
    entries: &[SourceEntry],
) -> Result<String, WindowsRuntimeMirrorError> {
    let mut digest = Sha256::new();
    digest.update(b"dig2browser-source-tree-v1\0");
    for entry in entries {
        let kind = match entry.kind {
            SourceEntryKind::Directory => 0u8,
            SourceEntryKind::File => 1u8,
        };
        let information = handle_information(
            &entry.handle,
            &entry.relative,
            "revalidate opened runtime mirror source entry",
        )?;
        ensure_handle_type(
            &information,
            entry.kind == SourceEntryKind::Directory,
            &entry.relative,
        )?;
        digest.update([kind]);
        hash_path_into(&mut digest, &entry.relative);
        digest.update(information.dwFileAttributes.to_le_bytes());
        let size = ((information.nFileSizeHigh as u64) << 32) | information.nFileSizeLow as u64;
        digest.update(size.to_le_bytes());
        let last_write_time = ((information.ftLastWriteTime.dwHighDateTime as u64) << 32)
            | information.ftLastWriteTime.dwLowDateTime as u64;
        digest.update(last_write_time.to_le_bytes());
    }
    Ok(hex_digest(digest.finalize()))
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
    for _ in 0..STAGING_ATTEMPTS {
        let sequence = STAGING_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let name = format!(
            ".staging-{key}-{}-{nonce}-{sequence}",
            std::process::id()
        );
        let staging = base.path.join(&name);
        match open_relative(
            &base.handle,
            OsStr::new(&name),
            FILE_LIST_DIRECTORY.0 | FILE_READ_ATTRIBUTES.0 | DELETE_ACCESS,
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

fn populate_staging(
    entries: &[SourceEntry],
    staging: &OpenDirectory,
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
            FILE_LIST_DIRECTORY.0 | FILE_READ_ATTRIBUTES.0 | DELETE_ACCESS,
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
        create_hard_link_relative(
            &entry.handle,
            parent,
            name,
            &staging.path.join(&entry.relative),
        )?;
    }
    Ok(())
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
    staging: &OpenDirectory,
    target: &Path,
    binary_relative: &Path,
    manifest: &ReadyManifest,
    kind: BrowserKind,
) -> Result<WindowsBrowserRuntimeMirror, WindowsRuntimeMirrorError> {
    let target_name = target.file_name().ok_or_else(|| {
        WindowsRuntimeMirrorError::InvalidRelativePath { path: target.to_path_buf() }
    })?;
    let staging_identity = handle_identity(&staging.handle, &staging.path)?;
    match rename_relative(&staging.handle, &base.handle, target_name, target) {
        Ok(()) => {
            let mirror = validate_ready_mirror(target, binary_relative, manifest, kind)?;
            if mirror.identity != staging_identity {
                return Err(invalid_existing(target, "published mirror identity was replaced"));
            }
            Ok(mirror)
        }
        Err(rename_error) => match validate_ready_mirror(
            target,
            binary_relative,
            manifest,
            kind,
        ) {
            Ok(mirror) => Ok(mirror),
            Err(_) => Err(rename_error),
        },
    }
}

fn validate_ready_mirror(
    root: &Path,
    binary_relative: &Path,
    expected: &ReadyManifest,
    kind: BrowserKind,
) -> Result<WindowsBrowserRuntimeMirror, WindowsRuntimeMirrorError> {
    let mirror = inspect_ready_mirror(root)?;
    let base = existing_mirror_base()?;
    let opened = validate_owned_mirror_root_under_base(
        &mirror.root,
        &base,
        FILE_LIST_DIRECTORY.0 | FILE_READ_ATTRIBUTES.0,
        false,
    )?;
    if handle_identity(&opened.handle, &opened.path)? != mirror.identity {
        return Err(invalid_existing(&mirror.root, "runtime mirror changed during validation"));
    }
    let bytes = read_manifest_bytes_from_handle(&opened)?;
    validate_manifest_bytes(&bytes, expected).map_err(|reason| {
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
        false,
    )?;
    let identity = handle_identity(&root.handle, &root.path)?;
    let executable_paths = collect_mirror_executables_from_handle(&root)?;
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
    collect_mirror_executables_from_handle(&directory)
}

fn collect_mirror_executables_from_handle(
    root: &OpenDirectory,
) -> Result<Vec<PathBuf>, WindowsRuntimeMirrorError> {
    let mut pending = vec![(PathBuf::new(), duplicate_handle(&root.handle, &root.path)?)];
    let mut executable_paths = Vec::new();
    while let Some((relative, handle)) = pending.pop() {
        let path = root.path.join(&relative);
        for entry in enumerate_directory(&handle, &path)? {
            let child_relative = relative.join(&entry.name);
            let child_path = root.path.join(&child_relative);
            let is_directory = entry.attributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0;
            let child = open_relative(
                &handle,
                &entry.name,
                (FILE_LIST_DIRECTORY.0 * u32::from(is_directory)) | FILE_READ_ATTRIBUTES.0,
                is_directory,
                FILE_OPEN,
                &child_path,
                "open runtime mirror entry",
            )?;
            if handle_identity(&child, &child_path)?.index != entry.file_id {
                return Err(invalid_existing(&root.path, "mirror entry changed during inspection"));
            }
            if is_directory {
                pending.push((child_relative, child));
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
    Ok(executable_paths)
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
        true,
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

fn cleanup_owned_staging(base: &CatalogDirectory, staging: &OpenDirectory) {
    if !is_owned_staging_path(&base.path, &staging.path) {
        return;
    }
    if let Ok(handle) = duplicate_handle(&staging.handle, &staging.path) {
        let _ = remove_open_tree(OpenDirectory {
            path: staging.path.clone(),
            handle,
        });
    }
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
            desired_access: FILE_LIST_DIRECTORY.0 | FILE_READ_ATTRIBUTES.0,
            expect_directory: true,
            disposition: FILE_OPEN_IF,
            share_delete: false,
            path,
            operation: "create or open runtime mirror directory",
        },
    )
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
                | FILE_SHARE_WRITE.0
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
    loop {
        let result = unsafe {
            GetFileInformationByHandleEx(
                handle.0,
                FileIdBothDirectoryInfo,
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
        };
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
        populate_staging(&entries, &staging).expect("populate staging with handle-relative links");
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
    fn removal_rejects_nested_junction_swap_without_touching_target() {
        let (base, root, key) = temporary_catalog();
        let nested = root.join("126.0.0.1");
        fs::create_dir(&nested).expect("create nested runtime directory");
        fs::write(root.join("chrome.exe"), b"main").expect("write main executable");
        fs::write(nested.join("helper.exe"), b"helper").expect("write helper executable");
        write_test_manifest(&root, key, Path::new("chrome.exe"));
        let mirror = inspect_ready_mirror_under_base(&root, &base)
            .expect("inspect mirror before junction swap");

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
            Some(mirror.identity),
        ).expect_err("nested junction swap must fail closed");
        assert!(error.to_string().contains("reparse point"));
        assert_eq!(fs::read(&sentinel).expect("read surviving sentinel"), b"must survive");

        fs::remove_dir(&nested).expect("remove junction only");
        fs::remove_dir_all(&root).expect("remove rejected mirror fixture");
        fs::remove_dir(&base).expect("remove empty test catalog");
        fs::remove_dir_all(&target).expect("remove untouched junction target");
    }

    #[test]
    fn removal_rejects_root_junction_swap_by_identity_without_touching_target() {
        let (base, root, key) = temporary_catalog();
        fs::write(root.join("chrome.exe"), b"main").expect("write main executable");
        write_test_manifest(&root, key, Path::new("chrome.exe"));
        let mirror = inspect_ready_mirror_under_base(&root, &base)
            .expect("inspect mirror before root swap");
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
            Some(mirror.identity),
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
}
