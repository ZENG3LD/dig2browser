#![cfg(windows)]

use std::collections::HashSet;
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::mem::size_of;
use std::net::{
    IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener,
    TcpStream, UdpSocket,
};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::process::Stdio;
#[cfg(feature = "tls-test-hooks")]
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Once};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dig2browser::detect::{
    BrowserBinary, BrowserKind, BrowserPreference, LaunchConfig,
};
use dig2browser::identity::ProfileOwnershipGuard;
use dig2browser::stealth::StealthConfig;
use dig2browser::{
    BrowserProcessIsolation, StealthBrowser, WindowsBrowserRuntimeMirror,
};
use dig2browser_client::{
    BrowserPersona, ClientConfig, ClientError, CollectionTask, ResponseStatus,
    RuntimeFeature, RuntimeKind, RuntimeRequirements, RuntimeSelector, StationClient,
    TaskCapturePolicy, TaskReply, TaskRuntimeContract, TaskStep,
};
use dig2browser_station::windows_wfp_broker::{
    inspect_windows_process_security, launch_elevated_windows_wfp_broker,
    ElevatedWindowsWfpBroker, WindowsWfpBrokerCapability,
    WindowsWfpBrokerOutcome, WFP_BROKER_CRASH_EXIT_CODE,
};
use dig2browser_station::ProfilesRootOwnership;
use tokio::io::AsyncReadExt;
use windows::core::PWSTR;
use windows::Win32::Foundation::{
    CloseHandle, FILETIME, HANDLE, INVALID_HANDLE_VALUE, STILL_ACTIVE,
};
use windows::Win32::Storage::FileSystem::{
    GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
};
use windows::Win32::System::Threading::{
    GetExitCodeProcess, GetProcessTimes, OpenProcess, QueryFullProcessImageNameW,
    PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

type ControlledResponse = (&'static str, Vec<(String, String)>, String);
type Responder = Arc<dyn Fn(&str) -> ControlledResponse + Send + Sync>;

const TH32CS_SNAPPROCESS: u32 = 0x0000_0002;
const ERROR_NO_MORE_FILES: i32 = 18;

#[repr(C)]
struct ProcessEntry32W {
    size: u32,
    usage: u32,
    process_id: u32,
    default_heap_id: usize,
    module_id: u32,
    thread_count: u32,
    parent_process_id: u32,
    base_priority: i32,
    flags: u32,
    executable: [u16; 260],
}

impl Default for ProcessEntry32W {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

#[derive(Clone)]
struct ProcessEntry {
    process_id: u32,
    parent_process_id: u32,
    executable: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct ProcessIdentity {
    process_id: u32,
    creation_filetime: u64,
}

struct ReadOnlyHandle(HANDLE);

impl Drop for ReadOnlyHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

static WFP_E2E_RUN_SERIALIZATION: Mutex<()> = Mutex::new(());
static WFP_E2E_PANIC_HOOK: Once = Once::new();
static WFP_E2E_PANIC_TARGET: Mutex<Option<PanicLogTarget>> = Mutex::new(None);

#[derive(Clone)]
struct PanicLogTarget {
    path: PathBuf,
    root: PathBuf,
}

enum PanicLogRestore {
    Inactive,
    Active(Option<PanicLogTarget>),
}

struct WfpE2eRun {
    root: PathBuf,
    panic_log_restore: Mutex<PanicLogRestore>,
    run_dir_environment: Option<ScopedEnvironmentVariable>,
    broker_log_environment: Option<ScopedEnvironmentVariable>,
    serialization_guard: Option<MutexGuard<'static, ()>>,
}

struct ScopedEnvironmentVariable {
    name: &'static str,
    previous: Option<OsString>,
}

impl ScopedEnvironmentVariable {
    fn set(name: &'static str, value: &Path) -> Self {
        let previous = std::env::var_os(name);
        std::env::set_var(name, value);
        Self { name, previous }
    }
}

impl Drop for ScopedEnvironmentVariable {
    fn drop(&mut self) {
        if let Some(previous) = &self.previous {
            std::env::set_var(self.name, previous);
        } else {
            std::env::remove_var(self.name);
        }
    }
}

fn lock_wfp_e2e_run_serialization() -> MutexGuard<'static, ()> {
    WFP_E2E_RUN_SERIALIZATION
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn lock_wfp_e2e_panic_target() -> MutexGuard<'static, Option<PanicLogTarget>> {
    WFP_E2E_PANIC_TARGET
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn install_wfp_e2e_panic_hook() {
    WFP_E2E_PANIC_HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |panic| {
            let target = lock_wfp_e2e_panic_target().clone();
            if let Some(target) = target {
                if let Ok(mut log) = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&target.path)
                {
                    let _ = writeln!(log, "{panic}");
                }
                append_e2e_event(
                    &target.root,
                    "test",
                    "panic",
                    serde_json::json!({ "message": panic.to_string() }),
                );
            }
            previous(panic);
        }));
    });
}

impl WfpE2eRun {
    fn start(scenario: &str) -> Self {
        let serialization_guard = lock_wfp_e2e_run_serialization();
        let started_at_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after Unix epoch")
            .as_millis() as u64;
        let root = std::env::var_os("DIG2BROWSER_E2E_RUN_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                e2e_temp_base().join("dig2browser-wfp-e2e-runs")
            })
            .join(format!(
                "{started_at_unix_ms}-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4().simple()
            ));
        std::fs::create_dir_all(&root).expect("create WFP E2E run directory");
        let manifest = serde_json::json!({
            "schema_version": 1,
            "scenario": scenario,
            "started_at_unix_ms": started_at_unix_ms,
            "test_process_id": std::process::id(),
            "run_directory": root,
        });
        std::fs::write(
            root.join("manifest.json"),
            serde_json::to_vec_pretty(&manifest).expect("serialize WFP E2E manifest"),
        )
        .expect("write WFP E2E manifest");
        File::create(root.join("panic.log")).expect("create WFP E2E panic log");
        let broker_log_path = root.join("broker-bootstrap.jsonl");
        File::create(&broker_log_path).expect("create WFP broker bootstrap log");
        let run_dir_environment = ScopedEnvironmentVariable::set(
            "DIG2BROWSER_E2E_RUN_DIR",
            &root,
        );
        let broker_log_environment = ScopedEnvironmentVariable::set(
            "DIG2BROWSER_WFP_BROKER_LOG",
            &broker_log_path,
        );
        eprintln!("DIG2BROWSER_E2E_RUN_DIR={}", root.display());
        let run = Self {
            root,
            panic_log_restore: Mutex::new(PanicLogRestore::Inactive),
            run_dir_environment: Some(run_dir_environment),
            broker_log_environment: Some(broker_log_environment),
            serialization_guard: Some(serialization_guard),
        };
        run.event("test", "run_started", serde_json::json!({}));
        run
    }

    fn event(&self, component: &str, event: &str, detail: serde_json::Value) {
        append_e2e_event(&self.root, component, event, detail);
    }

    fn install_panic_log(&self) {
        install_wfp_e2e_panic_hook();
        let mut restore = self
            .panic_log_restore
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if matches!(*restore, PanicLogRestore::Active(_)) {
            return;
        }
        let target = PanicLogTarget {
            path: self.root.join("panic.log"),
            root: self.root.clone(),
        };
        let previous = lock_wfp_e2e_panic_target().replace(target);
        *restore = PanicLogRestore::Active(previous);
    }
}

impl Drop for WfpE2eRun {
    fn drop(&mut self) {
        let restore = self
            .panic_log_restore
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let PanicLogRestore::Active(previous) =
            std::mem::replace(restore, PanicLogRestore::Inactive)
        {
            *lock_wfp_e2e_panic_target() = previous;
        }
        drop(self.broker_log_environment.take());
        drop(self.run_dir_environment.take());
        drop(self.serialization_guard.take());
    }
}

struct LoggedStation {
    child: tokio::process::Child,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
    diagnostic_path: PathBuf,
}

impl LoggedStation {
    fn id(&self) -> Option<u32> {
        self.child.id()
    }

    fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        self.child.try_wait()
    }

    async fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        self.child.wait().await
    }

    fn output(&self) -> (String, String) {
        let stdout = std::fs::read_to_string(&self.stdout_path)
            .unwrap_or_else(|error| format!("<cannot read station stdout: {error}>"));
        let stderr = std::fs::read_to_string(&self.stderr_path)
            .unwrap_or_else(|error| format!("<cannot read station stderr: {error}>"));
        (stdout, stderr)
    }

    fn diagnostic_tail(&self) -> String {
        const MAX_BYTES: usize = 16 * 1024;

        let bytes = match std::fs::read(&self.diagnostic_path) {
            Ok(bytes) => bytes,
            Err(error) => return format!("<cannot read station diagnostic log: {error}>"),
        };
        let start = bytes.len().saturating_sub(MAX_BYTES);
        String::from_utf8_lossy(&bytes[start..]).into_owned()
    }
}

fn current_e2e_run_root() -> PathBuf {
    std::env::var_os("DIG2BROWSER_E2E_RUN_DIR")
        .map(PathBuf::from)
        .expect("WFP E2E run directory is initialized")
}

fn e2e_component_path(component: &str, suffix: &str) -> PathBuf {
    current_e2e_run_root().join(format!(
        "{}.{}.log",
        safe_e2e_component_name(component),
        suffix
    ))
}

fn e2e_component_artifact_path(component: &str, suffix: &str) -> PathBuf {
    current_e2e_run_root().join(format!(
        "{}.{}",
        safe_e2e_component_name(component),
        suffix
    ))
}

fn safe_e2e_component_name(component: &str) -> String {
    component
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn record_e2e_event(component: &str, event: &str, detail: serde_json::Value) {
    append_e2e_event(&current_e2e_run_root(), component, event, detail);
}

fn append_e2e_event(
    root: &Path,
    component: &str,
    event: &str,
    detail: serde_json::Value,
) {
    let at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default();
    let record = serde_json::json!({
        "schema_version": 1,
        "at_unix_ms": at_unix_ms,
        "component": component,
        "event": event,
        "detail": detail,
    });
    if let Ok(mut log) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(root.join("events.jsonl"))
    {
        if let Ok(mut encoded) = serde_json::to_vec(&record) {
            encoded.push(b'\n');
            let _ = log.write_all(&encoded);
        }
    }
}

fn assert_medium_process(process_id: u32, label: &str) {
    let security = inspect_windows_process_security(process_id)
        .unwrap_or_else(|error| panic!("inspect {label} security: {error}"));
    record_e2e_event(
        "test",
        "process_security_observed",
        serde_json::json!({
            "label": label,
            "process_id": security.process_id,
            "elevated": security.elevated,
            "integrity_rid": security.integrity_rid,
        }),
    );
    assert!(
        !security.elevated && security.is_medium_integrity(),
        "{label} must remain non-elevated medium integrity: {security:?}"
    );
}

fn assert_non_elevated_process_at_or_below_medium(process_id: u32, label: &str) {
    let security = inspect_windows_process_security(process_id)
        .unwrap_or_else(|error| panic!("inspect {label} security: {error}"));
    record_e2e_event(
        "test",
        "process_security_observed",
        serde_json::json!({
            "label": label,
            "process_id": security.process_id,
            "elevated": security.elevated,
            "integrity_rid": security.integrity_rid,
        }),
    );
    assert!(
        !security.elevated && !security.is_high_integrity(),
        "{label} must remain non-elevated at or below medium integrity: {security:?}"
    );
}

#[link(name = "kernel32")]
extern "system" {
    #[link_name = "CreateToolhelp32Snapshot"]
    fn create_toolhelp32_snapshot(flags: u32, process_id: u32) -> HANDLE;
    #[link_name = "Process32FirstW"]
    fn process32_first(snapshot: HANDLE, entry: *mut ProcessEntry32W) -> i32;
    #[link_name = "Process32NextW"]
    fn process32_next(snapshot: HANDLE, entry: *mut ProcessEntry32W) -> i32;
}

fn process_snapshot() -> Result<Vec<ProcessEntry>, String> {
    let snapshot = unsafe { create_toolhelp32_snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(format!(
            "create read-only process snapshot: {}",
            std::io::Error::last_os_error()
        ));
    }
    let snapshot = ReadOnlyHandle(snapshot);
    let mut raw = ProcessEntry32W {
        size: size_of::<ProcessEntry32W>() as u32,
        ..ProcessEntry32W::default()
    };
    if unsafe { process32_first(snapshot.0, &mut raw) } == 0 {
        return Err(format!(
            "read first process snapshot entry: {}",
            std::io::Error::last_os_error()
        ));
    }

    let mut entries = Vec::new();
    loop {
        let name_length = raw
            .executable
            .iter()
            .position(|character| *character == 0)
            .unwrap_or(raw.executable.len());
        entries.push(ProcessEntry {
            process_id: raw.process_id,
            parent_process_id: raw.parent_process_id,
            executable: String::from_utf16_lossy(&raw.executable[..name_length]),
        });
        raw = ProcessEntry32W {
            size: size_of::<ProcessEntry32W>() as u32,
            ..ProcessEntry32W::default()
        };
        if unsafe { process32_next(snapshot.0, &mut raw) } == 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_NO_MORE_FILES) {
                return Err(format!("read process snapshot entry: {error}"));
            }
            break;
        }
    }
    Ok(entries)
}

fn station_descendant_process_ids(
    entries: &[ProcessEntry],
    station_process_id: u32,
    browser_executable: &str,
) -> Result<Vec<u32>, String> {
    let station_identity = current_process_identity(station_process_id)
        .ok_or_else(|| "station process is not an active exact incarnation".to_owned())?;
    let mut descendants = HashSet::from([station_process_id]);
    loop {
        let previous_count = descendants.len();
        for entry in entries {
            let belongs_to_current_station = current_process_identity(entry.process_id)
                .is_some_and(|identity| {
                    identity.creation_filetime >= station_identity.creation_filetime
                });
            if descendants.contains(&entry.parent_process_id)
                && belongs_to_current_station
            {
                descendants.insert(entry.process_id);
            }
        }
        if descendants.len() == previous_count {
            break;
        }
    }

    descendants.remove(&station_process_id);
    if descendants.is_empty() {
        return Err("station process tree does not contain browser processes".to_owned());
    }
    let browser_processes: HashSet<u32> = entries
        .iter()
        .filter(|entry| {
            descendants.contains(&entry.process_id)
                && entry.executable.eq_ignore_ascii_case(browser_executable)
        })
        .map(|entry| entry.process_id)
        .collect();
    if browser_processes.len() < 2 {
        return Err(format!(
            "station process tree does not contain a {browser_executable} root and descendant"
        ));
    }
    let root_count = entries.iter().filter(|entry| {
        browser_processes.contains(&entry.process_id)
            && !browser_processes.contains(&entry.parent_process_id)
    }).count();
    if root_count != 1 {
        return Err(format!(
            "station process tree contains {root_count} {browser_executable} roots"
        ));
    }
    Ok(descendants.into_iter().collect())
}

fn process_image_path(process_id: u32) -> Result<String, String> {
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, process_id) }
        .map(ReadOnlyHandle)
        .map_err(|error| format!("open Chrome for image-path query: {error}"))?;
    let mut path = vec![0_u16; 32_768];
    let mut path_length = path.len() as u32;
    unsafe {
        QueryFullProcessImageNameW(
            process.0,
            PROCESS_NAME_WIN32,
            PWSTR(path.as_mut_ptr()),
            &mut path_length,
        )
    }
    .map_err(|error| format!("query Chrome process image path: {error}"))?;
    path.truncate(path_length as usize);
    Ok(String::from_utf16_lossy(&path))
}

fn live_processes_with_images_under(root: &Path) -> Vec<serde_json::Value> {
    let root = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let root = normalized_windows_path(root.to_string_lossy())
        .trim_end_matches('\\')
        .to_owned();
    let prefix = format!("{root}\\");
    let Ok(entries) = process_snapshot() else {
        return Vec::new();
    };
    entries
        .into_iter()
        .filter_map(|entry| {
            let image_path = process_image_path(entry.process_id).ok()?;
            let normalized = normalized_windows_path(&image_path);
            (normalized == root || normalized.starts_with(&prefix)).then(|| {
                serde_json::json!({
                    "process_id": entry.process_id,
                    "parent_process_id": entry.parent_process_id,
                    "executable": entry.executable,
                    "image_path": image_path,
                })
            })
        })
        .collect()
}

async fn remove_runtime_mirror_with_evidence(
    mirror: WindowsBrowserRuntimeMirror,
    context: &str,
) -> Result<(), String> {
    const MAX_WAIT: Duration = Duration::from_secs(15);

    let root = mirror.root().to_path_buf();
    let started = Instant::now();
    record_e2e_event(
        "runtime-mirror",
        "removal_started",
        serde_json::json!({
            "context": context,
            "root": root,
            "max_wait_ms": MAX_WAIT.as_millis() as u64,
        }),
    );
    match mirror.remove_with_retry(MAX_WAIT).await {
        Ok(report) => {
            record_e2e_event(
                "runtime-mirror",
                "removal_finished",
                serde_json::json!({
                    "context": context,
                    "root": root,
                    "elapsed_ms": started.elapsed().as_millis() as u64,
                    "attempts": report.attempts,
                    "retry_wait_ms": report.waited.as_millis() as u64,
                }),
            );
            Ok(())
        }
        Err(error) => {
            record_e2e_event(
                "runtime-mirror",
                "removal_failed",
                serde_json::json!({
                    "context": context,
                    "root": root,
                    "elapsed_ms": started.elapsed().as_millis() as u64,
                    "error": error.to_string(),
                    "live_runtime_processes": live_processes_with_images_under(&root),
                }),
            );
            Err(error.to_string())
        }
    }
}

fn chromium_root_process_image_path(
    station_process_id: u32,
    runtime_name: &str,
) -> PathBuf {
    chromium_root_process(station_process_id, runtime_name).1
}

fn chromium_root_process(
    station_process_id: u32,
    runtime_name: &str,
) -> (u32, PathBuf) {
    let browser_executable = match runtime_name {
        "chrome" => "chrome.exe",
        "edge" => "msedge.exe",
        other => panic!("unsupported Chromium E2E runtime: {other}"),
    };
    let entries = process_snapshot().expect("read station process tree");
    let descendants = station_descendant_process_ids(
        &entries,
        station_process_id,
        browser_executable,
    )
    .expect("resolve station browser descendants")
    .into_iter()
    .collect::<HashSet<_>>();
    let browser_processes = entries
        .iter()
        .filter(|entry| {
            descendants.contains(&entry.process_id)
                && entry.executable.eq_ignore_ascii_case(browser_executable)
        })
        .map(|entry| entry.process_id)
        .collect::<HashSet<_>>();
    let roots = entries
        .iter()
        .filter(|entry| {
            browser_processes.contains(&entry.process_id)
                && !browser_processes.contains(&entry.parent_process_id)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        roots.len(),
        1,
        "station must have one exact {browser_executable} root"
    );
    let process_id = roots[0].process_id;
    let image_path = PathBuf::from(
        process_image_path(process_id).expect("read station browser root image path"),
    );
    (process_id, image_path)
}

fn current_process_identity(process_id: u32) -> Option<ProcessIdentity> {
    let process = unsafe {
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, process_id)
    }
    .ok()?;
    let process = ReadOnlyHandle(process);
    let mut exit_code = 0u32;
    unsafe { GetExitCodeProcess(process.0, &mut exit_code) }.ok()?;
    if exit_code != STILL_ACTIVE.0 as u32 {
        return None;
    }
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    unsafe {
        GetProcessTimes(
            process.0,
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    }
    .ok()?;
    let creation_filetime =
        ((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64;
    (creation_filetime != 0).then_some(ProcessIdentity {
        process_id,
        creation_filetime,
    })
}

fn normalized_windows_path(path: impl AsRef<str>) -> String {
    let normalized = path.as_ref().replace('/', "\\").to_ascii_lowercase();
    if let Some(relative) = normalized.strip_prefix(r"\\?\unc\") {
        format!(r"\\{relative}")
    } else if let Some(relative) = normalized.strip_prefix(r"\\?\") {
        relative.to_owned()
    } else {
        normalized
    }
}

fn runtime_mirror_root_for_image(
    image_path: &str,
    mirror_catalog: &Path,
) -> Result<String, String> {
    let image = std::fs::canonicalize(image_path)
        .map_err(|error| format!("canonicalize descendant image '{image_path}': {error}"))?;
    let catalog = std::fs::canonicalize(mirror_catalog).map_err(|error| {
        format!(
            "canonicalize runtime-mirror catalog '{}': {error}",
            mirror_catalog.display()
        )
    })?;
    let image = normalized_windows_path(image.to_string_lossy());
    let catalog = normalized_windows_path(catalog.to_string_lossy())
        .trim_end_matches('\\')
        .to_owned();
    let prefix = format!("{catalog}\\");
    let relative = image.strip_prefix(&prefix).ok_or_else(|| {
        format!("descendant image is outside the runtime-mirror catalog: {image}")
    })?;
    let mut components = relative.split('\\');
    let key = components.next().unwrap_or_default();
    if key.len() != 64
        || !key.bytes().all(|byte| byte.is_ascii_hexdigit())
        || key.bytes().any(|byte| byte.is_ascii_uppercase())
        || components.next().is_none()
    {
        return Err(format!(
            "descendant image is not inside an exact content-keyed mirror root: {image}"
        ));
    }
    Ok(format!("{prefix}{key}"))
}

async fn assert_chromium_descendants_use_station_mirror(
    station_process_id: u32,
    original_browser_path: &Path,
    mirror_catalog: &Path,
    expected_mirror_root: &Path,
    runtime_name: &str,
) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let original_browser_path = std::fs::canonicalize(original_browser_path)
        .unwrap_or_else(|_| original_browser_path.to_path_buf());
    let original_browser_path = normalized_windows_path(original_browser_path.to_string_lossy());
    let expected_mirror_root = std::fs::canonicalize(expected_mirror_root)
        .unwrap_or_else(|_| expected_mirror_root.to_path_buf());
    let expected_mirror_root = normalized_windows_path(expected_mirror_root.to_string_lossy());
    let browser_executable = match runtime_name {
        "chrome" => "chrome.exe",
        "edge" => "msedge.exe",
        other => panic!("unsupported Chromium E2E runtime: {other}"),
    };
    let mut last_error =
        format!("station process tree does not contain a {runtime_name} root and descendant");
    while tokio::time::Instant::now() < deadline {
        match process_snapshot() {
            Ok(entries) => {
                match station_descendant_process_ids(
                    &entries,
                    station_process_id,
                    browser_executable,
                ) {
                    Ok(process_ids) => {
                        let image_paths = process_ids
                            .into_iter()
                            .map(process_image_path)
                            .collect::<Result<Vec<_>, _>>();
                        match image_paths {
                            Ok(image_paths) => {
                                let mut mirror_roots = HashSet::new();
                                for image_path in image_paths {
                                    let image_path = normalized_windows_path(&image_path);
                                    assert_ne!(
                                        image_path, original_browser_path,
                                        "browser descendant ran from the original installed binary"
                                    );
                                    match runtime_mirror_root_for_image(
                                        &image_path,
                                        mirror_catalog,
                                    ) {
                                        Ok(root) => {
                                            mirror_roots.insert(root);
                                        }
                                        Err(error) => {
                                            last_error = error;
                                            mirror_roots.clear();
                                            break;
                                        }
                                    }
                                }
                                if mirror_roots.len() == 1
                                    && mirror_roots.contains(&expected_mirror_root)
                                {
                                    return;
                                }
                                if !mirror_roots.is_empty() {
                                    last_error = format!(
                                        "station descendants use unexpected runtime mirrors: {mirror_roots:?}"
                                    );
                                }
                            }
                            Err(error) => last_error = error,
                        }
                    }
                    Err(error) => last_error = error,
                }
            }
            Err(error) => last_error = error,
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("could not prove {runtime_name} runtime-mirror ownership: {last_error}");
}

async fn assert_chromium_descendants_use_installed_runtime(
    station_process_id: u32,
    installed_browser_path: &Path,
    mirror_catalog: &Path,
    runtime_name: &str,
) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let installed_browser_path = std::fs::canonicalize(installed_browser_path)
        .unwrap_or_else(|_| installed_browser_path.to_path_buf());
    let installed_runtime_root = installed_browser_path
        .parent()
        .expect("installed browser has an application root")
        .to_path_buf();
    let installed_browser_path =
        normalized_windows_path(installed_browser_path.to_string_lossy());
    let installed_runtime_root =
        normalized_windows_path(installed_runtime_root.to_string_lossy());
    let mirror_catalog = std::fs::canonicalize(mirror_catalog)
        .unwrap_or_else(|_| mirror_catalog.to_path_buf());
    let mirror_catalog = normalized_windows_path(mirror_catalog.to_string_lossy());
    let browser_executable = match runtime_name {
        "chrome" => "chrome.exe",
        "edge" => "msedge.exe",
        other => panic!("unsupported Chromium E2E runtime: {other}"),
    };
    let mut last_error = format!(
        "station process tree does not contain installed {runtime_name} descendants"
    );
    while tokio::time::Instant::now() < deadline {
        match process_snapshot().and_then(|entries| {
            station_descendant_process_ids(
                &entries,
                station_process_id,
                browser_executable,
            )
        }) {
            Ok(process_ids) => {
                match process_ids
                    .into_iter()
                    .map(process_image_path)
                    .collect::<Result<Vec<_>, _>>()
                {
                    Ok(image_paths) => {
                        let normalized = image_paths
                            .iter()
                            .map(normalized_windows_path)
                            .collect::<Vec<_>>();
                        assert!(
                            normalized.iter().all(|path| !path.starts_with(&mirror_catalog)),
                            "positive control used a station runtime mirror: {normalized:?}"
                        );
                        let root_path = normalized_windows_path(
                            chromium_root_process_image_path(
                                station_process_id,
                                runtime_name,
                            )
                            .to_string_lossy(),
                        );
                        if root_path == installed_browser_path
                            && normalized
                            .iter()
                            .all(|path| {
                                Path::new(path).starts_with(Path::new(&installed_runtime_root))
                            })
                        {
                            return;
                        }
                        last_error = format!(
                            "positive-control root={root_path} descendants used unexpected paths: {normalized:?}"
                        );
                    }
                    Err(error) => last_error = error,
                }
            }
            Err(error) => last_error = error,
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("could not prove direct installed {runtime_name} runtime use: {last_error}");
}

async fn chromium_browser_descendant_process_identities(
    station_process_id: u32,
    runtime_name: &str,
) -> Vec<ProcessIdentity> {
    let browser_executable = match runtime_name {
        "chrome" => "chrome.exe",
        "edge" => "msedge.exe",
        other => panic!("unsupported Chromium E2E runtime: {other}"),
    };
    let station_identity = current_process_identity(station_process_id)
        .expect("station process must be an active exact incarnation");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut last_error = "browser descendants are not live".to_owned();
    while tokio::time::Instant::now() < deadline {
        match process_snapshot() {
            Ok(entries) => {
                match station_descendant_process_ids(
                    &entries,
                    station_process_id,
                    browser_executable,
                ) {
                    Ok(descendants) => {
                        let descendants = descendants.into_iter().collect::<HashSet<_>>();
                        let browser_processes = entries
                            .iter()
                            .filter(|entry| {
                                descendants.contains(&entry.process_id)
                                    && entry.executable.eq_ignore_ascii_case(browser_executable)
                            })
                            .filter_map(|entry| current_process_identity(entry.process_id))
                            .filter(|identity| {
                                identity.creation_filetime
                                    >= station_identity.creation_filetime
                            })
                            .collect::<Vec<_>>();
                        if browser_processes.len() >= 2 {
                            return browser_processes;
                        }
                        last_error = format!(
                            "station has only {} live {browser_executable} descendants",
                            browser_processes.len()
                        );
                    }
                    Err(error) => last_error = error,
                }
            }
            Err(error) => last_error = error,
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("could not capture live {runtime_name} descendants: {last_error}");
}

async fn assert_processes_exit(
    process_identities: &[ProcessIdentity],
    context: &str,
) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let live = process_identities
            .iter()
            .copied()
            .filter(|identity| {
                current_process_identity(identity.process_id) == Some(*identity)
            })
            .collect::<Vec<_>>();
        if live.is_empty() {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("{context} left browser processes alive: {live:?}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

struct ControlledOrigin {
    address: SocketAddr,
    requests: Arc<AtomicUsize>,
    paths: Arc<Mutex<Vec<String>>>,
    stopping: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl ControlledOrigin {
    fn blocked() -> Self {
        Self::start_on("127.0.0.1", Arc::new(|_| {
            (
                "200 OK",
                Vec::new(),
                "<!doctype html><title>blocked origin</title>".to_owned(),
            )
        }))
    }

    fn peer_denied() -> Self {
        Self::start_on("127.0.0.2", Arc::new(|_| {
            (
                "200 OK",
                Vec::new(),
                "<!doctype html><title>peer denied</title>".to_owned(),
            )
        }))
    }

    fn allowed(blocked_origin: String) -> Self {
        Self::start_on("127.0.0.1", Arc::new(move |path| match path {
            "/document" => (
                "200 OK",
                Vec::new(),
                format!(
                    "<!doctype html><html><head><title>allowed origin</title></head><body><main id=\"ok\">allowed</main><img src=\"/allowed-pixel\"><img src=\"{blocked_origin}/pixel\"></body></html>"
                ),
            ),
            "/allowed-pixel" => ("200 OK", Vec::new(), "allowed pixel".to_owned()),
            "/popup" => (
                "200 OK",
                Vec::new(),
                "<!doctype html><title>popup</title><button id=\"popup\" onclick=\"window.open('/popup-child','_blank')\">open</button>".to_owned(),
            ),
            "/popup-child" => (
                "200 OK",
                Vec::new(),
                format!(
                    "<!doctype html><title>popup child</title><script>fetch('{blocked_origin}/popup-fetch').catch(()=>{{}});</script>"
                ),
            ),
            "/worker-page" => (
                "200 OK",
                Vec::new(),
                "<!doctype html><title>worker</title><main id=\"worker-state\">pending</main><script>const worker=new Worker('/worker.js');worker.onmessage=(event)=>{document.querySelector('#worker-state').textContent=event.data;};worker.onerror=()=>{document.querySelector('#worker-state').textContent='worker-error';};</script>".to_owned(),
            ),
            "/worker.js" => (
                "200 OK",
                vec![(
                    "Content-Type".to_owned(),
                    "text/javascript; charset=utf-8".to_owned(),
                )],
                format!(
                    "fetch('/worker-control').then(()=>fetch('{blocked_origin}/worker-fetch')).then(()=>postMessage('attempted'),()=>postMessage('attempted'));"
                ),
            ),
            "/worker-control" => ("200 OK", Vec::new(), "worker control".to_owned()),
            "/redirect-blocked" => (
                "302 Found",
                vec![("Location".to_owned(), format!("{blocked_origin}/redirect-target"))],
                String::new(),
            ),
            _ => ("404 Not Found", Vec::new(), String::new()),
        }))
    }

    fn webrtc_probe(
        stun_ipv4_address: SocketAddr,
        stun_ipv6_address: SocketAddr,
        turn_tcp_address: SocketAddr,
    ) -> Self {
        let page = r#"<!doctype html><html><head><title>WebRTC containment fixture</title><link rel="icon" href="data:,"></head><body><main id="webrtc-state">pending</main><script>(async()=>{const state=document.querySelector('#webrtc-state');if(typeof RTCPeerConnection!=='function'){state.textContent='api-missing';return;}const probes=[['udp4',{urls:'stun:__STUN_IPV4_ADDRESS__'}],['udp6',{urls:'stun:__STUN_IPV6_ADDRESS__'}],['turn-tcp',{urls:'turn:__TURN_TCP_ADDRESS__?transport=tcp',username:'dig2browser',credential:'containment-proof'}]];window.__dig2browserWebRtcProbes=[];try{const attempts=probes.map(async([name,iceServer])=>{const peer=new RTCPeerConnection({iceServers:[iceServer]});window.__dig2browserWebRtcProbes.push(peer);peer.createDataChannel(name);const offer=await peer.createOffer();await peer.setLocalDescription(offer);return name+':'+peer.iceGatheringState;});state.textContent='ice-attempted:'+(await Promise.all(attempts)).join(',');}catch(error){state.textContent='ice-error:'+error.name;}})();</script></body></html>"#
            .replace("__STUN_IPV4_ADDRESS__", &stun_ipv4_address.to_string())
            .replace("__STUN_IPV6_ADDRESS__", &stun_ipv6_address.to_string())
            .replace("__TURN_TCP_ADDRESS__", &turn_tcp_address.to_string());
        Self::start_on("127.0.0.1", Arc::new(move |path| match path {
            "/webrtc-probe" => ("200 OK", Vec::new(), page.clone()),
            _ => ("404 Not Found", Vec::new(), String::new()),
        }))
    }

    fn direct_tcp_probe() -> Self {
        let bind_ip = selected_non_loopback_ipv4().to_string();
        Self::start_on(&bind_ip, Arc::new(|path| match path {
            "/direct-tcp-probe" => (
                "200 OK",
                Vec::new(),
                "<!doctype html><title>direct tcp probe</title>".to_owned(),
            ),
            _ => ("404 Not Found", Vec::new(), String::new()),
        }))
    }

    fn start_on(bind_ip: &str, response: Responder) -> Self {
        let listener = TcpListener::bind((bind_ip, 0))
            .expect("bind navigation-policy controlled origin");
        let address = listener.local_addr().expect("read controlled origin address");
        listener
            .set_nonblocking(true)
            .expect("make controlled origin nonblocking");
        let requests = Arc::new(AtomicUsize::new(0));
        let paths = Arc::new(Mutex::new(Vec::new()));
        let stopping = Arc::new(AtomicBool::new(false));
        let thread_requests = Arc::clone(&requests);
        let thread_paths = Arc::clone(&paths);
        let thread_stopping = Arc::clone(&stopping);
        let thread = thread::spawn(move || {
            while !thread_stopping.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_nonblocking(false)
                            .expect("make controlled connection blocking");
                        thread_requests.fetch_add(1, Ordering::AcqRel);
                        let _ = serve_request(&mut stream, &response, &thread_paths);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("controlled origin failed: {error}"),
                }
            }
        });
        Self {
            address,
            requests,
            paths,
            stopping,
            thread: Some(thread),
        }
    }

    fn origin(&self) -> String {
        format!("http://{}", self.address)
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.origin())
    }

    fn request_count(&self) -> usize {
        self.requests.load(Ordering::Acquire)
    }

    fn path_count(&self, expected: &str) -> usize {
        self.paths
            .lock()
            .expect("controlled origin paths remain available")
            .iter()
            .filter(|path| path.as_str() == expected)
            .count()
    }
}

struct ControlledUdpReceiver {
    address: SocketAddr,
    datagrams: Arc<AtomicUsize>,
    stun_datagrams: Arc<AtomicUsize>,
    stopping: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl ControlledUdpReceiver {
    fn start_ipv4() -> Self {
        Self::start_on(SocketAddr::V4(SocketAddrV4::new(
            selected_non_loopback_ipv4(),
            0,
        )))
    }

    fn start_ipv6() -> Self {
        let bind_address = selected_ipv6_address()
            .unwrap_or_else(|| SocketAddrV6::new(std::net::Ipv6Addr::LOCALHOST, 0, 0, 0));
        Self::start_on(SocketAddr::V6(bind_address))
    }

    fn start_on(bind_address: SocketAddr) -> Self {
        let socket = UdpSocket::bind(bind_address)
            .expect("bind controlled WebRTC STUN receiver");
        let address = socket.local_addr().expect("read STUN receiver address");
        socket
            .set_nonblocking(true)
            .expect("make STUN receiver nonblocking");
        let datagrams = Arc::new(AtomicUsize::new(0));
        let stun_datagrams = Arc::new(AtomicUsize::new(0));
        let stopping = Arc::new(AtomicBool::new(false));
        let thread_datagrams = Arc::clone(&datagrams);
        let thread_stun_datagrams = Arc::clone(&stun_datagrams);
        let thread_stopping = Arc::clone(&stopping);
        let thread = thread::spawn(move || {
            let mut buffer = [0_u8; 2048];
            while !thread_stopping.load(Ordering::Acquire) {
                match socket.recv_from(&mut buffer) {
                    Ok((count, _peer)) => {
                        thread_datagrams.fetch_add(1, Ordering::AcqRel);
                        let declared_length = if count >= 4 {
                            usize::from(u16::from_be_bytes([buffer[2], buffer[3]]))
                        } else {
                            0
                        };
                        if count >= 20
                            && u16::from_be_bytes([buffer[0], buffer[1]]) == 0x0001
                            && declared_length % 4 == 0
                            && count == 20 + declared_length
                            && buffer[4..8] == [0x21, 0x12, 0xa4, 0x42]
                        {
                            thread_stun_datagrams.fetch_add(1, Ordering::AcqRel);
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("controlled STUN receiver failed: {error}"),
                }
            }
        });
        Self {
            address,
            datagrams,
            stun_datagrams,
            stopping,
            thread: Some(thread),
        }
    }

    fn address(&self) -> SocketAddr {
        self.address
    }

    fn datagram_count(&self) -> usize {
        self.datagrams.load(Ordering::Acquire)
    }

    fn stun_datagram_count(&self) -> usize {
        self.stun_datagrams.load(Ordering::Acquire)
    }

    fn prove_ready(&self) {
        let baseline = self.datagram_count();
        let sender_address = match self.address {
            SocketAddr::V4(address) => SocketAddr::V4(SocketAddrV4::new(*address.ip(), 0)),
            SocketAddr::V6(address) => SocketAddr::V6(SocketAddrV6::new(
                *address.ip(),
                0,
                address.flowinfo(),
                address.scope_id(),
            )),
        };
        let sender = UdpSocket::bind(sender_address)
            .expect("bind controlled STUN receiver readiness sender");
        sender
            .send_to(b"dig2browser-udp-readiness", self.address)
            .expect("send STUN receiver readiness datagram");
        for _ in 0..100 {
            if self.datagram_count() > baseline {
                return;
            }
            thread::sleep(Duration::from_millis(5));
        }
        panic!("controlled STUN receiver did not observe its readiness datagram");
    }

    async fn wait_for_stun(&self, timeout: Duration) -> usize {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let count = self.stun_datagram_count();
            if count > 0 || tokio::time::Instant::now() >= deadline {
                return count;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
}

fn selected_non_loopback_ipv4() -> Ipv4Addr {
    let route_probe = UdpSocket::bind("0.0.0.0:0")
        .expect("bind local-interface route probe");
    route_probe
        .connect("192.0.2.1:9")
        .expect("select a local IPv4 interface for the direct-egress receiver");
    let IpAddr::V4(local_ip) = route_probe
        .local_addr()
        .expect("read selected local IPv4 interface")
        .ip()
    else {
        panic!("IPv4 route probe selected a non-IPv4 interface");
    };
    assert!(
        !local_ip.is_loopback() && !local_ip.is_unspecified(),
        "WebRTC egress E2E requires a non-loopback local IPv4 interface"
    );
    local_ip
}

fn selected_ipv6_address() -> Option<SocketAddrV6> {
    let route_probe = UdpSocket::bind("[::]:0").ok()?;
    route_probe.connect("[2001:db8::1]:9").ok()?;
    let SocketAddr::V6(address) = route_probe.local_addr().ok()? else {
        return None;
    };
    if address.ip().is_loopback()
        || address.ip().is_unspecified()
        || address.ip().is_unicast_link_local()
    {
        None
    } else {
        Some(SocketAddrV6::new(
            *address.ip(),
            0,
            address.flowinfo(),
            address.scope_id(),
        ))
    }
}

struct ControlledTurnTcpReceiver {
    address: SocketAddr,
    connections: Arc<AtomicUsize>,
    allocate_requests: Arc<AtomicUsize>,
    stopping: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl ControlledTurnTcpReceiver {
    fn start() -> Self {
        let listener = TcpListener::bind((selected_non_loopback_ipv4(), 0))
            .expect("bind controlled WebRTC TURN/TCP receiver");
        let address = listener.local_addr().expect("read TURN/TCP receiver address");
        listener
            .set_nonblocking(true)
            .expect("make TURN/TCP receiver nonblocking");
        let connections = Arc::new(AtomicUsize::new(0));
        let allocate_requests = Arc::new(AtomicUsize::new(0));
        let stopping = Arc::new(AtomicBool::new(false));
        let thread_connections = Arc::clone(&connections);
        let thread_allocate_requests = Arc::clone(&allocate_requests);
        let thread_stopping = Arc::clone(&stopping);
        let thread = thread::spawn(move || {
            while !thread_stopping.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _peer)) => {
                        thread_connections.fetch_add(1, Ordering::AcqRel);
                        stream
                            .set_read_timeout(Some(Duration::from_millis(500)))
                            .expect("bound TURN/TCP receiver read timeout");
                        let mut received = Vec::new();
                        let mut buffer = [0_u8; 2048];
                        loop {
                            match stream.read(&mut buffer) {
                                Ok(0) => break,
                                Ok(count) => {
                                    received.extend_from_slice(&buffer[..count]);
                                    if contains_turn_allocate_request(&received) {
                                        thread_allocate_requests.fetch_add(1, Ordering::AcqRel);
                                        break;
                                    }
                                    if received.len() >= 8192 {
                                        break;
                                    }
                                }
                                Err(error)
                                    if matches!(
                                        error.kind(),
                                        std::io::ErrorKind::WouldBlock
                                            | std::io::ErrorKind::TimedOut
                                    ) =>
                                {
                                    break;
                                }
                                Err(error) => panic!("controlled TURN/TCP receiver failed: {error}"),
                            }
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("controlled TURN/TCP listener failed: {error}"),
                }
            }
        });
        Self {
            address,
            connections,
            allocate_requests,
            stopping,
            thread: Some(thread),
        }
    }

    fn address(&self) -> SocketAddr {
        self.address
    }

    fn connection_count(&self) -> usize {
        self.connections.load(Ordering::Acquire)
    }

    fn allocate_request_count(&self) -> usize {
        self.allocate_requests.load(Ordering::Acquire)
    }

    fn prove_ready(&self) {
        let baseline = self.connection_count();
        TcpStream::connect_timeout(&self.address, Duration::from_secs(1))
            .expect("connect controlled TURN/TCP readiness probe");
        for _ in 0..100 {
            if self.connection_count() > baseline {
                return;
            }
            thread::sleep(Duration::from_millis(5));
        }
        panic!("controlled TURN/TCP receiver did not observe its readiness connection");
    }

    async fn wait_for_allocate_request(&self, timeout: Duration) -> usize {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let count = self.allocate_request_count();
            if count > 0 || tokio::time::Instant::now() >= deadline {
                return count;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
}

impl Drop for ControlledTurnTcpReceiver {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        let _ = TcpStream::connect_timeout(&self.address, Duration::from_millis(100));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn contains_turn_allocate_request(received: &[u8]) -> bool {
    received.windows(20).any(|header| {
        u16::from_be_bytes([header[0], header[1]]) == 0x0003
            && usize::from(u16::from_be_bytes([header[2], header[3]])) % 4 == 0
            && header[4..8] == [0x21, 0x12, 0xa4, 0x42]
    })
}

impl Drop for ControlledUdpReceiver {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for ControlledOrigin {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        let _ = TcpStream::connect_timeout(&self.address, Duration::from_millis(100));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(feature = "tls-test-hooks")]
const HTTPS_PAGE: &str = "<!doctype html><html><head><title>secure fixture</title><link rel=\"icon\" href=\"data:,\"></head><body><main id=\"secure\">pinned transport</main></body></html>";

#[cfg(feature = "tls-test-hooks")]
struct ControlledHttpsOrigin {
    address: SocketAddr,
    directory: PathBuf,
    certificate_spki: String,
    child: Child,
}

#[cfg(feature = "tls-test-hooks")]
impl ControlledHttpsOrigin {
    fn start(base: &Path) -> Self {
        let directory = base.join("https-fixture");
        std::fs::create_dir_all(&directory).expect("create HTTPS fixture directory");
        let openssl = openssl_executable();
        let key = directory.join("key.pem");
        let certificate = directory.join("certificate.pem");
        let public_key = directory.join("public-key.pem");
        let public_key_der = directory.join("public-key.der");
        let public_key_sha256 = directory.join("public-key.sha256");
        let public_key_sha256_base64 = directory.join("public-key.sha256.base64");
        run_openssl(
            &openssl,
            &[
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-sha256",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=127.0.0.1",
                "-addext",
                "subjectAltName=IP:127.0.0.1",
                "-keyout",
                key.to_str().expect("UTF-8 HTTPS key path"),
                "-out",
                certificate.to_str().expect("UTF-8 HTTPS certificate path"),
            ],
        );
        run_openssl(
            &openssl,
            &[
                "x509",
                "-in",
                certificate.to_str().expect("UTF-8 HTTPS certificate path"),
                "-pubkey",
                "-noout",
                "-out",
                public_key.to_str().expect("UTF-8 HTTPS public-key path"),
            ],
        );
        run_openssl(
            &openssl,
            &[
                "pkey",
                "-pubin",
                "-in",
                public_key.to_str().expect("UTF-8 HTTPS public-key path"),
                "-outform",
                "DER",
                "-out",
                public_key_der.to_str().expect("UTF-8 HTTPS DER path"),
            ],
        );
        run_openssl(
            &openssl,
            &[
                "dgst",
                "-sha256",
                "-binary",
                "-out",
                public_key_sha256.to_str().expect("UTF-8 HTTPS digest path"),
                public_key_der.to_str().expect("UTF-8 HTTPS DER path"),
            ],
        );
        run_openssl(
            &openssl,
            &[
                "base64",
                "-A",
                "-in",
                public_key_sha256.to_str().expect("UTF-8 HTTPS digest path"),
                "-out",
                public_key_sha256_base64
                    .to_str()
                    .expect("UTF-8 HTTPS base64 path"),
            ],
        );
        let certificate_spki = std::fs::read_to_string(&public_key_sha256_base64)
            .expect("read HTTPS SPKI SHA-256 base64");
        assert_eq!(certificate_spki.len(), 44, "canonical SHA-256 base64 length");
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{}",
            HTTPS_PAGE.len(),
            HTTPS_PAGE
        );
        std::fs::write(directory.join("secure"), response)
            .expect("write controlled HTTPS response");

        let listener = TcpListener::bind("127.0.0.1:0").expect("reserve HTTPS fixture port");
        let address = listener.local_addr().expect("HTTPS fixture address");
        drop(listener);
        let child = Command::new(&openssl)
            .args([
                "s_server",
                "-4",
                "-accept",
                &format!("127.0.0.1:{}", address.port()),
                "-cert",
                certificate.to_str().expect("UTF-8 HTTPS certificate path"),
                "-key",
                key.to_str().expect("UTF-8 HTTPS key path"),
                "-HTTP",
                "-quiet",
            ])
            .current_dir(&directory)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start controlled OpenSSL HTTPS fixture");
        let mut fixture = Self {
            address,
            directory,
            certificate_spki,
            child,
        };
        fixture.wait_until_ready();
        fixture
    }

    fn origin(&self) -> String {
        format!("https://{}", self.address)
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.origin())
    }

    fn certificate_spki(&self) -> &str {
        &self.certificate_spki
    }

    fn wait_until_ready(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if self.child.try_wait().expect("poll HTTPS fixture").is_some() {
                panic!("OpenSSL HTTPS fixture exited before accepting connections");
            }
            if let Ok(stream) = TcpStream::connect_timeout(
                &self.address,
                Duration::from_millis(100),
            ) {
                drop(stream);
                return;
            }
            assert!(
                Instant::now() < deadline,
                "OpenSSL HTTPS fixture did not bind its controlled listener"
            );
            thread::sleep(Duration::from_millis(25));
        }
    }
}

#[cfg(feature = "tls-test-hooks")]
impl Drop for ControlledHttpsOrigin {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

#[cfg(feature = "tls-test-hooks")]
fn openssl_executable() -> PathBuf {
    if let Some(path) = std::env::var_os("DIG2BROWSER_OPENSSL") {
        return PathBuf::from(path);
    }
    let git_openssl = PathBuf::from(r"C:\Program Files\Git\mingw64\bin\openssl.exe");
    if git_openssl.is_file() {
        return git_openssl;
    }
    PathBuf::from("openssl")
}

#[cfg(feature = "tls-test-hooks")]
fn run_openssl(executable: &Path, arguments: &[&str]) {
    let output = Command::new(executable)
        .args(arguments)
        .stdin(Stdio::null())
        .output()
        .expect("run OpenSSL fixture command");
    assert!(
        output.status.success(),
        "OpenSSL fixture command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn serve_request(
    stream: &mut TcpStream,
    response: &Responder,
    paths: &Mutex<Vec<String>>,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut request = Vec::with_capacity(4096);
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let mut chunk = [0_u8; 1024];
        let count = stream.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..count]);
        if request.len() >= 16 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "controlled-origin headers exceed bound",
            ));
        }
    }
    let request = String::from_utf8_lossy(&request);
    let path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");
    paths
        .lock()
        .expect("controlled origin paths remain available")
        .push(path.to_owned());
    let (status, headers, body) = response(path);
    write!(stream, "HTTP/1.1 {status}\r\n")?;
    let has_content_type = headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("content-type"));
    for (name, value) in headers {
        write!(stream, "{name}: {value}\r\n")?;
    }
    if !has_content_type {
        write!(stream, "Content-Type: text/html; charset=utf-8\r\n")?;
    }
    write!(
        stream,
        "Content-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body.as_bytes())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stationd_remote_shutdown_at_connection_capacity_exits_e2e() {
    let unique = uuid::Uuid::new_v4();
    let pipe_name = format!("dig2browser-capacity-shutdown-{unique}");
    let profiles = e2e_temp_base().join(format!("dig2browser-capacity-shutdown-{unique}"));
    std::fs::create_dir_all(&profiles).expect("create capacity-shutdown profiles root");
    let mut daemon = spawn_capacity_shutdown_stationd(&pipe_name, &profiles);
    let client = connect(&pipe_name).await;

    client
        .shutdown()
        .await
        .expect("request shutdown while the only connection slot is occupied");
    let status = tokio::time::timeout(Duration::from_secs(15), daemon.wait())
        .await
        .expect("station did not exit after capacity-bound remote shutdown")
        .expect("wait for capacity-shutdown station");
    assert!(status.success(), "capacity-shutdown station failed: {status}");
    let (stdout, stderr) = read_child_output(&mut daemon).await;
    assert!(stderr.is_empty(), "capacity-shutdown station wrote stderr: {stderr}");
    let report: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("parse capacity-shutdown station report");
    assert_eq!(report["outcome"], "clean", "unclean station report: {stdout}");
    assert_eq!(report["stop_reason"], "remote_request");
    assert_eq!(report["accepted_connections"], 1);
    assert_eq!(report["completed_connections"], 1);
    assert_eq!(report["aborted_connections"], 0);

    let released_profiles = ProfilesRootOwnership::acquire(&profiles)
        .expect("capacity-shutdown station releases profiles-root ownership");
    drop(released_profiles);
    remove_tree(&profiles).await;
}

#[cfg(feature = "tls-test-hooks")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stationd_rejects_malformed_test_certificate_error_spki_before_profile_acquisition() {
    let unique = uuid::Uuid::new_v4();
    let pipe_name = format!("dig2browser-invalid-spki-{unique}");
    let profiles = e2e_temp_base().join(format!("dig2browser-invalid-spki-{unique}"));
    assert!(!profiles.exists(), "invalid-config profile fixture must start absent");
    let mut daemon = spawn_https_stationd(
        &pipe_name,
        &profiles,
        "https://127.0.0.1:443",
        Some("AA=="),
    );
    let status = tokio::time::timeout(Duration::from_secs(15), daemon.wait())
        .await
        .expect("invalid SPKI station exit timeout")
        .expect("wait for invalid SPKI station");
    assert!(!status.success(), "invalid SPKI station unexpectedly started");
    let (stdout, stderr) = read_child_output(&mut daemon).await;
    assert!(stdout.is_empty(), "invalid SPKI station wrote stdout: {stdout}");
    assert!(
        stderr.contains("\"error_class\":\"invalid_config\""),
        "invalid SPKI station returned wrong error: {stderr}"
    );
    assert!(
        !profiles.exists(),
        "invalid SPKI configuration acquired or created the profiles root"
    );
}

#[cfg(feature = "tls-test-hooks")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires installed Chrome, OpenSSL, and --features tls-test-hooks"]
async fn stationd_chrome_spki_certificate_exception_reaches_https_through_owned_connect_e2e() {
    let _serial = e2e_serial_guard().await;
    let unique = uuid::Uuid::new_v4();
    let base = e2e_temp_base().join(format!("dig2browser-https-spki-{unique}"));
    std::fs::create_dir_all(&base).expect("create HTTPS SPKI E2E root");
    let https = ControlledHttpsOrigin::start(&base);

    let pinned_pipe = format!("dig2browser-https-pinned-{unique}");
    let pinned_profiles = base.join("profiles-pinned");
    std::fs::create_dir_all(&pinned_profiles).expect("create pinned profiles root");
    let mut pinned_daemon = spawn_https_stationd(
        &pinned_pipe,
        &pinned_profiles,
        &https.origin(),
        Some(https.certificate_spki()),
    );
    let pinned_client = connect(&pinned_pipe).await;
    let requested_url = https.url("/secure");
    let result = pinned_client
        .run_task("https-pinned", https_task(requested_url.clone()))
        .await
        .expect("exact SPKI certificate exception must allow the controlled HTTPS document");
    assert_eq!(result.replies().len(), 3);
    assert_eq!(result.replies()[0], TaskReply::Acknowledged);
    assert_eq!(
        result.replies()[1],
        TaskReply::Text("pinned transport".to_owned())
    );
    let TaskReply::Capture(capture) = &result.replies()[2] else {
        panic!("pinned HTTPS task did not return an HTML capture");
    };
    assert_eq!(capture.requested_url, requested_url);
    assert_eq!(capture.final_url, requested_url);
    assert_eq!(capture.http_status, Some(200));
    assert_eq!(capture.title, "secure fixture");
    assert!(
        String::from_utf8_lossy(&capture.html).contains("pinned transport"),
        "HTML capture did not contain the controlled HTTPS marker"
    );
    pinned_client
        .shutdown()
        .await
        .expect("request clean pinned station shutdown");
    drop(pinned_client);
    assert_https_clean_exit(&mut pinned_daemon).await;
    let released_profiles = ProfilesRootOwnership::acquire(&pinned_profiles)
        .expect("clean HTTPS station shutdown releases profiles-root ownership");
    let released_profile = ProfileOwnershipGuard::acquire(pinned_profiles.join("https-pinned"))
        .expect("clean HTTPS station shutdown releases the browser profile");
    drop(released_profile);
    drop(released_profiles);
    drop(https);

    remove_tree(&base).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a medium-integrity test process, UAC for the WFP broker, installed Chrome, and --features containment-test-hooks"]
async fn stationd_chrome_wfp_app_id_allows_only_exact_proxy_and_blocks_direct_egress_e2e() {
    let _serial = e2e_serial_guard().await;
    let run = WfpE2eRun::start(
        "stationd_chrome_wfp_app_id_allows_only_exact_proxy_and_blocks_direct_egress_e2e",
    );
    run.install_panic_log();
    run_wfp_app_id_containment_e2e("chrome", RuntimeKind::Chrome).await;
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires installed Chrome; proves the real runtime tree can be mirrored and removed without UAC or browser launch"]
async fn chrome_runtime_mirror_materializes_and_removes_e2e() {
    let _serial = e2e_serial_guard().await;
    let run = WfpE2eRun::start(
        "chrome_runtime_mirror_materializes_and_removes_e2e",
    );
    run.install_panic_log();
    let unique = uuid::Uuid::new_v4();
    let profiles = e2e_temp_base().join(format!(
        "dig2browser-runtime-mirror-chrome-{unique}"
    ));
    std::fs::create_dir_all(&profiles).expect("create runtime-mirror E2E profiles root");
    let prepared = prepare_webrtc_runtime("chrome", RuntimeKind::Chrome);
    let source = BrowserBinary {
        path: prepared.original_browser_path.clone(),
        kind: BrowserKind::Chrome,
    };
    run.event(
        "test",
        "runtime_mirror_materialization_started",
        serde_json::json!({
            "source": source.path,
            "catalog": prepared.mirror_catalog,
            "catalog_entries_before": prepared.mirror_entries_before.len(),
        }),
    );
    let mirror = WindowsBrowserRuntimeMirror::materialize(&source, &profiles)
        .unwrap_or_else(|error| {
            run.event(
                "test",
                "runtime_mirror_materialization_failed",
                serde_json::json!({ "error": error.to_string() }),
            );
            panic!("materialize real Chrome runtime mirror: {error}");
        });
    let mirror_root = mirror.root().to_path_buf();
    let source_identity = file_identity_and_size(&source.path);
    let mirror_identity = file_identity_and_size(&mirror.browser_binary().path);
    run.event(
        "test",
        "runtime_mirror_materialized",
        serde_json::json!({
            "mirror_root": mirror_root,
            "source_file_id": source_identity.1,
            "mirror_file_id": mirror_identity.1,
            "source_bytes": source_identity.2,
            "mirror_bytes": mirror_identity.2,
            "mode": if source_identity.0 == mirror_identity.0
                && source_identity.1 == mirror_identity.1
            {
                "hard_link"
            } else {
                "copy"
            },
        }),
    );
    mirror
        .remove()
        .expect("remove real Chrome runtime mirror");
    assert!(!mirror_root.exists(), "removed runtime mirror still exists");
    // The catalog is the shared, station-owned `%LOCALAPPDATA%` directory
    // (`runtime_mirror_catalog()` cannot be relocated to an isolated per-run
    // temp dir; see `ensure_mirror_base`/`existing_mirror_base` in
    // `dig2browser/src/windows_runtime_mirror.rs`), so it may already carry
    // foreign entries left by other runs. Assert only that this test did not
    // leave a new entry behind, ignoring whatever pre-existed the baseline.
    let mirror_entries_after = directory_entry_names(&prepared.mirror_catalog);
    assert!(
        mirror_entries_after.is_subset(&prepared.mirror_entries_before),
        "runtime-mirror E2E left a newly-created runtime mirror or staging directory behind: before={:?}, after={mirror_entries_after:?}",
        prepared.mirror_entries_before,
    );
    remove_tree(&profiles).await;
    run.event(
        "test",
        "runtime_mirror_removed",
        serde_json::json!({ "mirror_root": mirror_root }),
    );
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires installed Edge; proves the copied real runtime can reach a controlled direct TCP fixture without WFP or UAC"]
async fn edge_runtime_mirror_reaches_direct_tcp_fixture_e2e() {
    let _serial = e2e_serial_guard().await;
    let run = WfpE2eRun::start(
        "edge_runtime_mirror_reaches_direct_tcp_fixture_e2e",
    );
    run.install_panic_log();
    let unique = uuid::Uuid::new_v4();
    let profiles = e2e_temp_base().join(format!(
        "dig2browser-runtime-mirror-edge-{unique}"
    ));
    std::fs::create_dir_all(&profiles).expect("create Edge runtime-mirror E2E profiles root");
    let prepared = prepare_webrtc_runtime("edge", RuntimeKind::Edge);
    let source = BrowserBinary {
        path: prepared.original_browser_path.clone(),
        kind: BrowserKind::Edge,
    };
    let materialization_started = Instant::now();
    run.event(
        "test",
        "runtime_mirror_materialization_started",
        serde_json::json!({
            "source": source.path,
            "catalog": prepared.mirror_catalog,
            "catalog_entries_before": prepared.mirror_entries_before.len(),
        }),
    );
    let mirror = WindowsBrowserRuntimeMirror::materialize(&source, &profiles)
        .unwrap_or_else(|error| {
            run.event(
                "test",
                "runtime_mirror_materialization_failed",
                serde_json::json!({
                    "elapsed_ms": materialization_started.elapsed().as_millis() as u64,
                    "error": error.to_string(),
                }),
            );
            panic!("materialize real Edge runtime mirror: {error}");
        });
    let mirror_root = mirror.root().to_path_buf();
    let source_identity = file_identity_and_size(&source.path);
    let mirror_identity = file_identity_and_size(&mirror.browser_binary().path);
    run.event(
        "test",
        "runtime_mirror_materialized",
        serde_json::json!({
            "elapsed_ms": materialization_started.elapsed().as_millis() as u64,
            "mirror_root": mirror_root,
            "source_file_id": source_identity.1,
            "mirror_file_id": mirror_identity.1,
            "source_bytes": source_identity.2,
            "mirror_bytes": mirror_identity.2,
            "mode": if source_identity.0 == mirror_identity.0
                && source_identity.1 == mirror_identity.1
            {
                "hard_link"
            } else {
                "copy"
            },
        }),
    );
    let origin = ControlledOrigin::direct_tcp_probe();
    let context = "uncontained runtime-mirror edge";
    let observation = run_owned_browser_direct_tcp_probe(
        RuntimeKind::Edge,
        mirror.browser_binary().path.clone(),
        &origin,
        context,
    )
    .await;
    drop(origin);
    remove_runtime_mirror_with_evidence(
        mirror,
        "remove real Edge runtime mirror after direct TCP probe",
    )
    .await
    .unwrap_or_else(|error| panic!("remove real Edge runtime mirror: {error}"));
    assert!(!mirror_root.exists(), "removed Edge runtime mirror still exists");
    // Same shared-catalog caveat as the Chrome runtime-mirror E2E above:
    // assert no new entry survives this test, ignoring foreign pre-existing
    // entries in the shared `%LOCALAPPDATA%` catalog.
    let mirror_entries_after = directory_entry_names(&prepared.mirror_catalog);
    assert!(
        mirror_entries_after.is_subset(&prepared.mirror_entries_before),
        "Edge runtime-mirror E2E left a newly-created runtime mirror or staging directory behind: before={:?}, after={mirror_entries_after:?}",
        prepared.mirror_entries_before,
    );
    remove_tree(&profiles).await;
    run.event(
        "test",
        "runtime_mirror_removed",
        serde_json::json!({ "mirror_root": mirror_root }),
    );
    assert_direct_tcp_probe_observation(observation, true, context);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a medium-integrity test process, UAC for the WFP broker, installed Edge, and --features containment-test-hooks"]
async fn stationd_edge_wfp_app_id_allows_only_exact_proxy_and_blocks_direct_egress_e2e() {
    let _serial = e2e_serial_guard().await;
    let run = WfpE2eRun::start(
        "stationd_edge_wfp_app_id_allows_only_exact_proxy_and_blocks_direct_egress_e2e",
    );
    run.install_panic_log();
    run_wfp_app_id_containment_e2e("edge", RuntimeKind::Edge).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires installed Chrome and --features containment-test-hooks; proves IPv4/IPv6 STUN UDP and direct HTTP TCP positive controls"]
async fn stationd_chrome_direct_egress_positive_control_e2e() {
    let _serial = e2e_serial_guard().await;
    let run = WfpE2eRun::start(
        "stationd_chrome_direct_egress_positive_control_e2e",
    );
    run.install_panic_log();
    run_direct_stun_positive_control_only_e2e("chrome", RuntimeKind::Chrome).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires installed Edge and --features containment-test-hooks; proves IPv4/IPv6 STUN UDP and direct HTTP TCP positive controls"]
async fn stationd_edge_direct_egress_positive_control_e2e() {
    let _serial = e2e_serial_guard().await;
    let run = WfpE2eRun::start(
        "stationd_edge_direct_egress_positive_control_e2e",
    );
    run.install_panic_log();
    run_direct_stun_positive_control_only_e2e("edge", RuntimeKind::Edge).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a medium-integrity test process, UAC for the WFP broker, installed Chrome, and --features containment-test-hooks"]
async fn stationd_chrome_wfp_broker_crash_is_fail_closed_and_reconciles_e2e() {
    let _serial = e2e_serial_guard().await;
    let run = WfpE2eRun::start(
        "stationd_chrome_wfp_broker_crash_is_fail_closed_and_reconciles_e2e",
    );
    run.install_panic_log();
    assert_containment_test_hooks_enabled();
    let runtime_name = "chrome";
    let runtime_kind = RuntimeKind::Chrome;
    let unique = uuid::Uuid::new_v4();
    let profiles = e2e_temp_base().join(format!(
        "dig2browser-containment-crash-{runtime_name}-{unique}"
    ));
    let traces = e2e_temp_base().join(format!(
        "dig2browser-containment-crash-trace-{runtime_name}-{unique}"
    ));
    let successor_profiles = e2e_temp_base().join(format!(
        "dig2browser-containment-crash-successor-{runtime_name}-{unique}"
    ));
    std::fs::create_dir_all(&profiles).expect("create crash E2E profiles root");
    std::fs::create_dir_all(&traces).expect("create crash E2E trace root");
    std::fs::create_dir_all(&successor_profiles)
        .expect("create crash successor E2E profiles root");
    let prepared = prepare_webrtc_runtime(runtime_name, runtime_kind);
    let udp_ipv4 = ControlledUdpReceiver::start_ipv4();
    let udp_ipv6 = ControlledUdpReceiver::start_ipv6();
    let turn_tcp = ControlledTurnTcpReceiver::start();
    let direct_tcp = ControlledOrigin::direct_tcp_probe();
    udp_ipv4.prove_ready();
    udp_ipv6.prove_ready();
    turn_tcp.prove_ready();
    let turn_tcp_connection_baseline = turn_tcp.connection_count();
    let origin = ControlledOrigin::webrtc_probe(
        udp_ipv4.address(),
        udp_ipv6.address(),
        turn_tcp.address(),
    );
    let allowed_origin = origin.origin();
    let first_broker_pipe = format!("dig2browser-wfp-crash-first-{unique}");
    let first_station_pipe = format!("dig2browser-wfp-crash-station-first-{unique}");
    let (first_broker_capability, first_station_capability) =
        WindowsWfpBrokerCapability::generate_pair();
    let mut first_broker = spawn_wfp_broker(
        &first_broker_pipe,
        &prepared.mirror_catalog,
        first_broker_capability,
    )
    .await;
    let first_broker_pid = first_broker.id();
    assert!(
        first_broker.security().elevated
            && first_broker.security().is_high_integrity(),
        "WFP broker must be the only elevated high-integrity process"
    );
    let mut first_daemon = spawn_webrtc_stationd(
        &first_station_pipe,
        &profiles,
        &traces,
        runtime_name,
        &[&allowed_origin],
        WebRtcStationOptions {
            broker_pipe_name: Some(&first_broker_pipe),
            broker_capability: Some(first_station_capability),
            command_timeout_seconds: 60,
            close_timeout_seconds: None,
            test_close_delay_millis: None,
        },
    )
    .await;
    let first_client = connect(&first_station_pipe).await;
    let profile_id = "webrtc-wfp-crash-chrome";
    assert_webrtc_probe_completes(
        &first_client,
        profile_id,
        runtime_kind,
        &origin,
        runtime_name,
    )
    .await;

    let mirror_entries = directory_entry_names(&prepared.mirror_catalog);
    let created_mirrors = mirror_entries
        .difference(&prepared.mirror_entries_before)
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        created_mirrors.len(),
        1,
        "first broker did not create exactly one crash-scoped mirror: {created_mirrors:?}"
    );
    let mirror_root = prepared.mirror_catalog.join(&created_mirrors[0]);
    let first_station_pid = first_daemon
        .id()
        .expect("first containment station remains live");
    assert_chromium_descendants_use_station_mirror(
        first_station_pid,
        &prepared.original_browser_path,
        &prepared.mirror_catalog,
        &mirror_root,
        runtime_name,
    )
    .await;
    let mirror_browser_path = chromium_root_process_image_path(
        first_station_pid,
        runtime_name,
    );
    let direct_probe_context = format!("WFP-contained {runtime_name}");
    let direct_probe = run_owned_browser_direct_tcp_probe(
        runtime_kind,
        mirror_browser_path,
        &direct_tcp,
        &direct_probe_context,
    )
    .await;
    assert_direct_tcp_probe_observation(direct_probe, false, &direct_probe_context);
    let first_browser_processes =
        chromium_browser_descendant_process_identities(first_station_pid, runtime_name).await;
    assert_eq!(
        udp_ipv4.wait_for_stun(Duration::from_secs(2)).await,
        0,
        "first contained browser emitted IPv4 STUN before broker crash"
    );
    assert_eq!(
        udp_ipv6.wait_for_stun(Duration::from_secs(2)).await,
        0,
        "first contained browser emitted IPv6 STUN before broker crash"
    );
    assert_eq!(
        turn_tcp.wait_for_allocate_request(Duration::from_secs(2)).await,
        0,
        "first contained browser emitted TURN/TCP before broker crash"
    );

    let first_broker_exit = first_broker
        .request_crash()
        .await
        .expect("request test-owned broker self-termination");
    assert_eq!(
        first_broker_exit.exit_code,
        WFP_BROKER_CRASH_EXIT_CODE,
        "crash-controlled broker exited with an unexpected code"
    );
    assert!(
        first_broker_exit.outcome.is_none(),
        "crash-controlled broker emitted a clean outcome"
    );
    assert_containment_lost_exit(&mut first_daemon).await;
    drop(first_client);
    assert_processes_exit(
        &first_browser_processes,
        "containment-lost emergency shutdown",
    )
    .await;
    assert_eq!(
        directory_entry_names(&prepared.mirror_catalog),
        mirror_entries,
        "broker crash removed or changed the fail-closed runtime mirror"
    );
    assert_eq!(
        udp_ipv4.stun_datagram_count(),
        0,
        "broker crash exposed an IPv4 STUN leak before emergency browser termination"
    );
    assert_eq!(
        udp_ipv6.stun_datagram_count(),
        0,
        "broker crash exposed an IPv6 STUN leak before emergency browser termination"
    );
    assert_eq!(
        turn_tcp.connection_count(),
        turn_tcp_connection_baseline,
        "broker crash exposed a TURN/TCP connection before emergency browser termination"
    );
    let released_profiles = ProfilesRootOwnership::acquire(&profiles)
        .expect("containment-lost station releases profiles-root ownership");
    let released_profile = ProfileOwnershipGuard::acquire(profiles.join(profile_id))
        .expect("containment-lost station releases browser profile ownership");
    drop(released_profile);
    drop(released_profiles);

    let successor_broker_pipe = format!("dig2browser-wfp-crash-successor-{unique}");
    let successor_station_pipe = format!("dig2browser-wfp-crash-station-successor-{unique}");
    let (successor_broker_capability, successor_station_capability) =
        WindowsWfpBrokerCapability::generate_pair();
    let mut successor_broker = spawn_wfp_broker(
        &successor_broker_pipe,
        &prepared.mirror_catalog,
        successor_broker_capability,
    )
    .await;
    assert_ne!(
        successor_broker.id(),
        first_broker_pid,
        "successor broker unexpectedly reused the killed broker PID"
    );
    let mut successor_daemon = spawn_webrtc_stationd(
        &successor_station_pipe,
        &successor_profiles,
        &traces,
        runtime_name,
        &[&allowed_origin],
        WebRtcStationOptions {
            broker_pipe_name: Some(&successor_broker_pipe),
            broker_capability: Some(successor_station_capability),
            command_timeout_seconds: 60,
            close_timeout_seconds: None,
            test_close_delay_millis: None,
        },
    )
    .await;
    let successor_client = connect(&successor_station_pipe).await;
    assert_webrtc_probe_completes(
        &successor_client,
        profile_id,
        runtime_kind,
        &origin,
        runtime_name,
    )
    .await;
    let successor_mirror_entries = directory_entry_names(&prepared.mirror_catalog);
    let successor_created_mirrors = successor_mirror_entries
        .difference(&prepared.mirror_entries_before)
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        successor_created_mirrors.len(),
        1,
        "successor did not leave exactly one active mirror after stale cleanup: {successor_created_mirrors:?}"
    );
    let successor_mirror_root = prepared
        .mirror_catalog
        .join(&successor_created_mirrors[0]);
    assert_ne!(
        successor_mirror_root, mirror_root,
        "a different profiles scope unexpectedly reused the crash-scoped mirror"
    );
    assert!(
        !mirror_root.exists(),
        "successor retained the dead, unreferenced crash-scoped mirror"
    );
    assert_chromium_descendants_use_station_mirror(
        successor_daemon
            .id()
            .expect("successor containment station remains live"),
        &prepared.original_browser_path,
        &prepared.mirror_catalog,
        &successor_mirror_root,
        runtime_name,
    )
    .await;
    assert_eq!(udp_ipv4.stun_datagram_count(), 0);
    assert_eq!(udp_ipv6.stun_datagram_count(), 0);
    assert_eq!(turn_tcp.connection_count(), turn_tcp_connection_baseline);

    successor_client
        .shutdown()
        .await
        .expect("request clean successor station shutdown");
    drop(successor_client);
    assert_webrtc_clean_exit(&mut successor_daemon, true).await;
    assert_wfp_broker_clean_exit(&mut successor_broker).await;
    // The catalog is the shared, station-owned `%LOCALAPPDATA%` directory
    // (see `runtime_mirror_catalog()` / `ensure_mirror_base` — it cannot be
    // relocated to an isolated per-run temp dir), so a full baseline-equality
    // assert is fragile against unrelated concurrent or historical entries.
    // Assert by name instead: both of this test's own mirrors (the crashed
    // first station's and the reconciled successor's) must be gone, ignoring
    // any foreign entries already in, or added to, the shared catalog.
    let successor_cleanup_entries = directory_entry_names(&prepared.mirror_catalog);
    assert!(
        !successor_cleanup_entries.contains(&created_mirrors[0]),
        "clean successor close left the crashed first station's runtime mirror behind: {}",
        created_mirrors[0]
    );
    assert!(
        !successor_cleanup_entries.contains(&successor_created_mirrors[0]),
        "clean successor close did not remove the reconciled runtime mirror: {}",
        successor_created_mirrors[0]
    );
    let released_profiles = ProfilesRootOwnership::acquire(&successor_profiles)
        .expect("clean successor releases profiles-root ownership");
    let released_profile = ProfileOwnershipGuard::acquire(successor_profiles.join(profile_id))
        .expect("clean successor releases browser profile ownership");
    drop(released_profile);
    drop(released_profiles);
    drop(origin);
    drop(udp_ipv4);
    drop(udp_ipv6);
    drop(turn_tcp);
    remove_tree(&profiles).await;
    remove_tree(&traces).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a medium-integrity test process, UAC for the WFP broker, installed Chrome, and --features containment-test-hooks"]
async fn stationd_chrome_worker_close_timeout_retains_wfp_until_process_tree_exit_e2e() {
    let _serial = e2e_serial_guard().await;
    let run = WfpE2eRun::start(
        "stationd_chrome_worker_close_timeout_retains_wfp_until_process_tree_exit_e2e",
    );
    run.install_panic_log();
    assert_containment_test_hooks_enabled();
    let unique = uuid::Uuid::new_v4();
    let profiles = e2e_temp_base().join(format!(
        "dig2browser-containment-close-timeout-{unique}"
    ));
    let successor_profiles = e2e_temp_base().join(format!(
        "dig2browser-containment-close-timeout-successor-{unique}"
    ));
    let traces = e2e_temp_base().join(format!(
        "dig2browser-containment-close-timeout-trace-{unique}"
    ));
    std::fs::create_dir_all(&profiles).expect("create close-timeout profiles root");
    std::fs::create_dir_all(&successor_profiles)
        .expect("create close-timeout successor profiles root");
    std::fs::create_dir_all(&traces).expect("create close-timeout trace root");
    let prepared = prepare_webrtc_runtime("chrome", RuntimeKind::Chrome);

    let udp_ipv4 = ControlledUdpReceiver::start_ipv4();
    let udp_ipv6 = ControlledUdpReceiver::start_ipv6();
    let turn_tcp = ControlledTurnTcpReceiver::start();
    udp_ipv4.prove_ready();
    udp_ipv6.prove_ready();
    turn_tcp.prove_ready();
    let turn_tcp_connection_baseline = turn_tcp.connection_count();
    let origin = ControlledOrigin::webrtc_probe(
        udp_ipv4.address(),
        udp_ipv6.address(),
        turn_tcp.address(),
    );
    let allowed_origin = origin.origin();
    let broker_pipe = format!("dig2browser-wfp-close-timeout-{unique}");
    let station_pipe = format!("dig2browser-wfp-close-timeout-station-{unique}");
    let (broker_capability, station_capability) =
        WindowsWfpBrokerCapability::generate_pair();
    let mut broker = spawn_wfp_broker(
        &broker_pipe,
        &prepared.mirror_catalog,
        broker_capability,
    )
    .await;
    let mut daemon = spawn_webrtc_stationd(
        &station_pipe,
        &profiles,
        &traces,
        "chrome",
        &[&allowed_origin],
        WebRtcStationOptions {
            broker_pipe_name: Some(&broker_pipe),
            broker_capability: Some(station_capability),
            // Step-0 setup (assert_webrtc_probe_completes: navigate + ICE +
            // capture) needs more than 1s, so command_timeout must cover
            // it; the worker close/teardown budget is bounded separately
            // (well under the injected 30s close delay) so this test still
            // proves WFP retention on a slow close.
            command_timeout_seconds: 60,
            close_timeout_seconds: Some(1),
            test_close_delay_millis: Some(30_000),
        },
    )
    .await;
    let client = connect(&station_pipe).await;
    let profile_id = "webrtc-wfp-close-timeout-chrome";
    assert_webrtc_probe_completes(
        &client,
        profile_id,
        RuntimeKind::Chrome,
        &origin,
        "chrome",
    )
    .await;

    let active_entries = directory_entry_names(&prepared.mirror_catalog);
    let active_mirrors = active_entries
        .difference(&prepared.mirror_entries_before)
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(active_mirrors.len(), 1, "unexpected active mirrors: {active_mirrors:?}");
    let old_mirror_root = prepared.mirror_catalog.join(&active_mirrors[0]);
    let station_pid = daemon.id().expect("close-timeout station remains live");
    assert_chromium_descendants_use_station_mirror(
        station_pid,
        &prepared.original_browser_path,
        &prepared.mirror_catalog,
        &old_mirror_root,
        "chrome",
    )
    .await;
    let browser_processes =
        chromium_browser_descendant_process_identities(station_pid, "chrome").await;
    assert_eq!(udp_ipv4.wait_for_stun(Duration::from_secs(2)).await, 0);
    assert_eq!(udp_ipv6.wait_for_stun(Duration::from_secs(2)).await, 0);
    assert_eq!(
        turn_tcp.wait_for_allocate_request(Duration::from_secs(2)).await,
        0
    );

    let shutdown_started = tokio::time::Instant::now();
    client
        .shutdown()
        .await
        .expect("request close-timeout station shutdown");
    drop(client);
    assert_station_shutdown_failure(&mut daemon).await;
    assert!(
        shutdown_started.elapsed() < Duration::from_secs(15),
        "station waited for the full injected close delay instead of its worker timeout"
    );
    assert_processes_exit(&browser_processes, "close-timeout containment shutdown").await;
    assert!(
        old_mirror_root.exists(),
        "failed station shutdown removed its retained runtime mirror"
    );
    assert_eq!(
        directory_entry_names(&prepared.mirror_catalog),
        active_entries,
        "failed station shutdown changed the retained mirror catalog"
    );
    assert_eq!(udp_ipv4.stun_datagram_count(), 0);
    assert_eq!(udp_ipv6.stun_datagram_count(), 0);
    assert_eq!(turn_tcp.connection_count(), turn_tcp_connection_baseline);
    assert_wfp_broker_client_disconnected(&mut broker).await;

    let successor_broker_pipe = format!("dig2browser-wfp-close-timeout-next-{unique}");
    let successor_station_pipe = format!(
        "dig2browser-wfp-close-timeout-station-next-{unique}"
    );
    let (successor_broker_capability, successor_station_capability) =
        WindowsWfpBrokerCapability::generate_pair();
    let mut successor_broker = spawn_wfp_broker(
        &successor_broker_pipe,
        &prepared.mirror_catalog,
        successor_broker_capability,
    )
    .await;
    let mut successor_daemon = spawn_webrtc_stationd(
        &successor_station_pipe,
        &successor_profiles,
        &traces,
        "chrome",
        &[&allowed_origin],
        WebRtcStationOptions {
            broker_pipe_name: Some(&successor_broker_pipe),
            broker_capability: Some(successor_station_capability),
            command_timeout_seconds: 60,
            close_timeout_seconds: None,
            test_close_delay_millis: None,
        },
    )
    .await;
    let successor_client = connect(&successor_station_pipe).await;
    assert_webrtc_probe_completes(
        &successor_client,
        profile_id,
        RuntimeKind::Chrome,
        &origin,
        "chrome",
    )
    .await;
    // Capture the successor's own new mirror by name (diffed against the
    // catalog snapshot taken right after the primary daemon's probe) before
    // its reconciliation and later cleanup can remove it, so the final
    // assert below can check for it by name rather than by full-catalog
    // equality.
    let successor_active_entries = directory_entry_names(&prepared.mirror_catalog);
    let successor_active_mirrors = successor_active_entries
        .difference(&active_entries)
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        successor_active_mirrors.len(),
        1,
        "unexpected successor active mirrors: {successor_active_mirrors:?}"
    );
    let successor_mirror_name = successor_active_mirrors[0].clone();
    assert!(
        !old_mirror_root.exists(),
        "successor reconciliation retained the dead unreferenced mirror"
    );
    successor_client
        .shutdown()
        .await
        .expect("request clean successor shutdown");
    drop(successor_client);
    assert_webrtc_clean_exit(&mut successor_daemon, true).await;
    assert_wfp_broker_clean_exit(&mut successor_broker).await;
    // The catalog is the shared, station-owned `%LOCALAPPDATA%` directory
    // (`runtime_mirror_catalog()` cannot be relocated to an isolated per-run
    // temp dir; see `ensure_mirror_base`/`existing_mirror_base` in
    // `dig2browser/src/windows_runtime_mirror.rs`), so other runs' entries
    // (including hours-old orphaned `.staging-*` dirs, or mirrors from
    // completely unrelated concurrent station activity) can already be
    // present in, or appear in, the baseline. A full-catalog equality assert
    // against that shared baseline is therefore fragile. Instead assert by
    // name that both of this test's own daemon mirrors (the retained primary
    // mirror and the successor's reconciled mirror) are gone, ignoring any
    // foreign entries.
    let successor_cleanup_entries = directory_entry_names(&prepared.mirror_catalog);
    assert!(
        !successor_cleanup_entries.contains(&active_mirrors[0]),
        "successor cleanup left the primary station's retained runtime mirror behind: {}",
        active_mirrors[0]
    );
    assert!(
        !successor_cleanup_entries.contains(&successor_mirror_name),
        "successor cleanup did not remove its own runtime mirror: {successor_mirror_name}"
    );

    drop(origin);
    drop(udp_ipv4);
    drop(udp_ipv6);
    drop(turn_tcp);
    remove_tree(&profiles).await;
    remove_tree(&successor_profiles).await;
    remove_tree(&traces).await;
}

struct PreparedWebRtcRuntime {
    original_browser_path: PathBuf,
    mirror_catalog: PathBuf,
    mirror_entries_before: HashSet<String>,
}

fn prepare_webrtc_runtime(
    runtime_name: &str,
    runtime_kind: RuntimeKind,
) -> PreparedWebRtcRuntime {
    let candidates = match runtime_kind {
        RuntimeKind::Chrome => vec![
            PathBuf::from(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
            PathBuf::from(r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"),
            std::env::var_os("LOCALAPPDATA")
                .map(PathBuf::from)
                .unwrap_or_default()
                .join(r"Google\Chrome\Application\chrome.exe"),
        ],
        RuntimeKind::Edge => vec![
            PathBuf::from(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
            PathBuf::from(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
            std::env::var_os("LOCALAPPDATA")
                .map(PathBuf::from)
                .unwrap_or_default()
                .join(r"Microsoft\Edge\Application\msedge.exe"),
        ],
        other => panic!("unsupported WFP E2E runtime: {other:?}"),
    };
    let original_browser_path = candidates
        .into_iter()
        .find(|path| path.is_file())
        .unwrap_or_else(|| panic!("no standard installed {runtime_name} runtime found"));
    let mirror_catalog = runtime_mirror_catalog();
    std::fs::create_dir_all(&mirror_catalog)
        .expect("create station-owned runtime-mirror catalog");
    let mirror_entries_before = directory_entry_names(&mirror_catalog);
    PreparedWebRtcRuntime {
        original_browser_path,
        mirror_catalog,
        mirror_entries_before,
    }
}

fn assert_containment_test_hooks_enabled() {
    #[cfg(not(feature = "containment-test-hooks"))]
    panic!("this E2E requires --features containment-test-hooks");
}

fn browser_binary_kind(runtime_kind: RuntimeKind) -> BrowserKind {
    match runtime_kind {
        RuntimeKind::Chrome => BrowserKind::Chrome,
        RuntimeKind::Edge => BrowserKind::Edge,
        other => panic!("unsupported direct TCP probe runtime: {other:?}"),
    }
}

fn file_identity_and_size(path: &Path) -> (u32, u64, u64) {
    let file = File::open(path)
        .unwrap_or_else(|error| panic!("open '{}' for file identity: {error}", path.display()));
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    unsafe {
        GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut information)
            .unwrap_or_else(|error| {
                panic!("read '{}' file identity: {error}", path.display())
            });
    }
    let file_index = ((information.nFileIndexHigh as u64) << 32)
        | information.nFileIndexLow as u64;
    let file_size = ((information.nFileSizeHigh as u64) << 32)
        | information.nFileSizeLow as u64;
    (information.dwVolumeSerialNumber, file_index, file_size)
}

fn browser_preference(runtime_kind: RuntimeKind) -> BrowserPreference {
    match runtime_kind {
        RuntimeKind::Chrome => BrowserPreference::ChromeOnly,
        RuntimeKind::Edge => BrowserPreference::EdgeOnly,
        other => panic!("unsupported direct TCP probe runtime: {other:?}"),
    }
}

struct DirectTcpProbeObservation {
    navigation_succeeded: bool,
    reached: bool,
    navigation_detail: String,
}

fn assert_direct_tcp_probe_observation(
    observation: Result<DirectTcpProbeObservation, String>,
    expected_reachable: bool,
    context: &str,
) {
    let observation = observation.unwrap_or_else(|error| panic!("{context}: {error}"));
    if expected_reachable {
        assert!(
            observation.navigation_succeeded && observation.reached,
            "{context}: exact browser binary did not reach the direct TCP fixture: {}",
            observation.navigation_detail
        );
    } else {
        assert!(
            !observation.reached,
            "{context}: contained exact browser binary reached the direct TCP fixture: {}",
            observation.navigation_detail
        );
    }
}

async fn run_owned_browser_direct_tcp_probe(
    runtime_kind: RuntimeKind,
    binary_path: PathBuf,
    origin: &ControlledOrigin,
    context: &str,
) -> Result<DirectTcpProbeObservation, String> {
    let runtime_root = binary_path
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .to_path_buf();
    let component = format!(
        "direct-tcp-probe-{:?}-{}",
        runtime_kind,
        uuid::Uuid::new_v4().simple()
    );
    let browser_stderr_log = e2e_component_path(&component, "browser-stderr");
    let browser_lifecycle_log = e2e_component_artifact_path(&component, "lifecycle.jsonl");
    let browser_net_log = matches!(
        std::env::var("DIG2BROWSER_E2E_NETLOG"),
        Ok(value) if value == "1"
    )
    .then(|| e2e_component_artifact_path(&component, "netlog.json"));
    let requested_url = origin.url("/direct-tcp-probe");
    File::create(&browser_stderr_log)
        .expect("create direct TCP probe browser stderr log");
    File::create(&browser_lifecycle_log)
        .expect("create direct TCP probe browser lifecycle log");
    let _browser_stderr = ScopedEnvironmentVariable::set(
        "DIG2BROWSER_BROWSER_STDERR_LOG",
        &browser_stderr_log,
    );
    let _browser_lifecycle = ScopedEnvironmentVariable::set(
        "DIG2BROWSER_BROWSER_LIFECYCLE_LOG",
        &browser_lifecycle_log,
    );
    record_e2e_event(
        &component,
        "browser_probe_started",
        serde_json::json!({
            "binary_path": binary_path,
            "browser_stderr_log": browser_stderr_log,
            "browser_lifecycle_log": browser_lifecycle_log,
            "browser_net_log": browser_net_log.as_ref(),
            "context": context,
            "requested_url": requested_url,
        }),
    );
    let mut extra_args = vec![
        "--enable-logging=stderr".to_owned(),
        "--v=1".to_owned(),
    ];
    if let Some(browser_net_log) = browser_net_log.as_ref() {
        extra_args.push(format!("--log-net-log={}", browser_net_log.display()));
        extra_args.push("--net-log-capture-mode=Everything".to_owned());
    }
    let launch = LaunchConfig {
        browser_pref: browser_preference(runtime_kind),
        browser_proxy: Some(dig2browser::BrowserProxy::Direct),
        extra_args,
        ..LaunchConfig::default()
    };
    let isolation = BrowserProcessIsolation::WindowsRuntimeMirror(BrowserBinary {
        path: binary_path,
        kind: browser_binary_kind(runtime_kind),
    });
    let launch_started = Instant::now();
    let browser = match StealthBrowser::launch_with_process_isolation(
        launch,
        StealthConfig::default(),
        isolation,
    )
    .await {
        Ok(browser) => browser,
        Err(error) => {
            record_e2e_event(
                &component,
                "browser_probe_launch_failed",
                serde_json::json!({
                    "elapsed_ms": launch_started.elapsed().as_millis() as u64,
                    "error": error.to_string(),
                }),
            );
            return Err(format!("launch direct TCP probe browser: {error}"));
        }
    };
    record_e2e_event(
        &component,
        "browser_probe_launched",
        serde_json::json!({
            "elapsed_ms": launch_started.elapsed().as_millis() as u64,
        }),
    );
    let baseline = origin.path_count("/direct-tcp-probe");
    let navigation_started = Instant::now();
    record_e2e_event(
        &component,
        "browser_probe_navigation_started",
        serde_json::json!({
            "baseline_requests": baseline,
            "requested_url": requested_url,
        }),
    );
    let navigation = tokio::time::timeout(
        Duration::from_secs(10),
        browser.new_page(&requested_url),
    )
    .await;
    let reached = origin.path_count("/direct-tcp-probe") > baseline;
    let (navigation_succeeded, navigation_detail) = match &navigation {
        Ok(Ok(_)) => (true, "completed".to_owned()),
        Ok(Err(error)) => (false, format!("failed: {error}")),
        Err(error) => (false, format!("timed out: {error}")),
    };
    record_e2e_event(
        &component,
        "browser_probe_navigation_finished",
        serde_json::json!({
            "baseline_requests": baseline,
            "final_requests": origin.path_count("/direct-tcp-probe"),
            "elapsed_ms": navigation_started.elapsed().as_millis() as u64,
            "navigation": navigation_detail,
            "reached": reached,
        }),
    );
    drop(navigation);
    let close_started = Instant::now();
    record_e2e_event(
        &component,
        "browser_probe_close_started",
        serde_json::json!({}),
    );
    if let Err(error) = browser.close().await {
        let live_runtime_processes = live_processes_with_images_under(&runtime_root);
        record_e2e_event(
            &component,
            "browser_probe_close_failed",
            serde_json::json!({
                "elapsed_ms": close_started.elapsed().as_millis() as u64,
                "error": error.to_string(),
                "runtime_root": runtime_root,
                "live_runtime_processes": live_runtime_processes,
            }),
        );
        return Err(format!("close direct TCP probe browser: {error}"));
    }
    let live_runtime_processes = live_processes_with_images_under(&runtime_root);
    record_e2e_event(
        &component,
        "browser_probe_closed",
        serde_json::json!({
            "elapsed_ms": close_started.elapsed().as_millis() as u64,
            "runtime_root": runtime_root,
            "live_runtime_processes": live_runtime_processes,
        }),
    );
    Ok(DirectTcpProbeObservation {
        navigation_succeeded,
        reached,
        navigation_detail,
    })
}

async fn run_direct_stun_positive_control_only_e2e(
    runtime_name: &str,
    runtime_kind: RuntimeKind,
) {
    assert_containment_test_hooks_enabled();
    let unique = uuid::Uuid::new_v4();
    let profiles = e2e_temp_base().join(format!(
        "dig2browser-stun-positive-{runtime_name}-{unique}"
    ));
    let traces = e2e_temp_base().join(format!(
        "dig2browser-stun-positive-trace-{runtime_name}-{unique}"
    ));
    std::fs::create_dir_all(&profiles).expect("create positive-control profiles root");
    std::fs::create_dir_all(&traces).expect("create positive-control trace root");
    let prepared = prepare_webrtc_runtime(runtime_name, runtime_kind);

    run_direct_egress_positive_control(
        runtime_name,
        runtime_kind,
        &unique,
        &profiles,
        &traces,
        &prepared,
    )
    .await;

    // Same shared-catalog caveat as the runtime-mirror E2Es above: the
    // catalog is a station-owned `%LOCALAPPDATA%` directory shared across
    // runs, so only assert this run did not add a new entry.
    let mirror_entries_after = directory_entry_names(&prepared.mirror_catalog);
    assert!(
        mirror_entries_after.is_subset(&prepared.mirror_entries_before),
        "positive control unexpectedly created a runtime mirror: before={:?}, after={mirror_entries_after:?}",
        prepared.mirror_entries_before,
    );
    remove_tree(&profiles).await;
    remove_tree(&traces).await;
}

async fn run_wfp_app_id_containment_e2e(
    runtime_name: &str,
    runtime_kind: RuntimeKind,
) {
    assert_containment_test_hooks_enabled();
    record_e2e_event(
        "test",
        "runtime_preparation_started",
        serde_json::json!({ "runtime": runtime_name }),
    );
    let unique = uuid::Uuid::new_v4();
    let broker_pipe_name = format!("dig2browser-wfp-e2e-{runtime_name}-{unique}");
    let profiles = e2e_temp_base().join(format!(
        "dig2browser-containment-{runtime_name}-{unique}"
    ));
    let traces = e2e_temp_base().join(format!(
        "dig2browser-containment-trace-{runtime_name}-{unique}"
    ));
    std::fs::create_dir_all(&profiles).expect("create WebRTC profiles root");
    std::fs::create_dir_all(&traces).expect("create WebRTC trace root");
    let prepared = prepare_webrtc_runtime(runtime_name, runtime_kind);
    record_e2e_event(
        "test",
        "runtime_prepared",
        serde_json::json!({
            "runtime": runtime_name,
            "browser_path": prepared.original_browser_path,
            "mirror_catalog": prepared.mirror_catalog,
        }),
    );

    record_e2e_event(
        "test",
        "direct_positive_control_started",
        serde_json::json!({ "runtime": runtime_name }),
    );
    run_direct_egress_positive_control(
        runtime_name,
        runtime_kind,
        &unique,
        &profiles,
        &traces,
        &prepared,
    )
    .await;
    record_e2e_event(
        "test",
        "direct_positive_control_passed",
        serde_json::json!({ "runtime": runtime_name }),
    );

    let source = BrowserBinary {
        path: prepared.original_browser_path.clone(),
        kind: browser_binary_kind(runtime_kind),
    };
    let mirror = WindowsBrowserRuntimeMirror::materialize(&source, &profiles)
        .expect("materialize runtime-mirror positive control");
    let mirror_root = mirror.root().to_path_buf();
    let source_identity = file_identity_and_size(&source.path);
    let mirror_identity = file_identity_and_size(&mirror.browser_binary().path);
    let same_file_identity = source_identity.0 == mirror_identity.0
        && source_identity.1 == mirror_identity.1;
    record_e2e_event(
        "test",
        "runtime_mirror_materialized",
        serde_json::json!({
            "runtime": runtime_name,
            "mode": if same_file_identity { "hard_link" } else { "copy" },
            "source_bytes": source_identity.2,
            "mirror_bytes": mirror_identity.2,
        }),
    );
    let mirror_probe = ControlledOrigin::direct_tcp_probe();
    let mirror_probe_context = format!("uncontained runtime-mirror {runtime_name}");
    let mirror_probe_observation = run_owned_browser_direct_tcp_probe(
        runtime_kind,
        mirror.browser_binary().path.clone(),
        &mirror_probe,
        &mirror_probe_context,
    )
    .await;
    drop(mirror_probe);
    remove_runtime_mirror_with_evidence(mirror, "remove runtime-mirror positive control")
        .await
        .unwrap_or_else(|error| panic!("remove runtime-mirror positive control: {error}"));
    assert!(
        !mirror_root.exists(),
        "runtime-mirror positive control survived explicit removal"
    );
    assert_direct_tcp_probe_observation(
        mirror_probe_observation,
        true,
        &mirror_probe_context,
    );
    record_e2e_event(
        "test",
        "runtime_mirror_positive_control_passed",
        serde_json::json!({ "runtime": runtime_name }),
    );

    let (broker_capability, station_capability) =
        WindowsWfpBrokerCapability::generate_pair();
    record_e2e_event(
        "test",
        "broker_launch_started",
        serde_json::json!({ "runtime": runtime_name }),
    );
    let mut broker = spawn_wfp_broker(
        &broker_pipe_name,
        &prepared.mirror_catalog,
        broker_capability,
    )
    .await;
    record_e2e_event(
        "test",
        "broker_launch_passed",
        serde_json::json!({
            "process_id": broker.id(),
            "integrity_rid": broker.security().integrity_rid,
            "elevated": broker.security().elevated,
        }),
    );

    let udp_ipv4 = ControlledUdpReceiver::start_ipv4();
    let udp_ipv6 = ControlledUdpReceiver::start_ipv6();
    let turn_tcp = ControlledTurnTcpReceiver::start();
    let direct_tcp = ControlledOrigin::direct_tcp_probe();
    udp_ipv4.prove_ready();
    udp_ipv6.prove_ready();
    turn_tcp.prove_ready();
    let origin = ControlledOrigin::webrtc_probe(
        udp_ipv4.address(),
        udp_ipv6.address(),
        turn_tcp.address(),
    );
    let pipe_name = format!("dig2browser-containment-{runtime_name}-{unique}");
    let allowed_origin = origin.origin();
    let mut daemon = spawn_webrtc_stationd(
        &pipe_name,
        &profiles,
        &traces,
        runtime_name,
        &[&allowed_origin],
        WebRtcStationOptions {
            broker_pipe_name: Some(&broker_pipe_name),
            broker_capability: Some(station_capability),
            command_timeout_seconds: 60,
            close_timeout_seconds: None,
            test_close_delay_millis: None,
        },
    )
    .await;
    let containment_startup_timeout = Duration::from_secs(180);
    record_e2e_event(
        "test",
        "contained_station_connect_started",
        serde_json::json!({
            "runtime": runtime_name,
            "startup_timeout_ms": containment_startup_timeout.as_millis() as u64,
        }),
    );
    let client = connect_with_daemon_timeout(
        &pipe_name,
        &mut daemon,
        containment_startup_timeout,
    )
    .await;
    let profile_id = format!("webrtc-wfp-app-id-{runtime_name}");
    record_e2e_event(
        "test",
        "contained_browser_task_started",
        serde_json::json!({ "runtime": runtime_name, "profile_id": profile_id }),
    );
    assert_webrtc_probe_completes(
        &client,
        &profile_id,
        runtime_kind,
        &origin,
        runtime_name,
    )
    .await;
    record_e2e_event(
        "test",
        "contained_browser_task_passed",
        serde_json::json!({ "runtime": runtime_name, "profile_id": profile_id }),
    );

    let mirror_entries = directory_entry_names(&prepared.mirror_catalog);
    let created_mirrors = mirror_entries
        .difference(&prepared.mirror_entries_before)
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        created_mirrors.len(),
        1,
        "elevated broker did not create exactly one scoped runtime mirror: {created_mirrors:?}"
    );
    let mirror_root = prepared.mirror_catalog.join(&created_mirrors[0]);
    let station_pid = daemon
        .id()
        .expect("containment station process remains live");
    assert_medium_process(station_pid, "containment station");
    assert_chromium_descendants_use_station_mirror(
        station_pid,
        &prepared.original_browser_path,
        &prepared.mirror_catalog,
        &mirror_root,
        runtime_name,
    )
    .await;
    let (browser_root_pid, mirror_browser_path) = chromium_root_process(
        station_pid,
        runtime_name,
    );
    assert_medium_process(browser_root_pid, "contained browser root");
    for browser in
        chromium_browser_descendant_process_identities(station_pid, runtime_name).await
    {
        assert_non_elevated_process_at_or_below_medium(
            browser.process_id,
            "contained browser process",
        );
    }
    let direct_probe_context = format!("WFP-contained {runtime_name}");
    let direct_probe = run_owned_browser_direct_tcp_probe(
        runtime_kind,
        mirror_browser_path,
        &direct_tcp,
        &direct_probe_context,
    )
    .await;
    assert_direct_tcp_probe_observation(direct_probe, false, &direct_probe_context);

    let stun_ipv4_datagrams = udp_ipv4.wait_for_stun(Duration::from_secs(5)).await;
    assert_eq!(
        stun_ipv4_datagrams, 0,
        "WFP App-ID containment allowed {runtime_name} to emit direct IPv4 STUN"
    );
    let stun_ipv6_datagrams = udp_ipv6.wait_for_stun(Duration::from_secs(5)).await;
    assert_eq!(
        stun_ipv6_datagrams, 0,
        "WFP App-ID containment allowed {runtime_name} to emit direct IPv6 STUN to {}",
        udp_ipv6.address()
    );

    client.shutdown().await.expect("request clean WebRTC station shutdown");
    drop(client);
    assert_webrtc_clean_exit(&mut daemon, true).await;
    let mirror_entries_after = directory_entry_names(&prepared.mirror_catalog);
    assert!(
        mirror_entries_after.is_subset(&prepared.mirror_entries_before),
        "clean station shutdown left a newly-created runtime mirror or staging directory behind: before={:?}, after={mirror_entries_after:?}",
        prepared.mirror_entries_before,
    );
    record_e2e_event(
        "test",
        "runtime_mirror_cleanup_passed",
        serde_json::json!({
            "entries_before": prepared.mirror_entries_before,
            "entries_after": mirror_entries_after,
        }),
    );
    let released_profiles = ProfilesRootOwnership::acquire(&profiles)
        .expect("clean WebRTC station shutdown releases profiles-root ownership");
    let released_profile = ProfileOwnershipGuard::acquire(profiles.join(&profile_id))
        .expect("clean WebRTC station shutdown releases the browser profile");
    drop(released_profile);
    drop(released_profiles);
    drop(origin);
    drop(udp_ipv4);
    drop(udp_ipv6);
    drop(turn_tcp);
    drop(direct_tcp);
    assert_wfp_broker_clean_exit(&mut broker).await;
    record_e2e_event(
        "test",
        "run_passed",
        serde_json::json!({ "runtime": runtime_name }),
    );

    remove_tree(&profiles).await;
    remove_tree(&traces).await;
}

async fn run_direct_egress_positive_control(
    runtime_name: &str,
    runtime_kind: RuntimeKind,
    unique: &uuid::Uuid,
    profiles: &Path,
    traces: &Path,
    prepared: &PreparedWebRtcRuntime,
) {
    let udp_ipv4 = ControlledUdpReceiver::start_ipv4();
    let udp_ipv6 = ControlledUdpReceiver::start_ipv6();
    let turn_tcp = ControlledTurnTcpReceiver::start();
    let direct_tcp = ControlledOrigin::direct_tcp_probe();
    udp_ipv4.prove_ready();
    udp_ipv6.prove_ready();
    turn_tcp.prove_ready();
    let origin = ControlledOrigin::webrtc_probe(
        udp_ipv4.address(),
        udp_ipv6.address(),
        turn_tcp.address(),
    );
    let pipe_name = format!("dig2browser-stun-positive-{runtime_name}-{unique}");
    let allowed_origin = origin.origin();
    let mut daemon = spawn_webrtc_stationd(
        &pipe_name,
        profiles,
        traces,
        runtime_name,
        &[&allowed_origin],
        WebRtcStationOptions {
            broker_pipe_name: None,
            broker_capability: None,
            command_timeout_seconds: 60,
            close_timeout_seconds: None,
            test_close_delay_millis: None,
        },
    )
    .await;
    let client = connect_with_daemon(&pipe_name, &mut daemon).await;
    let profile_id = format!("webrtc-stun-positive-{runtime_name}");
    assert_webrtc_probe_completes(
        &client,
        &profile_id,
        runtime_kind,
        &origin,
        runtime_name,
    )
    .await;

    assert_chromium_descendants_use_installed_runtime(
        daemon.id().expect("positive-control station process remains live"),
        &prepared.original_browser_path,
        &prepared.mirror_catalog,
        runtime_name,
    )
    .await;
    let direct_probe_context = format!("uncontained {runtime_name}");
    let direct_probe = run_owned_browser_direct_tcp_probe(
        runtime_kind,
        prepared.original_browser_path.clone(),
        &direct_tcp,
        &direct_probe_context,
    )
    .await;
    assert_direct_tcp_probe_observation(direct_probe, true, &direct_probe_context);

    let stun_ipv4_datagrams = udp_ipv4.wait_for_stun(Duration::from_secs(5)).await;
    assert!(
        stun_ipv4_datagrams >= 1,
        "uncontained {runtime_name} positive control emitted no direct IPv4 STUN"
    );
    let stun_ipv6_datagrams = udp_ipv6.wait_for_stun(Duration::from_secs(5)).await;
    assert!(
        stun_ipv6_datagrams >= 1,
        "uncontained {runtime_name} positive control emitted no direct IPv6 STUN to {}",
        udp_ipv6.address()
    );

    client
        .shutdown()
        .await
        .expect("request clean positive-control station shutdown");
    drop(client);
    assert_webrtc_clean_exit(&mut daemon, false).await;
    let released_profiles = ProfilesRootOwnership::acquire(profiles)
        .expect("positive-control station releases profiles-root ownership");
    let released_profile = ProfileOwnershipGuard::acquire(profiles.join(&profile_id))
        .expect("positive-control station releases the browser profile");
    drop(released_profile);
    drop(released_profiles);
    drop(origin);
    drop(udp_ipv4);
    drop(udp_ipv6);
    drop(turn_tcp);
    drop(direct_tcp);
}

async fn assert_webrtc_probe_completes(
    client: &StationClient,
    profile_id: &str,
    runtime_kind: RuntimeKind,
    origin: &ControlledOrigin,
    runtime_name: &str,
) {
    let requested_url = origin.url("/webrtc-probe");
    let result = client
        .run_task(
            profile_id,
            webrtc_probe_task(runtime_kind, requested_url.clone()),
        )
        .await
        .unwrap_or_else(|error| {
            panic!("exact {runtime_name} route did not complete WebRTC task: {error}")
        });
    assert_eq!(result.replies().len(), 4);
    assert_eq!(result.replies()[0], TaskReply::Acknowledged);
    assert_eq!(result.replies()[1], TaskReply::Acknowledged);
    let TaskReply::Text(ice_state) = &result.replies()[2] else {
        panic!("WebRTC page did not return its ICE state");
    };
    assert!(
        ice_state.starts_with("ice-attempted:"),
        "WebRTC API/ICE attempt did not actually run: {ice_state}"
    );
    for probe in ["udp4:", "udp6:", "turn-tcp:"] {
        assert!(
            ice_state.contains(probe),
            "WebRTC page did not execute the {probe} ICE probe: {ice_state}"
        );
    }
    let TaskReply::Capture(capture) = &result.replies()[3] else {
        panic!("WebRTC task did not return an HTML capture");
    };
    assert_eq!(capture.requested_url, requested_url);
    assert_eq!(capture.final_url, requested_url);
    assert_eq!(capture.http_status, Some(200));
    assert_eq!(capture.title, "WebRTC containment fixture");
    assert!(
        String::from_utf8_lossy(&capture.html).contains("ice-attempted:"),
        "WebRTC capture did not preserve the completed ICE attempt"
    );
    assert!(
        origin.path_count("/webrtc-probe") >= 1,
        "exact allowed origin did not serve the controlled page"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stationd_enforces_exact_origin_url_policy_across_runtime_targets_e2e() {
    let _serial = e2e_serial_guard().await;
    let blocked = ControlledOrigin::blocked();
    let peer_denied = ControlledOrigin::peer_denied();
    let allowed = ControlledOrigin::allowed(blocked.origin());

    for (runtime_name, runtime_kind) in [
        ("lightweight", RuntimeKind::Lightweight),
        ("chrome", RuntimeKind::Chrome),
    ] {
        let unique = uuid::Uuid::new_v4();
        let pipe_name = format!("dig2browser-policy-{runtime_name}-{unique}");
        let profiles = e2e_temp_base().join(format!(
            "dig2browser-policy-{runtime_name}-{unique}"
        ));
        let traces = e2e_temp_base().join(format!(
            "dig2browser-policy-trace-{runtime_name}-{unique}"
        ));
        std::fs::create_dir_all(&profiles).expect("create policy E2E profiles");
        std::fs::create_dir_all(&traces).expect("create policy E2E trace root");
        let allowed_origin = allowed.origin();
        let peer_denied_origin = peer_denied.origin();
        let mut daemon = spawn_stationd(
            &pipe_name,
            &profiles,
            &traces,
            runtime_name,
            &[&allowed_origin, &peer_denied_origin],
        );
        let client = connect(&pipe_name).await;
        let profile_id = format!("policy-{runtime_name}");

        let legacy_profile_id = format!("policy-legacy-{runtime_name}");
        let legacy_error = client
            .capture(&legacy_profile_id, blocked.url("/legacy-capture"))
            .await
            .expect_err("legacy capture must reject a disallowed origin");
        assert_remote(
            legacy_error,
            ResponseStatus::Invalid,
            "navigation target rejected",
        );
        assert!(!profiles.join(&legacy_profile_id).exists());
        assert_eq!(blocked.request_count(), 0);

        let collection_profile_id = format!("policy-collection-{runtime_name}");
        let collection_error = client
            .begin_collection(
                &collection_profile_id,
                navigation_task(runtime_kind, blocked.url("/collection")),
            )
            .await
            .expect_err("durable collection must reject a disallowed origin");
        assert_remote(
            collection_error,
            ResponseStatus::Invalid,
            "collection request rejected",
        );
        assert!(!profiles.join(&collection_profile_id).exists());
        assert_eq!(blocked.request_count(), 0);

        let error = client
            .run_task(
                &profile_id,
                navigation_task(runtime_kind, blocked.url("/direct")),
            )
            .await
            .expect_err("station must reject an explicit disallowed origin");
        assert_remote(error, ResponseStatus::Invalid, "navigation target rejected");
        assert_eq!(blocked.request_count(), 0);
        assert!(!profiles.join(&profile_id).exists());
        let status = client.status().await.expect("read post-rejection status");
        assert_eq!(status.resident_identities, 0);

        if runtime_kind == RuntimeKind::Chrome {
            let auth_profile_id = "policy-auth-chrome";
            let auth_error = client
                .begin_auth_session(
                    auth_profile_id,
                    BrowserPersona::desktop_default(),
                    blocked.url("/auth"),
                )
                .await
                .expect_err("headful auth must reject a disallowed origin");
            assert_remote(
                auth_error,
                ResponseStatus::Invalid,
                "authentication identity rejected",
            );
            assert!(!profiles.join(auth_profile_id).exists());
            assert_eq!(blocked.request_count(), 0);
        }

        let redirect_error = client
            .run_task(
                &profile_id,
                navigation_task(runtime_kind, allowed.url("/redirect-blocked")),
            )
            .await
            .expect_err("runtime must block a redirect to a disallowed origin");
        assert_remote(
            redirect_error,
            ResponseStatus::CaptureFailed,
            "task failed at step 0",
        );
        assert_eq!(
            blocked.request_count(),
            0,
            "{runtime_name} contacted the blocked redirect origin"
        );

        let allowed_pixel_before = allowed.path_count("/allowed-pixel");
        let result = client
            .run_task(
                &profile_id,
                capture_task(runtime_kind, allowed.url("/document")),
            )
            .await
            .expect("allowed origin must remain collectable");
        assert_eq!(result.replies().len(), 2);
        let allowed_pixel_delta =
            allowed.path_count("/allowed-pixel") - allowed_pixel_before;
        if runtime_kind == RuntimeKind::Chrome {
            assert!(
                allowed_pixel_delta >= 1,
                "Chrome did not load the allowed same-page subresource"
            );
        } else {
            assert_eq!(
                allowed_pixel_delta, 0,
                "lightweight runtime unexpectedly loaded a subresource"
            );
        }
        assert_eq!(
            blocked.request_count(),
            0,
            "{runtime_name} contacted the blocked subresource origin"
        );

        let peer_denied_before = peer_denied.request_count();
        let peer_error = client
            .run_task(
                &profile_id,
                navigation_task(runtime_kind, peer_denied.url("/peer-policy")),
            )
            .await
            .expect_err("station proxy must reject an origin-allowed peer");
        assert_remote(
            peer_error,
            ResponseStatus::CaptureFailed,
            "task failed at step 0",
        );
        assert_eq!(
            peer_denied.request_count(),
            peer_denied_before,
            "{runtime_name} bypassed the station proxy for a denied loopback peer"
        );

        if runtime_kind == RuntimeKind::Chrome {
            let popup_child_before = allowed.path_count("/popup-child");
            let blocked_popup_before = blocked.request_count();
            let popup_result = client
                .run_task(&profile_id, popup_task(allowed.url("/popup")))
                .await
                .expect("Chrome popup task must complete under the policy");
            assert_eq!(popup_result.replies().len(), 3);
            assert!(
                allowed.path_count("/popup-child") > popup_child_before,
                "Chrome did not load the controlled popup child"
            );
            assert_eq!(
                blocked.request_count(),
                blocked_popup_before,
                "Chrome popup contacted the blocked origin"
            );

            let worker_script_before = allowed.path_count("/worker.js");
            let worker_control_before = allowed.path_count("/worker-control");
            let blocked_worker_before = blocked.request_count();
            let worker_result = client
                .run_task(&profile_id, worker_task(allowed.url("/worker-page")))
                .await
                .expect("Chrome worker task must complete under the policy");
            assert!(
                allowed.path_count("/worker.js") > worker_script_before,
                "Chrome did not load the controlled worker script"
            );
            assert!(
                allowed.path_count("/worker-control") > worker_control_before,
                "Chrome worker did not execute its allowed control fetch"
            );
            assert_eq!(
                worker_result.replies()[2],
                TaskReply::Text("attempted".to_owned())
            );
            assert_eq!(
                blocked.request_count(),
                blocked_worker_before,
                "Chrome worker contacted the blocked origin"
            );
        }

        client.shutdown().await.expect("request clean station shutdown");
        assert_clean_exit(&mut daemon).await;
        remove_tree(&profiles).await;
        remove_tree(&traces).await;
    }
    assert!(allowed.request_count() >= 6, "shared corpus was not exercised");
}

fn navigation_task(runtime: RuntimeKind, url: String) -> CollectionTask {
    task(
        runtime,
        vec![TaskStep::Navigate { url }],
        vec![RuntimeFeature::Navigate, RuntimeFeature::Lifecycle],
    )
}

fn capture_task(runtime: RuntimeKind, url: String) -> CollectionTask {
    task(
        runtime,
        vec![
            TaskStep::Navigate { url },
            TaskStep::Capture {
                policy: TaskCapturePolicy::HtmlOnly,
            },
        ],
        vec![
            RuntimeFeature::Navigate,
            RuntimeFeature::CaptureState,
            RuntimeFeature::CaptureHtml,
            RuntimeFeature::Lifecycle,
        ],
    )
}

#[cfg(feature = "tls-test-hooks")]
fn https_task(url: String) -> CollectionTask {
    task(
        RuntimeKind::Chrome,
        vec![
            TaskStep::Navigate { url },
            TaskStep::ReadSelectorText {
                selector: "#secure".to_owned(),
            },
            TaskStep::Capture {
                policy: TaskCapturePolicy::HtmlOnly,
            },
        ],
        vec![
            RuntimeFeature::Navigate,
            RuntimeFeature::DomInspect,
            RuntimeFeature::CaptureState,
            RuntimeFeature::CaptureHtml,
            RuntimeFeature::Lifecycle,
        ],
    )
}

fn popup_task(url: String) -> CollectionTask {
    task(
        RuntimeKind::Chrome,
        vec![
            TaskStep::Navigate { url },
            TaskStep::ClickSelector {
                selector: "#popup".to_owned(),
            },
            TaskStep::Wait {
                duration: Duration::from_millis(750),
            },
        ],
        vec![
            RuntimeFeature::Navigate,
            RuntimeFeature::DomInspect,
            RuntimeFeature::DomInteract,
            RuntimeFeature::Lifecycle,
        ],
    )
}

fn worker_task(url: String) -> CollectionTask {
    task(
        RuntimeKind::Chrome,
        vec![
            TaskStep::Navigate { url },
            TaskStep::Wait {
                duration: Duration::from_millis(3_000),
            },
            TaskStep::ReadSelectorText {
                selector: "#worker-state".to_owned(),
            },
        ],
        vec![
            RuntimeFeature::Navigate,
            RuntimeFeature::DomInspect,
            RuntimeFeature::Lifecycle,
        ],
    )
}

fn webrtc_probe_task(runtime: RuntimeKind, url: String) -> CollectionTask {
    task(
        runtime,
        vec![
            TaskStep::Navigate { url },
            TaskStep::Wait {
                duration: Duration::from_millis(1_500),
            },
            TaskStep::ReadSelectorText {
                selector: "#webrtc-state".to_owned(),
            },
            TaskStep::Capture {
                policy: TaskCapturePolicy::HtmlOnly,
            },
        ],
        vec![
            RuntimeFeature::Navigate,
            RuntimeFeature::DomInspect,
            RuntimeFeature::CaptureState,
            RuntimeFeature::CaptureHtml,
            RuntimeFeature::Lifecycle,
        ],
    )
}

fn task(
    runtime: RuntimeKind,
    steps: Vec<TaskStep>,
    features: Vec<RuntimeFeature>,
) -> CollectionTask {
    let requirements =
        RuntimeRequirements::new(features, false).expect("valid policy requirements");
    let contract = TaskRuntimeContract::new(
        RuntimeSelector::Exact(runtime),
        requirements,
    )
    .expect("valid exact runtime contract");
    CollectionTask::new_with_runtime(steps, contract).expect("valid policy task")
}

fn assert_remote(error: ClientError, status: ResponseStatus, message: &str) {
    match error {
        ClientError::Remote {
            status: actual,
            message: actual_message,
        } => {
            assert_eq!(actual, status);
            assert_eq!(actual_message, message);
        }
        other => panic!("unexpected policy error: {other}"),
    }
}

fn spawn_stationd(
    pipe_name: &str,
    profiles: &Path,
    traces: &Path,
    runtime: &str,
    allowed_origins: &[&str],
) -> tokio::process::Child {
    let mut command = tokio::process::Command::new(
        env!("CARGO_BIN_EXE_dig2browser-stationd"),
    );
    command.args([
        "--pipe-name",
        pipe_name,
        "--profiles-root",
        profiles.to_str().expect("profiles path is UTF-8"),
        "--trace-root",
        traces.to_str().expect("trace path is UTF-8"),
        "--runtime",
        runtime,
        "--max-resident",
        "1",
        "--max-in-flight",
        "2",
        "--max-connections",
        "2",
        "--timeout-seconds",
        "60",
        "--drain-seconds",
        "15",
        "--allow-remote-shutdown",
        "--allow-interactive-tasks",
        "--allow-headful-auth",
        "--allow-durable-read",
        "--allow-durable-write",
    ]);
    for origin in allowed_origins {
        command.args(["--allow-origin", origin]);
    }
    command.args(["--allow-private-peer", "127.0.0.1"]);
    command
        .env("HTTP_PROXY", "http://127.0.0.1:1")
        .env("HTTPS_PROXY", "http://127.0.0.1:1")
        .env("ALL_PROXY", "http://127.0.0.1:1")
        .env("NO_PROXY", "*")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn navigation-policy station")
}

struct WebRtcStationOptions<'a> {
    broker_pipe_name: Option<&'a str>,
    broker_capability: Option<WindowsWfpBrokerCapability>,
    command_timeout_seconds: u64,
    /// Worker close/drain teardown budget, distinct from
    /// `command_timeout_seconds`. `None` leaves `--close-timeout-seconds`
    /// unset, which falls back to `command_timeout_seconds` in the daemon.
    close_timeout_seconds: Option<u64>,
    test_close_delay_millis: Option<u64>,
}

async fn spawn_webrtc_stationd(
    pipe_name: &str,
    profiles: &Path,
    traces: &Path,
    runtime: &str,
    allowed_origins: &[&str],
    options: WebRtcStationOptions<'_>,
) -> LoggedStation {
    let WebRtcStationOptions {
        broker_pipe_name,
        broker_capability,
        command_timeout_seconds,
        close_timeout_seconds,
        test_close_delay_millis,
    } = options;
    assert_eq!(
        broker_pipe_name.is_some(),
        broker_capability.is_some(),
        "WFP broker pipe and capability must be configured together"
    );
    let mut command = tokio::process::Command::new(
        env!("CARGO_BIN_EXE_dig2browser-stationd"),
    );
    command.args([
        "--pipe-name",
        pipe_name,
        "--profiles-root",
        profiles.to_str().expect("profiles path is UTF-8"),
        "--trace-root",
        traces.to_str().expect("trace path is UTF-8"),
        "--runtime",
        runtime,
        "--max-resident",
        "1",
        "--max-in-flight",
        "2",
        "--max-connections",
        "2",
        "--drain-seconds",
        "15",
        "--allow-remote-shutdown",
        "--allow-interactive-tasks",
        "--allow-headful-auth",
        "--allow-durable-read",
        "--allow-durable-write",
    ]);
    command
        .arg("--timeout-seconds")
        .arg(command_timeout_seconds.to_string());
    if let Some(close_timeout_seconds) = close_timeout_seconds {
        command
            .arg("--close-timeout-seconds")
            .arg(close_timeout_seconds.to_string());
    }
    if let Some(delay_millis) = test_close_delay_millis {
        command
            .arg("--test-chromium-close-delay-millis")
            .arg(delay_millis.to_string());
    }
    if let Some(broker_pipe_name) = broker_pipe_name {
        command.args([
            "--windows-containment",
            "required",
            "--windows-wfp-broker-pipe",
            broker_pipe_name,
        ]);
    }
    for origin in allowed_origins {
        command.args(["--allow-origin", origin]);
    }
    command.args(["--allow-private-peer", "127.0.0.1"]);
    let component = format!("station-{pipe_name}");
    let stdout_path = e2e_component_path(&component, "stdout");
    let stderr_path = e2e_component_path(&component, "stderr");
    let runtime_log = e2e_component_path(&component, "runtime");
    let browser_stderr_log = e2e_component_path(&component, "browser-stderr");
    let station_diagnostic_log = e2e_component_path(&component, "diagnostic");
    let stdout = File::create(&stdout_path).expect("create station stdout log");
    let stderr = File::create(&stderr_path).expect("create station stderr log");
    File::create(&runtime_log).expect("create station runtime log");
    File::create(&browser_stderr_log).expect("create browser stderr log");
    File::create(&station_diagnostic_log).expect("create station diagnostic log");
    record_e2e_event(
        &component,
        "spawn_requested",
        serde_json::json!({
            "runtime": runtime,
            "containment_required": broker_pipe_name.is_some(),
            "stdout": stdout_path,
            "stderr": stderr_path,
            "runtime_log": runtime_log,
            "browser_stderr_log": browser_stderr_log,
            "station_diagnostic_log": station_diagnostic_log,
        }),
    );
    let mut child = command
        .env_remove("CHROME_PATH")
        .env_remove("EDGE_PATH")
        .env("DIG2BROWSER_TEST_ALLOW_DIRECT_WEBRTC_UDP", "1")
        .env("DIG2BROWSER_RUNTIME_DIAGNOSTIC_LOG", &runtime_log)
        .env("DIG2BROWSER_BROWSER_STDERR_LOG", &browser_stderr_log)
        .env("DIG2BROWSER_STATION_DIAGNOSTIC_LOG", &station_diagnostic_log)
        .env("HTTP_PROXY", "http://127.0.0.1:1")
        .env("HTTPS_PROXY", "http://127.0.0.1:1")
        .env("ALL_PROXY", "http://127.0.0.1:1")
        .env("NO_PROXY", "*")
        .stdin(if broker_capability.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .kill_on_drop(true)
        .spawn()
        .expect("spawn WebRTC proof station");
    record_e2e_event(
        &component,
        "spawned",
        serde_json::json!({ "process_id": child.id() }),
    );
    if let Some(capability) = broker_capability {
        let mut stdin = child
            .stdin
            .take()
            .expect("contained station stdin is piped");
        capability
            .write_to_async(&mut stdin)
            .await
            .expect("write station WFP capability");
    }
    LoggedStation {
        child,
        stdout_path,
        stderr_path,
        diagnostic_path: station_diagnostic_log,
    }
}

async fn spawn_wfp_broker(
    pipe_name: &str,
    allowed_runtime_root: &Path,
    capability: WindowsWfpBrokerCapability,
) -> ElevatedWindowsWfpBroker {
    let parent = inspect_windows_process_security(std::process::id())
        .expect("inspect WFP E2E parent security");
    assert!(
        !parent.elevated && parent.is_medium_integrity(),
        "WFP E2E parent must remain non-elevated medium integrity: {parent:?}"
    );
    let result = launch_elevated_windows_wfp_broker(
        Path::new(env!("CARGO_BIN_EXE_dig2browser-wfp-broker")),
        pipe_name,
        allowed_runtime_root,
        capability,
    )
    .await;
    match result {
        Ok(broker) => {
            record_e2e_event(
                "wfp-broker",
                "bootstrap_authenticated",
                serde_json::json!({
                    "process_id": broker.id(),
                    "integrity_rid": broker.security().integrity_rid,
                    "elevated": broker.security().elevated,
                }),
            );
            broker
        }
        Err(error) => {
            record_e2e_event(
                "wfp-broker",
                "launch_failed",
                serde_json::json!({ "error": error.to_string() }),
            );
            panic!("launch broker-only elevated WFP process: {error}");
        }
    }
}

fn spawn_capacity_shutdown_stationd(
    pipe_name: &str,
    profiles: &Path,
) -> tokio::process::Child {
    let mut command = tokio::process::Command::new(
        env!("CARGO_BIN_EXE_dig2browser-stationd"),
    );
    command.args([
        "--pipe-name",
        pipe_name,
        "--profiles-root",
        profiles.to_str().expect("profiles path is UTF-8"),
        "--runtime",
        "lightweight",
        "--max-resident",
        "1",
        "--max-in-flight",
        "1",
        "--max-connections",
        "1",
        "--timeout-seconds",
        "10",
        "--drain-seconds",
        "2",
        "--allow-remote-shutdown",
    ]);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn capacity-shutdown station")
}

#[cfg(feature = "tls-test-hooks")]
fn spawn_https_stationd(
    pipe_name: &str,
    profiles: &Path,
    allowed_origin: &str,
    certificate_spki: Option<&str>,
) -> tokio::process::Child {
    let mut command = tokio::process::Command::new(
        env!("CARGO_BIN_EXE_dig2browser-stationd"),
    );
    command.args([
        "--pipe-name",
        pipe_name,
        "--profiles-root",
        profiles.to_str().expect("profiles path is UTF-8"),
        "--runtime",
        "chrome",
        "--allow-origin",
        allowed_origin,
        "--allow-private-peer",
        "127.0.0.1",
        "--max-resident",
        "1",
        "--max-in-flight",
        "1",
        "--max-connections",
        "1",
        "--timeout-seconds",
        "10",
        "--drain-seconds",
        "2",
        "--allow-remote-shutdown",
        "--allow-interactive-tasks",
    ]);
    if let Some(certificate_spki) = certificate_spki {
        command.args([
            "--test-chrome-certificate-error-spki-sha256",
            certificate_spki,
        ]);
    }
    command
        .env("HTTP_PROXY", "http://127.0.0.1:1")
        .env("HTTPS_PROXY", "http://127.0.0.1:1")
        .env("ALL_PROXY", "http://127.0.0.1:1")
        .env("NO_PROXY", "*")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn HTTPS policy station")
}

async fn connect(pipe_name: &str) -> StationClient {
    StationClient::connect(
        ClientConfig::new(
            pipe_name,
            Duration::from_secs(15),
            Duration::from_secs(60),
        )
        .expect("valid policy client config"),
    )
    .await
    .expect("connect navigation-policy station")
}

async fn connect_with_daemon(
    pipe_name: &str,
    daemon: &mut LoggedStation,
) -> StationClient {
    connect_with_daemon_timeout(
        pipe_name,
        daemon,
        Duration::from_secs(15),
    )
    .await
}

async fn connect_with_daemon_timeout(
    pipe_name: &str,
    daemon: &mut LoggedStation,
    startup_timeout: Duration,
) -> StationClient {
    const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);

    let started = Instant::now();
    record_e2e_event(
        "test",
        "station_connect_requested",
        serde_json::json!({
            "pipe_name": pipe_name,
            "process_id": daemon.id(),
            "startup_timeout_ms": startup_timeout.as_millis() as u64,
        }),
    );
    loop {
        let remaining = startup_timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            let (stdout, stderr) = daemon.output();
            let diagnostic = daemon.diagnostic_tail();
            record_e2e_event(
                "test",
                "station_connect_timed_out_live",
                serde_json::json!({
                    "pipe_name": pipe_name,
                    "process_id": daemon.id(),
                    "elapsed_ms": started.elapsed().as_millis() as u64,
                    "diagnostic": diagnostic,
                }),
            );
            panic!(
                "connect navigation-policy station timed out after {startup_timeout:?}; daemon pid={:?} remained live; diagnostic={diagnostic:?}; stdout={stdout:?}; stderr={stderr:?}",
                daemon.id()
            );
        }
        let config = ClientConfig::new(
            pipe_name,
            ATTEMPT_TIMEOUT.min(remaining),
            Duration::from_secs(60),
        )
        .expect("valid policy client config");
        match StationClient::connect(config).await {
            Ok(client) => {
                record_e2e_event(
                    "test",
                    "station_connected",
                    serde_json::json!({
                        "pipe_name": pipe_name,
                        "process_id": daemon.id(),
                        "elapsed_ms": started.elapsed().as_millis() as u64,
                    }),
                );
                return client;
            }
            Err(error) => match daemon.try_wait() {
                Ok(Some(status)) => {
                    let (stdout, stderr) = daemon.output();
                    let diagnostic = daemon.diagnostic_tail();
                    record_e2e_event(
                        "test",
                        "station_connect_failed",
                        serde_json::json!({
                            "pipe_name": pipe_name,
                            "status": status.to_string(),
                            "error": error.to_string(),
                            "diagnostic": diagnostic,
                        }),
                    );
                    panic!(
                        "connect navigation-policy station: {error}; daemon={status}; diagnostic={diagnostic:?}; stdout={stdout:?}; stderr={stderr:?}"
                    );
                }
                Ok(None) => {
                    let diagnostic = daemon.diagnostic_tail();
                    record_e2e_event(
                        "test",
                        "station_connect_waiting",
                        serde_json::json!({
                            "pipe_name": pipe_name,
                            "process_id": daemon.id(),
                            "elapsed_ms": started.elapsed().as_millis() as u64,
                            "remaining_ms": startup_timeout
                                .saturating_sub(started.elapsed())
                                .as_millis() as u64,
                            "last_error": error.to_string(),
                            "diagnostic": diagnostic,
                        }),
                    );
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(wait_error) => panic!(
                    "connect navigation-policy station: {error}; daemon status failed: {wait_error}"
                ),
            },
        }
    }
}

async fn assert_clean_exit(daemon: &mut tokio::process::Child) {
    let status = tokio::time::timeout(Duration::from_secs(30), daemon.wait())
        .await
        .expect("policy station exit timeout")
        .expect("wait for policy station");
    assert!(status.success(), "policy station failed: {status}");
    let (stdout, stderr) = read_child_output(daemon).await;
    assert!(stderr.is_empty(), "policy station wrote stderr: {stderr}");
    assert!(stdout.contains("\"outcome\":\"clean\""));
    let report: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("parse policy station exit report");
    assert!(
        report["egress_completed_connections"]
            .as_u64()
            .is_some_and(|count| count >= 1),
        "policy station did not report a completed egress connection: {stdout}"
    );
    assert!(
        report["egress_denied_connections"]
            .as_u64()
            .is_some_and(|count| count >= 1),
        "policy station did not report a denied egress connection: {stdout}"
    );
}

async fn assert_webrtc_clean_exit(
    daemon: &mut LoggedStation,
    expected_containment: bool,
) {
    let status = tokio::time::timeout(Duration::from_secs(30), daemon.wait())
        .await
        .expect("WebRTC policy station exit timeout")
        .expect("wait for WebRTC policy station");
    record_e2e_event(
        "station",
        "exited",
        serde_json::json!({
            "process_id": daemon.id(),
            "status": status.to_string(),
            "expected_containment": expected_containment,
        }),
    );
    assert!(status.success(), "WebRTC policy station failed: {status}");
    let (stdout, stderr) = daemon.output();
    assert!(stderr.is_empty(), "WebRTC policy station wrote stderr: {stderr}");
    let report: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("parse WebRTC station exit report");
    assert_eq!(report["outcome"], "clean", "unclean station report: {stdout}");
    assert_eq!(report["stop_reason"], "remote_request");
    assert_eq!(report["stopped_workers"], 1);
    let accepted = report["egress_accepted_connections"]
        .as_u64()
        .expect("accepted WebRTC egress count");
    assert!(accepted >= 1, "WebRTC station accepted no egress connections: {stdout}");
    let classified: u64 = [
        "egress_completed_connections",
        "egress_denied_connections",
        "egress_invalid_connections",
        "egress_idle_connections",
        "egress_failed_connections",
        "egress_timed_out_connections",
        "egress_aborted_connections",
    ]
    .iter()
    .map(|counter| report[*counter].as_u64().expect("classified WebRTC egress count"))
    .sum();
    assert_eq!(accepted, classified, "unaccounted WebRTC egress connection: {stdout}");
    assert!(
        report["egress_completed_connections"]
            .as_u64()
            .is_some_and(|count| count >= 1),
        "WebRTC station did not complete the controlled HTTP request: {stdout}"
    );
    assert_eq!(
        report["egress_failed_connections"],
        0,
        "WebRTC station reported failed egress: {stdout}"
    );
    assert_eq!(
        report["egress_timed_out_connections"],
        0,
        "WebRTC station reported timed-out egress: {stdout}"
    );
    assert_eq!(report["egress_drain_timed_out"], false);
    if expected_containment {
        assert_eq!(report["containment_subject_scope"], "known_executable_set");
        assert_eq!(report["containment_station_instance_exclusive"], true);
        assert_eq!(report["containment_provider_crash"], "enforcement_retained");
        assert_eq!(report["containment_tcp"], true);
        assert_eq!(report["containment_udp"], true);
        assert_eq!(report["containment_raw_ip"], true);
        assert_eq!(report["containment_system_name_resolution"], false);
        assert_eq!(report["containment_ipv4"], true);
        assert_eq!(report["containment_ipv6"], true);
    } else {
        assert_eq!(report["containment_subject_scope"], "disabled");
        assert_eq!(report["containment_station_instance_exclusive"], false);
        assert_eq!(report["containment_provider_crash"], "not_applicable");
    }
}

async fn assert_containment_lost_exit(daemon: &mut LoggedStation) {
    let status = tokio::time::timeout(Duration::from_secs(30), daemon.wait())
        .await
        .expect("containment-lost station exit timeout")
        .expect("wait for containment-lost station");
    assert!(!status.success(), "containment-lost station exited successfully");
    let (stdout, stderr) = daemon.output();
    assert!(
        stdout.is_empty(),
        "containment-lost station unexpectedly wrote a clean report: {stdout}"
    );
    let report: serde_json::Value = serde_json::from_str(stderr.trim())
        .expect("parse containment-lost station exit report");
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["event"], "station_exit");
    assert_eq!(report["outcome"], "error");
    assert_eq!(report["error_class"], "containment_lost");
}

async fn assert_wfp_broker_clean_exit(broker: &mut ElevatedWindowsWfpBroker) {
    let exit = tokio::time::timeout(Duration::from_secs(30), broker.wait())
        .await
        .expect("WFP broker exit timeout")
        .expect("wait for WFP broker");
    record_e2e_event(
        "wfp-broker",
        "exited",
        serde_json::json!({
            "process_id": broker.id(),
            "exit_code": exit.exit_code,
            "outcome": format!("{:?}", exit.outcome),
        }),
    );
    assert_eq!(exit.exit_code, 0, "WFP broker failed: {exit:?}");
    assert!(
        matches!(exit.outcome, Some(WindowsWfpBrokerOutcome::Closed { version: 3 })),
        "unclean WFP broker outcome: {exit:?}"
    );
}

async fn assert_wfp_broker_client_disconnected(broker: &mut ElevatedWindowsWfpBroker) {
    let exit = tokio::time::timeout(Duration::from_secs(30), broker.wait())
        .await
        .expect("disconnected WFP broker exit timeout")
        .expect("wait for disconnected WFP broker");
    record_e2e_event(
        "wfp-broker",
        "client_disconnected_exit",
        serde_json::json!({
            "process_id": broker.id(),
            "exit_code": exit.exit_code,
            "outcome": format!("{:?}", exit.outcome),
        }),
    );
    assert_ne!(exit.exit_code, 0, "disconnected WFP broker exited successfully");
    assert!(
        matches!(
            exit.outcome,
            Some(WindowsWfpBrokerOutcome::ClientDisconnected { version: 3, .. })
        ),
        "unexpected disconnected WFP broker outcome: {exit:?}"
    );
}

async fn assert_station_shutdown_failure(daemon: &mut LoggedStation) {
    let status = tokio::time::timeout(Duration::from_secs(30), daemon.wait())
        .await
        .expect("shutdown-failure station exit timeout")
        .expect("wait for shutdown-failure station");
    assert!(!status.success(), "shutdown-failure station exited successfully");
    let (stdout, stderr) = daemon.output();
    assert!(stdout.is_empty(), "shutdown-failure station wrote clean report: {stdout}");
    let report: serde_json::Value = serde_json::from_str(stderr.trim())
        .expect("parse shutdown-failure station report");
    assert_eq!(report["outcome"], "error");
    assert_eq!(report["error_class"], "station_shutdown_failure");
}

#[cfg(feature = "tls-test-hooks")]
async fn assert_https_clean_exit(daemon: &mut tokio::process::Child) {
    let status = tokio::time::timeout(Duration::from_secs(30), daemon.wait())
        .await
        .expect("HTTPS policy station exit timeout")
        .expect("wait for HTTPS policy station");
    assert!(status.success(), "HTTPS policy station failed: {status}");
    let (stdout, stderr) = read_child_output(daemon).await;
    assert!(stderr.is_empty(), "HTTPS policy station wrote stderr: {stderr}");
    let report: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("parse HTTPS station exit report");
    assert_eq!(report["outcome"], "clean", "unclean station report: {stdout}");
    assert_eq!(report["stop_reason"], "remote_request");
    assert_eq!(report["stopped_workers"], 1);
    assert!(
        report["egress_accepted_connections"]
            .as_u64()
            .is_some_and(|count| count >= 1),
        "HTTPS station did not own a CONNECT tunnel: {stdout}"
    );
    assert!(
        report["egress_completed_connections"]
            .as_u64()
            .is_some_and(|count| count >= 1),
        "HTTPS station did not complete a CONNECT tunnel: {stdout}"
    );
    let accepted = report["egress_accepted_connections"]
        .as_u64()
        .expect("accepted egress count");
    let classified = [
        "egress_completed_connections",
        "egress_denied_connections",
        "egress_invalid_connections",
        "egress_idle_connections",
        "egress_failed_connections",
        "egress_timed_out_connections",
        "egress_aborted_connections",
    ]
    .iter()
    .map(|counter| report[*counter].as_u64().expect("classified egress count"))
    .sum::<u64>();
    assert_eq!(accepted, classified, "unaccounted egress connection: {stdout}");
    for counter in ["egress_failed_connections", "egress_timed_out_connections"] {
        assert_eq!(report[counter], 0, "dirty {counter} counter: {stdout}");
    }
    assert_eq!(report["egress_drain_timed_out"], false);
}

async fn read_child_output(child: &mut tokio::process::Child) -> (String, String) {
    let mut stdout = String::new();
    if let Some(mut stream) = child.stdout.take() {
        stream.read_to_string(&mut stdout).await.expect("read stdout");
    }
    let mut stderr = String::new();
    if let Some(mut stream) = child.stderr.take() {
        stream.read_to_string(&mut stderr).await.expect("read stderr");
    }
    (stdout, stderr)
}

async fn e2e_serial_guard() -> tokio::sync::SemaphorePermit<'static> {
    static E2E_SERIAL: tokio::sync::Semaphore =
        tokio::sync::Semaphore::const_new(1);
    E2E_SERIAL.acquire().await.expect("E2E semaphore remains open")
}

fn e2e_temp_base() -> PathBuf {
    std::env::var_os("DIG2BROWSER_E2E_TMP")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\tmp"))
}

fn runtime_mirror_catalog() -> PathBuf {
    PathBuf::from(
        std::env::var_os("LOCALAPPDATA")
            .filter(|value| !value.is_empty())
            .expect("LOCALAPPDATA is available for the Windows E2E"),
    )
    .join("dig2browser")
    .join("runtime-mirrors")
}

fn directory_entry_names(path: &Path) -> HashSet<String> {
    std::fs::read_dir(path)
        .expect("read runtime-mirror catalog")
        .map(|entry| {
            entry
                .expect("read runtime-mirror catalog entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect()
}

async fn remove_tree(path: &Path) {
    for _ in 0..30 {
        match std::fs::remove_dir_all(path) {
            Ok(()) => return,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    panic!("could not remove policy E2E profiles: {}", path.display());
}
