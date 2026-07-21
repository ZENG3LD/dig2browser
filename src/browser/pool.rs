//! BrowserPool — a fixed-size pool of StealthBrowser instances.
//!
//! Callers `acquire()` a page from the pool; the RAII guard returns the
//! semaphore permit on drop so the next waiter can proceed.

use std::ops::Deref;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;

use crate::detect::BrowserProfile;
use crate::detect::LaunchConfig;
use crate::stealth::StealthConfig;
use tracing::warn;

use crate::browser::browser::StealthBrowser;
use crate::browser::error::BrowserError;
use crate::browser::page::StealthPage;

/// Configuration for the browser pool.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Number of browser processes to launch.
    pub size: usize,
    /// How long to wait for a slot before returning `PoolExhausted`.
    pub acquire_timeout: Duration,
    /// Launch configuration applied to every browser in the pool.
    pub launch: LaunchConfig,
    /// Stealth configuration applied to every browser in the pool.
    pub stealth: StealthConfig,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            size: 3,
            acquire_timeout: Duration::from_secs(30),
            launch: LaunchConfig::default(),
            stealth: StealthConfig::default(),
        }
    }
}

/// A fixed-size pool of browser instances.
///
/// `acquire()` blocks until a slot is free (up to `PoolConfig::acquire_timeout`),
/// then opens a new page on a browser selected by round-robin.
pub struct BrowserPool {
    browsers: Vec<Arc<StealthBrowser>>,
    semaphore: Arc<tokio::sync::Semaphore>,
    counter: Arc<AtomicUsize>,
    acquire_timeout: Duration,
}

impl BrowserPool {
    /// Launch `config.size` browser instances and build the pool.
    pub async fn new(config: PoolConfig) -> Result<Self, BrowserError> {
        let size = config.size.max(1);
        validate_pool_profile(&config.launch.profile, size)?;
        let mut browsers = Vec::with_capacity(size);

        // Launch browsers in parallel.
        let mut handles = Vec::with_capacity(size);
        for index in 0..size {
            #[cfg(windows)]
            let launch = config.launch.clone();
            #[cfg(not(windows))]
            let mut launch = config.launch.clone();
            #[cfg(not(windows))]
            if launch.debug_port.is_none() {
                let base = LaunchConfig::find_free_port();
                launch.debug_port = Some(base.saturating_add(index as u16));
            }
            #[cfg(windows)]
            let _ = index;
            let stealth = config.stealth.clone();

            handles.push(tokio::spawn(async move {
                StealthBrowser::launch_with(launch, stealth).await
            }));
        }

        for handle in handles {
            let browser = handle
                .await
                .map_err(|e| BrowserError::Launch(e.to_string()))??;
            browsers.push(Arc::new(browser));
        }

        Ok(Self {
            semaphore: Arc::new(tokio::sync::Semaphore::new(size)),
            browsers,
            counter: Arc::new(AtomicUsize::new(0)),
            acquire_timeout: config.acquire_timeout,
        })
    }

    /// Acquire a page from the pool, waiting up to `acquire_timeout`.
    ///
    /// Returns a [`PoolPage`] RAII guard that releases the semaphore slot on drop.
    pub async fn acquire(&self) -> Result<PoolPage, BrowserError> {
        let permit = tokio::time::timeout(
            self.acquire_timeout,
            Arc::clone(&self.semaphore).acquire_owned(),
        )
        .await
        .map_err(|_| BrowserError::PoolExhausted(self.acquire_timeout))?
        .map_err(|_| BrowserError::Other("semaphore closed".into()))?;

        // Round-robin selection.
        let idx = self.counter.fetch_add(1, Ordering::Relaxed) % self.browsers.len();
        let browser = Arc::clone(&self.browsers[idx]);

        let page = browser.new_blank_page().await?;

        Ok(PoolPage {
            page,
            _permit: permit,
        })
    }

    /// Close all browsers in the pool.
    ///
    /// Logs a warning for any browser that is still referenced elsewhere.
    pub async fn shutdown(self) -> Result<(), BrowserError> {
        for browser_arc in self.browsers {
            match Arc::try_unwrap(browser_arc) {
                Ok(browser) => {
                    let _ = browser.close().await;
                }
                Err(_) => {
                    warn!("BrowserPool::shutdown — browser still referenced, skipping");
                }
            }
        }
        Ok(())
    }
}

fn validate_pool_profile(profile: &BrowserProfile, size: usize) -> Result<(), BrowserError> {
    if size > 1 && matches!(profile, BrowserProfile::Persistent(_)) {
        return Err(BrowserError::Launch(
            "a persistent profile has a single owner; BrowserPool size must be 1".into(),
        ));
    }
    Ok(())
}

/// RAII guard that holds a semaphore permit for the duration of a pool interaction.
///
/// The inner [`StealthPage`] is accessible via `Deref` or `.page()`.
pub struct PoolPage {
    page: StealthPage,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl PoolPage {
    /// Borrow the inner page.
    pub fn page(&self) -> &StealthPage {
        &self.page
    }
}

impl Deref for PoolPage {
    type Target = StealthPage;

    fn deref(&self) -> &Self::Target {
        &self.page
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[derive(Clone)]
    struct ProcessEntry {
        pid: u32,
        parent_pid: u32,
        image: String,
    }

    #[cfg(windows)]
    #[derive(Debug)]
    struct TcpListenerOwner {
        pid: u32,
        address_family: &'static str,
        port: u16,
    }

    #[cfg(windows)]
    fn process_snapshot() -> Result<Vec<ProcessEntry>, String> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW,
            Process32NextW, TH32CS_SNAPPROCESS,
        };

        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
            .map_err(|error| format!("create process snapshot: {error}"))?;
        let mut raw = PROCESSENTRY32W::default();
        raw.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut entries = Vec::new();
        let mut next = unsafe { Process32FirstW(snapshot, &mut raw) };
        while next.is_ok() {
            let image_len = raw
                .szExeFile
                .iter()
                .position(|character| *character == 0)
                .unwrap_or(raw.szExeFile.len());
            entries.push(ProcessEntry {
                pid: raw.th32ProcessID,
                parent_pid: raw.th32ParentProcessID,
                image: String::from_utf16_lossy(&raw.szExeFile[..image_len]),
            });
            next = unsafe { Process32NextW(snapshot, &mut raw) };
        }
        let _ = unsafe { CloseHandle(snapshot) };

        if entries.is_empty() {
            return Err("process snapshot was empty".to_owned());
        }
        Ok(entries)
    }

    #[cfg(windows)]
    fn is_chromium_image(image: &str) -> bool {
        image.eq_ignore_ascii_case("chrome.exe")
            || image.eq_ignore_ascii_case("msedge.exe")
            || image.eq_ignore_ascii_case("chromium.exe")
    }

    #[cfg(windows)]
    fn new_chromium_roots(
        baseline: &[ProcessEntry],
        live: &[ProcessEntry],
    ) -> Vec<u32> {
        let baseline_pids = baseline
            .iter()
            .map(|entry| entry.pid)
            .collect::<std::collections::HashSet<_>>();
        let new_chromium_pids = live
            .iter()
            .filter(|entry| {
                !baseline_pids.contains(&entry.pid) && is_chromium_image(&entry.image)
            })
            .map(|entry| entry.pid)
            .collect::<std::collections::HashSet<_>>();

        live.iter()
            .filter(|entry| {
                new_chromium_pids.contains(&entry.pid)
                    && entry.parent_pid == std::process::id()
            })
            .map(|entry| entry.pid)
            .collect()
    }

    #[cfg(windows)]
    fn process_tree_pids(entries: &[ProcessEntry], roots: &[u32]) -> std::collections::HashSet<u32> {
        let mut tree = roots.iter().copied().collect::<std::collections::HashSet<_>>();
        let mut changed = true;
        while changed {
            changed = false;
            for entry in entries {
                if tree.contains(&entry.parent_pid) && tree.insert(entry.pid) {
                    changed = true;
                }
            }
        }
        tree
    }

    #[cfg(windows)]
    fn tcp_listener_owners() -> Result<Vec<TcpListenerOwner>, String> {
        use windows::Win32::Foundation::{BOOL, ERROR_INSUFFICIENT_BUFFER};
        use windows::Win32::NetworkManagement::IpHelper::{
            GetExtendedTcpTable, MIB_TCP6TABLE_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
            TCP_TABLE_OWNER_PID_LISTENER,
        };
        use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

        unsafe fn read_table<Row, Table>(
            address_family: u32,
            family_name: &'static str,
            row_pointer: unsafe fn(*const Table) -> (*const Row, u32),
            owner: fn(&Row) -> (u32, u16),
        ) -> Result<Vec<TcpListenerOwner>, String> {
            let mut byte_count = 0u32;
            let probe = unsafe {
                GetExtendedTcpTable(
                    None,
                    &mut byte_count,
                    BOOL(0),
                    address_family,
                    TCP_TABLE_OWNER_PID_LISTENER,
                    0,
                )
            };
            if probe != ERROR_INSUFFICIENT_BUFFER.0 {
                return Err(format!(
                    "probe {family_name} TCP listener table failed with Win32 status {probe}"
                ));
            }

            let word_size = std::mem::size_of::<usize>();
            let word_count = (byte_count as usize + word_size - 1) / word_size;
            let mut storage = vec![0usize; word_count];
            let status = unsafe {
                GetExtendedTcpTable(
                    Some(storage.as_mut_ptr().cast()),
                    &mut byte_count,
                    BOOL(0),
                    address_family,
                    TCP_TABLE_OWNER_PID_LISTENER,
                    0,
                )
            };
            if status != 0 {
                return Err(format!(
                    "read {family_name} TCP listener table failed with Win32 status {status}"
                ));
            }

            let table = storage.as_ptr().cast::<Table>();
            let (rows, count) = unsafe { row_pointer(table) };
            let rows = unsafe { std::slice::from_raw_parts(rows, count as usize) };
            Ok(rows
                .iter()
                .map(|row| {
                    let (pid, port) = owner(row);
                    TcpListenerOwner {
                        pid,
                        address_family: family_name,
                        port,
                    }
                })
                .collect())
        }

        unsafe fn ipv4_rows(
            table: *const MIB_TCPTABLE_OWNER_PID,
        ) -> (*const windows::Win32::NetworkManagement::IpHelper::MIB_TCPROW_OWNER_PID, u32) {
            unsafe { ((*table).table.as_ptr(), (*table).dwNumEntries) }
        }

        unsafe fn ipv6_rows(
            table: *const MIB_TCP6TABLE_OWNER_PID,
        ) -> (*const windows::Win32::NetworkManagement::IpHelper::MIB_TCP6ROW_OWNER_PID, u32) {
            unsafe { ((*table).table.as_ptr(), (*table).dwNumEntries) }
        }

        let mut owners = unsafe {
            read_table(
                AF_INET.0 as u32,
                "IPv4",
                ipv4_rows,
                |row| (row.dwOwningPid, u16::from_be(row.dwLocalPort as u16)),
            )?
        };
        owners.extend(unsafe {
            read_table(
                AF_INET6.0 as u32,
                "IPv6",
                ipv6_rows,
                |row| (row.dwOwningPid, u16::from_be(row.dwLocalPort as u16)),
            )?
        });
        Ok(owners)
    }

    #[test]
    fn rejects_multiple_browsers_for_one_persistent_profile() {
        let profile = BrowserProfile::Persistent("profile".into());
        let error = validate_pool_profile(&profile, 2).unwrap_err();
        assert!(error.to_string().contains("single owner"));
    }

    #[test]
    fn allows_single_browser_for_persistent_profile() {
        let profile = BrowserProfile::Persistent("profile".into());
        assert!(validate_pool_profile(&profile, 1).is_ok());
    }

    #[test]
    fn allows_ephemeral_pool() {
        assert!(validate_pool_profile(&BrowserProfile::Ephemeral, 3).is_ok());
    }

    #[cfg(windows)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn default_two_browser_pool_launches_over_owned_cdp_pipes_e2e() {
        let baseline = process_snapshot().expect("capture process baseline");
        let config = PoolConfig {
            size: 2,
            acquire_timeout: Duration::from_secs(30),
            ..PoolConfig::default()
        };
        assert_eq!(config.launch.debug_port, None);

        let pool = BrowserPool::new(config)
            .await
            .expect("launch two-browser pool over inherited CDP pipes");
        assert_eq!(pool.browsers.len(), 2);
        assert!(
            pool.browsers
                .iter()
                .all(|browser| browser._launch.debug_port.is_none()),
            "pool must preserve the default pipe transport instead of allocating TCP ports"
        );

        let first = pool.acquire().await.expect("acquire first pooled page");
        let second = pool.acquire().await.expect("acquire second pooled page");

        let live_before_tcp = process_snapshot().expect("capture live Chromium process trees");
        let roots = new_chromium_roots(&baseline, &live_before_tcp);
        assert_eq!(
            roots.len(),
            2,
            "expected exactly two new Chromium roots, got {roots:?}"
        );
        let listeners = tcp_listener_owners().expect("read OS TCP listener tables");
        let live_after_tcp = process_snapshot().expect("confirm live Chromium process trees");
        let mut tree_pids = process_tree_pids(&live_before_tcp, &roots);
        tree_pids.extend(process_tree_pids(&live_after_tcp, &roots));
        let browser_listeners = listeners
            .into_iter()
            .filter(|listener| tree_pids.contains(&listener.pid))
            .map(|listener| {
                format!(
                    "{} pid={} port={}",
                    listener.address_family, listener.pid, listener.port
                )
            })
            .collect::<Vec<_>>();
        assert!(
            browser_listeners.is_empty(),
            "pipe-controlled Chromium trees unexpectedly own TCP listeners: {browser_listeners:?}"
        );

        drop((first, second));

        pool.shutdown().await.expect("shutdown pooled browsers");
    }
}
