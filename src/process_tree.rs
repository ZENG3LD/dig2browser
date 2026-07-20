//! Owned process-tree containment for browser processes.

use std::io;

/// Owns the operating-system containment primitive for one launched browser.
///
/// On Windows, closing the contained Job Object terminates every process still
/// assigned to it. This is deliberately separate from `Child::kill`: killing
/// a Chromium root process does not recursively terminate its descendants.
pub(crate) struct OwnedProcessTree {
    #[cfg(windows)]
    job: windows::Win32::Foundation::HANDLE,
}

impl OwnedProcessTree {
    pub(crate) fn supports_immediate_termination(&self) -> bool {
        cfg!(windows)
    }

    pub(crate) fn new() -> io::Result<Self> {
        #[cfg(windows)]
        {
            use windows::core::PCWSTR;
            use windows::Win32::Foundation::CloseHandle;
            use windows::Win32::System::JobObjects::{
                CreateJobObjectW, JobObjectExtendedLimitInformation,
                SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            };

            // SAFETY: null security attributes and a null name are supported;
            // the returned handle is owned by this value.
            let job = unsafe { CreateJobObjectW(None, PCWSTR::null()) }
                .map_err(windows_error)?;
            let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            // SAFETY: `limits` matches the documented information class and
            // remains alive for the duration of the call.
            let configured = unsafe {
                SetInformationJobObject(
                    job,
                    JobObjectExtendedLimitInformation,
                    &limits as *const _ as *const std::ffi::c_void,
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            };
            if let Err(error) = configured {
                // SAFETY: `job` is a valid owned handle and is not used again.
                let _ = unsafe { CloseHandle(job) };
                return Err(windows_error(error));
            }
            Ok(Self { job })
        }

        #[cfg(not(windows))]
        Ok(Self {})
    }

    pub(crate) fn assign(&self, child: &tokio::process::Child) -> io::Result<()> {
        #[cfg(windows)]
        {
            use windows::Win32::Foundation::HANDLE;
            use windows::Win32::System::JobObjects::AssignProcessToJobObject;

            let raw_handle = child
                .raw_handle()
                .ok_or_else(|| io::Error::other("child process handle is unavailable"))?;
            let process = HANDLE(raw_handle);
            // SAFETY: both handles are valid for this call. The child remains
            // owned by the caller and the Job Object remains owned by `self`.
            unsafe { AssignProcessToJobObject(self.job, process) }
                .map_err(windows_error)?;
        }
        #[cfg(not(windows))]
        let _ = child;
        Ok(())
    }

    pub(crate) fn terminate_now(&self) -> io::Result<()> {
        #[cfg(windows)]
        {
            use windows::Win32::System::JobObjects::TerminateJobObject;

            // SAFETY: `self.job` is a valid owned Job Object handle.
            unsafe { TerminateJobObject(self.job, 1) }.map_err(windows_error)?;
        }
        Ok(())
    }

    pub(crate) async fn terminate_and_wait(
        &self,
        timeout: std::time::Duration,
    ) -> io::Result<()> {
        #[cfg(windows)]
        {
            use windows::Win32::System::JobObjects::{
                JobObjectBasicAccountingInformation, QueryInformationJobObject,
                JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
            };

            self.terminate_now()?;
            let deadline = tokio::time::Instant::now() + timeout;
            loop {
                let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
                // SAFETY: the buffer matches the requested information class
                // and remains alive for the duration of the call.
                unsafe {
                    QueryInformationJobObject(
                        self.job,
                        JobObjectBasicAccountingInformation,
                        &mut accounting as *mut _ as *mut std::ffi::c_void,
                        std::mem::size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                        None,
                    )
                }
                .map_err(windows_error)?;
                if accounting.ActiveProcesses == 0 {
                    return Ok(());
                }
                if tokio::time::Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "browser process tree did not terminate",
                    ));
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        }

        #[cfg(not(windows))]
        {
            let _ = timeout;
            Ok(())
        }
    }

    /// Wait for every process in the owned tree to exit without terminating it.
    ///
    /// Chromium may keep its network service alive briefly after the root
    /// process exits so profile databases and WAL files can be committed.
    pub(crate) async fn wait_until_empty(
        &self,
        timeout: std::time::Duration,
    ) -> io::Result<bool> {
        #[cfg(windows)]
        {
            use windows::Win32::System::JobObjects::{
                JobObjectBasicAccountingInformation, QueryInformationJobObject,
                JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
            };

            let deadline = tokio::time::Instant::now() + timeout;
            loop {
                let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
                // SAFETY: the buffer matches the requested information class
                // and remains alive for the duration of the call.
                unsafe {
                    QueryInformationJobObject(
                        self.job,
                        JobObjectBasicAccountingInformation,
                        &mut accounting as *mut _ as *mut std::ffi::c_void,
                        std::mem::size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                        None,
                    )
                }
                .map_err(windows_error)?;
                if accounting.ActiveProcesses == 0 {
                    return Ok(true);
                }
                if tokio::time::Instant::now() >= deadline {
                    return Ok(false);
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        }

        #[cfg(not(windows))]
        {
            let _ = timeout;
            Ok(true)
        }
    }
}

#[cfg(windows)]
fn windows_error(error: windows::core::Error) -> io::Error {
    io::Error::other(error.to_string())
}

#[cfg(windows)]
// SAFETY: a Job Object handle may be used from any thread. Ownership remains
// unique and the handle is closed exactly once by Drop.
unsafe impl Send for OwnedProcessTree {}

#[cfg(windows)]
// SAFETY: assigning processes to the same Job Object is thread-safe in Win32.
unsafe impl Sync for OwnedProcessTree {}

#[cfg(windows)]
impl Drop for OwnedProcessTree {
    fn drop(&mut self) {
        use windows::Win32::Foundation::CloseHandle;

        // SAFETY: `self.job` is the valid handle owned by this value.
        let _ = unsafe { CloseHandle(self.job) };
    }
}
