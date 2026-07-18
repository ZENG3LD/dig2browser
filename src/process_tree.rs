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
            return Ok(Self { job });
        }

        #[cfg(not(windows))]
        Ok(Self {})
    }

    pub(crate) fn assign(&self, child: &tokio::process::Child) -> io::Result<()> {
        #[cfg(windows)]
        {
            use windows::Win32::Foundation::HANDLE;
            use windows::Win32::System::JobObjects::AssignProcessToJobObject;

            let raw_handle = child.raw_handle().ok_or_else(|| {
                io::Error::new(io::ErrorKind::Other, "child process handle is unavailable")
            })?;
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
}

#[cfg(windows)]
fn windows_error(error: windows::core::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, error.to_string())
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
