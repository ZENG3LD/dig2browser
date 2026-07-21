//! Owned browser process launch and lifecycle primitives.

use std::io;
use std::process::ExitStatus;

pub(crate) struct BrowserProcess {
    #[cfg(windows)]
    process: WindowsProcess,
    #[cfg(not(windows))]
    process: tokio::process::Child,
}

impl BrowserProcess {
    pub(crate) fn from_tokio(process: tokio::process::Child) -> Self {
        #[cfg(windows)]
        return Self {
            process: WindowsProcess::Tokio(Box::new(process)),
        };

        #[cfg(not(windows))]
        Self { process }
    }

    #[cfg(windows)]
    fn from_windows(process: OwnedWindowsProcess) -> Self {
        Self {
            process: WindowsProcess::Native(process),
        }
    }

    pub(crate) fn start_kill(&mut self) -> io::Result<()> {
        #[cfg(windows)]
        return self.process.start_kill();

        #[cfg(not(windows))]
        self.process.start_kill()
    }

    pub(crate) async fn wait(&mut self) -> io::Result<ExitStatus> {
        #[cfg(windows)]
        return self.process.wait().await;

        #[cfg(not(windows))]
        self.process.wait().await
    }

    pub(crate) async fn kill(&mut self) -> io::Result<()> {
        #[cfg(windows)]
        return self.process.kill().await;

        #[cfg(not(windows))]
        self.process.kill().await
    }

    #[cfg(windows)]
    pub(crate) fn raw_handle(&self) -> *mut std::ffi::c_void {
        match &self.process {
            WindowsProcess::Native(process) => process.process.0.0,
            WindowsProcess::Tokio(process) => process
                .raw_handle()
                .unwrap_or(std::ptr::null_mut()),
        }
    }

    #[cfg(windows)]
    pub(crate) fn resume(&mut self) -> io::Result<()> {
        self.process.resume()
    }
}

#[cfg(windows)]
enum WindowsProcess {
    Native(OwnedWindowsProcess),
    Tokio(Box<tokio::process::Child>),
}

#[cfg(windows)]
impl WindowsProcess {
    fn start_kill(&mut self) -> io::Result<()> {
        match self {
            Self::Native(process) => process.start_kill(),
            Self::Tokio(process) => process.start_kill(),
        }
    }

    async fn wait(&mut self) -> io::Result<ExitStatus> {
        match self {
            Self::Native(process) => process.wait().await,
            Self::Tokio(process) => process.wait().await,
        }
    }

    async fn kill(&mut self) -> io::Result<()> {
        match self {
            Self::Native(process) => process.kill().await,
            Self::Tokio(process) => process.kill().await,
        }
    }

    fn resume(&mut self) -> io::Result<()> {
        match self {
            Self::Native(process) => process.resume(),
            Self::Tokio(_) => Ok(()),
        }
    }
}

#[cfg(windows)]
pub(crate) struct PreparedWindowsCdpProcess {
    browser_input: OwnedWindowsHandle,
    controller_output: OwnedWindowsHandle,
    controller_input: OwnedWindowsHandle,
    browser_output: OwnedWindowsHandle,
    stderr_input: OwnedWindowsHandle,
    stderr_output: OwnedWindowsHandle,
    null_input: OwnedWindowsHandle,
    null_output: OwnedWindowsHandle,
}

#[cfg(windows)]
pub(crate) struct SpawnedWindowsCdpProcess {
    pub(crate) process: BrowserProcess,
    pub(crate) cdp_reader: tokio::fs::File,
    pub(crate) cdp_writer: tokio::fs::File,
    pub(crate) stderr: tokio::fs::File,
}

#[cfg(windows)]
impl PreparedWindowsCdpProcess {
    pub(crate) fn new() -> io::Result<Self> {
        let (browser_input, controller_output) = create_inherited_pipe(false)?;
        let (controller_input, browser_output) = create_inherited_pipe(true)?;
        let (stderr_input, stderr_output) = create_inherited_pipe(true)?;
        let null_input = open_inherited_null(false)?;
        let null_output = open_inherited_null(true)?;
        Ok(Self {
            browser_input,
            controller_output,
            controller_input,
            browser_output,
            stderr_input,
            stderr_output,
            null_input,
            null_output,
        })
    }

    pub(crate) fn child_cdp_handles(&self) -> io::Result<(u32, u32)> {
        Ok((
            serialized_handle(self.browser_input.raw())?,
            serialized_handle(self.browser_output.raw())?,
        ))
    }

    pub(crate) fn spawn_suspended(
        self,
        executable: &std::path::Path,
        args: &[String],
    ) -> io::Result<SpawnedWindowsCdpProcess> {
        use windows::Win32::Foundation::BOOL;
        use windows::Win32::System::Threading::{
            CreateProcessW, PROCESS_INFORMATION, STARTF_USESTDHANDLES,
            STARTUPINFOEXW, CREATE_SUSPENDED, EXTENDED_STARTUPINFO_PRESENT,
        };
        use windows::core::{PCWSTR, PWSTR};

        let inherited = [
            self.browser_input.raw(),
            self.browser_output.raw(),
            self.stderr_output.raw(),
            self.null_input.raw(),
            self.null_output.raw(),
        ];
        let attributes = ProcessAttributeList::with_inherited_handles(&inherited)?;
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = self.null_input.raw();
        startup.StartupInfo.hStdOutput = self.null_output.raw();
        startup.StartupInfo.hStdError = self.stderr_output.raw();
        startup.lpAttributeList = attributes.raw();

        let executable_wide = nul_terminated(executable.as_os_str())?;
        let mut command_line = build_command_line(executable.as_os_str(), args)?;
        let mut process_info = PROCESS_INFORMATION::default();
        // SAFETY: every pointer references live, writable storage for the
        // duration of the call. Only the explicit handle list is inherited.
        unsafe {
            CreateProcessW(
                PCWSTR(executable_wide.as_ptr()),
                PWSTR(command_line.as_mut_ptr()),
                None,
                None,
                BOOL(1),
                CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
                None,
                PCWSTR::null(),
                &startup.StartupInfo,
                &mut process_info,
            )
        }
        .map_err(windows_error)?;

        let process = OwnedWindowsProcess {
            process: OwnedWindowsHandle::new(process_info.hProcess),
            thread: Some(OwnedWindowsHandle::new(process_info.hThread)),
            resumed: false,
        };
        let cdp_reader = into_tokio_file(self.controller_input);
        let cdp_writer = into_tokio_file(self.controller_output);
        let stderr = into_tokio_file(self.stderr_input);
        Ok(SpawnedWindowsCdpProcess {
            process: BrowserProcess::from_windows(process),
            cdp_reader,
            cdp_writer,
            stderr,
        })
    }
}

#[cfg(windows)]
struct OwnedWindowsProcess {
    process: OwnedWindowsHandle,
    thread: Option<OwnedWindowsHandle>,
    resumed: bool,
}

#[cfg(windows)]
impl OwnedWindowsProcess {
    fn resume(&mut self) -> io::Result<()> {
        use windows::Win32::System::Threading::ResumeThread;

        if self.resumed {
            return Ok(());
        }
        let thread = self
            .thread
            .as_ref()
            .ok_or_else(|| io::Error::other("browser launch thread is unavailable"))?;
        // SAFETY: the thread handle belongs to the suspended process and has
        // not been resumed or closed yet.
        let previous = unsafe { ResumeThread(thread.raw()) };
        if previous == u32::MAX {
            return Err(io::Error::last_os_error());
        }
        self.resumed = true;
        self.thread.take();
        Ok(())
    }

    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        use std::os::windows::process::ExitStatusExt;
        use windows::Win32::Foundation::STILL_ACTIVE;
        use windows::Win32::System::Threading::GetExitCodeProcess;

        let mut code = 0u32;
        // SAFETY: the process handle remains owned by this value.
        unsafe { GetExitCodeProcess(self.process.raw(), &mut code) }
            .map_err(windows_error)?;
        if code == STILL_ACTIVE.0 as u32 {
            Ok(None)
        } else {
            Ok(Some(ExitStatus::from_raw(code)))
        }
    }

    fn start_kill(&mut self) -> io::Result<()> {
        use windows::Win32::System::Threading::TerminateProcess;

        if self.try_wait()?.is_some() {
            return Ok(());
        }
        // SAFETY: the process handle remains owned by this value.
        unsafe { TerminateProcess(self.process.raw(), 1) }
            .map_err(windows_error)
    }

    async fn wait(&mut self) -> io::Result<ExitStatus> {
        loop {
            if let Some(status) = self.try_wait()? {
                return Ok(status);
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    }

    async fn kill(&mut self) -> io::Result<()> {
        self.start_kill()?;
        self.wait().await.map(|_| ())
    }
}

#[cfg(windows)]
impl Drop for OwnedWindowsProcess {
    fn drop(&mut self) {
        let _ = self.start_kill();
    }
}

#[cfg(windows)]
// SAFETY: Windows process and thread handles may be used from any thread. The
// wrapper retains unique ownership and closes each handle exactly once.
unsafe impl Send for OwnedWindowsProcess {}

#[cfg(windows)]
struct ProcessAttributeList {
    storage: Vec<usize>,
    list: windows::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST,
}

#[cfg(windows)]
impl ProcessAttributeList {
    fn with_inherited_handles(
        handles: &[windows::Win32::Foundation::HANDLE],
    ) -> io::Result<Self> {
        use windows::Win32::System::Threading::{
            InitializeProcThreadAttributeList,
            LPPROC_THREAD_ATTRIBUTE_LIST, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            UpdateProcThreadAttribute,
        };

        let mut bytes = 0usize;
        // SAFETY: the documented sizing call uses a null list and writes only
        // the required byte count.
        let _ = unsafe {
            InitializeProcThreadAttributeList(
                LPPROC_THREAD_ATTRIBUTE_LIST::default(),
                1,
                0,
                &mut bytes,
            )
        };
        if bytes == 0 {
            return Err(io::Error::last_os_error());
        }
        let words = bytes.div_ceil(std::mem::size_of::<usize>());
        let mut storage = vec![0usize; words];
        let list = LPPROC_THREAD_ATTRIBUTE_LIST(storage.as_mut_ptr().cast());
        // SAFETY: `storage` is aligned and large enough for the attribute list
        // and remains owned by the returned value.
        unsafe { InitializeProcThreadAttributeList(list, 1, 0, &mut bytes) }
            .map_err(windows_error)?;
        let attributes = Self { storage, list };
        // SAFETY: the handle array remains live through CreateProcessW and the
        // byte length exactly covers every HANDLE entry.
        unsafe {
            UpdateProcThreadAttribute(
                attributes.list,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                Some(handles.as_ptr().cast()),
                std::mem::size_of_val(handles),
                None,
                None,
            )
        }
        .map_err(windows_error)?;
        Ok(attributes)
    }

    fn raw(&self) -> windows::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST {
        self.list
    }
}

#[cfg(windows)]
impl Drop for ProcessAttributeList {
    fn drop(&mut self) {
        use windows::Win32::System::Threading::DeleteProcThreadAttributeList;

        // SAFETY: the list was initialized in this allocation and is deleted
        // before its backing storage is released.
        unsafe { DeleteProcThreadAttributeList(self.list) };
        let _ = self.storage.len();
    }
}

#[cfg(windows)]
struct OwnedWindowsHandle(windows::Win32::Foundation::HANDLE);

#[cfg(windows)]
// SAFETY: Win32 kernel handles may be transferred between threads. This
// wrapper retains unique ownership and closes the handle exactly once.
unsafe impl Send for OwnedWindowsHandle {}

#[cfg(windows)]
// SAFETY: shared access only copies the opaque handle value for Win32 calls;
// ownership and mutation remain behind exclusive references.
unsafe impl Sync for OwnedWindowsHandle {}

#[cfg(windows)]
impl OwnedWindowsHandle {
    fn new(handle: windows::Win32::Foundation::HANDLE) -> Self {
        Self(handle)
    }

    fn raw(&self) -> windows::Win32::Foundation::HANDLE {
        self.0
    }

    fn into_raw(mut self) -> *mut std::ffi::c_void {
        let raw = self.0.0;
        self.0 = windows::Win32::Foundation::HANDLE::default();
        raw
    }
}

#[cfg(windows)]
impl Drop for OwnedWindowsHandle {
    fn drop(&mut self) {
        use windows::Win32::Foundation::CloseHandle;

        if !self.0.is_invalid() {
            // SAFETY: this value uniquely owns the valid handle.
            let _ = unsafe { CloseHandle(self.0) };
        }
    }
}

#[cfg(windows)]
fn create_inherited_pipe(
    parent_reads: bool,
) -> io::Result<(OwnedWindowsHandle, OwnedWindowsHandle)> {
    use windows::Win32::Foundation::{
        HANDLE, HANDLE_FLAGS, HANDLE_FLAG_INHERIT, SetHandleInformation,
    };
    use windows::Win32::Security::SECURITY_ATTRIBUTES;
    use windows::Win32::System::Pipes::CreatePipe;

    let mut read = HANDLE::default();
    let mut write = HANDLE::default();
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: true.into(),
    };
    // SAFETY: output pointers and the security attributes are valid.
    unsafe { CreatePipe(&mut read, &mut write, Some(&attributes), 0) }
        .map_err(windows_error)?;
    let read = OwnedWindowsHandle::new(read);
    let write = OwnedWindowsHandle::new(write);
    let parent = if parent_reads { read.raw() } else { write.raw() };
    // SAFETY: the selected parent handle is valid and uniquely owned here.
    unsafe { SetHandleInformation(parent, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0)) }
        .map_err(windows_error)?;
    Ok((read, write))
}

#[cfg(windows)]
fn open_inherited_null(write: bool) -> io::Result<OwnedWindowsHandle> {
    use windows::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, HANDLE};
    use windows::Win32::Security::SECURITY_ATTRIBUTES;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE,
        OPEN_EXISTING,
    };
    use windows::core::w;

    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: true.into(),
    };
    let access = if write { GENERIC_WRITE.0 } else { GENERIC_READ.0 };
    // SAFETY: NUL is a stable system device and the security attributes remain
    // live for the duration of the call.
    let handle = unsafe {
        CreateFileW(
            w!("NUL"),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            Some(&attributes),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE::default(),
        )
    }
    .map_err(windows_error)?;
    Ok(OwnedWindowsHandle::new(handle))
}

#[cfg(windows)]
fn serialized_handle(handle: windows::Win32::Foundation::HANDLE) -> io::Result<u32> {
    u32::try_from(handle.0 as usize)
        .map_err(|_| io::Error::other("browser pipe handle exceeds Chromium's u32 format"))
}

#[cfg(windows)]
fn into_tokio_file(handle: OwnedWindowsHandle) -> tokio::fs::File {
    use std::os::windows::io::{FromRawHandle, RawHandle};

    // SAFETY: ownership moves from `OwnedWindowsHandle` into the File exactly
    // once and both wrappers use CloseHandle for cleanup.
    let file = unsafe {
        std::fs::File::from_raw_handle(handle.into_raw() as RawHandle)
    };
    tokio::fs::File::from_std(file)
}

#[cfg(windows)]
fn nul_terminated(value: &std::ffi::OsStr) -> io::Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;

    let mut wide = value.encode_wide().collect::<Vec<_>>();
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "browser process argument contains NUL",
        ));
    }
    wide.push(0);
    Ok(wide)
}

#[cfg(windows)]
fn build_command_line(
    executable: &std::ffi::OsStr,
    args: &[String],
) -> io::Result<Vec<u16>> {
    let mut command = Vec::new();
    append_windows_argument(&mut command, executable)?;
    for argument in args {
        command.push(b' ' as u16);
        append_windows_argument(&mut command, std::ffi::OsStr::new(argument))?;
    }
    command.push(0);
    Ok(command)
}

#[cfg(windows)]
fn append_windows_argument(
    command: &mut Vec<u16>,
    argument: &std::ffi::OsStr,
) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    let units = argument.encode_wide().collect::<Vec<_>>();
    if units.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "browser process argument contains NUL",
        ));
    }
    let quote = units.is_empty()
        || units.iter().any(|unit| {
            *unit == b' ' as u16 || *unit == b'\t' as u16 || *unit == b'"' as u16
        });
    if !quote {
        command.extend(units);
        return Ok(());
    }

    command.push(b'"' as u16);
    let mut backslashes = 0usize;
    for unit in units {
        if unit == b'\\' as u16 {
            backslashes += 1;
            continue;
        }
        if unit == b'"' as u16 {
            command.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2 + 1));
        } else {
            command.extend(std::iter::repeat_n(b'\\' as u16, backslashes));
        }
        backslashes = 0;
        command.push(unit);
    }
    command.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2));
    command.push(b'"' as u16);
    Ok(())
}

#[cfg(windows)]
fn windows_error(error: windows::core::Error) -> io::Error {
    io::Error::other(error.to_string())
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn windows_command_line_quotes_spaces_quotes_and_trailing_slashes() {
        use std::os::windows::ffi::OsStringExt;

        let command = build_command_line(
            std::ffi::OsStr::new(r"C:\Program Files\Browser\chrome.exe"),
            &[
                "plain".to_owned(),
                "two words".to_owned(),
                r#"quote\"inside"#.to_owned(),
                r"trailing slash\".to_owned(),
            ],
        )
        .expect("valid command line");
        let rendered = std::ffi::OsString::from_wide(&command[..command.len() - 1]);
        assert_eq!(
            rendered,
            std::ffi::OsString::from(
                r#""C:\Program Files\Browser\chrome.exe" plain "two words" "quote\\\"inside" "trailing slash\\""#
            )
        );
    }
}
