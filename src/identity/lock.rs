use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use super::IdentityError;

const LOCK_FILE_NAME: &str = ".dig2browser-profile.lock";

/// RAII ownership token for one persistent browser profile.
///
/// Windows uses an OS-enforced exclusive file handle, so ownership is released
/// even if the process crashes. Other targets use atomic lock-file creation.
#[derive(Debug)]
pub struct ProfileOwnershipGuard {
    file: Option<File>,
    lock_path: PathBuf,
    remove_on_drop: bool,
}

impl ProfileOwnershipGuard {
    pub fn acquire(profile_dir: impl AsRef<Path>) -> Result<Self, IdentityError> {
        let profile_dir = profile_dir.as_ref();
        std::fs::create_dir_all(profile_dir)?;
        let lock_path = profile_dir.join(LOCK_FILE_NAME);
        let mut file = match open_exclusive(&lock_path) {
            Ok(file) => file,
            Err(source) if is_ownership_conflict(&source) => {
                return Err(IdentityError::ProfileAlreadyOwned {
                    path: profile_dir.to_path_buf(),
                    source,
                });
            }
            Err(source) => return Err(IdentityError::Io(source)),
        };

        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        writeln!(file, "pid={}", std::process::id())?;
        file.flush()?;

        Ok(Self {
            file: Some(file),
            lock_path,
            remove_on_drop: !cfg!(windows),
        })
    }

    pub fn lock_path(&self) -> &Path {
        &self.lock_path
    }
}

fn is_ownership_conflict(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::AlreadyExists
        || error.kind() == std::io::ErrorKind::WouldBlock
        || (cfg!(windows) && matches!(error.raw_os_error(), Some(32 | 33)))
}

#[cfg(windows)]
fn open_exclusive(lock_path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .share_mode(0)
        .open(lock_path)
}

#[cfg(not(windows))]
fn open_exclusive(lock_path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(lock_path)
}

impl Drop for ProfileOwnershipGuard {
    fn drop(&mut self) {
        self.file.take();
        if self.remove_on_drop {
            let _ = std::fs::remove_file(&self.lock_path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_concurrent_profile_owner_and_releases_on_drop() {
        let profile_dir = std::env::temp_dir().join(format!(
            "dig2browser-profile-lock-test-{}",
            uuid::Uuid::new_v4()
        ));

        let first = ProfileOwnershipGuard::acquire(&profile_dir).unwrap();
        assert!(ProfileOwnershipGuard::acquire(&profile_dir).is_err());
        drop(first);
        assert!(ProfileOwnershipGuard::acquire(&profile_dir).is_ok());

        let _ = std::fs::remove_dir_all(profile_dir);
    }
}
