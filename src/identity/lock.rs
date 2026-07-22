use std::fs::{File, OpenOptions, TryLockError};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use super::IdentityError;

const LOCK_FILE_NAME: &str = ".dig2browser-profile.lock";
static RETAINED_PROFILE_OWNERS: OnceLock<Mutex<Vec<ProfileOwnershipGuard>>> = OnceLock::new();

/// RAII ownership token for one persistent browser profile.
///
/// The lock file is persistent, while ownership is an OS-backed exclusive file
/// lock. Closing the process releases ownership on every supported platform,
/// including after a crash.
#[derive(Debug)]
pub struct ProfileOwnershipGuard {
    file: Option<File>,
    lock_path: PathBuf,
}

impl ProfileOwnershipGuard {
    pub fn acquire(profile_dir: impl AsRef<Path>) -> Result<Self, IdentityError> {
        let profile_dir = profile_dir.as_ref();
        std::fs::create_dir_all(profile_dir)?;
        let lock_path = profile_dir.join(LOCK_FILE_NAME);
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(IdentityError::ProfileAlreadyOwned {
                    path: profile_dir.to_path_buf(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        "profile lock is held by another process",
                    ),
                });
            }
            Err(TryLockError::Error(source)) => return Err(IdentityError::Io(source)),
        }

        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        writeln!(file, "pid={}", std::process::id())?;
        file.flush()?;

        Ok(Self {
            file: Some(file),
            lock_path,
        })
    }

    pub fn lock_path(&self) -> &Path {
        &self.lock_path
    }

    /// Keep an unconfirmed browser profile unavailable for the rest of this
    /// process. The OS releases the underlying lock if the process exits or
    /// crashes; the persistent lock file itself never represents ownership.
    pub(crate) fn retain_until_process_exit(self) {
        RETAINED_PROFILE_OWNERS
            .get_or_init(|| Mutex::new(Vec::new()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(self);
    }

    #[cfg(test)]
    pub(crate) fn release_retained_for_test(profile_dir: &Path) {
        let Some(retained) = RETAINED_PROFILE_OWNERS.get() else {
            return;
        };
        retained
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|guard| guard.lock_path.parent() != Some(profile_dir));
    }
}

impl Drop for ProfileOwnershipGuard {
    fn drop(&mut self) {
        self.file.take();
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
        assert!(profile_dir.join(LOCK_FILE_NAME).exists());

        let _ = std::fs::remove_dir_all(profile_dir);
    }

    #[test]
    fn stale_lock_file_does_not_claim_profile_ownership() {
        let profile_dir = std::env::temp_dir().join(format!(
            "dig2browser-stale-profile-lock-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&profile_dir).unwrap();
        std::fs::write(profile_dir.join(LOCK_FILE_NAME), "pid=stale\n").unwrap();

        let owner = ProfileOwnershipGuard::acquire(&profile_dir)
            .expect("a stale file must not survive as ownership");
        assert!(ProfileOwnershipGuard::acquire(&profile_dir).is_err());
        drop(owner);

        std::fs::remove_dir_all(profile_dir).unwrap();
    }
}
