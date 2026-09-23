//! Test-only support shared across in-crate lib tests.
//!
//! Not compiled into the library proper — `#[cfg(test)]` only.

use tokio::sync::Mutex;

/// Serializes every lib test that launches a real browser process
/// (Chrome/Edge/Chromium/Firefox) against every other such test.
///
/// libtest runs `#[test]`/`#[tokio::test]` functions concurrently on separate
/// threads by default, and nothing else in this crate serializes access to
/// the host's real browser processes. A test that counts or inspects the
/// system-wide process tree (e.g. "exactly N new Chromium roots appeared")
/// is invalidated by a concurrently running test that launches its own
/// browser. Every such test must hold this lock for its full duration,
/// before launching anything and until every browser process it owns has
/// been asked to close.
///
/// A [`tokio::sync::Mutex`] (rather than `std::sync::Mutex`) is used on
/// purpose: the guard is held across many `.await` points for the whole
/// test body, which is exactly what an async-aware mutex is for, and tokio
/// is already a dependency of this crate — no new dependency (e.g.
/// `serial_test`) is introduced.
pub(crate) static REAL_BROWSER_E2E: Mutex<()> = Mutex::const_new(());
