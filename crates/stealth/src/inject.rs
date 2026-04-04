//! Injection strategy trait for stealth scripts.
//!
//! Protocol-level implementations (CDP, WebDriver) live in the protocol crates
//! and implement this trait. The stealth crate itself has zero protocol deps.

use futures::future::BoxFuture;

use crate::StealthError;

/// Strategy for injecting stealth scripts into a browser context.
///
/// Implementors bridge the protocol gap: CDP uses
/// `Page.addScriptToEvaluateOnNewDocument`, WebDriver uses `execute_script`.
pub trait InjectionStrategy: Send + Sync {
    /// Register scripts to run on every new document before page scripts execute.
    ///
    /// This is the preferred method — scripts run before any page JS so
    /// anti-detection overrides are in place from the very first tick.
    fn inject_on_new_document<'a>(
        &'a self,
        scripts: &'a [String],
    ) -> BoxFuture<'a, Result<(), StealthError>>;

    /// Evaluate scripts in the current page context immediately.
    ///
    /// Used when `inject_on_new_document` is unavailable (e.g. WebDriver without BiDi).
    /// Scripts run after the page has already started loading, so some checks may
    /// have already fired.
    fn inject_now<'a>(
        &'a self,
        scripts: &'a [String],
    ) -> BoxFuture<'a, Result<(), StealthError>>;
}
