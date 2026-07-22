//! Process isolation selected for an owned browser launch.

/// Operating-system isolation for the complete browser process tree.
///
/// The default preserves the host browser's native sandbox. Windows stations
/// may additionally select a station-owned runtime path. Network containment
/// for that path is a separate station/broker responsibility.
#[derive(Debug, Clone, Default)]
pub enum BrowserProcessIsolation {
    /// Use the browser's native process sandbox without an outer container.
    #[default]
    Native,
    /// Launch Chromium from a station-owned runtime mirror.
    #[cfg(windows)]
    WindowsRuntimeMirror(crate::detect::BrowserBinary),
}

impl BrowserProcessIsolation {
    pub fn is_native(&self) -> bool {
        matches!(self, Self::Native)
    }

    #[cfg(windows)]
    pub(crate) fn browser_binary(&self) -> Option<&crate::detect::BrowserBinary> {
        match self {
            Self::Native => None,
            Self::WindowsRuntimeMirror(binary) => Some(binary),
        }
    }
}
