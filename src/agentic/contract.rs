use std::fmt;

/// Maximum number of distinct capabilities carried by one worker handle.
pub const MAX_CAPABILITIES: usize = 16;

/// Level 1 capabilities operate on raw viewport input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum L1Capability {
    Pointer,
    Keyboard,
    Scroll,
}

/// Level 2 capabilities operate on epoch-bound DOM references.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum L2Capability {
    Inspect,
    Interact,
    Evaluate,
}

/// Level 3 capabilities operate on browser state and lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum L3Capability {
    Navigate,
    Capture,
    Lifecycle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Capability {
    L1(L1Capability),
    L2(L2Capability),
    L3(L3Capability),
}

/// A small, duplicate-free capability set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilitySet {
    capabilities: Vec<Capability>,
}

impl CapabilitySet {
    pub fn new(capabilities: impl IntoIterator<Item = Capability>) -> Result<Self, ContractError> {
        let mut capabilities: Vec<_> = capabilities.into_iter().collect();
        if capabilities.len() > MAX_CAPABILITIES {
            return Err(ContractError::TooManyCapabilities {
                maximum: MAX_CAPABILITIES,
                actual: capabilities.len(),
            });
        }
        capabilities.sort_unstable();
        if capabilities.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ContractError::DuplicateCapability);
        }
        Ok(Self { capabilities })
    }

    /// Capabilities suitable for a read-only monitoring worker.
    pub fn monitoring() -> Self {
        Self::new([
            Capability::L2(L2Capability::Inspect),
            Capability::L3(L3Capability::Navigate),
            Capability::L3(L3Capability::Capture),
            Capability::L3(L3Capability::Lifecycle),
        ])
        .expect("built-in capability set is valid")
    }

    pub fn all() -> Self {
        Self::new([
            Capability::L1(L1Capability::Pointer),
            Capability::L1(L1Capability::Keyboard),
            Capability::L1(L1Capability::Scroll),
            Capability::L2(L2Capability::Inspect),
            Capability::L2(L2Capability::Interact),
            Capability::L2(L2Capability::Evaluate),
            Capability::L3(L3Capability::Navigate),
            Capability::L3(L3Capability::Capture),
            Capability::L3(L3Capability::Lifecycle),
        ])
        .expect("built-in capability set is valid")
    }

    /// Read-oriented monitoring plus bounded page-script evaluation. This is
    /// separate from `monitoring()` so ordinary capture clients do not gain a
    /// script execution capability implicitly.
    pub fn scripted_monitoring() -> Self {
        Self::new([
            Capability::L2(L2Capability::Inspect),
            Capability::L2(L2Capability::Evaluate),
            Capability::L3(L3Capability::Navigate),
            Capability::L3(L3Capability::Capture),
            Capability::L3(L3Capability::Lifecycle),
        ])
        .expect("built-in capability set is valid")
    }

    /// Collection tasks that need bounded scrolling, selector interaction,
    /// page evaluation, navigation, and evidence capture without raw pointer
    /// or keyboard control.
    pub fn collection() -> Self {
        Self::new([
            Capability::L1(L1Capability::Scroll),
            Capability::L2(L2Capability::Inspect),
            Capability::L2(L2Capability::Interact),
            Capability::L2(L2Capability::Evaluate),
            Capability::L3(L3Capability::Navigate),
            Capability::L3(L3Capability::Capture),
            Capability::L3(L3Capability::Lifecycle),
        ])
        .expect("built-in capability set is valid")
    }

    pub fn contains(&self, capability: Capability) -> bool {
        self.capabilities.binary_search(&capability).is_ok()
    }

    pub fn iter(&self) -> impl Iterator<Item = Capability> + '_ {
        self.capabilities.iter().copied()
    }
}

/// One open page target (tab/window) discovered by `AgentCommand::ListTabs`.
/// Mirrors the wire `TabInfo`, but is the root-crate type: the root crate
/// does not depend on `dig2browser-protocol`, so the station types this into
/// the protocol `TabInfo` at its boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TabInfo {
    pub id: String,
    pub url: String,
    pub title: String,
}

/// A DOM locator that is valid only for the page epoch in which it was resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElementRef {
    selector: String,
    page_epoch: u64,
}

impl ElementRef {
    pub fn new(selector: impl Into<String>, page_epoch: u64) -> Result<Self, ContractError> {
        let selector = selector.into();
        validate_selector(&selector)?;
        Ok(Self {
            selector,
            page_epoch,
        })
    }

    pub fn selector(&self) -> &str {
        &self.selector
    }

    pub fn page_epoch(&self) -> u64 {
        self.page_epoch
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapturePolicy {
    StateOnly,
    HtmlOnly,
    EvidenceViewport,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentState {
    pub url: String,
    pub title: String,
    pub ready_state: String,
    pub http_status: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureArtifact {
    StateOnly(DocumentState),
    HtmlOnly {
        state: DocumentState,
        html: String,
    },
    /// HTML plus a viewport PNG. This deliberately does not claim full-page capture.
    EvidenceViewport {
        state: DocumentState,
        html: String,
        png: Vec<u8>,
    },
}

/// A single cookie to install into a session. Mirrors `crate::cookies::Cookie`
/// but lives in the agentic contract (which is `PartialEq`). `value` is secret
/// material and is redacted from `Debug`.
#[derive(Clone, PartialEq)]
pub struct CookieSpec {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    pub secure: bool,
    pub http_only: bool,
    pub expires_unix: Option<i64>,
}

impl std::fmt::Debug for CookieSpec {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CookieSpec")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .field("domain", &self.domain)
            .field("path", &self.path)
            .field("secure", &self.secure)
            .field("http_only", &self.http_only)
            .field("expires_unix", &self.expires_unix)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum AgentCommand {
    ClickAt {
        x: f64,
        y: f64,
    },
    Wheel {
        x: f64,
        y: f64,
        delta_x: f64,
        delta_y: f64,
    },
    KeyPress {
        key: String,
    },
    ResolveElement {
        selector: String,
    },
    ClickElement {
        element: ElementRef,
    },
    TypeElement {
        element: ElementRef,
        text: String,
    },
    /// Choose an `<option>` of a `<select>` by value/label/text via a fixed,
    /// station-authored script parameterized only by `value` — never a consumer
    /// script. Fires `input`/`change` like a real gesture. Backs the
    /// `SelectOption` task step.
    SelectOption {
        element: ElementRef,
        value: String,
    },
    /// Set the files a file `<input>` element has selected, by local path (CDP
    /// `DOM.setFileInputFiles`). The browser reads the file itself; no bytes
    /// cross IPC. Backs the gated `UploadFile` task step.
    UploadFile {
        element: ElementRef,
        path: String,
    },
    /// Block until a download triggered by this page completes, or `timeout`
    /// elapses, and return its suggested filename and raw bytes (CDP
    /// `Browser.downloadWillBegin`/`downloadProgress`). Backs the gated
    /// `WaitForDownload` task step.
    WaitForDownload {
        timeout: std::time::Duration,
    },
    ReadElementText {
        element: ElementRef,
    },
    /// Observe the document's load state (`document.readyState`) via a fixed,
    /// station-authored evaluation — inspect-only, never a consumer script.
    /// Backs the `WaitForLoadState` task step.
    ObserveDocument,
    /// Enumerate the page's interactive elements via a fixed, station-authored
    /// DOM read — inspect-only, never a consumer script. Returns raw JSON
    /// (`[{role, name, selector}, …]`) as an `AgentReply::ScriptValue`; the
    /// station types it into `InteractiveElement` records. Backs the
    /// `ReadInteractiveElements` task step.
    ReadInteractiveElements,
    Evaluate {
        script: String,
    },
    Navigate {
        url: String,
    },
    Capture {
        policy: CapturePolicy,
    },
    /// Install a set of cookies into the running session (CDP `Network.setCookie`).
    /// Used by the station's gated session-import flow; never derived from a
    /// consumer task step.
    SetCookies {
        cookies: Vec<CookieSpec>,
    },
    /// Enumerate the browser's open page targets (tabs/windows). Backs the
    /// ungated `ListTabs` task step.
    ListTabs,
    /// Make the target identified by `id` (from a prior `ListTabs`) the
    /// worker's active page. Backs the ungated `SwitchToTab` task step.
    SwitchToTab {
        id: String,
    },
    Restart,
    Shutdown,
}

impl AgentCommand {
    pub fn required_capability(&self) -> Capability {
        match self {
            Self::ClickAt { .. } => Capability::L1(L1Capability::Pointer),
            Self::Wheel { .. } => Capability::L1(L1Capability::Scroll),
            Self::KeyPress { .. } => Capability::L1(L1Capability::Keyboard),
            Self::ResolveElement { .. }
            | Self::ReadElementText { .. }
            | Self::ObserveDocument
            | Self::ReadInteractiveElements => Capability::L2(L2Capability::Inspect),
            Self::ClickElement { .. }
            | Self::TypeElement { .. }
            | Self::SelectOption { .. }
            | Self::UploadFile { .. } => Capability::L2(L2Capability::Interact),
            Self::Evaluate { .. } => Capability::L2(L2Capability::Evaluate),
            Self::Navigate { .. } => Capability::L3(L3Capability::Navigate),
            Self::Capture { .. } | Self::WaitForDownload { .. } => {
                Capability::L3(L3Capability::Capture)
            }
            Self::SetCookies { .. } => Capability::L2(L2Capability::Interact),
            Self::ListTabs => Capability::L2(L2Capability::Inspect),
            Self::SwitchToTab { .. } | Self::Restart | Self::Shutdown => {
                Capability::L3(L3Capability::Lifecycle)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentReply {
    Acknowledged,
    Element(ElementRef),
    Text(String),
    ScriptValue(serde_json::Value),
    Capture(CaptureArtifact),
    /// Result of `WaitForDownload`: the captured download's suggested
    /// filename and raw bytes.
    Download {
        suggested_filename: String,
        bytes: Vec<u8>,
    },
    /// Result of `ListTabs`: the browser's open page targets.
    Tabs(Vec<TabInfo>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerLifecycle {
    Starting,
    Ready,
    Restarting,
    Degraded,
    ShuttingDown,
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeFailureKind {
    Identity,
    Launch,
    Navigation,
    Interaction,
    ObservationMissing,
    Capture,
    Protocol,
    Timeout,
    Shutdown,
}

/// Sanitized state published over `watch`.
///
/// It intentionally contains neither profile paths nor captured content, cookie values,
/// raw URLs, or backend error strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserSnapshot {
    pub identity_id: String,
    pub lifecycle: WorkerLifecycle,
    pub page_epoch: u64,
    pub current_origin: Option<String>,
    pub restart_count: u64,
    pub last_failure: Option<RuntimeFailureKind>,
}

impl BrowserSnapshot {
    pub(crate) fn starting(identity_id: String) -> Self {
        Self {
            identity_id,
            lifecycle: WorkerLifecycle::Starting,
            page_epoch: 0,
            current_origin: None,
            restart_count: 0,
            last_failure: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractError {
    TooManyCapabilities { maximum: usize, actual: usize },
    DuplicateCapability,
    InvalidSelector,
}

impl fmt::Display for ContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyCapabilities { maximum, actual } => write!(
                formatter,
                "capability set contains {actual} entries; maximum is {maximum}"
            ),
            Self::DuplicateCapability => write!(formatter, "capability set contains duplicates"),
            Self::InvalidSelector => write!(formatter, "selector must contain 1 to 4096 bytes"),
        }
    }
}

impl std::error::Error for ContractError {}

pub(crate) fn validate_selector(selector: &str) -> Result<(), ContractError> {
    if selector.is_empty() || selector.len() > 4096 || selector.contains('\0') {
        return Err(ContractError::InvalidSelector);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_set_is_bounded_and_duplicate_free() {
        let duplicate = CapabilitySet::new([
            Capability::L3(L3Capability::Navigate),
            Capability::L3(L3Capability::Navigate),
        ]);
        assert_eq!(duplicate.unwrap_err(), ContractError::DuplicateCapability);

        let too_many = CapabilitySet::new(std::iter::repeat_n(
            Capability::L3(L3Capability::Navigate),
            MAX_CAPABILITIES + 1,
        ));
        assert!(matches!(
            too_many,
            Err(ContractError::TooManyCapabilities { .. })
        ));
    }

    #[test]
    fn element_reference_rejects_unbounded_selector() {
        assert!(ElementRef::new("", 1).is_err());
        assert!(ElementRef::new("a".repeat(4097), 1).is_err());
        assert!(ElementRef::new("#submit", 1).is_ok());
    }
}
