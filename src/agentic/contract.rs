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
    ReadElementText {
        element: ElementRef,
    },
    Navigate {
        url: String,
    },
    Capture {
        policy: CapturePolicy,
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
            Self::ResolveElement { .. } | Self::ReadElementText { .. } => {
                Capability::L2(L2Capability::Inspect)
            }
            Self::ClickElement { .. } | Self::TypeElement { .. } => {
                Capability::L2(L2Capability::Interact)
            }
            Self::Navigate { .. } => Capability::L3(L3Capability::Navigate),
            Self::Capture { .. } => Capability::L3(L3Capability::Capture),
            Self::Restart | Self::Shutdown => Capability::L3(L3Capability::Lifecycle),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentReply {
    Acknowledged,
    Element(ElementRef),
    Text(String),
    Capture(CaptureArtifact),
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

        let too_many = CapabilitySet::new(
            std::iter::repeat(Capability::L3(L3Capability::Navigate)).take(MAX_CAPABILITIES + 1),
        );
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
