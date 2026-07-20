//! Capability-gated, single-owner browser workers for agent control.

mod contract;
mod mobile;
mod navigation;
mod runtime;
mod worker;

pub use contract::{
    AgentCommand, AgentReply, BrowserSnapshot, Capability, CapabilitySet, CaptureArtifact,
    CapturePolicy, ContractError, DocumentState, ElementRef, L1Capability, L2Capability,
    L3Capability, RuntimeFailureKind, WorkerLifecycle, MAX_CAPABILITIES,
};
pub use mobile::{MobileLayout, MobileLayoutError};
pub use navigation::{
    NavigationPolicy, NavigationPolicyError, NavigationTarget, MAX_ALLOWED_ORIGINS,
};
pub use runtime::{BrowserRuntime, RealBrowserRuntime, RuntimeError, RuntimeResult};
pub use worker::{BrowserWorker, BrowserWorkerConfig, WorkerError};
