//! Hand-written typed helpers for the CDP domains used by dig2browser.

pub mod emulation;
pub mod fetch;
pub mod log;
pub mod network;
pub mod page;
pub mod runtime;
pub mod security;
pub mod target;

pub use fetch::RequestPattern;
pub use network::CdpCookie;
pub use target::TargetInfo;
