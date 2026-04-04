//! Hand-written typed helpers for the CDP domains used by dig2browser.

pub mod dom;
pub mod emulation;
pub mod fetch;
pub mod input;
pub mod log;
pub mod network;
pub mod page;
pub mod runtime;
pub mod security;
pub mod target;

pub use dom::{BoxModel, DomNode};
pub use emulation::MediaFeature;
pub use fetch::{HeaderEntry, RequestPattern};
pub use input::TouchPoint;
pub use network::CdpCookie;
pub use page::{PrintToPdfOptions, Viewport};
pub use target::TargetInfo;
