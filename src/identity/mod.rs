//! Stable browser identities and exclusive persistent-profile ownership.

mod lock;
mod profile;

pub use lock::ProfileOwnershipGuard;
pub use profile::{
    validate_profile_id, BrowserBackend, DevicePersona, IdentityClass, IdentityError,
    IdentityProfile,
};
