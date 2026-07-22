//! Platform-neutral network containment contract.
//!
//! Route selection tells a browser which transport to use. Containment is a
//! separate deny-by-default boundary that limits which network peers the
//! selected operating-system subject may reach.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

const MAX_NETWORK_PERMITS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainmentRequirement {
    Disabled,
    Required,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetworkProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NetworkPermit {
    protocol: NetworkProtocol,
    peer: SocketAddr,
}

impl NetworkPermit {
    pub fn new(
        protocol: NetworkProtocol,
        peer: SocketAddr,
    ) -> Result<Self, ContainmentContractError> {
        if peer.port() == 0
            || peer.ip().is_unspecified()
            || peer.ip().is_multicast()
            || peer.ip() == IpAddr::V4(Ipv4Addr::BROADCAST)
        {
            return Err(ContainmentContractError::InvalidPeer);
        }
        Ok(Self { protocol, peer })
    }

    pub fn protocol(&self) -> NetworkProtocol {
        self.protocol
    }

    pub fn peer(&self) -> SocketAddr {
        self.peer
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkPolicy {
    Disabled,
    DenyByDefault { permits: Vec<NetworkPermit> },
}

impl NetworkPolicy {
    pub fn deny_by_default(
        permits: impl IntoIterator<Item = NetworkPermit>,
    ) -> Result<Self, ContainmentContractError> {
        let permits = permits.into_iter().collect::<Vec<_>>();
        if permits.len() > MAX_NETWORK_PERMITS {
            return Err(ContainmentContractError::TooManyPermits);
        }
        let unique = permits.iter().copied().collect::<HashSet<_>>();
        if unique.len() != permits.len() {
            return Err(ContainmentContractError::DuplicatePermit);
        }
        Ok(Self::DenyByDefault { permits })
    }

    pub fn permits(&self) -> &[NetworkPermit] {
        match self {
            Self::Disabled => &[],
            Self::DenyByDefault { permits } => permits,
        }
    }

    pub fn is_deny_by_default(&self) -> bool {
        matches!(self, Self::DenyByDefault { .. })
    }
}

/// The operating-system identity to which a network policy is actually bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkSubjectScope {
    /// A finite, validated inventory of executable identities.
    KnownExecutableSet,
    /// One signed application and helper tools attributed to that application.
    SignedApplicationAndHelpers,
    /// Every process that remains in an inherited operating-system boundary.
    InheritedProcessTree,
}

impl NetworkSubjectScope {
    pub fn covers(self, required: Self) -> bool {
        self == required
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkCoverage {
    pub tcp: bool,
    pub udp: bool,
    /// Raw IP sockets attributed to the contained subject are denied too.
    pub raw_ip: bool,
    /// Name resolution cannot escape through an out-of-scope OS resolver.
    pub system_name_resolution: bool,
    pub ipv4: bool,
    pub ipv6: bool,
}

impl NetworkCoverage {
    /// All ordinary IP sockets attributed to the selected OS subject.
    ///
    /// This intentionally does not claim control over delegated OS name
    /// resolution or raw sockets.
    pub const fn attributed_inet() -> Self {
        Self {
            tcp: true,
            udp: true,
            raw_ip: false,
            system_name_resolution: false,
            ipv4: true,
            ipv6: true,
        }
    }

    pub fn covers(self, required: Self) -> bool {
        (!required.tcp || self.tcp)
            && (!required.udp || self.udp)
            && (!required.raw_ip || self.raw_ip)
            && (!required.system_name_resolution || self.system_name_resolution)
            && (!required.ipv4 || self.ipv4)
            && (!required.ipv6 || self.ipv6)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderCrashBehavior {
    /// Losing the userspace provider or broker also removes enforcement.
    EnforcementLost,
    /// Enforcement survives loss of the userspace provider or broker.
    ///
    /// This does not imply survival across OS network-service restart or reboot.
    EnforcementRetained,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContainmentAssurance {
    pub subject_scope: NetworkSubjectScope,
    pub station_instance_exclusive: bool,
    pub coverage: NetworkCoverage,
    pub provider_crash: ProviderCrashBehavior,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContainmentRequirements {
    pub required_subject_scope: NetworkSubjectScope,
    pub require_station_instance_exclusive: bool,
    pub coverage: NetworkCoverage,
    pub retain_on_provider_crash: bool,
}

impl ContainmentRequirements {
    pub fn accepts(self, assurance: ContainmentAssurance) -> bool {
        assurance.subject_scope.covers(self.required_subject_scope)
            && (!self.require_station_instance_exclusive
                || assurance.station_instance_exclusive)
            && assurance.coverage.covers(self.coverage)
            && (!self.retain_on_provider_crash
                || assurance.provider_crash == ProviderCrashBehavior::EnforcementRetained)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainmentRequest {
    requirement: ContainmentRequirement,
    policy: NetworkPolicy,
    requirements: Option<ContainmentRequirements>,
}

impl ContainmentRequest {
    pub fn disabled() -> Self {
        Self {
            requirement: ContainmentRequirement::Disabled,
            policy: NetworkPolicy::Disabled,
            requirements: None,
        }
    }

    pub fn required(
        policy: NetworkPolicy,
        requirements: ContainmentRequirements,
    ) -> Result<Self, ContainmentContractError> {
        if !policy.is_deny_by_default() {
            return Err(ContainmentContractError::RequirementPolicyMismatch);
        }
        Ok(Self {
            requirement: ContainmentRequirement::Required,
            policy,
            requirements: Some(requirements),
        })
    }

    pub fn requirement(&self) -> ContainmentRequirement {
        self.requirement
    }

    pub fn policy(&self) -> &NetworkPolicy {
        &self.policy
    }

    pub fn requirements(&self) -> Option<ContainmentRequirements> {
        self.requirements
    }

    pub fn accepts(&self, assurance: ContainmentAssurance) -> bool {
        self.requirements
            .is_some_and(|requirements| requirements.accepts(assurance))
    }

    pub fn require_assurance(
        &self,
        assurance: ContainmentAssurance,
    ) -> Result<ContainmentAssurance, ContainmentContractError> {
        if self.accepts(assurance) {
            Ok(assurance)
        } else {
            Err(ContainmentContractError::InsufficientAssurance)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainmentState {
    Requested,
    Prepared,
    Active,
    Draining,
    Lost,
    Released,
}

impl ContainmentState {
    pub fn may_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Requested, Self::Prepared)
                | (Self::Prepared, Self::Active)
                | (Self::Prepared, Self::Released)
                | (Self::Active, Self::Draining)
                | (Self::Active, Self::Lost)
                | (Self::Draining, Self::Lost)
                | (Self::Draining, Self::Released)
                | (Self::Lost, Self::Released)
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ContainmentContractError {
    #[error("network permit requires a concrete unicast peer and nonzero port")]
    InvalidPeer,
    #[error("network containment policy has too many permits")]
    TooManyPermits,
    #[error("network containment policy contains a duplicate permit")]
    DuplicatePermit,
    #[error("required containment needs a deny-by-default network policy")]
    RequirementPolicyMismatch,
    #[error("containment provider does not meet the requested assurance")]
    InsufficientAssurance,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loopback_tcp() -> NetworkPermit {
        NetworkPermit::new(
            NetworkProtocol::Tcp,
            "127.0.0.1:18080".parse().unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn deny_by_default_policy_rejects_duplicate_permits() {
        let permit = loopback_tcp();
        assert_eq!(
            NetworkPolicy::deny_by_default([permit, permit]),
            Err(ContainmentContractError::DuplicatePermit)
        );
    }

    #[test]
    fn subject_scopes_are_incomparable() {
        let scopes = [
            NetworkSubjectScope::KnownExecutableSet,
            NetworkSubjectScope::SignedApplicationAndHelpers,
            NetworkSubjectScope::InheritedProcessTree,
        ];
        for actual in scopes {
            for required in scopes {
                assert_eq!(actual.covers(required), actual == required);
            }
        }
    }

    #[test]
    fn required_request_rejects_crash_volatile_assurance() {
        let request = ContainmentRequest::required(
            NetworkPolicy::deny_by_default([loopback_tcp()]).unwrap(),
            ContainmentRequirements {
                required_subject_scope: NetworkSubjectScope::KnownExecutableSet,
                require_station_instance_exclusive: true,
                coverage: NetworkCoverage::attributed_inet(),
                retain_on_provider_crash: true,
            },
        )
        .unwrap();
        let volatile = ContainmentAssurance {
            subject_scope: NetworkSubjectScope::KnownExecutableSet,
            station_instance_exclusive: true,
            coverage: NetworkCoverage::attributed_inet(),
            provider_crash: ProviderCrashBehavior::EnforcementLost,
        };
        let retained = ContainmentAssurance {
            provider_crash: ProviderCrashBehavior::EnforcementRetained,
            ..volatile
        };

        assert_eq!(
            request.require_assurance(volatile),
            Err(ContainmentContractError::InsufficientAssurance)
        );
        assert_eq!(request.require_assurance(retained), Ok(retained));
    }

    #[test]
    fn required_request_rejects_nonexclusive_subject_assurance() {
        let request = ContainmentRequest::required(
            NetworkPolicy::deny_by_default([loopback_tcp()]).unwrap(),
            ContainmentRequirements {
                required_subject_scope: NetworkSubjectScope::SignedApplicationAndHelpers,
                require_station_instance_exclusive: true,
                coverage: NetworkCoverage::attributed_inet(),
                retain_on_provider_crash: true,
            },
        )
        .unwrap();
        let shared_identity = ContainmentAssurance {
            subject_scope: NetworkSubjectScope::SignedApplicationAndHelpers,
            station_instance_exclusive: false,
            coverage: NetworkCoverage::attributed_inet(),
            provider_crash: ProviderCrashBehavior::EnforcementRetained,
        };

        assert_eq!(
            request.require_assurance(shared_identity),
            Err(ContainmentContractError::InsufficientAssurance)
        );
    }

    #[test]
    fn containment_state_rejects_reactivation_after_loss() {
        assert!(ContainmentState::Active.may_transition_to(ContainmentState::Lost));
        assert!(!ContainmentState::Lost.may_transition_to(ContainmentState::Active));
        assert!(ContainmentState::Lost.may_transition_to(ContainmentState::Released));
    }
}
