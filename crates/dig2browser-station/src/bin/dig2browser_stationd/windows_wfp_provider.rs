//! Windows WFP adapter for the station daemon's neutral containment request.
//!
//! This module owns only the OS containment lease and runtime mirror. HTTP,
//! route selection, navigation policy and browser-worker lifecycle remain in
//! the station daemon.

use std::net::{SocketAddr, SocketAddrV4};
use std::path::Path;
use std::time::Duration;

use dig2browser::{
    BrowserProcessIsolation, WindowsBrowserRuntimeMirror, WindowsRuntimeMirrorError,
    WindowsRuntimeMirrorScope,
};
use dig2browser_station::containment::{
    ContainmentAssurance, ContainmentContractError, ContainmentRequest,
    ContainmentRequirement, NetworkCoverage, NetworkPolicy, NetworkProtocol,
    NetworkSubjectScope, ProviderCrashBehavior,
};
use dig2browser_station::windows_wfp_broker::{
    acquire_windows_wfp_lease, BrokerBrowser, WindowsWfpBrokerCapability,
    WindowsWfpBrokerError, WindowsWfpLease, WindowsWfpLeaseLoss,
};

pub(super) struct WindowsWfpProvider {
    broker_pipe: String,
    browser: BrokerBrowser,
    mirror_scope: WindowsRuntimeMirrorScope,
    capability: WindowsWfpBrokerCapability,
}

impl WindowsWfpProvider {
    pub(super) fn new(
        broker_pipe: String,
        browser: BrokerBrowser,
        profiles_root: &Path,
        capability: WindowsWfpBrokerCapability,
    ) -> Self {
        Self {
            broker_pipe,
            browser,
            mirror_scope: WindowsRuntimeMirrorScope::for_profiles_root(profiles_root),
            capability,
        }
    }

    pub(super) async fn acquire(
        self,
        request: &ContainmentRequest,
    ) -> Result<WindowsWfpContainment, WindowsWfpProviderError> {
        let proxy = validate_request(request)?;
        let assurance = request.require_assurance(windows_wfp_assurance())?;
        let acquisition = acquire_windows_wfp_lease(
            &self.broker_pipe,
            self.browser,
            self.mirror_scope,
            proxy,
            self.capability,
        )
        .await?;
        let (lease, mirror) = acquisition.into_parts();
        Ok(WindowsWfpContainment {
            lease,
            mirror,
            assurance,
        })
    }
}

pub(super) struct WindowsWfpContainment {
    lease: WindowsWfpLease,
    mirror: WindowsBrowserRuntimeMirror,
    assurance: ContainmentAssurance,
}

impl WindowsWfpContainment {
    const MIRROR_REMOVAL_MAX_WAIT: Duration = Duration::from_secs(15);

    pub(super) fn process_isolation(&self) -> BrowserProcessIsolation {
        BrowserProcessIsolation::WindowsRuntimeMirror(
            self.mirror.browser_binary().clone(),
        )
    }

    pub(super) fn assurance(&self) -> ContainmentAssurance {
        self.assurance
    }

    pub(super) async fn wait_for_unexpected_loss(&self) -> WindowsWfpLeaseLoss {
        self.lease.wait_for_unexpected_loss().await
    }

    pub(super) async fn close(self) -> Result<(), WindowsWfpProviderError> {
        let Self {
            lease,
            mirror,
            assurance: _,
        } = self;
        // Keep WFP active until no process can still hold the exact AppID
        // runtime tree. Dropping a lease does not authorize policy removal, so
        // any mirror cleanup failure remains fail-closed for reconciliation.
        mirror
            .remove_with_retry(Self::MIRROR_REMOVAL_MAX_WAIT)
            .await?;
        lease.close().await?;
        Ok(())
    }
}

fn validate_request(
    request: &ContainmentRequest,
) -> Result<SocketAddrV4, WindowsWfpProviderError> {
    if request.requirement() != ContainmentRequirement::Required {
        return Err(WindowsWfpProviderError::UnsupportedRequest(
            "Windows WFP provider requires mandatory containment",
        ));
    }
    let permits = match request.policy() {
        NetworkPolicy::DenyByDefault { permits } => permits,
        NetworkPolicy::Disabled => {
            return Err(WindowsWfpProviderError::UnsupportedRequest(
                "Windows WFP provider requires a deny-by-default policy",
            ));
        }
    };
    let [permit] = permits.as_slice() else {
        return Err(WindowsWfpProviderError::UnsupportedRequest(
            "Windows WFP provider supports exactly one proxy permit",
        ));
    };
    if permit.protocol() != NetworkProtocol::Tcp {
        return Err(WindowsWfpProviderError::UnsupportedRequest(
            "Windows WFP provider supports only a TCP proxy permit",
        ));
    }
    let SocketAddr::V4(proxy) = permit.peer() else {
        return Err(WindowsWfpProviderError::UnsupportedRequest(
            "Windows WFP provider requires an IPv4 proxy endpoint",
        ));
    };
    if !proxy.ip().is_loopback() {
        return Err(WindowsWfpProviderError::UnsupportedRequest(
            "Windows WFP provider requires a loopback proxy endpoint",
        ));
    }
    Ok(proxy)
}

fn windows_wfp_assurance() -> ContainmentAssurance {
    ContainmentAssurance {
        subject_scope: NetworkSubjectScope::KnownExecutableSet,
        station_instance_exclusive: true,
        coverage: NetworkCoverage {
            raw_ip: true,
            ..NetworkCoverage::attributed_inet()
        },
        provider_crash: ProviderCrashBehavior::EnforcementRetained,
    }
}

#[derive(Debug, thiserror::Error)]
pub(super) enum WindowsWfpProviderError {
    #[error("unsupported Windows WFP containment request: {0}")]
    UnsupportedRequest(&'static str),
    #[error(transparent)]
    Contract(#[from] ContainmentContractError),
    #[error(transparent)]
    Broker(#[from] WindowsWfpBrokerError),
    #[error(transparent)]
    Mirror(#[from] WindowsRuntimeMirrorError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig2browser_station::containment::{
        ContainmentRequirements, NetworkPermit,
    };

    fn requirements() -> ContainmentRequirements {
        ContainmentRequirements {
            required_subject_scope: NetworkSubjectScope::KnownExecutableSet,
            require_station_instance_exclusive: true,
            coverage: NetworkCoverage::attributed_inet(),
            retain_on_provider_crash: true,
        }
    }

    fn request(
        permits: impl IntoIterator<Item = NetworkPermit>,
        requirements: ContainmentRequirements,
    ) -> ContainmentRequest {
        ContainmentRequest::required(
            NetworkPolicy::deny_by_default(permits).expect("valid test policy"),
            requirements,
        )
        .expect("valid required request")
    }

    fn permit(protocol: NetworkProtocol, peer: &str) -> NetworkPermit {
        NetworkPermit::new(protocol, peer.parse().expect("test peer"))
            .expect("valid test permit")
    }

    #[test]
    fn single_loopback_tcp_permit_maps_to_wfp_proxy() {
        let request = request(
            [permit(NetworkProtocol::Tcp, "127.0.0.1:18080")],
            requirements(),
        );

        assert_eq!(
            validate_request(&request).expect("supported request"),
            "127.0.0.1:18080".parse::<SocketAddrV4>().unwrap()
        );
        assert_eq!(
            request
                .require_assurance(windows_wfp_assurance())
                .expect("sufficient WFP assurance"),
            windows_wfp_assurance()
        );
    }

    #[test]
    fn unsupported_policy_forms_fail_before_broker_acquisition() {
        assert!(matches!(
            validate_request(&ContainmentRequest::disabled()),
            Err(WindowsWfpProviderError::UnsupportedRequest(_))
        ));

        for permits in [
            Vec::new(),
            vec![
                permit(NetworkProtocol::Tcp, "127.0.0.1:18080"),
                permit(NetworkProtocol::Tcp, "127.0.0.1:18081"),
            ],
            vec![permit(NetworkProtocol::Udp, "127.0.0.1:18080")],
            vec![permit(NetworkProtocol::Tcp, "[::1]:18080")],
            vec![permit(NetworkProtocol::Tcp, "192.0.2.1:18080")],
        ] {
            assert!(matches!(
                validate_request(&request(permits, requirements())),
                Err(WindowsWfpProviderError::UnsupportedRequest(_))
            ));
        }
    }

    #[test]
    fn fixed_wfp_assurance_is_checked_before_broker_acquisition() {
        let mut incompatible = requirements();
        incompatible.required_subject_scope =
            NetworkSubjectScope::SignedApplicationAndHelpers;
        let incompatible_request = request(
            [permit(NetworkProtocol::Tcp, "127.0.0.1:18080")],
            incompatible,
        );

        assert!(matches!(
            incompatible_request.require_assurance(windows_wfp_assurance()),
            Err(ContainmentContractError::InsufficientAssurance)
        ));

        let mut resolver_required = requirements();
        resolver_required.coverage.system_name_resolution = true;
        let request = request(
            [permit(NetworkProtocol::Tcp, "127.0.0.1:18080")],
            resolver_required,
        );
        assert!(matches!(
            request.require_assurance(windows_wfp_assurance()),
            Err(ContainmentContractError::InsufficientAssurance)
        ));
    }
}
