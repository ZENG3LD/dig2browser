use std::collections::HashMap;
use std::net::SocketAddr;

use dig2browser::agentic::BrowserWorkerConfig;
use dig2browser::BrowserProxy;
use dig2browser_core::RouteRef;

/// The browser-visible transport selected for one non-secret route reference.
///
/// `HostDirect` means the selected browser uses the host network stack without
/// a browser-configured proxy. It does not claim a particular public IP, DNS
/// path, ASN, VPN state, or physical location.
/// External transports configure one station-selected browser proxy endpoint;
/// they do not add process-level network containment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteTransport {
    HostDirect,
    ExternalHttp(SocketAddr),
    ExternalSocks5(SocketAddr),
}

/// Station-owned resolution of an opaque route reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteDescriptor {
    reference: RouteRef,
    transport: RouteTransport,
    egress_proxy: Option<SocketAddr>,
}

impl RouteDescriptor {
    pub fn host_direct(reference: RouteRef) -> Self {
        Self {
            reference,
            transport: RouteTransport::HostDirect,
            egress_proxy: None,
        }
    }

    pub fn guarded_host_direct(
        reference: RouteRef,
        egress_proxy: SocketAddr,
    ) -> Result<Self, EgressRouteError> {
        if !egress_proxy.ip().is_loopback() || egress_proxy.port() == 0 {
            return Err(EgressRouteError::InvalidEgressProxy);
        }
        Ok(Self {
            reference,
            transport: RouteTransport::HostDirect,
            egress_proxy: Some(egress_proxy),
        })
    }

    pub fn external_http(
        reference: RouteRef,
        proxy: SocketAddr,
    ) -> Result<Self, EgressRouteError> {
        Self::external_proxy(reference, RouteTransport::ExternalHttp(proxy), proxy)
    }

    pub fn external_socks5(
        reference: RouteRef,
        proxy: SocketAddr,
    ) -> Result<Self, EgressRouteError> {
        Self::external_proxy(reference, RouteTransport::ExternalSocks5(proxy), proxy)
    }

    fn external_proxy(
        reference: RouteRef,
        transport: RouteTransport,
        proxy: SocketAddr,
    ) -> Result<Self, EgressRouteError> {
        if proxy.port() == 0 || proxy.ip().is_unspecified() || proxy.ip().is_multicast() {
            return Err(EgressRouteError::InvalidExternalProxy);
        }
        Ok(Self {
            reference,
            transport,
            egress_proxy: None,
        })
    }

    pub fn reference(&self) -> &RouteRef {
        &self.reference
    }

    pub fn transport(&self) -> RouteTransport {
        self.transport
    }

    pub fn is_egress_guarded(&self) -> bool {
        self.egress_proxy.is_some()
    }
}

/// Trusted station catalog. Consumers carry only an opaque reference; proxy
/// endpoints and credentials never cross the browser IPC contract.
#[derive(Debug, Clone)]
pub struct RouteRegistry {
    routes: HashMap<RouteRef, RouteDescriptor>,
}

impl RouteRegistry {
    pub fn empty() -> Self {
        Self {
            routes: HashMap::new(),
        }
    }

    pub fn host_direct_only() -> Self {
        let mut registry = Self::empty();
        registry
            .register(RouteDescriptor::host_direct(RouteRef::host_direct()))
            .expect("built-in host-direct route reference must be unique");
        registry
    }

    pub fn register(
        &mut self,
        descriptor: RouteDescriptor,
    ) -> Result<(), RouteRegistryError> {
        if self.routes.contains_key(descriptor.reference()) {
            return Err(RouteRegistryError::DuplicateRoute);
        }
        self.routes.insert(descriptor.reference.clone(), descriptor);
        Ok(())
    }

    pub(crate) fn prepare(
        &self,
        reference: &RouteRef,
        worker: &BrowserWorkerConfig,
    ) -> Result<PreparedRoute, RouteRegistryError> {
        let descriptor = self
            .routes
            .get(reference)
            .cloned()
            .ok_or(RouteRegistryError::UnknownRoute)?;
        PreparedRoute::new(descriptor, worker)
    }
}

impl Default for RouteRegistry {
    fn default() -> Self {
        Self::host_direct_only()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PreparedRoute {
    descriptor: RouteDescriptor,
}

impl PreparedRoute {
    fn new(
        descriptor: RouteDescriptor,
        worker: &BrowserWorkerConfig,
    ) -> Result<Self, RouteRegistryError> {
        if worker.launch.browser_proxy.is_some()
            || worker
                .launch
                .extra_args
                .iter()
                .any(|argument| route_owned_argument(argument))
        {
            return Err(RouteRegistryError::ConflictingLaunchArgument);
        }
        Ok(Self { descriptor })
    }

    pub(crate) fn apply(&self, worker: &mut BrowserWorkerConfig) {
        match self.descriptor.transport {
            RouteTransport::HostDirect => {
                if self.descriptor.egress_proxy.is_none() {
                    worker.launch.browser_proxy = Some(BrowserProxy::Direct);
                }
            }
            RouteTransport::ExternalHttp(proxy) => {
                worker.launch.browser_proxy = Some(BrowserProxy::Http(proxy));
            }
            RouteTransport::ExternalSocks5(proxy) => {
                worker.launch.browser_proxy = Some(BrowserProxy::Socks5(proxy));
            }
        }
    }

    pub(crate) fn egress_proxy(&self) -> Option<SocketAddr> {
        self.descriptor.egress_proxy
    }
}

fn route_owned_argument(argument: &str) -> bool {
    let name = argument
        .split_once('=')
        .map_or(argument, |(name, _)| name)
        .to_ascii_lowercase();
    matches!(
        name.as_str(),
        "--proxy-server"
            | "--proxy-pac-url"
            | "--proxy-auto-detect"
            | "--proxy-bypass-list"
            | "--no-proxy-server"
            | "--host-resolver-rules"
            | "--host-rules"
            | "--enable-quic"
            | "--disable-quic"
            | "--force-webrtc-ip-handling-policy"
            | "--webrtc-ip-handling-policy"
            | "--load-extension"
            | "--disable-extensions-except"
            | "--disable-extensions"
            | "--enable-extensions"
            | "--disable-background-networking"
            | "--enable-background-networking"
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RouteRegistryError {
    #[error("route reference is already registered")]
    DuplicateRoute,
    #[error("route reference is not configured by this station")]
    UnknownRoute,
    #[error("worker launch arguments conflict with station-owned route policy")]
    ConflictingLaunchArgument,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EgressRouteError {
    #[error("station egress proxy must be a bound loopback endpoint")]
    InvalidEgressProxy,
    #[error("external route proxy must be a usable IP endpoint")]
    InvalidExternalProxy,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_direct_is_resolved_to_typed_direct_proxy_policy() {
        let registry = RouteRegistry::host_direct_only();
        let mut worker = BrowserWorkerConfig::default();
        let route = registry
            .prepare(&RouteRef::host_direct(), &worker)
            .expect("resolve host-direct");

        route.apply(&mut worker);

        assert_eq!(worker.launch.browser_proxy, Some(BrowserProxy::Direct));
    }

    #[test]
    fn guarded_host_direct_reserves_proxy_ownership_for_runtime() {
        let endpoint: SocketAddr = "127.0.0.1:18080".parse().expect("proxy endpoint");
        let mut registry = RouteRegistry::empty();
        registry
            .register(
                RouteDescriptor::guarded_host_direct(RouteRef::host_direct(), endpoint)
                    .expect("guarded route"),
            )
            .expect("register guarded route");
        let mut worker = BrowserWorkerConfig::default();
        let route = registry
            .prepare(&RouteRef::host_direct(), &worker)
            .expect("prepare guarded route");

        route.apply(&mut worker);

        assert_eq!(route.egress_proxy(), Some(endpoint));
        assert_eq!(worker.launch.browser_proxy, None);
    }

    #[test]
    fn guarded_host_direct_rejects_non_loopback_proxy() {
        let endpoint: SocketAddr = "192.0.2.1:18080".parse().expect("proxy endpoint");
        assert_eq!(
            RouteDescriptor::guarded_host_direct(RouteRef::host_direct(), endpoint),
            Err(EgressRouteError::InvalidEgressProxy)
        );
    }

    #[test]
    fn route_policy_rejects_unowned_proxy_configuration() {
        let registry = RouteRegistry::host_direct_only();
        let mut worker = BrowserWorkerConfig::default();
        worker
            .launch
            .extra_args
            .push("--proxy-server=http://127.0.0.1:8080".to_owned());

        assert_eq!(
            registry.prepare(&RouteRef::host_direct(), &worker),
            Err(RouteRegistryError::ConflictingLaunchArgument)
        );
    }

    #[test]
    fn route_policy_rejects_consumer_typed_proxy_configuration() {
        let registry = RouteRegistry::host_direct_only();
        let mut worker = BrowserWorkerConfig::default();
        worker.launch.browser_proxy = Some(BrowserProxy::Http(
            "127.0.0.1:8080".parse().expect("proxy endpoint"),
        ));

        assert_eq!(
            registry.prepare(&RouteRef::host_direct(), &worker),
            Err(RouteRegistryError::ConflictingLaunchArgument)
        );
    }

    #[test]
    fn external_routes_apply_typed_browser_proxy_policy() {
        let http_endpoint = "192.0.2.10:8080".parse().expect("HTTP proxy endpoint");
        let socks_endpoint = "198.51.100.20:1080"
            .parse()
            .expect("SOCKS5 proxy endpoint");
        for (descriptor, expected) in [
            (
                RouteDescriptor::external_http(
                    RouteRef::new("external.http").expect("HTTP route reference"),
                    http_endpoint,
                )
                .expect("HTTP route"),
                BrowserProxy::Http(http_endpoint),
            ),
            (
                RouteDescriptor::external_socks5(
                    RouteRef::new("external.socks5").expect("SOCKS5 route reference"),
                    socks_endpoint,
                )
                .expect("SOCKS5 route"),
                BrowserProxy::Socks5(socks_endpoint),
            ),
        ] {
            let reference = descriptor.reference().clone();
            let mut registry = RouteRegistry::empty();
            registry.register(descriptor).expect("register route");
            let mut worker = BrowserWorkerConfig::default();
            let prepared = registry.prepare(&reference, &worker).expect("prepare route");

            prepared.apply(&mut worker);

            assert_eq!(worker.launch.browser_proxy, Some(expected));
            assert_eq!(prepared.egress_proxy(), None);
        }
    }

    #[test]
    fn external_routes_reject_unusable_proxy_endpoints() {
        for endpoint in ["0.0.0.0:8080", "224.0.0.1:8080", "127.0.0.1:0"] {
            let endpoint = endpoint.parse().expect("socket endpoint");
            assert_eq!(
                RouteDescriptor::external_http(RouteRef::host_direct(), endpoint),
                Err(EgressRouteError::InvalidExternalProxy)
            );
            assert_eq!(
                RouteDescriptor::external_socks5(RouteRef::host_direct(), endpoint),
                Err(EgressRouteError::InvalidExternalProxy)
            );
        }
    }

    #[test]
    fn route_policy_rejects_consumer_browser_escape_arguments_in_both_forms() {
        let registry = RouteRegistry::host_direct_only();
        for name in [
            "--load-extension",
            "--disable-extensions-except",
            "--disable-extensions",
            "--enable-extensions",
            "--disable-background-networking",
            "--enable-background-networking",
            "--webrtc-ip-handling-policy",
        ] {
            for arguments in [
                vec![name.to_owned(), "consumer-value".to_owned()],
                vec![format!("{name}=consumer-value")],
            ] {
                let mut worker = BrowserWorkerConfig::default();
                worker.launch.extra_args.extend(arguments);

                assert_eq!(
                    registry.prepare(&RouteRef::host_direct(), &worker),
                    Err(RouteRegistryError::ConflictingLaunchArgument),
                    "station accepted route-owned launch argument {name}"
                );
            }
        }
    }

    #[test]
    fn unknown_route_fails_before_runtime_launch() {
        let registry = RouteRegistry::host_direct_only();
        let reference = RouteRef::new("unconfigured-route").expect("valid route reference");

        assert_eq!(
            registry.prepare(&reference, &BrowserWorkerConfig::default()),
            Err(RouteRegistryError::UnknownRoute)
        );
    }
}
