use std::collections::HashMap;

use dig2browser::agentic::BrowserWorkerConfig;
use dig2browser_core::RouteRef;

/// The browser-visible transport selected for one non-secret route reference.
///
/// `HostDirect` means Chromium is forced to use the host network stack without
/// a browser-configured proxy. It does not claim a particular public IP, DNS
/// path, ASN, VPN state, or physical location.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteTransport {
    HostDirect,
}

/// Station-owned resolution of an opaque route reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteDescriptor {
    reference: RouteRef,
    transport: RouteTransport,
}

impl RouteDescriptor {
    pub fn host_direct(reference: RouteRef) -> Self {
        Self {
            reference,
            transport: RouteTransport::HostDirect,
        }
    }

    pub fn reference(&self) -> &RouteRef {
        &self.reference
    }

    pub fn transport(&self) -> RouteTransport {
        self.transport
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
        if worker
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
                worker.launch.extra_args.push("--no-proxy-server".to_owned());
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_direct_is_resolved_and_forces_browser_proxy_off() {
        let registry = RouteRegistry::host_direct_only();
        let mut worker = BrowserWorkerConfig::default();
        let route = registry
            .prepare(&RouteRef::host_direct(), &worker)
            .expect("resolve host-direct");

        route.apply(&mut worker);

        assert!(worker
            .launch
            .extra_args
            .iter()
            .any(|argument| argument == "--no-proxy-server"));
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
    fn unknown_route_fails_before_runtime_launch() {
        let registry = RouteRegistry::host_direct_only();
        let reference = RouteRef::new("unconfigured-route").expect("valid route reference");

        assert_eq!(
            registry.prepare(&reference, &BrowserWorkerConfig::default()),
            Err(RouteRegistryError::UnknownRoute)
        );
    }
}
