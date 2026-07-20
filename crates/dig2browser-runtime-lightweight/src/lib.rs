//! Bounded static-document runtime for station-routed monitoring and research.
//!
//! This runtime fetches one HTML document and exposes a read-only parsed DOM.
//! It deliberately has no script engine, subresource loader, layout, visual
//! rendering, cookies, browser storage, or interactive DOM.

use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use dig2browser::agentic::{
    BrowserRuntime, CaptureArtifact, CapturePolicy, DocumentState, RuntimeError,
    RuntimeFailureKind, RuntimeResult, NavigationPolicy,
};
use dig2browser::identity::{
    BrowserBackend, DevicePersona, IdentityProfile, ProfileOwnershipGuard,
};
use dig2browser_core::{
    ControlTransport, EngineFamily, FeatureSupport, RuntimeDescriptor,
    RuntimeFeature, RuntimeKind, RuntimeLimitation, SupportLevel,
};
use futures::future::BoxFuture;
use reqwest::header::CONTENT_TYPE;
use scraper::{Html, Selector};

pub const RUNTIME_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const DEFAULT_MAX_DOCUMENT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_DOCUMENT_BYTES: usize = 64 * 1024 * 1024;
pub const DEFAULT_REDIRECT_LIMIT: usize = 5;
pub const MAX_REDIRECT_LIMIT: usize = 10;
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const MAX_NETWORK_TIMEOUT: Duration = Duration::from_secs(5 * 60);
pub const DEFAULT_RESTART_AFTER_NAVIGATIONS: u32 = 100;
pub const MAX_RESTART_AFTER_NAVIGATIONS: u32 = 100_000;
pub const DEFAULT_SELECTOR_TEXT_LIMIT: usize = 64 * 1024;
pub const MAX_SELECTOR_TEXT_LIMIT: usize = 1024 * 1024;
const MAX_SELECTOR_BYTES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LightweightRuntimeConfig {
    pub max_document_bytes: usize,
    pub redirect_limit: usize,
    pub request_timeout: Duration,
    pub connect_timeout: Duration,
    pub restart_after_navigations: u32,
    pub selector_text_limit: usize,
}

impl LightweightRuntimeConfig {
    pub fn validate(&self) -> Result<(), LightweightRuntimeConfigError> {
        if !(1..=MAX_DOCUMENT_BYTES).contains(&self.max_document_bytes) {
            return Err(LightweightRuntimeConfigError::MaxDocumentBytes);
        }
        if self.redirect_limit > MAX_REDIRECT_LIMIT {
            return Err(LightweightRuntimeConfigError::RedirectLimit);
        }
        if !(Duration::from_millis(1)..=MAX_NETWORK_TIMEOUT)
            .contains(&self.request_timeout)
        {
            return Err(LightweightRuntimeConfigError::RequestTimeout);
        }
        if !(Duration::from_millis(1)..=MAX_NETWORK_TIMEOUT)
            .contains(&self.connect_timeout)
        {
            return Err(LightweightRuntimeConfigError::ConnectTimeout);
        }
        if self.connect_timeout > self.request_timeout {
            return Err(LightweightRuntimeConfigError::ConnectExceedsRequest);
        }
        if self.restart_after_navigations > MAX_RESTART_AFTER_NAVIGATIONS {
            return Err(LightweightRuntimeConfigError::RestartAfterNavigations);
        }
        if !(1..=MAX_SELECTOR_TEXT_LIMIT).contains(&self.selector_text_limit) {
            return Err(LightweightRuntimeConfigError::SelectorTextLimit);
        }
        Ok(())
    }
}

impl Default for LightweightRuntimeConfig {
    fn default() -> Self {
        Self {
            max_document_bytes: DEFAULT_MAX_DOCUMENT_BYTES,
            redirect_limit: DEFAULT_REDIRECT_LIMIT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            restart_after_navigations: DEFAULT_RESTART_AFTER_NAVIGATIONS,
            selector_text_limit: DEFAULT_SELECTOR_TEXT_LIMIT,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LightweightRuntimeConfigError {
    MaxDocumentBytes,
    RedirectLimit,
    RequestTimeout,
    ConnectTimeout,
    ConnectExceedsRequest,
    RestartAfterNavigations,
    SelectorTextLimit,
}

impl fmt::Display for LightweightRuntimeConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::MaxDocumentBytes => "max document bytes must be within the supported bound",
            Self::RedirectLimit => "redirect limit exceeds the supported bound",
            Self::RequestTimeout => "request timeout must be within the supported bound",
            Self::ConnectTimeout => "connect timeout must be within the supported bound",
            Self::ConnectExceedsRequest => "connect timeout must not exceed request timeout",
            Self::RestartAfterNavigations => {
                "restart-after-navigations exceeds the supported bound"
            }
            Self::SelectorTextLimit => "selector text limit must be within the supported bound",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for LightweightRuntimeConfigError {}

/// Read-only runtime holding exclusive ownership of its station identity.
pub struct LightweightRuntime {
    identity: IdentityProfile,
    config: LightweightRuntimeConfig,
    navigation_policy: NavigationPolicy,
    client: reqwest::Client,
    profile_owner: Option<ProfileOwnershipGuard>,
    html: Option<String>,
    document: Option<Html>,
    state: Option<DocumentState>,
    navigation_count: u32,
}

impl LightweightRuntime {
    pub fn new(
        identity: IdentityProfile,
        config: LightweightRuntimeConfig,
    ) -> RuntimeResult<Self> {
        Self::new_with_navigation_policy(identity, config, NavigationPolicy::default())
    }

    pub fn new_with_navigation_policy(
        identity: IdentityProfile,
        config: LightweightRuntimeConfig,
        navigation_policy: NavigationPolicy,
    ) -> RuntimeResult<Self> {
        Self::new_with_navigation_policy_and_proxy(
            identity,
            config,
            navigation_policy,
            None,
        )
    }

    pub fn new_with_navigation_policy_and_proxy(
        identity: IdentityProfile,
        config: LightweightRuntimeConfig,
        navigation_policy: NavigationPolicy,
        egress_proxy: Option<SocketAddr>,
    ) -> RuntimeResult<Self> {
        config
            .validate()
            .map_err(|_| RuntimeError::new(RuntimeFailureKind::Protocol))?;
        if identity.backend() != BrowserBackend::Lightweight
            || identity.device() != DevicePersona::DesktopNative
        {
            return Err(RuntimeError::new(RuntimeFailureKind::Identity));
        }

        let redirect_limit = config.redirect_limit;
        let redirect_navigation_policy = navigation_policy.clone();
        let mut client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::custom(move |attempt| {
                if attempt.previous().len() > redirect_limit {
                    attempt.error("lightweight redirect limit exceeded")
                } else if redirect_navigation_policy.allows(attempt.url().as_str()) {
                    attempt.follow()
                } else {
                    attempt.error("lightweight redirect target rejected")
                }
            }))
            .timeout(config.request_timeout)
            .connect_timeout(config.connect_timeout)
            .user_agent(format!("dig2browser-lightweight/{RUNTIME_VERSION}"));
        if let Some(endpoint) = egress_proxy {
            if !endpoint.ip().is_loopback() || endpoint.port() == 0 {
                return Err(RuntimeError::new(RuntimeFailureKind::Launch));
            }
            let proxy = reqwest::Proxy::all(format!("http://{endpoint}"))
                .map_err(|_| RuntimeError::new(RuntimeFailureKind::Launch))?;
            client = client.proxy(proxy);
        }
        let client = client
            .build()
            .map_err(|_| RuntimeError::new(RuntimeFailureKind::Launch))?;

        Ok(Self {
            identity,
            config,
            navigation_policy,
            client,
            profile_owner: None,
            html: None,
            document: None,
            state: None,
            navigation_count: 0,
        })
    }

    fn clear_document(&mut self) {
        self.html = None;
        self.document = None;
        self.state = None;
    }

    fn ensure_started(&self) -> RuntimeResult<()> {
        self.profile_owner
            .as_ref()
            .map(|_| ())
            .ok_or_else(|| RuntimeError::new(RuntimeFailureKind::Protocol))
    }

    fn document(&self) -> RuntimeResult<&Html> {
        self.ensure_started()?;
        self.document
            .as_ref()
            .ok_or_else(|| RuntimeError::new(RuntimeFailureKind::Protocol))
    }

    fn document_state(&self) -> RuntimeResult<DocumentState> {
        self.ensure_started()?;
        self.state
            .clone()
            .ok_or_else(|| RuntimeError::new(RuntimeFailureKind::Protocol))
    }

    fn parse_selector(selector: &str) -> RuntimeResult<Selector> {
        if selector.is_empty()
            || selector.len() > MAX_SELECTOR_BYTES
            || selector.contains('\0')
        {
            return Err(RuntimeError::new(RuntimeFailureKind::Interaction));
        }
        Selector::parse(selector)
            .map_err(|_| RuntimeError::new(RuntimeFailureKind::Interaction))
    }

    async fn fetch_document(
        client: reqwest::Client,
        max_document_bytes: usize,
        selector_text_limit: usize,
        navigation_policy: &NavigationPolicy,
        value: &str,
    ) -> RuntimeResult<FetchedDocument> {
        let url = reqwest::Url::parse(value)
            .map_err(|_| RuntimeError::new(RuntimeFailureKind::Navigation))?;
        if !navigation_policy.allows(url.as_str()) {
            return Err(RuntimeError::new(RuntimeFailureKind::Navigation));
        }

        let mut response = client
            .get(url)
            .send()
            .await
            .map_err(map_network_error)?;
        if response.status().is_redirection() {
            return Err(RuntimeError::new(RuntimeFailureKind::Navigation));
        }
        validate_content_type(&response)?;
        if response
            .content_length()
            .is_some_and(|length| length > max_document_bytes as u64)
        {
            return Err(RuntimeError::new(RuntimeFailureKind::Navigation));
        }

        let status = response.status().as_u16();
        let final_url = response.url().to_string();
        let mut bytes = Vec::with_capacity(
            response
                .content_length()
                .unwrap_or(0)
                .min(max_document_bytes as u64) as usize,
        );
        while let Some(chunk) = response.chunk().await.map_err(map_network_error)? {
            let next_len = bytes
                .len()
                .checked_add(chunk.len())
                .filter(|length| *length <= max_document_bytes)
                .ok_or_else(|| RuntimeError::new(RuntimeFailureKind::Navigation))?;
            bytes.reserve(next_len.saturating_sub(bytes.len()));
            bytes.extend_from_slice(&chunk);
        }
        let html = String::from_utf8(bytes)
            .map_err(|_| RuntimeError::new(RuntimeFailureKind::Navigation))?;
        let document = Html::parse_document(&html);
        let title_selector = Selector::parse("title")
            .map_err(|_| RuntimeError::new(RuntimeFailureKind::Protocol))?;
        let title = document
            .select(&title_selector)
            .next()
            .map(|element| normalize_text(element.text(), selector_text_limit))
            .transpose()
            .map_err(|_| RuntimeError::new(RuntimeFailureKind::Navigation))?
            .unwrap_or_default();
        let state = DocumentState {
            url: final_url,
            title,
            ready_state: "complete".to_owned(),
            http_status: Some(status),
        };
        Ok(FetchedDocument {
            html,
            document,
            state,
        })
    }
}

struct FetchedDocument {
    html: String,
    document: Html,
    state: DocumentState,
}

fn validate_content_type(response: &reqwest::Response) -> RuntimeResult<()> {
    let Some(value) = response.headers().get(CONTENT_TYPE) else {
        return Ok(());
    };
    let value = value
        .to_str()
        .map_err(|_| RuntimeError::new(RuntimeFailureKind::Navigation))?;
    let media_type = value.split(';').next().unwrap_or_default().trim();
    if media_type.eq_ignore_ascii_case("text/html")
        || media_type.eq_ignore_ascii_case("application/xhtml+xml")
    {
        Ok(())
    } else {
        Err(RuntimeError::new(RuntimeFailureKind::Navigation))
    }
}

fn map_network_error(error: reqwest::Error) -> RuntimeError {
    if error.is_timeout() {
        RuntimeError::new(RuntimeFailureKind::Timeout)
    } else {
        RuntimeError::new(RuntimeFailureKind::Navigation)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TextLimitExceeded;

fn normalize_text<'a>(
    parts: impl IntoIterator<Item = &'a str>,
    limit: usize,
) -> Result<String, TextLimitExceeded> {
    let mut output = String::new();
    let mut pending_space = false;
    for part in parts {
        for character in part.chars() {
            if character.is_whitespace() {
                pending_space = !output.is_empty();
                continue;
            }
            if pending_space {
                if output.len() + 1 + character.len_utf8() > limit {
                    return Err(TextLimitExceeded);
                }
                output.push(' ');
                pending_space = false;
            }
            if output.len() + character.len_utf8() > limit {
                return Err(TextLimitExceeded);
            }
            output.push(character);
        }
    }
    Ok(output)
}

impl BrowserRuntime for LightweightRuntime {
    fn start(&mut self) -> BoxFuture<'_, RuntimeResult<()>> {
        Box::pin(async move {
            if self.profile_owner.is_none() {
                self.profile_owner = Some(
                    ProfileOwnershipGuard::acquire(self.identity.profile_dir())
                        .map_err(|_| RuntimeError::new(RuntimeFailureKind::Identity))?,
                );
            }
            Ok(())
        })
    }

    fn restart(&mut self) -> BoxFuture<'_, RuntimeResult<()>> {
        Box::pin(async move {
            self.ensure_started()?;
            self.clear_document();
            self.navigation_count = 0;
            Ok(())
        })
    }

    fn close(&mut self) -> BoxFuture<'_, RuntimeResult<()>> {
        Box::pin(async move {
            self.clear_document();
            self.navigation_count = 0;
            self.profile_owner.take();
            Ok(())
        })
    }

    fn needs_restart(&self) -> bool {
        self.config.restart_after_navigations > 0
            && self.navigation_count >= self.config.restart_after_navigations
    }

    fn navigate<'a>(&'a mut self, url: &'a str) -> BoxFuture<'a, RuntimeResult<DocumentState>> {
        Box::pin(async move {
            self.ensure_started()?;
            let fetched = Self::fetch_document(
                self.client.clone(),
                self.config.max_document_bytes,
                self.config.selector_text_limit,
                &self.navigation_policy,
                url,
            )
            .await?;
            self.navigation_count = self.navigation_count.saturating_add(1);
            let state = fetched.state.clone();
            self.html = Some(fetched.html);
            self.document = Some(fetched.document);
            self.state = Some(fetched.state);
            Ok(state)
        })
    }

    fn click_at(&mut self, _x: f64, _y: f64) -> BoxFuture<'_, RuntimeResult<()>> {
        Box::pin(async { Err(RuntimeError::new(RuntimeFailureKind::Interaction)) })
    }

    fn wheel(
        &mut self,
        _x: f64,
        _y: f64,
        _delta_x: f64,
        _delta_y: f64,
    ) -> BoxFuture<'_, RuntimeResult<()>> {
        Box::pin(async { Err(RuntimeError::new(RuntimeFailureKind::Interaction)) })
    }

    fn key_press<'a>(&'a mut self, _key: &'a str) -> BoxFuture<'a, RuntimeResult<()>> {
        Box::pin(async { Err(RuntimeError::new(RuntimeFailureKind::Interaction)) })
    }

    fn resolve_element<'a>(&'a mut self, selector: &'a str) -> BoxFuture<'a, RuntimeResult<()>> {
        Box::pin(async move {
            let selector = Self::parse_selector(selector)?;
            self.document()?
                .select(&selector)
                .next()
                .map(|_| ())
                .ok_or_else(|| RuntimeError::new(RuntimeFailureKind::ObservationMissing))
        })
    }

    fn click_element<'a>(&'a mut self, _selector: &'a str) -> BoxFuture<'a, RuntimeResult<()>> {
        Box::pin(async { Err(RuntimeError::new(RuntimeFailureKind::Interaction)) })
    }

    fn type_element<'a>(
        &'a mut self,
        _selector: &'a str,
        _text: &'a str,
    ) -> BoxFuture<'a, RuntimeResult<()>> {
        Box::pin(async { Err(RuntimeError::new(RuntimeFailureKind::Interaction)) })
    }

    fn read_element_text<'a>(
        &'a mut self,
        selector: &'a str,
    ) -> BoxFuture<'a, RuntimeResult<String>> {
        Box::pin(async move {
            let selector = Self::parse_selector(selector)?;
            let element = self.document()?
                .select(&selector)
                .next()
                .ok_or_else(|| RuntimeError::new(RuntimeFailureKind::ObservationMissing))?;
            normalize_text(element.text(), self.config.selector_text_limit)
                .map_err(|_| RuntimeError::new(RuntimeFailureKind::Interaction))
        })
    }

    fn evaluate<'a>(
        &'a mut self,
        _script: &'a str,
    ) -> BoxFuture<'a, RuntimeResult<serde_json::Value>> {
        Box::pin(async { Err(RuntimeError::new(RuntimeFailureKind::Interaction)) })
    }

    fn capture(&mut self, policy: CapturePolicy) -> BoxFuture<'_, RuntimeResult<CaptureArtifact>> {
        Box::pin(async move {
            let state = self.document_state()?;
            match policy {
                CapturePolicy::StateOnly => Ok(CaptureArtifact::StateOnly(state)),
                CapturePolicy::HtmlOnly => Ok(CaptureArtifact::HtmlOnly {
                    state,
                    html: self.html
                        .clone()
                        .ok_or_else(|| RuntimeError::new(RuntimeFailureKind::Capture))?,
                }),
                CapturePolicy::EvidenceViewport => {
                    Err(RuntimeError::new(RuntimeFailureKind::Capture))
                }
            }
        })
    }
}

pub fn runtime_descriptor() -> RuntimeDescriptor {
    use RuntimeFeature::*;

    let native = [Navigate, DomInspect, CaptureState, CaptureHtml, Lifecycle];
    let unsupported = [
        PointerInput,
        KeyboardInput,
        ScrollInput,
        DomInteract,
        ScriptEvaluate,
        CaptureViewportPng,
        PersistentProfile,
        HeadfulAuthentication,
        MobileWebEmulation,
        NativeMobileDevice,
    ];
    let mut features = native
        .into_iter()
        .map(|feature| FeatureSupport::new(feature, SupportLevel::Native, Vec::new()))
        .collect::<Vec<_>>();
    features.push(FeatureSupport::new(
        DesktopWeb,
        SupportLevel::Partial,
        vec![
            RuntimeLimitation::NoScriptExecution,
            RuntimeLimitation::NoVisualRendering,
            RuntimeLimitation::NoInteractiveDom,
            RuntimeLimitation::NoSubresourceLoading,
            RuntimeLimitation::NoPersonaEmulation,
            RuntimeLimitation::Utf8HtmlOnly,
            RuntimeLimitation::NoBrowserSessionState,
        ],
    ));
    features.extend(
        unsupported
            .into_iter()
            .map(|feature| FeatureSupport::new(feature, SupportLevel::Unsupported, Vec::new())),
    );
    RuntimeDescriptor::new(
        RuntimeKind::Lightweight,
        EngineFamily::Dig2Lightweight,
        ControlTransport::Native,
        features,
    )
    .expect("lightweight runtime descriptor contains each feature exactly once")
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    use dig2browser::agentic::BrowserRuntime;
    use dig2browser::identity::{
        BrowserBackend, DevicePersona, IdentityClass, IdentityProfile,
        ProfileOwnershipGuard,
    };

    use super::*;

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    const PAGE: &str = "<!doctype html><html><head><title>fixture title</title><script>document.title='executed'</script></head><body><div id='target'> Hello <span>world</span> </div></body></html>";

    struct ControlledOrigin {
        address: std::net::SocketAddr,
        stopping: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
    }

    impl ControlledOrigin {
        fn start(oversized_length: usize) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind controlled origin");
            listener
                .set_nonblocking(true)
                .expect("set controlled origin nonblocking");
            let address = listener.local_addr().expect("read controlled origin address");
            let stopping = Arc::new(AtomicBool::new(false));
            let thread_stopping = Arc::clone(&stopping);
            let thread = thread::spawn(move || {
                while !thread_stopping.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            stream
                                .set_nonblocking(false)
                                .expect("make controlled connection blocking");
                            serve_request(&mut stream, oversized_length);
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
            });
            Self {
                address,
                stopping,
                thread: Some(thread),
            }
        }

        fn url(&self, path: &str) -> String {
            format!("http://{}{}", self.address, path)
        }
    }

    impl Drop for ControlledOrigin {
        fn drop(&mut self) {
            self.stopping.store(true, Ordering::Release);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    fn serve_request(stream: &mut TcpStream, oversized_length: usize) {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("bound controlled request read");
        let mut request = Vec::with_capacity(1024);
        while request.len() < 4096 && !request.windows(4).any(|part| part == b"\r\n\r\n") {
            let mut block = [0_u8; 512];
            let length = stream.read(&mut block).expect("read controlled request");
            if length == 0 {
                break;
            }
            request.extend_from_slice(&block[..length]);
        }
        let request = String::from_utf8_lossy(&request);
        let path = request
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap_or("/");
        let response = match path {
            "/redirect" => concat!(
                "HTTP/1.1 302 Found\r\n",
                "Location: /page\r\n",
                "Content-Length: 0\r\n",
                "Connection: close\r\n\r\n"
            ).to_owned(),
            "/invalid-redirect" => concat!(
                "HTTP/1.1 302 Found\r\n",
                "Location: file:///forbidden\r\n",
                "Content-Length: 0\r\n",
                "Connection: close\r\n\r\n"
            ).to_owned(),
            "/page" => format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                PAGE.len(),
                PAGE,
            ),
            "/no-content-type" => format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                PAGE.len(),
                PAGE,
            ),
            "/oversized" => format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {oversized_length}\r\nConnection: close\r\n\r\n"
            ),
            _ => concat!(
                "HTTP/1.1 404 Not Found\r\n",
                "Content-Type: text/html\r\n",
                "Content-Length: 0\r\n",
                "Connection: close\r\n\r\n"
            ).to_owned(),
        };
        stream
            .write_all(response.as_bytes())
            .expect("write controlled response");
    }

    fn temp_profile_root() -> PathBuf {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "dig2browser-lightweight-test-{}-{sequence}",
            std::process::id()
        ))
    }

    fn test_identity(root: &PathBuf) -> IdentityProfile {
        IdentityProfile::new(
            root,
            "lightweight-e2e",
            IdentityClass::Public,
            BrowserBackend::Lightweight,
            DevicePersona::DesktopNative,
        )
        .expect("create lightweight identity")
    }

    #[test]
    fn config_rejects_unbounded_or_incoherent_values() {
        let config = LightweightRuntimeConfig {
            max_document_bytes: 0,
            ..LightweightRuntimeConfig::default()
        };
        assert_eq!(
            config.validate(),
            Err(LightweightRuntimeConfigError::MaxDocumentBytes)
        );

        let config = LightweightRuntimeConfig {
            connect_timeout: DEFAULT_REQUEST_TIMEOUT + Duration::from_millis(1),
            ..LightweightRuntimeConfig::default()
        };
        assert_eq!(
            config.validate(),
            Err(LightweightRuntimeConfigError::ConnectExceedsRequest)
        );
    }

    #[test]
    fn descriptor_reports_static_document_truth() {
        let descriptor = runtime_descriptor();
        assert_eq!(descriptor.kind(), RuntimeKind::Lightweight);
        assert_eq!(descriptor.engine(), EngineFamily::Dig2Lightweight);
        assert_eq!(descriptor.control(), ControlTransport::Native);
        assert_eq!(
            descriptor.support_for(RuntimeFeature::DomInspect).unwrap().level(),
            SupportLevel::Native
        );
        assert_eq!(
            descriptor.support_for(RuntimeFeature::DesktopWeb).unwrap().limitations(),
            &[
                RuntimeLimitation::NoScriptExecution,
                RuntimeLimitation::NoVisualRendering,
                RuntimeLimitation::NoInteractiveDom,
                RuntimeLimitation::NoSubresourceLoading,
                RuntimeLimitation::NoPersonaEmulation,
                RuntimeLimitation::Utf8HtmlOnly,
                RuntimeLimitation::NoBrowserSessionState,
            ]
        );
        assert_eq!(descriptor.features().len(), 16);
    }

    #[test]
    fn selector_text_is_whitespace_normalized_and_fails_closed_at_bound() {
        assert_eq!(
            normalize_text(["  alpha\n", " beta  "], 32).unwrap(),
            "alpha beta"
        );
        assert_eq!(
            normalize_text(["a  ", "\u{00e9}xtra"], 4),
            Err(TextLimitExceeded)
        );
        assert_eq!(normalize_text(["alpha beta"], 7), Err(TextLimitExceeded));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lightweight_runtime_redirect_dom_capture_bounds_and_lock_e2e() {
        let profile_root = temp_profile_root();
        let identity = test_identity(&profile_root);
        let config = LightweightRuntimeConfig {
            max_document_bytes: 512,
            selector_text_limit: 128,
            ..LightweightRuntimeConfig::default()
        };
        let origin = ControlledOrigin::start(config.max_document_bytes + 1);
        let mut runtime = LightweightRuntime::new(identity.clone(), config)
            .expect("create lightweight runtime");

        runtime.start().await.expect("start lightweight runtime");
        assert!(ProfileOwnershipGuard::acquire(identity.profile_dir()).is_err());

        let state = runtime
            .navigate(&origin.url("/redirect"))
            .await
            .expect("follow controlled redirect");
        assert!(state.url.ends_with("/page"));
        assert_eq!(state.title, "fixture title");
        assert_eq!(state.ready_state, "complete");
        assert_eq!(state.http_status, Some(200));

        let no_content_type = runtime
            .navigate(&origin.url("/no-content-type"))
            .await
            .expect("accept absent content type");
        assert!(no_content_type.url.ends_with("/no-content-type"));

        runtime
            .resolve_element("#target")
            .await
            .expect("resolve static selector");
        assert_eq!(
            runtime.read_element_text("#target").await.unwrap(),
            "Hello world"
        );
        assert_eq!(
            runtime.resolve_element("#missing").await.unwrap_err().kind(),
            RuntimeFailureKind::ObservationMissing
        );
        let capture = runtime
            .capture(CapturePolicy::HtmlOnly)
            .await
            .expect("capture raw bounded HTML");
        assert!(matches!(
            capture,
            CaptureArtifact::HtmlOnly { html, .. } if html == PAGE
        ));

        let script = runtime.evaluate("document.title = 'changed'").await;
        assert_eq!(
            script.unwrap_err().kind(),
            RuntimeFailureKind::Interaction
        );
        assert_eq!(
            runtime.capture(CapturePolicy::EvidenceViewport).await
                .unwrap_err()
                .kind(),
            RuntimeFailureKind::Capture
        );
        assert_eq!(
            runtime.navigate(&origin.url("/oversized")).await
                .unwrap_err()
                .kind(),
            RuntimeFailureKind::Navigation
        );
        assert_eq!(
            runtime.navigate(&origin.url("/invalid-redirect")).await
                .unwrap_err()
                .kind(),
            RuntimeFailureKind::Navigation
        );

        runtime.close().await.expect("close lightweight runtime");
        let released = ProfileOwnershipGuard::acquire(identity.profile_dir())
            .expect("profile lock released on close");
        drop(released);
        drop(runtime);

        let mut dropped_runtime = LightweightRuntime::new(
            identity.clone(),
            LightweightRuntimeConfig::default(),
        )
        .expect("create drop-release runtime");
        dropped_runtime.start().await.expect("start drop-release runtime");
        assert!(ProfileOwnershipGuard::acquire(identity.profile_dir()).is_err());
        drop(dropped_runtime);
        let released_after_drop = ProfileOwnershipGuard::acquire(identity.profile_dir())
            .expect("profile lock released on drop");
        drop(released_after_drop);
        drop(origin);
        std::fs::remove_dir_all(profile_root).expect("remove lightweight test profile");
    }
}
