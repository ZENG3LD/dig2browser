//! Bounded station-owned loopback proxy for exact-origin browser egress.

use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use dig2browser::agentic::NavigationPolicy;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;

const MAX_CONNECTIONS: usize = 64;
const MAX_HEADER_BYTES: usize = 32 * 1024;
const MAX_HEADERS: usize = 100;
const MAX_DNS_ANSWERS: usize = 16;
const MAX_PEER_EXCEPTIONS: usize = 64;
const READ_CHUNK_BYTES: usize = 4 * 1024;
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

/// Network peers admitted by the egress proxy after origin validation.
///
/// Globally routable unicast addresses are admitted by default. A bounded set
/// of non-global unicast addresses may be admitted by exact address, but only
/// for a matching IP-literal target. This prevents a hostname from reusing an
/// unrelated private exception through DNS rebinding. Unspecified, multicast
/// and limited-broadcast addresses can never be exceptions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressPeerPolicy {
    exact_non_global: Vec<IpAddr>,
}

impl EgressPeerPolicy {
    pub fn public_only() -> Self {
        Self {
            exact_non_global: Vec::new(),
        }
    }

    pub fn with_exact_exceptions<I>(exceptions: I) -> Result<Self, EgressPeerPolicyError>
    where
        I: IntoIterator<Item = IpAddr>,
    {
        let mut exact_non_global = Vec::new();
        for address in exceptions {
            if exact_non_global.len() >= MAX_PEER_EXCEPTIONS {
                return Err(EgressPeerPolicyError::TooManyExceptions);
            }
            if is_global_unicast(address) || !is_exception_eligible(address) {
                return Err(EgressPeerPolicyError::InvalidException);
            }
            exact_non_global.push(address);
        }
        exact_non_global.sort_unstable();
        exact_non_global.dedup();
        Ok(Self { exact_non_global })
    }

    pub fn exact_exceptions(&self) -> &[IpAddr] {
        &self.exact_non_global
    }

    fn allows(&self, address: IpAddr, literal_target: Option<IpAddr>) -> bool {
        is_global_unicast(address)
            || (literal_target == Some(address)
                && is_exception_eligible(address)
                && self.exact_non_global.binary_search(&address).is_ok())
    }
}

impl Default for EgressPeerPolicy {
    fn default() -> Self {
        Self::public_only()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressPeerPolicyError {
    TooManyExceptions,
    InvalidException,
}

impl fmt::Display for EgressPeerPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TooManyExceptions => "egress peer exception limit exceeded",
            Self::InvalidException => "egress peer exception is invalid",
        })
    }
}

impl std::error::Error for EgressPeerPolicyError {}

/// A loopback listener that enforces one immutable navigation and peer policy.
#[derive(Debug)]
pub struct EgressProxy {
    listener: TcpListener,
    local_addr: SocketAddr,
    policy: NavigationPolicy,
    peer_policy: EgressPeerPolicy,
}

impl EgressProxy {
    pub async fn bind(
        policy: NavigationPolicy,
        peer_policy: EgressPeerPolicy,
    ) -> Result<Self, EgressError> {
        if !policy.is_exact() {
            return Err(EgressError::PolicyConfiguration);
        }
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(|_| EgressError::Bind)?;
        let local_addr = listener.local_addr().map_err(|_| EgressError::Bind)?;
        Ok(Self {
            listener,
            local_addr,
            policy,
            peer_policy,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub async fn run(
        self,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<EgressReport, EgressError> {
        let Self {
            listener,
            policy,
            peer_policy,
            ..
        } = self;
        let (connection_shutdown, _) = watch::channel(false);
        let mut connections = JoinSet::new();
        let mut report = EgressReport::default();

        loop {
            if *shutdown.borrow() {
                break;
            }
            while connections.len() >= MAX_CONNECTIONS {
                tokio::select! {
                    biased;
                    _ = wait_for_shutdown(&mut shutdown) => break,
                    joined = connections.join_next() => record_join(joined, &mut report),
                }
                if *shutdown.borrow() {
                    break;
                }
            }
            if *shutdown.borrow() {
                break;
            }

            tokio::select! {
                biased;
                _ = wait_for_shutdown(&mut shutdown) => break,
                joined = connections.join_next(), if !connections.is_empty() => {
                    record_join(joined, &mut report);
                }
                accepted = listener.accept() => {
                    let (stream, client_addr) = accepted.map_err(|_| EgressError::Accept)?;
                    report.accepted_connections = report.accepted_connections.saturating_add(1);
                    if !client_addr.ip().is_loopback() {
                        report.denied_connections = report.denied_connections.saturating_add(1);
                        continue;
                    }
                    let policy = policy.clone();
                    let peer_policy = peer_policy.clone();
                    let connection_shutdown = connection_shutdown.subscribe();
                    connections.spawn(async move {
                        serve_connection(stream, policy, peer_policy, connection_shutdown).await
                    });
                }
            }
        }

        connection_shutdown.send_replace(true);
        let drained = tokio::time::timeout(DRAIN_TIMEOUT, async {
            while let Some(joined) = connections.join_next().await {
                record_join(Some(joined), &mut report);
            }
        })
        .await;
        if drained.is_err() {
            report.drain_timed_out = true;
            report.aborted_connections = report
                .aborted_connections
                .saturating_add(u64::try_from(connections.len()).unwrap_or(u64::MAX));
            connections.abort_all();
            while connections.join_next().await.is_some() {}
        }
        Ok(report)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EgressReport {
    pub accepted_connections: u64,
    pub completed_connections: u64,
    pub denied_connections: u64,
    pub invalid_connections: u64,
    pub failed_connections: u64,
    pub timed_out_connections: u64,
    pub aborted_connections: u64,
    pub drain_timed_out: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressError {
    PolicyConfiguration,
    Bind,
    Accept,
}

impl fmt::Display for EgressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::PolicyConfiguration => "egress proxy policy configuration failed",
            Self::Bind => "egress proxy listener setup failed",
            Self::Accept => "egress proxy listener failed",
        })
    }
}

impl std::error::Error for EgressError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionOutcome {
    Completed,
    Denied,
    Invalid,
    Failed,
    TimedOut,
    Aborted,
}

fn record_join(
    joined: Option<Result<ConnectionOutcome, tokio::task::JoinError>>,
    report: &mut EgressReport,
) {
    match joined {
        Some(Ok(ConnectionOutcome::Completed)) => {
            report.completed_connections = report.completed_connections.saturating_add(1)
        }
        Some(Ok(ConnectionOutcome::Denied)) => {
            report.denied_connections = report.denied_connections.saturating_add(1)
        }
        Some(Ok(ConnectionOutcome::Invalid)) => {
            report.invalid_connections = report.invalid_connections.saturating_add(1)
        }
        Some(Ok(ConnectionOutcome::TimedOut)) => {
            report.timed_out_connections = report.timed_out_connections.saturating_add(1)
        }
        Some(Ok(ConnectionOutcome::Aborted)) => {
            report.aborted_connections = report.aborted_connections.saturating_add(1)
        }
        Some(Ok(ConnectionOutcome::Failed)) | Some(Err(_)) => {
            report.failed_connections = report.failed_connections.saturating_add(1)
        }
        None => {}
    }
}

async fn serve_connection(
    stream: TcpStream,
    policy: NavigationPolicy,
    peer_policy: EgressPeerPolicy,
    mut shutdown: watch::Receiver<bool>,
) -> ConnectionOutcome {
    tokio::select! {
        biased;
        _ = wait_for_shutdown(&mut shutdown) => ConnectionOutcome::Aborted,
        result = tokio::time::timeout(
            CONNECTION_TIMEOUT,
            serve_connection_inner(stream, &policy, &peer_policy),
        ) => match result {
            Ok(Ok(())) => ConnectionOutcome::Completed,
            Ok(Err(failure)) => failure.outcome(),
            Err(_) => ConnectionOutcome::TimedOut,
        }
    }
}

async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) {
    loop {
        if *shutdown.borrow() {
            return;
        }
        if shutdown.changed().await.is_err() {
            return;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionFailure {
    Denied,
    Invalid,
    Failed,
    TimedOut,
}

impl ConnectionFailure {
    fn outcome(self) -> ConnectionOutcome {
        match self {
            Self::Denied => ConnectionOutcome::Denied,
            Self::Invalid => ConnectionOutcome::Invalid,
            Self::Failed => ConnectionOutcome::Failed,
            Self::TimedOut => ConnectionOutcome::TimedOut,
        }
    }
}

async fn serve_connection_inner(
    mut client: TcpStream,
    policy: &NavigationPolicy,
    peer_policy: &EgressPeerPolicy,
) -> Result<(), ConnectionFailure> {
    let (head, buffered) = tokio::time::timeout(HEADER_TIMEOUT, read_request_head(&mut client))
        .await
        .map_err(|_| ConnectionFailure::TimedOut)??;
    let request = parse_request(&head, buffered, policy)?;
    let addresses = resolve_target(&request.target, peer_policy).await?;
    let mut upstream = connect_target(&addresses).await?;

    match request.kind {
        RequestKind::Forward { method, headers } => {
            let outbound = build_forward_request(method, &request.target, &headers)?;
            tokio::time::timeout(WRITE_TIMEOUT, upstream.write_all(&outbound))
                .await
                .map_err(|_| ConnectionFailure::TimedOut)?
                .map_err(|_| ConnectionFailure::Failed)?;
            upstream.shutdown().await.map_err(|_| ConnectionFailure::Failed)?;
            tokio::io::copy(&mut upstream, &mut client)
                .await
                .map_err(|_| ConnectionFailure::Failed)?;
        }
        RequestKind::Connect { buffered } => {
            tokio::time::timeout(
                WRITE_TIMEOUT,
                client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n"),
            )
            .await
            .map_err(|_| ConnectionFailure::TimedOut)?
            .map_err(|_| ConnectionFailure::Failed)?;
            if !buffered.is_empty() {
                tokio::time::timeout(WRITE_TIMEOUT, upstream.write_all(&buffered))
                    .await
                    .map_err(|_| ConnectionFailure::TimedOut)?
                    .map_err(|_| ConnectionFailure::Failed)?;
            }
            tokio::io::copy_bidirectional(&mut client, &mut upstream)
                .await
                .map_err(|_| ConnectionFailure::Failed)?;
        }
    }
    let _ = client.shutdown().await;
    Ok(())
}

async fn read_request_head(
    stream: &mut TcpStream,
) -> Result<(Vec<u8>, Vec<u8>), ConnectionFailure> {
    let mut received = Vec::with_capacity(READ_CHUNK_BYTES);
    let mut chunk = [0_u8; READ_CHUNK_BYTES];
    loop {
        let count = stream
            .read(&mut chunk)
            .await
            .map_err(|_| ConnectionFailure::Failed)?;
        if count == 0 {
            return Err(ConnectionFailure::Invalid);
        }
        received.extend_from_slice(&chunk[..count]);
        if let Some(index) = find_header_end(&received) {
            let head_end = index + 4;
            if head_end > MAX_HEADER_BYTES {
                return Err(ConnectionFailure::Invalid);
            }
            let buffered = received.split_off(head_end);
            return Ok((received, buffered));
        }
        if received.len() > MAX_HEADER_BYTES {
            return Err(ConnectionFailure::Invalid);
        }
    }
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

#[derive(Debug)]
struct ParsedRequest {
    kind: RequestKind,
    target: Target,
}

#[derive(Debug)]
enum RequestKind {
    Forward {
        method: Method,
        headers: Vec<Header>,
    },
    Connect {
        buffered: Vec<u8>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Method {
    Get,
    Head,
}

impl Method {
    fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
        }
    }
}

#[derive(Debug)]
struct Header {
    name: String,
    lower_name: String,
    value: String,
}

#[derive(Debug)]
struct Target {
    host: String,
    port: u16,
    authority: String,
    origin_form: String,
    literal_ip: Option<IpAddr>,
}

fn parse_request(
    head: &[u8],
    buffered: Vec<u8>,
    policy: &NavigationPolicy,
) -> Result<ParsedRequest, ConnectionFailure> {
    if head.len() > MAX_HEADER_BYTES || !head.ends_with(b"\r\n\r\n") {
        return Err(ConnectionFailure::Invalid);
    }
    let text = std::str::from_utf8(&head[..head.len() - 4])
        .map_err(|_| ConnectionFailure::Invalid)?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or(ConnectionFailure::Invalid)?;
    let mut request_parts = request_line.split(' ');
    let method = request_parts.next().ok_or(ConnectionFailure::Invalid)?;
    let raw_target = request_parts.next().ok_or(ConnectionFailure::Invalid)?;
    let version = request_parts.next().ok_or(ConnectionFailure::Invalid)?;
    if request_parts.next().is_some()
        || method.is_empty()
        || raw_target.is_empty()
        || version != "HTTP/1.1"
    {
        return Err(ConnectionFailure::Invalid);
    }

    let headers = parse_headers(lines)?;
    let host = one_host_header(&headers)?;
    reject_request_body(&headers)?;

    match method {
        "GET" | "HEAD" => {
            if !buffered.is_empty()
                || raw_target.contains('#')
                || !raw_target.starts_with("http://")
            {
                return Err(ConnectionFailure::Invalid);
            }
            let parsed = policy
                .parse_target(raw_target)
                .map_err(|_| ConnectionFailure::Denied)?;
            if parsed.scheme() != "http" || !authority_matches(&parsed, host) {
                return Err(ConnectionFailure::Denied);
            }
            Ok(ParsedRequest {
                kind: RequestKind::Forward {
                    method: if method == "GET" { Method::Get } else { Method::Head },
                    headers,
                },
                target: Target {
                    host: parsed.host().to_owned(),
                    port: parsed.effective_port(),
                    authority: parsed.authority().to_string(),
                    origin_form: parsed.origin_form().to_string(),
                    literal_ip: parsed.ip_addr(),
                },
            })
        }
        "CONNECT" => {
            if raw_target.contains('/') || raw_target.contains('?') || raw_target.contains('#') {
                return Err(ConnectionFailure::Invalid);
            }
            let absolute = format!("https://{raw_target}/");
            let parsed = policy
                .parse_target(&absolute)
                .map_err(|_| ConnectionFailure::Denied)?;
            if parsed.scheme() != "https"
                || !authority_matches(&parsed, raw_target)
                || !authority_matches(&parsed, host)
            {
                return Err(ConnectionFailure::Denied);
            }
            Ok(ParsedRequest {
                kind: RequestKind::Connect { buffered },
                target: Target {
                    host: parsed.host().to_owned(),
                    port: parsed.effective_port(),
                    authority: parsed.authority().to_string(),
                    origin_form: parsed.origin_form().to_string(),
                    literal_ip: parsed.ip_addr(),
                },
            })
        }
        _ => Err(ConnectionFailure::Invalid),
    }
}

fn parse_headers<'a>(
    lines: impl Iterator<Item = &'a str>,
) -> Result<Vec<Header>, ConnectionFailure> {
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() || headers.len() >= MAX_HEADERS {
            return Err(ConnectionFailure::Invalid);
        }
        if line.starts_with([' ', '\t']) {
            return Err(ConnectionFailure::Invalid);
        }
        let (name, raw_value) = line.split_once(':').ok_or(ConnectionFailure::Invalid)?;
        if !is_header_name(name.as_bytes()) {
            return Err(ConnectionFailure::Invalid);
        }
        let value = raw_value.trim_matches([' ', '\t']);
        if !value
            .bytes()
            .all(|byte| byte == b'\t' || (0x20..=0x7e).contains(&byte))
        {
            return Err(ConnectionFailure::Invalid);
        }
        headers.push(Header {
            name: name.to_owned(),
            lower_name: name.to_ascii_lowercase(),
            value: value.to_owned(),
        });
    }
    Ok(headers)
}

fn is_header_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name.iter().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-'
                        | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
                )
        })
}

fn one_host_header(headers: &[Header]) -> Result<&str, ConnectionFailure> {
    let mut hosts = headers
        .iter()
        .filter(|header| header.lower_name == "host")
        .map(|header| header.value.as_str());
    let host = hosts.next().ok_or(ConnectionFailure::Invalid)?;
    if host.is_empty() || hosts.next().is_some() {
        return Err(ConnectionFailure::Invalid);
    }
    Ok(host)
}

fn reject_request_body(headers: &[Header]) -> Result<(), ConnectionFailure> {
    let mut content_length_seen = false;
    for header in headers {
        match header.lower_name.as_str() {
            "transfer-encoding" | "expect" => return Err(ConnectionFailure::Invalid),
            "content-length" => {
                if content_length_seen || header.value != "0" {
                    return Err(ConnectionFailure::Invalid);
                }
                content_length_seen = true;
            }
            _ => {}
        }
    }
    Ok(())
}

fn authority_matches(
    target: &dig2browser::agentic::NavigationTarget,
    authority: &str,
) -> bool {
    let canonical = target.authority().to_string();
    canonical.eq_ignore_ascii_case(authority)
        || (matches!(
            (target.scheme(), target.effective_port()),
            ("http", 80) | ("https", 443)
        ) && format!("{canonical}:{}", target.effective_port())
            .eq_ignore_ascii_case(authority))
}

fn build_forward_request(
    method: Method,
    target: &Target,
    headers: &[Header],
) -> Result<Vec<u8>, ConnectionFailure> {
    let mut connection_named = HashSet::new();
    for header in headers
        .iter()
        .filter(|header| header.lower_name == "connection")
    {
        for token in header.value.split(',').map(str::trim) {
            if !is_header_name(token.as_bytes()) {
                return Err(ConnectionFailure::Invalid);
            }
            connection_named.insert(token.to_ascii_lowercase());
        }
    }

    let mut outbound = Vec::with_capacity(MAX_HEADER_BYTES);
    append_bytes(&mut outbound, method.as_str().as_bytes())?;
    append_bytes(&mut outbound, b" ")?;
    append_bytes(&mut outbound, target.origin_form.as_bytes())?;
    append_bytes(&mut outbound, b" HTTP/1.1\r\nHost: ")?;
    append_bytes(&mut outbound, target.authority.as_bytes())?;
    append_bytes(&mut outbound, b"\r\n")?;
    for header in headers {
        if is_hop_by_hop(&header.lower_name)
            || header.lower_name == "host"
            || header.lower_name == "content-length"
            || connection_named.contains(&header.lower_name)
        {
            continue;
        }
        append_bytes(&mut outbound, header.name.as_bytes())?;
        append_bytes(&mut outbound, b": ")?;
        append_bytes(&mut outbound, header.value.as_bytes())?;
        append_bytes(&mut outbound, b"\r\n")?;
    }
    append_bytes(&mut outbound, b"Connection: close\r\n\r\n")?;
    Ok(outbound)
}

fn append_bytes(outbound: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ConnectionFailure> {
    if outbound.len().saturating_add(bytes.len()) > MAX_HEADER_BYTES {
        return Err(ConnectionFailure::Invalid);
    }
    outbound.extend_from_slice(bytes);
    Ok(())
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

async fn resolve_target(
    target: &Target,
    peer_policy: &EgressPeerPolicy,
) -> Result<Vec<SocketAddr>, ConnectionFailure> {
    let resolved = tokio::time::timeout(DNS_TIMEOUT, lookup_host((target.host.as_str(), target.port)))
        .await
        .map_err(|_| ConnectionFailure::TimedOut)?
        .map_err(|_| ConnectionFailure::Failed)?;
    let mut addresses = Vec::new();
    let mut answer_count = 0_usize;
    for address in resolved {
        answer_count = answer_count.saturating_add(1);
        if answer_count > MAX_DNS_ANSWERS {
            return Err(ConnectionFailure::Denied);
        }
        if !peer_policy.allows(address.ip(), target.literal_ip)
            || target.literal_ip.is_some_and(|literal| literal != address.ip())
        {
            return Err(ConnectionFailure::Denied);
        }
        if !addresses.contains(&address) {
            addresses.push(address);
        }
    }
    if addresses.is_empty() {
        return Err(ConnectionFailure::Failed);
    }
    Ok(addresses)
}

async fn connect_target(addresses: &[SocketAddr]) -> Result<TcpStream, ConnectionFailure> {
    tokio::time::timeout(CONNECT_TIMEOUT, async {
        for address in addresses {
            let stream = match TcpStream::connect(*address).await {
                Ok(stream) => stream,
                Err(_) => continue,
            };
            let peer = stream.peer_addr().map_err(|_| ConnectionFailure::Failed)?;
            if peer != *address {
                return Err(ConnectionFailure::Denied);
            }
            return Ok(stream);
        }
        Err(ConnectionFailure::Failed)
    })
    .await
    .map_err(|_| ConnectionFailure::TimedOut)?
}

fn is_exception_eligible(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            !address.is_unspecified() && !address.is_multicast() && !address.is_broadcast()
        }
        IpAddr::V6(address) => {
            if let Some(mapped) = address.to_ipv4_mapped() {
                return is_exception_eligible(IpAddr::V4(mapped));
            }
            let first = address.segments()[0];
            !address.is_unspecified()
                && !address.is_multicast()
                && !is_ipv4_compatible_prefix(address)
                && first & 0xffc0 != 0xfe80
                && first & 0xffc0 != 0xfec0
        }
    }
}

fn is_global_unicast(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_global_ipv4(address),
        IpAddr::V6(address) => is_global_ipv6(address),
    }
}

fn is_global_ipv4(address: Ipv4Addr) -> bool {
    let [a, b, c, d] = address.octets();
    if a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 192 && b == 0 && c == 0 && !matches!(d, 9 | 10))
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 88 && c == 99)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224
    {
        return false;
    }
    true
}

fn is_global_ipv6(address: Ipv6Addr) -> bool {
    if address.is_unspecified() || address.is_loopback() || address.is_multicast() {
        return false;
    }
    if let Some(mapped) = address.to_ipv4_mapped() {
        return is_global_ipv4(mapped);
    }
    if is_ipv4_compatible_prefix(address) {
        return false;
    }
    let segments = address.segments();
    let first = segments[0];
    if first & 0xe000 != 0x2000
        || (first == 0x2001 && segments[1] <= 0x01ff)
        || (first == 0x2001 && segments[1] == 0x0db8)
        || first == 0x2002
        || (first == 0x3fff && segments[1] & 0xf000 == 0)
        || first & 0xfe00 == 0xfc00
        || first & 0xffc0 == 0xfe80
        || first & 0xffc0 == 0xfec0
    {
        return false;
    }
    true
}

fn is_ipv4_compatible_prefix(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    segments[..6].iter().all(|segment| *segment == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_classification_rejects_non_global_and_multicast_ranges() {
        assert!(is_global_unicast("8.8.8.8".parse().expect("global v4")));
        assert!(is_global_unicast(
            "2606:4700:4700::1111".parse().expect("global v6")
        ));
        for address in [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "192.0.2.1",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "fc00::1",
            "fe80::1",
            "64:ff9b:1::1",
            "100::1",
            "100:0:0:1::1",
            "2001::1",
            "2001:2::1",
            "2001:db8::1",
            "2002::1",
            "3fff::1",
            "5f00::1",
            "ff02::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(!is_global_unicast(address.parse().expect("special address")));
        }
    }

    #[test]
    fn peer_exceptions_are_exact_and_never_admit_non_unicast_addresses() {
        let allowed: IpAddr = "127.0.0.1".parse().expect("loopback");
        let adjacent: IpAddr = "127.0.0.2".parse().expect("adjacent loopback");
        let private: IpAddr = "10.2.3.4".parse().expect("private");
        let policy = EgressPeerPolicy::with_exact_exceptions([allowed, private])
            .expect("valid exact exceptions");
        assert!(policy.allows(allowed, Some(allowed)));
        assert!(policy.allows(private, Some(private)));
        assert!(!policy.allows(adjacent, Some(adjacent)));
        assert!(!policy.allows(allowed, None));
        assert!(policy.allows(
            "8.8.8.8".parse().expect("global peer"),
            None,
        ));
        assert!(matches!(
            EgressPeerPolicy::with_exact_exceptions([
                "0.0.0.0".parse().expect("unspecified")
            ]),
            Err(EgressPeerPolicyError::InvalidException)
        ));
        assert!(matches!(
            EgressPeerPolicy::with_exact_exceptions([
                "224.0.0.1".parse().expect("multicast")
            ]),
            Err(EgressPeerPolicyError::InvalidException)
        ));
        assert!(matches!(
            EgressPeerPolicy::with_exact_exceptions([
                "255.255.255.255".parse().expect("broadcast")
            ]),
            Err(EgressPeerPolicyError::InvalidException)
        ));
        for address in [
            "::ffff:0.0.0.0",
            "::ffff:224.0.0.1",
            "::ffff:255.255.255.255",
        ] {
            assert!(matches!(
                EgressPeerPolicy::with_exact_exceptions([
                    address.parse().expect("mapped forbidden address")
                ]),
                Err(EgressPeerPolicyError::InvalidException)
            ));
        }
    }

    #[test]
    fn parser_enforces_header_bound_and_host_origin_match() {
        let policy = NavigationPolicy::exact_origins(["http://example.test/"])
            .expect("exact policy");
        let request = b"GET http://example.test/path HTTP/1.1\r\nHost: other.test\r\n\r\n";
        assert!(matches!(
            parse_request(request, Vec::new(), &policy),
            Err(ConnectionFailure::Denied)
        ));
        for host in ["example.test/path", "example.test?x", "example.test#x"] {
            let request = format!(
                "GET http://example.test/path HTTP/1.1\r\nHost: {host}\r\n\r\n"
            );
            assert!(matches!(
                parse_request(request.as_bytes(), Vec::new(), &policy),
                Err(ConnectionFailure::Denied)
            ));
        }

        let oversized = vec![b'a'; MAX_HEADER_BYTES + 1];
        assert!(matches!(
            parse_request(&oversized, Vec::new(), &policy),
            Err(ConnectionFailure::Invalid)
        ));
    }

    #[tokio::test]
    async fn connect_tunnel_uses_the_validated_peer() {
        let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind CONNECT upstream");
        let upstream_address = upstream.local_addr().expect("CONNECT upstream address");
        let origin = format!("https://{upstream_address}");
        let policy = NavigationPolicy::exact_origins([origin]).expect("exact CONNECT policy");
        let peer_policy = EgressPeerPolicy::with_exact_exceptions([
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        ])
        .expect("loopback CONNECT exception");
        let proxy = EgressProxy::bind(policy, peer_policy)
            .await
            .expect("bind CONNECT proxy");
        let proxy_address = proxy.local_addr();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let proxy_task = tokio::spawn(proxy.run(shutdown_rx));
        let upstream_task = tokio::spawn(async move {
            let (mut stream, peer) = upstream.accept().await.expect("accept CONNECT peer");
            assert!(peer.ip().is_loopback());
            let mut payload = [0_u8; 5];
            stream.read_exact(&mut payload).await.expect("read tunnel payload");
            assert_eq!(&payload, b"hello");
            stream.write_all(b"world").await.expect("write tunnel reply");
            stream.shutdown().await.expect("close CONNECT upstream");
        });

        let mut client = TcpStream::connect(proxy_address)
            .await
            .expect("connect to station proxy");
        client
            .write_all(
                format!(
                    "CONNECT {upstream_address} HTTP/1.1\r\nHost: {upstream_address}\r\n\r\nhello"
                )
                .as_bytes(),
            )
            .await
            .expect("send CONNECT request");
        client.shutdown().await.expect("finish CONNECT request");
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut response))
            .await
            .expect("CONNECT response timeout")
            .expect("read CONNECT response");
        assert!(response.starts_with(b"HTTP/1.1 200 Connection Established\r\n\r\n"));
        assert!(response.ends_with(b"world"));
        upstream_task.await.expect("join CONNECT upstream");
        shutdown_tx.send_replace(true);
        let report = proxy_task
            .await
            .expect("join CONNECT proxy")
            .expect("CONNECT proxy report");
        assert_eq!(report.completed_connections, 1);
        assert_eq!(report.denied_connections, 0);
    }
}
