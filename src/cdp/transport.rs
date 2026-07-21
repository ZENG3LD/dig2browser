//! Core transport for multiplexing Chrome DevTools commands and events over
//! either WebSocket or Chrome's ASCIIZ pipe protocol.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{debug, error, warn};

use crate::cdp::error::CdpError;
use crate::cdp::session::CdpSession;
use crate::cdp::types::{CdpEvent, CdpInbound, CdpOutbound, CdpOutboundFrame};

/// Broadcast channel capacity for inbound CDP events.
const EVENT_CHANNEL_CAPACITY: usize = 4096;
/// Outbound mpsc channel capacity.
const OUTBOUND_CHANNEL_CAPACITY: usize = 128;
/// Maximum payload size for one NUL-delimited CDP pipe frame.
const MAX_PIPE_FRAME_SIZE: usize = 64 * 1024 * 1024;

type PendingResponses =
    Arc<DashMap<u64, oneshot::Sender<Result<serde_json::Value, CdpError>>>>;

/// A multiplexed CDP client.
///
/// Cloning / sharing is done via `Arc<CdpClient>`. Multiple [`CdpSession`]
/// handles can share the same underlying connection.
pub struct CdpClient {
    sender: mpsc::Sender<CdpTransportCommand>,
    event_tx: broadcast::Sender<CdpEvent>,
    terminal_tx: watch::Sender<bool>,
    next_id: AtomicU64,
    pending: PendingResponses,
}

enum CdpTransportCommand {
    Send(CdpOutbound),
    Close,
}

fn serialize_and_register(
    cmd: CdpOutbound,
    pending: &PendingResponses,
) -> Option<(u64, String)> {
    let frame = CdpOutboundFrame::from(&cmd);
    let text = match serde_json::to_string(&frame) {
        Ok(text) => text,
        Err(error) => {
            error!("CDP serialize error: {error}");
            let _ = cmd.response_tx.send(Err(CdpError::Json(error)));
            return None;
        }
    };

    let id = cmd.id;
    pending.insert(id, cmd.response_tx);
    Some((id, text))
}

fn dispatch_inbound(
    raw: &[u8],
    pending: &PendingResponses,
    event_tx: &broadcast::Sender<CdpEvent>,
) -> Result<(), serde_json::Error> {
    let inbound: CdpInbound = serde_json::from_slice(raw)?;

    if let Some(id) = inbound.id {
        if let Some((_, tx)) = pending.remove(&id) {
            let result = if let Some(err) = inbound.error {
                Err(CdpError::Protocol {
                    code: err.code,
                    message: err.message,
                })
            } else {
                Ok(inbound.result.unwrap_or(serde_json::Value::Null))
            };
            let _ = tx.send(result);
        }
    } else if let Some(method) = inbound.method {
        let event = CdpEvent {
            method,
            params: inbound.params,
            session_id: inbound.session_id,
        };
        // No active subscribers is not a transport error.
        let _ = event_tx.send(event);
    }

    Ok(())
}

fn mark_terminal(terminal_tx: &watch::Sender<bool>, pending: &PendingResponses) {
    terminal_tx.send_replace(true);
    pending.retain(|_, _| false);
}

async fn read_pipe_frame<R>(
    reader: &mut BufReader<R>,
    frame: &mut Vec<u8>,
    max_frame_size: usize,
) -> std::io::Result<Option<()>>
where
    R: AsyncRead + Unpin,
{
    frame.clear();

    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            if frame.is_empty() {
                return Ok(None);
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "CDP pipe closed before NUL frame delimiter",
            ));
        }

        if let Some(delimiter) = available.iter().position(|byte| *byte == 0) {
            if frame.len() + delimiter > max_frame_size {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "CDP pipe frame exceeds maximum size",
                ));
            }
            frame.extend_from_slice(&available[..delimiter]);
            reader.consume(delimiter + 1);
            return Ok(Some(()));
        }

        if frame.len() + available.len() > max_frame_size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "CDP pipe frame exceeds maximum size",
            ));
        }
        let available_len = available.len();
        frame.extend_from_slice(available);
        reader.consume(available_len);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use serde_json::json;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio::time::timeout;

    use super::CdpClient;
    use crate::cdp::error::CdpError;

    const TEST_TIMEOUT: Duration = Duration::from_secs(2);

    fn pipe_pair_with_limit(
        max_frame_size: usize,
    ) -> (Arc<CdpClient>, DuplexStream, DuplexStream) {
        let (client_reader, server_writer) = duplex(4096);
        let (client_writer, server_reader) = duplex(4096);
        let client = CdpClient::from_pipe_with_max_frame_size(
            client_reader,
            client_writer,
            max_frame_size,
        );
        (client, server_reader, server_writer)
    }

    async fn pipe_pair() -> (Arc<CdpClient>, DuplexStream, DuplexStream) {
        let (client_reader, server_writer) = duplex(4096);
        let (client_writer, server_reader) = duplex(4096);
        let client = CdpClient::connect_pipe(client_reader, client_writer)
            .await
            .expect("construct pipe transport");
        (client, server_reader, server_writer)
    }

    async fn read_wire_frame(reader: &mut DuplexStream) -> Vec<u8> {
        let mut frame = Vec::new();
        loop {
            let mut byte = [0_u8; 1];
            timeout(TEST_TIMEOUT, reader.read_exact(&mut byte))
                .await
                .expect("timed out waiting for outbound pipe frame")
                .expect("outbound pipe closed before frame delimiter");
            frame.push(byte[0]);
            if byte[0] == 0 {
                return frame;
            }
        }
    }

    async fn assert_terminal(client: &CdpClient) {
        let mut terminal = client.subscribe_terminal();
        if !*terminal.borrow() {
            timeout(TEST_TIMEOUT, terminal.changed())
                .await
                .expect("timed out waiting for terminal state")
                .expect("terminal watch sender dropped");
        }
        assert!(*terminal.borrow());
        assert!(client.is_terminal());
    }

    #[tokio::test]
    async fn pipe_multiplexes_commands_responses_and_events_with_nul_framing() {
        let (client, mut server_reader, mut server_writer) = pipe_pair().await;
        let mut events = client.subscribe();
        let command_client = Arc::clone(&client);
        let command = tokio::spawn(async move {
            command_client
                .send(
                    "Runtime.evaluate",
                    Some(json!({"expression": "6 * 7"})),
                    Some("session-1".to_owned()),
                )
                .await
        });

        let frame = read_wire_frame(&mut server_reader).await;
        assert_eq!(frame.last(), Some(&0));
        assert_eq!(frame[..frame.len() - 1].iter().position(|byte| *byte == 0), None);
        let outbound: serde_json::Value =
            serde_json::from_slice(&frame[..frame.len() - 1]).expect("valid outbound JSON");
        assert_eq!(outbound["id"], 1);
        assert_eq!(outbound["method"], "Runtime.evaluate");
        assert_eq!(outbound["params"], json!({"expression": "6 * 7"}));
        assert_eq!(outbound["sessionId"], "session-1");

        server_writer
            .write_all(
                b"{\"method\":\"Runtime.consoleAPICalled\",\"params\":{\"type\":\"log\"},\"sessionId\":\"session-1\"}\0{\"id\":1,\"result\":{\"value\":42}}\0",
            )
            .await
            .expect("write multiplexed inbound frames");

        let event = timeout(TEST_TIMEOUT, events.recv())
            .await
            .expect("timed out waiting for event")
            .expect("event channel closed");
        assert_eq!(event.method, "Runtime.consoleAPICalled");
        assert_eq!(event.params, Some(json!({"type": "log"})));
        assert_eq!(event.session_id.as_deref(), Some("session-1"));

        let result = timeout(TEST_TIMEOUT, command)
            .await
            .expect("timed out waiting for command response")
            .expect("command task panicked")
            .expect("command failed");
        assert_eq!(result, json!({"value": 42}));
    }

    #[tokio::test]
    async fn pipe_oversize_frame_is_terminal() {
        let (client, _server_reader, mut server_writer) = pipe_pair_with_limit(32);
        server_writer
            .write_all(&[b'x'; 33])
            .await
            .expect("write oversize frame");

        assert_terminal(&client).await;
    }

    #[tokio::test]
    async fn pipe_malformed_frame_is_terminal() {
        let (client, _server_reader, mut server_writer) = pipe_pair().await;
        server_writer
            .write_all(b"not-json\0")
            .await
            .expect("write malformed frame");

        assert_terminal(&client).await;
    }

    #[tokio::test]
    async fn pipe_eof_is_terminal_and_fails_pending_command() {
        let (client, mut server_reader, server_writer) = pipe_pair().await;
        let command_client = Arc::clone(&client);
        let command = tokio::spawn(async move {
            command_client.send("Browser.getVersion", None, None).await
        });
        let _frame = read_wire_frame(&mut server_reader).await;

        drop(server_writer);

        assert_terminal(&client).await;
        let result = timeout(TEST_TIMEOUT, command)
            .await
            .expect("timed out waiting for pending command failure")
            .expect("command task panicked");
        assert!(matches!(result, Err(CdpError::ConnectionClosed)));
    }

    #[tokio::test]
    async fn pipe_close_propagates_eof_terminal_and_pending_failure() {
        let (client, mut server_reader, _server_writer) = pipe_pair().await;
        let command_client = Arc::clone(&client);
        let command = tokio::spawn(async move {
            command_client.send("Browser.getVersion", None, None).await
        });
        let _frame = read_wire_frame(&mut server_reader).await;

        client
            .close_transport()
            .await
            .expect("enqueue pipe transport close");

        let mut byte = [0_u8; 1];
        let read = timeout(TEST_TIMEOUT, server_reader.read(&mut byte))
            .await
            .expect("timed out waiting for pipe writer EOF")
            .expect("read pipe writer EOF");
        assert_eq!(read, 0);
        assert_terminal(&client).await;
        let result = timeout(TEST_TIMEOUT, command)
            .await
            .expect("timed out waiting for pending command failure")
            .expect("command task panicked");
        assert!(matches!(result, Err(CdpError::ConnectionClosed)));
    }
}

impl CdpClient {
    fn new_transport() -> (Arc<Self>, mpsc::Receiver<CdpTransportCommand>) {
        let (event_tx, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        let (outbound_tx, outbound_rx) =
            mpsc::channel::<CdpTransportCommand>(OUTBOUND_CHANNEL_CAPACITY);
        let (terminal_tx, _) = watch::channel(false);

        let client = Arc::new(CdpClient {
            sender: outbound_tx,
            event_tx,
            terminal_tx,
            next_id: AtomicU64::new(1),
            pending: Arc::new(DashMap::new()),
        });

        (client, outbound_rx)
    }

    /// Connect to a CDP WebSocket endpoint (e.g. `ws://localhost:9222/json/...`).
    pub async fn connect(ws_url: &str) -> Result<Arc<Self>, CdpError> {
        let (ws_stream, _) = connect_async(ws_url)
            .await
            .map_err(|e| CdpError::WebSocket(e.to_string()))?;

        let (mut ws_sink, mut ws_source) = ws_stream.split();

        let (client, mut outbound_rx) = Self::new_transport();
        let event_tx = client.event_tx.clone();
        let terminal_tx = client.terminal_tx.clone();
        let pending = Arc::clone(&client.pending);

        // ── outbound writer task ──────────────────────────────────────────────
        let terminal_tx_writer = terminal_tx.clone();
        let mut terminal_rx_writer = terminal_tx.subscribe();
        tokio::spawn(async move {
            loop {
                let command = tokio::select! {
                    biased;
                    _ = terminal_rx_writer.changed() => break,
                    command = outbound_rx.recv() => command,
                };
                let Some(command) = command else {
                    break;
                };
                let cmd = match command {
                    CdpTransportCommand::Send(cmd) => cmd,
                    CdpTransportCommand::Close => {
                        if let Err(error) = ws_sink.send(Message::Close(None)).await {
                            warn!("CDP WebSocket close error: {error}");
                        }
                        mark_terminal(&terminal_tx_writer, &pending);
                        break;
                    }
                };
                let Some((id, text)) = serialize_and_register(cmd, &pending) else {
                    continue;
                };
                if *terminal_rx_writer.borrow() {
                    if let Some((_, tx)) = pending.remove(&id) {
                        let _ = tx.send(Err(CdpError::ConnectionClosed));
                    }
                    break;
                }
                let send_result = tokio::select! {
                    biased;
                    _ = terminal_rx_writer.changed() => {
                        if let Some((_, tx)) = pending.remove(&id) {
                            let _ = tx.send(Err(CdpError::ConnectionClosed));
                        }
                        break;
                    }
                    result = ws_sink.send(Message::Text(text.into())) => result,
                };
                if let Err(e) = send_result {
                    error!("CDP ws send error: {e}");
                    // Remove the pending entry and report failure.
                    if let Some((_, tx)) = pending.remove(&id) {
                        let _ = tx.send(Err(CdpError::WebSocket(e.to_string())));
                    }
                    mark_terminal(&terminal_tx_writer, &pending);
                    break;
                }
            }
            debug!("CDP outbound writer exiting");
        });

        // ── inbound reader task ───────────────────────────────────────────────
        let pending_reader = Arc::clone(&client.pending);
        let event_tx_reader = event_tx.clone();
        let terminal_tx_reader = terminal_tx;
        tokio::spawn(async move {
            while let Some(msg_result) = ws_source.next().await {
                let raw = match msg_result {
                    Ok(Message::Text(t)) => t.to_string(),
                    Ok(Message::Binary(b)) => match String::from_utf8(b.to_vec()) {
                        Ok(s) => s,
                        Err(e) => {
                            warn!("CDP binary message not UTF-8: {e}");
                            continue;
                        }
                    },
                    Ok(Message::Close(_)) => {
                        debug!("CDP WebSocket closed by server");
                        break;
                    }
                    Ok(_) => continue,
                    Err(e) => {
                        error!("CDP ws recv error: {e}");
                        break;
                    }
                };

                if let Err(e) = dispatch_inbound(raw.as_bytes(), &pending_reader, &event_tx_reader) {
                    warn!("CDP parse error ({e}): {raw}");
                }
            }

            debug!("CDP inbound reader exiting");
            mark_terminal(&terminal_tx_reader, &pending_reader);
        });

        Ok(client)
    }

    /// Construct a CDP client over Chrome's NUL-delimited pipe protocol.
    ///
    /// `reader` receives frames from Chrome and `writer` sends frames to it.
    /// Each frame is UTF-8 JSON followed by one NUL byte.
    pub async fn connect_pipe<R, W>(reader: R, writer: W) -> Result<Arc<Self>, CdpError>
    where
        R: AsyncRead + Send + Unpin + 'static,
        W: AsyncWrite + Send + Unpin + 'static,
    {
        Ok(Self::from_pipe_with_max_frame_size(
            reader,
            writer,
            MAX_PIPE_FRAME_SIZE,
        ))
    }

    fn from_pipe_with_max_frame_size<R, W>(
        reader: R,
        writer: W,
        max_frame_size: usize,
    ) -> Arc<Self>
    where
        R: AsyncRead + Send + Unpin + 'static,
        W: AsyncWrite + Send + Unpin + 'static,
    {
        let (client, mut outbound_rx) = Self::new_transport();

        let pending_writer = Arc::clone(&client.pending);
        let terminal_tx_writer = client.terminal_tx.clone();
        let mut terminal_rx_writer = client.terminal_tx.subscribe();
        tokio::spawn(async move {
            let mut writer = writer;
            loop {
                let command = tokio::select! {
                    biased;
                    _ = terminal_rx_writer.changed() => break,
                    command = outbound_rx.recv() => command,
                };
                let Some(command) = command else {
                    break;
                };

                let cmd = match command {
                    CdpTransportCommand::Send(cmd) => cmd,
                    CdpTransportCommand::Close => {
                        if let Err(error) = writer.shutdown().await {
                            warn!("CDP pipe shutdown error: {error}");
                        }
                        mark_terminal(&terminal_tx_writer, &pending_writer);
                        break;
                    }
                };

                let Some((id, text)) = serialize_and_register(cmd, &pending_writer) else {
                    continue;
                };
                if *terminal_rx_writer.borrow() {
                    if let Some((_, tx)) = pending_writer.remove(&id) {
                        let _ = tx.send(Err(CdpError::ConnectionClosed));
                    }
                    break;
                }

                let write_result = tokio::select! {
                    biased;
                    _ = terminal_rx_writer.changed() => {
                        if let Some((_, tx)) = pending_writer.remove(&id) {
                            let _ = tx.send(Err(CdpError::ConnectionClosed));
                        }
                        break;
                    }
                    result = async {
                        writer.write_all(text.as_bytes()).await?;
                        writer.write_all(&[0]).await?;
                        writer.flush().await
                    } => result,
                };

                if let Err(error) = write_result {
                    error!("CDP pipe send error: {error}");
                    if let Some((_, tx)) = pending_writer.remove(&id) {
                        let _ = tx.send(Err(CdpError::WebSocket(format!(
                            "CDP pipe send error: {error}"
                        ))));
                    }
                    mark_terminal(&terminal_tx_writer, &pending_writer);
                    break;
                }
            }
            debug!("CDP pipe outbound writer exiting");
        });

        let pending_reader = Arc::clone(&client.pending);
        let event_tx_reader = client.event_tx.clone();
        let terminal_tx_reader = client.terminal_tx.clone();
        tokio::spawn(async move {
            let mut reader = BufReader::new(reader);
            let mut frame = Vec::new();

            loop {
                match read_pipe_frame(&mut reader, &mut frame, max_frame_size).await {
                    Ok(Some(())) => {
                        if let Err(error) =
                            dispatch_inbound(&frame, &pending_reader, &event_tx_reader)
                        {
                            warn!("CDP pipe parse error: {error}");
                            break;
                        }
                    }
                    Ok(None) => {
                        debug!("CDP pipe closed by peer");
                        break;
                    }
                    Err(error) => {
                        warn!("CDP pipe receive error: {error}");
                        break;
                    }
                }
            }

            debug!("CDP pipe inbound reader exiting");
            mark_terminal(&terminal_tx_reader, &pending_reader);
        });

        client
    }

    /// Subscribe to the broadcast stream of inbound CDP events.
    pub fn subscribe(&self) -> broadcast::Receiver<CdpEvent> {
        self.event_tx.subscribe()
    }

    pub(crate) fn subscribe_terminal(&self) -> watch::Receiver<bool> {
        self.terminal_tx.subscribe()
    }

    pub(crate) fn is_terminal(&self) -> bool {
        *self.terminal_tx.borrow()
    }

    pub(crate) async fn close_transport(&self) -> Result<(), CdpError> {
        self.sender
            .send(CdpTransportCommand::Close)
            .await
            .map_err(|_| CdpError::ConnectionClosed)
    }

    /// Create a root-level [`CdpSession`] (no session_id — targets the browser
    /// itself rather than a specific page target).
    pub fn root_session(self: &Arc<Self>) -> CdpSession {
        CdpSession::new(None, Arc::clone(self))
    }

    /// Send an outbound command and wait for the response.
    pub(crate) async fn send(
        &self,
        method: &str,
        params: Option<serde_json::Value>,
        session_id: Option<String>,
    ) -> Result<serde_json::Value, CdpError> {
        let mut terminal = self.subscribe_terminal();
        if *terminal.borrow() {
            return Err(CdpError::ConnectionClosed);
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (response_tx, response_rx) = oneshot::channel();

        let cmd = CdpOutbound {
            id,
            method: method.to_owned(),
            params,
            session_id,
            response_tx,
        };

        self.sender
            .send(CdpTransportCommand::Send(cmd))
            .await
            .map_err(|_| CdpError::ConnectionClosed)?;

        tokio::select! {
            biased;
            _ = terminal.changed() => Err(CdpError::ConnectionClosed),
            response = response_rx => response.map_err(|_| CdpError::ConnectionClosed)?,
        }
    }
}
