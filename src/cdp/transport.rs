//! Core WebSocket transport — connects to a Chrome DevTools endpoint and
//! multiplexes commands / events over a single connection.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{debug, error, warn};

use crate::cdp::error::CdpError;
use crate::cdp::session::CdpSession;
use crate::cdp::types::{CdpEvent, CdpInbound, CdpOutbound, CdpOutboundFrame};

/// Broadcast channel capacity for inbound CDP events.
const EVENT_CHANNEL_CAPACITY: usize = 256;
/// Outbound mpsc channel capacity.
const OUTBOUND_CHANNEL_CAPACITY: usize = 128;

/// A multiplexed CDP WebSocket client.
///
/// Cloning / sharing is done via `Arc<CdpClient>`. Multiple [`CdpSession`]
/// handles can share the same underlying connection.
pub struct CdpClient {
    sender: mpsc::Sender<CdpOutbound>,
    event_tx: broadcast::Sender<CdpEvent>,
    next_id: AtomicU64,
    pending: Arc<DashMap<u64, oneshot::Sender<Result<serde_json::Value, CdpError>>>>,
}

impl CdpClient {
    /// Connect to a CDP WebSocket endpoint (e.g. `ws://localhost:9222/json/...`).
    pub async fn connect(ws_url: &str) -> Result<Arc<Self>, CdpError> {
        let (ws_stream, _) = connect_async(ws_url)
            .await
            .map_err(|e| CdpError::WebSocket(e.to_string()))?;

        let (mut ws_sink, mut ws_source) = ws_stream.split();

        let (event_tx, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        let (outbound_tx, mut outbound_rx) = mpsc::channel::<CdpOutbound>(OUTBOUND_CHANNEL_CAPACITY);
        let pending: Arc<DashMap<u64, oneshot::Sender<Result<serde_json::Value, CdpError>>>> =
            Arc::new(DashMap::new());

        let client = Arc::new(CdpClient {
            sender: outbound_tx,
            event_tx: event_tx.clone(),
            next_id: AtomicU64::new(1),
            pending: pending.clone(),
        });

        // ── outbound writer task ──────────────────────────────────────────────
        tokio::spawn(async move {
            while let Some(cmd) = outbound_rx.recv().await {
                let frame = CdpOutboundFrame::from(&cmd);
                let text = match serde_json::to_string(&frame) {
                    Ok(t) => t,
                    Err(e) => {
                        error!("CDP serialize error: {e}");
                        let _ = cmd.response_tx.send(Err(CdpError::Json(e)));
                        continue;
                    }
                };
                pending.insert(
                    cmd.id,
                    cmd.response_tx,
                );
                if let Err(e) = ws_sink.send(Message::Text(text.into())).await {
                    error!("CDP ws send error: {e}");
                    // Remove the pending entry and report failure.
                    if let Some((_, tx)) = pending.remove(&cmd.id) {
                        let _ = tx.send(Err(CdpError::WebSocket(e.to_string())));
                    }
                }
            }
            debug!("CDP outbound writer exiting");
        });

        // ── inbound reader task ───────────────────────────────────────────────
        let pending_reader = Arc::clone(&client.pending);
        let event_tx_reader = event_tx.clone();
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
                        // Wake all pending requests with ConnectionClosed.
                        pending_reader.retain(|_, tx| {
                            // `retain` keeps entries where closure returns true.
                            // We want to drain all — send and remove.
                            // We can't move `tx` out of a shared ref in `retain`,
                            // so we use a workaround: collect keys first.
                            let _ = tx; // satisfy borrow checker below via separate drain
                            false
                        });
                        break;
                    }
                    Ok(_) => continue,
                    Err(e) => {
                        error!("CDP ws recv error: {e}");
                        break;
                    }
                };

                let inbound: CdpInbound = match serde_json::from_str(&raw) {
                    Ok(v) => v,
                    Err(e) => {
                        warn!("CDP parse error ({e}): {raw}");
                        continue;
                    }
                };

                if let Some(id) = inbound.id {
                    // This is a response to a pending command.
                    if let Some((_, tx)) = pending_reader.remove(&id) {
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
                    // This is an event.
                    let event = CdpEvent {
                        method,
                        params: inbound.params,
                        session_id: inbound.session_id,
                    };
                    // Ignore send errors — no active subscribers is fine.
                    let _ = event_tx_reader.send(event);
                }
            }

            debug!("CDP inbound reader exiting");
            // Drain remaining pending entries.
            pending_reader.retain(|_, _| false);
        });

        Ok(client)
    }

    /// Subscribe to the broadcast stream of inbound CDP events.
    pub fn subscribe(&self) -> broadcast::Receiver<CdpEvent> {
        self.event_tx.subscribe()
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
            .send(cmd)
            .await
            .map_err(|_| CdpError::ConnectionClosed)?;

        response_rx.await.map_err(|_| CdpError::ConnectionClosed)?
    }
}
