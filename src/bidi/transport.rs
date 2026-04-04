use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio_tungstenite::{connect_async, tungstenite::Message};

use crate::bidi::{
    error::BiDiError,
    types::{BiDiEvent, BiDiOutbound},
};

type PendingMap = DashMap<u64, oneshot::Sender<Result<serde_json::Value, BiDiError>>>;

/// A connected WebDriver BiDi client.
///
/// All commands are dispatched over a single WebSocket connection. Responses
/// are matched to outstanding callers via the numeric `id` field. Events (no
/// `id`) are broadcast to all subscribers.
pub struct BiDiClient {
    sender: mpsc::Sender<BiDiOutbound>,
    event_tx: broadcast::Sender<BiDiEvent>,
    next_id: AtomicU64,
    pending: Arc<PendingMap>,
}

impl BiDiClient {
    /// Open a WebSocket connection to `ws_url` and start the I/O background task.
    pub async fn connect(ws_url: &str) -> Result<Arc<Self>, BiDiError> {
        let (ws_stream, _) = connect_async(ws_url)
            .await
            .map_err(|e| BiDiError::WebSocket(e.to_string()))?;

        let (mut ws_tx, mut ws_rx) = ws_stream.split();

        let (cmd_tx, mut cmd_rx) = mpsc::channel::<BiDiOutbound>(256);
        let (event_tx, _) = broadcast::channel::<BiDiEvent>(256);
        let event_tx_clone = event_tx.clone();

        let pending: Arc<PendingMap> = Arc::new(DashMap::new());
        let pending_recv = Arc::clone(&pending);

        // Sender task: forwards outbound commands to the WebSocket.
        tokio::spawn(async move {
            while let Some(cmd) = cmd_rx.recv().await {
                let msg = serde_json::json!({
                    "id": cmd.id,
                    "method": cmd.method,
                    "params": cmd.params,
                });
                let text = match serde_json::to_string(&msg) {
                    Ok(t) => t,
                    Err(e) => {
                        tracing::error!("BiDi serialize error: {e}");
                        continue;
                    }
                };
                if let Err(e) = ws_tx.send(Message::Text(text.into())).await {
                    tracing::error!("BiDi ws send error: {e}");
                    break;
                }
            }
        });

        // Receiver task: routes incoming frames to callers or event broadcast.
        tokio::spawn(async move {
            while let Some(frame) = ws_rx.next().await {
                let text = match frame {
                    Ok(Message::Text(t)) => t,
                    Ok(Message::Close(_)) | Err(_) => break,
                    _ => continue,
                };

                let val: serde_json::Value = match serde_json::from_str(&text) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!("BiDi parse error: {e}");
                        continue;
                    }
                };

                if let Some(id) = val.get("id").and_then(|v| v.as_u64()) {
                    // Command response.
                    if let Some((_, tx)) = pending_recv.remove(&id) {
                        let result = if let Some(err) = val.get("error") {
                            Err(BiDiError::Protocol {
                                error: err.as_str().unwrap_or("unknown").to_string(),
                                message: val
                                    .get("message")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                            })
                        } else {
                            Ok(val
                                .get("result")
                                .cloned()
                                .unwrap_or(serde_json::Value::Null))
                        };
                        let _ = tx.send(result);
                    }
                } else if let Some(method) = val.get("method").and_then(|v| v.as_str()) {
                    // Unsolicited event.
                    let event = BiDiEvent {
                        method: method.to_string(),
                        params: val
                            .get("params")
                            .cloned()
                            .unwrap_or(serde_json::Value::Null),
                    };
                    let _ = event_tx_clone.send(event);
                }
            }
            tracing::debug!("BiDi receiver task exited");
        });

        Ok(Arc::new(Self {
            sender: cmd_tx,
            event_tx,
            next_id: AtomicU64::new(1),
            pending,
        }))
    }

    /// Subscribe to all unsolicited BiDi events.
    pub fn subscribe(&self) -> broadcast::Receiver<BiDiEvent> {
        self.event_tx.subscribe()
    }

    /// Send a BiDi command and await its response.
    pub async fn call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, BiDiError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (resp_tx, resp_rx) = oneshot::channel();

        // Register the pending response slot BEFORE sending to avoid a race where
        // the response arrives before we have a slot to put it in.
        self.pending.insert(id, resp_tx);

        if let Err(_) = self
            .sender
            .send(BiDiOutbound {
                id,
                method: method.to_string(),
                params,
            })
            .await
        {
            self.pending.remove(&id);
            return Err(BiDiError::ConnectionClosed);
        }

        resp_rx.await.map_err(|_| BiDiError::ConnectionClosed)?
    }
}
