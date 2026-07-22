use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::time::Duration;

use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use tokio::sync::{broadcast, mpsc, oneshot, watch, Mutex};
use tokio::task::JoinHandle;
use tokio_tungstenite::{connect_async, tungstenite::Message};

use crate::bidi::{
    error::BiDiError,
    types::{BiDiEvent, BiDiOutbound},
};

type PendingMap = DashMap<u64, oneshot::Sender<Result<serde_json::Value, BiDiError>>>;

const TRANSPORT_CLOSE_TIMEOUT: Duration = Duration::from_secs(5);
const TRANSPORT_ABORT_TIMEOUT: Duration = Duration::from_secs(1);

struct TransportTasks {
    shutdown: Option<oneshot::Sender<()>>,
    sender: JoinHandle<Result<(), BiDiError>>,
    receiver: JoinHandle<Result<(), BiDiError>>,
}

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
    accepting_commands: AtomicBool,
    terminal_tx: watch::Sender<bool>,
    tasks: Mutex<Option<TransportTasks>>,
}

impl BiDiClient {
    /// Open a WebSocket connection to `ws_url` and start the I/O background task.
    pub async fn connect(ws_url: &str) -> Result<Arc<Self>, BiDiError> {
        let (ws_stream, _) = connect_async(ws_url)
            .await
            .map_err(|e| BiDiError::WebSocket(e.to_string()))?;

        let (mut ws_tx, mut ws_rx) = ws_stream.split();

        let (cmd_tx, mut cmd_rx) = mpsc::channel::<BiDiOutbound>(256);
        let (event_tx, _) = broadcast::channel::<BiDiEvent>(4096);
        let event_tx_clone = event_tx.clone();
        let (terminal_tx, _) = watch::channel(false);

        let pending: Arc<PendingMap> = Arc::new(DashMap::new());
        let pending_send = Arc::clone(&pending);
        let pending_recv = Arc::clone(&pending);
        let terminal_tx_send = terminal_tx.clone();
        let terminal_tx_recv = terminal_tx.clone();
        let mut sender_terminal_rx = terminal_tx.subscribe();
        let mut receiver_terminal_rx = terminal_tx.subscribe();
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

        // Sender task: forwards outbound commands to the WebSocket.
        let sender_task = tokio::spawn(async move {
            loop {
                let cmd = tokio::select! {
                    biased;
                    _ = &mut shutdown_rx => {
                        let close_result = ws_tx
                            .send(Message::Close(None))
                            .await
                            .map_err(|error| BiDiError::WebSocket(error.to_string()));
                        mark_terminal(&terminal_tx_send, &pending_send);
                        close_result?;
                        ws_tx
                            .close()
                            .await
                            .map_err(|error| BiDiError::WebSocket(error.to_string()))?;
                        break;
                    }
                    changed = sender_terminal_rx.changed() => {
                        if changed.is_err() || *sender_terminal_rx.borrow() {
                            break;
                        }
                        continue;
                    }
                    cmd = cmd_rx.recv() => match cmd {
                        Some(cmd) => cmd,
                        None => break,
                    },
                };
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
                    mark_terminal(&terminal_tx_send, &pending_send);
                    return Err(BiDiError::WebSocket(e.to_string()));
                }
            }
            mark_terminal(&terminal_tx_send, &pending_send);
            Ok(())
        });

        // Receiver task: routes incoming frames to callers or event broadcast.
        let receiver_task = tokio::spawn(async move {
            loop {
                let frame = tokio::select! {
                    biased;
                    changed = receiver_terminal_rx.changed() => {
                        if changed.is_err() || *receiver_terminal_rx.borrow() {
                            break;
                        }
                        continue;
                    }
                    frame = ws_rx.next() => match frame {
                        Some(frame) => frame,
                        None => break,
                    },
                };
                let text = match frame {
                    Ok(Message::Text(t)) => t,
                    Ok(Message::Close(_)) => break,
                    Err(error) => {
                        mark_terminal(&terminal_tx_recv, &pending_recv);
                        return Err(BiDiError::WebSocket(error.to_string()));
                    }
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
            mark_terminal(&terminal_tx_recv, &pending_recv);
            tracing::debug!("BiDi receiver task exited");
            Ok(())
        });

        Ok(Arc::new(Self {
            sender: cmd_tx,
            event_tx,
            next_id: AtomicU64::new(1),
            pending,
            accepting_commands: AtomicBool::new(true),
            terminal_tx,
            tasks: Mutex::new(Some(TransportTasks {
                shutdown: Some(shutdown_tx),
                sender: sender_task,
                receiver: receiver_task,
            })),
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
        if !self.accepting_commands.load(Ordering::Acquire)
            || *self.terminal_tx.borrow()
        {
            return Err(BiDiError::ConnectionClosed);
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (resp_tx, resp_rx) = oneshot::channel();

        // Register the pending response slot BEFORE sending to avoid a race where
        // the response arrives before we have a slot to put it in.
        self.pending.insert(id, resp_tx);

        if !self.accepting_commands.load(Ordering::Acquire)
            || *self.terminal_tx.borrow()
        {
            self.pending.remove(&id);
            return Err(BiDiError::ConnectionClosed);
        }

        let send_result = self
            .sender
            .send(BiDiOutbound {
                id,
                method: method.to_string(),
                params,
            })
            .await;
        if send_result.is_err() {
            self.pending.remove(&id);
            return Err(BiDiError::ConnectionClosed);
        }

        resp_rx.await.map_err(|_| BiDiError::ConnectionClosed)?
    }

    /// Send a WebSocket Close frame and wait for both transport tasks to stop.
    pub(crate) async fn close_transport(&self) -> Result<(), BiDiError> {
        self.close_transport_with_timeout(TRANSPORT_CLOSE_TIMEOUT).await
    }

    async fn close_transport_with_timeout(&self, timeout: Duration) -> Result<(), BiDiError> {
        self.accepting_commands.store(false, Ordering::Release);

        let Some(mut tasks) = self.tasks.lock().await.take() else {
            return Ok(());
        };

        if let Some(shutdown) = tasks.shutdown.take() {
            let _ = shutdown.send(());
        }

        let joined = tokio::time::timeout(timeout, async {
            let (sender, receiver) = tokio::join!(&mut tasks.sender, &mut tasks.receiver);
            task_result("sender", sender)?;
            task_result("receiver", receiver)
        })
        .await;

        match joined {
            Ok(result) => result,
            Err(_) => {
                tasks.sender.abort();
                tasks.receiver.abort();
                let _ = tokio::time::timeout(TRANSPORT_ABORT_TIMEOUT, async {
                    let _ = (&mut tasks.sender).await;
                    let _ = (&mut tasks.receiver).await;
                })
                .await;
                mark_terminal(&self.terminal_tx, &self.pending);
                Err(BiDiError::Timeout)
            }
        }
    }
}

fn mark_terminal(terminal_tx: &watch::Sender<bool>, pending: &PendingMap) {
    terminal_tx.send_replace(true);
    pending.clear();
}

fn task_result(
    name: &str,
    result: Result<Result<(), BiDiError>, tokio::task::JoinError>,
) -> Result<(), BiDiError> {
    match result {
        Ok(result) => result,
        Err(error) => Err(BiDiError::WebSocket(format!(
            "BiDi {name} task failed: {error}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use tokio_tungstenite::accept_async;

    #[tokio::test]
    async fn bidi_close_sends_close_and_rejects_pending_calls() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind BiDi test server");
        let address = listener.local_addr().expect("read BiDi test address");
        let (command_seen_tx, command_seen_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept BiDi client");
            let mut websocket = accept_async(stream).await.expect("accept WebSocket");

            let command = tokio::time::timeout(Duration::from_secs(1), websocket.next())
                .await
                .expect("BiDi command timed out")
                .expect("BiDi client disconnected before command")
                .expect("read BiDi command");
            assert!(matches!(command, Message::Text(_)));
            command_seen_tx.send(()).expect("report BiDi command");

            let close = tokio::time::timeout(Duration::from_secs(1), websocket.next())
                .await
                .expect("BiDi close frame timed out")
                .expect("BiDi client disconnected without Close")
                .expect("read BiDi close frame");
            assert!(matches!(close, Message::Close(_)));
        });

        let client = BiDiClient::connect(&format!("ws://{address}"))
            .await
            .expect("connect BiDi client");
        let pending_client = Arc::clone(&client);
        let pending = tokio::spawn(async move {
            pending_client
                .call("session.status", serde_json::json!({}))
                .await
        });

        tokio::time::timeout(Duration::from_secs(1), command_seen_rx)
            .await
            .expect("BiDi server did not receive command")
            .expect("BiDi server dropped command receipt");
        client
            .close_transport_with_timeout(Duration::from_secs(1))
            .await
            .expect("close BiDi transport");

        assert!(matches!(
            pending.await.expect("join pending call"),
            Err(BiDiError::ConnectionClosed)
        ));
        assert!(matches!(
            client.call("session.status", serde_json::json!({})).await,
            Err(BiDiError::ConnectionClosed)
        ));
        server.await.expect("join BiDi test server");
    }
}
