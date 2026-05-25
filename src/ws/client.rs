//! WS client core — connect, send subscribe frames, dispatch inbound messages.
//!
//! The connection is managed by a background tokio task spawned by
//! [`WsClient::connect`]. The task:
//!
//! 1. Opens a `wss://` connection.
//! 2. Re-issues every active subscription on reconnect.
//! 3. Sends `ping` frames at the configured interval.
//! 4. Forwards inbound channel frames to the user via the
//!    `tokio::sync::broadcast` channel exposed by [`WsClient::messages`].
//!
//! On disconnect it reconnects with exponential backoff (capped). The user
//! task continues to consume the broadcast — they will see new frames once
//! reconnection succeeds.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use tokio::sync::{Mutex, broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message;

use crate::error::ClientError;
use crate::ws::subscriptions::{Subscription, WsMessage};

/// Tunable WS configuration.
#[derive(Clone, Debug)]
pub struct WsConfig {
    /// Heartbeat interval. Default: 30 seconds.
    pub ping_interval: Duration,
    /// Initial backoff after first disconnect. Default: 250 ms.
    pub initial_backoff: Duration,
    /// Cap on backoff between reconnect attempts. Default: 30 seconds.
    pub max_backoff: Duration,
    /// Capacity of the inbound message broadcast channel. Default: 1024.
    pub channel_capacity: usize,
}

impl Default for WsConfig {
    fn default() -> Self {
        Self {
            ping_interval: Duration::from_secs(30),
            initial_backoff: Duration::from_millis(250),
            max_backoff: Duration::from_secs(30),
            channel_capacity: 1024,
        }
    }
}

/// Internal control-plane commands to the background task.
#[derive(Debug)]
enum Command {
    Subscribe(Subscription),
    Unsubscribe(Subscription),
    Shutdown,
}

/// Connected WebSocket client.
///
/// Cheap to clone — wraps `Arc`/channels internally. Drop the last clone to
/// trigger shutdown.
#[derive(Debug, Clone)]
pub struct WsClient {
    /// Inbound message broadcast.
    inbound_tx: broadcast::Sender<WsMessage>,
    /// Control-plane channel to the background task.
    cmd_tx: mpsc::UnboundedSender<Command>,
    /// Connection state flag (true while the background loop is running).
    alive: Arc<AtomicBool>,
    /// Active subscriptions; replayed on reconnect.
    active: Arc<Mutex<Vec<Subscription>>>,
}

impl WsClient {
    /// Connect to a WS endpoint with the default configuration.
    ///
    /// `url` should be a `wss://...` URL. Returns a [`WsClient`] handle as
    /// soon as the initial connect succeeds.
    ///
    /// # Errors
    /// [`ClientError::WebSocket`] on initial connect failure.
    pub async fn connect(url: impl Into<String>) -> Result<Self, ClientError> {
        Self::connect_with(url, WsConfig::default()).await
    }

    /// Connect with a custom [`WsConfig`].
    ///
    /// # Errors
    /// See [`WsClient::connect`].
    pub async fn connect_with(
        url: impl Into<String>,
        config: WsConfig,
    ) -> Result<Self, ClientError> {
        let url = url.into();
        let (inbound_tx, _) = broadcast::channel(config.channel_capacity);
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let alive = Arc::new(AtomicBool::new(true));
        let active: Arc<Mutex<Vec<Subscription>>> = Arc::new(Mutex::new(Vec::new()));

        // Quick connect-then-drop to validate the URL up front; the
        // background task will reconnect from scratch.
        let (probe, _) = tokio_tungstenite::connect_async(&url).await?;
        drop(probe);

        let task_state = TaskState {
            url,
            config,
            inbound_tx: inbound_tx.clone(),
            cmd_rx,
            alive: alive.clone(),
            active: active.clone(),
        };
        let _handle: JoinHandle<()> = tokio::spawn(run_background(task_state));

        Ok(Self {
            inbound_tx,
            cmd_tx,
            alive,
            active,
        })
    }

    /// Subscribe a stream. The channel is replayed on reconnect.
    ///
    /// # Errors
    /// [`ClientError::WebSocket`] if the background task is gone.
    pub async fn subscribe(&self, sub: Subscription) -> Result<(), ClientError> {
        {
            let mut g = self.active.lock().await;
            if !g.contains(&sub) {
                g.push(sub.clone());
            }
        }
        self.cmd_tx
            .send(Command::Subscribe(sub))
            .map_err(|_| ClientError::WebSocket("ws task is dead".into()))?;
        Ok(())
    }

    /// Unsubscribe a stream.
    ///
    /// # Errors
    /// [`ClientError::WebSocket`] if the background task is gone.
    pub async fn unsubscribe(&self, sub: Subscription) -> Result<(), ClientError> {
        {
            let mut g = self.active.lock().await;
            g.retain(|s| s != &sub);
        }
        self.cmd_tx
            .send(Command::Unsubscribe(sub))
            .map_err(|_| ClientError::WebSocket("ws task is dead".into()))?;
        Ok(())
    }

    /// Subscribe to L2 book updates for a market. Convenience wrapper.
    ///
    /// # Errors
    /// See [`WsClient::subscribe`].
    pub async fn subscribe_l2_book(
        &self,
        market: crate::types::MarketId,
    ) -> Result<(), ClientError> {
        self.subscribe(Subscription::L2Book { market_id: market })
            .await
    }

    /// Subscribe to public trades for a market.
    ///
    /// # Errors
    /// See [`WsClient::subscribe`].
    pub async fn subscribe_trades(
        &self,
        market: crate::types::MarketId,
    ) -> Result<(), ClientError> {
        self.subscribe(Subscription::Trades { market_id: market })
            .await
    }

    /// Subscribe to per-user fills.
    ///
    /// # Errors
    /// See [`WsClient::subscribe`].
    pub async fn subscribe_user_fills(
        &self,
        addr: crate::wallet::Address,
    ) -> Result<(), ClientError> {
        self.subscribe(Subscription::UserFills { address: addr })
            .await
    }

    /// Subscribe to vault NAV updates.
    ///
    /// # Errors
    /// See [`WsClient::subscribe`].
    pub async fn subscribe_vault_nav(
        &self,
        vault_id: crate::types::VaultId,
    ) -> Result<(), ClientError> {
        self.subscribe(Subscription::VaultNav { vault_id }).await
    }

    /// Receive inbound channel frames.
    ///
    /// Each call returns a fresh [`broadcast::Receiver`] so multiple consumers
    /// can subscribe to the same stream. Returns `None` once the task has
    /// shut down.
    #[must_use]
    pub fn messages(&self) -> broadcast::Receiver<WsMessage> {
        self.inbound_tx.subscribe()
    }

    /// True if the background reconnect task is still running.
    #[must_use]
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }

    /// Initiate a graceful shutdown of the background task. Subsequent
    /// `subscribe` calls will fail.
    pub async fn shutdown(&self) {
        let _ = self.cmd_tx.send(Command::Shutdown);
        self.alive.store(false, Ordering::Release);
    }
}

/// Internal task state.
struct TaskState {
    url: String,
    config: WsConfig,
    inbound_tx: broadcast::Sender<WsMessage>,
    cmd_rx: mpsc::UnboundedReceiver<Command>,
    alive: Arc<AtomicBool>,
    active: Arc<Mutex<Vec<Subscription>>>,
}

/// The reconnect-with-backoff loop.
async fn run_background(mut state: TaskState) {
    let mut backoff = state.config.initial_backoff;
    loop {
        match run_connection(&mut state).await {
            Ok(ConnectionExit::Shutdown) => break,
            Ok(ConnectionExit::Recoverable) | Err(_) => {
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(state.config.max_backoff);
                // continue loop -> reconnect
            }
        }
    }
    state.alive.store(false, Ordering::Release);
}

/// Outcome of one connection's lifetime.
#[derive(Debug)]
enum ConnectionExit {
    /// User asked to stop; do not reconnect.
    Shutdown,
    /// Connection dropped / errored; reconnect with backoff.
    Recoverable,
}

async fn run_connection(state: &mut TaskState) -> Result<ConnectionExit, ClientError> {
    let (stream, _) = tokio_tungstenite::connect_async(&state.url).await?;
    let (mut sink, mut stream) = stream.split();

    // Replay active subscriptions on (re)connect.
    {
        let subs = state.active.lock().await.clone();
        for sub in &subs {
            let frame = json!({"method": "subscribe", "subscription": sub});
            sink.send(Message::Text(frame.to_string())).await?;
        }
    }

    let mut ping_tick = tokio::time::interval(state.config.ping_interval);
    ping_tick.tick().await; // consume the immediate first tick

    loop {
        tokio::select! {
            cmd = state.cmd_rx.recv() => {
                match cmd {
                    Some(Command::Subscribe(sub)) => {
                        let frame = json!({"method": "subscribe", "subscription": sub});
                        sink.send(Message::Text(frame.to_string())).await?;
                    }
                    Some(Command::Unsubscribe(sub)) => {
                        let frame = json!({"method": "unsubscribe", "subscription": sub});
                        sink.send(Message::Text(frame.to_string())).await?;
                    }
                    Some(Command::Shutdown) | None => {
                        let _ = sink.send(Message::Close(None)).await;
                        return Ok(ConnectionExit::Shutdown);
                    }
                }
            }
            _ = ping_tick.tick() => {
                let ping = json!({"method": "ping"});
                if sink.send(Message::Text(ping.to_string())).await.is_err() {
                    return Ok(ConnectionExit::Recoverable);
                }
            }
            frame = stream.next() => {
                let Some(frame) = frame else {
                    return Ok(ConnectionExit::Recoverable);
                };
                match frame {
                    Ok(Message::Text(text)) => {
                        if let Ok(msg) = serde_json::from_str::<WsMessage>(&text) {
                            let _ = state.inbound_tx.send(msg);
                        }
                    }
                    Ok(Message::Binary(_) | Message::Pong(_) | Message::Ping(_)) => {
                        // Ignore non-text control frames; tungstenite handles
                        // pong automatically for ping.
                    }
                    Ok(Message::Close(_)) => {
                        return Ok(ConnectionExit::Recoverable);
                    }
                    Ok(Message::Frame(_)) => {
                        // Raw frame — ignore.
                    }
                    Err(_) => return Ok(ConnectionExit::Recoverable),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ws_config_default_values() {
        let c = WsConfig::default();
        assert_eq!(c.ping_interval, Duration::from_secs(30));
        assert_eq!(c.initial_backoff, Duration::from_millis(250));
        assert_eq!(c.max_backoff, Duration::from_secs(30));
        assert_eq!(c.channel_capacity, 1024);
    }
}
