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

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::sync::{Mutex, broadcast, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message;

use crate::error::ClientError;
use crate::types::order::{CancelOrder, Order, OrderResponse};
use crate::wallet::{TypedTradingAction, TypedTradingDigest, Wallet};
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
    /// How long a `post` request waits for its correlated response before
    /// failing with [`ClientError::WebSocket`]. Default: 10 seconds.
    pub post_timeout: Duration,
}

impl Default for WsConfig {
    fn default() -> Self {
        Self {
            ping_interval: Duration::from_secs(30),
            initial_backoff: Duration::from_millis(250),
            max_backoff: Duration::from_secs(30),
            channel_capacity: 1024,
            post_timeout: Duration::from_secs(10),
        }
    }
}

/// Internal control-plane commands to the background task.
#[derive(Debug)]
enum Command {
    Subscribe(Subscription),
    Unsubscribe(Subscription),
    /// A correlated `post` request: the pre-serialized frame plus a one-shot
    /// channel the background task completes with the matching `response`
    /// object (`{type, payload}`) once the `{channel:"post"}` frame arrives.
    Post {
        id: u64,
        frame: String,
        reply: oneshot::Sender<Value>,
    },
    /// Drop a pending `post` whose caller gave up (timed out) so its entry
    /// doesn't linger in the correlation map for the life of the connection.
    CancelPost {
        id: u64,
    },
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
    /// Monotonic id source for `post` request/response correlation.
    post_id: Arc<AtomicU64>,
    /// Per-request timeout for `post` calls.
    post_timeout: Duration,
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
        let post_timeout = config.post_timeout;

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
            post_id: Arc::new(AtomicU64::new(1)),
            post_timeout,
        })
    }

    /// Subscribe a stream. The channel is replayed on reconnect.
    ///
    /// # Errors
    /// [`ClientError::WebSocket`] if the background task is gone.
    pub async fn subscribe(&self, sub: Subscription) -> Result<(), ClientError> {
        {
            let mut g = self.active.lock().await;
            if let Subscription::L2Book { coin, .. } = &sub {
                // The server holds ONE l2_book view per coin and REPLACES it when
                // the coin is re-subscribed with different aggregation params.
                // Drop any prior l2_book entry for this coin so reconnect-replay
                // can't resurrect stale params and clobber the new view.
                let coin = coin.clone();
                g.retain(|s| !l2_book_is_coin(s, &coin));
                g.push(sub.clone());
            } else if !g.contains(&sub) {
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
            if let Subscription::L2Book { coin, .. } = &sub {
                // Server unsubscribe is keyed by coin WITHOUT params — drop the
                // active l2_book entry for this coin regardless of its params.
                let coin = coin.clone();
                g.retain(|s| !l2_book_is_coin(s, &coin));
            } else {
                g.retain(|s| s != &sub);
            }
        }
        self.cmd_tx
            .send(Command::Unsubscribe(sub))
            .map_err(|_| ClientError::WebSocket("ws task is dead".into()))?;
        Ok(())
    }

    /// Subscribe to L2 book updates for a market. Convenience wrapper (full,
    /// ungrouped book). For a spot pair or aggregated depth use
    /// [`WsClient::subscribe_l2_book_coin`].
    ///
    /// # Errors
    /// See [`WsClient::subscribe`].
    pub async fn subscribe_l2_book(
        &self,
        market: crate::types::MarketId,
    ) -> Result<(), ClientError> {
        self.subscribe(Subscription::L2Book {
            coin: market.0.to_string(),
            n_sig_figs: None,
            mantissa: None,
            n_levels: None,
        })
        .await
    }

    /// Subscribe to L2 book updates by raw `coin` (a perp asset-id string or a
    /// spot pair — name `"BTC/USDC"` or the pair-id string), with optional
    /// deterministic away-from-spread aggregation ([`L2BookParams`]).
    ///
    /// Re-subscribing the same coin with different params REPLACES the view
    /// (the server holds one l2_book view per coin per connection); the active
    /// set keeps at most one l2_book entry per coin so reconnect-replay stays
    /// honest.
    ///
    /// # Errors
    /// See [`WsClient::subscribe`].
    pub async fn subscribe_l2_book_coin(
        &self,
        coin: impl Into<String>,
        params: Option<crate::rest::info::L2BookParams>,
    ) -> Result<(), ClientError> {
        let p = params.unwrap_or_default();
        self.subscribe(Subscription::L2Book {
            coin: coin.into(),
            n_sig_figs: p.n_sig_figs,
            mantissa: p.mantissa,
            n_levels: p.n_levels,
        })
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
        self.subscribe(Subscription::Trades {
            coin: market.0.to_string(),
        })
        .await
    }

    /// Subscribe to best-bid-best-offer ticks for a market.
    ///
    /// # Errors
    /// See [`WsClient::subscribe`].
    pub async fn subscribe_bbo(&self, market: crate::types::MarketId) -> Result<(), ClientError> {
        self.subscribe(Subscription::Bbo {
            coin: market.0.to_string(),
        })
        .await
    }

    /// Subscribe to per-market mark / oracle / funding context.
    ///
    /// # Errors
    /// See [`WsClient::subscribe`].
    pub async fn subscribe_active_asset_ctx(
        &self,
        market: crate::types::MarketId,
    ) -> Result<(), ClientError> {
        self.subscribe(Subscription::ActiveAssetCtx {
            coin: market.0.to_string(),
        })
        .await
    }

    /// Subscribe to OHLCV candles for a market + interval token
    /// (`"1m"`/`"5m"`/`"15m"`/`"1h"`/`"4h"`/`"1d"`).
    ///
    /// # Errors
    /// See [`WsClient::subscribe`].
    pub async fn subscribe_candles(
        &self,
        market: crate::types::MarketId,
        interval: impl Into<String>,
    ) -> Result<(), ClientError> {
        self.subscribe(Subscription::Candles {
            coin: market.0.to_string(),
            interval: interval.into(),
        })
        .await
    }

    /// Subscribe to the global all-market mids stream.
    ///
    /// # Errors
    /// See [`WsClient::subscribe`].
    pub async fn subscribe_all_mids(&self) -> Result<(), ClientError> {
        self.subscribe(Subscription::AllMids).await
    }

    /// Subscribe to per-user fills.
    ///
    /// # Errors
    /// See [`WsClient::subscribe`].
    pub async fn subscribe_fills(&self, user: crate::wallet::Address) -> Result<(), ClientError> {
        self.subscribe(Subscription::Fills { user }).await
    }

    /// Subscribe to per-user order lifecycle updates.
    ///
    /// # Errors
    /// See [`WsClient::subscribe`].
    pub async fn subscribe_order_updates(
        &self,
        user: crate::wallet::Address,
    ) -> Result<(), ClientError> {
        self.subscribe(Subscription::OrderUpdates { user }).await
    }

    /// Subscribe to per-user account / margin events.
    ///
    /// # Errors
    /// See [`WsClient::subscribe`].
    pub async fn subscribe_user_events(
        &self,
        user: crate::wallet::Address,
    ) -> Result<(), ClientError> {
        self.subscribe(Subscription::UserEvents { user }).await
    }

    /// Subscribe to the per-user live account-state stream.
    ///
    /// # Errors
    /// See [`WsClient::subscribe`].
    pub async fn subscribe_account_state(
        &self,
        user: crate::wallet::Address,
    ) -> Result<(), ClientError> {
        self.subscribe(Subscription::AccountState { user }).await
    }

    /// Subscribe to the per-user live spot clearinghouse-state stream.
    ///
    /// # Errors
    /// See [`WsClient::subscribe`].
    pub async fn subscribe_spot_state(
        &self,
        user: crate::wallet::Address,
    ) -> Result<(), ClientError> {
        self.subscribe(Subscription::SpotState { user }).await
    }

    /// Subscribe to per-user realized funding payments.
    ///
    /// # Errors
    /// See [`WsClient::subscribe`].
    pub async fn subscribe_user_fundings(
        &self,
        user: crate::wallet::Address,
    ) -> Result<(), ClientError> {
        self.subscribe(Subscription::UserFundings { user }).await
    }

    /// Subscribe to the global explorer block-header stream.
    ///
    /// # Errors
    /// See [`WsClient::subscribe`].
    pub async fn subscribe_explorer_block(&self) -> Result<(), ClientError> {
        self.subscribe(Subscription::ExplorerBlock).await
    }

    /// Subscribe to the global explorer transaction stream (each row carries a
    /// 0x action `hash`).
    ///
    /// # Errors
    /// See [`WsClient::subscribe`].
    pub async fn subscribe_explorer_txs(&self) -> Result<(), ClientError> {
        self.subscribe(Subscription::ExplorerTxs).await
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

    // ---- `post` request/response (HL `post` method) ----

    /// Issue a signed exchange action over the WebSocket `post` channel,
    /// returning the node's action response payload.
    ///
    /// This is the WS analogue of [`crate::rest::exchange::Exchange::post_signed`]: the
    /// action is signed with the SAME EIP-712 digest (recovered over the
    /// compact JSON of the action object), wrapped as
    /// `{"method":"post","id":N,"request":{"type":"action","payload":{signature,nonce,action}}}`,
    /// and sent over the existing connection. The returned `Value` is the
    /// `payload` of the node's `action` response (e.g. `{"accepted":true,…}`);
    /// a malformed-request rejection surfaces as [`ClientError::WebSocket`].
    ///
    /// # Errors
    /// - [`ClientError::Signature`] on signing failure.
    /// - [`ClientError::WebSocket`] if the socket is down, the post times out,
    ///   or the node returns a post-level error frame.
    pub async fn post_action(&self, wallet: &Wallet, action: Value) -> Result<Value, ClientError> {
        let (nonce, signature) = crate::rest::exchange::sign_action(wallet, &action)?;
        let payload = json!({ "signature": signature, "nonce": nonce, "action": action });
        self.post_request("action", payload).await
    }

    /// Issue a TRADING action (order / cancel / …) over the WS `post` channel,
    /// signed under the typed scheme. The 12 trading actions migrated to the
    /// typed scheme (the node rejects them under the opaque envelope), so the WS
    /// `post` path posts to the typed-only `/exchange` alongside the structured digest.
    async fn post_typed_trade(
        &self,
        wallet: &Wallet,
        action: Value,
        typed: TypedTradingAction<'_>,
    ) -> Result<Value, ClientError> {
        let nonce = crate::rest::exchange::next_nonce();
        let digest =
            TypedTradingDigest::new(typed, crate::rest::exchange::MTF_CHAIN_ID, nonce).digest()?;
        let signature = wallet.sign_digest(&digest)?.to_hex();
        let payload = json!({
            "signature": signature,
            "nonce": nonce,
            "action": action,
        });
        self.post_request("action", payload).await
    }

    /// Issue an `info` read over the WebSocket `post` channel, returning the
    /// info response payload.
    ///
    /// The WS analogue of a `POST /info` call: `payload` is the usual
    /// `{"type":"<info>",…}` body. Lets a subscriber multiplex one-off reads
    /// over the same socket instead of opening a REST connection.
    ///
    /// # Errors
    /// [`ClientError::WebSocket`] if the socket is down, the post times out, or
    /// the node returns a post-level error frame.
    pub async fn post_info(&self, payload: Value) -> Result<Value, ClientError> {
        self.post_request("info", payload).await
    }

    /// Submit a limit / market / trigger order over the WS `post` channel,
    /// decoding the typed [`OrderResponse`].
    ///
    /// Convenience wrapper over [`Self::post_action`] mirroring
    /// [`crate::rest::exchange::Exchange::submit_order`]. The order's `owner` MUST equal
    /// the wallet address.
    ///
    /// # Errors
    /// - [`ClientError::Validation`] if `order.owner != wallet.address()`.
    /// - [`ClientError::Decode`] if the response payload is not an
    ///   [`OrderResponse`].
    /// - WebSocket / signature errors per [`Self::post_action`].
    pub async fn submit_order(
        &self,
        wallet: &Wallet,
        order: &Order,
    ) -> Result<OrderResponse, ClientError> {
        if order.owner != wallet.address() {
            return Err(ClientError::Validation(format!(
                "order.owner {} != wallet address {}",
                order.owner,
                wallet.address()
            )));
        }
        // Coerce a Market order's tif to IOC before signing (a Market+Gtc/Alo
        // would silently REST on the book); see `Order::coerce_market_tif`.
        let order = order.market_tif_coerced();
        let action = json!({ "type": "submit_order", "order": &order });
        let payload = self
            .post_typed_trade(wallet, action, TypedTradingAction::SubmitOrder(&order))
            .await?;
        Ok(serde_json::from_value(payload)?)
    }

    /// Cancel an order over the WS `post` channel.
    ///
    /// Convenience wrapper over [`Self::post_action`] mirroring
    /// [`crate::rest::exchange::Exchange::cancel_order`].
    ///
    /// # Errors
    /// - [`ClientError::Validation`] if `cancel.owner != wallet.address()`.
    /// - WebSocket / signature errors per [`Self::post_action`].
    pub async fn cancel_order(
        &self,
        wallet: &Wallet,
        cancel: &CancelOrder,
    ) -> Result<Value, ClientError> {
        if cancel.owner != wallet.address() {
            return Err(ClientError::Validation(format!(
                "cancel.owner {} != wallet address {}",
                cancel.owner,
                wallet.address()
            )));
        }
        let action = json!({ "type": "cancel_order", "cancel": cancel });
        self.post_typed_trade(wallet, action, TypedTradingAction::CancelOrder(cancel))
            .await
    }

    /// Core `post` machinery: assign a correlation id, ship the frame to the
    /// background task, and await the matching response. Maps a node
    /// `{"type":"error",…}` response to [`ClientError::WebSocket`]; returns the
    /// inner `payload` on success.
    async fn post_request(&self, request_type: &str, payload: Value) -> Result<Value, ClientError> {
        let id = self.post_id.fetch_add(1, Ordering::Relaxed);
        let frame = json!({
            "method": "post",
            "id": id,
            "request": { "type": request_type, "payload": payload },
        })
        .to_string();

        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::Post {
                id,
                frame,
                reply: reply_tx,
            })
            .map_err(|_| ClientError::WebSocket("ws task is dead".into()))?;

        let response = match tokio::time::timeout(self.post_timeout, reply_rx).await {
            Ok(Ok(resp)) => resp,
            // Sender dropped => the connection cycled before the response
            // arrived. A signed action is one-shot, so we surface the failure
            // rather than silently retrying (which could double-submit).
            Ok(Err(_)) => {
                return Err(ClientError::WebSocket(
                    "ws post: connection closed before response".into(),
                ));
            }
            Err(_) => {
                // We gave up waiting; tell the background task to evict the
                // pending entry so it can't leak on a long-lived connection.
                // Best-effort: if the task is gone the entry dies with it.
                let _ = self.cmd_tx.send(Command::CancelPost { id });
                return Err(ClientError::WebSocket("ws post: timed out".into()));
            }
        };

        // The node wraps every reply as `{type, payload}`; an error reply
        // carries the message as a string payload.
        if response.get("type").and_then(Value::as_str) == Some("error") {
            let msg = response
                .get("payload")
                .and_then(Value::as_str)
                .unwrap_or("unknown post error");
            return Err(ClientError::WebSocket(format!("ws post error: {msg}")));
        }
        Ok(response.get("payload").cloned().unwrap_or(Value::Null))
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

/// True when `sub` is an `L2Book` subscription for `coin`, IGNORING its
/// aggregation params. Used to enforce the server's one-view-per-coin l2_book
/// semantics in the active set (replace on re-subscribe, param-blind unsubscribe).
fn l2_book_is_coin(sub: &Subscription, coin: &str) -> bool {
    matches!(sub, Subscription::L2Book { coin: c, .. } if c.as_str() == coin)
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

    // In-flight `post` requests for this connection, keyed by correlation id.
    // Dropped (with all reply senders) when the connection exits, so any
    // caller awaiting a response on a dead socket unblocks with an error.
    let mut pending: HashMap<u64, oneshot::Sender<Value>> = HashMap::new();

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
                    Some(Command::Post { id, frame, reply }) => {
                        // Send first; only track the reply once the frame is on
                        // the wire. A send failure propagates `Err` out of
                        // `run_connection` (which `run_background` treats as a
                        // recoverable reconnect) and drops `reply`, surfacing a
                        // disconnect to the caller.
                        sink.send(Message::Text(frame)).await?;
                        pending.insert(id, reply);
                    }
                    Some(Command::CancelPost { id }) => {
                        // Caller timed out; drop the dangling reply sender.
                        pending.remove(&id);
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
                        // A `{channel:"post"}` frame correlates by id back to the
                        // waiting caller; every other frame is a channel update
                        // for the broadcast.
                        match serde_json::from_str::<Value>(&text) {
                            Ok(v)
                                if v.get("channel").and_then(Value::as_str) == Some("post") =>
                            {
                                if let Some(id) =
                                    v.pointer("/data/id").and_then(Value::as_u64)
                                {
                                    if let Some(reply) = pending.remove(&id) {
                                        let resp = v
                                            .pointer("/data/response")
                                            .cloned()
                                            .unwrap_or(Value::Null);
                                        let _ = reply.send(resp);
                                    }
                                }
                            }
                            Ok(v) => {
                                // Unknown / future channels (and any frame whose
                                // `data` we can't type) fall back to `Unknown`
                                // instead of being dropped, so a forward-compat
                                // consumer still sees that a frame arrived.
                                let msg = serde_json::from_value::<WsMessage>(v)
                                    .unwrap_or(WsMessage::Unknown);
                                let _ = state.inbound_tx.send(msg);
                            }
                            Err(_) => {}
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

    #[test]
    fn l2_book_is_coin_ignores_params() {
        let full = Subscription::L2Book {
            coin: "1".into(),
            n_sig_figs: None,
            mantissa: None,
            n_levels: None,
        };
        let grouped = Subscription::L2Book {
            coin: "1".into(),
            n_sig_figs: Some(5),
            mantissa: Some(2),
            n_levels: Some(20),
        };
        // Same coin matches regardless of params; a different coin / channel doesn't.
        assert!(l2_book_is_coin(&full, "1"));
        assert!(l2_book_is_coin(&grouped, "1"));
        assert!(!l2_book_is_coin(&grouped, "2"));
        assert!(!l2_book_is_coin(
            &Subscription::Trades { coin: "1".into() },
            "1"
        ));
    }

    #[test]
    fn l2_book_resubscribe_replaces_prior_view_for_coin() {
        // Mirror the `subscribe()` active-set logic: a second l2_book on the same
        // coin (different params) REPLACES the first, so at most one entry per
        // coin survives into reconnect replay.
        let mut active: Vec<Subscription> = Vec::new();
        let first = Subscription::L2Book {
            coin: "1".into(),
            n_sig_figs: None,
            mantissa: None,
            n_levels: None,
        };
        active.retain(|s| !l2_book_is_coin(s, "1"));
        active.push(first);
        let second = Subscription::L2Book {
            coin: "1".into(),
            n_sig_figs: Some(5),
            mantissa: None,
            n_levels: Some(20),
        };
        active.retain(|s| !l2_book_is_coin(s, "1"));
        active.push(second.clone());
        assert_eq!(active.len(), 1);
        assert_eq!(active[0], second);
    }
}
