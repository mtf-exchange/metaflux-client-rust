//! WebSocket client — MTF-native subscriptions with reconnect-with-backoff.
//!
//! The [`WsClient`] connects to a `wss://` endpoint and multiplexes
//! subscriptions over a single connection. On disconnect it reconnects with
//! exponential backoff (capped) and re-subscribes to every active channel.
//!
//! Wire shape (snake_case):
//!
//! ```json
//! { "method": "subscribe",   "subscription": { "type": "l2_book", "coin": "BTC" } }
//! { "method": "unsubscribe", "subscription": { "type": "l2_book", "coin": "BTC" } }
//! ```
//!
//! Per-market channels carry `coin` as a JSON string — a market symbol
//! (`"BTC"`), a spot pair name (`"BTC/USDC"`), or a decimal asset id (`"1"`).
//! Per-account channels carry a `0x`-hex `user` address.
//!
//! ## Typed payloads
//!
//! Frames hand back a raw [`serde_json::Value`] so a new server field never
//! breaks an old client. [`WsMessage::as_account_state`],
//! [`WsMessage::as_open_orders`], [`WsMessage::as_order_updates`] and
//! [`WsMessage::as_ledger_updates`] decode the account channels into typed
//! records.
//!
//! ## Heartbeat
//!
//! The client sends a `{"method":"ping"}` frame every 30 seconds; if no
//! pong / data is received in 60 seconds the connection is recycled.

mod client;
mod subscriptions;
mod typed;

pub use client::{WsClient, WsConfig};
pub use subscriptions::{Subscription, WsFrame, WsMessage};
pub use typed::{OrderUpdate, WsLedgerUpdate, WsOrderRow};
