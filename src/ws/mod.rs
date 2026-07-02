//! WebSocket client — MTF-native subscriptions with reconnect-with-backoff.
//!
//! The [`WsClient`] connects to a `wss://` endpoint and multiplexes
//! subscriptions over a single connection. On disconnect it reconnects with
//! exponential backoff (capped) and re-subscribes to every active channel.
//!
//! Wire shape (snake_case):
//!
//! ```json
//! { "method": "subscribe",   "subscription": { "type": "l2_book", "coin": "1" } }
//! { "method": "unsubscribe", "subscription": { "type": "l2_book", "coin": "1" } }
//! ```
//!
//! Per-market channels carry `coin` (a quoted asset-id string, e.g. `"1"`);
//! per-account channels carry a `0x`-hex `user` address.
//!
//! ## Heartbeat
//!
//! The client sends a `{"method":"ping"}` frame every 30 seconds; if no
//! pong / data is received in 60 seconds the connection is recycled.

mod client;
mod subscriptions;

pub use client::{WsClient, WsConfig};
pub use subscriptions::{Subscription, WsMessage};
