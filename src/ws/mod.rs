//! WebSocket client — MTF-native subscriptions with reconnect-with-backoff.
//!
//! The [`WsClient`] connects to a `wss://` endpoint and multiplexes
//! subscriptions over a single connection. On disconnect it reconnects with
//! exponential backoff (capped) and re-subscribes to every active channel.
//!
//! Wire shape (snake_case):
//!
//! ```json
//! { "method": "subscribe",   "subscription": { "type": "l2_book", "market_id": 1 } }
//! { "method": "unsubscribe", "subscription": { "type": "l2_book", "market_id": 1 } }
//! ```
//!
//! Subscriptions are keyed by integer `market_id`, not a `coin` symbol.
//!
//! ## Heartbeat
//!
//! The client sends a `{"method":"ping"}` frame every 30 seconds; if no
//! pong / data is received in 60 seconds the connection is recycled.

mod client;
mod subscriptions;

pub use client::{WsClient, WsConfig};
pub use subscriptions::{Subscription, WsMessage};
