//! WS subscription discriminators and the typed message envelope.
//!
//! `Subscription` is the request payload sent in `{"method":"subscribe",
//! "subscription": <Subscription>}` frames; `WsMessage` is the typed
//! decoder for inbound channel frames.

use serde::{Deserialize, Serialize};

use crate::types::{MarketId, VaultId};
use crate::wallet::Address;

/// One subscription request body — sent inside the
/// `{"method":"subscribe","subscription": ...}` envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Subscription {
    /// L2 order-book updates for one market.
    L2Book {
        /// Market id.
        market_id: MarketId,
    },
    /// Public trade prints for one market.
    Trades {
        /// Market id.
        market_id: MarketId,
    },
    /// Best-bid-best-offer ticks for one market.
    Bbo {
        /// Market id.
        market_id: MarketId,
    },
    /// Per-user fill events.
    UserFills {
        /// User address.
        address: Address,
    },
    /// Per-user account / position updates.
    UserState {
        /// User address.
        address: Address,
    },
    /// NAV updates for one vault.
    VaultNav {
        /// Vault id.
        vault_id: VaultId,
    },
    /// Open-RFQ stream (for MMs that want to quote on new RFQ sessions).
    Rfq {
        /// Market id filter (0 = all markets).
        market_id: MarketId,
    },
    /// FBA batch result stream.
    FbaBatch {
        /// Market id.
        market_id: MarketId,
    },
}

/// Typed channel frame (server -> client).
///
/// Servers tag frames with `channel`; the SDK decodes only the variants it
/// knows about. Unknown channels surface as [`WsMessage::Unknown`] so user
/// code can choose to ignore or log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "channel", content = "data", rename_all = "snake_case")]
pub enum WsMessage {
    /// Ack envelope returned by the server when a `subscribe` is accepted.
    SubscriptionResponse {
        /// Echo of the original method (`"subscribe"` / `"unsubscribe"`).
        method: String,
        /// Echo of the subscription body.
        subscription: Subscription,
    },
    /// Server error envelope (kept open — connection survives).
    Error {
        /// Error message.
        message: String,
    },
    /// L2 book update frame.
    L2Book(serde_json::Value),
    /// Public trade frame.
    Trades(serde_json::Value),
    /// BBO tick.
    Bbo(serde_json::Value),
    /// User fill event.
    UserFills(serde_json::Value),
    /// User state delta.
    UserState(serde_json::Value),
    /// Vault NAV update.
    VaultNav(serde_json::Value),
    /// New / updated RFQ session.
    Rfq(serde_json::Value),
    /// FBA batch clear result.
    FbaBatch(serde_json::Value),
    /// Pong reply to our heartbeat.
    Pong(serde_json::Value),
    /// Any channel the SDK doesn't yet decode — carries the raw payload.
    #[serde(other)]
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscription_l2_book_serializes_snake_case() {
        let s = Subscription::L2Book {
            market_id: MarketId(1),
        };
        let j = serde_json::to_value(&s).unwrap();
        assert_eq!(j["type"], "l2_book");
        assert_eq!(j["market_id"], 1);
    }

    #[test]
    fn subscription_user_fills_uses_address() {
        let s = Subscription::UserFills {
            address: Address::ZERO,
        };
        let j = serde_json::to_value(&s).unwrap();
        assert_eq!(j["type"], "user_fills");
        assert!(j["address"].is_string());
    }

    #[test]
    fn ws_message_decodes_subscription_response() {
        let raw = serde_json::json!({
            "channel": "subscription_response",
            "data": {
                "method": "subscribe",
                "subscription": { "type": "l2_book", "market_id": 1 }
            }
        });
        let m: WsMessage = serde_json::from_value(raw).unwrap();
        match m {
            WsMessage::SubscriptionResponse {
                method,
                subscription,
            } => {
                assert_eq!(method, "subscribe");
                assert!(matches!(subscription, Subscription::L2Book { .. }));
            }
            other => panic!("expected SubscriptionResponse, got {other:?}"),
        }
    }

    #[test]
    fn ws_message_decodes_error() {
        let raw = serde_json::json!({ "channel": "error", "data": { "message": "bad channel" } });
        let m: WsMessage = serde_json::from_value(raw).unwrap();
        match m {
            WsMessage::Error { message } => assert_eq!(message, "bad channel"),
            other => panic!("expected Error, got {other:?}"),
        }
    }
}
