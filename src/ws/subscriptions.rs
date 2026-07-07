//! WS subscription discriminators and the typed message envelope.
//!
//! `Subscription` is the request payload sent in `{"method":"subscribe",
//! "subscription": <Subscription>}` frames; `WsMessage` is the typed decoder
//! for inbound channel frames.
//!
//! Wire contract (MTF-native, snake_case `type`), mirroring the node's WS
//! `subscribe` parser and verified against `wss://api.devnet.mtf.exchange`:
//!
//! - **Per-market** channels carry `coin` — a **decimal asset-id string**
//!   (`"1"`). The node resolves it via `str::parse::<u32>`, so it must be a
//!   quoted integer, not a JSON number; symbol resolution (e.g. `"BTC"`) is not
//!   wired yet.
//! - **Per-account** channels carry `user` — a `0x`-hex address. (The node also
//!   accepts the legacy alias `address`.)
//! - `active_asset_data` carries both `coin` and `user`. `all_mids` is global
//!   (no field).
//! - The subscribe ack returns on channel `subscriptionResponse` (camelCase);
//!   errors on `error` with `data.error`; the ping reply is a bare
//!   `{"channel":"pong"}` with **no** `data`.

use serde::{Deserialize, Serialize};

use crate::wallet::Address;

/// One subscription request body — sent inside the
/// `{"method":"subscribe","subscription": ...}` envelope.
///
/// Per-market variants carry `coin` as a decimal asset-id string (`"1"`);
/// per-account variants carry `user` as a `0x`-hex address. Prefer the
/// [`crate::ws::WsClient`] `subscribe_*` helpers, which format a typed
/// [`crate::types::MarketId`] / [`Address`] into the right wire shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Subscription {
    /// L2 order-book updates for one market.
    L2Book {
        /// Market asset-id as a decimal string (e.g. `"1"`).
        coin: String,
    },
    /// Public trade prints for one market. On subscribe the server sends a
    /// NON-EMPTY snapshot of the bounded recent tape (snapshot rows carry
    /// `users: null`); subsequent frames are live prints.
    Trades {
        /// Market asset-id as a decimal string.
        coin: String,
    },
    /// Best-bid-best-offer ticks for one market.
    Bbo {
        /// Market asset-id as a decimal string.
        coin: String,
    },
    /// Per-market mark/oracle/funding/open-interest context, one per commit
    /// (replaces the old `mark` + funding channels).
    ActiveAssetCtx {
        /// Market asset-id as a decimal string.
        coin: String,
    },
    /// OHLCV bar updates for one market + interval (`1m`/`5m`/`15m`/`1h`/…).
    Candles {
        /// Market asset-id as a decimal string.
        coin: String,
        /// Bar interval token.
        interval: String,
    },
    /// Global `{coin: mid}` snapshot, one per commit.
    AllMids,
    /// Per-account fill stream.
    Fills {
        /// User `0x` address.
        user: Address,
    },
    /// Per-account order/fill/funding/liquidation events.
    UserEvents {
        /// User `0x` address.
        user: Address,
    },
    /// Per-account order lifecycle (open/filled/canceled/rejected) — replaces
    /// the old `order_events`. On a filled status the record carries `sz` (the
    /// FILLED size) and `orig_sz` (the original order size).
    OrderUpdates {
        /// User `0x` address.
        user: Address,
    },
    /// Per-account risk / liquidation notifications.
    Notifications {
        /// User `0x` address.
        user: Address,
    },
    /// Per-account non-funding ledger updates (deposits/withdrawals/transfers).
    LedgerUpdates {
        /// User `0x` address.
        user: Address,
    },
    /// Per-account realized funding payments. Each record carries
    /// `{ coin, payment, szi, fundingRate, time }` (symbol coin, signed payment,
    /// signed position size at settlement, the applied rate, and the unix-ms
    /// boundary).
    UserFundings {
        /// User `0x` address.
        user: Address,
    },
    /// Per-account TWAP slice fills.
    UserTwapSliceFills {
        /// User `0x` address.
        user: Address,
    },
    /// Per-account TWAP lifecycle transitions.
    UserTwapHistory {
        /// User `0x` address.
        user: Address,
    },
    /// Per-account live PERP clearinghouse/account state, one per commit.
    AccountState {
        /// User `0x` address.
        user: Address,
    },
    /// Per-account live SPOT clearinghouse state, one per commit.
    SpotState {
        /// User `0x` address.
        user: Address,
    },
    /// Per-(user, market) leverage / margin-mode / max-trade context.
    ActiveAssetData {
        /// Market asset-id as a decimal string.
        coin: String,
        /// User `0x` address.
        user: Address,
    },
    /// Global stream of committed explorer block headers, one per block.
    ExplorerBlock,
    /// Global stream of committed explorer transaction rows. Each row carries a
    /// `hash` (the 0x action hash; empty for systemic transactions).
    ExplorerTxs,
}

/// Typed channel frame (server -> client).
///
/// Servers tag frames with `channel`; the SDK decodes only the variants it
/// knows about. Unknown channels surface as [`WsMessage::Unknown`] so user
/// code can choose to ignore or log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "channel", content = "data", rename_all = "snake_case")]
pub enum WsMessage {
    /// Ack envelope returned when a `subscribe`/`unsubscribe` is accepted. The
    /// node names this channel in camelCase, unlike the snake_case data channels.
    #[serde(rename = "subscriptionResponse")]
    SubscriptionResponse {
        /// Echo of the original method (`"subscribe"` / `"unsubscribe"`).
        method: String,
        /// Echo of the subscription body.
        subscription: Subscription,
    },
    /// Server error envelope (kept open — connection survives). The node carries
    /// the message under `data.error`.
    Error {
        /// Error message.
        error: String,
    },
    /// L2 book update frame.
    L2Book(serde_json::Value),
    /// Public trade frame.
    Trades(serde_json::Value),
    /// BBO tick.
    Bbo(serde_json::Value),
    /// Per-market context (mark/oracle/funding/OI).
    ActiveAssetCtx(serde_json::Value),
    /// OHLCV bar.
    Candles(serde_json::Value),
    /// Global mids snapshot.
    AllMids(serde_json::Value),
    /// Per-account fill frame.
    Fills(serde_json::Value),
    /// Per-account events.
    UserEvents(serde_json::Value),
    /// Per-account order lifecycle.
    OrderUpdates(serde_json::Value),
    /// Per-account notifications.
    Notifications(serde_json::Value),
    /// Per-account ledger updates.
    LedgerUpdates(serde_json::Value),
    /// Per-account realized funding.
    UserFundings(serde_json::Value),
    /// Per-account TWAP slice fills.
    UserTwapSliceFills(serde_json::Value),
    /// Per-account TWAP history.
    UserTwapHistory(serde_json::Value),
    /// Per-account live PERP account state.
    AccountState(serde_json::Value),
    /// Per-account live SPOT state.
    SpotState(serde_json::Value),
    /// Per-(user, market) leverage/margin context.
    ActiveAssetData(serde_json::Value),
    /// Committed explorer block header frame.
    ExplorerBlock(serde_json::Value),
    /// Committed explorer transaction rows (each row carries a 0x action `hash`,
    /// empty for systemic transactions).
    ExplorerTxs(serde_json::Value),
    /// Pong reply to our heartbeat — a bare `{"channel":"pong"}` with no `data`.
    Pong,
    /// Any channel the SDK doesn't yet decode — carries no typed payload.
    #[serde(other)]
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscription_l2_book_uses_coin_string() {
        let s = Subscription::L2Book { coin: "1".into() };
        let j = serde_json::to_value(&s).unwrap();
        assert_eq!(j["type"], "l2_book");
        // The node reads `coin` with `Value::as_str` — a bare number is dropped.
        assert_eq!(j["coin"], "1");
        assert!(j["coin"].is_string());
        assert!(j.get("market_id").is_none());
    }

    #[test]
    fn subscription_account_channel_uses_user_address() {
        let s = Subscription::Fills {
            user: Address::ZERO,
        };
        let j = serde_json::to_value(&s).unwrap();
        assert_eq!(j["type"], "fills");
        assert!(j["user"].is_string());
        assert!(j["user"].as_str().unwrap().starts_with("0x"));
    }

    #[test]
    fn subscription_candles_carries_coin_and_interval() {
        let s = Subscription::Candles {
            coin: "7".into(),
            interval: "5m".into(),
        };
        let j = serde_json::to_value(&s).unwrap();
        assert_eq!(j["type"], "candles");
        assert_eq!(j["coin"], "7");
        assert_eq!(j["interval"], "5m");
    }

    #[test]
    fn subscription_all_mids_is_bare_type() {
        let j = serde_json::to_value(Subscription::AllMids).unwrap();
        assert_eq!(j["type"], "all_mids");
        assert!(j.get("coin").is_none() && j.get("user").is_none());
    }

    #[test]
    fn subscription_active_asset_data_carries_coin_and_user() {
        let s = Subscription::ActiveAssetData {
            coin: "2".into(),
            user: Address::ZERO,
        };
        let j = serde_json::to_value(&s).unwrap();
        assert_eq!(j["type"], "active_asset_data");
        assert_eq!(j["coin"], "2");
        assert!(j["user"].is_string());
    }

    #[test]
    fn ws_message_decodes_subscription_response_camel_channel() {
        let raw = serde_json::json!({
            "channel": "subscriptionResponse",
            "data": {
                "method": "subscribe",
                "subscription": { "type": "l2_book", "coin": "1" }
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
    fn ws_message_decodes_error_with_error_field() {
        let raw = serde_json::json!({ "channel": "error", "data": { "error": "bad channel" } });
        let m: WsMessage = serde_json::from_value(raw).unwrap();
        match m {
            WsMessage::Error { error } => assert_eq!(error, "bad channel"),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn ws_message_decodes_bare_pong() {
        // Node sends `{"channel":"pong"}` with NO `data` field.
        let raw = serde_json::json!({ "channel": "pong" });
        let m: WsMessage = serde_json::from_value(raw).unwrap();
        assert!(matches!(m, WsMessage::Pong));
    }

    #[test]
    fn subscription_explorer_channels_are_bare_type() {
        for (sub, ty) in [
            (Subscription::ExplorerBlock, "explorer_block"),
            (Subscription::ExplorerTxs, "explorer_txs"),
        ] {
            let j = serde_json::to_value(&sub).unwrap();
            assert_eq!(j["type"], ty);
            assert!(j.get("coin").is_none() && j.get("user").is_none());
        }
    }

    #[test]
    fn ws_message_decodes_data_channels() {
        for chan in [
            "l2_book",
            "trades",
            "bbo",
            "active_asset_ctx",
            "all_mids",
            "fills",
            "order_updates",
            "account_state",
            "spot_state",
            "user_fundings",
            "explorer_block",
            "explorer_txs",
        ] {
            let raw = serde_json::json!({ "channel": chan, "data": { "x": 1 } });
            let m: WsMessage = serde_json::from_value(raw)
                .unwrap_or_else(|e| panic!("channel {chan} should decode: {e}"));
            assert!(
                !matches!(m, WsMessage::Unknown),
                "channel {chan} fell through to Unknown"
            );
        }
    }

    #[test]
    fn ws_message_unknown_channel_without_data_is_unknown() {
        // A future/unknown channel with no `data` decodes straight to Unknown.
        let raw = serde_json::json!({ "channel": "definitely_not_real" });
        let m: WsMessage = serde_json::from_value(raw).unwrap();
        assert!(matches!(m, WsMessage::Unknown));
    }

    #[test]
    fn ws_message_unknown_channel_with_data_fails_decode() {
        // The adjacently-tagged `other` variant is a unit, so an unknown channel
        // that DOES carry a `data` map can't decode here — `WsClient`'s
        // `run_connection` maps that decode failure to `Unknown` rather than
        // dropping the frame (see the `unwrap_or(WsMessage::Unknown)` there).
        let raw = serde_json::json!({ "channel": "definitely_not_real", "data": { "x": 1 } });
        assert!(serde_json::from_value::<WsMessage>(raw).is_err());
    }
}
