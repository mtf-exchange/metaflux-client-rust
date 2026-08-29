//! WS subscription discriminators and the typed message envelope.
//!
//! `Subscription` is the request payload sent in `{"method":"subscribe",
//! "subscription": <Subscription>}` frames; `WsMessage` is the typed decoder
//! for inbound channel frames.
//!
//! Wire contract (MTF-native, snake_case `type`), mirroring the node's WS
//! `subscribe` parser and verified against `wss://api.devnet.mtf.exchange`:
//!
//! - **Per-market** channels carry `coin` — a **JSON string**, never a bare
//!   number. The node canonicalizes it through the committed universe: a
//!   decimal asset id (`"1"`) first, then a perp market symbol (`"BTC"`), then
//!   a spot pair name (`"BTC/USDC"`). Prefer the symbol — it stays stable when
//!   asset ids shift. An unknown coin routes to a bucket that never publishes.
//!   Subscribe de-duplication keys on the RAW string, so `"BTC"` and `"0"`
//!   count as two subscriptions to the same market.
//! - **Per-account** channels carry `user` — a `0x`-hex address. (The node also
//!   accepts the legacy alias `address`.) `account_state`,
//!   `clearinghouse_state` and `option_state` REJECT a subscribe with no
//!   `user`; the node answers `"<channel> requires a `user`"`.
//! - `active_asset_data` carries both `coin` and `user`. `markets` is global
//!   (no field).
//! - The subscribe ack returns on channel `subscriptionResponse` (camelCase);
//!   errors on `error` with `data.error`; the ping reply is a bare
//!   `{"channel":"pong"}` with **no** `data`.

use serde::{Deserialize, Serialize};

use crate::types::candle::CandleType;
use crate::wallet::Address;

/// One subscription request body — sent inside the
/// `{"method":"subscribe","subscription": ...}` envelope.
///
/// Per-market variants carry `coin` as a market symbol (`"BTC"`), a spot pair
/// name (`"BTC/USDC"`), or a decimal asset-id string (`"1"`); per-account
/// variants carry `user` as a `0x`-hex address. Prefer the
/// [`crate::ws::WsClient`] `subscribe_*` helpers, which format a typed
/// [`crate::types::MarketId`] / [`Address`] into the right wire shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Subscription {
    /// L2 order-book updates for one market or spot pair.
    ///
    /// `coin` is a perp market symbol (`"BTC"`) or asset-id string (`"1"`), or
    /// a spot pair (name `"BTC/USDC"` or the pair-id string). The three optional aggregation
    /// params request deterministic away-from-spread grouping (snake_case on the
    /// native `/ws` dialect); they are OMITTED from the frame when `None`.
    ///
    /// The server holds ONE l2_book view per coin per connection: re-subscribing
    /// the same coin with different params REPLACES the view; unsubscribe is
    /// keyed by coin WITHOUT params. The `#[serde(default)]` lets a plain ack /
    /// echo that omits the params still decode back into this variant. The ack
    /// echoes `n_sig_figs` and `n_levels`, and `mantissa` only when it is not 1.
    L2Book {
        /// Market symbol (`"BTC"`), asset-id string (`"1"`), or spot pair
        /// (`"BTC/USDC"` / pair id).
        coin: String,
        /// Significant-figure grouping (`2..=5`). Omitted from the frame when `None`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        n_sig_figs: Option<u32>,
        /// Mantissa sub-division (`1 | 2 | 5`); valid only with `n_sig_figs == 5`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mantissa: Option<u32>,
        /// Max levels per side (`≥ 1`). Omitted from the frame when `None`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        n_levels: Option<u32>,
    },
    /// Public trade prints for one market. On subscribe the server sends a
    /// NON-EMPTY snapshot of the bounded recent tape (snapshot rows carry
    /// `users: null`); subsequent frames are live prints, whose `users` names
    /// the AGGRESSOR only. The resting maker is never disclosed.
    Trades {
        /// Market symbol (`"BTC"`) or asset-id string (`"1"`).
        coin: String,
    },
    /// Best-bid-best-offer ticks for one market.
    Bbo {
        /// Market symbol (`"BTC"`) or asset-id string (`"1"`).
        coin: String,
    },
    /// Rolling PRICE bars for one market, one series, one bar size. The routing
    /// key is `(coin, interval, candle_type)`, so `1m` and `5m` — or `mark` and
    /// `oracle` at the same interval — are independent subscriptions. The ack
    /// echoes `interval` and `candle_type`.
    ///
    /// Every frame carries `{snapshot, candles}`. `snapshot: true` is the
    /// recent history, oldest first; `snapshot: false` is the one bar that
    /// changed. The frame-level `is_snapshot` stays `false` on this channel.
    Candles {
        /// Market symbol (`"BTC"`) or asset-id string (`"1"`).
        coin: String,
        /// Bar interval token (`1m`/`5m`/`15m`/`1h`/`4h`/`1d`).
        interval: String,
        /// Price or executed-trade series. All three values are served.
        candle_type: CandleType,
    },
    /// Per-account fill stream.
    Fills {
        /// User `0x` address.
        user: Address,
    },
    /// Per-account order lifecycle — replaces the old `order_events`. `status`
    /// is `open` / `filled` / `rejected` / `canceled` / `cancel_rejected`.
    ///
    /// The record wraps the canonical order row under `order` and carries
    /// `filled_sz`, `avg_px`, `reason` and `time` as its OWN top-level fields.
    /// `order.sz` is the REMAINING size, NOT the filled size: a fully filled
    /// order reports `order.sz` `"0"` and the executed size in `filled_sz`.
    /// `order.orig_sz` is the original submitted size. Decode with
    /// [`crate::ws::WsMessage::as_order_updates`].
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
    /// Per-account account snapshot, one per commit: the cross-lane scalars
    /// plus the four lane summaries. Body identical to the REST `account_state`
    /// read. The perp POSITION table is NOT in it — subscribe to
    /// [`Subscription::ClearinghouseState`] for that.
    AccountState {
        /// User `0x` address.
        user: Address,
    },
    /// Per-account PERP position detail, one per commit — the dex-keyed table
    /// that left `account_state`. Body identical to the REST
    /// `clearinghouse_state` read, except that the frame never carries
    /// `adl_lamps`: the lamp ranks against OTHER accounts, so an always-on lamp
    /// would re-push this account whenever a stranger's ROE crossed a quartile.
    ClearinghouseState {
        /// User `0x` address.
        user: Address,
    },
    /// Per-account option legs, one per commit. Body identical to the REST
    /// `option_state` read.
    OptionState {
        /// User `0x` address.
        user: Address,
    },
    /// Per-account spot-margin positions, one per commit. Body identical to the
    /// REST `spot_margin_state` read.
    SpotMarginState {
        /// User `0x` address.
        user: Address,
    },
    /// Per-(user, market) leverage / margin-mode / max-trade context.
    ActiveAssetData {
        /// Market symbol (`"BTC"`) or asset-id string (`"1"`).
        coin: String,
        /// User `0x` address.
        user: Address,
    },
    /// Global stream of committed explorer block headers, one per block.
    ExplorerBlock,
    /// Global stream of committed explorer transaction rows. Each row carries a
    /// `hash` (the 0x action hash; empty for systemic transactions).
    ExplorerTxs,
    /// Per-account resting-order set (MTF-native). EVERY frame is a FULL
    /// snapshot of the account's current open orders, re-emitted on any
    /// resting-set mutation.
    OpenOrders {
        /// User `0x` address.
        user: Address,
    },
    /// GLOBAL per-market dynamic-state tape (MTF-native). Coinless and
    /// userless: an on-subscribe full snapshot, then per-commit changed-row
    /// deltas. Every row carries mid, mark, oracle, funding and open interest,
    /// so this ONE subscription answers what the retired `all_mids` and
    /// `active_asset_ctx` channels each answered in part.
    Markets,
}

/// Typed channel frame (server -> client).
///
/// Servers tag frames with `channel`; the SDK decodes only the variants it
/// knows about. Unknown channels surface as [`WsMessage::Unknown`] so user
/// code can choose to ignore or log.
///
/// A payload stays a raw [`serde_json::Value`] so a new server field never
/// breaks an old client. The account channels also offer typed accessors —
/// [`WsMessage::as_account_state`], [`WsMessage::as_clearinghouse_state`],
/// [`WsMessage::as_option_state`], [`WsMessage::as_open_orders`] and
/// [`WsMessage::as_order_updates`] — which decode the payload into the same
/// DTOs the REST reads return.
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
    /// OHLCV bar.
    Candles(serde_json::Value),
    /// Per-account fill frame.
    Fills(serde_json::Value),
    /// Per-account order lifecycle — an ARRAY of records. Decode with
    /// [`WsMessage::as_order_updates`].
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
    /// Per-account account snapshot — the SAME object the REST `account_state`
    /// read returns. Decode with [`WsMessage::as_account_state`].
    AccountState(serde_json::Value),
    /// Per-account PERP position detail — the SAME object the REST
    /// `clearinghouse_state` read returns. Decode with
    /// [`WsMessage::as_clearinghouse_state`].
    ClearinghouseState(serde_json::Value),
    /// Per-account option legs — the SAME object the REST `option_state` read
    /// returns. Decode with [`WsMessage::as_option_state`].
    OptionState(serde_json::Value),
    /// Per-account spot-margin positions.
    SpotMarginState(serde_json::Value),
    /// Per-(user, market) leverage/margin context.
    ActiveAssetData(serde_json::Value),
    /// Committed explorer block header frame.
    ExplorerBlock(serde_json::Value),
    /// Committed explorer transaction rows (each row carries a 0x action `hash`,
    /// empty for systemic transactions).
    ExplorerTxs(serde_json::Value),
    /// Per-account resting-order snapshot frame — a bare ARRAY of order rows,
    /// NOT the `{address, orders}` object the REST read returns. Decode with
    /// [`WsMessage::as_open_orders`].
    OpenOrders(serde_json::Value),
    /// Global per-market dynamic-state tape frame.
    Markets(serde_json::Value),
    /// Pong reply to our heartbeat — a bare `{"channel":"pong"}` with no `data`.
    Pong,
    /// Any channel the SDK doesn't yet decode — carries no typed payload.
    #[serde(other)]
    Unknown,
}

/// One decoded inbound frame: the typed channel message plus the envelope's
/// snapshot flag.
///
/// `is_snapshot` marks a frame that carries FULL state rather than a delta. The
/// server omits the flag on deltas, and an absent flag reads `false`, so an
/// older server never makes a consumer mistake a delta for a snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WsFrame {
    /// The typed channel message.
    pub message: WsMessage,
    /// Whether `message` carries a full-state snapshot.
    pub is_snapshot: bool,
}

impl WsFrame {
    /// Decode one raw inbound frame.
    ///
    /// An unknown channel — or a `data` payload this SDK cannot type — decodes
    /// to [`WsMessage::Unknown`] instead of being dropped, so a
    /// forward-compatible consumer still sees that a frame arrived.
    #[must_use]
    pub fn from_value(value: serde_json::Value) -> Self {
        let is_snapshot = value
            .get("is_snapshot")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        Self {
            message: serde_json::from_value(value).unwrap_or(WsMessage::Unknown),
            is_snapshot,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscription_l2_book_uses_coin_string() {
        let s = Subscription::L2Book {
            coin: "1".into(),
            n_sig_figs: None,
            mantissa: None,
            n_levels: None,
        };
        let j = serde_json::to_value(&s).unwrap();
        assert_eq!(j["type"], "l2_book");
        // The node reads `coin` with `Value::as_str` — a bare number is dropped.
        assert_eq!(j["coin"], "1");
        assert!(j["coin"].is_string());
        assert!(j.get("market_id").is_none());
        // No params set -> the aggregation keys are OMITTED from the frame.
        assert!(j.get("n_sig_figs").is_none());
        assert!(j.get("mantissa").is_none());
        assert!(j.get("n_levels").is_none());
    }

    #[test]
    fn subscription_l2_book_emits_snake_case_agg_params() {
        // The native /ws dialect reads snake_case params; mantissa valid only
        // with n_sig_figs == 5.
        let s = Subscription::L2Book {
            coin: "BTC/USDC".into(),
            n_sig_figs: Some(5),
            mantissa: Some(2),
            n_levels: Some(20),
        };
        let j = serde_json::to_value(&s).unwrap();
        assert_eq!(j["type"], "l2_book");
        assert_eq!(j["coin"], "BTC/USDC");
        assert_eq!(j["n_sig_figs"], 5);
        assert_eq!(j["mantissa"], 2);
        assert_eq!(j["n_levels"], 20);
    }

    #[test]
    fn subscription_l2_book_ack_without_params_decodes() {
        // The subscribe ack echoes a bare `{type, coin}` (no params) — the
        // `#[serde(default)]` on the param fields must let it decode back.
        let raw = serde_json::json!({ "type": "l2_book", "coin": "1" });
        let s: Subscription = serde_json::from_value(raw).unwrap();
        assert!(matches!(
            s,
            Subscription::L2Book {
                n_sig_figs: None,
                mantissa: None,
                n_levels: None,
                ..
            }
        ));
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

    /// The two channels the account reshape added. Both carry the wire name the
    /// node parses, and both REQUIRE the `user` — the node rejects a subscribe
    /// without one.
    #[test]
    fn subscription_detail_channels_carry_the_wire_name_and_the_user() {
        for (sub, want) in [
            (
                Subscription::ClearinghouseState {
                    user: Address::ZERO,
                },
                "clearinghouse_state",
            ),
            (
                Subscription::OptionState {
                    user: Address::ZERO,
                },
                "option_state",
            ),
        ] {
            let j = serde_json::to_value(&sub).unwrap();
            assert_eq!(j["type"], want);
            assert!(j["user"].as_str().unwrap().starts_with("0x"));
            assert_eq!(serde_json::from_value::<Subscription>(j).unwrap(), sub);
        }
    }

    #[test]
    fn subscription_candles_carries_coin_interval_and_candle_type() {
        let s = Subscription::Candles {
            coin: "7".into(),
            interval: "5m".into(),
            candle_type: CandleType::Oracle,
        };
        let j = serde_json::to_value(&s).unwrap();
        assert_eq!(j["type"], "candles");
        assert_eq!(j["coin"], "7");
        assert_eq!(j["interval"], "5m");
        assert_eq!(j["candle_type"], "oracle");
        // The routing key is the triple, so the same market at the same interval
        // on a different series is a DIFFERENT subscription.
        let mark = Subscription::Candles {
            coin: "7".into(),
            interval: "5m".into(),
            candle_type: CandleType::Mark,
        };
        assert_ne!(serde_json::to_value(&mark).unwrap(), j);
        assert_eq!(serde_json::to_value(&mark).unwrap()["candle_type"], "mark");
        // No camelCase leak.
        assert!(j.get("candleType").is_none());
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
            "fills",
            "order_updates",
            "account_state",
            "spot_margin_state",
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
    fn retired_channels_do_not_decode() {
        // Each of these duplicated a channel the SDK still carries, so the node
        // refuses a subscribe with an error envelope. `markets` answers what
        // `all_mids` and `active_asset_ctx` answered; `fills` / `order_updates`
        // / `ledger_updates` / `notifications` answer what `user_events` did.
        for chan in [
            "spot_state",
            "web_data",
            "all_mids",
            "active_asset_ctx",
            "user_events",
        ] {
            let raw = serde_json::json!({ "channel": chan, "data": { "x": 1 } });
            assert!(
                serde_json::from_value::<WsMessage>(raw).is_err(),
                "channel {chan} must not decode"
            );
        }
    }

    #[test]
    fn ws_frame_reads_the_snapshot_flag() {
        let snap = WsFrame::from_value(serde_json::json!({
            "channel": "open_orders",
            "data": [],
            "is_snapshot": true
        }));
        assert!(snap.is_snapshot);
        assert!(matches!(snap.message, WsMessage::OpenOrders(_)));

        // An absent flag reads as a delta, never as a snapshot.
        let delta = WsFrame::from_value(serde_json::json!({
            "channel": "order_updates",
            "data": []
        }));
        assert!(!delta.is_snapshot);

        // A typed-decode failure still surfaces the frame, with its flag.
        let opaque = WsFrame::from_value(serde_json::json!({
            "channel": "definitely_not_real",
            "data": { "x": 1 },
            "is_snapshot": true
        }));
        assert!(opaque.is_snapshot);
        assert!(matches!(opaque.message, WsMessage::Unknown));
    }

    #[test]
    fn spot_margin_state_carries_only_user() {
        let j = serde_json::to_value(Subscription::SpotMarginState {
            user: Address::ZERO,
        })
        .unwrap();
        assert!(j.get("user").is_some(), "missing user: {j}");
        assert!(j.get("coin").is_none());
        assert_eq!(j["type"], "spot_margin_state");
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
