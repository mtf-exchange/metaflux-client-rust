//! Typed decoders for the per-account WS channels.
//!
//! Every [`WsMessage`] payload stays a raw [`serde_json::Value`], so a server
//! that adds a field never breaks an old client. The accessors here decode that
//! payload into the same DTOs the REST reads return, and report a clear error
//! when the frame is a different channel or the shape does not match.
//!
//! The node builds the REST body and the WS body of `account_state` from ONE
//! function, so an `account_state` frame decodes into [`AccountState`] as-is.
//! The order channels differ in their ENVELOPE: `open_orders` is a bare array
//! of rows (the REST read wraps the same rows in `{address, orders}`), and
//! `order_updates` is an array of lifecycle records.

use serde::{Deserialize, Serialize};

use crate::error::ClientError;
use crate::rest::info::{AccountState, OpenOrder, OrderSide, OrderTrigger};
use crate::ws::subscriptions::WsMessage;

/// The inner `order` object of an [`OrderUpdate`].
///
/// The node renders it with the SAME serializer the `open_orders` row uses, but
/// a lifecycle record can describe an order the book no longer holds: a
/// `rejected` record has no `oid` and no `sz`, and a `canceled` record carries
/// only `coin` plus whichever id the cancel named. The node writes `null` for
/// every unknown field, so each field here is optional. Use [`OpenOrder`] for
/// the `open_orders` rows, where the node always fills them.
///
/// `px` and the sizes are whole-unit decimal **strings**. `sz` is the REMAINING
/// size — the executed size rides [`OrderUpdate::filled_sz`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct WsOrderRow {
    /// Resting-order id. `null` on a rejected order and on a cancel by cloid.
    #[serde(default)]
    pub oid: Option<u64>,
    /// Market symbol (`"BTC"`) or spot pair name (`"BTC/USDC"`).
    pub coin: String,
    /// Side, `"B"` (bid) / `"A"` (ask). `null` on a cancel record.
    #[serde(default)]
    pub side: Option<OrderSide>,
    /// Limit price, tick-snapped whole-USDC decimal string.
    #[serde(default)]
    pub px: Option<String>,
    /// REMAINING size, whole-base-unit decimal string. `"0"` once the order is
    /// fully filled.
    #[serde(default)]
    pub sz: Option<String>,
    /// Original submitted size, decimal string.
    #[serde(default)]
    pub orig_sz: Option<String>,
    /// Submit-time client order id (`0x`-hex), when the order carried one.
    #[serde(default)]
    pub cloid: Option<String>,
    /// Time-in-force token (`"alo"` / `"ioc"` / `"gtc"`), or `"trigger"` on a
    /// parked TP / SL / stop row.
    #[serde(default)]
    pub tif: Option<String>,
    /// Whether the order may only reduce an existing position.
    #[serde(default)]
    pub reduce_only: Option<bool>,
    /// Trigger detail when the order is registered for a trigger.
    #[serde(default)]
    pub trigger: Option<OrderTrigger>,
    /// Insertion timestamp (unix ms). `null` on a live delta — the record's own
    /// [`OrderUpdate::time`] carries the block timestamp there.
    #[serde(default)]
    pub inserted_at: Option<u64>,
}

/// One `order_updates` record: the order row plus its lifecycle outcome.
///
/// `status` is `"open"`, `"filled"`, `"rejected"`, `"canceled"` or
/// `"cancel_rejected"`. It stays a `String` because the node adds statuses as it
/// covers more events; a closed enum would reject a newer server.
///
/// `filled_sz` is the executed size of THIS event, not a running total: a maker
/// leg reports the size of the one match. `order.sz` is what REMAINS.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct OrderUpdate {
    /// The canonical order row.
    pub order: WsOrderRow,
    /// Lifecycle outcome token.
    pub status: String,
    /// Executed size of this event, decimal string; `null` when nothing filled.
    #[serde(default)]
    pub filled_sz: Option<String>,
    /// Average execution price of this event, decimal string.
    #[serde(default)]
    pub avg_px: Option<String>,
    /// Rejection reason on `"rejected"` / `"cancel_rejected"`.
    #[serde(default)]
    pub reason: Option<String>,
    /// Event timestamp (unix ms) — the consensus block time on a live delta,
    /// the order's `inserted_at` on the on-subscribe snapshot.
    pub time: u64,
}

fn wrong_channel(want: &str, got: &WsMessage) -> ClientError {
    use serde::de::Error as _;
    ClientError::Decode(serde_json::Error::custom(format!(
        "expected a `{want}` frame, got `{}`",
        got.channel()
    )))
}

impl WsMessage {
    /// The wire `channel` name of this frame.
    #[must_use]
    pub fn channel(&self) -> &'static str {
        match self {
            Self::SubscriptionResponse { .. } => "subscriptionResponse",
            Self::Error { .. } => "error",
            Self::L2Book(_) => "l2_book",
            Self::Trades(_) => "trades",
            Self::Bbo(_) => "bbo",
            Self::ActiveAssetCtx(_) => "active_asset_ctx",
            Self::Candles(_) => "candles",
            Self::AllMids(_) => "all_mids",
            Self::Fills(_) => "fills",
            Self::UserEvents(_) => "user_events",
            Self::OrderUpdates(_) => "order_updates",
            Self::Notifications(_) => "notifications",
            Self::LedgerUpdates(_) => "ledger_updates",
            Self::UserFundings(_) => "user_fundings",
            Self::UserTwapSliceFills(_) => "user_twap_slice_fills",
            Self::UserTwapHistory(_) => "user_twap_history",
            Self::AccountState(_) => "account_state",
            Self::WebData(_) => "web_data",
            Self::SpotMarginState(_) => "spot_margin_state",
            Self::ActiveAssetData(_) => "active_asset_data",
            Self::ExplorerBlock(_) => "explorer_block",
            Self::ExplorerTxs(_) => "explorer_txs",
            Self::OpenOrders(_) => "open_orders",
            Self::Markets(_) => "markets",
            Self::Pong => "pong",
            Self::Unknown => "unknown",
        }
    }

    /// Decode an `account_state` frame into the typed [`AccountState`].
    ///
    /// The body is identical to the REST `account_state` read, including the
    /// `height` / `time` stamp and the dex-keyed `clearinghouse_state` whose
    /// core key is the empty string.
    ///
    /// # Errors
    /// [`ClientError::Decode`] when this is not an `account_state` frame, or
    /// when the payload does not match [`AccountState`].
    pub fn as_account_state(&self) -> Result<AccountState, ClientError> {
        match self {
            Self::AccountState(v) => Ok(AccountState::deserialize(v)?),
            other => Err(wrong_channel("account_state", other)),
        }
    }

    /// Decode an `open_orders` frame into the typed rows.
    ///
    /// The frame is a bare ARRAY of the canonical order rows — the REST read
    /// wraps the same rows in `{address, orders}`. Every frame is a FULL
    /// snapshot of the account's resting set.
    ///
    /// # Errors
    /// [`ClientError::Decode`] when this is not an `open_orders` frame, or when
    /// the payload does not match `Vec<OpenOrder>`.
    pub fn as_open_orders(&self) -> Result<Vec<OpenOrder>, ClientError> {
        match self {
            Self::OpenOrders(v) => Ok(Vec::<OpenOrder>::deserialize(v)?),
            other => Err(wrong_channel("open_orders", other)),
        }
    }

    /// Decode an `order_updates` frame into the typed lifecycle records.
    ///
    /// # Errors
    /// [`ClientError::Decode`] when this is not an `order_updates` frame, or
    /// when the payload does not match `Vec<OrderUpdate>`.
    pub fn as_order_updates(&self) -> Result<Vec<OrderUpdate>, ClientError> {
        match self {
            Self::OrderUpdates(v) => Ok(Vec::<OrderUpdate>::deserialize(v)?),
            other => Err(wrong_channel("order_updates", other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rest::info::{Abstraction, PositionMode, Tier};
    use crate::ws::WsFrame;
    use serde_json::json;

    /// A live `account_state` frame, key-for-key as `wss://api.devnet.mtf.exchange`
    /// serves it: dex-keyed `clearinghouse_state` with the `""` core key, the
    /// `balances` ARRAY, and the `height` / `time` stamp.
    fn account_state_frame() -> serde_json::Value {
        json!({
            "channel": "account_state",
            "is_snapshot": true,
            "data": {
                "abstraction": "unified",
                "account_value": "1250.5",
                "address": "0xd486e1b74b8ba0b30bff5c1c5c4e0a5f2c1c0a1f",
                "balances": [{ "asset": 100, "hold": "0", "name": "USDC", "total": "1250.5" }],
                "clearinghouse_state": { "": { "positions": [{
                    "coin": "BTC",
                    "size": "-1.5",
                    "entry": "64000",
                    "upnl": "500",
                    "isolated": false,
                    "lev": 10,
                    "liq": "71000",
                    "roe": "0.02",
                    "funding": "-1.25",
                    "margin": "9600",
                    "maint_margin": "480",
                    "notional": "96000"
                }] } },
                "withdrawable": "1000",
                "health": "770.5",
                "height": 318_172u64,
                "init_margin": "250",
                "pm_concentration_penalty": "0",
                "pm_maint_margin": "0",
                "pm_net_value": "0",
                "position_mode": "one_way",
                "tier": "Safe",
                "time": 1_785_139_478_032u64
            }
        })
    }

    #[test]
    fn account_state_frame_decodes_typed() {
        let f = WsFrame::from_value(account_state_frame());
        assert!(f.is_snapshot);
        let a = f.message.as_account_state().unwrap();
        assert_eq!(a.account_value, "1250.5");
        assert_eq!(a.tier, Tier::Safe);
        assert_eq!(a.abstraction, Abstraction::Unified);
        assert_eq!(a.position_mode, PositionMode::OneWay);
        assert_eq!(a.height, 318_172);
        assert_eq!(a.time, 1_785_139_478_032);
        assert!(!a.health_deferred);
        assert_eq!(a.balances[0].asset, 100);
        assert_eq!(a.core_positions().len(), 1);
        assert_eq!(a.core_positions()[0].coin, "BTC");
    }

    #[test]
    fn account_state_frame_reads_health_deferred() {
        let mut v = account_state_frame();
        v["data"]["health_deferred"] = json!(true);
        let a = WsFrame::from_value(v).message.as_account_state().unwrap();
        assert!(a.health_deferred);
    }

    /// The raw `Value` accessor survives a field the SDK does not model, so a
    /// newer server never costs a consumer the whole frame.
    #[test]
    fn account_state_frame_keeps_the_raw_value() {
        let mut v = account_state_frame();
        v["data"]["future_field"] = json!("keep me");
        let f = WsFrame::from_value(v);
        let WsMessage::AccountState(raw) = &f.message else {
            panic!("expected an account_state frame");
        };
        assert_eq!(raw["future_field"], "keep me");
        assert!(f.message.as_account_state().is_ok());
    }

    /// `open_orders` is a bare ARRAY of rows, NOT the REST `{address, orders}`
    /// object.
    #[test]
    fn open_orders_frame_decodes_the_bare_array() {
        let f = WsFrame::from_value(json!({
            "channel": "open_orders",
            "is_snapshot": true,
            "data": [{
                "oid": 4242u64,
                "coin": "BTC",
                "side": "B",
                "px": "64000",
                "sz": "0.5",
                "orig_sz": null,
                "cloid": "0x000000000000000000000000000000ab",
                "tif": "gtc",
                "reduce_only": false,
                "trigger": null,
                "inserted_at": 1_785_139_478_032u64
            }]
        }));
        let rows = f.message.as_open_orders().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].oid, 4242);
        assert_eq!(rows[0].sz, "0.5");
        assert_eq!(rows[0].inserted_at, 1_785_139_478_032);
    }

    #[test]
    fn open_orders_empty_frame_decodes() {
        let f = WsFrame::from_value(json!({
            "channel": "open_orders", "is_snapshot": true, "data": []
        }));
        assert!(f.message.as_open_orders().unwrap().is_empty());
    }

    /// A `filled` record reports the REMAINING size on `order.sz` and the
    /// executed size on the record's own `filled_sz`. Reading `sz` as the fill
    /// makes a fully-filled order look like a zero fill.
    #[test]
    fn order_updates_filled_record_splits_remaining_from_filled() {
        let f = WsFrame::from_value(json!({
            "channel": "order_updates",
            "data": [{
                "order": {
                    "oid": 4242u64,
                    "coin": "BTC",
                    "side": "B",
                    "px": "64000",
                    "sz": "0",
                    "orig_sz": "0.5",
                    "cloid": null,
                    "tif": "gtc",
                    "reduce_only": false,
                    "trigger": null,
                    "inserted_at": null
                },
                "status": "filled",
                "filled_sz": "0.5",
                "avg_px": "63999.5",
                "reason": null,
                "time": 1_785_139_478_032u64
            }]
        }));
        let recs = f.message.as_order_updates().unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].status, "filled");
        assert_eq!(recs[0].order.sz.as_deref(), Some("0"));
        assert_eq!(recs[0].order.orig_sz.as_deref(), Some("0.5"));
        assert_eq!(recs[0].filled_sz.as_deref(), Some("0.5"));
        assert_eq!(recs[0].avg_px.as_deref(), Some("63999.5"));
        assert_eq!(recs[0].time, 1_785_139_478_032);
    }

    /// A cancel record carries a mostly `null` order row. [`OpenOrder`] would
    /// reject it, which is why the WS row type keeps every field optional.
    #[test]
    fn order_updates_cancel_record_decodes_a_null_order_row() {
        let data = json!([{
            "order": {
                "oid": 4242u64, "coin": "BTC", "side": null, "px": null, "sz": null,
                "orig_sz": null, "cloid": null, "tif": null, "reduce_only": null,
                "trigger": null, "inserted_at": null
            },
            "status": "canceled",
            "filled_sz": null,
            "avg_px": null,
            "reason": null,
            "time": 1_785_139_478_032u64
        }]);
        let row = data[0]["order"].clone();
        let f = WsFrame::from_value(json!({ "channel": "order_updates", "data": data }));
        let recs = f.message.as_order_updates().unwrap();
        assert_eq!(recs[0].status, "canceled");
        assert_eq!(recs[0].order.oid, Some(4242));
        assert!(recs[0].order.px.is_none());
        assert!(serde_json::from_value::<OpenOrder>(row).is_err());
    }

    #[test]
    fn order_updates_rejected_record_carries_the_reason() {
        let f = WsFrame::from_value(json!({
            "channel": "order_updates",
            "data": [{
                "order": {
                    "oid": null, "coin": "BTC", "side": "A", "px": "64000", "sz": null,
                    "orig_sz": "0.5", "cloid": null, "tif": "ioc", "reduce_only": false,
                    "trigger": null, "inserted_at": null
                },
                "status": "rejected",
                "filled_sz": null,
                "avg_px": null,
                "reason": "insufficient margin",
                "time": 1_785_139_478_032u64
            }]
        }));
        let recs = f.message.as_order_updates().unwrap();
        assert_eq!(recs[0].status, "rejected");
        assert!(recs[0].order.oid.is_none());
        assert_eq!(recs[0].reason.as_deref(), Some("insufficient margin"));
    }

    #[test]
    fn typed_accessor_rejects_another_channel() {
        let f = WsFrame::from_value(json!({ "channel": "trades", "data": [] }));
        let err = f.message.as_account_state().unwrap_err();
        assert!(matches!(err, ClientError::Decode(_)), "{err}");
        assert!(err.to_string().contains("account_state"), "{err}");
        assert!(err.to_string().contains("trades"), "{err}");
    }

    /// A shape mismatch on the right channel must FAIL, not read as empty.
    #[test]
    fn typed_accessor_rejects_a_bad_shape() {
        let mut v = account_state_frame();
        v["data"]["account_value"] = json!(1250.5);
        let err = WsFrame::from_value(v)
            .message
            .as_account_state()
            .unwrap_err();
        assert!(matches!(err, ClientError::Decode(_)), "{err}");
    }

    #[test]
    fn channel_name_matches_the_wire_tag() {
        for (tag, want) in [
            ("account_state", "account_state"),
            ("open_orders", "open_orders"),
            ("order_updates", "order_updates"),
            ("subscriptionResponse", "subscriptionResponse"),
        ] {
            let v = if tag == "subscriptionResponse" {
                json!({ "channel": tag, "data": {
                    "method": "subscribe",
                    "subscription": { "type": "all_mids" }
                }})
            } else {
                json!({ "channel": tag, "data": [] })
            };
            assert_eq!(WsFrame::from_value(v).message.channel(), want);
        }
        assert_eq!(
            WsFrame::from_value(json!({ "channel": "pong" }))
                .message
                .channel(),
            "pong"
        );
    }
}
