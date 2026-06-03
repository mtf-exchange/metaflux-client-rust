//! Order types — limit / market / trigger orders and lifecycle enums.
//!
//! Wire shape (MTF-native, snake_case):
//!
//! ```json
//! {
//!   "owner":            "0x...",
//!   "market":           1,
//!   "side":             "bid",
//!   "kind":             "limit",
//!   "size":             1000,
//!   "limit_px":         5_000_000_000_000,
//!   "tif":              "gtc",
//!   "stp_mode":         "cancel_oldest",
//!   "reduce_only":      false,
//!   "cloid":             null,
//!   "builder":          {"fee": 5, "user": "0x..."}
//! }
//! ```
//!
//! The submit shape carries **no `oid`** — the order id is assigned by the node
//! and returned in [`OrderResponse`]. A client never declares it.
//!
//! Numerics are plain integers (u64 / i64). Sizes / prices use **fixed-point
//! tick units** — the SDK does not adopt the HL decimal-string convention.

use serde::{Deserialize, Serialize};

use crate::types::{Cloid, MarketId, OrderId};
use crate::wallet::Address;

/// Side of an order — buyer (bid) or seller (ask).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Side {
    /// Buy side.
    Bid,
    /// Sell side.
    Ask,
}

/// Order kind — controls execution semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderKind {
    /// Limit order, rests on the book until matched or cancelled.
    Limit,
    /// Market order, immediate execution against best available.
    Market,
    /// Stop-loss trigger; converts to a limit/market when stop_px is hit.
    StopLoss,
    /// Take-profit trigger.
    TakeProfit,
}

/// Time-in-force policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeInForce {
    /// Good-til-cancelled — rests until matched or cancelled.
    Gtc,
    /// Immediate-or-cancel — match what we can, cancel the remainder.
    Ioc,
    /// All-or-none — match in full or cancel.
    Aon,
    /// Post-only / "ALO" — reject if would cross (queue jump prevention).
    Alo,
}

/// Self-trade prevention mode (ADR-009 chose `CancelOldest` as default).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StpMode {
    /// Cancel the resting (older) order, let the new one through.
    CancelOldest,
    /// Cancel the incoming (newer) order, keep the resting.
    CancelNewest,
    /// Cancel both sides.
    CancelBoth,
    /// Reject the new order (no cancellations).
    Reject,
}

/// A single order submission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Order {
    /// 20-byte EVM address that owns the order.
    pub owner: Address,
    /// Target market id.
    pub market: MarketId,
    /// Bid / ask.
    pub side: Side,
    /// Order kind (limit / market / triggers).
    pub kind: OrderKind,
    /// Size in fixed-point tick units (u64 — see market `size_decimals`).
    pub size: u64,
    /// Limit price in fixed-point tick units. Ignored for pure market orders.
    pub limit_px: u64,
    /// Time-in-force policy.
    pub tif: TimeInForce,
    /// STP mode (ADR-009).
    pub stp_mode: StpMode,
    /// Reduce-only flag — order may only reduce an existing position.
    pub reduce_only: bool,
    /// Optional client-supplied identifier for idempotency.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloid: Option<Cloid>,
    /// Optional builder-code fee attribution (RFC-009 Stage 2b).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub builder: Option<Builder>,
}

/// Builder-code fee attribution riding inside a signed order (RFC-009 Stage 2b).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Builder {
    /// Builder fee in basis points (server enforces ≤ 8).
    pub fee: u16,
    /// Address credited with the builder fee.
    pub user: Address,
}

/// Cancel intent — by `oid` or by `cloid`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CancelOrder {
    /// 20-byte EVM address of the order owner.
    pub owner: Address,
    /// Target market id.
    pub market: MarketId,
    /// Optional server `oid`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oid: Option<OrderId>,
    /// Optional cloid (mutually exclusive with `oid`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloid: Option<Cloid>,
}

/// Per-order status entry returned by `/exchange` for an `Order` action.
///
/// Per the committed contract (`api/rest/exchange.md` — `Order` →
/// **Response status entries**), each submitted order resolves to one of three
/// outcomes, emitted in submission order:
///
/// ```json
/// {"resting": {"oid": 12345, "cloid": "0x..."}}
/// {"filled":  {"total_sz": "100000000", "avg_px": "10050000000", "oid": 12345}}
/// {"error":   "<reason>"}
/// ```
///
/// `total_sz` / `avg_px` are 8-decimal fixed-point **u128 strings** on the wire
/// (native JSON numbers would lose precision past 2^53); `oid` is a JSON number
/// (uint64). The variant is selected by the single present key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderStatus {
    /// Posted to the book; not (fully) filled.
    Resting(RestingStatus),
    /// Crossed immediately for `total_sz` at `avg_px`.
    Filled(FilledStatus),
    /// This entry was rejected at admission (the rest of the batch may still
    /// have succeeded). Carries the reason string.
    Error(String),
}

impl OrderStatus {
    /// The server-assigned `oid`, if this entry produced one (`resting` /
    /// `filled`). `None` for an `error` entry.
    #[must_use]
    pub fn oid(&self) -> Option<OrderId> {
        match self {
            OrderStatus::Resting(r) => Some(r.oid),
            OrderStatus::Filled(f) => Some(f.oid),
            OrderStatus::Error(_) => None,
        }
    }

    /// `true` if this entry was rejected at admission.
    #[must_use]
    pub const fn is_error(&self) -> bool {
        matches!(self, OrderStatus::Error(_))
    }
}

/// Payload of [`OrderStatus::Resting`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RestingStatus {
    /// Server-assigned order id.
    pub oid: OrderId,
    /// Echo of the client order id, if one was supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloid: Option<Cloid>,
}

/// Payload of [`OrderStatus::Filled`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct FilledStatus {
    /// Total size filled, 8-decimal fixed-point as a decimal string.
    pub total_sz: String,
    /// Volume-weighted average fill price, 8-decimal fixed-point as a string.
    pub avg_px: String,
    /// Server-assigned order id.
    pub oid: OrderId,
}

/// Response from `/exchange` for an `Order` action.
///
/// The `Order` action submits one or many orders atomically; the response is
/// an array of [`OrderStatus`] entries, one per submitted order, in order.
/// A single-order submit yields a one-element vec.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderResponse {
    /// Per-order status entries, in submission order.
    pub statuses: Vec<OrderStatus>,
}

impl OrderResponse {
    /// The first status entry, if any. Convenience for the common single-order
    /// submit path.
    #[must_use]
    pub fn first(&self) -> Option<&OrderStatus> {
        self.statuses.first()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_order() -> Order {
        Order {
            owner: Address::ZERO,
            market: MarketId(1),
            side: Side::Bid,
            kind: OrderKind::Limit,
            size: 1_000,
            limit_px: 5_000_000_000_000,
            tif: TimeInForce::Gtc,
            stp_mode: StpMode::CancelOldest,
            reduce_only: false,
            cloid: None,
            builder: None,
        }
    }

    #[test]
    fn order_serializes_snake_case() {
        let o = sample_order();
        let j = serde_json::to_value(&o).unwrap();
        assert!(j.get("limit_px").is_some(), "expected snake_case field");
        assert!(j.get("reduce_only").is_some());
        assert!(j.get("stp_mode").is_some());
        // No camelCase leak.
        assert!(j.get("limitPx").is_none());
        assert!(j.get("reduceOnly").is_none());
        assert!(j.get("stpMode").is_none());
    }

    #[test]
    fn side_serializes_snake_case() {
        assert_eq!(serde_json::to_string(&Side::Bid).unwrap(), "\"bid\"");
        assert_eq!(serde_json::to_string(&Side::Ask).unwrap(), "\"ask\"");
    }

    #[test]
    fn tif_serializes_snake_case() {
        for (tif, expected) in [
            (TimeInForce::Gtc, "\"gtc\""),
            (TimeInForce::Ioc, "\"ioc\""),
            (TimeInForce::Aon, "\"aon\""),
            (TimeInForce::Alo, "\"alo\""),
        ] {
            assert_eq!(serde_json::to_string(&tif).unwrap(), expected);
        }
    }

    #[test]
    fn order_serializes_size_as_integer_not_string() {
        let o = sample_order();
        let j = serde_json::to_value(&o).unwrap();
        assert!(j["size"].is_number(), "size must be a plain JSON number");
        assert!(
            j["limit_px"].is_number(),
            "limit_px must be a plain JSON number"
        );
    }

    #[test]
    fn order_round_trips() {
        let o = sample_order();
        let j = serde_json::to_string(&o).unwrap();
        let dec: Order = serde_json::from_str(&j).unwrap();
        assert_eq!(o, dec);
    }

    #[test]
    fn order_omits_none_cloid() {
        let o = sample_order();
        let j = serde_json::to_value(&o).unwrap();
        assert!(j.get("cloid").is_none());
    }

    #[test]
    fn order_omits_none_builder() {
        let o = sample_order();
        let j = serde_json::to_value(&o).unwrap();
        assert!(j.get("builder").is_none());
    }

    #[test]
    fn order_serializes_builder_object() {
        let mut o = sample_order();
        let user = Address::from_hex("0x00000000000000000000000000000000000000ff").unwrap();
        o.builder = Some(Builder { fee: 5, user });
        let j = serde_json::to_value(&o).unwrap();
        let b = j.get("builder").expect("builder key present");
        assert_eq!(b["fee"], serde_json::json!(5));
        assert!(b["fee"].is_number(), "fee must be a plain JSON number");
        assert_eq!(
            b["user"],
            serde_json::json!("0x00000000000000000000000000000000000000ff")
        );
    }

    /// A submitted order must NOT carry an `oid` — the node assigns it and
    /// returns it in `OrderResponse`. A client never declares the order id.
    #[test]
    fn order_submit_shape_has_no_oid() {
        let o = sample_order();
        let j = serde_json::to_value(&o).unwrap();
        assert!(
            j.get("oid").is_none(),
            "submit Order must not serialize oid"
        );
    }

    #[test]
    fn cancel_order_omits_none_fields() {
        let c = CancelOrder {
            owner: Address::ZERO,
            market: MarketId(1),
            oid: Some(OrderId(42)),
            cloid: None,
        };
        let j = serde_json::to_value(&c).unwrap();
        assert!(j.get("oid").is_some());
        assert!(j.get("cloid").is_none());
    }

    // ── OrderStatus union (api/rest/exchange.md — Order response entries) ──

    #[test]
    fn order_status_decodes_resting() {
        let j = serde_json::json!({
            "resting": { "oid": 12345, "cloid": "0x000102030405060708090a0b0c0d0e0f" }
        });
        let s: OrderStatus = serde_json::from_value(j).unwrap();
        match &s {
            OrderStatus::Resting(r) => {
                assert_eq!(r.oid, OrderId(12345));
                assert!(r.cloid.is_some());
            }
            other => panic!("expected Resting, got {other:?}"),
        }
        assert_eq!(s.oid(), Some(OrderId(12345)));
        assert!(!s.is_error());
    }

    #[test]
    fn order_status_decodes_resting_without_cloid() {
        let j = serde_json::json!({ "resting": { "oid": 7 } });
        let s: OrderStatus = serde_json::from_value(j).unwrap();
        match s {
            OrderStatus::Resting(r) => {
                assert_eq!(r.oid, OrderId(7));
                assert!(r.cloid.is_none());
            }
            other => panic!("expected Resting, got {other:?}"),
        }
    }

    #[test]
    fn order_status_decodes_filled_with_string_numerics() {
        let j = serde_json::json!({
            "filled": { "total_sz": "100000000", "avg_px": "10050000000", "oid": 12345 }
        });
        let s: OrderStatus = serde_json::from_value(j).unwrap();
        match s {
            OrderStatus::Filled(f) => {
                assert_eq!(f.total_sz, "100000000");
                assert_eq!(f.avg_px, "10050000000");
                assert_eq!(f.oid, OrderId(12345));
            }
            other => panic!("expected Filled, got {other:?}"),
        }
    }

    #[test]
    fn order_status_decodes_error() {
        let j = serde_json::json!({ "error": "px not tick-aligned" });
        let s: OrderStatus = serde_json::from_value(j).unwrap();
        assert!(s.is_error());
        assert_eq!(s.oid(), None);
        match s {
            OrderStatus::Error(msg) => assert_eq!(msg, "px not tick-aligned"),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn order_response_decodes_statuses_object() {
        // Real server shape: ExchangeResponse `{ statuses: [<per-order union>] }`
        // (api/rest/exchange.md) — an object with a `statuses` array, NOT a bare
        // array. The order path returns exactly this.
        let j = serde_json::json!({ "statuses": [
            { "resting": { "oid": 12345, "cloid": "0x000102030405060708090a0b0c0d0e0f" } },
            { "filled":  { "total_sz": "100000000", "avg_px": "10050000000", "oid": 12346 } },
            { "error":   "size below market minimum" }
        ]});
        let resp: OrderResponse = serde_json::from_value(j).unwrap();
        assert_eq!(resp.statuses.len(), 3);
        assert_eq!(resp.first().and_then(OrderStatus::oid), Some(OrderId(12345)));
        assert!(resp.statuses[2].is_error());
    }

    #[test]
    fn order_response_round_trips() {
        let resp = OrderResponse {
            statuses: vec![
                OrderStatus::Resting(RestingStatus {
                    oid: OrderId(1),
                    cloid: None,
                }),
                OrderStatus::Filled(FilledStatus {
                    total_sz: "5".into(),
                    avg_px: "100".into(),
                    oid: OrderId(2),
                }),
                OrderStatus::Error("nope".into()),
            ],
        };
        let j = serde_json::to_value(&resp).unwrap();
        assert!(j.is_object() && j.get("statuses").is_some(), "OrderResponse wraps the per-order array under `statuses`");
        let dec: OrderResponse = serde_json::from_value(j).unwrap();
        assert_eq!(resp, dec);
    }
}
