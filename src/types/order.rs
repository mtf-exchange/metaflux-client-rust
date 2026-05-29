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
//!   "coid":             null
//! }
//! ```
//!
//! The submit shape carries **no `oid`** — the order id is assigned by the node
//! and returned in [`OrderResponse`]. A client never declares it.
//!
//! Numerics are plain integers (u64 / i64). Sizes / prices use **fixed-point
//! tick units** — the SDK does not adopt the HL decimal-string convention.

use serde::{Deserialize, Serialize};

use crate::types::{Coid, MarketId, OrderId};
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
    pub coid: Option<Coid>,
}

/// Cancel intent — by `oid` or by `coid`.
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
    /// Optional coid (mutually exclusive with `oid`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coid: Option<Coid>,
}

/// Response envelope from `/exchange` for an order submission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct OrderResponse {
    /// Server-assigned oid (non-zero on success).
    pub oid: OrderId,
    /// Outcome — `accepted` / `rejected` / `filled` / etc.
    pub status: String,
    /// Number of base units filled at accept time (0 if fully resting).
    pub filled_size: u64,
    /// Volume-weighted average fill price (0 if no fills).
    pub avg_px: u64,
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
            coid: None,
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
    fn order_omits_none_coid() {
        let o = sample_order();
        let j = serde_json::to_value(&o).unwrap();
        assert!(j.get("coid").is_none());
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
            coid: None,
        };
        let j = serde_json::to_value(&c).unwrap();
        assert!(j.get("oid").is_some());
        assert!(j.get("coid").is_none());
    }
}
