//! Spot CLOB types — SE-0 spot order / cancel (MTF-native `/exchange`).
//!
//! The spot order engine (SE-0) is a separate CLOB from the perp book: orders
//! reference a spot `pair` id (not a perp `market` id) and trade raw base lots
//! against a quote. v0 is **IOC limit only** — `tif` must be `ioc` and
//! `limit_px > 0`; the node rejects `gtc` / `alo` and a market (`limit_px = 0`)
//! order at admission. The builders here default `tif` to [`TimeInForce::Ioc`]
//! and document the constraint, but do not hard-block other tifs so a caller
//! can pass one through unchanged once the node lifts the v0 limit.
//!
//! Wire shape (MTF-native, snake_case):
//!
//! ```json
//! {
//!   "pair":      3,
//!   "side":      "bid",
//!   "size":      1000,
//!   "limit_px":  5000000000,
//!   "tif":       "ioc",
//!   "stp_mode":  "cancel_oldest",
//!   "cloid":     null
//! }
//! ```
//!
//! Numerics are plain integers. `size` is in raw base lots (u64); `limit_px`
//! is on the 1e8 fixed-point price plane (u64). `cloid` is a 32-char hex
//! `0x...` string or omitted (`null`).

use serde::{Deserialize, Serialize};

use crate::types::Cloid;
use crate::types::order::{Side, StpMode, TimeInForce};

/// A single spot CLOB order submission (SE-0).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SpotOrder {
    /// Target spot pair id.
    pub pair: u32,
    /// Bid / ask.
    pub side: Side,
    /// Size in raw base lots (u64).
    pub size: u64,
    /// Limit price on the 1e8 fixed-point price plane (u64). v0 requires
    /// `limit_px > 0` — a market (px = 0) order is rejected.
    pub limit_px: u64,
    /// Time-in-force. v0 supports `ioc` only; defaults to [`TimeInForce::Ioc`]
    /// via [`SpotOrder::ioc_limit`].
    pub tif: TimeInForce,
    /// Self-trade-prevention mode (the same wire enum as a perp order — the spot
    /// engine accepts no extra modes).
    pub stp_mode: StpMode,
    /// Optional client-supplied identifier for idempotency.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloid: Option<Cloid>,
}

impl SpotOrder {
    /// Build a v0-conformant IOC limit spot order.
    ///
    /// `tif` defaults to [`TimeInForce::Ioc`] and `stp_mode` to
    /// [`StpMode::CancelOldest`] (the engine default); set
    /// [`SpotOrder::cloid`] / [`SpotOrder::stp_mode`] afterwards to override.
    /// `limit_px` must be `> 0` for the node to accept it.
    #[must_use]
    pub const fn ioc_limit(pair: u32, side: Side, size: u64, limit_px: u64) -> Self {
        Self {
            pair,
            side,
            size,
            limit_px,
            tif: TimeInForce::Ioc,
            stp_mode: StpMode::CancelOldest,
            cloid: None,
        }
    }
}

/// Cancel a resting spot order by `oid`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SpotCancel {
    /// Target spot pair id.
    pub pair: u32,
    /// Server-assigned spot order id.
    pub oid: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spot_order_ioc_limit_defaults() {
        let o = SpotOrder::ioc_limit(3, Side::Bid, 1000, 5_000_000_000);
        assert_eq!(o.tif, TimeInForce::Ioc);
        assert_eq!(o.stp_mode, StpMode::CancelOldest);
        assert!(o.cloid.is_none());
    }

    #[test]
    fn spot_order_serializes_snake_case_integers() {
        let o = SpotOrder::ioc_limit(3, Side::Ask, 1000, 5_000_000_000);
        let j = serde_json::to_value(&o).unwrap();
        assert!(j["pair"].is_number());
        assert!(j["size"].is_number());
        assert!(j["limit_px"].is_number(), "limit_px must be a plain number");
        assert_eq!(j["side"], serde_json::json!("ask"));
        assert_eq!(j["tif"], serde_json::json!("ioc"));
        assert_eq!(j["stp_mode"], serde_json::json!("cancel_oldest"));
        assert!(j.get("limitPx").is_none(), "no camelCase leak");
    }

    #[test]
    fn spot_order_omits_none_cloid() {
        let o = SpotOrder::ioc_limit(1, Side::Bid, 1, 1);
        let j = serde_json::to_value(&o).unwrap();
        assert!(j.get("cloid").is_none());
    }

    #[test]
    fn spot_order_serializes_cloid_when_set() {
        let mut o = SpotOrder::ioc_limit(1, Side::Bid, 1, 1);
        o.cloid = Some(Cloid([0xCDu8; 16]));
        let j = serde_json::to_value(&o).unwrap();
        assert_eq!(
            j["cloid"],
            serde_json::json!("0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd")
        );
    }

    #[test]
    fn spot_order_round_trips() {
        let mut o = SpotOrder::ioc_limit(7, Side::Ask, 42, 9_999);
        o.stp_mode = StpMode::CancelNewest;
        o.cloid = Some(Cloid([0x01u8; 16]));
        let j = serde_json::to_string(&o).unwrap();
        let dec: SpotOrder = serde_json::from_str(&j).unwrap();
        assert_eq!(o, dec);
    }

    #[test]
    fn spot_cancel_serializes_snake_case() {
        let c = SpotCancel { pair: 3, oid: 12345 };
        let j = serde_json::to_value(c).unwrap();
        assert_eq!(j["pair"], serde_json::json!(3));
        assert_eq!(j["oid"], serde_json::json!(12345));
        let dec: SpotCancel = serde_json::from_value(j).unwrap();
        assert_eq!(c, dec);
    }
}
