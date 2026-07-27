//! TWAP (time-weighted average price) order types.
//!
//! A TWAP parent slices `total_size` into `slice_count` child orders spaced
//! `delay_ms` apart. `total_size` is in fixed-point tick units like a perp
//! order's `size`.
//!
//! ## Who owns the parent
//!
//! Both actions accept an agent-resolved `owner` on the wire, and this SDK does
//! not yet build it. The signing wallet is therefore the trader. The two
//! actions treat the owner differently, so a future port must keep them apart:
//! `twap_cancel` binds it in the EIP-712 digest (the `*_WITH_OWNER` type
//! string), while `twap_order` uses it only as an admission-routing hint and
//! signs the base type string either way.

use serde::{Deserialize, Serialize};

use crate::types::MarketId;
use crate::types::order::Side;

/// Action — submit a sliced (TWAP) order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TwapOrder {
    /// Target market id.
    pub market: MarketId,
    /// Bid / ask.
    pub side: Side,
    /// Total size in fixed-point tick units, split across all slices.
    pub total_size: u64,
    /// Number of child slices.
    pub slice_count: u32,
    /// Inter-slice delay in milliseconds.
    pub delay_ms: u64,
    /// Reduce-only flag (each slice may only reduce an existing position).
    pub reduce_only: bool,
}

/// Action — cancel a running TWAP parent by id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TwapCancel {
    /// TWAP parent id (assigned when the parent was submitted).
    pub twap_id: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn twap_order_serializes_snake_case() {
        let a = TwapOrder {
            market: MarketId(4),
            side: Side::Ask,
            total_size: 1_000,
            slice_count: 10,
            delay_ms: 500,
            reduce_only: true,
        };
        let j = serde_json::to_value(a).unwrap();
        assert_eq!(j["side"], serde_json::json!("ask"));
        assert_eq!(j["total_size"], serde_json::json!(1_000));
        assert_eq!(j["slice_count"], serde_json::json!(10));
        assert!(j.get("totalSize").is_none(), "no camelCase leak");
    }

    #[test]
    fn twap_cancel_round_trips() {
        let a = TwapCancel { twap_id: 17 };
        let j = serde_json::to_string(&a).unwrap();
        assert_eq!(serde_json::from_str::<TwapCancel>(&j).unwrap(), a);
    }
}
