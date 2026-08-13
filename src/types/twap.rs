//! TWAP (time-weighted average price) order types.
//!
//! A TWAP parent slices `total_size` into `slice_count` child orders spaced
//! `delay_ms` apart. `total_size` is in fixed-point tick units like a perp
//! order's `size`.
//!
//! ## Two optional fields select the signing string
//!
//! [`TwapOrder::position_side`] and [`TwapOrder::randomize`] each move the
//! EIP-712 type string, so the payload and the signature must agree. The node's
//! rule, mirrored by this SDK's typed-order signer: `randomize == true` selects
//! the V3 string WHATEVER the leg (a one-way randomized parent signs an EMPTY
//! `positionSide`); else a present `position_side` selects V2; else the base
//! string. A one-way, non-randomized parent therefore signs the same bytes an
//! older SDK signed.
//!
//! A HEDGE account MUST send `position_side` and a one-way account MUST NOT: the
//! wrong one is admitted to the mempool and rejected at commit, on no channel.
//!
//! ## Perp markets only today
//!
//! A spot pair id in `market` is refused at commit with `no perp market for
//! asset`. The spot lane is built and waits for an activation height. Above it
//! each slice is an IOC through the spot order path, priced off the base token's
//! oracle mark rather than off the touch, and three fields are REFUSED rather
//! than dropped — the whole action is rejected:
//!
//! - `reduce_only: true` — `spot has no position to reduce: reduce_only is not supported`
//! - `position_side` — `spot has no position side`
//! - `randomize: true` — `spot twap does not support randomize`
//!
//! One live-parent budget covers perp and spot parents together, and
//! [`TwapCancel`] takes a spot parent's id unchanged. The wire shape does not
//! change, so these types need no new field for the spot lane.
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
use crate::types::order::{PositionSide, Side};

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
    /// The leg every child slice carries. REQUIRED on a hedge account, REFUSED
    /// on a one-way one. `None` omits the field on the wire and keeps the base
    /// signing string, so a one-way payload stays byte-identical to an older
    /// SDK.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub position_side: Option<PositionSide>,
    /// Randomized schedule: the chain draws each slice size and each
    /// inter-slice delay from a digest over committed inputs, so the schedule is
    /// harder to front-run. Deterministic — every validator draws the same
    /// numbers, and the sizes still sum to `total_size`.
    ///
    /// `false` omits the field on the wire and keeps the older signing strings.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub randomize: bool,
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

    fn one_way() -> TwapOrder {
        TwapOrder {
            market: MarketId(4),
            side: Side::Ask,
            total_size: 1_000,
            slice_count: 10,
            delay_ms: 500,
            reduce_only: true,
            position_side: None,
            randomize: false,
        }
    }

    #[test]
    fn twap_order_serializes_snake_case() {
        let j = serde_json::to_value(one_way()).unwrap();
        assert_eq!(j["side"], serde_json::json!("ask"));
        assert_eq!(j["total_size"], serde_json::json!(1_000));
        assert_eq!(j["slice_count"], serde_json::json!(10));
        assert!(j.get("totalSize").is_none(), "no camelCase leak");
    }

    /// A one-way, non-randomized parent must serialize the pre-hedge field set,
    /// or an older payload stops matching its own signing string.
    #[test]
    fn one_way_parent_omits_both_optional_fields() {
        let j = serde_json::to_value(one_way()).unwrap();
        assert!(j.get("position_side").is_none());
        assert!(j.get("randomize").is_none());
    }

    #[test]
    fn hedge_and_randomized_parents_serialize_their_fields() {
        let mut a = one_way();
        a.position_side = Some(PositionSide::Long);
        a.randomize = true;
        let j = serde_json::to_value(a).unwrap();
        assert_eq!(j["position_side"], serde_json::json!("long"));
        assert_eq!(j["randomize"], serde_json::json!(true));
    }

    #[test]
    fn twap_cancel_round_trips() {
        let a = TwapCancel { twap_id: 17 };
        let j = serde_json::to_string(&a).unwrap();
        assert_eq!(serde_json::from_str::<TwapCancel>(&j).unwrap(), a);
    }
}
