//! Chase-order types — one signed intent the node keeps re-pricing to the top
//! of the book until it fills, expires, or hits its reprice cap.
//!
//! Wire shape (MTF-native, snake_case), mirroring the node's `NativeChaseOrder`:
//!
//! ```json
//! {
//!   "market":          3,
//!   "side":            "bid",
//!   "size":            4000,
//!   "cloid":           "0x...",
//!   "stp_mode":        "cancel_oldest",
//!   "interval_blocks": 4,
//!   "ttl_ms":          3_600_000,
//!   "max_reprices":    500
//! }
//! ```
//!
//! One `chase_order` places a single post-only leg near the best price. Each
//! reprice cancels the old leg and places a new leg that shares the SAME
//! re-stamped `cloid` (only the leg oid changes). The leg tracks the top of book
//! until one of three limits ends it: the order fills, `ttl_ms` elapses
//! (consensus time), or `max_reprices` executed reprices is reached.
//!
//! `size` is a raw-lot size on the market's `10^sz_decimals` plane. There is no
//! chase WS channel — correlate the leg placements and the fills by `cloid` on
//! the existing `order_updates` / `open_orders` / `fills` feeds.
//!
//! PERP MARKETS ONLY TODAY. A spot pair id in `market` is refused at commit with
//! `chase market has no tick/lot grid`. The spot lane is built and waits for an
//! activation height: above it the leg pegs inside the SPOT touch,
//! `position_side` is refused, a reprice that needs more free quote than the
//! owner holds is SKIPPED without cancelling the current leg, and a failed
//! re-place RETIRES the chase. The wire shape does not change, so these types
//! need no new field.

use serde::{Deserialize, Serialize};

use crate::types::order::{PositionSide, Side, StpMode};
use crate::types::{Cloid, MarketId};
use crate::wallet::Address;

/// Inclusive bounds for [`ChaseParams::interval_blocks`] (debounce K, committed
/// heights). Mirrors the node's admission guard. A value outside this range is
/// rejected at admission.
pub const CHASE_INTERVAL_BLOCKS_RANGE: std::ops::RangeInclusive<u32> = 2..=28_800;

/// Inclusive bounds for [`ChaseParams::ttl_ms`] (time-to-live, consensus ms):
/// 1 minute to 7 days. Mirrors the node's admission guard.
pub const CHASE_TTL_MS_RANGE: std::ops::RangeInclusive<u64> = 60_000..=604_800_000;

/// Inclusive bounds for [`ChaseParams::max_reprices`]. Mirrors the node's
/// admission guard.
pub const CHASE_MAX_REPRICES_RANGE: std::ops::RangeInclusive<u32> = 1..=100_000;

/// A chase order — one signature places a self-repricing post-only leg that
/// tracks the top of book until it fills, expires, or hits `max_reprices`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ChaseParams {
    /// Target market id — a PERP market today. A spot pair id is refused until
    /// the spot lane activates (see the module doc).
    pub market: MarketId,
    /// Leg side (`bid` = buy chase, `ask` = sell chase).
    pub side: Side,
    /// Leg size (raw-lot plane). MUST be `> 0` and on the lot grid.
    pub size: u64,
    /// Optional client handle. Re-stamped on every reprice leg (each reprice
    /// carries the SAME `cloid`; only the leg oid changes). Omitted from the wire
    /// when absent; signs the empty-string sentinel.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloid: Option<Cloid>,
    /// Self-trade prevention mode, re-applied on every leg.
    pub stp_mode: StpMode,
    /// Hedge-mode leg selector. `None` (omitted) on a one-way account; REQUIRED
    /// on a hedge account. Signs the empty-string sentinel when absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub position_side: Option<PositionSide>,
    /// Debounce K, in committed heights. See [`CHASE_INTERVAL_BLOCKS_RANGE`].
    pub interval_blocks: u32,
    /// Time-to-live in consensus ms. See [`CHASE_TTL_MS_RANGE`].
    pub ttl_ms: u64,
    /// Cap on executed reprices. See [`CHASE_MAX_REPRICES_RANGE`].
    pub max_reprices: u32,
    /// Optional agent-resolved owner (operator / vault trading). `None` = the
    /// signer trades for itself. Bound into the `*_WITH_OWNER` digest when
    /// present; omitted from the wire otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<Address>,
}

/// Cancel a running chase by its registry handle.
///
/// The `chase_oid` is the stable handle returned by admission (the `chase_oid`
/// field of the `chase` status), NOT the leg's oid. Owner-gated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CancelChaseParams {
    /// Target market id. MUST match the chase's market.
    pub market: MarketId,
    /// The chase handle (registry key) returned by admission.
    pub chase_oid: u64,
    /// Optional agent-resolved owner (operator / vault trading). `None` = self.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<Address>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cloid() -> Cloid {
        Cloid([0xCD; 16])
    }

    fn base_params() -> ChaseParams {
        ChaseParams {
            market: MarketId(3),
            side: Side::Bid,
            size: 4000,
            cloid: None,
            stp_mode: StpMode::CancelOldest,
            position_side: None,
            interval_blocks: 4,
            ttl_ms: 3_600_000,
            max_reprices: 500,
            owner: None,
        }
    }

    #[test]
    fn chase_params_serializes_snake_case_integers() {
        let p = ChaseParams {
            cloid: Some(cloid()),
            ..base_params()
        };
        let j = serde_json::to_value(&p).unwrap();
        assert_eq!(j["market"], serde_json::json!(3));
        assert_eq!(j["side"], serde_json::json!("bid"));
        assert!(j["size"].is_number(), "size is a plain JSON number");
        assert!(j["interval_blocks"].is_number());
        assert!(j["ttl_ms"].is_number());
        assert!(j["max_reprices"].is_number());
        assert_eq!(j["stp_mode"], serde_json::json!("cancel_oldest"));
        assert_eq!(
            j["cloid"],
            serde_json::json!("0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd")
        );
        // No camelCase leak.
        assert!(j.get("intervalBlocks").is_none());
        assert!(j.get("ttlMs").is_none());
        assert!(j.get("maxReprices").is_none());
    }

    #[test]
    fn chase_params_omits_none_optionals() {
        let p = base_params();
        let j = serde_json::to_value(&p).unwrap();
        assert!(j.get("owner").is_none());
        assert!(j.get("position_side").is_none());
        assert!(j.get("cloid").is_none());
    }

    #[test]
    fn chase_params_serializes_hedge_and_owner_when_set() {
        let p = ChaseParams {
            position_side: Some(PositionSide::Short),
            owner: Some(Address([0x11; 20])),
            ..base_params()
        };
        let j = serde_json::to_value(&p).unwrap();
        assert_eq!(j["position_side"], serde_json::json!("short"));
        assert_eq!(
            j["owner"],
            serde_json::json!("0x1111111111111111111111111111111111111111")
        );
    }

    #[test]
    fn chase_params_round_trips() {
        let p = ChaseParams {
            cloid: Some(cloid()),
            position_side: Some(PositionSide::Long),
            ..base_params()
        };
        let j = serde_json::to_string(&p).unwrap();
        let dec: ChaseParams = serde_json::from_str(&j).unwrap();
        assert_eq!(p, dec);
    }

    #[test]
    fn cancel_chase_omits_none_owner() {
        let c = CancelChaseParams {
            market: MarketId(3),
            chase_oid: 12345,
            owner: None,
        };
        let j = serde_json::to_value(c).unwrap();
        assert!(j.get("owner").is_none());
        assert_eq!(j["market"], serde_json::json!(3));
        assert!(j["chase_oid"].is_number());
        assert_eq!(j["chase_oid"], serde_json::json!(12345));
    }

    #[test]
    fn cancel_chase_round_trips() {
        let c = CancelChaseParams {
            market: MarketId(7),
            chase_oid: 99,
            owner: Some(Address([0x22; 20])),
        };
        let j = serde_json::to_string(&c).unwrap();
        let dec: CancelChaseParams = serde_json::from_str(&j).unwrap();
        assert_eq!(c, dec);
    }

    #[test]
    fn admission_range_constants_match_contract() {
        assert_eq!(CHASE_INTERVAL_BLOCKS_RANGE, 2..=28_800);
        assert_eq!(CHASE_TTL_MS_RANGE, 60_000..=604_800_000);
        assert_eq!(CHASE_MAX_REPRICES_RANGE, 1..=100_000);
    }
}
