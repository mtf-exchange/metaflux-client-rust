//! Scale-ladder order types — one signed compact ladder the node expands
//! DETERMINISTICALLY into N resting limit legs that share one `cloid`.
//!
//! Wire shape (MTF-native, snake_case), mirroring the node's `NativeScaleOrder`:
//!
//! ```json
//! {
//!   "market":        3,
//!   "side":          "bid",
//!   "n":             4,
//!   "px_low":        6_800_000_000_000,
//!   "px_high":       6_900_000_000_000,
//!   "total_size":    4000,
//!   "dist":          "lin_desc",
//!   "tif":           "alo",
//!   "reduce_only":   false,
//!   "stp_mode":      "cancel_oldest",
//!   "cloid":         "0x..."
//! }
//! ```
//!
//! `px_low` / `px_high` are 1e8-plane fixed-point prices; `total_size` is a
//! raw-lot size. The `weights` array rides the wire ONLY for `dist == "custom"`
//! (the node derives the weights from `dist` + `n` otherwise, so a non-custom
//! order MUST carry an empty array — the node rejects a non-empty one). The
//! EIP-712 digest binds `weights` as a `bytes32`: `keccak256(concat(per-weight
//! 32-byte-big-endian words))` for `custom`, the 32-byte ZERO hash otherwise.
//!
//! PERP MARKETS ONLY TODAY. A spot pair id in `market` is refused at commit —
//! every rung is refused in its own slot and nothing rests. The spot lane is
//! built and waits for an activation height: above it the rungs floor onto the
//! PAIR's tick/lot grid and run the spot admission, and `reduce_only` /
//! `position_side` are refused. The wire shape does not change, so these types
//! need no new field.

use serde::{Deserialize, Serialize};

use crate::types::order::{PositionSide, Side, StpMode, TimeInForce};
use crate::types::{Cloid, MarketId};
use crate::wallet::Address;

/// Maximum rung count of a scale ladder (`2 ..= 100`). Mirrors the node's
/// `MAX_SCALE_RUNGS`; a `custom` order's `weights` length MUST equal `n` and
/// never exceed this bound.
pub const MAX_SCALE_RUNGS: u32 = 100;

/// Size distribution across a scale ladder's rungs.
///
/// `Flat` / `LinAsc` / `LinDesc` are derived by the node from `dist` + `n`, so
/// they carry NO `weights` array (empty on the wire). `Custom` reads the
/// per-rung `weights` array (length must equal `n`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScaleDist {
    /// Equal weight on every rung.
    #[default]
    Flat,
    /// Weight rises with rung index.
    LinAsc,
    /// Weight falls with rung index.
    LinDesc,
    /// Per-rung weights read from the `weights` array.
    Custom,
}

/// A scale-ladder order — one signature places `n` resting limit legs between
/// `px_low` and `px_high` sharing one `cloid`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ScaleParams {
    /// Target market id.
    pub market: MarketId,
    /// Ladder side (rung 0 sits at `px_low` for both bids and asks).
    pub side: Side,
    /// Rung count. `2 ..= MAX_SCALE_RUNGS`.
    pub n: u32,
    /// Low end of the ladder (1e8 price plane).
    pub px_low: u64,
    /// High end of the ladder (1e8 price plane).
    pub px_high: u64,
    /// Total base size across all rungs (raw-lot plane).
    pub total_size: u64,
    /// Size distribution across the rungs.
    pub dist: ScaleDist,
    /// Per-rung weights. Read ONLY for `dist == Custom` (length must equal `n`);
    /// MUST be empty for any other distribution.
    #[serde(default)]
    pub weights: Vec<u32>,
    /// Time-in-force (`gtc` / `alo`; `ioc` / `aon` are rejected by the node).
    pub tif: TimeInForce,
    /// Reduce-only flag, uniform across rungs.
    #[serde(default)]
    pub reduce_only: bool,
    /// Self-trade prevention mode, uniform across rungs.
    pub stp_mode: StpMode,
    /// Hedge-mode leg selector. `None` (omitted) on a one-way account; REQUIRED
    /// on a hedge account. Signs the empty-string sentinel when absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub position_side: Option<PositionSide>,
    /// The ladder handle, shared by every rung (`0x`-hex, REQUIRED).
    pub cloid: Cloid,
    /// Optional agent-resolved owner (operator / vault trading). `None` = the
    /// signer trades for itself. Bound into the `*_WITH_OWNER` digest when
    /// present; omitted from the wire otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<Address>,
}

/// Cancel every resting leg on `market` that carries `cloid`
/// (cancel-all-by-cloid for a scale ladder).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CancelScaleParams {
    /// Target market id.
    pub market: MarketId,
    /// The ladder handle to sweep (`0x`-hex, REQUIRED).
    pub cloid: Cloid,
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

    #[test]
    fn scale_dist_serializes_snake_case() {
        assert_eq!(serde_json::to_string(&ScaleDist::Flat).unwrap(), "\"flat\"");
        assert_eq!(
            serde_json::to_string(&ScaleDist::LinAsc).unwrap(),
            "\"lin_asc\""
        );
        assert_eq!(
            serde_json::to_string(&ScaleDist::LinDesc).unwrap(),
            "\"lin_desc\""
        );
        assert_eq!(
            serde_json::to_string(&ScaleDist::Custom).unwrap(),
            "\"custom\""
        );
    }

    #[test]
    fn scale_params_omits_none_owner_and_position_side() {
        let p = ScaleParams {
            market: MarketId(3),
            side: Side::Bid,
            n: 4,
            px_low: 100,
            px_high: 200,
            total_size: 4000,
            dist: ScaleDist::LinDesc,
            weights: vec![],
            tif: TimeInForce::Alo,
            reduce_only: false,
            stp_mode: StpMode::CancelOldest,
            position_side: None,
            cloid: cloid(),
            owner: None,
        };
        let j = serde_json::to_value(&p).unwrap();
        assert!(j.get("owner").is_none());
        assert!(j.get("position_side").is_none());
    }

    #[test]
    fn cancel_scale_omits_none_owner() {
        let c = CancelScaleParams {
            market: MarketId(3),
            cloid: cloid(),
            owner: None,
        };
        let j = serde_json::to_value(c).unwrap();
        assert!(j.get("owner").is_none());
        assert_eq!(j["market"], serde_json::json!(3));
    }
}
