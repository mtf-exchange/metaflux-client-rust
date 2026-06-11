//! FBA — Frequent Batch Auction read types.
//!
//! Under per-market FBA mode, orders accumulate into a batch over a fixed
//! window (typically 100-500 ms) and match uniformly at the end of each window,
//! removing the speed advantage of co-located makers. These types model the FBA
//! config and cleared-batch results read back over `/info`.

use serde::{Deserialize, Serialize};

use crate::types::MarketId;
use crate::types::rfq::CoreSide;

/// FBA configuration per market.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct FbaConfig {
    /// Auction window in milliseconds (100-500ms typical).
    pub period_ms: u32,
    /// Minimum lot for an FBA submission.
    pub min_lot: u64,
    /// Timestamp of the next auction (unix ms).
    pub next_auction_at_ms: u64,
    /// Whether FBA is enabled for this market (otherwise CLOB-only).
    pub enabled: bool,
}

/// FBA batch result published after the auction clears.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct FbaBatchResult {
    /// Batch id.
    pub batch_id: u64,
    /// Market id.
    pub market: MarketId,
    /// Uniform clearing price for this batch (tick units).
    pub clearing_px: u64,
    /// Total volume matched.
    pub volume: u64,
    /// Batch close timestamp (unix ms).
    pub closed_at_ms: u64,
}

/// Action — `fba_submit`: submit an order into a market's frequent-batch-auction
/// pool.
///
/// Mirrors the node's `core_state` `FbaSubmitParams`. The action envelope wraps
/// this under the key **`submit`**.
///
/// Traps mirrored from the node: `side` is PascalCase ([`CoreSide`]), the price
/// field is named **`price`** (NOT `limit_px` as in spot/perp orders), and
/// `stp_group` carries no serde default so the key must be present (`null` for
/// `None`).
///
/// Forward-compat: see [`crate::types::rfq::RfqRequest`] — the node returns
/// `UnsupportedAction` until it bridges this handler onto `/exchange`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct FbaSubmit {
    /// Target market.
    pub market: MarketId,
    /// Side — serializes PascalCase (`"Bid"`/`"Ask"`).
    pub side: CoreSide,
    /// Submitted size (`>= pool.min_lot`).
    pub size: u128,
    /// Limit / worst-acceptable price (`> 0`). Field is `price` per the core
    /// struct — not `limit_px`.
    pub price: i128,
    /// Optional STP group. Key is always present (`null` for `None`).
    pub stp_group: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fba_submit_uses_price_pascalcase_side_and_present_stp() {
        let s = FbaSubmit {
            market: MarketId(7),
            side: CoreSide::Ask,
            size: 1_000,
            price: 5_000_000_000,
            stp_group: None,
        };
        let j = serde_json::to_value(s).unwrap();
        assert_eq!(j["side"], "Ask");
        // Price field is `price`, NOT `limit_px`.
        assert!(j.get("price").is_some());
        assert!(j.get("limit_px").is_none());
        // No serde default on the node => key present, value null.
        assert!(j.get("stp_group").is_some() && j["stp_group"].is_null());
        let dec: FbaSubmit = serde_json::from_value(j).unwrap();
        assert_eq!(dec, s);
    }

    #[test]
    fn fba_config_round_trips() {
        let c = FbaConfig {
            period_ms: 250,
            min_lot: 5,
            next_auction_at_ms: 1_700_000_001_000,
            enabled: true,
        };
        let j = serde_json::to_string(&c).unwrap();
        let dec: FbaConfig = serde_json::from_str(&j).unwrap();
        assert_eq!(c, dec);
    }

    #[test]
    fn batch_result_has_clearing_px_field() {
        let r = FbaBatchResult {
            batch_id: 1,
            market: MarketId(1),
            clearing_px: 5_000_000_000_000,
            volume: 1000,
            closed_at_ms: 1_700_000_002_000,
        };
        let j = serde_json::to_value(&r).unwrap();
        assert!(j.get("clearing_px").is_some());
    }
}
