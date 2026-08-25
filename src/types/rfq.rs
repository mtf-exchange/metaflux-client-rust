//! RFQ — Request-for-Quote WRITE types.
//!
//! A taker opens an RFQ session; market makers quote it; the taker crosses
//! against the best quote, or the window expires. These types model the ACTIONS
//! a client submits. The read side is OPERATOR LANE: the RFQ engine is not
//! reachable from the public `/exchange` yet, so its `rfq_open` / `rfq_user`
//! reads do not ship publicly and this SDK types no response for them.

use serde::{Deserialize, Serialize};

use crate::types::MarketId;

/// Server-assigned RFQ session id.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct RfqId(pub u64);

/// Order side as the **core** RFQ / FBA action handlers deserialize it:
/// PascalCase `Bid` / `Ask`.
///
/// Deliberately distinct from [`crate::types::order::Side`] (snake_case
/// `bid`/`ask`): the node's `core_state::Side` enum carries no
/// `#[serde(rename_all)]`, so the `rfq_request` / `fba_submit` payloads expect
/// PascalCase tokens. Reusing the snake_case `Side` would silently emit
/// `"bid"`/`"ask"` that the core handlers reject.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoreSide {
    /// Buy side.
    Bid,
    /// Sell side.
    Ask,
}

/// Action — `rfq_request`: a taker opens an RFQ session asking MMs to quote.
///
/// Mirrors the node's `core_state` `RfqRequestParams`. The action envelope
/// wraps this under the key **`rfq`** (not `params`).
///
/// `limit_px` and `stp_group` carry **no** serde default on the node, so the
/// keys must always be present — `None` serializes as JSON `null` (the SDK does
/// not skip them).
///
/// Forward-compat: the node currently answers this tag with `UnsupportedAction`
/// on the public `/exchange` path; the SDK emits the byte-correct shape the
/// core handler will accept once the bridge lands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RfqRequest {
    /// Market to request a quote on.
    pub market: MarketId,
    /// Taker side — serializes PascalCase (`"Bid"`/`"Ask"`).
    pub side: CoreSide,
    /// Requested size (must be > 0).
    pub size: u128,
    /// Optional worst-acceptable price. Key is always present (`null` for
    /// `None`).
    pub limit_px: Option<i128>,
    /// Server-clock expiry (ms). `0` lets the node default to `ts_ms + 5_000`.
    pub expiry_ms: u64,
    /// Optional STP group id. Key is always present (`null` for `None`).
    pub stp_group: Option<u64>,
}

/// Action — `rfq_accept`: a taker crosses against a specific resting quote.
///
/// Mirrors the node's `RfqAcceptParams`. The action envelope wraps this under
/// the key **`accept`** — note the family inconsistency (`rfq_request` uses
/// `rfq`, `rfq_accept` uses `accept`).
///
/// Forward-compat: see [`RfqRequest`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RfqAccept {
    /// Parent RFQ session id.
    pub rfq_id: RfqId,
    /// Index of the accepted quote in the session's quote vector.
    pub quote_idx: u32,
    /// Accepted size (`<= min(request.size, quote.max_size)`).
    pub size: u128,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_side_serializes_pascal_case() {
        assert_eq!(serde_json::to_string(&CoreSide::Bid).unwrap(), "\"Bid\"");
        assert_eq!(serde_json::to_string(&CoreSide::Ask).unwrap(), "\"Ask\"");
    }

    #[test]
    fn rfq_request_keeps_optional_keys_present() {
        let r = RfqRequest {
            market: MarketId(7),
            side: CoreSide::Bid,
            size: 1_000,
            limit_px: None,
            expiry_ms: 0,
            stp_group: None,
        };
        let j = serde_json::to_value(r).unwrap();
        assert_eq!(j["side"], "Bid");
        assert_eq!(j["market"], 7);
        // The node core struct has no serde default => the keys must be present
        // (value `null`); a skip_serializing_if would break decode there.
        assert!(j.get("limit_px").is_some() && j["limit_px"].is_null());
        assert!(j.get("stp_group").is_some() && j["stp_group"].is_null());
        let dec: RfqRequest = serde_json::from_value(j).unwrap();
        assert_eq!(dec, r);
    }

    #[test]
    fn rfq_accept_round_trips() {
        let a = RfqAccept {
            rfq_id: RfqId(5),
            quote_idx: 0,
            size: 1_000,
        };
        let j = serde_json::to_value(a).unwrap();
        assert_eq!(j["rfq_id"], 5);
        assert_eq!(j["quote_idx"], 0);
        let dec: RfqAccept = serde_json::from_value(j).unwrap();
        assert_eq!(dec, a);
    }
}
