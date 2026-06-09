//! RFQ — Request-for-Quote.
//!
//! RFQ flow:
//!
//! 1. Taker submits [`RfqRequest`] (action) — opens an RFQ session.
//! 2. MMs see the open RFQ via `subscribe_rfq` (WS) and submit [`MmQuote`]s.
//! 3. Taker picks the best quote and submits [`RfqAccept`] (action) — that
//!    crosses the trade against the chosen MM.
//! 4. Window expires → session closes; status -> `Expired`.
//!
//! Wire shape (snake_case) matches the node's native RFQ action encoding
//! (action field 58).

use serde::{Deserialize, Serialize};

use crate::types::MarketId;
use crate::types::order::Side;
use crate::wallet::Address;

/// Server-assigned RFQ session id.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct RfqId(pub u64);

/// Lifecycle status of an RFQ session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RfqStatus {
    /// Quote window is open; MMs may still submit.
    Open,
    /// Taker accepted a quote.
    Accepted,
    /// Window elapsed without an accept.
    Expired,
    /// Taker cancelled.
    Cancelled,
}

/// Action — taker opens an RFQ session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RfqRequest {
    /// Taker address.
    pub taker: Address,
    /// Market id.
    pub market: MarketId,
    /// Side the taker intends to take.
    pub side: Side,
    /// Requested size in fixed-point tick units.
    pub size: u64,
    /// Quote window in milliseconds (MMs have until `now + window_ms` to
    /// submit). Typical: 500-5000ms.
    pub window_ms: u32,
}

/// One MM quote submitted into an open RFQ.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MmQuote {
    /// RFQ session id.
    pub rfq_id: RfqId,
    /// Market-maker address.
    pub mm: Address,
    /// Quoted price in fixed-point tick units.
    pub price: u64,
    /// Size the MM is willing to take (≤ taker's requested size).
    pub size: u64,
}

/// Action — taker accepts a specific MM quote and crosses the trade.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RfqAccept {
    /// RFQ session id.
    pub rfq_id: RfqId,
    /// MM whose quote is accepted.
    pub mm: Address,
    /// Quoted price (sanity check — server validates against the recorded quote).
    pub price: u64,
}

/// Snapshot of an open RFQ session (returned by `info: rfq_state`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RfqState {
    /// Session id.
    pub rfq_id: RfqId,
    /// Taker address.
    pub taker: Address,
    /// Market id.
    pub market: MarketId,
    /// Side the taker intends to take.
    pub side: Side,
    /// Requested size.
    pub size: u64,
    /// Session expiry timestamp (unix ms).
    pub expires_at_ms: u64,
    /// All quotes submitted so far.
    pub quotes: Vec<MmQuote>,
    /// Current lifecycle status.
    pub status: RfqStatus,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfq_status_serializes_snake_case() {
        assert_eq!(serde_json::to_string(&RfqStatus::Open).unwrap(), "\"open\"");
        assert_eq!(
            serde_json::to_string(&RfqStatus::Accepted).unwrap(),
            "\"accepted\""
        );
        assert_eq!(
            serde_json::to_string(&RfqStatus::Cancelled).unwrap(),
            "\"cancelled\""
        );
    }

    #[test]
    fn rfq_request_round_trips() {
        let r = RfqRequest {
            taker: Address::ZERO,
            market: MarketId(1),
            side: Side::Bid,
            size: 1_000,
            window_ms: 2000,
        };
        let j = serde_json::to_string(&r).unwrap();
        let dec: RfqRequest = serde_json::from_str(&j).unwrap();
        assert_eq!(r, dec);
    }

    #[test]
    fn rfq_request_uses_window_ms_snake_case() {
        let r = RfqRequest {
            taker: Address::ZERO,
            market: MarketId(1),
            side: Side::Ask,
            size: 500,
            window_ms: 2000,
        };
        let j = serde_json::to_value(&r).unwrap();
        assert!(j.get("window_ms").is_some());
        assert!(j.get("windowMs").is_none());
    }
}
