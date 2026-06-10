//! RFQ — Request-for-Quote read types.
//!
//! A taker opens an RFQ session; market makers submit [`MmQuote`]s; the taker
//! crosses against the best quote, or the window expires. These types model the
//! session state read back over `/info` and the WebSocket RFQ channel.

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

/// Snapshot of an open RFQ session (returned over `/info`).
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
    fn rfq_state_round_trips() {
        let s = RfqState {
            rfq_id: RfqId(7),
            taker: Address::ZERO,
            market: MarketId(1),
            side: Side::Bid,
            size: 1_000,
            expires_at_ms: 1_700_000_000_000,
            quotes: vec![MmQuote {
                rfq_id: RfqId(7),
                mm: Address::ZERO,
                price: 100,
                size: 500,
            }],
            status: RfqStatus::Open,
        };
        let j = serde_json::to_string(&s).unwrap();
        let dec: RfqState = serde_json::from_str(&j).unwrap();
        assert_eq!(s, dec);
    }
}
