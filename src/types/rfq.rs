//! RFQ — Request-for-Quote WRITE types.
//!
//! # RFQ IS THE OPTION TRADE PATH
//!
//! All three actions clear OPTION series and nothing else. A market that is not
//! a live option series is rejected:
//!
//! ```text
//! precondition failed: rfq is options-only: market <n> is not an option series
//! ```
//!
//! A request-for-quote lane beside a public order book lets size trade away from
//! the price everyone else posts against, so MetaFlux offers RFQ only where
//! there is no continuous book to undercut. Options have none.
//!
//! `market` takes the `signing_id` of a live series, from
//! [`Info::option_series`](crate::rest::info::Info::option_series). Serve that
//! number; do not derive it.
//!
//! A taker opens an RFQ session; market makers quote it; the taker accepts one
//! quote, or the window expires. An accept moves the premium from the buyer to
//! the writer and locks the writer's escrow. It opens no perpetual position and
//! reserves no margin.
//!
//! # THE PREMIUM IS USDC. THE ESCROW MAY NOT BE.
//!
//! A quote price, and [`RfqRequest::limit_px`], are USDC per whole underlying
//! unit on BOTH option kinds. The fill moves the premium and the taker fee
//! through the unified USDC pool.
//!
//! The ESCROW follows the series instead. A put escrows USDC; a CALL escrows
//! the underlying coin, one coin per unit. The series row names the asset in
//! `settle_asset` — read it, because the two denominations meet on one action:
//! a client prices a call in dollars and funds it in coin.
//!
//! So a writer on a call series must hold the COIN on the spot ledger. Holding
//! it IS the collateral test, and the coin escrow cannot net against the USDC
//! premium the fill pays in. Two rejections follow, and both are reachable:
//!
//! ```text
//! precondition failed: insufficient underlying balance for the escrow
//! precondition failed: insufficient free collateral for the fee
//! ```
//!
//! The second is a separate gate: the fee leg is USDC even when the escrow is
//! not, so a writer holding the coin and no dollars still fails it.
//!
//! These types model the ACTIONS a client submits. The session reads
//! `rfq_open` and `rfq_user` are public, and this SDK does not type them yet, so
//! a caller reads them raw to find its own `rfq_id` and the `quote_idx` an
//! accept must name. No WS channel carries an RFQ event, so both are polled.

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
/// The signed typed path is [`Exchange::rfq_request_typed`](crate::rest::exchange::Exchange::rfq_request_typed),
/// which posts the action under `params`. This struct models the older
/// envelope shape and is kept for callers that build the body themselves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RfqRequest {
    /// Market to request a quote on.
    pub market: MarketId,
    /// Taker side — serializes PascalCase (`"Bid"`/`"Ask"`).
    pub side: CoreSide,
    /// Requested size (must be > 0).
    pub size: u128,
    /// Optional worst-acceptable price, USDC per whole underlying unit. USDC
    /// on both option kinds — see the module header. Key is always present
    /// (`null` for `None`).
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
/// Envelope note: see [`RfqRequest`].
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
