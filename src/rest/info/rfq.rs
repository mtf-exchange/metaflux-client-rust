//! `/info` — RFQ session reads.
//!
//! Two public reads: [`Info::rfq_open`] and [`Info::rfq_user`].
//!
//! ## Both ends of the lane need a read
//!
//! RFQ is the option trade path, and it takes four steps: a taker requests, a
//! maker quotes, the taker accepts, the engine fills. A taker learns the
//! `rfq_id` its request was assigned from [`Info::rfq_user`], and a maker finds
//! a request to quote on from [`Info::rfq_open`]. Without both reads a caller
//! can post a request and can never complete an accept.

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::error::ClientError;
use crate::rest::info::Info;
use crate::wallet::Address;

/// One maker quote resting on an [`OpenRfq`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RfqQuoteRow {
    /// The quoting maker, `0x` hex.
    pub maker: String,
    /// The maker's self-trade-prevention group, when it set one.
    #[serde(default)]
    pub maker_stp_group: Option<u64>,
    /// Quoted price, whole-USDC decimal string.
    pub price: String,
    /// Largest size the maker will fill, decimal string in the series size
    /// plane.
    pub max_size: String,
    /// Consensus ms the quote stops being acceptable.
    pub valid_until: u64,
    /// Consensus ms the quote was posted.
    pub submitted_at: u64,
}

/// One open RFQ request with every quote resting on it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct OpenRfq {
    /// Session id. This is the `rfq_id` an accept names.
    pub rfq_id: u64,
    /// The `uint32` to put in the signed `market` field. It differs from
    /// `rfq_id` and from any perp asset id — RFQ markets sit in their own id
    /// range — so a signer cannot derive it and must read it here.
    pub signing_id: u32,
    /// Underlying market symbol of the option series. `None` when the series is
    /// no longer registered.
    #[serde(default)]
    pub underlying: Option<String>,
    /// Taker direction, `"B"` (bid) or `"A"` (ask) — the same token
    /// `user_fills` and `trades` use.
    pub side: String,
    /// Requested size, decimal string in the series size plane.
    pub sz: String,
    /// The taker, `0x` hex. An accept is admitted only from this account, so an
    /// agent that opened the RFQ for a vault must accept for the same vault.
    pub requester: String,
    /// The taker's self-trade-prevention group, when it set one.
    #[serde(default)]
    pub requester_stp_group: Option<u64>,
    /// Consensus ms the request stops accepting quotes.
    pub expiry: u64,
    /// The taker's worst acceptable price, whole-USDC decimal string. `None`
    /// when the taker set no limit.
    #[serde(default)]
    pub limit_px: Option<String>,
    /// Consensus ms the request was opened.
    pub created_at: u64,
    /// Resting maker quotes. The index of a quote in THIS vector is the
    /// `quote_idx` an accept names.
    #[serde(default)]
    pub quotes: Vec<RfqQuoteRow>,
}

/// `rfq_open` — every open RFQ request on the venue.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RfqOpen {
    /// One row per open request, ascending by `rfq_id`.
    #[serde(default)]
    pub rfqs: Vec<OpenRfq>,
}

/// `rfq_user` — the RFQs one account is party to.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RfqUser {
    /// The queried account, `0x` hex.
    pub address: String,
    /// Requests this account opened as the taker.
    #[serde(default)]
    pub requested: Vec<OpenRfq>,
    /// Requests this account has quoted on as a maker.
    #[serde(default)]
    pub quoted: Vec<OpenRfq>,
}

impl Info<'_> {
    /// Read every open RFQ request and its resting quotes (`rfq_open`).
    ///
    /// This is a maker's entry point: it is the only way to find a request to
    /// quote on.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn rfq_open(&self) -> Result<RfqOpen, ClientError> {
        self.client
            .post_json("/info", &json!({ "type": "rfq_open" }))
            .await
    }

    /// Read the RFQs an account takes or makes in (`rfq_user`).
    ///
    /// This is a taker's entry point: a request does not return its id, so
    /// `requested` is where the `rfq_id` an accept needs comes from.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn rfq_user(&self, addr: Address) -> Result<RfqUser, ClientError> {
        self.client
            .post_json("/info", &json!({ "type": "rfq_user", "address": addr }))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROW: &str = r#"{
        "rfq_id": 9,
        "signing_id": 4000000,
        "underlying": "BTC",
        "side": "B",
        "sz": "1.5",
        "requester": "0x00000000000000000000000000000000000000aa",
        "requester_stp_group": null,
        "expiry": 1700000060000,
        "limit_px": "105.5",
        "created_at": 1700000000000,
        "quotes": [{
            "maker": "0x00000000000000000000000000000000000000bb",
            "maker_stp_group": 7,
            "price": "105",
            "max_size": "1",
            "valid_until": 1700000030000,
            "submitted_at": 1700000010000
        }]
    }"#;

    #[test]
    fn open_row_decodes_and_quote_index_is_the_accept_index() {
        let v: RfqOpen =
            serde_json::from_str(&format!(r#"{{"rfqs":[{ROW}]}}"#)).expect("decode rfq_open");
        let r = &v.rfqs[0];
        assert_eq!(r.rfq_id, 9);
        // `signing_id` is the signed `market` value, NOT the session id.
        assert_eq!(r.signing_id, 4_000_000);
        assert_eq!(r.side, "B");
        assert_eq!(r.limit_px.as_deref(), Some("105.5"));
        assert_eq!(r.requester_stp_group, None);
        assert_eq!(r.quotes[0].maker_stp_group, Some(7));
    }

    /// A market-order taker sets no limit, and the node then omits the key
    /// rather than sending `"0"`.
    #[test]
    fn an_absent_limit_px_is_none_not_zero() {
        let r: OpenRfq = serde_json::from_str(
            r#"{"rfq_id":1,"signing_id":4000000,"side":"A","sz":"1",
                "requester":"0x00000000000000000000000000000000000000aa",
                "expiry":0,"created_at":0}"#,
        )
        .expect("decode minimal");
        assert_eq!(r.limit_px, None);
        assert_eq!(r.underlying, None);
        assert!(r.quotes.is_empty());
    }

    #[test]
    fn rfq_user_carries_both_sides_and_empty_is_party_to_nothing() {
        let v: RfqUser = serde_json::from_str(&format!(
            r#"{{"address":"0x00000000000000000000000000000000000000aa",
                 "requested":[{ROW}],"quoted":[]}}"#
        ))
        .expect("decode rfq_user");
        assert_eq!(v.requested.len(), 1);
        assert!(v.quoted.is_empty());
    }
}
