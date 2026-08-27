//! `/info` — the live option series registry.
//!
//! One PUBLIC query: [`Info::option_series`]. It answers the two questions a
//! caller has about the option lane: which series are live, and which number to
//! sign against.
//!
//! ## `signing_id` is the number an RFQ action carries
//!
//! [`OptionSeries::signing_id`] is a [`MarketId`], and it goes straight into the
//! `market` field of [`rfq_request`](crate::rest::exchange::Exchange::rfq_request_typed).
//! The registry serves it whole. **There is no formula, no base and no
//! arithmetic that derives it** — the encoding behind the number is internal to
//! the node and may move. Take the served value.
//!
//! ## The escrow is what a writer locks
//!
//! [`OptionSeries::escrow_per_unit`] is the collateral a WRITER locks per whole
//! unit, in USDC. For a [`OptionKind::CappedCall`] it is `cap − strike`, not
//! `strike`: a $100,000 strike capped at $130,000 locks $30,000 per unit.
//! Reading `strike` as the lock overstates it by the whole strike.
//!
//! ## What the registry does not carry
//!
//! No option price, no implied volatility, no open interest. The chain never
//! prices an option; the premium is what two accounts agree on in an RFQ. There
//! is also no public read for an option POSITION yet — the visible effect of a
//! fill is the USDC balance change on `account_state`.

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::error::ClientError;
use crate::rest::info::Info;
use crate::types::MarketId;

/// Option kind. A call is always CAPPED — an uncapped call has no finite worst
/// case, so cash cannot fully collateralize it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OptionKind {
    /// Payoff `max(K − S, 0)` per unit. The writer locks the strike.
    Put,
    /// Payoff `min(max(S − K, 0), C − K)` per unit. The writer locks `C − K`.
    CappedCall,
}

/// One live option series.
///
/// Money fields are canonical whole-USDC decimal strings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct OptionSeries {
    /// The number an RFQ action puts in its `market` field. Served whole —
    /// never derive it.
    pub signing_id: MarketId,
    /// Symbol of the underlying market the settlement price comes from.
    pub underlying: String,
    /// Put, or capped call.
    pub kind: OptionKind,
    /// Strike `K`, whole USDC.
    pub strike: String,
    /// Cap `C`, whole USDC. `None` on a put — the node omits the key.
    #[serde(default)]
    pub cap: Option<String>,
    /// Expiry, consensus milliseconds. The first settlement attempt runs at
    /// this stamp.
    pub expiry: u64,
    /// Size precision. An RFQ `size` of `10^sz_decimals` is ONE whole unit.
    pub sz_decimals: u8,
    /// What a WRITER locks per whole unit, whole USDC. `cap − strike` on a
    /// capped call.
    pub escrow_per_unit: String,
}

/// The live option series registry (`option_series`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct OptionSeriesRegistry {
    /// One row per live series, oldest series first. Empty when none is live.
    pub series: Vec<OptionSeries>,
}

impl Info<'_> {
    /// Read the live option series registry (`option_series`). No parameters.
    ///
    /// Every row carries the `signing_id` an RFQ action signs against, and the
    /// `escrow_per_unit` a writer locks. A settled or expired series leaves the
    /// registry, so an id that is absent here is refused by the RFQ actions.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn option_series(&self) -> Result<OptionSeriesRegistry, ClientError> {
        self.client
            .post_json("/info", &json!({ "type": "option_series" }))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A put carries no `cap`, and its escrow is the strike.
    #[test]
    fn a_put_row_decodes_without_a_cap() {
        let v: OptionSeriesRegistry = serde_json::from_str(
            r#"{"series":[
                {"signing_id":2147483649,"underlying":"BTC","kind":"put",
                 "strike":"100000","expiry":1735689600000,"sz_decimals":5,
                 "escrow_per_unit":"100000"}
            ]}"#,
        )
        .expect("decode registry");
        assert_eq!(v.series.len(), 1);
        assert_eq!(v.series[0].signing_id, MarketId(2_147_483_649));
        assert_eq!(v.series[0].kind, OptionKind::Put);
        assert_eq!(v.series[0].cap, None);
        assert_eq!(v.series[0].escrow_per_unit, "100000");
    }

    /// A capped call escrows the WIDTH. Decoding `strike` as the lock would
    /// overstate it by the whole strike.
    #[test]
    fn a_capped_call_row_keeps_the_cap_and_the_width() {
        let v: OptionSeriesRegistry = serde_json::from_str(
            r#"{"series":[
                {"signing_id":2147483650,"underlying":"BTC","kind":"capped_call",
                 "strike":"100000","cap":"130000","expiry":1735689600000,
                 "sz_decimals":5,"escrow_per_unit":"30000"}
            ]}"#,
        )
        .expect("decode registry");
        assert_eq!(v.series[0].kind, OptionKind::CappedCall);
        assert_eq!(v.series[0].cap.as_deref(), Some("130000"));
        assert_eq!(v.series[0].escrow_per_unit, "30000");
    }

    #[test]
    fn an_empty_registry_decodes() {
        let v: OptionSeriesRegistry = serde_json::from_str(r#"{"series":[]}"#).expect("decode");
        assert!(v.series.is_empty());
    }
}
