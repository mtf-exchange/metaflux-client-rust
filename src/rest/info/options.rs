//! `/info` — the option lane reads.
//!
//! Two PUBLIC queries. [`Info::option_series`] answers which series are live and
//! which number to sign against. [`Info::option_state`] answers what one
//! account holds in them.
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
//! ## A position row carries TWO planes
//!
//! [`OptionPosition::long`] and [`OptionPosition::short`] are UNIT counts on the
//! series size scale. The node already divides by `sz_decimals`, so `"2.5"` is
//! two and a half whole units. [`OptionPosition::escrow`] is MONEY: a decimal
//! USDC string.
//!
//! Both planes are `String`, so a caller that reads `escrow` as a unit count, or
//! `short` as a dollar figure, gets a wrong number that still parses. The type
//! cannot catch it. Read the field name.
//!
//! ## What the registry does not carry
//!
//! No option price, no implied volatility, no open interest. The chain never
//! prices an option; the premium is what two accounts agree on in an RFQ.

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::error::ClientError;
use crate::rest::info::Info;
use crate::types::MarketId;
use crate::wallet::Address;

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

/// One account's open leg in one option series.
///
/// The row mixes two planes. `long` / `short` are UNIT counts; `escrow` is
/// USDC. See the module header.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct OptionPosition {
    /// The number an RFQ action puts in its `market` field. Served whole —
    /// never derive it.
    pub signing_id: MarketId,
    /// Symbol of the underlying market the settlement price comes from.
    pub underlying: String,
    /// Put, or capped call.
    pub kind: OptionKind,
    /// Strike `K`, whole USDC.
    pub strike: String,
    /// Expiry, consensus milliseconds.
    pub expiry: u64,
    /// Units HELD, on the series size scale. Already whole units, not a
    /// money figure.
    pub long: String,
    /// Units WRITTEN, on the series size scale. Already whole units, not a
    /// money figure.
    pub short: String,
    /// USDC this account has locked in the series pot. MONEY, not a unit
    /// count. It is what the writer takes back if the series settles
    /// worthless.
    pub escrow: String,
}

/// `option_state` response — one account's open option legs.
///
/// The row carries no `cap`, no `sz_decimals` and no `escrow_per_unit` — those
/// are series-wide, on [`OptionSeries`].
///
/// One of `long` / `short` is always `"0"`. A fill consumes the opposite leg
/// before it opens a new one, so a row is either a holding or a written
/// position, never both.
///
/// `height` / `time` stamp the committed block the snapshot was read at, so a
/// client can reject a stale snapshot. The WebSocket `option_state` frame
/// carries the same body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct OptionState {
    /// The account the rows belong to, `0x` hex.
    pub address: String,
    /// One row per open leg. Empty when the account is party to no series.
    pub positions: Vec<OptionPosition>,
    /// Committed block height the snapshot was read at.
    pub height: u64,
    /// Committed block timestamp the snapshot was read at (unix ms).
    pub time: u64,
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

    /// Read one account's open option legs (`option_state`).
    ///
    /// Each row carries the series terms beside the position, so no second read
    /// is needed. An account party to no series answers `200` with an empty
    /// list.
    ///
    /// An option fill writes no ledger row of its own. Between the fill and
    /// expiry, this is the only read where a writer sees the escrow it locked
    /// and a holder sees the units it owns.
    ///
    /// `long` / `short` are UNIT counts and `escrow` is USDC. See the module
    /// header — both are `String` and nothing in the type separates them.
    ///
    /// The read was named `option_positions` before wire-v3. The old name is
    /// GONE, not aliased: the node answers it with `unknown info type`.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn option_state(&self, address: Address) -> Result<OptionState, ClientError> {
        self.client
            .post_json(
                "/info",
                &json!({ "type": "option_state", "address": address }),
            )
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

    /// The two planes on one row. `short` is a unit count and `escrow` is USDC;
    /// swapping them is the failure this read warns about, and both decode as
    /// `String`, so only the field name separates them.
    #[test]
    fn a_position_row_keeps_units_and_escrow_apart() {
        let v: OptionState = serde_json::from_str(
            r#"{"address":"0xa1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1","positions":[
                {"signing_id":2147483650,"underlying":"BTC","kind":"capped_call",
                 "strike":"100000","expiry":1735689600000,
                 "long":"0","short":"1.5","escrow":"45000"}
            ],"height":8416000,"time":1783011600000}"#,
        )
        .expect("decode positions");
        let row = &v.positions[0];
        assert_eq!(row.signing_id, MarketId(2_147_483_650));
        // 1.5 whole units written ...
        assert_eq!(row.short, "1.5");
        assert_eq!(row.long, "0");
        // ... against 45,000 USDC locked. Two planes, one row.
        assert_eq!(row.escrow, "45000");
    }

    /// An account party to nothing is an empty list, not an error.
    #[test]
    fn an_account_party_to_nothing_decodes_empty() {
        let v: OptionState = serde_json::from_str(
            r#"{"address":"0xb2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2","positions":[],
                "height":8416000,"time":1783011600000}"#,
        )
        .expect("decode");
        assert!(v.positions.is_empty());
        assert_eq!(v.height, 8_416_000);
    }

    /// A dropped key on this frame must FAIL the decode: an absent `positions`
    /// must never read as an account that wrote nothing.
    #[test]
    fn a_dropped_key_fails_the_decode() {
        let full = serde_json::json!({
            "address": "0xb2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2",
            "positions": [], "height": 1u64, "time": 2u64
        });
        for key in ["address", "positions", "height", "time"] {
            let mut absent = full.clone();
            absent.as_object_mut().unwrap().remove(key);
            assert!(
                serde_json::from_value::<OptionState>(absent).is_err(),
                "a missing `{key}` must fail the decode"
            );
        }
        assert!(serde_json::from_value::<OptionState>(full).is_ok());
    }
}
