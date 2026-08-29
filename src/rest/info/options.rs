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
//! ## The options are STANDARD EUROPEAN. Read `settle_asset`.
//!
//! There are exactly two kinds, and they settle in DIFFERENT assets. Per whole
//! underlying unit, at settlement price `S*`:
//!
//! ```text
//! put:  payoff max(K − S*, 0) USDC,    escrow K USDC
//! call: payoff max(1 − K/S*, 0) COIN,  escrow ONE coin
//! ```
//!
//! The call's denomination is FORCED, not chosen. `max(S* − K, 0)` USDC has no
//! finite escrow, so no cash amount collateralizes a call. The same payoff read
//! in the UNDERLYING is bounded by one coin at every price. That bound is what
//! keeps both sides fully funded at the fill, which is why this lane can never
//! liquidate.
//!
//! [`OptionSeries::settle_asset`] carries the denomination as a coin label:
//! `"USDC"` on every put, the underlying's token name on every call.
//! [`OptionSeries::escrow_per_unit`], [`OptionPosition::escrow`] and every
//! settlement payout are amounts of THAT asset. **A caller that assumes dollars
//! is wrong on every call by the whole asset class** — it reads `"1"` on a
//! call and books one dollar where the chain locked one coin.
//!
//! The premium does NOT follow `settle_asset`. An RFQ price is USDC on both
//! lanes. So a client prices a call in dollars while it reads that call's
//! escrow and payout in coin.
//!
//! ## A position row carries TWO planes
//!
//! [`OptionPosition::long`] and [`OptionPosition::short`] are UNIT counts on the
//! series size scale. The node already divides by `sz_decimals`, so `"2.5"` is
//! two and a half whole units. [`OptionPosition::escrow`] is MONEY: a decimal
//! amount of [`OptionPosition::settle_asset`].
//!
//! Both planes are `String`, so a caller that reads `escrow` as a unit count, or
//! `short` as an amount, gets a wrong number that still parses. The type cannot
//! catch it. Read the field name.
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

/// Option kind. Standard European, and exactly two values.
///
/// The kind fixes the settlement asset, which the row also serves as
/// [`OptionSeries::settle_asset`]. A put settles in USDC; a call settles in the
/// underlying coin.
///
/// The enum is CLOSED at two. A third kind once expressed a call spread; it is
/// deleted, the chain can no longer list one, and this type refuses any token
/// outside `"put"` and `"call"`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OptionKind {
    /// Payoff `max(K − S*, 0)` USDC per unit. The writer locks `K` USDC, which
    /// bounds the payoff because `S*` is never negative.
    Put,
    /// Payoff `max(1 − K/S*, 0)` COIN per unit. The writer locks ONE coin.
    ///
    /// Read in USDC the payoff is `max(S* − K, 0)`, which no finite cash escrow
    /// covers. Read in the underlying it never exceeds one coin, so the coin
    /// escrow funds it at every price.
    Call,
}

/// One live option series.
///
/// Money fields are canonical whole-unit decimal strings. `strike` is USDC.
/// `escrow_per_unit` is [`OptionSeries::settle_asset`], which is USDC on a put
/// and the underlying coin on a call.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct OptionSeries {
    /// The number an RFQ action puts in its `market` field. Served whole —
    /// never derive it.
    pub signing_id: MarketId,
    /// Symbol of the underlying market the settlement price comes from.
    pub underlying: String,
    /// Put, or call.
    pub kind: OptionKind,
    /// Strike `K`, whole USDC. A strike is a PRICE, so it is quoted in dollars
    /// on both kinds — it does not follow [`Self::settle_asset`].
    pub strike: String,
    /// Expiry, consensus milliseconds. The first settlement attempt runs at
    /// this stamp.
    pub expiry: u64,
    /// Size precision. An RFQ `size` of `10^sz_decimals` is ONE whole unit.
    pub sz_decimals: u8,
    /// The asset this series escrows and pays in, as a coin label.
    ///
    /// `"USDC"` on every put. On a call it is the UNDERLYING's token name,
    /// because a call escrows and pays the coin, not dollars.
    /// [`Self::escrow_per_unit`], [`OptionPosition::escrow`] and every
    /// settlement payout are amounts of this asset. Read it before you read any
    /// of them: a client that assumes dollars misreads every call by the whole
    /// asset class.
    pub settle_asset: String,
    /// What a WRITER locks per whole unit, in [`Self::settle_asset`].
    ///
    /// The strike on a put. Exactly `"1"` on a call — one coin per unit, at
    /// every strike and every price.
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
/// money, in `settle_asset`. See the module header.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct OptionPosition {
    /// The number an RFQ action puts in its `market` field. Served whole —
    /// never derive it.
    pub signing_id: MarketId,
    /// Symbol of the underlying market the settlement price comes from.
    pub underlying: String,
    /// Put, or call.
    pub kind: OptionKind,
    /// Strike `K`, whole USDC. A price on both kinds — see
    /// [`OptionSeries::strike`].
    pub strike: String,
    /// Expiry, consensus milliseconds.
    pub expiry: u64,
    /// Units HELD, on the series size scale. Already whole units, not a
    /// money figure.
    pub long: String,
    /// Units WRITTEN, on the series size scale. Already whole units, not a
    /// money figure.
    pub short: String,
    /// The asset the escrow below is denominated in. Same meaning as
    /// [`OptionSeries::settle_asset`]: `"USDC"` on a put, the underlying's
    /// token name on a call.
    pub settle_asset: String,
    /// What this account has locked in the series pot, in [`Self::settle_asset`].
    /// MONEY, not a unit count. It is what the writer takes back if the series
    /// settles worthless.
    ///
    /// A call escrows COINS, so summing this across an account's rows adds
    /// coins to dollars. Sum per `settle_asset`, or read the USDC total from
    /// the `account_state` option lane, which counts put legs only.
    pub escrow: String,
}

/// `option_state` response — one account's open option legs.
///
/// The row carries no `sz_decimals` and no `escrow_per_unit` — those are
/// series-wide, on [`OptionSeries`].
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
    /// Every row carries the `signing_id` an RFQ action signs against, the
    /// `settle_asset` the series is denominated in, and the `escrow_per_unit` a
    /// writer locks in that asset. A settled or expired series leaves the
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
    /// `long` / `short` are UNIT counts and `escrow` is money in
    /// [`OptionPosition::settle_asset`]. See the module header — both are
    /// `String` and nothing in the type separates them.
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

    /// A put settles in USDC and its escrow is the strike.
    #[test]
    fn a_put_row_settles_in_usdc_at_the_strike() {
        let v: OptionSeriesRegistry = serde_json::from_str(
            r#"{"series":[
                {"signing_id":2147483649,"underlying":"BTC","kind":"put",
                 "strike":"100000","expiry":1735689600000,"sz_decimals":5,
                 "settle_asset":"USDC","escrow_per_unit":"100000"}
            ]}"#,
        )
        .expect("decode registry");
        assert_eq!(v.series.len(), 1);
        assert_eq!(v.series[0].signing_id, MarketId(2_147_483_649));
        assert_eq!(v.series[0].kind, OptionKind::Put);
        assert_eq!(v.series[0].settle_asset, "USDC");
        assert_eq!(v.series[0].escrow_per_unit, "100000");
    }

    /// A call settles in the UNDERLYING and escrows one coin. Reading
    /// `escrow_per_unit` as dollars books $1 where the chain locked a coin.
    #[test]
    fn a_call_row_settles_in_the_coin_and_escrows_one() {
        let v: OptionSeriesRegistry = serde_json::from_str(
            r#"{"series":[
                {"signing_id":2147483650,"underlying":"BTC","kind":"call",
                 "strike":"100000","expiry":1735689600000,"sz_decimals":5,
                 "settle_asset":"BTC","escrow_per_unit":"1"}
            ]}"#,
        )
        .expect("decode registry");
        assert_eq!(v.series[0].kind, OptionKind::Call);
        assert_eq!(v.series[0].settle_asset, "BTC");
        assert_eq!(v.series[0].escrow_per_unit, "1");
        // The strike stays a USDC price on a coin-settled series.
        assert_eq!(v.series[0].strike, "100000");
    }

    /// Only the two kinds decode. A retired or unknown token must FAIL, so a
    /// client can never carry a shape the chain no longer lists.
    #[test]
    fn a_kind_outside_the_two_fails_the_decode() {
        for kind in ["spread", "european_call", "", "Put"] {
            let row = serde_json::json!({ "series": [{
                "signing_id": 2_147_483_650u32, "underlying": "BTC", "kind": kind,
                "strike": "100000", "expiry": 1_735_689_600_000u64, "sz_decimals": 5,
                "settle_asset": "USDC", "escrow_per_unit": "100000"
            }]});
            assert!(
                serde_json::from_value::<OptionSeriesRegistry>(row).is_err(),
                "kind `{kind}` must not decode"
            );
        }
    }

    /// `settle_asset` carries no default: a row without it must fail rather
    /// than read as USDC, which would silently dollar-price every call.
    #[test]
    fn a_row_without_settle_asset_fails_the_decode() {
        assert!(
            serde_json::from_str::<OptionSeriesRegistry>(
                r#"{"series":[
                {"signing_id":2147483649,"underlying":"BTC","kind":"put",
                 "strike":"100000","expiry":1735689600000,"sz_decimals":5,
                 "escrow_per_unit":"100000"}
            ]}"#,
            )
            .is_err()
        );
    }

    #[test]
    fn an_empty_registry_decodes() {
        let v: OptionSeriesRegistry = serde_json::from_str(r#"{"series":[]}"#).expect("decode");
        assert!(v.series.is_empty());
    }

    /// The two planes on one row. `short` is a unit count and `escrow` is
    /// money; swapping them is the failure this read warns about, and both
    /// decode as `String`, so only the field name separates them. On a call the
    /// money is COINS: 1.5 units written escrow 1.5 coins.
    #[test]
    fn a_position_row_keeps_units_and_escrow_apart() {
        let v: OptionState = serde_json::from_str(
            r#"{"address":"0xa1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1","positions":[
                {"signing_id":2147483650,"underlying":"BTC","kind":"call",
                 "strike":"100000","expiry":1735689600000,
                 "long":"0","short":"1.5","settle_asset":"BTC","escrow":"1.5"}
            ],"height":8416000,"time":1783011600000}"#,
        )
        .expect("decode positions");
        let row = &v.positions[0];
        assert_eq!(row.signing_id, MarketId(2_147_483_650));
        // 1.5 whole units written ...
        assert_eq!(row.short, "1.5");
        assert_eq!(row.long, "0");
        // ... against 1.5 BTC locked, not 1.5 dollars. Two planes, one row.
        assert_eq!(row.settle_asset, "BTC");
        assert_eq!(row.escrow, "1.5");
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
