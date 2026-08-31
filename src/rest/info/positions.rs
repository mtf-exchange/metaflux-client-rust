//! `/info` — the perp POSITION detail read (`clearinghouse_state`).
//!
//! The dex-keyed position table LEFT the `account_state` body. It is its own
//! read and its own WebSocket channel, both named `clearinghouse_state`. The row
//! shape did not change.
//!
//! ## Two frames, one height
//!
//! [`crate::rest::info::AccountState`] carries the lane SUMMARIES;
//! [`ClearinghouseState`] carries the position DETAIL. Both stamp `height` and
//! `time`, so a caller sees when its detail lags its summary. Never join the two
//! frames to compute a health figure: they can come from different commits, and
//! the result was never true at either.
//!
//! ## The `adl` lamps are opt-in
//!
//! `adl = true` widens every row with [`AccountPosition::adl_lamps`]. Each lamp
//! ranks the position against every other position in that market, so the node
//! pays one extra pass per row. Ask for it only when you render the column. The
//! WebSocket frame never carries the lamps.

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::error::ClientError;
use crate::rest::info::Info;
use crate::wallet::Address;

/// Hedge-leg label on an [`AccountPosition`] — `"long"` / `"short"`.
///
/// A one-way account omits the field, so it is always `Option`. This is NOT the
/// order-book side token — see [`crate::rest::info::OrderSide`], which spells `"B"` / `"A"`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PositionSide {
    /// Long leg.
    Long,
    /// Short leg.
    Short,
}

/// One open position inside a [`DexPositions`] group.
///
/// Every monetary magnitude is a whole-USDC decimal string. `size` is SIGNED
/// (negative = short) and rides the market's own size plane; note the key is
/// `size`, not the `sz` the order / book / trade rows use. `lev` is the user's
/// CHOSEN leverage, not an effective ratio.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AccountPosition {
    /// Market symbol (e.g. `"BTC"`).
    pub coin: String,
    /// Signed position size, decimal string (negative = short).
    pub size: String,
    /// Volume-weighted entry price, whole-USDC decimal string.
    #[serde(rename = "entry")]
    pub entry_px: String,
    /// Unrealised PnL (signed), whole-USDC decimal string.
    #[serde(rename = "upnl")]
    pub unrealised_pnl: String,
    /// Whether this position uses isolated margin.
    pub isolated: bool,
    /// Chosen leverage multiple.
    #[serde(rename = "lev")]
    pub leverage: u32,
    /// Liquidation price as a whole-USDC decimal string, or `None` when the
    /// position has none. An isolated leg whose bucket no non-negative price can
    /// breach reads `None`, NEVER `"0"` — a zero is a price, and reading one as
    /// the other says "liquidates immediately" about a position that cannot be
    /// price-liquidated.
    #[serde(rename = "liq", default)]
    pub liquidation_px: Option<String>,
    /// Return on equity, decimal-fraction string.
    pub roe: String,
    /// Cumulative funding paid (positive) / received (negative) over the
    /// position's life, whole-USDC decimal string.
    pub funding: String,
    /// Initial margin posted for the position, whole-USDC decimal string.
    #[serde(rename = "margin")]
    pub margin_used: String,
    /// Maintenance margin required by the position, whole-USDC decimal string.
    pub maint_margin: String,
    /// Position notional at the mark, whole-USDC decimal string.
    #[serde(rename = "notional")]
    pub position_value: String,
    /// Hedge-leg label; absent on a one-way account.
    #[serde(default)]
    pub side: Option<PositionSide>,
    /// ADL queue indicator, `0..=4` lamps. Served ONLY when the read asks for
    /// `adl = true`; the plain read and every WebSocket frame read `None`.
    ///
    /// More lamps = sooner in the auto-deleveraging queue. It is a RANKING of
    /// this seat against the other seats on the same side, NOT a probability:
    /// four lamps with nobody being liquidated on the other side still means
    /// nothing happens.
    ///
    /// `Some(0)` is meaningful and is not "unknown". Zero says the position is
    /// not in the queue at all, which is the honest answer for a position ADL
    /// cannot structurally reach — no committed mark, no profit, no cost basis,
    /// or nobody on the opposite side to be deleveraged against. A hedge
    /// account whose only opposing leg is its OWN reads zero, because ADL never
    /// nets an account against itself.
    #[serde(default)]
    pub adl_lamps: Option<u8>,
}

/// The positions of one dex inside [`ClearinghouseState::clearinghouse_state`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DexPositions {
    /// Open positions hosted by this dex.
    #[serde(default)]
    pub positions: Vec<AccountPosition>,
}

/// `clearinghouse_state` response — one account's open perp positions, grouped
/// by dex.
///
/// The key is the DEX NAME. The core dex is the empty string `""` and is ALWAYS
/// present, even for an account with no position. A MIP-3 deployer dex keys on
/// the name its deployer registered, such as `"GRAD"`. That name is also the
/// symbol namespace, so a position on dex `GRAD` has a coin like
/// `"GRAD:000001SH"`, and it joins this table to `perp_dexs` by `name`. Use
/// [`ClearinghouseState::core_positions`] for the core group.
///
/// `height` / `time` stamp the committed block the snapshot was read at.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ClearinghouseState {
    /// Echo of the requested address.
    pub address: Address,
    /// Open positions grouped by dex key. `BTreeMap` for deterministic key
    /// ordering.
    pub clearinghouse_state: std::collections::BTreeMap<String, DexPositions>,
    /// Committed block height the snapshot was read at.
    pub height: u64,
    /// Committed block timestamp the snapshot was read at (unix ms).
    pub time: u64,
}

impl ClearinghouseState {
    /// Positions of the CORE dex (the `""` key), which the node always emits.
    #[must_use]
    pub fn core_positions(&self) -> &[AccountPosition] {
        self.clearinghouse_state
            .get("")
            .map_or(&[], |d| d.positions.as_slice())
    }
}

impl Info<'_> {
    /// `clearinghouse_state` — one account's open perp positions, keyed by
    /// `address`.
    ///
    /// This is the position DETAIL that left the `account_state` body. Read
    /// [`Info::account_state`] for the account equity, margin and lane
    /// summaries; the two frames each carry their own `height`.
    ///
    /// `adl` widens every row with [`AccountPosition::adl_lamps`]. It costs one
    /// extra pass per row, so ask for it only when you render the column.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn clearinghouse_state(
        &self,
        addr: Address,
        adl: bool,
    ) -> Result<ClearinghouseState, ClientError> {
        let mut body = json!({ "type": "clearinghouse_state", "address": addr });
        if adl {
            let obj = body.as_object_mut().expect("json! produced an object");
            obj.insert("detail".into(), json!("adl"));
        }
        self.client.post_json("/info", &body).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body() -> serde_json::Value {
        json!({
            "address": "0x000000000000000000000000000000000000beef",
            "clearinghouse_state": {
                "": { "positions": [{
                    "coin": "BTC", "size": "-1.5", "entry": "64000", "upnl": "500",
                    "isolated": false, "lev": 10, "liq": "71000", "roe": "0.02",
                    "funding": "-1.25", "margin": "9600", "maint_margin": "480",
                    "notional": "96000"
                }] },
                "GRAD": { "positions": [{
                    "coin": "GRAD:XYZ", "size": "2", "entry": "10", "upnl": "0",
                    "isolated": true, "lev": 3, "liq": "5", "roe": "0",
                    "funding": "0", "margin": "6.66", "maint_margin": "0.4",
                    "notional": "20", "side": "long"
                }] }
            },
            "height": 8_416_000u64,
            "time": 1_783_011_600_000u64
        })
    }

    #[test]
    fn the_detail_frame_decodes_and_round_trips() {
        let c: ClearinghouseState = serde_json::from_value(body()).unwrap();
        assert_eq!(c.clearinghouse_state.len(), 2);
        let core = c.core_positions();
        assert_eq!(core.len(), 1);
        assert_eq!(core[0].coin, "BTC");
        // `size` is SIGNED and keeps the `size` key — the order / book `sz` key
        // is a different plane and must not be unified with it.
        assert_eq!(core[0].size, "-1.5");
        assert!(core[0].side.is_none());
        assert_eq!(core[0].adl_lamps, None);
        let dex = &c.clearinghouse_state["GRAD"];
        assert_eq!(dex.positions[0].side, Some(PositionSide::Long));
        assert_eq!(c.height, 8_416_000);

        let dec: ClearinghouseState =
            serde_json::from_str(&serde_json::to_string(&c).unwrap()).unwrap();
        assert_eq!(c, dec);
    }

    /// An account with no position still gets the `""` anchor, so an empty
    /// group must decode as an empty list rather than as a decode failure.
    #[test]
    fn an_empty_account_keeps_the_core_anchor() {
        let c: ClearinghouseState = serde_json::from_value(json!({
            "address": "0x000000000000000000000000000000000000beef",
            "clearinghouse_state": { "": { "positions": [] } },
            "height": 1u64, "time": 2u64
        }))
        .unwrap();
        assert_eq!(c.clearinghouse_state.len(), 1);
        assert!(c.core_positions().is_empty());
    }

    /// Zero lamps is a real answer — the position is not in the queue — so it
    /// must decode as `Some(0)`, never as the absent case.
    #[test]
    fn the_adl_read_keeps_a_zero_lamp_apart_from_an_absent_one() {
        let mut v = body();
        v["clearinghouse_state"][""]["positions"][0]["adl_lamps"] = json!(3u8);
        v["clearinghouse_state"]["GRAD"]["positions"][0]["adl_lamps"] = json!(0u8);
        let c: ClearinghouseState = serde_json::from_value(v).unwrap();
        assert_eq!(c.core_positions()[0].adl_lamps, Some(3));
        assert_eq!(
            c.clearinghouse_state["GRAD"].positions[0].adl_lamps,
            Some(0)
        );
    }

    /// A dropped or renamed key on this frame must FAIL the decode. An absent
    /// position table must never read as an account that holds nothing.
    #[test]
    fn a_dropped_or_renamed_key_fails_the_decode() {
        for key in ["address", "clearinghouse_state", "height", "time"] {
            let mut absent = body();
            absent.as_object_mut().unwrap().remove(key);
            assert!(
                serde_json::from_value::<ClearinghouseState>(absent).is_err(),
                "a missing `{key}` must fail the decode"
            );
        }
        assert!(serde_json::from_value::<ClearinghouseState>(body()).is_ok());
    }
}
