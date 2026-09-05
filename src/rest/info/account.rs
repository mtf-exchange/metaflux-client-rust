//! `/info` — the per-account SUMMARY read (`account_state`).
//!
//! One coherent snapshot per account: the CROSS-lane scalars at the top level,
//! then one summary per lane — `perp`, `spot`, `margin`, `option`.
//!
//! ## The top-level figures are cross-lane, and one of them looks like it is not
//!
//! [`AccountState::account_value`] folds perp AND spot-margin unrealised PnL,
//! and [`AccountState::withdrawable`] subtracts both lanes' held initial margin.
//! [`AccountState::pm_net_value`] is the portfolio-margin twin of
//! `account_value` and stays at the top level for the same reason: its cash term
//! is the whole unified pool, so filing it under `perp` would let a caller that
//! sums the lanes count the same USDC twice.
//!
//! ## A zeroed lane is not an unserved lane
//!
//! At the default depth the node serves all four lane keys, zeroed when the lane
//! is empty. `None` on this type therefore means "this depth did not serve the
//! lane" — the [`AccountDetail::Margin`] case — never "the account holds
//! nothing".
//!
//! ## The positions left this body
//!
//! The dex-keyed position table is its own read,
//! [`Info::clearinghouse_state`], and the option legs are
//! [`Info::option_state`]. Each frame stamps its own `height`, so never join two
//! of them to build one number.

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::error::ClientError;
use crate::rest::info::{Abstraction, Info, PositionMode, Tier};
#[cfg(doc)]
use crate::rest::info::{AccountOverview, AccountPosition};
use crate::wallet::Address;

/// One token balance row inside [`SpotLane::balances`].
///
/// The USDC row is always first and is ALWAYS present, so the array is never
/// empty. A token row with neither a spendable balance nor an escrow hold is
/// skipped, so absence means zero.
///
/// `total - hold` is NOT the spendable amount. `hold` counts spot order escrow
/// only: USDC that margins an open perpetual position stays in `total` and
/// never enters `hold`. Read [`AccountState::withdrawable`] for the budget.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TokenBalance {
    /// Token symbol (e.g. `"USDC"`), else `asset:<id>`.
    pub name: String,
    /// The uint32 to put in the `asset` field of a signed `send_asset`, and in
    /// `asset` of an `earn_deposit`. It has no other meaning: every row is keyed
    /// and joined by `name`.
    ///
    /// There is no `spot_send` action. That name is a `ledger_updates` record
    /// kind; the node answers `unknown variant` to it.
    #[serde(default)]
    pub signing_id: u32,
    /// Total balance (spendable + hold), decimal string.
    pub total: String,
    /// Amount held in escrow by resting orders, decimal string.
    pub hold: String,
    /// Weighted-average acquisition cost, whole USDC PER WHOLE TOKEN. A price,
    /// not a total: `(mark_px - avg_entry_px) * total` is the unrealized spot
    /// PnL. `total` includes the part held behind resting orders, so multiply
    /// by the quantity you mean rather than one the server picked for you.
    ///
    /// `None` means UNKNOWN, never zero. The chain rolls the basis on spot BUYS
    /// only — a sell keeps the standing per-unit average, and a deposit (bridge
    /// credit, Core-EVM credit, spot transfer, governance adjustment) writes no
    /// basis at all. Render nothing rather than a PnL against a `None` basis:
    /// that error is the whole notional reported as gain.
    ///
    /// The USDC row always reads `None` — a cost basis on the quote asset in
    /// terms of itself has no meaning.
    #[serde(default)]
    pub avg_entry_px: Option<String>,
}

/// The `perp` lane summary of [`AccountState`] — the CROSS perp legs folded to
/// four numbers.
///
/// An ISOLATED leg is margined on its own bucket and is NOT counted here, so
/// this is not the account's whole perp exposure. Read the per-leg rows on the
/// [`Info::clearinghouse_state`] frame for that.
///
/// The `pm_*` figures are meaningful only when
/// [`AccountState::abstraction`] is [`Abstraction::Portfolio`]. They read `"0"`
/// on an account that is not enrolled, so a zero is not the same claim as
/// "portfolio margin says zero".
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PerpLane {
    /// Initial margin the perp lane posts, whole-USDC decimal string. This is
    /// the field the flat body called `total_margin_used`.
    pub init_margin: String,
    /// Mark notional of the CROSS legs, whole-USDC decimal string.
    pub total_ntl_pos: String,
    /// Portfolio-margin maintenance margin, whole-USDC decimal string.
    pub pm_maint_margin: String,
    /// Portfolio-margin concentration penalty, whole-USDC decimal string.
    pub pm_concentration_penalty: String,
}

/// The `spot` lane summary of [`AccountState`] — the account's WHOLE token
/// ledger.
///
/// A spot balance IS the spot position, so nothing splits off to a detail
/// frame. The USDC row is unconditional, so [`SpotLane::balances`] is never
/// empty on a real account.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SpotLane {
    /// The unified USDC pool in row 0, then every spot token the account holds.
    pub balances: Vec<TokenBalance>,
}

/// The `margin` lane summary of [`AccountState`] — the spot-margin lane folded
/// to three numbers.
///
/// `collateral` and `debt` are USDC sums: the quote asset of every spot pair is
/// USDC, so the two add across pairs. `debt` accrues through the same reader the
/// [`Info::spot_margin_state`] rows report, so the summary cannot disagree with
/// the detail.
///
/// The per-pair `base_held` does NOT fold in. It is BASE units with no common
/// unit across pairs, and a notional needs a mark this read does not fetch.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MarginLane {
    /// Posted collateral summed over every margin pair, whole-USDC decimal
    /// string.
    pub collateral: String,
    /// Accrued debt summed over every margin pair, whole-USDC decimal string.
    pub debt: String,
    /// How many spot pairs the account has a margin account on. A COUNT, so it
    /// rides the wire as a number, not a string.
    pub pairs: u32,
}

/// The `option` lane summary of [`AccountState`] — the writer escrow, the leg
/// count and the nearest expiry.
///
/// Read [`Info::option_state`] for the per-series legs. No mark-priced figure is
/// served here: the chain never prices an option.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct OptionLane {
    /// Total short-leg escrow, whole-USDC decimal string.
    ///
    /// PUT LEGS ONLY. A call escrows the underlying coin, so adding a call leg
    /// would sum coins into dollars. [`Self::legs`] still counts every leg, so
    /// this number can be `"0"` while `legs` is not. Read
    /// [`Info::option_state`] for the per-series escrow and its `settle_asset`.
    pub escrow: String,
    /// How many series the account is party to. A COUNT, so it rides the wire
    /// as a number.
    pub legs: u32,
    /// Nearest expiry over the account's legs, consensus milliseconds.
    ///
    /// ABSENT — and therefore `None` — when `legs` is 0. The node omits the key
    /// rather than sending a zero, because a zero timestamp reads as 1970.
    #[serde(default)]
    pub next_expiry: Option<u64>,
}

/// `account_state` response — one coherent per-account snapshot keyed by
/// `address`: the ACCOUNT truths at the top level, then one summary per LANE.
///
/// Every monetary magnitude is a whole-USDC decimal **string** so precision
/// survives the JS safe-integer limit; `health` may be negative.
///
/// # The top-level figures are CROSS-lane
///
/// [`AccountState::account_value`] folds perp AND spot-margin unrealised PnL,
/// [`AccountState::withdrawable`] subtracts both lanes' held initial margin, and
/// `health` / `tier` derive from those. [`AccountState::pm_net_value`] is the
/// portfolio-margin twin of `account_value` and stays at the top level for the
/// same reason: its cash term is the whole unified pool, so filing it under
/// `perp` would let a caller that sums the lanes count the same USDC twice.
///
/// # The lanes are always present and zeroed
///
/// At the default depth the node serves all four lane keys, zeroed when the lane
/// is empty. `None` here therefore means "this depth did not serve the lane",
/// which is the [`AccountDetail::Margin`] case — never "the account holds
/// nothing". A zeroed lane must not be confused with an unserved one.
///
/// # The positions LEFT this body
///
/// The dex-keyed position table is its own read and its own WebSocket channel,
/// [`Info::clearinghouse_state`]. Both frames stamp `height` / `time`, so a
/// caller sees when its detail lags its summary. Do not join the two frames to
/// compute one number: they can come from different commits.
///
/// # Depth
///
/// Every money field the requested depth serves is required, so decoding FAILS
/// if the server drops or renames one — a missing money field must never read as
/// an empty account. The [`AccountDetail::Margin`]-only fields
/// (`cross_maintenance_margin_used`, `total_margin_used`), the default-depth
/// fields (`pm_net_value`, `position_mode`, the four lanes) and
/// `health_deferred` are the exceptions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AccountState {
    /// Echo of the requested address.
    pub address: Address,
    /// Equity including unrealised PnL, whole-USDC decimal string. CROSS-lane.
    pub account_value: String,
    /// Cash the account can take out, decimal string, CLAMPED at zero.
    ///
    /// Settled cash minus funding owed minus both lanes' held initial margin. It
    /// does NOT count unrealised profit, so a healthy account whose margin is
    /// funded by open profit reads `"0"` — that means "nothing to withdraw", not
    /// "broke". The chain's admission gate uses the raw signed figure, which can
    /// go negative; this read never does.
    pub withdrawable: String,
    /// Settled cash equity, whole-USDC decimal string. It EXCLUDES unrealised
    /// PnL: `account_value` counts open profit, this does not. Served at BOTH
    /// depths.
    pub total_raw_usd: String,
    /// `account_value - cross_maintenance_margin_used`, decimal string; can be
    /// negative.
    pub health: String,
    /// Liquidation tier.
    pub tier: Tier,
    /// `true` when the risk engine DEFERS on this account: it holds a leg no
    /// risk path can price. `tier` and `health` are then NOT solvency
    /// statements, and the maintenance margin reads 0 for want of a price.
    /// The node emits the key only when it is true, so absent means `false`.
    #[serde(default)]
    pub health_deferred: bool,
    /// Margin abstraction class (`"unified"` / `"standard"` / `"portfolio"`).
    pub abstraction: Abstraction,
    /// Portfolio-margin net account value, whole-USDC decimal string. CROSS-lane
    /// — see the type doc. `None` at [`AccountDetail::Margin`].
    #[serde(default)]
    pub pm_net_value: Option<String>,
    /// Position mode (one-way / hedge). `None` at [`AccountDetail::Margin`],
    /// which serves the scalars alone.
    #[serde(default)]
    pub position_mode: Option<PositionMode>,
    /// Maintenance margin of the CROSS book, whole-USDC decimal string. Served
    /// ONLY at [`AccountDetail::Margin`]; the default depth carries the per-leg
    /// `maint_margin` on each [`Info::clearinghouse_state`] row instead.
    ///
    /// The scope is CROSS. An isolated position is margined and liquidated on
    /// its own bucket, so NEVER size an isolated position off this number. Read
    /// that leg's own [`AccountPosition::maint_margin`] instead.
    #[serde(default)]
    pub cross_maintenance_margin_used: Option<String>,
    /// Total initial margin the account posts, whole-USDC decimal string.
    /// Served ONLY at [`AccountDetail::Margin`]; the default depth carries the
    /// same figure as [`PerpLane::init_margin`].
    #[serde(default)]
    pub total_margin_used: Option<String>,
    /// The perp lane summary. `None` at [`AccountDetail::Margin`].
    #[serde(default)]
    pub perp: Option<PerpLane>,
    /// The spot lane summary — the whole token ledger. `None` at
    /// [`AccountDetail::Margin`].
    #[serde(default)]
    pub spot: Option<SpotLane>,
    /// The spot-margin lane summary. `None` at [`AccountDetail::Margin`].
    #[serde(default)]
    pub margin: Option<MarginLane>,
    /// The option lane summary. `None` at [`AccountDetail::Margin`].
    #[serde(default)]
    pub option: Option<OptionLane>,
    /// Committed block height the snapshot was read at.
    pub height: u64,
    /// Committed block timestamp the snapshot was read at (unix ms).
    pub time: u64,
}

impl AccountState {
    /// The token ledger of the [`AccountState::spot`] lane, or an empty slice
    /// when the depth did not serve the lane.
    #[must_use]
    pub fn balances(&self) -> &[TokenBalance] {
        self.spot.as_ref().map_or(&[], |s| s.balances.as_slice())
    }
}

/// Response depth for [`Info::account_state`].
///
/// The node accepts a third value, `"overview"`. It answers with the
/// [`AccountOverview`] shape, which [`AccountState`] cannot decode, so
/// [`Info::account_overview`] serves it instead of a variant here.
///
/// There is no `"adl"` value. The position rows it widened moved to
/// [`Info::clearinghouse_state`], which takes the lamps instead; the node
/// REFUSES `detail: "adl"` on `account_state` with a 400.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountDetail {
    /// The four lane summaries beside the account scalars. The default.
    Full,
    /// Margin scalars only — no lane summaries at all. Adds
    /// [`AccountState::cross_maintenance_margin_used`] and
    /// [`AccountState::total_margin_used`], which the default depth files under
    /// [`PerpLane::init_margin`].
    Margin,
}

impl Info<'_> {
    /// `account_state` — the account's TRADING state, keyed by `address`: the
    /// cross-lane scalars, then one summary per lane.
    ///
    /// [`AccountDetail::Full`] (or `None`) answers with equity, health, tier and
    /// the four lane summaries — [`AccountState::perp`],
    /// [`AccountState::spot`], [`AccountState::margin`] and
    /// [`AccountState::option`]. Each lane key is always present and zeroed when
    /// the lane is empty.
    ///
    /// [`AccountDetail::Margin`] answers with the margin scalars only — no lane
    /// summaries, which is the right ask for a frequent liquidation-health poll.
    /// Both depths compute the scalars with one shared helper, so the two can
    /// never disagree. [`AccountState::cross_maintenance_margin_used`] and
    /// [`AccountState::total_margin_used`] are served ONLY at that depth.
    ///
    /// The dex-keyed POSITION table is not in this body. Read
    /// [`Info::clearinghouse_state`] for it.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn account_state(
        &self,
        addr: Address,
        detail: Option<AccountDetail>,
    ) -> Result<AccountState, ClientError> {
        let mut body = json!({ "type": "account_state", "address": addr });
        if let Some(d) = detail {
            let obj = body.as_object_mut().expect("json! produced an object");
            obj.insert("detail".into(), json!(d));
        }
        self.client.post_json("/info", &body).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wire-v3 `account_state.data` body, exactly as the node serializes it:
    /// the cross-lane scalars, then the four lane summaries. No position table.
    fn account_state_fixture() -> serde_json::Value {
        serde_json::json!({
            "address": "0x000000000000000000000000000000000000beef",
            "account_value": "100000000",
            "total_raw_usd": "99500000",
            "withdrawable": "80000000",
            "health": "10000000",
            "tier": "Safe",
            "abstraction": "unified",
            "perp": {
                "init_margin": "20000000",
                "total_ntl_pos": "96000",
                "pm_maint_margin": "0",
                "pm_concentration_penalty": "0"
            },
            "pm_net_value": "0",
            "spot": {
                "balances": [
                    { "name": "USDC", "signing_id": 100, "total": "100000000", "hold": "0" },
                    { "name": "ETH", "signing_id": 102, "total": "5000000000", "hold": "1" }
                ]
            },
            "margin": { "collateral": "500", "debt": "120.5", "pairs": 2 },
            "option": { "escrow": "45000", "legs": 1, "next_expiry": 1_735_689_600_000u64 },
            "position_mode": "one_way",
            "height": 8_416_000u64,
            "time": 1_783_011_600_000u64
        })
    }

    #[test]
    fn account_state_decodes_the_wire_v3_body() {
        let a: AccountState = serde_json::from_value(account_state_fixture()).unwrap();
        assert_eq!(a.account_value, "100000000");
        // `total_raw_usd` excludes the leg's unrealised profit.
        assert_eq!(a.total_raw_usd, "99500000");
        assert_eq!(a.tier, Tier::Safe);
        assert_eq!(a.abstraction, Abstraction::Unified);
        assert_eq!(a.position_mode, Some(PositionMode::OneWay));
        assert_eq!(a.height, 8_416_000);
        assert_eq!(a.time, 1_783_011_600_000);

        // `pm_net_value` is CROSS-lane and stays at the TOP level. Under `perp`
        // a caller that sums the lanes counts the same USDC twice.
        assert_eq!(a.pm_net_value.as_deref(), Some("0"));

        let perp = a.perp.as_ref().unwrap();
        // The flat body called this `total_margin_used`.
        assert_eq!(perp.init_margin, "20000000");
        // An ISOLATED leg is not in the cross notional.
        assert_eq!(perp.total_ntl_pos, "96000");
        assert_eq!(perp.pm_maint_margin, "0");
        assert_eq!(perp.pm_concentration_penalty, "0");

        // The token ledger moved under `spot`; USDC is first.
        assert_eq!(a.balances()[0].name, "USDC");
        assert_eq!(a.balances()[0].signing_id, 100);
        assert_eq!(a.balances()[1].name, "ETH");
        assert_eq!(a.balances()[1].hold, "1");

        let margin = a.margin.as_ref().unwrap();
        assert_eq!(margin.collateral, "500");
        assert_eq!(margin.debt, "120.5");
        // A COUNT rides the wire as a number, not a string.
        assert_eq!(margin.pairs, 2);

        let option = a.option.as_ref().unwrap();
        assert_eq!(option.escrow, "45000");
        assert_eq!(option.legs, 1);
        assert_eq!(option.next_expiry, Some(1_735_689_600_000));

        let dec: AccountState = serde_json::from_str(&serde_json::to_string(&a).unwrap()).unwrap();
        assert_eq!(a, dec);
    }

    /// The keys that MOVED into a lane must be gone from the top level. A body
    /// that carries both is half wire-v2 and half wire-v3, and a client that
    /// reads the flat name gets a number the node no longer maintains.
    #[test]
    fn account_state_body_drops_the_moved_keys() {
        let body = account_state_fixture();
        for key in [
            "positions",
            "clearinghouse_state",
            "balances",
            "total_margin_used",
            "total_ntl_pos",
            "pm_maint_margin",
            "pm_concentration_penalty",
            "cross_maintenance_margin_used",
            "init_margin",
            "maint_margin",
            "mode",
            "pm_enabled",
        ] {
            assert!(body.get(key).is_none(), "`{key}` must not be top level");
        }
        assert!(body["spot"]["balances"].is_array());
    }

    /// Every lane key is present and ZEROED for an account with nothing in that
    /// lane. A zeroed lane must decode; it is the shape an idle account returns.
    ///
    /// `next_expiry` is the one non-uniform key: the node OMITS it at zero legs,
    /// because a zero timestamp reads as 1970. `spot.balances` still carries the
    /// unconditional USDC row, so the array is never empty.
    #[test]
    fn account_state_decodes_an_empty_lane_as_zeroed_not_absent() {
        let mut body = account_state_fixture();
        body["perp"] = serde_json::json!({
            "init_margin": "0", "total_ntl_pos": "0",
            "pm_maint_margin": "0", "pm_concentration_penalty": "0"
        });
        body["spot"] = serde_json::json!({
            "balances": [{ "name": "USDC", "signing_id": 100, "total": "0", "hold": "0",
                           "avg_entry_px": serde_json::Value::Null }]
        });
        body["margin"] = serde_json::json!({ "collateral": "0", "debt": "0", "pairs": 0 });
        body["option"] = serde_json::json!({ "escrow": "0", "legs": 0 });

        let a: AccountState = serde_json::from_value(body).unwrap();
        assert_eq!(a.perp.as_ref().unwrap().init_margin, "0");
        assert_eq!(a.margin.as_ref().unwrap().pairs, 0);
        let option = a.option.as_ref().unwrap();
        assert_eq!(option.legs, 0);
        assert_eq!(option.next_expiry, None);
        // The USDC row is unconditional: an EMPTY array is a shape no real
        // account returns.
        assert_eq!(a.balances().len(), 1);
        assert_eq!(a.balances()[0].name, "USDC");
        assert_eq!(a.balances()[0].avg_entry_px, None);
    }

    /// The node emits `health_deferred` ONLY when the risk engine defers, so
    /// absent must read `false` and present must read `true`.
    #[test]
    fn account_state_reads_the_conditional_health_deferred_flag() {
        let body = account_state_fixture();
        assert!(body.get("health_deferred").is_none());
        let a: AccountState = serde_json::from_value(body.clone()).unwrap();
        assert!(!a.health_deferred);

        let mut deferred = body;
        deferred["health_deferred"] = serde_json::json!(true);
        let d: AccountState = serde_json::from_value(deferred).unwrap();
        assert!(d.health_deferred);
    }

    /// A dropped or renamed field on the money path must FAIL the decode. With
    /// `#[serde(default)]` a rename decoded fine and reported an account that
    /// holds nothing.
    ///
    /// The four lane keys are NOT in this list: the margin depth omits all four
    /// by design, so the type cannot demand them.
    #[test]
    fn account_state_rejects_a_dropped_or_renamed_field() {
        for key in [
            "abstraction",
            "account_value",
            "withdrawable",
            "total_raw_usd",
            "health",
            "tier",
            "height",
            "time",
            "address",
        ] {
            let mut absent = account_state_fixture();
            absent.as_object_mut().unwrap().remove(key);
            assert!(
                serde_json::from_value::<AccountState>(absent).is_err(),
                "a missing `{key}` must fail the decode"
            );

            let mut renamed = account_state_fixture();
            let v = renamed.as_object_mut().unwrap().remove(key).unwrap();
            renamed[format!("{key}_v4")] = v;
            assert!(
                serde_json::from_value::<AccountState>(renamed).is_err(),
                "a renamed `{key}` must fail the decode"
            );
        }
    }

    /// A renamed LANE key must not decode as a zeroed lane. `None` says the
    /// depth did not serve the lane; it must never stand in for "the lane moved
    /// and we missed it".
    #[test]
    fn account_state_renamed_lane_reads_none_not_zero() {
        for lane in ["perp", "spot", "margin", "option"] {
            let mut renamed = account_state_fixture();
            let v = renamed.as_object_mut().unwrap().remove(lane).unwrap();
            renamed[format!("{lane}_v4")] = v;
            let a: AccountState = serde_json::from_value(renamed).unwrap();
            let served = match lane {
                "perp" => a.perp.is_some(),
                "spot" => a.spot.is_some(),
                "margin" => a.margin.is_some(),
                _ => a.option.is_some(),
            };
            assert!(!served, "a renamed `{lane}` must read as unserved");
        }
    }

    /// The rename guard above must not be satisfied by an unrelated failure:
    /// the untouched fixture still decodes.
    #[test]
    fn account_state_fixture_still_decodes_unmodified() {
        assert!(serde_json::from_value::<AccountState>(account_state_fixture()).is_ok());
    }

    /// The margin depth answers the scalars alone. It serves NO lane, and it is
    /// the only depth that carries `cross_maintenance_margin_used` and the flat
    /// `total_margin_used`. Every lane must read `None` — "not served" — never a
    /// fabricated zero.
    #[test]
    fn account_state_margin_depth_serves_no_lane_and_adds_the_two_scalars() {
        // The body `detail: "margin"` really returns: scalars, no lane keys, no
        // `pm_net_value`, no `position_mode`.
        let body = serde_json::json!({
            "address": "0x000000000000000000000000000000000000beef",
            "account_value": "100000000",
            "total_raw_usd": "99500000",
            "withdrawable": "80000000",
            "cross_maintenance_margin_used": "90000000",
            "total_margin_used": "20000000",
            "health": "10000000",
            "tier": "Safe",
            "abstraction": "unified",
            "height": 8_416_000u64,
            "time": 1_783_011_600_000u64
        });

        let a: AccountState = serde_json::from_value(body).unwrap();
        assert_eq!(a.cross_maintenance_margin_used.as_deref(), Some("90000000"));
        assert_eq!(a.total_margin_used.as_deref(), Some("20000000"));
        assert_eq!(a.total_raw_usd, "99500000");
        assert!(a.perp.is_none());
        assert!(a.spot.is_none());
        assert!(a.margin.is_none());
        assert!(a.option.is_none());
        assert!(a.pm_net_value.is_none());
        assert!(a.position_mode.is_none());
        assert!(a.balances().is_empty());

        // The default depth is the other half of the contract: lanes served, and
        // neither margin-only scalar present.
        let full: AccountState = serde_json::from_value(account_state_fixture()).unwrap();
        assert!(full.cross_maintenance_margin_used.is_none());
        assert!(full.total_margin_used.is_none());
        assert_eq!(full.perp.as_ref().unwrap().total_ntl_pos, "96000");
    }

    /// The node REFUSES `detail: "adl"` on this read with a 400, so the depth
    /// enum must not be able to spell it. The lamps ride
    /// [`Info::clearinghouse_state`] instead.
    #[test]
    fn account_detail_spells_only_the_two_served_depths() {
        assert_eq!(
            serde_json::to_value(AccountDetail::Full).unwrap(),
            serde_json::json!("full")
        );
        assert_eq!(
            serde_json::to_value(AccountDetail::Margin).unwrap(),
            serde_json::json!("margin")
        );
        assert!(serde_json::from_value::<AccountDetail>(serde_json::json!("adl")).is_err());
    }

    #[test]
    fn account_state_reads_a_portfolio_margin_account() {
        let mut body = account_state_fixture();
        body["abstraction"] = serde_json::json!("portfolio");
        body["perp"]["pm_maint_margin"] = serde_json::json!("1234.56");
        body["pm_net_value"] = serde_json::json!("98765.4");
        let a: AccountState = serde_json::from_value(body).unwrap();
        assert_eq!(a.abstraction, Abstraction::Portfolio);
        assert_eq!(a.perp.as_ref().unwrap().pm_maint_margin, "1234.56");
        assert_eq!(a.pm_net_value.as_deref(), Some("98765.4"));
    }
}
