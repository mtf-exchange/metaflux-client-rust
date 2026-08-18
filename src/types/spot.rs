//! Spot CLOB types — spot order / cancel (`/exchange`).
//!
//! The spot order engine is a separate CLOB from the perp book: orders
//! reference a spot `pair` id (not a perp `market` id) and trade raw base lots
//! against a quote. `tif` accepts `ioc`, `gtc` and `alo`; a `gtc` / `alo`
//! residual RESTS on the book against escrowed funds. A limit is required
//! (`limit_px > 0`) — the node rejects a market order. [`SpotOrder::ioc_limit`]
//! defaults `tif` to [`TimeInForce::Ioc`].
//!
//! ## Who owns the order
//!
//! `owner` is OPTIONAL and mirrors the node's `NativeSpotOrder.owner`. With
//! `owner` present, an approved agent of that address places the order AS the
//! owner — the signer is the AGENT, and the node binds the order to the owner.
//! Absent, the signer trades for itself. The same rule holds for
//! [`SpotCancel`]. See
//! [`Exchange::spot_order`](crate::rest::exchange::Exchange::spot_order).
//!
//! Wire shape (MTF-native, snake_case):
//!
//! ```json
//! {
//!   "owner":     "0x1111111111111111111111111111111111111111",
//!   "pair":      3,
//!   "side":      "bid",
//!   "size":      1000,
//!   "limit_px":  5000000000,
//!   "tif":       "ioc",
//!   "stp_mode":  "cancel_oldest",
//!   "cloid":     null
//! }
//! ```
//!
//! Numerics are plain integers. `size` is in raw base lots (u64); `limit_px`
//! is on the 1e8 fixed-point price plane (u64). `cloid` is a 32-char hex
//! `0x...` string or omitted (`null`). `owner` is a `0x`-hex 20-byte address,
//! omitted when absent.

use serde::{Deserialize, Serialize};

use crate::types::Cloid;
use crate::types::order::{Side, StpMode, TimeInForce};
use crate::wallet::Address;

/// A single spot CLOB order submission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SpotOrder {
    /// Optional agent-resolved owner. `Some` = an approved agent of this
    /// address places the order AS that owner; `None` = the signer trades for
    /// itself. Bound into the `*_WITH_OWNER` digest when present; omitted from
    /// the wire otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<Address>,
    /// Target spot pair id.
    pub pair: u32,
    /// Bid / ask.
    pub side: Side,
    /// Size in raw base lots (u64).
    pub size: u64,
    /// Limit price on the 1e8 fixed-point price plane (u64). Must be `> 0` — a
    /// market (px = 0) order is rejected.
    pub limit_px: u64,
    /// Time-in-force (`ioc` / `gtc` / `alo`). Defaults to [`TimeInForce::Ioc`]
    /// via [`SpotOrder::ioc_limit`].
    pub tif: TimeInForce,
    /// Self-trade-prevention mode (the same wire enum as a perp order — the spot
    /// engine accepts no extra modes).
    pub stp_mode: StpMode,
    /// Optional client-supplied identifier for idempotency.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloid: Option<Cloid>,
}

impl SpotOrder {
    /// Build an IOC limit spot order owned by the signer.
    ///
    /// `tif` defaults to [`TimeInForce::Ioc`] and `stp_mode` to
    /// [`StpMode::CancelOldest`] (the engine default); set
    /// [`SpotOrder::cloid`] / [`SpotOrder::stp_mode`] afterwards to override.
    /// `limit_px` must be `> 0` for the node to accept it. For agent-placed
    /// orders add an owner with [`SpotOrder::with_owner`].
    #[must_use]
    pub const fn ioc_limit(pair: u32, side: Side, size: u64, limit_px: u64) -> Self {
        Self {
            owner: None,
            pair,
            side,
            size,
            limit_px,
            tif: TimeInForce::Ioc,
            stp_mode: StpMode::CancelOldest,
            cloid: None,
        }
    }

    /// Place this order AS `owner`. The signing wallet must be an approved agent
    /// of `owner`.
    #[must_use]
    pub const fn with_owner(mut self, owner: Address) -> Self {
        self.owner = Some(owner);
        self
    }
}

/// Cancel a resting spot order by `oid`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SpotCancel {
    /// Optional agent-resolved owner. `Some` = an approved agent of this
    /// address cancels AS that owner; `None` = the signer cancels its own
    /// order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<Address>,
    /// Target spot pair id.
    pub pair: u32,
    /// Server-assigned spot order id.
    pub oid: u64,
}

impl SpotCancel {
    /// Cancel the signer's own resting order. For an agent-placed cancel add an
    /// owner with [`SpotCancel::with_owner`].
    #[must_use]
    pub const fn new(pair: u32, oid: u64) -> Self {
        Self {
            owner: None,
            pair,
            oid,
        }
    }

    /// Cancel AS `owner`. The signing wallet must be an approved agent of
    /// `owner`.
    #[must_use]
    pub const fn with_owner(mut self, owner: Address) -> Self {
        self.owner = Some(owner);
        self
    }
}

// ---- Spot margin (leveraged spot) + Earn (lending pool) ----
//
// Available on devnet (preview). Leveraged spot is isolated per `(account,
// pair)`: posted quote collateral is a loss buffer, the borrow funds the buy
// 100%, and the bought base is held segregated on the margin account. Earn is
// the supply side that funds the borrows. All actions are sender-authorized
// (the recovered signer is the actor — no owner field). Decimal magnitudes
// (`amount` / `borrow` / `shares`) ride the wire as JSON **strings** to preserve
// fractional precision; `size` / `limit_px` are plain integers on the raw-lot /
// 1e8 planes, like a [`SpotOrder`].

/// **DEPRECATED — the node REJECTS this action.** Post quote (USDC) collateral
/// into the `(account, pair)` margin account.
///
/// Spot margin is cross-collateralized against the one unified USDC account, so
/// there is no per-pair collateral bucket to post into. The node rejects the
/// action whenever the cross-margin model is active, which on the live chain is
/// from genesis. Fund the unified USDC account instead, then use
/// [`SpotMarginOpen`] / [`SpotMarginClose`].
///
/// The type and its EIP-712 type string stay so old signatures remain
/// verifiable. See
/// [`Exchange::spot_margin_deposit`](crate::rest::exchange::Exchange::spot_margin_deposit).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SpotMarginDeposit {
    /// Spot pair id.
    pub pair: u32,
    /// Quote collateral to post (whole units), as a decimal string (`> 0`).
    pub amount: String,
}

/// **DEPRECATED — the node REJECTS this action.** Withdraw free collateral from
/// the `(account, pair)` margin account.
///
/// The twin of [`SpotMarginDeposit`]: there is no per-pair collateral bucket to
/// withdraw from under cross-margin. The node rejects the action whenever the
/// cross-margin model is active, which on the live chain is from genesis. Close
/// with [`SpotMarginClose`], then withdraw from the unified USDC account through
/// the normal account lane.
///
/// The type and its EIP-712 type string stay so old signatures remain
/// verifiable. See
/// [`Exchange::spot_margin_withdraw`](crate::rest::exchange::Exchange::spot_margin_withdraw).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SpotMarginWithdraw {
    /// Spot pair id.
    pub pair: u32,
    /// Collateral to withdraw (whole quote units), as a decimal string (`> 0`).
    pub amount: String,
}

/// Open a leveraged long: borrow quote from the pair's Earn pool and IOC-buy
/// `size` base at up to `limit_px`.
///
/// The borrow funds the buy 100%; the bought base is held segregated. Any
/// unspent borrow is repaid instantly. Gated by the initial-margin requirement
/// on the worst-case cost (`limit_px × size`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SpotMarginOpen {
    /// Spot pair id.
    pub pair: u32,
    /// Buy size in base-asset raw lots (`10^sz_decimals` per whole unit).
    pub size: u64,
    /// Limit price on the 1e8 fixed-point price plane (`> 0`).
    pub limit_px: u64,
    /// Quote principal to draw from the Earn pool (whole units), as a decimal
    /// string (`> 0`).
    pub borrow: String,
}

/// Close the position: IOC-sell the held base at no less than `limit_px`, repay
/// principal + accrued interest to the Earn pool, return the remainder.
///
/// A partial fill keeps the account open (unsold base stays segregated,
/// collateral untouched).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SpotMarginClose {
    /// Spot pair id.
    pub pair: u32,
    /// Floor price for the close sell, on the 1e8 plane (`> 0`).
    pub limit_px: u64,
}

/// Supply quote into an Earn lending pool for pool shares.
///
/// 1:1 on a fresh pool, else priced off pool NAV. The pool auto-creates on the
/// first deposit for any asset that is the quote of a registered spot pair.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct EarnDeposit {
    /// Lendable asset id (a spot pair's quote) — the pool key.
    pub asset: u32,
    /// Quote to supply (whole units), as a decimal string (`> 0`).
    pub amount: String,
}

/// Redeem pool shares back to quote.
///
/// The payout is clamped to the pool's idle liquidity (`supplied − borrowed`):
/// a redemption larger than idle pays exactly idle and burns proportionally
/// fewer shares.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct EarnWithdraw {
    /// Lendable asset id (the pool key).
    pub asset: u32,
    /// Pool shares to redeem, as a decimal string (`> 0`, owned by the sender).
    pub shares: String,
}

// ---- Permissionless spot deployer lane ----
//
// Six sender-authorized actions deploy a spot token and its pair. The signer IS
// the deployer — there is no `owner` field. The full sequence is: register the
// token, register the pair, set its params, stage the genesis rows in one or
// more calls, seal the supply, then open the pair.
//
// `max_deploy_fee` is the highest Dutch-clock accept price the signer takes, in
// WHOLE USDC. It is not gas. The node charges the clock price at register time
// from free collateral and refuses the call when the clock is above this cap.
//
// Every decimal here is hashed VERBATIM into the signed digest and re-sent
// unchanged, so pick one canonical form: `"980"` and `"980.00"` are different
// signatures.

/// Register a fresh spot token (step 1 of the deployer sequence).
///
/// The node assigns the token id. A deployer cannot declare its token canonical
/// or bind its own EVM contract — neither field is on this wire.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SpotRegisterToken {
    /// Token symbol.
    pub symbol: String,
    /// Display / size precision.
    pub sz_decimals: u8,
    /// Native (ERC-20 style) token decimals. The node rejects a value above 18;
    /// pass 1 or more, since a 0 names a token with no wei scale.
    pub wei_decimals: u8,
    /// Highest Dutch accept price taken, as a decimal string in whole USDC
    /// (`>= 0`).
    pub max_deploy_fee: String,
}

/// Register a `(base, quote)` trading pair over registered tokens (step 2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SpotRegisterPair {
    /// Base token id.
    pub base: u32,
    /// Quote token id (USDC today).
    pub quote: u32,
    /// Pair name.
    pub name: String,
    /// Highest Dutch accept price taken, as a decimal string in whole USDC
    /// (`>= 0`).
    pub max_deploy_fee: String,
}

/// Set a pair's fee tier and minimum order notional in one intent.
///
/// **Unit trap:** both fees are DECI-bps (one tenth of a basis point), not bps.
/// The node rejects a leg at 1000 or above.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SpotSetPairParams {
    /// Spot pair id.
    pub pair: u32,
    /// Taker fee in deci-bps (`< 1000`).
    pub taker_fee_dbps: u32,
    /// Maker fee in deci-bps (`< 1000`).
    pub maker_fee_dbps: u32,
    /// Min order notional in USDC cents.
    pub min_notional_cents: u64,
}

/// Open or close a pair to new orders.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SpotSetPairActive {
    /// Spot pair id.
    pub pair: u32,
    /// `true` opens the pair, `false` closes it.
    pub active: bool,
}

/// Stage genesis holder rows for a registered token. Repeatable.
///
/// The two arrays are parallel and must be the same length; an empty call is
/// refused. Both ride INSIDE the signed digest, so a relay can neither
/// re-target, re-size nor re-order a row.
///
/// **Amounts are WHOLE UNITS, never wei.** The spot ledger is whole-unit, so a
/// caller that sends wei mints 10^18 times too much AND the
/// [`SpotFinalizeSupply`] checksum agrees — the error is silent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SpotSeedHolders {
    /// The spot token being staged.
    pub asset: u32,
    /// Holder addresses, parallel with `amounts`. At most 128 rows per call.
    pub holders: Vec<Address>,
    /// Whole-unit amounts as decimal strings, parallel with `holders`.
    pub amounts: Vec<String>,
}

/// Check the staged sum, then mint the supply once.
///
/// `max_supply` is an integrity check over the seed SEQUENCE, not a setting: it
/// proves every [`SpotSeedHolders`] call landed. A mismatch refuses the mint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SpotFinalizeSupply {
    /// The spot token being sealed.
    pub asset: u32,
    /// Sum of every staged row, as a whole-unit decimal string.
    pub max_supply: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spot_order_ioc_limit_defaults() {
        let o = SpotOrder::ioc_limit(3, Side::Bid, 1000, 5_000_000_000);
        assert_eq!(o.tif, TimeInForce::Ioc);
        assert_eq!(o.stp_mode, StpMode::CancelOldest);
        assert!(o.cloid.is_none());
    }

    #[test]
    fn spot_order_serializes_snake_case_integers() {
        let o = SpotOrder::ioc_limit(3, Side::Ask, 1000, 5_000_000_000);
        let j = serde_json::to_value(&o).unwrap();
        assert!(j["pair"].is_number());
        assert!(j["size"].is_number());
        assert!(j["limit_px"].is_number(), "limit_px must be a plain number");
        assert_eq!(j["side"], serde_json::json!("ask"));
        assert_eq!(j["tif"], serde_json::json!("ioc"));
        assert_eq!(j["stp_mode"], serde_json::json!("cancel_oldest"));
        assert!(j.get("limitPx").is_none(), "no camelCase leak");
    }

    #[test]
    fn spot_order_omits_none_cloid() {
        let o = SpotOrder::ioc_limit(1, Side::Bid, 1, 1);
        let j = serde_json::to_value(&o).unwrap();
        assert!(j.get("cloid").is_none());
    }

    #[test]
    fn spot_order_serializes_cloid_when_set() {
        let mut o = SpotOrder::ioc_limit(1, Side::Bid, 1, 1);
        o.cloid = Some(Cloid([0xCDu8; 16]));
        let j = serde_json::to_value(&o).unwrap();
        assert_eq!(
            j["cloid"],
            serde_json::json!("0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd")
        );
    }

    #[test]
    fn spot_order_round_trips() {
        let mut o = SpotOrder::ioc_limit(7, Side::Ask, 42, 9_999);
        o.stp_mode = StpMode::CancelNewest;
        o.cloid = Some(Cloid([0x01u8; 16]));
        let j = serde_json::to_string(&o).unwrap();
        let dec: SpotOrder = serde_json::from_str(&j).unwrap();
        assert_eq!(o, dec);
    }

    #[test]
    fn spot_cancel_serializes_snake_case() {
        let c = SpotCancel::new(3, 12345);
        let j = serde_json::to_value(c).unwrap();
        assert_eq!(j["pair"], serde_json::json!(3));
        assert_eq!(j["oid"], serde_json::json!(12345));
        let dec: SpotCancel = serde_json::from_value(j).unwrap();
        assert_eq!(c, dec);
    }

    // ---- agent-resolved `owner` ----

    fn agent_owner() -> Address {
        Address([0xbb; 20])
    }

    /// BYTE PIN: an owner-less order serializes exactly as it did before the
    /// field existed. A caller signing a self-trade sees no change.
    #[test]
    fn spot_order_without_owner_is_byte_identical() {
        let o = SpotOrder::ioc_limit(3, Side::Bid, 1000, 5_000_000_000);
        assert_eq!(
            serde_json::to_string(&o).unwrap(),
            r#"{"pair":3,"side":"bid","size":1000,"limit_px":5000000000,"tif":"ioc","stp_mode":"cancel_oldest"}"#
        );
        let c = SpotCancel::new(3, 12345);
        assert_eq!(
            serde_json::to_string(&c).unwrap(),
            r#"{"pair":3,"oid":12345}"#
        );
    }

    /// A present `owner` serializes FIRST, mirroring the node's
    /// `NativeSpotOrder` declaration order. The POSTed action nests this inside
    /// a `serde_json::Value`, which re-keys alphabetically; those wire bytes are
    /// pinned in `tests/native_signing_xcheck.rs`.
    #[test]
    fn spot_order_with_owner_emits_it_first() {
        let o = SpotOrder::ioc_limit(3, Side::Bid, 1000, 5_000_000_000).with_owner(agent_owner());
        assert_eq!(
            serde_json::to_string(&o).unwrap(),
            r#"{"owner":"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","pair":3,"side":"bid","size":1000,"limit_px":5000000000,"tif":"ioc","stp_mode":"cancel_oldest"}"#
        );
        let c = SpotCancel::new(3, 12345).with_owner(agent_owner());
        assert_eq!(
            serde_json::to_string(&c).unwrap(),
            r#"{"owner":"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","pair":3,"oid":12345}"#
        );
    }

    #[test]
    fn spot_owner_round_trips() {
        let o = SpotOrder::ioc_limit(7, Side::Ask, 42, 9_999).with_owner(agent_owner());
        let dec: SpotOrder = serde_json::from_str(&serde_json::to_string(&o).unwrap()).unwrap();
        assert_eq!(o, dec);
        assert_eq!(dec.owner, Some(agent_owner()));

        let c = SpotCancel::new(7, 42).with_owner(agent_owner());
        let dec: SpotCancel = serde_json::from_str(&serde_json::to_string(&c).unwrap()).unwrap();
        assert_eq!(c, dec);
    }

    /// An owner-less wire body still decodes — the node's `#[serde(default)]`
    /// contract, mirrored here.
    #[test]
    fn spot_order_decodes_a_body_without_owner() {
        let j = r#"{"pair":3,"side":"bid","size":1000,"limit_px":5000000000,"tif":"ioc","stp_mode":"cancel_oldest"}"#;
        let dec: SpotOrder = serde_json::from_str(j).unwrap();
        assert_eq!(dec.owner, None);
        let dec: SpotCancel = serde_json::from_str(r#"{"pair":3,"oid":9}"#).unwrap();
        assert_eq!(dec.owner, None);
    }

    /// An `owner` that is not a 20-byte hex address is REFUSED, not truncated or
    /// zero-filled: a silently wrong owner would route the order to the wrong
    /// account.
    #[test]
    fn spot_order_refuses_an_invalid_owner_address() {
        for bad in [
            r#""0xbeef""#,
            r#""0xzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz""#,
            r#""0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb""#,
            "42",
        ] {
            let j = format!(
                r#"{{"owner":{bad},"pair":3,"side":"bid","size":1,"limit_px":1,"tif":"ioc","stp_mode":"cancel_oldest"}}"#
            );
            assert!(
                serde_json::from_str::<SpotOrder>(&j).is_err(),
                "owner {bad} must be refused"
            );
            let j = format!(r#"{{"owner":{bad},"pair":3,"oid":9}}"#);
            assert!(
                serde_json::from_str::<SpotCancel>(&j).is_err(),
                "owner {bad} must be refused"
            );
        }
        assert!(Address::from_hex("0xbeef").is_err());
    }

    #[test]
    fn spot_margin_deposit_decimal_rides_as_json_string() {
        let d = SpotMarginDeposit {
            pair: 200,
            amount: "100".into(),
        };
        let j = serde_json::to_value(&d).unwrap();
        assert_eq!(j["pair"], serde_json::json!(200));
        assert!(
            j["amount"].is_string(),
            "decimal amount must be a JSON string"
        );
        assert_eq!(j["amount"], serde_json::json!("100"));
        let dec: SpotMarginDeposit = serde_json::from_value(j).unwrap();
        assert_eq!(d, dec);
    }

    #[test]
    fn spot_margin_open_mixes_integer_planes_and_decimal_string() {
        let o = SpotMarginOpen {
            pair: 200,
            size: 200,
            limit_px: 200_000_000,
            borrow: "400".into(),
        };
        let j = serde_json::to_value(&o).unwrap();
        assert!(j["size"].is_number(), "size is a raw-lot integer");
        assert!(j["limit_px"].is_number(), "limit_px is a 1e8-plane integer");
        assert_eq!(j["limit_px"], serde_json::json!(200_000_000));
        assert!(j["borrow"].is_string(), "borrow is a decimal JSON string");
        assert!(j.get("limitPx").is_none(), "no camelCase leak");
        let dec: SpotMarginOpen = serde_json::from_value(j).unwrap();
        assert_eq!(o, dec);
    }

    #[test]
    fn spot_margin_close_serializes_snake_case() {
        let c = SpotMarginClose {
            pair: 200,
            limit_px: 190_000_000,
        };
        let j = serde_json::to_value(c).unwrap();
        assert_eq!(j["pair"], serde_json::json!(200));
        assert_eq!(j["limit_px"], serde_json::json!(190_000_000));
        let dec: SpotMarginClose = serde_json::from_value(j).unwrap();
        assert_eq!(c, dec);
    }

    #[test]
    fn earn_actions_serialize_asset_and_decimal_string() {
        let d = EarnDeposit {
            asset: 100,
            amount: "5000".into(),
        };
        let jd = serde_json::to_value(&d).unwrap();
        assert_eq!(jd["asset"], serde_json::json!(100));
        assert_eq!(jd["amount"], serde_json::json!("5000"));
        assert!(jd["amount"].is_string());
        assert_eq!(d, serde_json::from_value::<EarnDeposit>(jd).unwrap());

        let w = EarnWithdraw {
            asset: 100,
            shares: "1234.5".into(),
        };
        let jw = serde_json::to_value(&w).unwrap();
        assert_eq!(jw["asset"], serde_json::json!(100));
        assert_eq!(jw["shares"], serde_json::json!("1234.5"));
        assert!(
            jw["shares"].is_string(),
            "fractional shares must survive as a string"
        );
        assert_eq!(w, serde_json::from_value::<EarnWithdraw>(jw).unwrap());
    }

    /// The node reads `max_deploy_fee` / `max_supply` as the VERBATIM signed
    /// string. A JSON number there fails the read and the action is refused, so
    /// pin the string shape and the trailing zero.
    #[test]
    fn spot_deploy_decimals_ride_as_verbatim_json_strings() {
        let t = SpotRegisterToken {
            symbol: "MTFX".into(),
            sz_decimals: 2,
            wei_decimals: 8,
            max_deploy_fee: "1250.50".into(),
        };
        let jt = serde_json::to_value(&t).unwrap();
        assert_eq!(jt["max_deploy_fee"], serde_json::json!("1250.50"));
        assert!(jt["max_deploy_fee"].is_string());
        assert_eq!(jt["sz_decimals"], serde_json::json!(2));
        assert!(jt.get("szDecimals").is_none(), "no camelCase leak");
        assert_eq!(t, serde_json::from_value(jt).unwrap());

        let p = SpotRegisterPair {
            base: 42,
            quote: 0,
            name: "MTFX/USDC".into(),
            max_deploy_fee: "980.00".into(),
        };
        let jp = serde_json::to_value(&p).unwrap();
        assert_eq!(
            jp["max_deploy_fee"],
            serde_json::json!("980.00"),
            "the trailing zeros are part of the signed bytes"
        );
        assert_eq!(p, serde_json::from_value(jp).unwrap());

        let f = SpotFinalizeSupply {
            asset: 42,
            max_supply: "1250.500001".into(),
        };
        let jf = serde_json::to_value(&f).unwrap();
        assert!(jf["max_supply"].is_string());
        assert_eq!(f, serde_json::from_value(jf).unwrap());
    }

    #[test]
    fn spot_seed_holders_keeps_two_parallel_arrays() {
        let s = SpotSeedHolders {
            asset: 42,
            holders: vec![
                Address::from_hex("0x1111111111111111111111111111111111111111").unwrap(),
                Address::from_hex("0x00000000000000000000000000000000000000aB").unwrap(),
            ],
            amounts: vec!["1000.5".into(), "250".into()],
        };
        let j = serde_json::to_value(&s).unwrap();
        assert_eq!(j["holders"].as_array().unwrap().len(), 2);
        assert!(j["holders"][0].is_string(), "holders are 0x-hex strings");
        assert_eq!(j["amounts"], serde_json::json!(["1000.5", "250"]));
        assert_eq!(s, serde_json::from_value(j).unwrap());
    }

    #[test]
    fn spot_pair_params_and_active_serialize_snake_case() {
        let p = SpotSetPairParams {
            pair: 7,
            taker_fee_dbps: 350,
            maker_fee_dbps: 120,
            min_notional_cents: 1000,
        };
        let j = serde_json::to_value(p).unwrap();
        assert_eq!(j["taker_fee_dbps"], serde_json::json!(350));
        assert_eq!(j["min_notional_cents"], serde_json::json!(1000));
        assert!(j.get("takerFeeDbps").is_none(), "no camelCase leak");
        assert_eq!(p, serde_json::from_value(j).unwrap());

        let a = SpotSetPairActive {
            pair: 7,
            active: true,
        };
        let ja = serde_json::to_value(a).unwrap();
        assert_eq!(ja["active"], serde_json::json!(true));
        assert_eq!(a, serde_json::from_value(ja).unwrap());
    }
}
