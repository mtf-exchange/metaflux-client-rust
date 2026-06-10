//! Spot CLOB types — spot order / cancel (`/exchange`).
//!
//! The spot order engine is a separate CLOB from the perp book: orders
//! reference a spot `pair` id (not a perp `market` id) and trade raw base lots
//! against a quote. v0 is **IOC limit only** — `tif` must be `ioc` and
//! `limit_px > 0`; the node rejects `gtc` / `alo` and a market (`limit_px = 0`)
//! order at admission. The builders here default `tif` to [`TimeInForce::Ioc`]
//! and document the constraint, but do not hard-block other tifs so a caller
//! can pass one through unchanged once the node lifts the v0 limit.
//!
//! Wire shape (MTF-native, snake_case):
//!
//! ```json
//! {
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
//! `0x...` string or omitted (`null`).

use serde::{Deserialize, Serialize};

use crate::types::Cloid;
use crate::types::order::{Side, StpMode, TimeInForce};

/// A single spot CLOB order submission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SpotOrder {
    /// Target spot pair id.
    pub pair: u32,
    /// Bid / ask.
    pub side: Side,
    /// Size in raw base lots (u64).
    pub size: u64,
    /// Limit price on the 1e8 fixed-point price plane (u64). v0 requires
    /// `limit_px > 0` — a market (px = 0) order is rejected.
    pub limit_px: u64,
    /// Time-in-force. v0 supports `ioc` only; defaults to [`TimeInForce::Ioc`]
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
    /// Build a v0-conformant IOC limit spot order.
    ///
    /// `tif` defaults to [`TimeInForce::Ioc`] and `stp_mode` to
    /// [`StpMode::CancelOldest`] (the engine default); set
    /// [`SpotOrder::cloid`] / [`SpotOrder::stp_mode`] afterwards to override.
    /// `limit_px` must be `> 0` for the node to accept it.
    #[must_use]
    pub const fn ioc_limit(pair: u32, side: Side, size: u64, limit_px: u64) -> Self {
        Self {
            pair,
            side,
            size,
            limit_px,
            tif: TimeInForce::Ioc,
            stp_mode: StpMode::CancelOldest,
            cloid: None,
        }
    }
}

/// Cancel a resting spot order by `oid`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SpotCancel {
    /// Target spot pair id.
    pub pair: u32,
    /// Server-assigned spot order id.
    pub oid: u64,
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

/// Post quote (USDC) collateral into the `(account, pair)` margin account.
///
/// Margin must be enabled for the pair (per-pair risk params present), else the
/// node rejects with `spot margin not enabled for pair`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SpotMarginDeposit {
    /// Spot pair id.
    pub pair: u32,
    /// Quote collateral to post (whole units), as a decimal string (`> 0`).
    pub amount: String,
}

/// Withdraw free collateral from the `(account, pair)` margin account back to
/// the spendable quote balance.
///
/// Full collateral is withdrawable while flat; an open position gates the
/// withdraw at the initial-margin requirement.
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
        let c = SpotCancel { pair: 3, oid: 12345 };
        let j = serde_json::to_value(c).unwrap();
        assert_eq!(j["pair"], serde_json::json!(3));
        assert_eq!(j["oid"], serde_json::json!(12345));
        let dec: SpotCancel = serde_json::from_value(j).unwrap();
        assert_eq!(c, dec);
    }

    #[test]
    fn spot_margin_deposit_decimal_rides_as_json_string() {
        let d = SpotMarginDeposit { pair: 200, amount: "100".into() };
        let j = serde_json::to_value(&d).unwrap();
        assert_eq!(j["pair"], serde_json::json!(200));
        assert!(j["amount"].is_string(), "decimal amount must be a JSON string");
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
        let c = SpotMarginClose { pair: 200, limit_px: 190_000_000 };
        let j = serde_json::to_value(c).unwrap();
        assert_eq!(j["pair"], serde_json::json!(200));
        assert_eq!(j["limit_px"], serde_json::json!(190_000_000));
        let dec: SpotMarginClose = serde_json::from_value(j).unwrap();
        assert_eq!(c, dec);
    }

    #[test]
    fn earn_actions_serialize_asset_and_decimal_string() {
        let d = EarnDeposit { asset: 100, amount: "5000".into() };
        let jd = serde_json::to_value(&d).unwrap();
        assert_eq!(jd["asset"], serde_json::json!(100));
        assert_eq!(jd["amount"], serde_json::json!("5000"));
        assert!(jd["amount"].is_string());
        assert_eq!(d, serde_json::from_value::<EarnDeposit>(jd).unwrap());

        let w = EarnWithdraw { asset: 100, shares: "1234.5".into() };
        let jw = serde_json::to_value(&w).unwrap();
        assert_eq!(jw["asset"], serde_json::json!(100));
        assert_eq!(jw["shares"], serde_json::json!("1234.5"));
        assert!(jw["shares"].is_string(), "fractional shares must survive as a string");
        assert_eq!(w, serde_json::from_value::<EarnWithdraw>(jw).unwrap());
    }
}
