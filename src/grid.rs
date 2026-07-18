//! Round a desired order price / size onto a market's on-chain grid.
//!
//! The node REJECTS off-grid orders: a price that is not a multiple of the
//! market tick, a size that is not a multiple of the lot step, or a size below
//! the market minimum are all admission errors. [`round_order_to_grid`] snaps a
//! desired price / size to that grid so a submission is admitted.
//!
//! ## Plane bridge
//!
//! [`MarketInfo`] reports `tick_size` / `step_size` / `min_order` as CANONICAL
//! decimal strings: `tick_size` in whole USDC (e.g. `"0.01"`), `step_size` /
//! `min_order` in whole base units (e.g. `"0.001"`). The order wire lives on two
//! different integer planes — `limit_px` is 1e8 fixed-point and `size` is raw
//! lots (`whole × 10^sz_decimals`). So the tick is scaled to the price plane
//! (`tick_1e8 = tick_size × 10^8`) and the step / minimum are scaled to the lot
//! plane (`× 10^sz_decimals`) before snapping. No floating point is used: the
//! canonical decimal strings are parsed straight into scaled integers.

use crate::rest::info::MarketInfo;

/// The order wire `limit_px` plane is 1e8 fixed-point, so a whole-USDC tick
/// scales by `10^8`.
const PRICE_PLANE_DECIMALS: u32 = 8;

/// Order price / size snapped onto a market's tick / lot grid, ready for the
/// wire (`limit_px` and `size` fields of an [`crate::types::order::Order`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GridOrder {
    /// Tick-snapped limit price on the 1e8 fixed-point plane (order wire `limit_px`).
    pub limit_px: u64,
    /// Step-snapped size in raw lots (`whole × 10^sz_decimals`, order wire `size`).
    pub size: u64,
}

/// Why a desired order cannot be placed on a market's grid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GridError {
    /// `tick_size` was non-positive or unparseable — the market has no price grid.
    BadTick,
    /// `step_size` was non-positive or unparseable — the market has no size grid.
    BadStep,
    /// `limit_px` rounded down to zero (it was below a single tick).
    PriceBelowTick,
    /// The step-snapped size was zero or below the market `min_order`.
    BelowMinOrder,
}

impl core::fmt::Display for GridError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            GridError::BadTick => "market tick_size is not a positive grid value",
            GridError::BadStep => "market step_size is not a positive grid value",
            GridError::PriceBelowTick => "limit price rounds below one tick",
            GridError::BelowMinOrder => "size below the market minimum order",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for GridError {}

/// Snap a desired order price and size onto `market`'s tick / lot grid.
///
/// `limit_px` is the desired price on the 1e8 fixed-point plane (the order wire
/// `limit_px`); `size` is the desired size in raw lots
/// (`whole × 10^sz_decimals`, the order wire `size`). Both are rounded **toward
/// zero** onto a grid multiple — `limit_px` down to a `tick_size` multiple,
/// `size` down to a `step_size` multiple — and the snapped size is checked
/// against `min_order`.
///
/// See the [module docs](self) for the plane bridge between `MarketInfo`'s
/// canonical decimal strings and the integer wire planes.
///
/// # Errors
/// [`GridError`] when the market reports no usable grid, the price rounds below
/// one tick, or the snapped size is below the market minimum.
pub fn round_order_to_grid(
    market: &MarketInfo,
    limit_px: u64,
    size: u64,
) -> Result<GridOrder, GridError> {
    let tick_1e8 = decimal_to_scaled(&market.tick_size, PRICE_PLANE_DECIMALS)
        .filter(|t| *t > 0)
        .ok_or(GridError::BadTick)?;
    let sz_scale = u32::from(market.sz_decimals);
    let step_lots = decimal_to_scaled(&market.step_size, sz_scale)
        .filter(|s| *s > 0)
        .ok_or(GridError::BadStep)?;
    let min_lots = decimal_to_scaled(&market.min_order, sz_scale).unwrap_or(0);

    let px = (u128::from(limit_px) / tick_1e8) * tick_1e8;
    if px == 0 {
        return Err(GridError::PriceBelowTick);
    }
    let sz = (u128::from(size) / step_lots) * step_lots;
    if sz == 0 || sz < min_lots {
        return Err(GridError::BelowMinOrder);
    }
    // px ≤ limit_px ≤ u64::MAX and sz ≤ size ≤ u64::MAX, so both fit a u64.
    Ok(GridOrder {
        limit_px: px as u64,
        size: sz as u64,
    })
}

/// Parse a NON-NEGATIVE canonical decimal string (`"0.01"`, `"100"`, `"0"`) into
/// `floor(value × 10^scale)` as an integer, with no floating point. Fractional
/// digits beyond `scale` are truncated toward zero. Returns `None` on a sign, an
/// empty string, a non-digit, or `u128` overflow.
fn decimal_to_scaled(s: &str, scale: u32) -> Option<u128> {
    let s = s.trim();
    if s.is_empty() || s.starts_with('-') {
        return None;
    }
    let (int_part, frac_part) = s.split_once('.').unwrap_or((s, ""));
    if int_part.is_empty() && frac_part.is_empty() {
        return None;
    }

    let mut acc: u128 = 0;
    for b in int_part.bytes() {
        if !b.is_ascii_digit() {
            return None;
        }
        acc = acc.checked_mul(10)?.checked_add(u128::from(b - b'0'))?;
    }

    let frac = frac_part.as_bytes();
    for i in 0..scale as usize {
        acc = acc.checked_mul(10)?;
        if let Some(&b) = frac.get(i) {
            if !b.is_ascii_digit() {
                return None;
            }
            acc = acc.checked_add(u128::from(b - b'0'))?;
        }
    }
    // Truncated fractional digits are dropped, but must still be valid digits.
    for &b in frac.iter().skip(scale as usize) {
        if !b.is_ascii_digit() {
            return None;
        }
    }
    Some(acc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rest::info::{Funding, MarketInfo, MarketKind};

    fn mkt(tick: &str, step: &str, min: &str, sz_decimals: u8) -> MarketInfo {
        MarketInfo {
            coin: "BTC".into(),
            asset_id: 0,
            kind: MarketKind::Perp,
            sz_decimals,
            mark_px: "0".into(),
            oracle_px: "0".into(),
            tick_size: tick.into(),
            step_size: step.into(),
            min_order: min.into(),
            max_leverage: 50,
            maint_margin_ratio: "0".into(),
            init_margin_ratio: "0".into(),
            funding: Funding {
                rate_per_hr: "0".into(),
                cap_per_hr: "0".into(),
                interval_ms: 3_600_000,
                next_payment_ts: 0,
            },
            margin_tiers: Vec::new(),
            mark_source: "oracle_median".into(),
            fba_enabled: false,
            open_interest: "0".into(),
            token: None,
        }
    }

    #[test]
    fn decimal_tick_scales_into_the_1e8_plane() {
        // tick "0.01" whole-USDC → 1_000_000 on the 1e8 plane.
        assert_eq!(
            decimal_to_scaled("0.01", PRICE_PLANE_DECIMALS),
            Some(1_000_000)
        );
        // step "0.001" whole-units → 100 lots at sz_decimals = 5.
        assert_eq!(decimal_to_scaled("0.001", 5), Some(100));
        // whole / half / zero.
        assert_eq!(decimal_to_scaled("0.5", 8), Some(50_000_000));
        assert_eq!(decimal_to_scaled("100", 8), Some(10_000_000_000));
        assert_eq!(decimal_to_scaled("0", 8), Some(0));
        assert_eq!(decimal_to_scaled("1", 0), Some(1));
        // truncate finer-than-scale fractional digits toward zero.
        assert_eq!(decimal_to_scaled("0.0009", 3), Some(0));
        assert_eq!(decimal_to_scaled("1.2345", 2), Some(123));
        // rejects.
        assert_eq!(decimal_to_scaled("-1", 8), None);
        assert_eq!(decimal_to_scaled("", 8), None);
        assert_eq!(decimal_to_scaled("1.2.3", 8), None);
        assert_eq!(decimal_to_scaled("abc", 8), None);
    }

    #[test]
    fn snaps_price_and_size_onto_the_grid() {
        // tick $0.01 (1e6 on the 1e8 plane); step 0.001 BTC (100 lots @ sz=5).
        let m = mkt("0.01", "0.001", "0.001", 5);
        // $66735.255 → 6_673_525_500_000 on the 1e8 plane; sub-tick digit dropped.
        let g = round_order_to_grid(&m, 6_673_525_500_000, 250).unwrap();
        assert_eq!(g.limit_px, 6_673_525_000_000); // $66735.25
        assert_eq!(g.size, 200); // floor(250 / 100) * 100
    }

    #[test]
    fn min_order_is_enforced_after_snapping() {
        let m = mkt("0.01", "0.001", "0.001", 5); // min = 100 lots
        // 50 lots floors to 0 of a 100-lot step → below the minimum.
        assert_eq!(
            round_order_to_grid(&m, 6_673_525_000_000, 50),
            Err(GridError::BelowMinOrder)
        );
    }

    #[test]
    fn price_rounds_toward_zero() {
        // tick $1 (1e8 on the price plane), sz_decimals 0, step/min = 1 lot.
        let m = mkt("1", "1", "1", 0);
        // 1.9999… ticks rounds DOWN to exactly one tick.
        let g = round_order_to_grid(&m, 199_999_999, 7).unwrap();
        assert_eq!(g.limit_px, 100_000_000); // $1.00
        assert_eq!(g.size, 7);
    }

    #[test]
    fn rejects_bad_grid_and_subtick_price() {
        // Non-positive tick → no price grid.
        assert_eq!(
            round_order_to_grid(&mkt("0", "0.001", "0.001", 5), 1_000_000, 100),
            Err(GridError::BadTick)
        );
        // Non-positive step → no size grid.
        assert_eq!(
            round_order_to_grid(&mkt("0.01", "0", "0", 5), 1_000_000, 100),
            Err(GridError::BadStep)
        );
        // Price below one tick rounds to zero.
        assert_eq!(
            round_order_to_grid(&mkt("0.01", "0.001", "0.001", 5), 999_999, 100),
            Err(GridError::PriceBelowTick)
        );
    }
}
