//! Client-side TWAP planning: a duration and a USD notional become the wire
//! fields `slice_count`, `delay_ms` and `total_size`.
//!
//! The wire carries no duration and no USD amount. A caller who thinks in "sell
//! this much, over this long" must derive the three wire fields itself, so this
//! module does it once, the same way in every MetaFlux client.
//!
//! ## The minimum-delay floor is the part callers get wrong
//!
//! The node clamps `delay_ms` UP to a governed minimum at registration
//! (`twap_min_delay_ms`, default 10_000 ms). The clamp is SILENT: the order is
//! accepted, and the parent then runs LONGER than the duration the caller typed.
//! No endpoint serves the live floor, so it arrives here as
//! [`TwapDurationRequest::min_delay_ms`]. [`twap_from_duration`] reports the
//! clamp in [`TwapPlan::clamped_to_min_delay`] and reports the run time the
//! chain will really take in [`TwapPlan::effective_duration_ms`]. Show the
//! caller that number, not the request.
//!
//! ## Plane bridge
//!
//! [`MarketMeta`] reports `mark_px` in whole USDC and `step_size` / `min_order`
//! in whole base units, both as canonical decimal strings. The wire `size` is
//! raw lots (`whole × 10^sz_decimals`). The USD amount and the mark are parsed
//! into the shared 1e8 integer plane, where the scale cancels, and only the lot
//! plane is left to multiply in. No floating point: a large notional keeps every
//! digit that `usd / mark` in an `f64` would drop.

use crate::grid::{GridError, decimal_to_scaled};
use crate::rest::info::MarketMeta;

/// The 1e8 fixed-point plane both the USD amount and the mark are parsed into.
const USD_PLANE_DECIMALS: u32 = 8;

/// Governed minimum inter-slice delay, node default (`twap_min_delay_ms`).
/// Governance can retune it, and no endpoint serves the live value — pass the
/// live one when you know it.
pub const DEFAULT_TWAP_MIN_DELAY_MS: u64 = 10_000;

/// Target cadence used to pick a slice count: one slice per 30 s of the window.
pub const DEFAULT_TWAP_TARGET_SLICE_MS: u64 = 30_000;

/// Slice-count ceiling this planner will derive. The node's own ceiling is
/// governed (`twap_max_slices`, default 10_000); this default stays well under
/// it so a governance retune downward does not start rejecting derived orders.
pub const DEFAULT_TWAP_MAX_SLICES: u32 = 1_000;

/// Inputs to [`twap_from_duration`].
///
/// [`Default`] fills the three tuning fields with the constants above, so a
/// caller usually sets only `duration_ms` and the sizing triple.
#[derive(Clone, Copy, Debug)]
pub struct TwapDurationRequest<'a> {
    /// Requested run time in milliseconds. The chain honours it only when the
    /// derived delay clears the floor — read [`TwapPlan::effective_duration_ms`]
    /// back.
    pub duration_ms: u64,
    /// Total USD notional to convert to a wire size. Needs `mark_px` and
    /// `market` too. `None` plans the schedule only.
    pub total_usd: Option<&'a str>,
    /// Live mark price, canonical decimal string from `/info` ("64250.5").
    pub mark_px: Option<&'a str>,
    /// Market the size is snapped against (`step_size`, `min_order`,
    /// `sz_decimals`).
    pub market: Option<&'a MarketMeta>,
    /// Governed minimum inter-slice delay in ms.
    pub min_delay_ms: u64,
    /// Slice-count ceiling.
    pub max_slices: u32,
    /// Target cadence in ms.
    pub target_slice_ms: u64,
}

impl Default for TwapDurationRequest<'_> {
    fn default() -> Self {
        Self {
            duration_ms: 0,
            total_usd: None,
            mark_px: None,
            market: None,
            min_delay_ms: DEFAULT_TWAP_MIN_DELAY_MS,
            max_slices: DEFAULT_TWAP_MAX_SLICES,
            target_slice_ms: DEFAULT_TWAP_TARGET_SLICE_MS,
        }
    }
}

/// A planned TWAP: the wire fields, plus what the chain will really do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TwapPlan {
    /// Wire `slice_count`.
    pub slice_count: u32,
    /// Wire `delay_ms`, already at or above the floor — the node will not move it.
    pub delay_ms: u64,
    /// Wire `total_size` in the market's lot plane. `Some` only when the sizing
    /// triple was supplied.
    pub total_size: Option<u64>,
    /// Nominal size of one slice, the node's own `remaining / remaining_slices`
    /// toward zero with a one-lot floor. The final slice takes the remainder.
    pub slice_size: Option<u64>,
    /// The floor raised `delay_ms` above the evenly-spread value. When true the
    /// requested duration is NOT honoured — the run takes `effective_duration_ms`.
    pub clamped_to_min_delay: bool,
    /// Run time the chain will really take: the first slice fires one `delay_ms`
    /// after registration and the last fires at `slice_count * delay_ms`.
    pub effective_duration_ms: u64,
    /// The duration that was asked for, echoed for display beside the effective one.
    pub requested_duration_ms: u64,
}

/// Why a TWAP cannot be planned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TwapPlanError {
    /// `duration_ms` was zero.
    ZeroDuration,
    /// `min_delay_ms` or `target_slice_ms` was zero, or `max_slices` was under 2.
    BadTuning,
    /// A USD notional was given without both `mark_px` and `market`.
    MissingConversionInput,
    /// `total_usd` was not a non-negative canonical decimal.
    BadUsd,
    /// `mark_px` was not a positive canonical decimal.
    BadMark,
    /// The converted size does not fit the market grid.
    Grid(GridError),
    /// The converted size does not fit a `u64` wire field.
    SizeOverflow,
}

impl core::fmt::Display for TwapPlanError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TwapPlanError::ZeroDuration => f.write_str("duration_ms must be positive"),
            TwapPlanError::BadTuning => f.write_str(
                "min_delay_ms and target_slice_ms must be positive, max_slices at least 2",
            ),
            TwapPlanError::MissingConversionInput => {
                f.write_str("total_usd needs both mark_px and market to convert to a size")
            }
            TwapPlanError::BadUsd => f.write_str("total_usd is not a non-negative decimal value"),
            TwapPlanError::BadMark => f.write_str("mark_px is not a positive decimal price"),
            TwapPlanError::Grid(e) => write!(f, "{e}"),
            TwapPlanError::SizeOverflow => f.write_str("converted size exceeds the u64 wire field"),
        }
    }
}

impl std::error::Error for TwapPlanError {}

impl From<GridError> for TwapPlanError {
    fn from(e: GridError) -> Self {
        TwapPlanError::Grid(e)
    }
}

/// Derive `slice_count` / `delay_ms` (and optionally `total_size`) from a
/// duration and a USD notional.
///
/// The schedule targets one slice per `target_slice_ms`, then spreads the
/// duration evenly over the slices. When that spacing falls under the governed
/// floor the planner sheds slices first — a slower cadence over the requested
/// window beats a window that silently overruns. Only a duration under two
/// floor-lengths cannot be honoured at all; that case sets
/// [`TwapPlan::clamped_to_min_delay`] and puts
/// [`TwapPlan::effective_duration_ms`] above `duration_ms`.
///
/// # Errors
/// [`TwapPlanError`] on a zero duration, degenerate tuning, an incomplete sizing
/// triple, an unparseable amount or mark, or a size off the market grid.
pub fn twap_from_duration(req: &TwapDurationRequest<'_>) -> Result<TwapPlan, TwapPlanError> {
    if req.duration_ms == 0 {
        return Err(TwapPlanError::ZeroDuration);
    }
    if req.min_delay_ms == 0 || req.target_slice_ms == 0 || req.max_slices < 2 {
        return Err(TwapPlanError::BadTuning);
    }

    let max = u64::from(req.max_slices);
    let mut slice_count = (req.duration_ms / req.target_slice_ms).clamp(2, max);
    let mut delay_ms = req.duration_ms / slice_count;
    if delay_ms < req.min_delay_ms {
        slice_count = (req.duration_ms / req.min_delay_ms).clamp(2, max);
        delay_ms = req.duration_ms / slice_count;
    }
    let clamped_to_min_delay = delay_ms < req.min_delay_ms;
    if clamped_to_min_delay {
        delay_ms = req.min_delay_ms;
    }

    let (total_size, slice_size) = match req.total_usd {
        None => (None, None),
        Some(usd) => {
            let (mark, market) = req
                .mark_px
                .zip(req.market)
                .ok_or(TwapPlanError::MissingConversionInput)?;
            let total = usd_to_wire_size(usd, mark, market)?;
            (Some(total), Some((total / slice_count).max(1)))
        }
    };

    Ok(TwapPlan {
        slice_count: u32::try_from(slice_count).unwrap_or(req.max_slices),
        delay_ms,
        total_size,
        slice_size,
        clamped_to_min_delay,
        effective_duration_ms: slice_count.saturating_mul(delay_ms),
        requested_duration_ms: req.duration_ms,
    })
}

/// Convert a USD notional to a wire `size` at the live mark, snapped onto the
/// market lot. Exact integer division toward zero — no floating point.
///
/// `total_usd` and `mark_px` are canonical decimal strings in whole USDC, the
/// form `/info` reports. The result is raw lots (`whole × 10^sz_decimals`), the
/// plane the order wire `size` rides.
///
/// # Errors
/// [`TwapPlanError`] on an unparseable amount, a non-positive mark, a market
/// with no size grid, or a snapped size below `min_order`.
pub fn usd_to_wire_size(
    total_usd: &str,
    mark_px: &str,
    market: &MarketMeta,
) -> Result<u64, TwapPlanError> {
    let usd = decimal_to_scaled(total_usd, USD_PLANE_DECIMALS).ok_or(TwapPlanError::BadUsd)?;
    let mark = decimal_to_scaled(mark_px, USD_PLANE_DECIMALS)
        .filter(|m| *m > 0)
        .ok_or(TwapPlanError::BadMark)?;
    let sz_scale = u32::from(market.sz_decimals);
    let lot_scale = 10u128
        .checked_pow(sz_scale)
        .ok_or(TwapPlanError::SizeOverflow)?;
    // Both sides ride the 1e8 plane, so the scale cancels and the lot plane is
    // all that is left to multiply in.
    let raw = usd
        .checked_mul(lot_scale)
        .ok_or(TwapPlanError::SizeOverflow)?
        / mark;

    let step_lots = decimal_to_scaled(&market.step_size, sz_scale)
        .filter(|s| *s > 0)
        .ok_or(GridError::BadStep)?;
    let min_lots = decimal_to_scaled(&market.min_order, sz_scale).unwrap_or(0);
    let sz = (raw / step_lots) * step_lots;
    if sz == 0 || sz < min_lots {
        return Err(GridError::BelowMinOrder.into());
    }
    u64::try_from(sz).map_err(|_| TwapPlanError::SizeOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rest::info::{Funding, MarketKind};

    fn mkt(step: &str, min: &str, sz_decimals: u8) -> MarketMeta {
        MarketMeta {
            coin: "BTC".into(),
            signing_id: 0,
            risk_override: None,
            kind: MarketKind::Perp,
            sz_decimals,
            mark_px: "0".into(),
            oracle_px: "0".into(),
            tick_size: "0.1".into(),
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
            open: Some(true),
            close: Some(true),
            strict_isolated: Some(false),
            oi_cap: None,
            halted: Some(false),
            mid_px: None,
            impact_pxs: None,
            px_stale: None,
            premium: None,
            prev_day_px: None,
            change_24h: None,
            day_ntl_vlm: None,
            day_ntl_vlm_lower_bound_from: None,
        }
    }

    fn plan(duration_ms: u64) -> TwapPlan {
        twap_from_duration(&TwapDurationRequest {
            duration_ms,
            ..Default::default()
        })
        .unwrap()
    }

    #[test]
    fn targets_one_slice_per_thirty_seconds() {
        let p = plan(30 * 60_000);
        assert_eq!(p.slice_count, 60);
        assert_eq!(p.delay_ms, 30_000);
        assert!(!p.clamped_to_min_delay);
        assert_eq!(p.effective_duration_ms, 30 * 60_000);
        assert_eq!(p.requested_duration_ms, 30 * 60_000);
    }

    #[test]
    fn never_derives_fewer_than_two_slices() {
        let p = plan(30_000);
        assert_eq!(p.slice_count, 2);
        assert_eq!(p.delay_ms, 15_000);
        assert!(!p.clamped_to_min_delay);
    }

    #[test]
    fn caps_the_slice_count_and_stretches_the_delay() {
        let p = plan(100 * 60 * 60_000);
        assert_eq!(p.slice_count, 1_000);
        assert_eq!(p.delay_ms, 360_000);
        assert_eq!(p.effective_duration_ms, 100 * 60 * 60_000);
    }

    #[test]
    fn sheds_slices_rather_than_overrun_when_the_floor_beats_the_cadence() {
        // A 5-minute window with a 60 s governed floor: 10 slices at 30 s would
        // be clamped up to 60 s each and run 10 minutes. Five slices fit.
        let p = twap_from_duration(&TwapDurationRequest {
            duration_ms: 5 * 60_000,
            min_delay_ms: 60_000,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(p.slice_count, 5);
        assert_eq!(p.delay_ms, 60_000);
        assert!(!p.clamped_to_min_delay);
        assert_eq!(p.effective_duration_ms, 5 * 60_000);
    }

    #[test]
    fn reports_the_clamp_and_the_longer_real_run_time() {
        let p = plan(15_000);
        assert!(p.clamped_to_min_delay);
        assert_eq!(p.delay_ms, DEFAULT_TWAP_MIN_DELAY_MS);
        assert_eq!(p.slice_count, 2);
        assert_eq!(p.requested_duration_ms, 15_000);
        assert_eq!(p.effective_duration_ms, 20_000);
        assert!(p.effective_duration_ms > p.requested_duration_ms);
    }

    #[test]
    fn every_plan_emits_a_delay_the_node_will_not_move() {
        for duration_ms in [1, 999, 15_000, 60_000, 3_600_000, 86_400_000] {
            let p = plan(duration_ms);
            // The node stamps `max(requested, floor)`, so a plan at or above the
            // floor survives registration unchanged.
            assert!(
                p.delay_ms >= DEFAULT_TWAP_MIN_DELAY_MS,
                "duration {duration_ms}"
            );
            assert_eq!(
                p.effective_duration_ms,
                u64::from(p.slice_count) * p.delay_ms,
                "duration {duration_ms}"
            );
        }
    }

    #[test]
    fn honours_a_governed_floor_passed_in_place_of_the_default() {
        let p = twap_from_duration(&TwapDurationRequest {
            duration_ms: 60_000,
            min_delay_ms: 120_000,
            ..Default::default()
        })
        .unwrap();
        assert!(p.clamped_to_min_delay);
        assert_eq!(p.delay_ms, 120_000);
        assert_eq!(p.effective_duration_ms, 240_000);
    }

    #[test]
    fn usd_divides_in_the_shared_plane_with_no_float() {
        let m = mkt("0.001", "0.001", 3);
        assert_eq!(usd_to_wire_size("64250", "64250", &m), Ok(1_000));
        assert_eq!(usd_to_wire_size("32125", "64250", &m), Ok(500));
        assert_eq!(usd_to_wire_size("0.3", "1", &m), Ok(300));
    }

    #[test]
    fn usd_keeps_precision_an_f64_would_lose() {
        let m = mkt("0.00000001", "0.00000001", 8);
        let got = usd_to_wire_size("123456789.12345678", "1.00000001", &m).unwrap();
        let want = (12_345_678_912_345_678u128 * 100_000_000) / 100_000_001;
        assert_eq!(u128::from(got), want);
    }

    #[test]
    fn usd_snaps_toward_zero_onto_the_lot() {
        let m = mkt("0.001", "0.001", 3);
        assert_eq!(usd_to_wire_size("1.9999", "1", &m), Ok(1_999));
    }

    #[test]
    fn usd_rejects_a_dead_mark_and_a_below_minimum_size() {
        let m = mkt("0.001", "0.001", 3);
        assert_eq!(
            usd_to_wire_size("100", "0", &m),
            Err(TwapPlanError::BadMark)
        );
        assert_eq!(
            usd_to_wire_size("0.0001", "1", &m),
            Err(TwapPlanError::Grid(GridError::BelowMinOrder))
        );
        assert_eq!(usd_to_wire_size("-1", "1", &m), Err(TwapPlanError::BadUsd));
    }

    #[test]
    fn sizing_rides_alongside_the_schedule() {
        let m = mkt("0.001", "0.001", 3);
        let p = twap_from_duration(&TwapDurationRequest {
            duration_ms: 30 * 60_000,
            total_usd: Some("64250"),
            mark_px: Some("64250"),
            market: Some(&m),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(p.total_size, Some(1_000));
        assert_eq!(p.slice_count, 60);
        // The node fires `remaining / remaining_slices` toward zero; 1000/60 = 16.
        assert_eq!(p.slice_size, Some(16));
    }

    #[test]
    fn nominal_slice_floors_at_one_lot_like_the_node() {
        let m = mkt("0.001", "0", 3);
        let p = twap_from_duration(&TwapDurationRequest {
            duration_ms: 30 * 60_000,
            total_usd: Some("0.01"),
            mark_px: Some("1"),
            market: Some(&m),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(p.total_size, Some(10));
        assert_eq!(p.slice_size, Some(1));
    }

    #[test]
    fn rejects_degenerate_inputs() {
        let m = mkt("0.001", "0.001", 3);
        assert_eq!(
            twap_from_duration(&TwapDurationRequest::default()),
            Err(TwapPlanError::ZeroDuration)
        );
        assert_eq!(
            twap_from_duration(&TwapDurationRequest {
                duration_ms: 60_000,
                max_slices: 1,
                ..Default::default()
            }),
            Err(TwapPlanError::BadTuning)
        );
        assert_eq!(
            twap_from_duration(&TwapDurationRequest {
                duration_ms: 60_000,
                min_delay_ms: 0,
                ..Default::default()
            }),
            Err(TwapPlanError::BadTuning)
        );
        assert_eq!(
            twap_from_duration(&TwapDurationRequest {
                duration_ms: 60_000,
                total_usd: Some("100"),
                ..Default::default()
            }),
            Err(TwapPlanError::MissingConversionInput)
        );
        assert_eq!(
            twap_from_duration(&TwapDurationRequest {
                duration_ms: 60_000,
                total_usd: Some("100"),
                mark_px: Some("1"),
                market: Some(&m),
                ..Default::default()
            })
            .map(|p| p.total_size),
            Ok(Some(100_000))
        );
    }
}
