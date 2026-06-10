//! Portfolio margin (PM) — SPAN-like cross-asset margin read types.
//!
//! Under portfolio margin the maintenance requirement is computed against a
//! scenario grid (price ± N steps, vol ± M steps) and netted across all
//! positions, rather than summed per position. Enroll / unenroll via the
//! `user_portfolio_margin` action; this module models the state read back over
//! `/info`.

use serde::{Deserialize, Serialize};

use crate::wallet::Address;

/// PM state snapshot returned over `/info` for a user.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PmState {
    /// User address.
    pub user: Address,
    /// Enrolment timestamp (unix ms; 0 if not enrolled).
    pub enrolled_at_ms: u64,
    /// Scenario-grid version at last computation (bumps when admin updates
    /// dynamic risk parameters).
    pub scenarios_grid_version: u32,
    /// Last-computed maintenance margin in USD cents (fixed-point).
    pub last_margin_cents: i64,
    /// Currently eligible (account net ≥ $100K USDC).
    pub eligible: bool,
    /// Concentration penalty in bps applied at last rebalance.
    pub last_concentration_penalty_bps: u16,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pm_state_round_trips() {
        let s = PmState {
            user: Address::ZERO,
            enrolled_at_ms: 1_700_000_000_000,
            scenarios_grid_version: 3,
            last_margin_cents: 1_234_567,
            eligible: true,
            last_concentration_penalty_bps: 250,
        };
        let j = serde_json::to_string(&s).unwrap();
        let dec: PmState = serde_json::from_str(&j).unwrap();
        assert_eq!(s, dec);
    }

    #[test]
    fn pm_state_uses_snake_case() {
        let s = PmState {
            user: Address::ZERO,
            enrolled_at_ms: 0,
            scenarios_grid_version: 1,
            last_margin_cents: 0,
            eligible: false,
            last_concentration_penalty_bps: 0,
        };
        let j = serde_json::to_value(&s).unwrap();
        for key in [
            "enrolled_at_ms",
            "scenarios_grid_version",
            "last_margin_cents",
            "last_concentration_penalty_bps",
        ] {
            assert!(j.get(key).is_some(), "missing {key}");
        }
    }
}
