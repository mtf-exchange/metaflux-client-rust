//! Open position snapshot per user × market.
//!
//! Returned by `user_state(addr)`. Wire shape matches the MTF-native
//! `position` element under the user-state document.

use serde::{Deserialize, Serialize};

use crate::types::MarketId;
use crate::wallet::Address;

/// A signed open position. Negative size = short.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Position {
    /// 20-byte EVM owner.
    pub owner: Address,
    /// Market identifier.
    pub market: MarketId,
    /// Signed size in fixed-point tick units (i64). Positive = long.
    pub size: i64,
    /// Volume-weighted average entry price (u64 tick units).
    pub entry_px: u64,
    /// Unrealised PnL in USD cents (signed).
    pub unrealised_pnl_cents: i64,
    /// Margin posted for this position in USD cents (unsigned).
    pub margin_cents: u64,
    /// Funding paid (positive) / received (negative) over position lifetime,
    /// in USD cents.
    pub funding_paid_cents: i64,
}

/// Top-level user state response from `info: { type: "user_state" }`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct UserState {
    /// Echo of the requested account address.
    pub address: Address,
    /// Aggregate margin metrics in USD cents.
    pub account_value_cents: i64,
    /// Aggregate unrealised PnL in USD cents.
    pub total_unrealised_pnl_cents: i64,
    /// Number of open positions.
    pub position_count: u32,
    /// All open positions for this user.
    pub positions: Vec<Position>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn position_serializes_snake_case() {
        let p = Position {
            owner: Address::ZERO,
            market: MarketId(1),
            size: -500,
            entry_px: 4_999_500_000_000,
            unrealised_pnl_cents: 1234,
            margin_cents: 500_000,
            funding_paid_cents: -42,
        };
        let j = serde_json::to_value(&p).unwrap();
        for key in [
            "entry_px",
            "unrealised_pnl_cents",
            "margin_cents",
            "funding_paid_cents",
        ] {
            assert!(j.get(key).is_some(), "missing snake_case key {key}");
        }
    }

    #[test]
    fn user_state_serializes_account_value_as_cents() {
        let u = UserState {
            address: Address::ZERO,
            account_value_cents: 10_000_000, // 100_000 USD
            total_unrealised_pnl_cents: -2_500,
            position_count: 0,
            positions: vec![],
        };
        let j = serde_json::to_value(&u).unwrap();
        assert_eq!(j["account_value_cents"], 10_000_000);
    }
}
