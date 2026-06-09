//! User-vault types.
//!
//! The `vault_state` endpoint returns one [`VaultState`] per vault id. Each
//! vault has a leader (controlling account), follower-supplied capital, and
//! a NAV computed by the L1 settlement loop.

use serde::{Deserialize, Serialize};

use crate::types::VaultId;
use crate::wallet::Address;

/// Snapshot of a user vault returned by `info: { type: "vault_state" }`.
///
/// Field shape matches the node's MTF-native `/info` `vault_state` response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct VaultState {
    /// Echo of the requested vault id.
    pub vault_id: VaultId,
    /// Leader account (20-byte address). Stored as `Address` (not `account_id`)
    /// since the SDK's user surface is keyed by address.
    pub leader: Address,
    /// Total share count across all followers.
    pub total_shares: u128,
    /// NAV in USD cents (signed — vaults can go negative on backstop takeovers).
    pub nav_usd_cents: i64,
    /// Whether the leader has paused the vault.
    pub paused: bool,
    /// Leader management fee in bps (protocol pins this to 1000 = 10%).
    pub management_fee_bps: u16,
    /// Follower withdrawal lock duration in milliseconds (4 days =
    /// 345_600_000 ms).
    pub withdrawal_lock_ms: u64,
    /// Vault creation timestamp.
    pub created_at_ms: u64,
    /// Distinct follower count.
    pub follower_count: u32,
}

/// Action — create a new user vault.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct VaultCreate {
    /// Leader address. Must match the signing wallet.
    pub leader: Address,
    /// Initial seed deposit in USD cents (must be ≥ minimum per §I-bis.1).
    pub seed_cents: u64,
    /// Initial management fee in bps; capped at 1000 (10%) per §I-bis.1.
    pub management_fee_bps: u16,
}

/// Action — distribute realised PnL to followers (leader-only).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct VaultDistribute {
    /// Vault id.
    pub vault_id: VaultId,
    /// Amount to distribute in USD cents.
    pub amount_cents: u64,
}

/// Action — follower withdraws from the vault.
///
/// Subject to the per-vault `withdrawal_lock_ms` cooldown.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct VaultWithdraw {
    /// Vault id.
    pub vault_id: VaultId,
    /// Number of shares to redeem.
    pub shares: u128,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_state_round_trips() {
        let v = VaultState {
            vault_id: VaultId(42),
            leader: Address::ZERO,
            total_shares: 1_000_000,
            nav_usd_cents: 5_000_000,
            paused: false,
            management_fee_bps: 1000,
            withdrawal_lock_ms: 345_600_000,
            created_at_ms: 1_700_000_000_000,
            follower_count: 5,
        };
        let j = serde_json::to_string(&v).unwrap();
        let dec: VaultState = serde_json::from_str(&j).unwrap();
        assert_eq!(v, dec);
    }

    #[test]
    fn vault_state_uses_snake_case_on_wire() {
        let v = VaultState {
            vault_id: VaultId(42),
            leader: Address::ZERO,
            total_shares: 0,
            nav_usd_cents: 0,
            paused: false,
            management_fee_bps: 1000,
            withdrawal_lock_ms: 345_600_000,
            created_at_ms: 0,
            follower_count: 0,
        };
        let j = serde_json::to_value(&v).unwrap();
        // No camelCase keys.
        for forbidden in [
            "vaultId",
            "navUsdCents",
            "managementFeeBps",
            "withdrawalLockMs",
            "createdAtMs",
            "followerCount",
            "totalShares",
        ] {
            assert!(j.get(forbidden).is_none(), "wire leak: {forbidden}");
        }
    }
}
