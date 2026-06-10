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

/// Kind of vault created by [`CreateVault`]. Serializes in PascalCase to match
/// the node's vault-kind enum (`"User"` / `"Metaliquidity"`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum VaultKind {
    /// A regular user-led vault.
    #[default]
    User,
    /// A metaliquidity-provider vault (operator-driven).
    Metaliquidity,
}

/// Action — create a new vault. The signing wallet becomes the leader.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CreateVault {
    /// Display name.
    pub name: String,
    /// Follower withdrawal lock period in seconds.
    pub lock_period_secs: u64,
    /// Optional parent vault id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<VaultId>,
    /// Vault kind (defaults to [`VaultKind::User`]).
    #[serde(default)]
    pub kind: VaultKind,
}

/// Action — leader moves capital into (`deposit = true`) or out of
/// (`deposit = false`) a vault. `amount` is a decimal USD string.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct VaultTransfer {
    /// Target vault id.
    pub vault_id: VaultId,
    /// `true` = deposit (leader → vault), `false` = withdraw (vault → leader).
    pub deposit: bool,
    /// Amount in USD as a decimal string.
    pub amount: String,
}

/// Action — leader updates vault configuration. A `None` field is unchanged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct VaultModify {
    /// Target vault id.
    pub vault_id: VaultId,
    /// New display name (`None` = unchanged).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_name: Option<String>,
    /// New lock period in seconds (`None` = unchanged).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_lock_period_secs: Option<u64>,
    /// New management fee in bps (`None` = unchanged).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_management_fee_bps: Option<u16>,
    /// New paused flag (`None` = unchanged).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_paused: Option<bool>,
}

/// Action — follower redeems shares from a vault.
///
/// Subject to the per-vault `withdrawal_lock_ms` cooldown. `shares` is a decimal
/// string.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct VaultWithdraw {
    /// Vault id.
    pub vault_id: VaultId,
    /// Shares to redeem, as a decimal string.
    pub shares: String,
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

    #[test]
    fn create_vault_defaults_kind_and_omits_parent() {
        let c = CreateVault {
            name: "mlp".into(),
            lock_period_secs: 604_800,
            parent: None,
            kind: VaultKind::default(),
        };
        let j = serde_json::to_value(&c).unwrap();
        assert!(j.get("parent").is_none());
        assert_eq!(j["kind"], serde_json::json!("User"));
        let c2 = CreateVault {
            kind: VaultKind::Metaliquidity,
            ..c
        };
        assert_eq!(
            serde_json::to_value(&c2).unwrap()["kind"],
            serde_json::json!("Metaliquidity")
        );
    }

    #[test]
    fn vault_withdraw_shares_is_string() {
        let w = VaultWithdraw {
            vault_id: VaultId(4),
            shares: "250".into(),
        };
        let j = serde_json::to_value(&w).unwrap();
        assert!(
            j["shares"].is_string(),
            "shares must be a decimal JSON string"
        );
        assert_eq!(w, serde_json::from_value(j).unwrap());
    }
}
