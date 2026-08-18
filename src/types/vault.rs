//! User-vault types.
//!
//! The `vault_state` endpoint returns one [`VaultState`] per vault ADDRESS. Each
//! vault has a leader (controlling account), follower-supplied capital, and
//! a NAV computed by the L1 settlement loop.

use serde::{Deserialize, Serialize};

use crate::types::VaultId;
use crate::wallet::Address;

/// Snapshot of a user vault returned by `info: { type: "vault_state" }`.
///
/// The request key is the vault ADDRESS (`vault`), not a numeric id.
///
/// # Value planes
/// `tvl`, `share_price` and `high_water_mark` are HUMAN whole-USDC decimal
/// strings, NOT cents and NOT raw-share plane. `share_price` is whole USDC per
/// WHOLE share at full precision — do not scale it by the share scale, that
/// double-scales the value by 1e18.
///
/// `lock_period_ms` keeps its `_ms` suffix because it is a DURATION, not a
/// timestamp.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct VaultState {
    /// Vault address (`0x`-hex).
    pub vault: String,
    /// Vault display name.
    pub name: String,
    /// Total value locked, whole-USDC decimal string.
    pub tvl: String,
    /// Price of one WHOLE share, whole-USDC decimal string, full precision.
    pub share_price: String,
    /// Distinct depositor count.
    pub depositor_count: u64,
    /// High-water mark, whole-USDC decimal string.
    pub high_water_mark: String,
    /// Leader performance fee in bps.
    pub performance_fee_bps: u16,
    /// Follower withdrawal lock DURATION in milliseconds.
    pub lock_period_ms: u64,
    /// Vault strategy class (`"User"` / `"Metaliquidity"`).
    pub strategy: String,
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

/// Action — `vault_distribute`: a follower deposits USD into a vault and
/// receives shares at the current NAV (subject to the per-vault withdrawal
/// lock).
///
/// Mirrors the node's `core_state` `VaultDistributeParams`. The action envelope
/// wraps this under the key **`params`**.
///
/// **Trap:** the deposit-amount field is named **`pnl`** (a legacy name on the
/// node), not `amount`/`deposit`. It is a positive USD amount encoded as a
/// decimal string (the SDK's `Decimal`-on-the-wire convention, matching
/// `vault_transfer` / `vault_withdraw`).
///
/// Forward-compat: the node currently answers this tag with `UnsupportedAction`
/// on the public `/exchange` path; the SDK emits the byte-correct shape the
/// core handler will accept once the bridge lands.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct VaultDistribute {
    /// Target vault id (serializes as a bare JSON number).
    pub vault_id: VaultId,
    /// Deposit amount in USD as a positive decimal string. Node field name is
    /// `pnl` (legacy) — do NOT rename.
    pub pnl: String,
}

/// Grant or revoke an operator on a vault the sender leads.
///
/// Sender-authorized: the recovered signer must be the vault leader. An
/// approved operator then acts AS the vault on the order and position lanes,
/// which carry the vault address as their `owner`.
///
/// `expires_at_ms` is a TIMESTAMP (ms since epoch), not a duration. `0` never
/// expires. Revoking (`allowed = false`) ignores it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RegisterMetaliquidityOperator {
    /// Vault id the operator acts for (serializes as a bare JSON number).
    pub vault_id: VaultId,
    /// Operator address.
    pub operator: Address,
    /// `true` grants, `false` revokes.
    pub allowed: bool,
    /// Grant expiry (ms since epoch). `0` = never expires.
    pub expires_at_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_distribute_emits_pnl_string_and_numeric_vault_id() {
        let d = VaultDistribute {
            vault_id: VaultId(42),
            pnl: "1000.5".into(),
        };
        let j = serde_json::to_value(&d).unwrap();
        assert_eq!(j["vault_id"], 42);
        assert_eq!(j["pnl"], "1000.5");
        assert!(j["pnl"].is_string());
        let dec: VaultDistribute = serde_json::from_value(j).unwrap();
        assert_eq!(dec, d);
    }

    #[test]
    fn register_operator_emits_hex_operator_and_numeric_ids() {
        let r = RegisterMetaliquidityOperator {
            vault_id: VaultId(42),
            operator: Address::from_hex("0x7070707070707070707070707070707070707070").unwrap(),
            allowed: true,
            expires_at_ms: 1_700_000_000_000,
        };
        let j = serde_json::to_value(r).unwrap();
        assert_eq!(j["vault_id"], 42);
        assert_eq!(j["operator"], "0x7070707070707070707070707070707070707070");
        assert_eq!(j["expires_at_ms"], 1_700_000_000_000u64);
        assert!(j.get("expiresAtMs").is_none(), "no camelCase leak");
        let dec: RegisterMetaliquidityOperator = serde_json::from_value(j).unwrap();
        assert_eq!(dec, r);
    }

    fn sample_vault_state() -> VaultState {
        VaultState {
            vault: "0x00000000000000000000000000000000000000aa".into(),
            name: "mlp".into(),
            tvl: "50000".into(),
            share_price: "1.000000000000000001".into(),
            depositor_count: 5,
            high_water_mark: "50000".into(),
            performance_fee_bps: 1000,
            lock_period_ms: 345_600_000,
            strategy: "Metaliquidity".into(),
        }
    }

    #[test]
    fn vault_state_round_trips() {
        let v = sample_vault_state();
        let j = serde_json::to_string(&v).unwrap();
        let dec: VaultState = serde_json::from_str(&j).unwrap();
        assert_eq!(v, dec);
    }

    #[test]
    fn vault_state_decodes_the_node_wire_shape() {
        let wire = serde_json::json!({
            "vault": "0x00000000000000000000000000000000000000aa",
            "name": "mlp",
            "tvl": "50000",
            "share_price": "1.000000000000000001",
            "depositor_count": 5,
            "high_water_mark": "50000",
            "performance_fee_bps": 1000,
            "lock_period_ms": 345_600_000u64,
            "strategy": "Metaliquidity"
        });
        let v: VaultState = serde_json::from_value(wire).unwrap();
        assert_eq!(v, sample_vault_state());
        // share_price is whole USDC per WHOLE share — a client that scales it by
        // the 1e18 share scale reads 1e18x high.
        assert_eq!(v.share_price, "1.000000000000000001");
    }

    #[test]
    fn vault_state_uses_snake_case_on_wire() {
        let j = serde_json::to_value(sample_vault_state()).unwrap();
        // No camelCase keys, and no retired cents-plane keys.
        for forbidden in [
            "vaultId",
            "vault_id",
            "navUsdCents",
            "nav_usd_cents",
            "sharePrice",
            "highWaterMark",
            "performanceFeeBps",
            "lockPeriodMs",
            "depositorCount",
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
