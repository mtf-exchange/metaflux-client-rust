//! Governance / operator actions.
//!
//! Sender-authorized, with action-level authorization enforced by the node at
//! dispatch: [`SetMetaliquidityWhitelist`] requires validator membership, and
//! [`RegisterMetaliquidityOperator`] requires the signer to be the vault leader.

use serde::{Deserialize, Serialize};

use crate::types::VaultId;
use crate::wallet::Address;

/// Action — set a metaliquidity-provider whitelist membership (validator vote).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SetMetaliquidityWhitelist {
    /// Address whose membership is being set.
    pub address: Address,
    /// `true` adds to the whitelist, `false` removes.
    pub allowed: bool,
}

/// Action — register or revoke an external strategy operator for a vault.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RegisterMetaliquidityOperator {
    /// Target vault id.
    pub vault_id: VaultId,
    /// Operator address.
    pub operator: Address,
    /// `true` registers, `false` revokes.
    pub allowed: bool,
    /// Optional expiry (unix ms). `None` never expires.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whitelist_round_trips() {
        let a = SetMetaliquidityWhitelist {
            address: Address::ZERO,
            allowed: true,
        };
        let j = serde_json::to_string(&a).unwrap();
        assert_eq!(
            serde_json::from_str::<SetMetaliquidityWhitelist>(&j).unwrap(),
            a
        );
    }

    #[test]
    fn register_operator_omits_none_expiry() {
        let a = RegisterMetaliquidityOperator {
            vault_id: VaultId(4),
            operator: Address::ZERO,
            allowed: true,
            expires_at_ms: None,
        };
        let j = serde_json::to_value(&a).unwrap();
        assert!(j.get("expires_at_ms").is_none());
        assert_eq!(j["vault_id"], serde_json::json!(4));
    }
}
