//! Staking actions — delegate / undelegate, claim rewards, link a staking user.
//!
//! All sender-authorized (the recovered signer is the staking account).
//! `amount` rides the wire as a decimal **string**.

use serde::{Deserialize, Serialize};

use crate::wallet::Address;

/// Action — delegate stake to a validator, or queue an undelegation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TokenDelegate {
    /// Validator address.
    pub validator: Address,
    /// Stake amount as a decimal string.
    pub amount: String,
    /// `true` = unstake / queue undelegation; `false` = delegate.
    pub is_undelegate: bool,
}

/// Action — claim accrued staking rewards.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ClaimRewards {
    /// Validator to claim from. `None` claims across all delegations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validator: Option<Address>,
}

/// Action — alias another account as this account's staking target.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct LinkStakingUser {
    /// Staking target address.
    pub target: Address,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_delegate_amount_is_string() {
        let a = TokenDelegate {
            validator: Address::ZERO,
            amount: "100.5".into(),
            is_undelegate: false,
        };
        let j = serde_json::to_value(&a).unwrap();
        assert!(j["amount"].is_string());
        assert_eq!(j["is_undelegate"], serde_json::json!(false));
        let dec: TokenDelegate = serde_json::from_value(j).unwrap();
        assert_eq!(a, dec);
    }

    #[test]
    fn claim_rewards_omits_none_validator() {
        let a = ClaimRewards { validator: None };
        let j = serde_json::to_value(a).unwrap();
        assert!(j.get("validator").is_none());
    }
}
