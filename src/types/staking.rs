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
    /// Lock tier in months — one of `0` (flexible), `1`, `6`, `24`. Ignored on
    /// undelegate. Defaults to `0`; omit it and existing flexible-stake callers
    /// keep working.
    #[serde(default)]
    pub lock_months: u8,
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

/// Action — move spot MTF into the free (undelegated) staking pool (`c_deposit`).
///
/// Sender-authorized. `amount` rides the wire as a decimal **string**.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CDeposit {
    /// Amount of MTF to move, as a decimal string.
    pub amount: String,
}

/// Action — move MTF from the free staking pool back to spot (`c_withdraw`).
///
/// Sender-authorized. `amount` rides the wire as a decimal **string**.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CWithdraw {
    /// Amount of MTF to move, as a decimal string.
    pub amount: String,
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
            lock_months: 0,
        };
        let j = serde_json::to_value(&a).unwrap();
        assert!(j["amount"].is_string());
        assert_eq!(j["is_undelegate"], serde_json::json!(false));
        assert_eq!(j["lock_months"], serde_json::json!(0));
        let dec: TokenDelegate = serde_json::from_value(j).unwrap();
        assert_eq!(a, dec);

        // `lock_months` is `#[serde(default)]`: a legacy payload without it
        // decodes as flexible (0).
        let legacy: TokenDelegate = serde_json::from_value(serde_json::json!({
            "validator": Address::ZERO,
            "amount": "100.5",
            "is_undelegate": false,
        }))
        .unwrap();
        assert_eq!(legacy.lock_months, 0);
    }

    #[test]
    fn claim_rewards_omits_none_validator() {
        let a = ClaimRewards { validator: None };
        let j = serde_json::to_value(a).unwrap();
        assert!(j.get("validator").is_none());
    }

    #[test]
    fn c_deposit_withdraw_amount_is_string() {
        let d = CDeposit {
            amount: "500".into(),
        };
        let jd = serde_json::to_value(&d).unwrap();
        assert_eq!(jd["amount"], serde_json::json!("500"));
        assert_eq!(serde_json::from_value::<CDeposit>(jd).unwrap(), d);

        let w = CWithdraw {
            amount: "500".into(),
        };
        let jw = serde_json::to_value(&w).unwrap();
        assert_eq!(jw["amount"], serde_json::json!("500"));
        assert_eq!(serde_json::from_value::<CWithdraw>(jw).unwrap(), w);
    }
}
