//! `/info` — fee credit an account has accrued, and the grants that create it.
//!
//! Four public reads: [`Info::referral_state`], [`Info::builder_state`],
//! [`Info::delegator_rewards`] and [`Info::approved_builders`].
//!
//! ## Read the credit BEFORE you claim it
//!
//! `claim_referral_rewards` and `claim_builder_rewards` drain the whole balance
//! and report no amount back. The claim response therefore cannot tell a caller
//! what it just collected, and a claim on an empty balance looks the same as a
//! claim on a full one. Read [`Info::referral_state`] or [`Info::builder_state`]
//! first: that is the only place the claimable figure is published.

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::error::ClientError;
use crate::rest::info::Info;
use crate::wallet::Address;

/// `referral_state` — one account's referral position.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ReferralState {
    /// The queried account, `0x` hex.
    pub user: String,
    /// Referral fee credit this account can claim now, whole-USDC decimal
    /// string. `"0"` means a claim would collect nothing.
    pub claimable_rewards: String,
    /// The referrer this account bound with `set_referrer`. `None` when the
    /// account never bound one — MTF's referral graph is one-directional, so
    /// this read can never list the accounts a REFERRER has referred.
    #[serde(default)]
    pub referrer: Option<String>,
}

/// `builder_state` — one broker's accrued broker-code fee credit.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct BuilderState {
    /// The queried account, `0x` hex.
    pub user: String,
    /// Broker fee credit this account can claim now, whole-USDC decimal string.
    pub claimable_rewards: String,
}

/// One validator row of [`DelegatorRewards`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DelegatorRewardRow {
    /// Validator this delegation sits with, `0x` hex.
    pub validator: String,
    /// Reward accrued against this delegation and not yet claimed, decimal
    /// string.
    pub unclaimed: String,
    /// Consensus ms of this delegation's last claim.
    pub last_claim_time: u64,
}

/// `delegator_rewards` — staking reward accruals for one delegator.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DelegatorRewards {
    /// The queried account, `0x` hex.
    pub address: String,
    /// What a claim-all would collect: the sum of every [`rows`](Self::rewards)
    /// `unclaimed` PLUS a pre-migration roll-up bucket that has no row of its
    /// own. Summing the rows therefore UNDER-reports the total — use this field.
    pub claimable_rewards: String,
    /// One row per delegation, ascending by validator address.
    #[serde(default)]
    pub rewards: Vec<DelegatorRewardRow>,
}

/// One broker grant from [`ApprovedBuilders`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ApprovedBuilder {
    /// The approved broker, `0x` hex.
    pub builder: String,
    /// The ceiling this account granted the broker, whole-bps decimal string.
    /// An order carrying a higher `builder_fee` is rejected — this is the same
    /// committed value the fee gate enforces.
    pub max_fee_bps: String,
}

/// `approved_builders` — every broker-fee grant an account has approved.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ApprovedBuilders {
    /// The queried account, `0x` hex.
    pub address: String,
    /// One row per approved broker, ascending by broker address. Empty when the
    /// account has approved none.
    #[serde(default)]
    pub builders: Vec<ApprovedBuilder>,
}

impl Info<'_> {
    /// Read an account's referral credit and bound referrer (`referral_state`).
    ///
    /// Call this before `claim_referral_rewards`: the claim reports no amount.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn referral_state(&self, user: Address) -> Result<ReferralState, ClientError> {
        self.client
            .post_json("/info", &json!({ "type": "referral_state", "user": user }))
            .await
    }

    /// Read a broker's accrued broker-code fee credit (`builder_state`).
    ///
    /// Call this before `claim_builder_rewards`: the claim reports no amount.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn builder_state(&self, user: Address) -> Result<BuilderState, ClientError> {
        self.client
            .post_json("/info", &json!({ "type": "builder_state", "user": user }))
            .await
    }

    /// Read a delegator's per-validator staking reward accruals
    /// (`delegator_rewards`).
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn delegator_rewards(&self, addr: Address) -> Result<DelegatorRewards, ClientError> {
        self.client
            .post_json(
                "/info",
                &json!({ "type": "delegator_rewards", "address": addr }),
            )
            .await
    }

    /// Read the broker-fee grants an account has approved (`approved_builders`).
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn approved_builders(&self, addr: Address) -> Result<ApprovedBuilders, ClientError> {
        self.client
            .post_json(
                "/info",
                &json!({ "type": "approved_builders", "address": addr }),
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn referral_state_decodes_and_an_unbound_referrer_is_none() {
        let bound: ReferralState = serde_json::from_str(
            r#"{"user":"0x00000000000000000000000000000000000000aa",
                "claimable_rewards":"12.5",
                "referrer":"0x00000000000000000000000000000000000000bb"}"#,
        )
        .expect("decode bound");
        assert_eq!(bound.claimable_rewards, "12.5");
        assert!(bound.referrer.is_some());

        let unbound: ReferralState = serde_json::from_str(
            r#"{"user":"0x00000000000000000000000000000000000000aa",
                "claimable_rewards":"0","referrer":null}"#,
        )
        .expect("decode unbound");
        assert_eq!(unbound.referrer, None);
    }

    #[test]
    fn builder_state_decodes() {
        let b: BuilderState = serde_json::from_str(
            r#"{"user":"0x00000000000000000000000000000000000000aa",
                "claimable_rewards":"3.25"}"#,
        )
        .expect("decode");
        assert_eq!(b.claimable_rewards, "3.25");
    }

    /// The roll-up bucket has no row, so the total is not the row sum. A caller
    /// that adds the rows up sees less than a claim-all would pay.
    #[test]
    fn delegator_rewards_total_exceeds_the_row_sum() {
        let d: DelegatorRewards = serde_json::from_str(
            r#"{"address":"0x00000000000000000000000000000000000000aa",
                "claimable_rewards":"7",
                "rewards":[
                  {"validator":"0x00000000000000000000000000000000000000b1",
                   "unclaimed":"2","last_claim_time":1700000000000},
                  {"validator":"0x00000000000000000000000000000000000000b2",
                   "unclaimed":"1","last_claim_time":0}]}"#,
        )
        .expect("decode");
        assert_eq!(d.rewards.len(), 2);
        assert_eq!(d.claimable_rewards, "7");
        assert_eq!(d.rewards[0].last_claim_time, 1_700_000_000_000);
    }

    #[test]
    fn approved_builders_decodes_and_empty_is_no_grant() {
        let a: ApprovedBuilders = serde_json::from_str(
            r#"{"address":"0x00000000000000000000000000000000000000aa",
                "builders":[{"builder":"0x00000000000000000000000000000000000000cc",
                             "max_fee_bps":"25"}]}"#,
        )
        .expect("decode");
        assert_eq!(a.builders[0].max_fee_bps, "25");

        let none: ApprovedBuilders = serde_json::from_str(
            r#"{"address":"0x00000000000000000000000000000000000000aa","builders":[]}"#,
        )
        .expect("decode empty");
        assert!(none.builders.is_empty());
    }
}
