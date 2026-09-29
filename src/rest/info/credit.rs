//! `/info` — fee credit an account has accrued, and the grants that create it.
//!
//! Seven public reads: [`Info::referral_state`], [`Info::referral_code`],
//! [`Info::referral_referees`], [`Info::referral_leaderboard`],
//! [`Info::builder_state`], [`Info::delegator_rewards`] and
//! [`Info::approved_builders`].
//!
//! ## Read the credit BEFORE you claim it
//!
//! `claim_referral_rewards` and `claim_broker_rewards` drain the whole balance
//! and report no amount back. The claim response therefore cannot tell a caller
//! what it just collected, and a claim on an empty balance looks the same as a
//! claim on a full one. Read [`Info::referral_state`] and [`Info::builder_state`]
//! first: that is the only place the claimable figure is published.
//!
//! From the next node release, either claim drains BOTH credits, so the
//! claimable figure is the sum of the two `claimable_rewards`. A live node still
//! drains only the credit that matches the action.

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::error::ClientError;
use crate::rest::info::Info;
use crate::wallet::Address;

/// `referral_state` — one account's referral position, as referee and as
/// referrer.
///
/// The fields after `referrer` are absent from a node before the release that
/// ships referral codes, so they decode as `None` there.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ReferralState {
    /// The queried account, `0x` hex.
    pub user: String,
    /// The queried account, `0x` hex. Same value as `user`.
    #[serde(default)]
    pub address: Option<String>,
    /// Referral fee credit this account can claim now, whole-USDC decimal
    /// string. `"0"` means a claim would collect nothing.
    pub claimable_rewards: String,
    /// The referrer this account is bound to. `None` when unbound. A binding
    /// is permanent.
    #[serde(default)]
    pub referrer: Option<String>,
    /// The referral code of the bound referrer. `None` when unbound or when
    /// the referrer holds no code.
    #[serde(default)]
    pub referrer_code: Option<String>,
    /// This account's own referral code. `None` when it holds none.
    #[serde(default)]
    pub code: Option<String>,
    /// This account's position as a referee. `None` when unbound.
    #[serde(default)]
    pub referee: Option<ReferralRefereeState>,
    /// This account's totals as a referrer.
    #[serde(default)]
    pub referrer_stats: Option<ReferrerStats>,
    /// Whether this account can register a referral code now.
    #[serde(default)]
    pub code_requirement: Option<ReferralCodeRequirement>,
}

/// [`ReferralState::referee`] — the counters since this account bound its
/// referrer. USDC values are whole-USDC decimal strings.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ReferralRefereeState {
    /// Consensus ms of the binding. `0` for a binding made before the release
    /// that ships referral codes; its counters start at zero.
    pub bound_ms: u64,
    /// Taker notional traded since the binding.
    pub volume_since_bind: String,
    /// Taker fees paid since the binding.
    pub fees_paid: String,
    /// Referrer share earned from this account's fees.
    pub rewarded: String,
    /// The referee taker discount that applies now, in permille. `0` when the
    /// discount is off or its volume cap is reached. The fee path takes the
    /// larger of this and the staking discount, never the sum.
    pub discount_permille: u32,
    /// Volume left before the discount stops. `None` when the discount has no
    /// cap.
    #[serde(default)]
    pub discount_volume_remaining: Option<String>,
    /// Volume left before the referrer share stops. `None` when the share has
    /// no cap.
    #[serde(default)]
    pub share_volume_remaining: Option<String>,
}

/// [`ReferralState::referrer_stats`] — totals over every referee of one
/// referrer. USDC values are whole-USDC decimal strings.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ReferrerStats {
    /// Number of accounts bound to this referrer.
    pub referee_count: u64,
    /// Taker fees the referees paid.
    pub referred_fees: String,
    /// Referrer share earned in total.
    pub rewarded: String,
    /// Referrer share claimed in total.
    pub claimed: String,
}

/// [`ReferralState::code_requirement`] — the gate on `register_referral_code`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ReferralCodeRequirement {
    /// `false` when the code program is off and registration is refused.
    pub enabled: bool,
    /// 30-day volume a registration needs, whole-USDC decimal string.
    pub min_volume_30d: String,
    /// This account's 30-day volume, whole-USDC decimal string.
    pub volume_30d: String,
    /// `true` when the program is on and the volume meets the minimum.
    pub eligible: bool,
}

/// `referral_code` — the owner of one referral code.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ReferralCode {
    /// The queried code.
    pub code: String,
    /// The account that holds the code, `0x` hex. `None` when the code is
    /// unknown or malformed.
    #[serde(default)]
    pub owner: Option<String>,
}

/// One row of [`ReferralReferees`]. USDC values are whole-USDC decimal strings.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RefereeRow {
    /// The referee, `0x` hex.
    pub user: String,
    /// Consensus ms of the binding. `0` for a binding made before the release
    /// that ships referral codes.
    pub bound_ms: u64,
    /// Taker notional traded since the binding.
    pub volume_since_bind: String,
    /// Taker fees paid since the binding.
    pub fees_paid: String,
    /// Referrer share earned from this referee.
    pub rewarded: String,
}

/// `referral_referees` — the accounts bound to one referrer.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ReferralReferees {
    /// The queried referrer, `0x` hex.
    pub address: String,
    /// Sorted by `rewarded` descending, then `user` ascending.
    #[serde(default)]
    pub referees: Vec<RefereeRow>,
}

/// One row of [`ReferralLeaderboard`]. USDC values are whole-USDC decimal
/// strings.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ReferralLeaderboardRow {
    /// The referrer, `0x` hex.
    pub address: String,
    /// The referrer's code. `None` when it holds none.
    #[serde(default)]
    pub code: Option<String>,
    /// Number of accounts bound to this referrer.
    pub referee_count: u64,
    /// Taker fees the referees paid.
    pub referred_fees: String,
    /// Referrer share earned in total.
    pub rewarded: String,
    /// Referrer share claimed in total.
    pub claimed: String,
}

/// `referral_leaderboard` — referrers ranked by reward.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ReferralLeaderboard {
    /// Sorted by `rewarded` descending, `referee_count` descending, then
    /// `address` ascending.
    #[serde(default)]
    pub rows: Vec<ReferralLeaderboardRow>,
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

    /// Read the owner of a referral code (`referral_code`).
    ///
    /// An unknown or malformed code answers `owner: None`, not an error.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn referral_code(&self, code: &str) -> Result<ReferralCode, ClientError> {
        self.client
            .post_json("/info", &json!({ "type": "referral_code", "code": code }))
            .await
    }

    /// Read the accounts bound to a referrer (`referral_referees`).
    ///
    /// `limit` defaults to 100 on the node; the node caps it at 500.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn referral_referees(
        &self,
        addr: Address,
        limit: Option<u32>,
    ) -> Result<ReferralReferees, ClientError> {
        let mut body = json!({ "type": "referral_referees", "address": addr });
        if let Some(limit) = limit {
            body["limit"] = json!(limit);
        }
        self.client.post_json("/info", &body).await
    }

    /// Read the referrer leaderboard (`referral_leaderboard`).
    ///
    /// `limit` defaults to 50 on the node; the node caps it at 200.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn referral_leaderboard(
        &self,
        limit: Option<u32>,
    ) -> Result<ReferralLeaderboard, ClientError> {
        let mut body = json!({ "type": "referral_leaderboard" });
        if let Some(limit) = limit {
            body["limit"] = json!(limit);
        }
        self.client.post_json("/info", &body).await
    }

    /// Read a broker's accrued broker-code fee credit (`builder_state`).
    ///
    /// Call this before `claim_broker_rewards`: the claim reports no amount.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn builder_state(&self, user: Address) -> Result<BuilderState, ClientError> {
        self.client
            .post_json("/info", &json!({ "type": "broker_state", "address": user }))
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
                &json!({ "type": "approved_brokers", "address": addr }),
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
