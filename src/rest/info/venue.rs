//! `/info` — venue, validator and deploy-auction reads.
//!
//! Public reads: [`Info::exchange_status`], [`Info::vault_summaries`],
//! [`Info::user_rate_limit`], [`Info::perp_dexs`],
//! [`Info::validator_summaries`], [`Info::validator_l1_votes`],
//! [`Info::mip3_active_bids`], [`Info::spot_deploy_auction`] and
//! [`Info::user_twaps`].

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::error::ClientError;
use crate::rest::info::Info;
use crate::wallet::Address;

/// `exchange_status` — whether the venue accepts trade right now.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ExchangeStatus {
    /// Spot trading is off.
    pub spot_disabled: bool,
    /// Only post-only orders are accepted.
    pub post_only: bool,
    /// Permissionless market deploy is live.
    pub mip3_enabled: bool,
    /// An upgrade freeze is PENDING — the chain halts at a height it has not
    /// reached yet. It goes false again once the freeze passes, so a caller
    /// polling this never sees a stuck `true` after an upgrade completes.
    pub frozen: bool,
    /// Consensus ms this answer speaks for.
    pub timestamp: u64,
}

/// One row of [`VaultSummaries`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct VaultSummary {
    /// Vault id.
    pub id: u64,
    /// Vault account, `0x` hex.
    pub address: String,
    /// Display name.
    #[serde(default)]
    pub name: Option<String>,
    /// The leader that trades the vault, `0x` hex.
    pub leader: String,
    /// Marked-to-market net asset value, whole-USDC decimal string. A withdraw
    /// prices against THIS figure, not against deposits.
    pub tvl: String,
    /// Number of accounts holding shares.
    pub follower_count: u64,
    /// `"user"` or `"metaliquidity"`.
    pub kind: String,
}

/// `vault_summaries` — every vault on the venue.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct VaultSummaries {
    /// One row per vault, ascending by id.
    #[serde(default)]
    pub vaults: Vec<VaultSummary>,
}

/// `user_rate_limit` — one account's action counters.
///
/// An account the chain has never seen reads as all zeros. That is the same
/// answer an account that has never acted gives, and neither is an error.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct UserRateLimit {
    /// The queried account, `0x` hex.
    pub address: String,
    /// Highest nonce the chain has committed for this account. The next signed
    /// action must use a higher one.
    pub last_nonce: u64,
    /// Actions admitted and not yet committed.
    pub pending_count: u64,
    /// Actions committed over the account's life.
    pub lifetime_count: u64,
}

/// Per-market ceilings every deployer market must meet.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PerMarketLimits {
    /// Open-interest ceiling, base-unit decimal string.
    pub max_oi: String,
    /// Leverage ceiling.
    pub max_leverage: u8,
    /// Taker fee ceiling, whole-bps decimal string.
    pub max_taker_fee_bps: String,
    /// Open-interest growth ceiling per second, base-unit decimal string.
    pub max_oi_per_second: String,
}

/// The deploy limits served beside [`PerpDexs::dexs`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PerpDexLimits {
    /// Permissionless deploy is live.
    pub mip3_enabled: bool,
    /// Deployer self-stake floor, MTF BASE units.
    pub min_deploy_stake_base: String,
    /// Permissionless deploy bond, WHOLE MTF. This is a SECOND governance knob,
    /// not `min_deploy_stake_base` on another plane — the two move apart.
    pub min_deploy_stake_mtf: String,
    /// Gas-auction reserve, whole USDC.
    pub gas_auction_min_bid: String,
    /// Auction clock decay window, in blocks.
    pub auction_duration_blocks: u32,
    /// Deployer fee ceiling, whole-bps decimal string.
    pub deployer_fee_cap_bps: String,
    /// Next-round start multiplier.
    pub dutch_start_multiplier: u128,
    /// Ceilings each deployer market must meet.
    pub per_market_limits: PerMarketLimits,
}

/// One perp DEX row.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PerpDex {
    /// Position of this dex in the venue's dex vector.
    ///
    /// A Vec subscript, not an identifier. Join on [`PerpDex::name`] instead.
    pub index: u64,
    /// The dex name, and the only stable identifier of a dex.
    ///
    /// It is the asset namespace: every market here has the symbol
    /// `<name>:<suffix>`. It is also the `clearinghouse_state` bucket key, so
    /// it joins an account's positions to this row. The core dex has `""`.
    #[serde(default)]
    pub name: String,
    /// The deployer that created this dex, `0x` hex. `None` on the core dex,
    /// which has no deployer.
    #[serde(default)]
    pub deployer: Option<String>,
    /// Number of markets it hosts.
    pub n_assets: u64,
    /// Market symbols it hosts.
    #[serde(default)]
    pub assets: Vec<String>,
}

/// `perp_dexs` — the perp DEX set and the deploy limits.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PerpDexs {
    /// One row per dex.
    #[serde(default)]
    pub dexs: Vec<PerpDex>,
    /// Governance deploy limits.
    pub limits: PerpDexLimits,
}

/// One validator row of [`ValidatorSummaries`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ValidatorSummary {
    /// Validator account, `0x` hex.
    pub validator: String,
    /// Signing key address, `0x` hex.
    pub signer: String,
    /// Consensus index.
    pub validator_index: u64,
    /// Total stake behind the validator, decimal string.
    pub stake: String,
    /// Stake the validator posted itself, decimal string.
    pub self_stake: String,
    /// Stake posted by everyone else, decimal string.
    pub delegated_stake: String,
    /// The operator's chosen handle. `None` means UNSET — fall back to the
    /// address, never invent a name.
    #[serde(default)]
    pub display_name: Option<String>,
    /// What the QUERIED account has delegated here, decimal string. Present on
    /// every row when the request named an address, absent on every row when it
    /// did not. `Some("0")` says the caller delegated nothing to THIS validator;
    /// `None` says the caller asked no account-scoped question.
    #[serde(default)]
    pub your_stake: Option<String>,
    /// Commission the validator keeps, whole-bps decimal string.
    pub commission_bps: String,
    /// In the active set.
    pub is_active: bool,
    /// Jailed.
    pub is_jailed: bool,
    /// Consensus ms the validator was jailed. `None` when not jailed.
    #[serde(default)]
    pub jailed_at: Option<u64>,
    /// Consensus ms the validator may unjail. `None` when not jailed.
    #[serde(default)]
    pub unjail_at: Option<u64>,
    /// First epoch the validator was active in.
    pub first_active_epoch: u64,
}

/// `validator_summaries` — the validator set.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ValidatorSummaries {
    /// Stake across the whole set, decimal string.
    pub total_stake: String,
    /// Number of validators in the active set.
    pub n_active: u64,
    /// One row per validator, ascending by address.
    #[serde(default)]
    pub validators: Vec<ValidatorSummary>,
}

/// One L1 vote record.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ValidatorL1Vote {
    /// Round the vote was cast in.
    pub round: u64,
    /// The voting validator, `0x` hex.
    pub validator: String,
    /// Consensus ms the vote was submitted.
    pub submitted_at: u64,
}

/// `validator_l1_votes` — recent oracle vote metadata.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ValidatorL1Votes {
    /// Newest round the tracker holds.
    pub latest_round: u64,
    /// One row per vote. The vote PAYLOAD is opaque oracle bytes and is not
    /// served — these are the metadata only.
    #[serde(default)]
    pub votes: Vec<ValidatorL1Vote>,
}

/// One bid in the perp-deploy gas auction.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Mip3Bid {
    /// The bidder, `0x` hex.
    pub bidder: String,
    /// Bid amount, decimal string.
    pub amount: String,
    /// Consensus ms the bid was submitted.
    pub submitted_at: u64,
    /// The bidder's own label, e.g. the market symbol it means to deploy.
    pub tag: String,
}

/// `mip3_active_bids` — the sealed perp-deploy gas auction.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Mip3ActiveBids {
    /// Round number.
    pub auction_round: u64,
    /// Highest bid so far, decimal string.
    pub current_bid: String,
    /// Account holding the highest bid, `0x` hex. `None` when nobody has bid.
    #[serde(default)]
    pub current_winner: Option<String>,
    /// Consensus ms the round closes.
    pub auction_end: u64,
    /// Consensus ms the round opened.
    pub started_at: u64,
    /// One row per bidder.
    #[serde(default)]
    pub bids: Vec<Mip3Bid>,
}

/// The sealed-bid round served beside the Dutch clock.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SealedRound {
    /// Round number.
    pub auction_round: u64,
    /// Highest bid so far, decimal string.
    pub current_bid: String,
    /// Account holding the highest bid, `0x` hex.
    #[serde(default)]
    pub current_winner: Option<String>,
    /// Consensus ms the round closes.
    pub auction_end: u64,
    /// Consensus ms the round opened.
    pub started_at: u64,
    /// Total burned by settled rounds, decimal string.
    pub total_burned: String,
    /// Deposit held, decimal string.
    pub deposit: String,
}

/// `spot_deploy_auction` — the live spot-pair deploy auction.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SpotDeployAuction {
    /// The clock ask at `now_block`, whole-USDC decimal string. An accept
    /// clears IMMEDIATELY at this price, so a bidder must offer at least it.
    pub current_ask: String,
    /// Resting low of the clock, whole-USDC decimal string.
    pub floor: String,
    /// Opening high of the clock, whole-USDC decimal string.
    pub start: String,
    /// The previous round's clearing price, whole-USDC decimal string. `"0"`
    /// when no round has ever cleared.
    pub last_clearing: String,
    /// Block the current round opened at. `0` = no round yet.
    pub opened_at_block: u64,
    /// Clock decay window, in blocks.
    pub duration_blocks: u32,
    /// Committed height this answer speaks for. The clock decays with HEIGHT,
    /// not with wall time, so a caller must re-read to price an accept.
    pub now_block: u64,
    /// Next-round start multiplier.
    pub start_multiplier: u128,
    /// The sealed-bid round running beside the clock. It is a SECOND auction
    /// with its own bids and its own winner, not a view of the clock above.
    pub sealed_round: SealedRound,
}

/// One live TWAP parent.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct UserTwap {
    /// Parent id.
    pub twap_id: u64,
    /// Market symbol.
    pub coin: String,
    /// `"B"` (bid) or `"A"` (ask).
    pub side: String,
    /// Total size ordered, decimal string in the market's size plane.
    pub sz: String,
    /// Size already filled, decimal string in the same plane.
    pub executed_sz: String,
    /// Slices the schedule holds.
    pub slices_total: u32,
    /// Slices already fired.
    pub slices_done: u32,
    /// Gap between slices, ms. Total run time is `slices_total * delay_ms`.
    pub delay_ms: u64,
    /// Consensus ms the last slice fired.
    pub last_fire_ts: u64,
    /// The schedule may only reduce a position.
    pub reduce_only: bool,
}

/// `user_twaps` — an account's LIVE TWAP parents.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct UserTwaps {
    /// The queried account, `0x` hex.
    pub address: String,
    /// One row per live parent. A completed or cancelled schedule LEAVES the
    /// set, so an empty list means nothing is running now — it is not a history
    /// of the account's TWAPs.
    #[serde(default)]
    pub twaps: Vec<UserTwap>,
}

impl Info<'_> {
    /// Read whether the venue accepts trade right now (`exchange_status`).
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn exchange_status(&self) -> Result<ExchangeStatus, ClientError> {
        self.client
            .post_json("/info", &json!({ "type": "exchange_status" }))
            .await
    }

    /// Read every vault on the venue (`vault_summaries`).
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn vault_summaries(&self) -> Result<VaultSummaries, ClientError> {
        self.client
            .post_json("/info", &json!({ "type": "vault_summaries" }))
            .await
    }

    /// Read one account's action counters (`user_rate_limit`).
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn user_rate_limit(&self, addr: Address) -> Result<UserRateLimit, ClientError> {
        self.client
            .post_json(
                "/info",
                &json!({ "type": "user_rate_limit", "address": addr }),
            )
            .await
    }

    /// Read the perp DEX set and the deploy limits (`perp_dexs`).
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn perp_dexs(&self) -> Result<PerpDexs, ClientError> {
        self.client
            .post_json("/info", &json!({ "type": "perp_dexs" }))
            .await
    }

    /// Read the validator set (`validator_summaries`).
    ///
    /// Pass `caller` to add a `your_stake` figure to every row; pass `None` for
    /// the set alone.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn validator_summaries(
        &self,
        caller: Option<Address>,
    ) -> Result<ValidatorSummaries, ClientError> {
        let mut body = json!({ "type": "validator_summaries" });
        if let Some(a) = caller {
            body["address"] = json!(a);
        }
        self.client.post_json("/info", &body).await
    }

    /// Read recent validator oracle-vote metadata (`validator_l1_votes`).
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn validator_l1_votes(&self) -> Result<ValidatorL1Votes, ClientError> {
        self.client
            .post_json("/info", &json!({ "type": "validator_l1_votes" }))
            .await
    }

    /// Read the sealed perp-deploy gas auction (`mip3_active_bids`).
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn mip3_active_bids(&self) -> Result<Mip3ActiveBids, ClientError> {
        self.client
            .post_json("/info", &json!({ "type": "mip3_active_bids" }))
            .await
    }

    /// Read the live spot-pair deploy auction (`spot_deploy_auction`).
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn spot_deploy_auction(&self) -> Result<SpotDeployAuction, ClientError> {
        self.client
            .post_json("/info", &json!({ "type": "spot_deploy_auction" }))
            .await
    }

    /// Read an account's live TWAP parents (`user_twaps`).
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn user_twaps(&self, addr: Address) -> Result<UserTwaps, ClientError> {
        self.client
            .post_json("/info", &json!({ "type": "user_twaps", "address": addr }))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exchange_status_decodes() {
        let s: ExchangeStatus = serde_json::from_str(
            r#"{"spot_disabled":false,"post_only":false,"mip3_enabled":true,
                "frozen":false,"timestamp":1700000000000}"#,
        )
        .expect("decode");
        assert!(s.mip3_enabled && !s.frozen);
        assert_eq!(s.timestamp, 1_700_000_000_000);
    }

    #[test]
    fn vault_summary_decodes_and_an_unnamed_vault_is_none() {
        let v: VaultSummaries = serde_json::from_str(
            r#"{"vaults":[{"id":1,"address":"0x00000000000000000000000000000000000000aa",
                 "name":"mlp","leader":"0x00000000000000000000000000000000000000bb",
                 "tvl":"50000","follower_count":3,"kind":"metaliquidity"},
                {"id":2,"address":"0x00000000000000000000000000000000000000cc",
                 "name":null,"leader":"0x00000000000000000000000000000000000000bb",
                 "tvl":"0","follower_count":0,"kind":"user"}]}"#,
        )
        .expect("decode");
        assert_eq!(v.vaults[0].name.as_deref(), Some("mlp"));
        assert_eq!(v.vaults[1].name, None);
        assert_eq!(v.vaults[1].kind, "user");
    }

    /// `your_stake` present-and-zero and absent are different answers, so the
    /// decode must keep them apart.
    #[test]
    fn your_stake_zero_is_not_your_stake_absent() {
        let scoped: ValidatorSummaries = serde_json::from_str(
            r#"{"total_stake":"100","n_active":1,"validators":[{
                "validator":"0x00000000000000000000000000000000000000a1",
                "signer":"0x00000000000000000000000000000000000000a2",
                "validator_index":0,"stake":"100","self_stake":"100",
                "delegated_stake":"0","display_name":null,"your_stake":"0",
                "commission_bps":"500","is_active":true,"is_jailed":false,
                "jailed_at":null,"unjail_at":null,"first_active_epoch":0}]}"#,
        )
        .expect("decode scoped");
        assert_eq!(scoped.validators[0].your_stake.as_deref(), Some("0"));

        let global: ValidatorSummaries = serde_json::from_str(
            r#"{"total_stake":"100","n_active":1,"validators":[{
                "validator":"0x00000000000000000000000000000000000000a1",
                "signer":"0x00000000000000000000000000000000000000a2",
                "validator_index":0,"stake":"100","self_stake":"100",
                "delegated_stake":"0","display_name":null,
                "commission_bps":"500","is_active":true,"is_jailed":false,
                "first_active_epoch":0}]}"#,
        )
        .expect("decode global");
        assert_eq!(global.validators[0].your_stake, None);
        assert_eq!(global.validators[0].jailed_at, None);
    }

    #[test]
    fn perp_dexs_decodes_the_two_independent_stake_knobs() {
        let d: PerpDexs = serde_json::from_str(
            r#"{"dexs":[{"index":0,"name":"","deployer":null,
                  "n_assets":2,"assets":["BTC","ETH"]},
                 {"index":1,"name":"GRAD","deployer":"0x10572bc485ee62403eb8778c1303857d6f4f9913",
                  "n_assets":1,"assets":["GRAD:000001SH"]}],
                "limits":{"mip3_enabled":true,
                  "min_deploy_stake_base":"100000000000",
                  "min_deploy_stake_mtf":"1000",
                  "gas_auction_min_bid":"500","auction_duration_blocks":86400,
                  "deployer_fee_cap_bps":"50","dutch_start_multiplier":3,
                  "per_market_limits":{"max_oi":"1000","max_leverage":20,
                    "max_taker_fee_bps":"10","max_oi_per_second":"5"}}}"#,
        )
        .expect("decode");
        assert_eq!(d.dexs[0].assets.len(), 2);
        // The core dex is named "", not null, and has no deployer. A deployer
        // dex carries both halves of the join key the account read needs.
        assert_eq!(d.dexs[0].name, "");
        assert_eq!(d.dexs[0].deployer, None);
        assert_eq!(d.dexs[1].name, "GRAD");
        assert!(d.dexs[1].deployer.is_some());
        assert_ne!(
            d.limits.min_deploy_stake_base,
            d.limits.min_deploy_stake_mtf
        );
        assert_eq!(d.limits.per_market_limits.max_leverage, 20);
    }

    #[test]
    fn auctions_decode_and_an_unbid_round_has_no_winner() {
        let m: Mip3ActiveBids = serde_json::from_str(
            r#"{"auction_round":4,"current_bid":"0","current_winner":null,
                "auction_end":0,"started_at":0,"bids":[]}"#,
        )
        .expect("decode sealed");
        assert_eq!(m.current_winner, None);

        let s: SpotDeployAuction = serde_json::from_str(
            r#"{"current_ask":"750","floor":"500","start":"1500",
                "last_clearing":"0","opened_at_block":10,"duration_blocks":86400,
                "now_block":40000,"start_multiplier":3,
                "sealed_round":{"auction_round":1,"current_bid":"0",
                  "current_winner":null,"auction_end":0,"started_at":0,
                  "total_burned":"0","deposit":"0"}}"#,
        )
        .expect("decode dutch");
        assert_eq!(s.current_ask, "750");
        assert_eq!(s.sealed_round.auction_round, 1);
    }

    #[test]
    fn user_twaps_decodes_and_an_empty_set_means_nothing_running() {
        let t: UserTwaps = serde_json::from_str(
            r#"{"address":"0x00000000000000000000000000000000000000aa",
                "twaps":[{"twap_id":3,"coin":"BTC","side":"B","sz":"10",
                  "executed_sz":"4","slices_total":10,"slices_done":4,
                  "delay_ms":30000,"last_fire_ts":1700000000000,
                  "reduce_only":false}]}"#,
        )
        .expect("decode");
        assert_eq!(t.twaps[0].slices_done, 4);

        let none: UserTwaps = serde_json::from_str(
            r#"{"address":"0x00000000000000000000000000000000000000aa","twaps":[]}"#,
        )
        .expect("decode empty");
        assert!(none.twaps.is_empty());
    }

    #[test]
    fn user_rate_limit_decodes_an_unseen_account_as_zeros() {
        let r: UserRateLimit = serde_json::from_str(
            r#"{"address":"0x00000000000000000000000000000000000000aa",
                "last_nonce":0,"pending_count":0,"lifetime_count":0}"#,
        )
        .expect("decode");
        assert_eq!(r.last_nonce, 0);
        assert_eq!(r.lifetime_count, 0);
    }

    #[test]
    fn validator_l1_votes_decodes() {
        let v: ValidatorL1Votes = serde_json::from_str(
            r#"{"latest_round":900,"votes":[{"round":900,
                "validator":"0x00000000000000000000000000000000000000a1",
                "submitted_at":1700000000000}]}"#,
        )
        .expect("decode");
        assert_eq!(v.latest_round, 900);
        assert_eq!(v.votes[0].round, 900);
    }
}
