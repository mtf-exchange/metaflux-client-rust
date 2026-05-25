//! `/info` — read-only MTF-native queries.
//!
//! No signing required. Discriminator is `type` per the MTF-native handler
//! in `crates/api-node/src/rest/info.rs`; payload fields are snake_case.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::error::ClientError;
use crate::rest::RestClient;
use crate::types::{
    MarketId, VaultId,
    pm::PmState,
    position::UserState,
    rfq::{RfqId, RfqState},
    vault::VaultState,
};
use crate::wallet::Address;

/// `info` namespace handle. Constructed via [`RestClient::info`].
#[derive(Debug)]
pub struct Info<'a> {
    pub(crate) client: &'a RestClient,
}

/// Static market metadata returned by `markets()`.
///
/// Wire shape:
/// ```json
/// { "market_id": 1, "symbol": "BTC-PERP", "size_decimals": 6,
///   "px_decimals": 4, "max_leverage": 50, "tick_size": 1, "min_size": 1 }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MarketMeta {
    /// Internal market id.
    pub market_id: MarketId,
    /// Human-readable symbol (e.g. `"BTC-PERP"`).
    pub symbol: String,
    /// Number of decimals in the size field's fixed-point encoding.
    pub size_decimals: u8,
    /// Number of decimals in the price field's fixed-point encoding.
    pub px_decimals: u8,
    /// Maximum leverage (integer multiple, e.g. 50 = 50×).
    pub max_leverage: u32,
    /// Tick size (smallest price increment) in fixed-point units.
    pub tick_size: u64,
    /// Minimum order size in fixed-point units.
    pub min_size: u64,
}

/// One level of the L2 book.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct L2Level {
    /// Price in fixed-point tick units.
    pub px: u64,
    /// Aggregate size at this price.
    pub size: u64,
    /// Number of orders at this price.
    pub n_orders: u32,
}

/// L2 book snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct L2Book {
    /// Market id (echo).
    pub market_id: MarketId,
    /// Server timestamp (unix ms).
    pub ts_ms: u64,
    /// Bid side (descending by price).
    pub bids: Vec<L2Level>,
    /// Ask side (ascending by price).
    pub asks: Vec<L2Level>,
}

/// `fee_schedule` response — pinned to the L1 §L.2 / §L.5 splits.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct FeeSchedule {
    /// Base taker fee in bps × 10 (i.e. 45 = 4.5 bps).
    pub taker_bps: u16,
    /// Base maker fee in bps × 10.
    pub maker_bps: u16,
    /// Referrer share as a fraction of the base taker take, in bps.
    pub referrer_share_bps: u16,
    /// Max additional builder code fee in bps.
    pub builder_cap_bps: u16,
    /// Max additional HIP-3 deployer fee in bps.
    pub deployer_cap_bps: u16,
    /// Burn fraction of the non-referrer remainder, in bps.
    pub burn_bps: u16,
    /// Vault fraction, in bps.
    pub vault_bps: u16,
    /// Validator fraction, in bps.
    pub validator_bps: u16,
    /// Treasury fraction, in bps.
    pub treasury_bps: u16,
}

/// `staking_state` response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct StakingState {
    /// Echo of requested address.
    pub address: Address,
    /// Total MTF staked across all delegations.
    pub total_staked: u128,
    /// Accrued but unclaimed rewards.
    pub pending_rewards: u128,
    /// Active delegations.
    pub delegations: Vec<Delegation>,
    /// Pending unbond entries.
    pub unbonding: Vec<UnbondingEntry>,
}

/// One delegation entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Delegation {
    /// Validator address.
    pub validator: Address,
    /// Staked MTF.
    pub amount: u128,
    /// Delegation timestamp (unix ms).
    pub since_ms: u64,
}

/// One unbonding entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct UnbondingEntry {
    /// Validator address.
    pub validator: Address,
    /// Amount being unbonded.
    pub amount: u128,
    /// Earliest claim timestamp (unix ms).
    pub claim_at_ms: u64,
}

impl<'a> Info<'a> {
    /// List all markets and their metadata.
    ///
    /// MTF-native shape: response is a JSON array of [`MarketMeta`] objects.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn markets(&self) -> Result<Vec<MarketMeta>, ClientError> {
        self.client
            .post_json("/info", &json!({ "type": "markets" }))
            .await
    }

    /// Fetch the L2 book snapshot for a market.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn l2_book(&self, market: MarketId) -> Result<L2Book, ClientError> {
        self.client
            .post_json(
                "/info",
                &json!({ "type": "l2_book", "market_id": market.0 }),
            )
            .await
    }

    /// Fetch the per-user state document (positions, margin, PnL).
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn user_state(&self, addr: Address) -> Result<UserState, ClientError> {
        self.client
            .post_json("/info", &json!({ "type": "user_state", "address": addr }))
            .await
    }

    /// Fetch the vault state by vault id.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn vault_state(&self, vault_id: VaultId) -> Result<VaultState, ClientError> {
        self.client
            .post_json(
                "/info",
                &json!({ "type": "vault_state", "vault_id": vault_id.0 }),
            )
            .await
    }

    /// Fetch the staking state for an address.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn staking_state(&self, addr: Address) -> Result<StakingState, ClientError> {
        self.client
            .post_json(
                "/info",
                &json!({ "type": "staking_state", "address": addr }),
            )
            .await
    }

    /// Fetch the global fee schedule.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn fee_schedule(&self) -> Result<FeeSchedule, ClientError> {
        self.client
            .post_json("/info", &json!({ "type": "fee_schedule" }))
            .await
    }

    /// List active delegations for an address. Convenience wrapper that
    /// extracts the `delegations` field from [`Info::staking_state`].
    ///
    /// # Errors
    /// See [`Info::staking_state`].
    pub async fn delegations(&self, addr: Address) -> Result<Vec<Delegation>, ClientError> {
        Ok(self.staking_state(addr).await?.delegations)
    }

    /// Fetch the portfolio-margin state for an address.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn pm_state(&self, addr: Address) -> Result<PmState, ClientError> {
        self.client
            .post_json("/info", &json!({ "type": "pm_state", "user": addr }))
            .await
    }

    /// Fetch the state of one RFQ session.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn rfq_state(&self, rfq_id: RfqId) -> Result<RfqState, ClientError> {
        self.client
            .post_json("/info", &json!({ "type": "rfq_state", "rfq_id": rfq_id.0 }))
            .await
    }

    /// Raw escape hatch — POST an arbitrary `type` payload to `/info`.
    ///
    /// Returns a raw [`serde_json::Value`] so callers can decode shapes the
    /// SDK doesn't yet have typed wrappers for.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn raw(&self, body: Value) -> Result<Value, ClientError> {
        self.client.post_json("/info", &body).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn market_meta_round_trips() {
        let m = MarketMeta {
            market_id: MarketId(1),
            symbol: "BTC-PERP".into(),
            size_decimals: 6,
            px_decimals: 4,
            max_leverage: 50,
            tick_size: 1,
            min_size: 1,
        };
        let j = serde_json::to_string(&m).unwrap();
        let dec: MarketMeta = serde_json::from_str(&j).unwrap();
        assert_eq!(m, dec);
    }

    #[test]
    fn fee_schedule_round_trips_plan_values() {
        let f = FeeSchedule {
            taker_bps: 45,
            maker_bps: 15,
            referrer_share_bps: 1000,
            builder_cap_bps: 8,
            deployer_cap_bps: 5,
            burn_bps: 5000,
            vault_bps: 2500,
            validator_bps: 1500,
            treasury_bps: 1000,
        };
        let j = serde_json::to_string(&f).unwrap();
        let dec: FeeSchedule = serde_json::from_str(&j).unwrap();
        assert_eq!(f, dec);
        // PLAN.md §L.2 split sums to 10000 bps.
        let sum = u64::from(f.burn_bps)
            + u64::from(f.vault_bps)
            + u64::from(f.validator_bps)
            + u64::from(f.treasury_bps);
        assert_eq!(sum, 10_000);
    }
}
