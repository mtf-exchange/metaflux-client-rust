//! `/info` — read-only MTF-native queries.
//!
//! No signing required. Discriminator is `type` per the MTF-native handler
//! in `crates/api-node/src/rest/info.rs`; payload fields are snake_case.
//!
//! Two tiers of query:
//!
//! - **Node-native** ([`Info::node_info`], [`Info::account_state`],
//!   [`Info::market_info`], [`Info::vault_state`], [`Info::staking_state`],
//!   [`Info::fee_schedule`]) — 1:1 with the node's `handle_info` dispatch.
//!   Keyed by internal numeric ids (`account_id` / `market_id` / `vault_id`).
//! - **Gateway-surface** ([`Info::markets`], [`Info::l2_book`],
//!   [`Info::user_state`], [`Info::pm_state`], [`Info::rfq_state`]) — richer
//!   `address`-keyed / aggregate shapes served by the gateway's MTF-native
//!   adapter (which translates `0x…` ↔ internal ids). Use these when pointed
//!   at a gateway URL rather than a bare node.

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
/// { "market_id": 1, "symbol": "BTC", "size_decimals": 6,
///   "px_decimals": 4, "max_leverage": 50, "tick_size": 1, "min_size": 1 }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MarketMeta {
    /// Internal market id.
    pub market_id: MarketId,
    /// Human-readable symbol (e.g. `"BTC"`).
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
    /// Max additional MIP-3 deployer fee in bps.
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

// ── node-native `/info` shapes ──────────────────────────────────────────────
//
// The handlers in `crates/api-node/src/rest/info.rs` are the source of truth
// for what the NODE serves directly. They are keyed by internal numeric ids
// (`account_id`, `market_id`, `vault_id`) — the gateway's HL-compat layer is
// what translates `user: 0x…` ↔ `account_id`. The richer `address`-keyed
// methods above target that gateway surface; the methods below hit the node
// 1:1 so a `Client` pointed straight at a node works today.

/// `node_info` response — chain identity + sync state. No request parameters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct NodeInfo {
    /// EVM chain id this node is pinned to (the EIP-712 domain chain id).
    pub chain_id: u64,
    /// Current consensus epoch.
    pub epoch: u64,
    /// Committed block height.
    pub height: u64,
    /// Number of connected gossip peers.
    pub peers_connected: u32,
}

/// `account_state` response — account snapshot keyed by internal `account_id`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AccountState {
    /// Echo of the requested account id.
    pub account_id: u64,
    /// Number of asset clearinghouses where the account holds a non-zero net
    /// position.
    pub position_count: u32,
    /// Native base balance (always 0 today — MTF has no single base balance).
    pub balance_base: i64,
    /// Quote collateral (`cross_account_value`), truncated toward zero.
    pub balance_quote: i64,
}

/// `market_info` response — single-market snapshot keyed by `market_id`.
///
/// `mark_px` is a decimal STRING: the node emits the raw fixed-point magnitude
/// (which can exceed JS safe-int range) as a string so no precision is lost on
/// the wire. `oi` (open interest, u128) is a JSON number today.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MarketInfo {
    /// Echo of the requested market id.
    pub market_id: u32,
    /// Mark price as a decimal string of the raw fixed-point magnitude.
    pub mark_px: String,
    /// Last trade timestamp (unix ms); 0 if no trades.
    pub last_trade_ms: u64,
    /// Open interest in fixed-point units.
    pub oi: u128,
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

    /// Fetch the staking state for an account.
    ///
    /// The node keys this query by internal `account_id` (the gateway HL-compat
    /// layer translates `user: 0x…` → `account_id`). Mirrors
    /// `handle_staking_state` in `crates/api-node/src/rest/info.rs`.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn staking_state(&self, account_id: u64) -> Result<StakingState, ClientError> {
        self.client
            .post_json(
                "/info",
                &json!({ "type": "staking_state", "account_id": account_id }),
            )
            .await
    }

    // ── node-native queries (keyed by internal numeric ids) ──

    /// `node_info` — chain identity + sync state. No parameters.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn node_info(&self) -> Result<NodeInfo, ClientError> {
        self.client
            .post_json("/info", &json!({ "type": "node_info" }))
            .await
    }

    /// `account_state` — account snapshot keyed by internal `account_id`.
    ///
    /// This is the node-native counterpart to [`Info::user_state`] (which
    /// targets the gateway's `address`-keyed surface).
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn account_state(&self, account_id: u64) -> Result<AccountState, ClientError> {
        self.client
            .post_json(
                "/info",
                &json!({ "type": "account_state", "account_id": account_id }),
            )
            .await
    }

    /// `market_info` — single-market snapshot keyed by `market_id`.
    ///
    /// Node-native counterpart to the gateway's `markets` / `l2_book` surface.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn market_info(&self, market: MarketId) -> Result<MarketInfo, ClientError> {
        self.client
            .post_json(
                "/info",
                &json!({ "type": "market_info", "market_id": market.0 }),
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

    /// List active delegations for an account. Convenience wrapper that
    /// extracts the `delegations` field from [`Info::staking_state`].
    ///
    /// # Errors
    /// See [`Info::staking_state`].
    pub async fn delegations(&self, account_id: u64) -> Result<Vec<Delegation>, ClientError> {
        Ok(self.staking_state(account_id).await?.delegations)
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
            symbol: "BTC".into(),
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
    fn node_info_round_trips() {
        let n = NodeInfo {
            chain_id: 998,
            epoch: 1,
            height: 42,
            peers_connected: 7,
        };
        let dec: NodeInfo = serde_json::from_str(&serde_json::to_string(&n).unwrap()).unwrap();
        assert_eq!(n, dec);
    }

    #[test]
    fn market_info_mark_px_is_a_string_on_the_wire() {
        let m = MarketInfo {
            market_id: 1,
            mark_px: "5000000000000".into(),
            last_trade_ms: 0,
            oi: 0,
        };
        let j = serde_json::to_value(&m).unwrap();
        assert!(
            j["mark_px"].is_string(),
            "mark_px must serialize as a string"
        );
        assert!(j["oi"].is_number(), "oi must serialize as a number");
    }

    #[test]
    fn account_state_round_trips() {
        let a = AccountState {
            account_id: 7,
            position_count: 3,
            balance_base: 0,
            balance_quote: -123,
        };
        let dec: AccountState = serde_json::from_str(&serde_json::to_string(&a).unwrap()).unwrap();
        assert_eq!(a, dec);
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
