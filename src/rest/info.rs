//! `/info` — read-only MTF-native queries.
//!
//! No signing required. Discriminator is `type` per the MTF-native handler
//! in `crates/api-node/src/rest/info.rs`; payload fields are snake_case.
//!
//! Two tiers of query:
//!
//! - **Node-native** ([`Info::node_info`], [`Info::account_state`],
//!   [`Info::market_info`], [`Info::vault_state`], [`Info::staking_state`],
//!   [`Info::fee_schedule`], [`Info::spot_meta`],
//!   [`Info::spot_clearinghouse_state`]) — 1:1 with the node's `handle_info`
//!   dispatch. Keyed by internal numeric ids (`account_id` / `market_id` /
//!   `vault_id`) or by 20-byte `address`.
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

/// One level of the L2 book.
///
/// Per `api/rest/info.md` (`l2_book`): `px` / `sz` are 8-decimal fixed-point
/// **u128 strings** (precision past 2^53), `n_orders` is a JSON number.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct L2Level {
    /// Price, 8-decimal fixed-point as a decimal string.
    pub px: String,
    /// Aggregate size at this price, fixed-point as a decimal string.
    pub sz: String,
    /// Number of orders at this price.
    pub n_orders: u32,
}

/// L2 book snapshot.
///
/// Per `api/rest/info.md` (`l2_book`) the `data` payload is exactly
/// `{ "bids": [...], "asks": [...] }`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct L2Book {
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

/// `node_info` response — static node identity + protocol version.
///
/// Per `api/rest/info.md` (`node_info`). No request parameters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct NodeInfo {
    /// Network variant: `"devnet"`, `"testnet"`, or `"mainnet"`.
    pub network: String,
    /// EIP-712 chain id this node is pinned to.
    pub chain_id: u64,
    /// Wire-protocol version (semver string).
    pub protocol_version: String,
    /// This node's index in the active validator set.
    pub validator_index: u32,
    /// Operator-published build identifier (short hex).
    pub build_commit: String,
    /// Process uptime in seconds.
    pub uptime_seconds: u64,
}

/// Account liquidation tier. See `concepts/tiered-liquidation.md`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Tier {
    /// Above all liquidation thresholds.
    Safe,
    /// Tier 0.
    T0,
    /// Tier 1.
    T1,
    /// Tier 2.
    T2,
    /// Tier 3.
    T3,
}

/// Account margin mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MarginMode {
    /// Cross margin — shared collateral across positions.
    Cross,
    /// Isolated margin.
    Isolated,
    /// Strict isolated margin.
    StrictIso,
}

/// One open position inside an [`AccountState`].
///
/// Distinct from [`crate::types::position::Position`] (the `user_state`
/// element): this is the `account_state.positions[*]` shape from
/// `api/rest/info.md`. `size` / `entry_px` / `unrealised_pnl` are fixed-point
/// **string** numerics; `leverage` is an integer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AccountPosition {
    /// Asset id.
    pub asset: u32,
    /// Signed position size, fixed-point as a decimal string.
    pub size: String,
    /// Volume-weighted entry price, fixed-point as a decimal string.
    pub entry_px: String,
    /// Unrealised PnL (signed), USDC base units as a decimal string.
    pub unrealised_pnl: String,
    /// Whether this position uses isolated margin.
    pub isolated: bool,
    /// Per-asset leverage multiple.
    pub leverage: u32,
}

/// Per-account balances inside an [`AccountState`].
///
/// `usdc` is the cross USDC collateral (6-decimal base units as a string);
/// `spot` maps spot-asset symbol → balance (8-decimal fixed-point string).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Balances {
    /// USDC collateral, 6-decimal base units as a decimal string.
    pub usdc: String,
    /// Spot balances keyed by asset symbol, fixed-point strings. `BTreeMap`
    /// for deterministic key ordering.
    #[serde(default)]
    pub spot: std::collections::BTreeMap<String, String>,
}

/// `account_state` response — rich per-account snapshot keyed by `address`.
///
/// Per `api/rest/info.md` (`account_state`). All monetary magnitudes are
/// fixed-point **string** numerics (USDC base units / 8-decimal fixed-point)
/// to survive JS-safe-integer limits; `health` may be negative.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AccountState {
    /// Echo of the requested address.
    pub address: Address,
    /// Equity including unrealised PnL, USDC base units (u128 string).
    pub account_value: String,
    /// Equity minus initial margin held by open positions (u128 string).
    pub free_collateral: String,
    /// Maintenance margin requirement (u128 string).
    pub maint_margin: String,
    /// Initial margin requirement (u128 string).
    pub init_margin: String,
    /// `account_value - maint_margin` (i128 string; can be negative).
    pub health: String,
    /// Liquidation tier.
    pub tier: Tier,
    /// Margin mode.
    pub margin_mode: MarginMode,
    /// Portfolio-margin opt-in state.
    pub pm_enabled: bool,
    /// Per-asset open positions.
    #[serde(default)]
    pub positions: Vec<AccountPosition>,
    /// Account balances.
    pub balances: Balances,
}

/// Market kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MarketKind {
    /// Perpetual future.
    Perp,
    /// Spot market.
    Spot,
}

/// Per-market funding parameters inside a [`MarketInfo`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Funding {
    /// Current funding rate per hour, fixed-point as a decimal string.
    pub rate_per_hr: String,
    /// Per-hour funding cap, fixed-point as a decimal string.
    pub cap_per_hr: String,
    /// Funding interval in milliseconds.
    pub interval_ms: u64,
    /// Next funding payment timestamp (unix ms).
    pub next_payment_ts: u64,
}

/// `market_info` response — rich per-market metadata.
///
/// Per `api/rest/info.md` (`market_info`). Fixed-point magnitudes
/// (`tick_size`, `step_size`, `min_order`, ratios, `open_interest`) are
/// **string** numerics; `asset_id` / `max_leverage` are JSON numbers.
/// Resolvable by `asset_id` or by `coin` (see [`Info::market_info`] /
/// [`Info::market_info_by_coin`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MarketInfo {
    /// Canonical asset id.
    pub asset_id: u32,
    /// Human-readable market name (e.g. `"BTC"`).
    pub name: String,
    /// Market kind.
    pub kind: MarketKind,
    /// Tick size (smallest price increment), fixed-point string.
    pub tick_size: String,
    /// Step size (smallest size increment), fixed-point string.
    pub step_size: String,
    /// Minimum order size, fixed-point string.
    pub min_order: String,
    /// Maximum leverage multiple.
    pub max_leverage: u32,
    /// Maintenance margin ratio, fixed-point string.
    pub maint_margin_ratio: String,
    /// Initial margin ratio, fixed-point string.
    pub init_margin_ratio: String,
    /// Funding parameters.
    pub funding: Funding,
    /// Mark-price source descriptor.
    pub mark_source: String,
    /// Whether frequent-batch-auction matching is enabled for this market.
    pub fba_enabled: bool,
    /// Open interest, fixed-point as a decimal string.
    pub open_interest: String,
}

/// One spot pair inside a [`SpotMeta`].
///
/// `id` is the numeric pair id — the SAME compact `coin` label spot prints
/// carry on the WS `trades` / `candles` / `fills` channels. `name` is the
/// human-readable `{base}/{quote}` display name derived from the token
/// registry; use this record to map between the two.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SpotPair {
    /// Numeric pair id (the WS `coin` label for spot prints).
    pub id: u32,
    /// Display name, derived as `{base}/{quote}` from the token registry.
    pub name: String,
    /// Base asset id.
    pub base: u32,
    /// Quote asset id.
    pub quote: u32,
    /// Taker fee in bps; `0` if unset.
    pub taker_fee_bps: u16,
    /// Minimum order notional (USDC cents) as a decimal string; `"0"` if unset.
    pub min_notional: String,
    /// Whether the pair is active for trading.
    pub active: bool,
}

/// One token registry entry inside a [`SpotMeta`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SpotToken {
    /// Token asset id.
    pub id: u32,
    /// Human token name (e.g. `"BTC"`).
    pub name: String,
    /// Display / size precision (decimals shown on the spot book).
    pub sz_decimals: u8,
    /// Native (ERC-20-style) token decimals (e.g. USDC = 6, BTC = 8).
    pub wei_decimals: u8,
}

/// `spot_meta` response — spot pair universe + token registry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SpotMeta {
    /// Registered spot pairs (token-registration sentinels excluded).
    pub pairs: Vec<SpotPair>,
    /// Token registry with per-token decimals.
    pub tokens: Vec<SpotToken>,
}

/// One spot balance inside a [`SpotClearinghouseState`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SpotBalance {
    /// Spot asset id.
    pub asset: u32,
    /// Human name for the asset, else `asset:<id>`.
    pub name: String,
    /// Balance as a decimal string (truncated toward zero).
    pub balance: String,
}

/// `spot_clearinghouse_state` response — per-account spot token balances.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SpotClearinghouseState {
    /// Echo of the requested address.
    pub address: Address,
    /// Spot balances held by the account.
    pub balances: Vec<SpotBalance>,
}

impl<'a> Info<'a> {
    /// List all markets and their rich metadata.
    ///
    /// Returns a JSON array of [`MarketInfo`] objects (the same record served
    /// per-market by [`Info::market_info`]).
    ///
    /// NOTE: `api/rest/info.md` does not define a bulk `markets` query type —
    /// only the per-market `market_info`. This method targets a gateway-surface
    /// `markets` aggregate that mirrors the `market_info` record shape.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn markets(&self) -> Result<Vec<MarketInfo>, ClientError> {
        self.client
            .post_json("/info", &json!({ "type": "markets" }))
            .await
    }

    /// Fetch the L2 book snapshot for a market.
    ///
    /// Per `api/rest/info.md` (`l2_book`): keyed by `asset_id`, `depth`
    /// levels per side. The `data` payload is `{ bids, asks }`.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn l2_book(&self, market: MarketId, depth: u32) -> Result<L2Book, ClientError> {
        self.client
            .post_json(
                "/info",
                &json!({ "type": "l2_book", "asset_id": market.0, "depth": depth }),
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

    /// `account_state` — rich per-account snapshot keyed by `address`.
    ///
    /// Per `api/rest/info.md` (`account_state`): the request carries the 20-byte
    /// `address`; the response is the rich [`AccountState`] (equity, margins,
    /// tier, positions, balances).
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn account_state(&self, addr: Address) -> Result<AccountState, ClientError> {
        self.client
            .post_json(
                "/info",
                &json!({ "type": "account_state", "address": addr }),
            )
            .await
    }

    /// `market_info` — rich single-market snapshot by canonical `asset_id`.
    ///
    /// Per `api/rest/info.md` (`market_info`). To resolve by human-readable
    /// name use [`Info::market_info_by_coin`].
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn market_info(&self, market: MarketId) -> Result<MarketInfo, ClientError> {
        self.client
            .post_json(
                "/info",
                &json!({ "type": "market_info", "asset_id": market.0 }),
            )
            .await
    }

    /// `market_info` — rich single-market snapshot by human-readable `coin`.
    ///
    /// Per `api/rest/info.md`: `asset_id` is canonical, `coin` is a convenience
    /// alias; both resolve to the same record. See [`Info::market_info`].
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn market_info_by_coin(&self, coin: &str) -> Result<MarketInfo, ClientError> {
        self.client
            .post_json(
                "/info",
                &json!({ "type": "market_info", "coin": coin }),
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

    /// `spot_meta` — spot pair universe + token registry. No parameters.
    ///
    /// Each [`SpotPair`]'s `name` is derived as `{base}/{quote}` from the
    /// token registry; the numeric `id` is the compact `coin` label spot
    /// prints carry on the WS `trades` / `candles` / `fills` channels.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn spot_meta(&self) -> Result<SpotMeta, ClientError> {
        self.client
            .post_json("/info", &json!({ "type": "spot_meta" }))
            .await
    }

    /// `spot_clearinghouse_state` — per-account spot token balances keyed by
    /// `address` (0x hex).
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn spot_clearinghouse_state(
        &self,
        addr: Address,
    ) -> Result<SpotClearinghouseState, ClientError> {
        self.client
            .post_json(
                "/info",
                &json!({ "type": "spot_clearinghouse_state", "address": addr }),
            )
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

    /// Decode the exact `node_info.data` payload from `api/rest/info.md`.
    #[test]
    fn node_info_decodes_doc_fixture() {
        let data = serde_json::json!({
            "network": "devnet",
            "chain_id": 31337,
            "protocol_version": "1.0.0",
            "validator_index": 3,
            "build_commit": "deadbeef",
            "uptime_seconds": 123456u64
        });
        let n: NodeInfo = serde_json::from_value(data).unwrap();
        assert_eq!(n.network, "devnet");
        assert_eq!(n.chain_id, 31337);
        assert_eq!(n.protocol_version, "1.0.0");
        assert_eq!(n.validator_index, 3);
        assert_eq!(n.uptime_seconds, 123456);
        // Round-trips.
        let dec: NodeInfo = serde_json::from_str(&serde_json::to_string(&n).unwrap()).unwrap();
        assert_eq!(n, dec);
    }

    /// Decode the exact `market_info.data` payload from `api/rest/info.md`.
    #[test]
    fn market_info_decodes_doc_fixture() {
        let data = serde_json::json!({
            "asset_id": 0,
            "name": "BTC",
            "kind": "Perp",
            "tick_size": "100",
            "step_size": "10000",
            "min_order": "10000",
            "max_leverage": 50,
            "maint_margin_ratio": "5000",
            "init_margin_ratio": "10000",
            "funding": {
                "rate_per_hr": "1000",
                "cap_per_hr": "50000",
                "interval_ms": 3600000u64,
                "next_payment_ts": 1735693200000u64
            },
            "mark_source": "MedianOfOraclesAndMid",
            "fba_enabled": false,
            "open_interest": "5000000000"
        });
        let m: MarketInfo = serde_json::from_value(data).unwrap();
        assert_eq!(m.asset_id, 0);
        assert_eq!(m.name, "BTC");
        assert_eq!(m.kind, MarketKind::Perp);
        assert_eq!(m.tick_size, "100");
        assert_eq!(m.max_leverage, 50);
        assert_eq!(m.funding.interval_ms, 3_600_000);
        assert_eq!(m.mark_source, "MedianOfOraclesAndMid");
        assert_eq!(m.open_interest, "5000000000");
        // Fixed-point magnitudes serialize back as strings.
        let j = serde_json::to_value(&m).unwrap();
        assert!(j["tick_size"].is_string());
        assert!(j["open_interest"].is_string());
        assert!(j["asset_id"].is_number());
    }

    /// Decode the exact `account_state.data` payload from `api/rest/info.md`.
    #[test]
    fn account_state_decodes_doc_fixture() {
        let data = serde_json::json!({
            "address": "0x000000000000000000000000000000000000beef",
            "account_value": "100000000",
            "free_collateral": "80000000",
            "maint_margin": "10000000",
            "init_margin": "20000000",
            "health": "10000000",
            "tier": "Safe",
            "margin_mode": "Cross",
            "pm_enabled": false,
            "positions": [{
                "asset": 0,
                "size": "100000000",
                "entry_px": "10000000000",
                "unrealised_pnl": "500000",
                "isolated": false,
                "leverage": 10
            }],
            "balances": {
                "usdc": "100000000",
                "spot": { "ETH": "5000000000" }
            }
        });
        let a: AccountState = serde_json::from_value(data).unwrap();
        assert_eq!(a.account_value, "100000000");
        assert_eq!(a.free_collateral, "80000000");
        assert_eq!(a.health, "10000000");
        assert_eq!(a.tier, Tier::Safe);
        assert_eq!(a.margin_mode, MarginMode::Cross);
        assert!(!a.pm_enabled);
        assert_eq!(a.positions.len(), 1);
        assert_eq!(a.positions[0].asset, 0);
        assert_eq!(a.positions[0].leverage, 10);
        assert_eq!(a.balances.usdc, "100000000");
        assert_eq!(a.balances.spot.get("ETH").map(String::as_str), Some("5000000000"));
        // Round-trips.
        let dec: AccountState = serde_json::from_str(&serde_json::to_string(&a).unwrap()).unwrap();
        assert_eq!(a, dec);
    }

    /// Decode the exact `l2_book.data` payload from `api/rest/info.md`.
    #[test]
    fn l2_book_decodes_doc_fixture() {
        let data = serde_json::json!({
            "bids": [{ "px": "10049000000", "sz": "100000000", "n_orders": 5 }],
            "asks": [{ "px": "10051000000", "sz": "200000000", "n_orders": 3 }]
        });
        let b: L2Book = serde_json::from_value(data).unwrap();
        assert_eq!(b.bids.len(), 1);
        assert_eq!(b.bids[0].px, "10049000000");
        assert_eq!(b.bids[0].sz, "100000000");
        assert_eq!(b.bids[0].n_orders, 5);
        assert_eq!(b.asks[0].n_orders, 3);
        // px/sz serialize as strings.
        let j = serde_json::to_value(&b).unwrap();
        assert!(j["bids"][0]["px"].is_string());
        assert!(j["bids"][0]["n_orders"].is_number());
    }

    /// Decode the exact `spot_meta.data` payload the node serves: pair `name`
    /// derived as `{base}/{quote}`, numeric `id` (the WS spot `coin` label),
    /// `min_notional` as a string, plus the token registry.
    #[test]
    fn spot_meta_decodes_node_fixture() {
        let data = serde_json::json!({
            "pairs": [{
                "id": 101,
                "name": "BTC/USDC",
                "base": 0,
                "quote": 100,
                "taker_fee_bps": 5,
                "min_notional": "1000",
                "active": true
            }],
            "tokens": [
                { "id": 0, "name": "BTC", "sz_decimals": 5, "wei_decimals": 8 },
                { "id": 100, "name": "USDC", "sz_decimals": 2, "wei_decimals": 6 }
            ]
        });
        let m: SpotMeta = serde_json::from_value(data).unwrap();
        assert_eq!(m.pairs.len(), 1);
        assert_eq!(m.pairs[0].id, 101);
        assert_eq!(m.pairs[0].name, "BTC/USDC");
        assert_eq!(m.pairs[0].base, 0);
        assert_eq!(m.pairs[0].quote, 100);
        assert_eq!(m.pairs[0].taker_fee_bps, 5);
        assert_eq!(m.pairs[0].min_notional, "1000");
        assert!(m.pairs[0].active);
        assert_eq!(m.tokens.len(), 2);
        assert_eq!(m.tokens[0].name, "BTC");
        assert_eq!(m.tokens[0].wei_decimals, 8);
        assert_eq!(m.tokens[1].id, 100);
        assert_eq!(m.tokens[1].sz_decimals, 2);
        // `min_notional` stays a string on the wire; ids stay numbers.
        let j = serde_json::to_value(&m).unwrap();
        assert!(j["pairs"][0]["min_notional"].is_string());
        assert!(j["pairs"][0]["id"].is_number());
        // Round-trips.
        let dec: SpotMeta = serde_json::from_str(&serde_json::to_string(&m).unwrap()).unwrap();
        assert_eq!(m, dec);
    }

    /// Decode the exact `spot_clearinghouse_state.data` payload the node serves.
    #[test]
    fn spot_clearinghouse_state_decodes_node_fixture() {
        let data = serde_json::json!({
            "address": "0x4242424242424242424242424242424242424242",
            "balances": [
                { "asset": 101, "name": "BTC/USDC", "balance": "500" }
            ]
        });
        let s: SpotClearinghouseState = serde_json::from_value(data).unwrap();
        assert_eq!(s.balances.len(), 1);
        assert_eq!(s.balances[0].asset, 101);
        assert_eq!(s.balances[0].name, "BTC/USDC");
        assert_eq!(s.balances[0].balance, "500");
        // `balance` stays a string on the wire.
        let j = serde_json::to_value(&s).unwrap();
        assert!(j["balances"][0]["balance"].is_string());
        assert!(j["balances"][0]["asset"].is_number());
        // Round-trips.
        let dec: SpotClearinghouseState =
            serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(s, dec);
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
