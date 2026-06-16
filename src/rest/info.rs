//! `/info` — read-only MTF-native queries.
//!
//! No signing required. Discriminator is `type` per the node's MTF-native
//! `/info` handler; payload fields are snake_case.
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
/// Per the gateway `/info` `l2_book` wire: `px` / `size` are 8-decimal
/// fixed-point **decimal strings** (precision past 2^53), `n_orders` is a JSON
/// number. (The price field is `size` on the REST read — not `sz`.)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct L2Level {
    /// Price, 8-decimal fixed-point as a decimal string.
    pub px: String,
    /// Aggregate raw-lot size at this price, decimal string.
    pub size: String,
    /// Number of resting orders at this price.
    pub n_orders: u32,
}

/// L2 book snapshot.
///
/// Per the `/info` contract (`l2_book`) the `data` payload is exactly
/// `{ "bids": [...], "asks": [...] }`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct L2Book {
    /// Bid side (descending by price).
    pub bids: Vec<L2Level>,
    /// Ask side (ascending by price).
    pub asks: Vec<L2Level>,
}

/// Order side as it appears on the REST `open_orders` read: lowercase
/// `"bid"` / `"ask"` (not `"buy"`/`"sell"`, not capitalized).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderSide {
    /// Resting buy.
    Bid,
    /// Resting sell.
    Ask,
}

/// One resting order in an [`OpenOrders`] snapshot.
///
/// `px` is x1e8 fixed-point (positive canonical price for **both** sides);
/// `size` is raw lots (`whole × 10^sz_decimals`). `oid` / `market_id` /
/// `inserted_at_ms` are bare integers.
///
/// LIVE GATEWAY GAP: a resting order currently reads back with `oid: 0` and
/// `inserted_at_ms: 0` even though it is on the book — so an order is NOT
/// reliably cancellable by the `oid` from this snapshot, and it carries no
/// `cloid`. Until the gateway populates `oid`, the oid-independent workaround
/// for reconcile / ghost-sweep is the `cancel_all_orders` exchange action
/// (by account / asset) rather than per-oid cancels.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct OpenOrder {
    /// Order id. See the struct note: currently `0` on the gateway.
    pub oid: u64,
    /// Market / asset id.
    pub market_id: u32,
    /// Side, lowercase `"bid"` / `"ask"`.
    pub side: OrderSide,
    /// Limit price, x1e8 fixed-point decimal string.
    pub px: String,
    /// Remaining size, raw lots (`whole × 10^sz_decimals`) decimal string.
    pub size: String,
    /// Insertion timestamp (unix ms). See the struct note: currently `0`.
    pub inserted_at_ms: u64,
}

/// `open_orders` response — resting orders for one account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct OpenOrders {
    /// Echo of the resolved account address (`0x` lowercase hex).
    pub address: Address,
    /// Numeric account id — present only when the request used `account_id`
    /// instead of `address`; `None` when resolved from an address.
    #[serde(default)]
    pub account_id: Option<u64>,
    /// Resting orders.
    #[serde(default)]
    pub orders: Vec<OpenOrder>,
}

/// One OHLCV bar from the `candle` `/info` read.
///
/// The REST companion to the live `candles` WS channel: the WS pushes the
/// forming bar as trades land, this read returns the closed history. Bars are
/// oldest-first by `open_time`; the newest element is the still-forming bar.
///
/// **Price plane — does NOT match the WS `candles` frame.** This REST read's
/// `open`/`close`/`high`/`low` are **whole-USDC** human-dollar decimal strings
/// (`"67042.50"`); the WS `candles` frame carries the SAME bar's OHLC as RAW
/// 1e8 fixed-point integers (`"6700000000000"`). Rescale if you mix the two
/// sources. `volume` is base units (coin size, NOT notional); `num_trades` is a
/// fill count, not notional.
///
/// GATEWAY-served, not node: candles are derived display data folded from the
/// public trade stream — not committed chain state, so they must be queried
/// against the **gateway** (`<net>-gateway.mtf.exchange/info`); a bare node
/// returns `unknown info type: candle`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Candle {
    /// Echoed market symbol (e.g. `"BTC"`).
    pub coin: String,
    /// Echoed bucket token (`1m`/`5m`/`15m`/`1h`/`4h`/`1d`).
    pub interval: String,
    /// Bar open timestamp (ms, bucket-aligned).
    pub open_time: u64,
    /// Bar close timestamp (ms) — `open_time + interval − 1`.
    pub close_time: u64,
    /// Open price, whole-USDC decimal string.
    pub open: String,
    /// Close price, whole-USDC decimal string.
    pub close: String,
    /// High price, whole-USDC decimal string.
    pub high: String,
    /// Low price, whole-USDC decimal string.
    pub low: String,
    /// Traded base volume in the bar, decimal string (coin size, not notional).
    pub volume: String,
    /// Fill count in the bar.
    pub num_trades: u64,
}

/// One fee tier inside a [`FeeSchedule`]. All bps fields are decimal strings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct FeeTier {
    /// Maker fee, bps decimal string (e.g. `"1.0"`).
    pub maker_bps: String,
    /// Taker fee, bps decimal string (e.g. `"5.0"`).
    pub taker_bps: String,
    /// 30-day volume threshold for this tier, decimal string (`"0"` = base).
    pub volume_30d: String,
}

/// `fee_schedule` response — protocol fee parameters.
///
/// All bps fields are **decimal strings** (`"1.0"`, `"5.0"`, `"0"`).
/// `burn_ratio` is a **fraction** in `[0, 1]` (`"0.8"` = 80%), NOT bps — do not
/// scale it by 10000 like the bps fields. `tiers[0]` is the canonical source of
/// maker/taker when the top-level pair is absent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct FeeSchedule {
    /// Top-level base maker fee, bps decimal string. Present on the deployed
    /// gateway; absent from a node built from the current source — fall back to
    /// `tiers[0].maker_bps` when `None`.
    #[serde(default)]
    pub maker_bps: Option<String>,
    /// Top-level base taker fee, bps decimal string. See `maker_bps`.
    #[serde(default)]
    pub taker_bps: Option<String>,
    /// Referrer share of the base taker take, bps decimal string (e.g. `"5.0"`).
    pub referrer_share_bps: String,
    /// Max additional builder-code rebate, bps decimal string (e.g. `"0"`).
    pub builder_rebate_bps: String,
    /// Burn fraction of the non-referrer remainder, fraction in `[0, 1]`
    /// (e.g. `"0.8"`). NOT bps.
    pub burn_ratio: String,
    /// Per-tier maker/taker schedule (authoritative carrier of maker/taker).
    pub tiers: Vec<FeeTier>,
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
// These read types mirror what the node serves directly. They are keyed by
// numeric ids (`account_id`, `market_id`, `vault_id`); a gateway translates
// `user: 0x…` ↔ `account_id` for the richer `address`-keyed methods above. The
// methods below hit the node 1:1, so a `Client` pointed straight at a node
// works without a gateway.

/// `node_info` response — static node identity + protocol version.
///
/// Per the `/info` contract (`node_info`). No request parameters.
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
/// the `/info` contract. `size` / `entry` / `upnl` are fixed-point
/// **string** numerics; `lev` is an integer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AccountPosition {
    /// Asset id.
    pub asset: u32,
    /// Signed position size, fixed-point as a decimal string.
    pub size: String,
    /// Volume-weighted entry price, fixed-point as a decimal string.
    #[serde(rename = "entry")]
    pub entry_px: String,
    /// Unrealised PnL (signed), USDC base units as a decimal string.
    #[serde(rename = "upnl")]
    pub unrealised_pnl: String,
    /// Whether this position uses isolated margin.
    pub isolated: bool,
    /// Per-asset leverage multiple.
    #[serde(rename = "lev")]
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
/// Per the `/info` contract (`account_state`). All monetary magnitudes are
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

/// Market kind. The gateway emits lowercase `"perp"` / `"spot"`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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
/// Per the `/info` contract (`market_info`). Fixed-point magnitudes
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
    /// Market kind (`"perp"` / `"spot"`).
    pub kind: MarketKind,
    /// Size precision: raw order/position `size` = `whole_units × 10^sz_decimals`.
    /// Load-bearing for size encoding — NOT derivable from `step_size`.
    pub sz_decimals: u8,
    /// Mark price, whole-USDC decimal string (tick-snapped; `"0"` fallback).
    pub mark_px: String,
    /// Oracle price, whole-USDC decimal string (tick-snapped; `"0"` fallback).
    pub oracle_px: String,
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
    /// NOTE: the `/info` contract does not define a bulk `markets` query type —
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
    /// Per the `/info` contract (`l2_book`): keyed by `asset_id`, `depth`
    /// levels per side. The `data` payload is `{ bids, asks }`.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn l2_book(&self, market: MarketId, depth: u32) -> Result<L2Book, ClientError> {
        self.client
            .post_json(
                "/info",
                &json!({ "type": "l2_book", "market_id": market.0, "depth": depth }),
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
    /// The node keys this query by numeric `account_id` (a gateway translates
    /// `user: 0x…` → `account_id`). Mirrors the node's `staking_state` read.
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
    /// Per the `/info` contract (`account_state`): the request carries the 20-byte
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

    /// `open_orders` — resting orders for an account, keyed by `address`.
    ///
    /// LIVE GATEWAY GAP: each [`OpenOrder`] currently reads back with `oid: 0`
    /// and `inserted_at_ms: 0`, so the orders are not cancellable by the `oid`
    /// from this snapshot and carry no `cloid`. The oid-independent workaround
    /// for reconcile / cancel-all is the `cancel_all_orders` exchange action
    /// keyed by account / asset rather than per-oid cancels.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn open_orders(&self, addr: Address) -> Result<OpenOrders, ClientError> {
        self.client
            .post_json("/info", &json!({ "type": "open_orders", "address": addr }))
            .await
    }

    /// `candle` — historical OHLCV bars for `(coin, interval)` over a window.
    ///
    /// The REST companion to the live `candles` WS channel. `coin` is a market
    /// **symbol** (e.g. `"BTC"`), not a numeric id. `start_time` / `end_time`
    /// are unix-ms filters on bar open (`None` = unbounded / from 0). Bars come
    /// oldest-first; the newest is the still-forming bar.
    ///
    /// GATEWAY-served, not node: a bare node returns `unknown info type:
    /// candle`. An empty vec is the honest-empty answer for an unsupported
    /// `interval`, a market with no indexed trades, or a deployment with no
    /// indexer wired.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn candle(
        &self,
        coin: &str,
        interval: &str,
        start_time: Option<u64>,
        end_time: Option<u64>,
    ) -> Result<Vec<Candle>, ClientError> {
        let mut req = json!({ "type": "candle", "coin": coin, "interval": interval });
        if let Some(s) = start_time {
            req["start_time"] = json!(s);
        }
        if let Some(e) = end_time {
            req["end_time"] = json!(e);
        }
        self.client.post_json("/info", &req).await
    }

    /// `market_info` — rich single-market snapshot by canonical `asset_id`.
    ///
    /// Per the `/info` contract (`market_info`). To resolve by human-readable
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
    /// Per the `/info` contract: `asset_id` is canonical, `coin` is a convenience
    /// alias; both resolve to the same record. See [`Info::market_info`].
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn market_info_by_coin(&self, coin: &str) -> Result<MarketInfo, ClientError> {
        self.client
            .post_json("/info", &json!({ "type": "market_info", "coin": coin }))
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

    /// Decode the exact `node_info.data` payload from the `/info` contract.
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

    /// Decode the exact `market_info.data` payload from the `/info` contract.
    #[test]
    fn market_info_decodes_doc_fixture() {
        let data = serde_json::json!({
            "asset_id": 0,
            "name": "BTC",
            "kind": "perp",
            "sz_decimals": 5,
            "mark_px": "50000",
            "oracle_px": "50000",
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
        assert_eq!(m.sz_decimals, 5);
        assert_eq!(m.mark_px, "50000");
        assert_eq!(m.oracle_px, "50000");
        assert_eq!(m.tick_size, "100");
        assert_eq!(m.max_leverage, 50);
        assert_eq!(m.funding.interval_ms, 3_600_000);
        assert_eq!(m.mark_source, "MedianOfOraclesAndMid");
        assert_eq!(m.open_interest, "5000000000");
        // Fixed-point magnitudes serialize back as strings; kind is lowercase.
        let j = serde_json::to_value(&m).unwrap();
        assert_eq!(j["kind"], "perp");
        assert!(j["sz_decimals"].is_number());
        assert!(j["tick_size"].is_string());
        assert!(j["open_interest"].is_string());
        assert!(j["asset_id"].is_number());
    }

    /// Decode the exact `account_state.data` payload from the `/info` contract.
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
                "entry": "10000000000",
                "upnl": "500000",
                "isolated": false,
                "lev": 10
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
        assert_eq!(
            a.balances.spot.get("ETH").map(String::as_str),
            Some("5000000000")
        );
        // Round-trips.
        let dec: AccountState = serde_json::from_str(&serde_json::to_string(&a).unwrap()).unwrap();
        assert_eq!(a, dec);
    }

    /// Decode the exact `l2_book.data` payload from the `/info` contract.
    #[test]
    fn l2_book_decodes_doc_fixture() {
        let data = serde_json::json!({
            "bids": [{ "px": "10049000000", "size": "100000000", "n_orders": 5 }],
            "asks": [{ "px": "10051000000", "size": "200000000", "n_orders": 3 }]
        });
        let b: L2Book = serde_json::from_value(data).unwrap();
        assert_eq!(b.bids.len(), 1);
        assert_eq!(b.bids[0].px, "10049000000");
        assert_eq!(b.bids[0].size, "100000000");
        assert_eq!(b.bids[0].n_orders, 5);
        assert_eq!(b.asks[0].n_orders, 3);
        // px/size serialize as strings.
        let j = serde_json::to_value(&b).unwrap();
        assert!(j["bids"][0]["px"].is_string());
        assert!(j["bids"][0]["size"].is_string());
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

    /// Decode the deployed gateway `fee_schedule.data`: string bps + tiers[].
    #[test]
    fn fee_schedule_decodes_gateway_fixture() {
        let data = serde_json::json!({
            "maker_bps": "1.0",
            "taker_bps": "5.0",
            "referrer_share_bps": "5.0",
            "builder_rebate_bps": "0",
            "burn_ratio": "0.8",
            "tiers": [{ "maker_bps": "1.0", "taker_bps": "5.0", "volume_30d": "0" }]
        });
        let f: FeeSchedule = serde_json::from_value(data).unwrap();
        assert_eq!(f.maker_bps.as_deref(), Some("1.0"));
        assert_eq!(f.referrer_share_bps, "5.0");
        assert_eq!(f.builder_rebate_bps, "0");
        assert_eq!(f.burn_ratio, "0.8");
        assert_eq!(f.tiers.len(), 1);
        assert_eq!(f.tiers[0].taker_bps, "5.0");
        assert_eq!(f.tiers[0].volume_30d, "0");
        let dec: FeeSchedule = serde_json::from_str(&serde_json::to_string(&f).unwrap()).unwrap();
        assert_eq!(f, dec);

        // A source-built node may omit the top-level maker/taker pair.
        let data2 = serde_json::json!({
            "referrer_share_bps": "5.0",
            "builder_rebate_bps": "0",
            "burn_ratio": "0.8",
            "tiers": [{ "maker_bps": "1.0", "taker_bps": "5.0", "volume_30d": "0" }]
        });
        let f2: FeeSchedule = serde_json::from_value(data2).unwrap();
        assert!(f2.maker_bps.is_none() && f2.taker_bps.is_none());
    }

    /// Decode the deployed gateway `open_orders.data` (note the live oid:0 gap).
    #[test]
    fn open_orders_decodes_gateway_fixture() {
        let data = serde_json::json!({
            "address": "0x000000000000000000000000000000000000beef",
            "orders": [
                { "oid": 0, "market_id": 0, "side": "bid", "px": "2500000000000", "size": "60", "inserted_at_ms": 0 }
            ]
        });
        let o: OpenOrders = serde_json::from_value(data).unwrap();
        assert!(o.account_id.is_none());
        assert_eq!(o.orders.len(), 1);
        assert_eq!(o.orders[0].side, OrderSide::Bid);
        assert_eq!(o.orders[0].px, "2500000000000");
        assert_eq!(o.orders[0].size, "60");
        // side is lowercase on the wire; oid/inserted_at_ms are numbers.
        let j = serde_json::to_value(&o).unwrap();
        assert_eq!(j["orders"][0]["side"], "bid");
        assert!(j["orders"][0]["oid"].is_number());
        let dec: OpenOrders = serde_json::from_str(&serde_json::to_string(&o).unwrap()).unwrap();
        assert_eq!(o, dec);
    }

    /// Decode the gateway `candle.data` array (whole-USDC prices, base volume).
    #[test]
    fn candle_decodes_gateway_fixture() {
        let data = serde_json::json!([
            {
                "coin": "BTC",
                "interval": "1m",
                "open_time": 1_700_000_040_000u64,
                "close_time": 1_700_000_099_999u64,
                "open": "67000.00",
                "close": "67042.50",
                "high": "67080.00",
                "low": "66990.00",
                "volume": "12.5",
                "num_trades": 37
            }
        ]);
        let bars: Vec<Candle> = serde_json::from_value(data).unwrap();
        assert_eq!(bars.len(), 1);
        assert_eq!(bars[0].coin, "BTC");
        assert_eq!(bars[0].interval, "1m");
        assert_eq!(bars[0].open_time, 1_700_000_040_000);
        assert_eq!(bars[0].close_time, 1_700_000_099_999);
        assert_eq!(bars[0].close, "67042.50");
        assert_eq!(bars[0].num_trades, 37);
        // OHLC / volume are strings; times + count are numbers.
        let j = serde_json::to_value(&bars[0]).unwrap();
        assert!(j["open"].is_string());
        assert!(j["volume"].is_string());
        assert!(j["open_time"].is_number());
        assert!(j["num_trades"].is_number());
    }
}
