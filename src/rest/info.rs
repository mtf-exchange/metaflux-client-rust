//! `/info` — read-only MTF-native queries.
//!
//! No signing required. Discriminator is `type` per the node's MTF-native
//! `/info` handler; payload fields are snake_case.
//!
//! Query addressing follows the consolidated `/info` surface: markets are keyed
//! by `coin` (the market symbol, e.g. `"BTC"`) and accounts by `address` (20-byte
//! `0x` hex). The older numeric `market_id` / `asset_id` / `account_id` request
//! params are gone — pass a `coin` or an `address`.
//!
//! - **Market reads** — [`Info::markets`], [`Info::market_info`],
//!   [`Info::l2_book`], [`Info::recent_trades`], [`Info::trades_by_time`],
//!   [`Info::candle_snapshot`], [`Info::predicted_fundings`].
//! - **Account reads** — [`Info::account_state`], [`Info::open_orders`],
//!   [`Info::user_state`], [`Info::spot_clearinghouse_state`],
//!   [`Info::staking_state`], [`Info::pm_state`].
//! - **Static / misc** — [`Info::node_info`], [`Info::spot_meta`],
//!   [`Info::fee_schedule`], [`Info::vault_state`], [`Info::rfq_state`].

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::error::ClientError;
use crate::rest::RestClient;
use crate::types::{
    VaultId,
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
/// Per the `/info` `l2_book` wire: `px` / `size` are CANONICAL decimal strings
/// (string-typed so precision survives past 2^53) — `px` is tick-snapped whole
/// USDC (e.g. `"62500.12"`), `size` is whole base units (e.g. `"1.5"`), NOT the
/// raw 1e8 / raw-lot planes. `n_orders` is a JSON number. (The size field is
/// `size` on the REST read — not `sz`.)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct L2Level {
    /// Price, canonical whole-USDC decimal string (tick-snapped).
    pub px: String,
    /// Aggregate size at this price, canonical whole-base-unit decimal string.
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
/// `px` / `size` are CANONICAL decimal strings — `px` is tick-snapped whole
/// USDC (positive for **both** sides), `size` is whole base units. `oid` /
/// `market_id` / `inserted_at_ms` are bare integers.
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
    /// Limit price, canonical whole-USDC decimal string (tick-snapped).
    pub px: String,
    /// Remaining size, canonical whole-base-unit decimal string.
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

/// One OHLCV bar from the `candle_snapshot` `/info` read.
///
/// The REST companion to the live `candles` WS channel: the WS pushes the
/// forming bar as trades land, this read returns the closed history. Bars are
/// oldest-first by `open_time`; the newest element is the still-forming bar.
///
/// Wire fields use the compact single-letter keys the archive serves
/// (`t`/`T`/`o`/`c`/`h`/`l`/`v`/`q`/`n`/`s`/`i`); this struct renames them to
/// readable names. `open`/`close`/`high`/`low` are whole-USDC human-dollar
/// decimal strings (`"61652.7"`), `volume` is base units (coin size),
/// `quote_volume` is the quote-denominated notional, and `num_trades` is a fill
/// count.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candle {
    /// Market symbol (e.g. `"BTC"`); wire key `s`.
    #[serde(rename = "s", default)]
    pub coin: String,
    /// Bucket token (`1m`/`5m`/`15m`/`1h`/`4h`/`1d`); wire key `i`.
    #[serde(rename = "i")]
    pub interval: String,
    /// Bar open timestamp (ms, bucket-aligned); wire key `t`.
    #[serde(rename = "t")]
    pub open_time: u64,
    /// Bar close timestamp (ms); wire key `T`.
    #[serde(rename = "T")]
    pub close_time: u64,
    /// Open price, whole-USDC decimal string; wire key `o`.
    #[serde(rename = "o")]
    pub open: String,
    /// Close price, whole-USDC decimal string; wire key `c`.
    #[serde(rename = "c")]
    pub close: String,
    /// High price, whole-USDC decimal string; wire key `h`.
    #[serde(rename = "h")]
    pub high: String,
    /// Low price, whole-USDC decimal string; wire key `l`.
    #[serde(rename = "l")]
    pub low: String,
    /// Traded base volume in the bar, decimal string (coin size); wire key `v`.
    #[serde(rename = "v")]
    pub volume: String,
    /// Quote-denominated notional traded in the bar, decimal string; wire key `q`.
    #[serde(rename = "q", default)]
    pub quote_volume: String,
    /// Fill count in the bar; wire key `n`.
    #[serde(rename = "n")]
    pub num_trades: u64,
}

/// One public trade print from [`Info::recent_trades`] / [`Info::trades_by_time`].
///
/// Prints render the market **symbol** in `coin` (`"BTC"`). `px` / `sz` are
/// canonical decimal strings; `side` is the aggressor taker side, `"A"` (a
/// sell hitting the bid) or `"B"` (a buy lifting the ask). `hash` is the 0x
/// action hash that produced the fill (empty for systemic prints); `tid` is the
/// unique trade id, `block` the block height, `time` the unix-ms timestamp.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Trade {
    /// Market symbol (e.g. `"BTC"`).
    pub coin: String,
    /// Trade price, canonical whole-USDC decimal string.
    pub px: String,
    /// Trade size, canonical whole-base-unit decimal string.
    pub sz: String,
    /// Aggressor taker side: `"A"` (sell) or `"B"` (buy).
    pub side: String,
    /// Unique trade id.
    pub tid: u64,
    /// Block height the trade committed in.
    pub block: u64,
    /// 0x action hash that produced the fill; empty for systemic prints.
    #[serde(default)]
    pub hash: String,
    /// Trade timestamp (unix ms).
    pub time: u64,
}

/// One entry from [`Info::predicted_fundings`].
///
/// `predicted_rate` is the CLAMPED rate actually charged at the boundary (bounded
/// by the per-asset cap, sign preserved); `next_funding_time` is the next aligned
/// per-asset settlement boundary (unix ms). Funding settles discretely at those
/// boundaries (1h default).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PredictedFunding {
    /// Market symbol (e.g. `"BTC"`).
    pub coin: String,
    /// Clamped funding rate charged at the boundary, fixed-point decimal string.
    pub predicted_rate: String,
    /// Next aligned per-asset settlement boundary (unix ms).
    pub next_funding_time: u64,
}

/// One leverage / margin band inside a [`MarketInfo::margin_tiers`] ladder.
///
/// Bands are upper-bound: a position with open interest at or below
/// `max_open_interest` may use up to `max_leverage` and is charged
/// `maint_margin_ratio` maintenance margin. `max_open_interest` is `None` on the
/// unbounded top tier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MarginTier {
    /// Upper open-interest bound for this band, decimal string; `None` = unbounded.
    #[serde(default)]
    pub max_open_interest: Option<String>,
    /// Maximum leverage multiple allowed in this band.
    pub max_leverage: u8,
    /// Maintenance margin ratio for this band, bps decimal string.
    pub maint_margin_ratio: String,
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
    /// Total MTF staked across all delegations, canonical decimal string.
    pub total_staked: String,
    /// Accrued but unclaimed rewards, canonical decimal string.
    pub pending_rewards: String,
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
    /// Staked MTF, canonical decimal string.
    pub amount: String,
    /// Delegation timestamp (unix ms).
    pub since_ms: u64,
}

/// One unbonding entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct UnbondingEntry {
    /// Validator address.
    pub validator: Address,
    /// Amount being unbonded, canonical decimal string.
    pub amount: String,
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
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum MarginMode {
    /// Cross margin — shared collateral across positions.
    #[default]
    Cross,
    /// Isolated margin.
    Isolated,
    /// Strict isolated margin.
    StrictIso,
}

/// Position mode. The deployed gateway emits this as `account_state.position_mode`
/// (the older `mode` margin-mode field is currently absent from its payload).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PositionMode {
    /// One-way (single net position per market).
    #[default]
    OneWay,
    /// Hedge (separate long/short legs).
    Hedge,
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
    /// Spot balances keyed by asset symbol. The deployed gateway maps each
    /// symbol to an [`AccountSpotBalance`] OBJECT (not a bare string). `BTreeMap`
    /// for deterministic key ordering.
    #[serde(default)]
    pub spot: std::collections::BTreeMap<String, AccountSpotBalance>,
}

/// One spot-asset balance inside [`Balances`] (account_state). Magnitudes are
/// fixed-point decimal strings; extra gateway fields (`pnl`, `evm_contract`)
/// are ignored. Distinct from [`SpotBalance`] (the `spot_clearinghouse_state`
/// element, which is keyed differently).
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AccountSpotBalance {
    /// Spot asset id (the token's id, e.g. MTF = 104).
    #[serde(default)]
    pub asset_id: Option<u32>,
    /// Total balance (fixed-point decimal string).
    pub total: String,
    /// Amount on hold in resting orders (fixed-point decimal string).
    #[serde(default)]
    pub hold: String,
    /// USD value of the balance (fixed-point decimal string).
    #[serde(default)]
    pub value: String,
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
    /// Margin mode. The deployed gateway does NOT currently emit `mode`; absent
    /// → default Cross (it sends `position_mode` instead, captured below).
    #[serde(default, rename = "mode")]
    pub margin_mode: MarginMode,
    /// Position mode (one-way / hedge) — the gateway's `position_mode` field.
    #[serde(default)]
    pub position_mode: PositionMode,
    /// Portfolio-margin opt-in state. Absent on the deployed gateway → false.
    #[serde(default)]
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
/// Per the `/info` contract (`market_info`). Magnitudes (`tick_size`,
/// `step_size`, `min_order`, ratios, `open_interest`) are CANONICAL decimal
/// **string** numerics — NOT the raw 1e8 / raw-lot planes; `max_leverage` is a
/// JSON number. Resolved by `coin` (the market symbol) — see [`Info::market_info`].
///
/// PLANE BRIDGE: `tick_size` is whole USDC while an order's `limit_px` is on the
/// 1e8 plane, and `step_size` / `min_order` are whole base units while an
/// order's `size` is raw lots (`whole × 10^sz_decimals`). Use
/// [`crate::round_order_to_grid`] to snap a desired price / size onto this grid.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MarketInfo {
    /// Market symbol (e.g. `"BTC"`) — the canonical market key.
    pub coin: String,
    /// DEPRECATED numeric asset id, retained only as a temporary indexer shim.
    /// Not a stable field: prefer `coin`. May be removed without a major bump.
    #[serde(default)]
    pub asset_id: u32,
    /// Market kind (`"perp"` / `"spot"`).
    pub kind: MarketKind,
    /// Size precision: raw order/position `size` = `whole_units × 10^sz_decimals`.
    /// Load-bearing for size encoding — NOT derivable from `step_size`.
    pub sz_decimals: u8,
    /// Mark price, whole-USDC decimal string (tick-snapped; `"0"` fallback).
    pub mark_px: String,
    /// Oracle price, whole-USDC decimal string (tick-snapped; `"0"` fallback).
    pub oracle_px: String,
    /// Tick size (smallest price increment), canonical whole-USDC decimal string
    /// (e.g. `"0.01"`). Scale to the order `limit_px` plane via `× 10^8`.
    pub tick_size: String,
    /// Step size (smallest size increment), canonical whole-base-unit decimal
    /// string (e.g. `"0.001"`). Scale to the order `size` plane via `× 10^sz_decimals`.
    pub step_size: String,
    /// Minimum order size, canonical whole-base-unit decimal string. Scale to
    /// the order `size` plane via `× 10^sz_decimals`.
    pub min_order: String,
    /// Maximum leverage multiple.
    pub max_leverage: u32,
    /// Maintenance margin ratio, fixed-point string.
    pub maint_margin_ratio: String,
    /// Initial margin ratio, fixed-point string.
    pub init_margin_ratio: String,
    /// Funding parameters.
    pub funding: Funding,
    /// Leverage / maintenance-margin ladder — upper-bound bands by open interest
    /// (the maintenance-margin schedule now rides inline on the market). Empty on
    /// markets that publish no tiered ladder.
    #[serde(default)]
    pub margin_tiers: Vec<MarginTier>,
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
    /// Returns the perp [`MarketInfo`] records.
    ///
    /// The deployed gateway serves `markets.data` as an OBJECT
    /// `{ "perp": [MarketInfo...], "spot": { pairs, tokens } }`, NOT a flat
    /// array. We decode that wrapper and return the `perp` markets (use
    /// [`Info::spot_meta`] for spot). Decoding `data` straight into a sequence
    /// (the old behaviour) failed with `invalid type: map, expected a sequence`.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn markets(&self) -> Result<Vec<MarketInfo>, ClientError> {
        #[derive(serde::Deserialize)]
        struct MarketsResp {
            #[serde(default)]
            perp: Vec<MarketInfo>,
        }
        let resp: MarketsResp = self
            .client
            .post_json("/info", &json!({ "type": "markets" }))
            .await?;
        Ok(resp.perp)
    }

    /// Fetch the L2 book snapshot for a market.
    ///
    /// Per the `/info` contract (`l2_book`): keyed by `coin` (the market symbol,
    /// e.g. `"BTC"`), `depth` levels per side. The `data` payload is
    /// `{ bids, asks }`.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn l2_book(&self, coin: &str, depth: u32) -> Result<L2Book, ClientError> {
        self.client
            .post_json(
                "/info",
                &json!({ "type": "l2_book", "coin": coin, "depth": depth }),
            )
            .await
    }

    /// Fetch the most recent public trade prints for a market (bounded window).
    ///
    /// Keyed by `coin` (the market symbol). Deep history is served by the
    /// gateway archive; this read returns the recent tape, newest-first.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn recent_trades(&self, coin: &str) -> Result<Vec<Trade>, ClientError> {
        #[derive(serde::Deserialize)]
        struct Resp {
            #[serde(default)]
            trades: Vec<Trade>,
        }
        let resp: Resp = self
            .client
            .post_json("/info", &json!({ "type": "recent_trades", "coin": coin }))
            .await?;
        Ok(resp.trades)
    }

    /// Fetch public trade prints for a market within a time window (unix ms).
    ///
    /// Keyed by `coin` (the market symbol); `start_time` / `end_time` bound a
    /// recent window. For deep history use the gateway archive query types.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn trades_by_time(
        &self,
        coin: &str,
        start_time: u64,
        end_time: u64,
    ) -> Result<Vec<Trade>, ClientError> {
        #[derive(serde::Deserialize)]
        struct Resp {
            #[serde(default)]
            trades: Vec<Trade>,
        }
        let resp: Resp = self
            .client
            .post_json(
                "/info",
                &json!({
                    "type": "trades_by_time",
                    "coin": coin,
                    "start_time": start_time,
                    "end_time": end_time,
                }),
            )
            .await?;
        Ok(resp.trades)
    }

    /// Fetch the predicted per-asset funding rates and their next settlement
    /// boundaries. No parameters; returns one entry per active market.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn predicted_fundings(&self) -> Result<Vec<PredictedFunding>, ClientError> {
        self.client
            .post_json("/info", &json!({ "type": "predicted_fundings" }))
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

    /// Fetch the staking state for an account, keyed by `address` (0x hex).
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

    /// `candle_snapshot` — historical OHLCV bars for `(coin, interval)` over a
    /// window. This is the single candle query: archive-first, with a fold
    /// fallback derived from the public trade stream.
    ///
    /// `coin` is a market **symbol** (e.g. `"BTC"`). `start_time` / `end_time`
    /// bound the window (unix ms). Bars come oldest-first; the newest is the
    /// still-forming bar. An empty vec is the honest-empty answer for an
    /// unsupported `interval` or a market with no indexed trades in the window.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn candle_snapshot(
        &self,
        coin: &str,
        interval: &str,
        start_time: u64,
        end_time: u64,
    ) -> Result<Vec<Candle>, ClientError> {
        #[derive(serde::Deserialize)]
        struct Resp {
            #[serde(default)]
            candles: Vec<Candle>,
        }
        let resp: Resp = self
            .client
            .post_json(
                "/info",
                &json!({
                    "type": "candle_snapshot",
                    "req": {
                        "coin": coin,
                        "interval": interval,
                        "start_time": start_time,
                        "end_time": end_time,
                    },
                }),
            )
            .await?;
        Ok(resp.candles)
    }

    /// `market_info` — rich single-market snapshot keyed by `coin` (the market
    /// symbol, e.g. `"BTC"`).
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn market_info(&self, coin: &str) -> Result<MarketInfo, ClientError> {
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
            "coin": "BTC",
            "asset_id": 0,
            "kind": "perp",
            "sz_decimals": 5,
            "mark_px": "50000",
            "oracle_px": "50000",
            "tick_size": "0.01",
            "step_size": "0.1",
            "min_order": "0.1",
            "max_leverage": 50,
            "maint_margin_ratio": "5000",
            "init_margin_ratio": "10000",
            "funding": {
                "rate_per_hr": "1000",
                "cap_per_hr": "50000",
                "interval_ms": 3600000u64,
                "next_payment_ts": 1735693200000u64
            },
            "margin_tiers": [
                { "max_open_interest": "100000", "max_leverage": 50, "maint_margin_ratio": "100" },
                { "max_open_interest": null, "max_leverage": 5, "maint_margin_ratio": "1000" }
            ],
            "mark_source": "MedianOfOraclesAndMid",
            "fba_enabled": false,
            "open_interest": "5000000000"
        });
        let m: MarketInfo = serde_json::from_value(data).unwrap();
        assert_eq!(m.coin, "BTC");
        assert_eq!(m.asset_id, 0);
        assert_eq!(m.kind, MarketKind::Perp);
        assert_eq!(m.sz_decimals, 5);
        assert_eq!(m.mark_px, "50000");
        assert_eq!(m.oracle_px, "50000");
        assert_eq!(m.tick_size, "0.01");
        assert_eq!(m.max_leverage, 50);
        assert_eq!(m.funding.interval_ms, 3_600_000);
        assert_eq!(m.mark_source, "MedianOfOraclesAndMid");
        assert_eq!(m.open_interest, "5000000000");
        // Inline maintenance-margin ladder; `null` upper bound = unbounded top.
        assert_eq!(m.margin_tiers.len(), 2);
        assert_eq!(
            m.margin_tiers[0].max_open_interest.as_deref(),
            Some("100000")
        );
        assert_eq!(m.margin_tiers[0].max_leverage, 50);
        assert!(m.margin_tiers[1].max_open_interest.is_none());
        // Fixed-point magnitudes serialize back as strings; kind is lowercase.
        let j = serde_json::to_value(&m).unwrap();
        assert_eq!(j["kind"], "perp");
        assert_eq!(j["coin"], "BTC");
        assert!(j["sz_decimals"].is_number());
        assert!(j["tick_size"].is_string());
        assert!(j["open_interest"].is_string());
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
            "mode": "Cross",
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
                "spot": { "ETH": { "asset_id": 102, "total": "5000000000", "hold": "0", "value": "0" } }
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
            a.balances.spot.get("ETH").map(|b| b.total.as_str()),
            Some("5000000000")
        );
        // Round-trips.
        let dec: AccountState = serde_json::from_str(&serde_json::to_string(&a).unwrap()).unwrap();
        assert_eq!(a, dec);
    }

    /// Decode the DEPLOYED gateway `account_state.data` shape (probed live
    /// 2026-06): it sends `position_mode` + `abstraction` and OMITS `mode` +
    /// `pm_enabled`; `balances` carries an extra `usdc_evm_contract`. The
    /// pre-fix struct failed here with `missing field 'mode'`.
    #[test]
    fn account_state_decodes_live_gateway_shape() {
        let data = serde_json::json!({
            "abstraction": "unified",
            "address": "0x000000000000000000000000000000000000beef",
            "account_value": "100000000",
            "free_collateral": "100000000",
            "maint_margin": "0",
            "init_margin": "0",
            "health": "100000000",
            "tier": "Safe",
            "position_mode": "one_way",
            "positions": [{
                "asset": 2, "size": "67", "entry": "74.36", "upnl": "-3.64",
                "isolated": false, "lev": 7,
                "funding": "0", "liq": "0", "margin": "1.49", "notional": "46.18", "roe": "0"
            }],
            "balances": {
                "usdc": "100000000",
                // gateway maps each spot symbol to an OBJECT (not a string)
                "spot": { "MTF": { "asset_id": 104, "evm_contract": null, "hold": "0",
                                   "pnl": null, "total": "10", "value": "50" } },
                "usdc_evm_contract": "0x0000000000000000000000000000000000010000"
            }
        });
        let a: AccountState = serde_json::from_value(data).unwrap();
        assert_eq!(a.margin_mode, MarginMode::Cross); // defaulted (absent)
        assert_eq!(a.position_mode, PositionMode::OneWay);
        assert!(!a.pm_enabled); // defaulted (absent)
        assert_eq!(a.account_value, "100000000");
        assert_eq!(a.tier, Tier::Safe);
        assert_eq!(a.positions.len(), 1); // rich position (extra fields ignored)
        assert_eq!(a.positions[0].leverage, 7);
        assert_eq!(a.balances.usdc, "100000000");
        assert_eq!(
            a.balances.spot.get("MTF").map(|b| b.total.as_str()),
            Some("10")
        );
    }

    /// Decode the DEPLOYED gateway `markets.data` shape: an object
    /// `{ "perp": [...], "spot": {...} }`, not a flat array. markets() must
    /// return the perp records (pre-fix: `invalid type: map, expected sequence`).
    #[test]
    fn markets_decodes_perp_spot_object() {
        #[derive(serde::Deserialize)]
        struct MarketsResp {
            #[serde(default)]
            perp: Vec<MarketInfo>,
        }
        let data = serde_json::json!({
            "perp": [{
                "coin": "BTC", "asset_id": 0, "kind": "perp", "sz_decimals": 5,
                "mark_px": "64000", "oracle_px": "64000", "mid_px": "64000",
                "mark_source": "oracle_median", "fba_enabled": false,
                "change_24h": "0", "day_ntl_vlm": "0", "premium": "0", "prev_day_px": "64000",
                "tick_size": "1000000", "step_size": "1", "min_order": "1",
                "max_leverage": 50, "init_margin_ratio": "200", "maint_margin_ratio": "300",
                "margin_tiers": [
                    { "max_open_interest": "100000", "max_leverage": 50, "maint_margin_ratio": "100" },
                    { "max_open_interest": null, "max_leverage": 5, "maint_margin_ratio": "1000" }
                ],
                "open_interest": "0", "funding": {
                    "rate_per_hr": "0", "cap_per_hr": "400", "interval_ms": 3600000,
                    "next_payment_ts": 0 }
            }],
            "spot": { "pairs": [], "tokens": [] }
        });
        let resp: MarketsResp = serde_json::from_value(data).unwrap();
        assert_eq!(resp.perp.len(), 1);
        assert_eq!(resp.perp[0].coin, "BTC");
        assert_eq!(resp.perp[0].margin_tiers.len(), 2);
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

    /// Decode a `candle_snapshot` bar using the compact single-letter wire keys.
    #[test]
    fn candle_snapshot_bar_decodes_compact_keys() {
        let data = serde_json::json!({
            "s": "BTC",
            "i": "1m",
            "t": 1_700_000_040_000u64,
            "T": 1_700_000_099_999u64,
            "o": "67000.0",
            "c": "67042.5",
            "h": "67080.0",
            "l": "66990.0",
            "v": "12.5",
            "q": "838031.25",
            "n": 37
        });
        let bar: Candle = serde_json::from_value(data).unwrap();
        assert_eq!(bar.coin, "BTC");
        assert_eq!(bar.interval, "1m");
        assert_eq!(bar.open_time, 1_700_000_040_000);
        assert_eq!(bar.close_time, 1_700_000_099_999);
        assert_eq!(bar.close, "67042.5");
        assert_eq!(bar.volume, "12.5");
        assert_eq!(bar.quote_volume, "838031.25");
        assert_eq!(bar.num_trades, 37);
        // Round-trips back to the compact keys.
        let j = serde_json::to_value(&bar).unwrap();
        assert_eq!(j["s"], "BTC");
        assert!(j["o"].is_string());
        assert!(j["t"].is_number());
        assert!(j["n"].is_number());
    }

    /// Decode a public `trades_by_time` / `recent_trades` print: symbol coin,
    /// A/B side, 0x action hash, big-integer `tid`.
    #[test]
    fn trade_decodes_symbol_coin_and_hash() {
        let data = serde_json::json!({
            "coin": "BTC",
            "px": "61643.70000000",
            "sz": "0.00024",
            "side": "A",
            "tid": 18232248797686447553u64,
            "block": 37697,
            "hash": "0xd3c94e061264a4e9fd3090f0a65da636377737bc7b8e6e5b0ee839ed3e5d07d7",
            "time": 1783000783768u64
        });
        let t: Trade = serde_json::from_value(data).unwrap();
        assert_eq!(t.coin, "BTC");
        assert_eq!(t.side, "A");
        assert_eq!(t.tid, 18_232_248_797_686_447_553);
        assert_eq!(t.block, 37697);
        assert!(t.hash.starts_with("0x"));
        // A systemic print with no action hash decodes to an empty string.
        let systemic = serde_json::json!({
            "coin": "BTC", "px": "1", "sz": "1", "side": "B",
            "tid": 1u64, "block": 1, "time": 1u64
        });
        let s: Trade = serde_json::from_value(systemic).unwrap();
        assert!(s.hash.is_empty());
    }

    /// Decode a `predicted_fundings` entry: clamped rate + next boundary.
    #[test]
    fn predicted_funding_decodes() {
        let data = serde_json::json!({
            "coin": "ETH",
            "predicted_rate": "0.0087084893337279276017913756",
            "next_funding_time": 1783011600000u64
        });
        let p: PredictedFunding = serde_json::from_value(data).unwrap();
        assert_eq!(p.coin, "ETH");
        assert_eq!(p.next_funding_time, 1_783_011_600_000);
        assert!(p.predicted_rate.starts_with("0.008"));
    }
}
