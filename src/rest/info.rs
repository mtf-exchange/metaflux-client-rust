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
//!   [`Info::candle_snapshot`], [`Info::predicted_fundings`],
//!   [`Info::funding_history`].
//! - **Account reads** — [`Info::account_state`], [`Info::open_orders`],
//!   [`Info::web_data`], [`Info::spot_clearinghouse_state`],
//!   [`Info::staking_state`], [`Info::pm_summary`], [`Info::order_status_by_oid`],
//!   [`Info::historical_orders`], [`Info::user_funding`],
//!   [`Info::spot_margin_state`], [`Info::earn_state`], [`Info::user_fills`],
//!   [`Info::user_fills_by_time`], [`Info::rfq_user`],
//!   [`Info::active_asset_data`], [`Info::agents`], [`Info::sub_accounts`].
//! - **Static / misc** — [`Info::node_info`], [`Info::spot_meta`],
//!   [`Info::fee_schedule`], [`Info::vault_state`], [`Info::rfq_open`],
//!   [`Info::encode_action`].

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::error::ClientError;
use crate::rest::RestClient;
use crate::types::vault::VaultState;
use crate::wallet::Address;

/// `info` namespace handle. Constructed via [`RestClient::info`].
#[derive(Debug)]
pub struct Info<'a> {
    pub(crate) client: &'a RestClient,
}

/// One level of the L2 book.
///
/// Per the `/info` `l2_book` wire: `px` / `sz` are CANONICAL decimal strings
/// (string-typed so precision survives past 2^53) — `px` is tick-snapped whole
/// USDC (e.g. `"62500.12"`), `sz` is whole base units (e.g. `"1.5"`), NOT the
/// raw 1e8 / raw-lot planes. `n_orders` is a JSON number.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct L2Level {
    /// Price, canonical whole-USDC decimal string (tick-snapped).
    pub px: String,
    /// Aggregate size at this price, canonical whole-base-unit decimal string.
    pub sz: String,
    /// Number of resting orders at this price.
    pub n_orders: u32,
}

/// L2 book snapshot.
///
/// Per the `/info` contract (`l2_book`) the `data` payload is
/// `{ "bids": [...], "asks": [...] }` (some builds also echo `coin`). A spot
/// pair coin (name `"BTC/USDC"` or pair id) now renders real spot depth here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct L2Book {
    /// Echo of the requested coin (market symbol or spot pair name/id). Absent
    /// on some node builds → empty.
    #[serde(default)]
    pub coin: String,
    /// Bid side (descending by price).
    pub bids: Vec<L2Level>,
    /// Ask side (ascending by price).
    pub asks: Vec<L2Level>,
}

/// Optional aggregation params for the `l2_book` read (REST + WS).
///
/// The gateway groups the raw book DETERMINISTICALLY away from the spread and
/// sums sizes into coarser price buckets, then caps the returned depth. All
/// three are optional; omit for the ungrouped full book.
///
/// - `n_sig_figs`: significant-figure grouping, `2..=5`. Coarser (fewer figs) =
///   wider buckets.
/// - `mantissa`: `1 | 2 | 5`, VALID ONLY with `n_sig_figs == 5` — sub-divides
///   the finest sig-fig grid.
/// - `n_levels`: max levels returned per side (`≥ 1`).
///
/// On the WS ack the server echoes `n_sig_figs` and `n_levels`, and `mantissa`
/// ONLY when it is not 1 — do not ack-match on exact param equality.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct L2BookParams {
    /// Significant-figure grouping (`2..=5`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n_sig_figs: Option<u32>,
    /// Mantissa sub-division (`1 | 2 | 5`); valid only with `n_sig_figs == 5`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mantissa: Option<u32>,
    /// Max levels returned per side (`≥ 1`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n_levels: Option<u32>,
}

/// Order side as the read wire spells it: the one-letter tokens `"B"` (buy /
/// bid) and `"A"` (sell / ask).
///
/// The same token pair is used by `open_orders`, `order_status`, `rfq_open` and
/// `fba_batch_state`. It is NOT the position leg label — see [`PositionSide`],
/// which spells `"long"` / `"short"`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrderSide {
    /// Resting buy (`"B"`).
    #[serde(rename = "B")]
    Bid,
    /// Resting sell (`"A"`).
    #[serde(rename = "A")]
    Ask,
}

/// Trigger detail attached to an [`OpenOrder`].
///
/// A resting book order's trigger block carries only `trigger_px` +
/// `trigger_above`. A parked off-book TP / SL / stop row (its order's `tif` is
/// `"trigger"`) additionally carries `is_parked`, `is_market`, and `limit_px` —
/// `is_market` is `true` for a market trigger (`limit_px` `null`) and `false`
/// for a limit trigger (`limit_px` a decimal string). Those three are absent on
/// a resting-book trigger block, hence `Option`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct OrderTrigger {
    /// Trigger price, tick-snapped decimal string.
    pub trigger_px: String,
    /// `true` = fire when the mark rises to `trigger_px`; `false` = when it
    /// falls.
    pub trigger_above: bool,
    /// `true` on a parked (off-book) TP / SL / stop row; absent on a resting
    /// book order's trigger block.
    #[serde(default)]
    pub is_parked: Option<bool>,
    /// `true` = market trigger; `false` = limit trigger. Present only on a
    /// parked row.
    #[serde(default)]
    pub is_market: Option<bool>,
    /// Limit price for a limit trigger, decimal string; `null` for a market
    /// trigger. Present only on a parked row.
    #[serde(default)]
    pub limit_px: Option<String>,
}

/// One open order in an [`OpenOrders`] snapshot — the canonical order row.
///
/// The node renders ONE row shape for the REST `open_orders` read, the WS
/// `open_orders` snapshot, and the inner `order` object of a WS `order_updates`
/// record. The row set covers perp resting orders, spot resting orders, and
/// parked TP / SL / stop triggers, so a protective leg needs no second read.
///
/// `px` / `sz` / `orig_sz` are CANONICAL decimal strings — `px` is tick-snapped
/// whole USDC (positive for **both** sides), the sizes are whole base units.
/// `oid` / `inserted_at` are bare integers; `coin` is the market symbol (a spot
/// row uses the pair name, e.g. `"BTC/USDC"`).
///
/// The node emits the real resting `oid`, `inserted_at`, and the submit-time
/// `cloid` (when the order carried one), so a client can bind a resting order to
/// its own submission by `cloid` — or cancel it by `oid` — instead of a
/// (px,sz) heuristic that collides across strategies on equal legs (the
/// multi-strategy co-residency case).
///
/// `tif` stays a `String`: a parked trigger row passes the non-TIF token
/// `"trigger"`, which a closed TIF enum would reject.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct OpenOrder {
    /// Real resting-order id (cancellable per-oid).
    pub oid: u64,
    /// Market symbol (e.g. `"BTC"`) or spot pair name (`"BTC/USDC"`).
    pub coin: String,
    /// Side, `"B"` (bid) / `"A"` (ask).
    pub side: OrderSide,
    /// Limit price, canonical whole-USDC decimal string (tick-snapped). A parked
    /// trigger row carries its trigger price here.
    pub px: String,
    /// Remaining size, canonical whole-base-unit decimal string.
    pub sz: String,
    /// Original submitted size, decimal string. The snapshot rows carry `null` —
    /// the committed book keeps only the remaining size.
    #[serde(default)]
    pub orig_sz: Option<String>,
    /// Submit-time client order id (`0x`-hex), when the order carried one —
    /// the id-based binding key for reconcile / co-residency. `null` otherwise.
    #[serde(default)]
    pub cloid: Option<String>,
    /// Time-in-force token (`"alo"` / `"ioc"` / `"gtc"`), or `"trigger"` on a
    /// parked TP / SL / stop row.
    #[serde(default)]
    pub tif: Option<String>,
    /// Whether the order may only reduce an existing position. Parked triggers
    /// are protective legs and read `true`.
    #[serde(default)]
    pub reduce_only: Option<bool>,
    /// Trigger detail when the order is registered for a trigger, else `null`.
    #[serde(default)]
    pub trigger: Option<OrderTrigger>,
    /// Insertion timestamp (unix ms). A parked trigger reports its registration
    /// timestamp here.
    pub inserted_at: u64,
}

/// `open_orders` response — open orders for one account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct OpenOrders {
    /// Echo of the resolved account address (`0x` lowercase hex).
    pub address: Address,
    /// Open orders: perp resting, spot resting, and parked triggers.
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
/// by the per-asset cap, sign preserved); `next_funding_ts` is the next aligned
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
    pub next_funding_ts: u64,
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

/// The staking facet body, without the account address.
///
/// The standalone `staking_state` read carries the address beside these fields;
/// the `web_data` read nests the same body under `staking.state` and drops the
/// address (it is carried once at the top). One type serves both.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct StakingSnapshot {
    /// Total MTF staked across all delegations, canonical decimal string.
    pub total_staked: String,
    /// Active delegations (unclaimed rewards live per-delegation).
    #[serde(default)]
    pub delegations: Vec<Delegation>,
    /// Queued undelegations awaiting maturity.
    #[serde(default)]
    pub pending_unstakes: Vec<PendingUnstake>,
}

/// `staking_state` response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct StakingState {
    /// Echo of requested address.
    pub address: Address,
    /// The staking facet body.
    #[serde(flatten)]
    pub state: StakingSnapshot,
}

/// One delegation entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Delegation {
    /// Validator address.
    pub validator: Address,
    /// Staked MTF, canonical decimal string.
    pub amount: String,
    /// Backing timestamp for this delegation (unix ms) — the last-claim ts.
    pub since_ts: u64,
    /// Accrued but unclaimed rewards for this delegation, canonical decimal
    /// string.
    pub pending_rewards: String,
}

/// One pending (queued) undelegation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PendingUnstake {
    /// Amount being unstaked, canonical decimal string.
    pub amount: String,
    /// Timestamp (unix ms) at which the unstake matures / becomes claimable.
    pub matures_at_ts: u64,
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

/// Account margin abstraction class — the margin model the account runs under.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Abstraction {
    /// Cross-collateral margin (the default).
    #[default]
    Unified,
    /// Portfolio margin (the account is enrolled).
    Portfolio,
}

/// Position mode, from `account_state.position_mode`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PositionMode {
    /// One-way (single net position per market).
    #[default]
    OneWay,
    /// Hedge (separate long/short legs).
    Hedge,
}

/// Hedge-leg label on an [`AccountPosition`] — `"long"` / `"short"`.
///
/// A one-way account omits the field, so it is always `Option`. This is NOT the
/// order-book side token — see [`OrderSide`], which spells `"B"` / `"A"`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PositionSide {
    /// Long leg.
    Long,
    /// Short leg.
    Short,
}

/// One open position inside a [`DexPositions`] group.
///
/// Every monetary magnitude is a whole-USDC decimal string. `size` is SIGNED
/// (negative = short) and rides the market's own size plane; note the key is
/// `size`, not the `sz` the order / book / trade rows use. `lev` is the user's
/// CHOSEN leverage, not an effective ratio.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AccountPosition {
    /// Market symbol (e.g. `"BTC"`).
    pub coin: String,
    /// Signed position size, decimal string (negative = short).
    pub size: String,
    /// Volume-weighted entry price, whole-USDC decimal string.
    #[serde(rename = "entry")]
    pub entry_px: String,
    /// Unrealised PnL (signed), whole-USDC decimal string.
    #[serde(rename = "upnl")]
    pub unrealised_pnl: String,
    /// Whether this position uses isolated margin.
    pub isolated: bool,
    /// Chosen leverage multiple.
    #[serde(rename = "lev")]
    pub leverage: u32,
    /// Liquidation price, whole-USDC decimal string.
    #[serde(rename = "liq")]
    pub liquidation_px: String,
    /// Return on equity, decimal-fraction string.
    pub roe: String,
    /// Cumulative funding paid (positive) / received (negative) over the
    /// position's life, whole-USDC decimal string.
    pub funding: String,
    /// Initial margin posted for the position, whole-USDC decimal string.
    #[serde(rename = "margin")]
    pub margin_used: String,
    /// Maintenance margin required by the position, whole-USDC decimal string.
    pub maint_margin: String,
    /// Position notional at the mark, whole-USDC decimal string.
    #[serde(rename = "notional")]
    pub position_value: String,
    /// Hedge-leg label; absent on a one-way account.
    #[serde(default)]
    pub side: Option<PositionSide>,
}

/// The positions of one dex inside [`AccountState::clearinghouse_state`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DexPositions {
    /// Open positions hosted by this dex.
    #[serde(default)]
    pub positions: Vec<AccountPosition>,
}

/// One token balance row inside [`AccountState::balances`].
///
/// The USDC row is always first. A token row with neither a spendable balance
/// nor an escrow hold is skipped, so absence means zero.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TokenBalance {
    /// Token asset id (USDC = 100).
    pub asset: u32,
    /// Token symbol (e.g. `"USDC"`), else `asset:<id>`.
    pub name: String,
    /// Total balance (spendable + hold), decimal string.
    pub total: String,
    /// Amount held in escrow by resting orders, decimal string.
    pub hold: String,
}

/// `account_state` response — rich per-account snapshot keyed by `address`.
///
/// Every monetary magnitude is a whole-USDC decimal **string** so precision
/// survives the JS safe-integer limit; `health` may be negative.
///
/// Positions are grouped by dex: the core dex key is the empty string `""` and
/// is ALWAYS present, and a MIP-3 deployer dex keys on the deployer's lowercase
/// 0x-hex address. `height` / `time` stamp the committed block the snapshot was
/// read at, so a client can reject a stale snapshot.
///
/// Only `health_deferred` is optional. Every other field is one the node always
/// emits, so decoding FAILS if the server drops or renames one. A missing money
/// field must never read as an empty account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AccountState {
    /// Echo of the requested address.
    pub address: Address,
    /// Equity including unrealised PnL, whole-USDC decimal string.
    pub account_value: String,
    /// Equity minus initial margin held by open positions, decimal string.
    pub free_collateral: String,
    /// Initial margin requirement, decimal string.
    pub init_margin: String,
    /// `account_value - maint_margin`, decimal string; can be negative.
    pub health: String,
    /// Liquidation tier.
    pub tier: Tier,
    /// `true` when the risk engine DEFERS on this account: it holds a leg no
    /// risk path can price. `tier` and `health` are then NOT solvency
    /// statements, and the maintenance margin reads 0 for want of a price.
    /// The node emits the key only when it is true, so absent means `false`.
    #[serde(default)]
    pub health_deferred: bool,
    /// Margin abstraction class (`"unified"` / `"portfolio"`).
    pub abstraction: Abstraction,
    /// Position mode (one-way / hedge).
    pub position_mode: PositionMode,
    /// Open positions grouped by dex key. `BTreeMap` for deterministic key
    /// ordering.
    pub clearinghouse_state: std::collections::BTreeMap<String, DexPositions>,
    /// Token balances; the USDC row is first.
    pub balances: Vec<TokenBalance>,
    /// Portfolio-margin maintenance margin, whole-USDC decimal string. Always
    /// present; `"0"` when the account is not enrolled.
    pub pm_maint_margin: String,
    /// Portfolio-margin net account value, whole-USDC decimal string.
    pub pm_net_value: String,
    /// Portfolio-margin concentration penalty, whole-USDC decimal string.
    pub pm_concentration_penalty: String,
    /// Committed block height the snapshot was read at.
    pub height: u64,
    /// Committed block timestamp the snapshot was read at (unix ms).
    pub time: u64,
}

impl AccountState {
    /// Positions of the CORE dex (the `""` key), which the node always emits.
    #[must_use]
    pub fn core_positions(&self) -> &[AccountPosition] {
        self.clearinghouse_state
            .get("")
            .map_or(&[], |d| d.positions.as_slice())
    }
}

/// EVM-side contract binding for a registered token.
///
/// Present on a [`SpotToken`] / [`PerpUnderlyingToken`] when the token has a
/// deployed EVM contract; the node emits it as an OBJECT (not a bare address
/// string). `evm_extra_wei_decimals` is the SIGNED decimal offset between the
/// token's native `wei_decimals` and its EVM ERC-20 decimals (can be negative).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TokenEvmContract {
    /// EVM contract address (`0x`-hex, 20 bytes).
    pub address: String,
    /// Signed decimal offset (native `wei_decimals` → EVM ERC-20 decimals).
    pub evm_extra_wei_decimals: i32,
}

/// The registered underlying-token block on a perp [`MarketInfo`].
///
/// OMITTED entirely (the `token` field is `None`) when the perp has no
/// registered underlying token — the node ABSENTS the key rather than emitting
/// `null`. Mirrors the spot [`SpotToken`] registry entry but carries
/// `circulating_supply` (NOT `total_supply`, which is the spot token-row key).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PerpUnderlyingToken {
    /// Token asset id.
    pub id: u32,
    /// Native (ERC-20-style) token decimals.
    pub wei_decimals: u8,
    /// 32-byte token id (`0x`-hex).
    pub token_id: String,
    /// 20-byte system address (`0x`-hex).
    pub system_address: String,
    /// EVM contract binding, when the token has a deployed contract.
    #[serde(default)]
    pub evm_contract: Option<TokenEvmContract>,
    /// Whether this is the canonical registration for the token.
    pub is_canonical: bool,
    /// Circulating supply, decimal string.
    pub circulating_supply: String,
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
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Absent on the STATIC `markets_meta` read (dynamic) → defaults to empty.
    #[serde(default)]
    pub mark_px: String,
    /// Oracle price, whole-USDC decimal string (tick-snapped; `"0"` fallback).
    /// Absent on the STATIC `markets_meta` read (dynamic) → defaults to empty.
    #[serde(default)]
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
    /// Funding parameters. Absent on the STATIC `markets_meta` read → defaults.
    #[serde(default)]
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
    /// Absent on the STATIC `markets_meta` read (dynamic) → defaults to empty.
    #[serde(default)]
    pub open_interest: String,
    /// Registered underlying-token block for this perp. Present on the
    /// `markets_meta` / `market_info` reads when the perp has a registered
    /// underlying token; OMITTED (→ `None`) otherwise. Carries the token's
    /// EVM binding + `circulating_supply`.
    #[serde(default)]
    pub token: Option<PerpUnderlyingToken>,
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
    /// Taker fee in bps, decimal STRING (e.g. `"5"`). The node emits this as a
    /// string (dbps/10 `.to_string()`); it is NOT a JSON number.
    pub taker_fee_bps: String,
    /// Minimum order notional (USDC cents) as a decimal string; `"0"` if unset.
    pub min_notional: String,
    /// Whether the pair is active for trading.
    pub active: bool,
    /// Mark price, whole-USDC decimal string. Absent on some reads → empty.
    #[serde(default)]
    pub mark_px: String,
    /// Mid price, whole-USDC decimal string; `None` when no two-sided book.
    #[serde(default)]
    pub mid_px: Option<String>,
    /// Previous-day price, whole-USDC decimal string; `None` when unavailable.
    #[serde(default)]
    pub prev_day_px: Option<String>,
    /// 24h notional volume, decimal string; `"0"` if unset.
    #[serde(default)]
    pub day_ntl_vlm: String,
    /// Circulating supply of the base token, decimal string; `"0"` if unset.
    #[serde(default)]
    pub circulating_supply: String,
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
    /// 32-byte token id (`0x`-hex). Absent on older reads → empty.
    #[serde(default)]
    pub token_id: String,
    /// 20-byte system address (`0x`-hex). Absent on older reads → empty.
    #[serde(default)]
    pub system_address: String,
    /// EVM contract binding, when the token has a deployed contract. The node
    /// emits this as an OBJECT (`{address, evm_extra_wei_decimals}`), not a
    /// bare address string.
    #[serde(default)]
    pub evm_contract: Option<TokenEvmContract>,
    /// Whether this is the canonical registration for the token.
    #[serde(default)]
    pub is_canonical: bool,
    /// Total supply of the token, decimal string; `"0"` if unset. (The perp
    /// underlying-token block carries `circulating_supply` instead — different
    /// key, do not unify.)
    #[serde(default)]
    pub total_supply: String,
}

/// `spot_meta` response — spot pair universe + token registry.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SpotMeta {
    /// Registered spot pairs (token-registration sentinels excluded).
    pub pairs: Vec<SpotPair>,
    /// Token registry with per-token decimals.
    pub tokens: Vec<SpotToken>,
}

/// One spot balance inside a [`SpotClearinghouseState`].
///
/// Same `{asset, name, total, hold}` token-row shape the `account_state`
/// `balances` array uses. Unlike that array this read keeps a token whose
/// balance is entirely zero.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SpotBalance {
    /// Spot asset id.
    pub asset: u32,
    /// Human name for the asset, else `asset:<id>`.
    pub name: String,
    /// Total balance (spendable + hold), decimal string.
    pub total: String,
    /// Amount held in escrow by resting orders, decimal string.
    pub hold: String,
}

/// `spot_clearinghouse_state` response — per-account spot token balances.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SpotClearinghouseState {
    /// Echo of the requested address.
    pub address: Address,
    /// Spot balances held by the account.
    pub balances: Vec<SpotBalance>,
    /// Committed block height the snapshot was read at.
    pub height: u64,
    /// Committed block timestamp the snapshot was read at (unix ms).
    pub time: u64,
}

/// One canonical fill record.
///
/// The node fill serializer (`user_fills` / `order_status` filled branch) emits
/// this shape: `coin` is the market SYMBOL (a spot pair uses the pair name), `px`
/// is the 8-dp tape price string, and `sz` / `start_position` are size-plane
/// decimal strings. `side` is the aggressor code (`"B"` buy / `"A"` sell). All
/// money / size magnitudes ride the wire as strings so precision survives past
/// 2^53.
///
/// `block` is present on a node-ring fill (the committed height) and ABSENT on an
/// archive-normalized fill — hence `Option`. A SPOT fill renders `sz` on the RAW
/// integer plane today (the node-tape `szd=0` pin). The TARGET is the human plane
/// (owner-ruled); the flip rides a fork-gated node-tape fix. The field stays a
/// decimal string either way — read it verbatim, do not assume a plane.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Fill {
    /// Market symbol (`"MTF"`) or spot pair name (`"MTF/USDC"`).
    pub coin: String,
    /// Aggressor taker side: `"B"` (buy) or `"A"` (sell).
    pub side: String,
    /// Fill price, 8-dp tape decimal string (trailing zeros kept).
    pub px: String,
    /// Fill size, size-plane decimal string.
    pub sz: String,
    /// Consensus fill timestamp (unix ms).
    pub time: u64,
    /// Resting-order id the fill matched.
    pub oid: u64,
    /// Unique trade id.
    pub tid: u64,
    /// Fee charged, whole-USDC decimal string.
    pub fee: String,
    /// Realized PnL of the closed portion, signed decimal string.
    pub closed_pnl: String,
    /// Human direction label (`"Open Long"` / `"Close Short"` / `"Buy"` …).
    pub dir: String,
    /// Signed position size BEFORE the fill, size-plane decimal string.
    pub start_position: String,
    /// Committed block height. Present on a node-ring fill; absent on an
    /// archive-normalized fill.
    #[serde(default)]
    pub block: Option<u64>,
    /// Trace hash of the action that produced the fill; empty for a systemic /
    /// maker-leg fill with no signed taker action.
    #[serde(default)]
    pub hash: String,
}

/// One resting order inside an [`OrderStatus::Resting`] result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RestingOrderStatus {
    /// Resting-order id (cancellable per-oid).
    pub oid: u64,
    /// Market symbol (perp) or spot pair name.
    pub coin: String,
    /// Side, `"B"` (bid) / `"A"` (ask).
    pub side: OrderSide,
    /// Limit price, tick-snapped decimal string.
    pub px: String,
    /// Remaining size, size-plane decimal string.
    pub sz: String,
    /// Insertion timestamp (unix ms).
    pub inserted_at: u64,
    /// Submit-time client order id (`0x`-hex), when the order carried one;
    /// `null` otherwise.
    #[serde(default)]
    pub cloid: Option<String>,
}

/// One parked trigger inside an [`OrderStatus::Triggered`] result.
///
/// A TP / SL / stop entry awaiting its mark cross. `is_market` is `true` for a
/// market trigger (`limit_px` `null`) and `false` for a limit trigger
/// (`limit_px` a decimal string).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TriggerOrderStatus {
    /// Trigger-order id.
    pub oid: u64,
    /// Market symbol (perp) or spot pair name.
    pub coin: String,
    /// Side, `"B"` (bid) / `"A"` (ask).
    pub side: OrderSide,
    /// Trigger price, tick-snapped decimal string.
    pub trigger_px: String,
    /// `true` = fire when mark rises to `trigger_px`; `false` = when it falls.
    pub trigger_above: bool,
    /// Order size, size-plane decimal string.
    pub sz: String,
    /// Registration timestamp (unix ms).
    pub registered_at: u64,
    /// Whether the trigger has already fired.
    pub fired: bool,
    /// `true` = market trigger; `false` = limit trigger.
    pub is_market: bool,
    /// Limit price for a limit trigger, decimal string; `null` for a market
    /// trigger.
    #[serde(default)]
    pub limit_px: Option<String>,
}

/// `order_status` response — single-order lifecycle lookup by `oid` or `cloid`.
///
/// The node resolves the FIRST hit: a live resting order, then a parked trigger,
/// then the most recent matching fill, else unknown. Tagged by the wire `status`
/// field. A cloid-only query resolves resting / triggered hits only — the fill
/// ring is oid-keyed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum OrderStatus {
    /// A live resting order.
    Resting {
        /// The resting order.
        order: RestingOrderStatus,
    },
    /// A parked trigger awaiting its mark cross.
    Triggered {
        /// The parked trigger.
        trigger: TriggerOrderStatus,
    },
    /// A terminal fill (the most recent matching leg in the ring).
    Filled {
        /// The matching fill.
        fill: Fill,
    },
    /// Never seen, or evicted from the ring.
    Unknown,
}

/// One record inside a [`HistoricalOrders`] response.
///
/// The node fold emits the 8 Always fields per executed order; a gateway-archive
/// row adds the optional converted superset (`limit_px` / `avg_px` / `sz` /
/// `orig_sz` / `total_sz` / `tif` / `reduce_only` / `cloid` / `cancel_reason` /
/// `error`) and `block`. `status` is `"filled"` only today (the committed ring
/// carries executed legs). `side` is the aggressor code (`"B"` / `"A"`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct HistoricalOrder {
    /// Order id.
    pub oid: u64,
    /// Market symbol (perp) or spot pair name.
    pub coin: String,
    /// Aggressor side code (`"B"` / `"A"`).
    pub side: String,
    /// Lifecycle status (`"filled"` today).
    pub status: String,
    /// Fill price, 8-dp tape decimal string.
    pub px: String,
    /// Total filled size, normalized decimal string.
    pub filled_sz: String,
    /// Timestamp of the most recent fill (unix ms).
    pub time: u64,
    /// Trace hash of the most recent fill; empty for a systemic fill.
    #[serde(default)]
    pub hash: String,
    /// Committed block height. Present on a node fold row; absent on an archive
    /// row.
    #[serde(default)]
    pub block: Option<u64>,
    /// Limit price (archive superset), decimal string.
    #[serde(default)]
    pub limit_px: Option<String>,
    /// Average fill price (archive superset), decimal string.
    #[serde(default)]
    pub avg_px: Option<String>,
    /// Filled size (archive superset), normalized decimal string.
    #[serde(default)]
    pub sz: Option<String>,
    /// Original order size (archive superset), normalized decimal string.
    #[serde(default)]
    pub orig_sz: Option<String>,
    /// Total order size (archive superset), normalized decimal string.
    #[serde(default)]
    pub total_sz: Option<String>,
    /// Time-in-force (archive superset).
    #[serde(default)]
    pub tif: Option<String>,
    /// Reduce-only flag (archive superset).
    #[serde(default)]
    pub reduce_only: Option<bool>,
    /// Client order id (archive superset), `0x`-hex.
    #[serde(default)]
    pub cloid: Option<String>,
    /// Cancel reason (archive superset).
    #[serde(default)]
    pub cancel_reason: Option<String>,
    /// Error string (archive superset).
    #[serde(default)]
    pub error: Option<String>,
}

/// `historical_orders` response — an account's past (executed) orders.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct HistoricalOrders {
    /// Echo of the resolved account address. `None` on a no-archive gateway's
    /// typed-empty fallback (it omits `address`); the real archive path carries it.
    #[serde(default)]
    pub address: Option<Address>,
    /// Past orders, newest first.
    #[serde(default)]
    pub orders: Vec<HistoricalOrder>,
}

/// One realized funding payment inside a [`UserFunding`] response.
///
/// `usdc` is the signed payment as a verbatim string — it may carry up to ~28
/// significant digits, so a client MUST keep it as a string and never re-parse
/// it through a fixed-precision decimal. The `#[serde(alias = "payment")]` hedges
/// the node's doc-locked future rename (the standing wire gate still pins
/// `usdc`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct FundingRecord {
    /// Market symbol.
    pub coin: String,
    /// Payment timestamp (unix ms).
    pub time: u64,
    /// Signed funding payment, verbatim whole-USDC string. Never re-parse.
    #[serde(alias = "payment")]
    pub usdc: String,
    /// Signed position size at settlement, decimal string.
    pub szi: String,
    /// Funding rate applied, decimal string.
    pub funding_rate: String,
}

/// `user_funding` response — realized funding-payment history.
///
/// The node returns `[]` today (funding rows drain to the WS sink); the gateway
/// archive leg returns real normalized rows. `start_time` / `end_time` echo the
/// request window (`null` when absent).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct UserFunding {
    /// Echo of the resolved account address. `None` on a no-archive gateway's
    /// typed-empty fallback (it omits `address`); the real archive path carries it.
    #[serde(default)]
    pub address: Option<Address>,
    /// Echo of the request `start_time` (unix ms); `null` when absent.
    #[serde(default)]
    pub start_time: Option<u64>,
    /// Echo of the request `end_time` (unix ms); `null` when absent.
    #[serde(default)]
    pub end_time: Option<u64>,
    /// Realized funding payments.
    #[serde(default)]
    pub fundings: Vec<FundingRecord>,
}

/// `user_ledger_updates` response envelope (the NODE kind).
///
/// The node returns `[]` today; its future per-record shape is doc-locked ONLY
/// and diverges from the gateway union (`amount` / `amount_units` vs `delta`), so
/// this types the ENVELOPE and leaves each record as raw JSON. Use
/// [`Info::user_non_funding_ledger_updates`] for the gateway-served NORMALIZED
/// union.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct UserLedgerUpdates {
    /// Echo of the resolved account address.
    pub address: Address,
    /// Echo of the request `start_time` (unix ms); `null` when absent.
    #[serde(default)]
    pub start_time: Option<u64>,
    /// Echo of the request `end_time` (unix ms); `null` when absent.
    #[serde(default)]
    pub end_time: Option<u64>,
    /// Raw ledger-update records (record shape not yet locked — decode per your
    /// own schema).
    #[serde(default)]
    pub updates: Vec<Value>,
}

/// One record inside a [`UserNonFundingLedgerUpdates`] union.
///
/// Two row shapes (a trade row and a money-movement row) share `coin` + `time`;
/// every other field is optional and varies per row. `coin` renders the market
/// SYMBOL (a trade row) or the token SYMBOL (a money-movement row).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct LedgerUpdate {
    /// Market or token symbol.
    pub coin: String,
    /// Record timestamp (unix ms).
    pub time: u64,
    /// Movement kind (`"deposit"` / `"spot_transfer"` / `"trade"` …).
    #[serde(default)]
    pub kind: Option<String>,
    /// Signed balance delta, decimal string.
    #[serde(default)]
    pub delta: Option<String>,
    /// Counterparty address (`0x`-hex) for a transfer.
    #[serde(default)]
    pub counterparty: Option<String>,
    /// Trade id for a trade row.
    #[serde(default)]
    pub tid: Option<u64>,
    /// Realized PnL for a trade row, signed decimal string.
    #[serde(default)]
    pub realized_pnl: Option<String>,
    /// Fee charged for a trade row, decimal string.
    #[serde(default)]
    pub fee: Option<String>,
    /// Fee token symbol for a trade row.
    #[serde(default)]
    pub fee_token: Option<String>,
}

/// `user_non_funding_ledger_updates` response (the GATEWAY-served normalized
/// union). The collection wire key is camelCase `ledgerUpdates`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct UserNonFundingLedgerUpdates {
    /// Ledger-update records. Wire key is camelCase `ledgerUpdates`.
    #[serde(rename = "ledgerUpdates", default)]
    pub ledger_updates: Vec<LedgerUpdate>,
}

/// Per-pair spot-margin risk parameters inside a [`SpotMarginAccount`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SpotMarginParams {
    /// Initial-margin requirement, bps decimal string.
    pub init_bps: String,
    /// Maintenance-margin requirement, bps decimal string.
    pub maint_bps: String,
}

/// One spot-margin position inside a [`SpotMarginState`] response.
///
/// All magnitudes are full-precision normalized decimal strings (these planes
/// carry fractional borrow indices / sub-unit base sizes). `params` is `null`
/// when margin is disabled / uncalibrated for the pair.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SpotMarginAccount {
    /// Spot pair NAME (e.g. `"BTC/USDC"`).
    pub pair: String,
    /// Posted collateral, decimal string.
    pub collateral: String,
    /// Borrowed principal, decimal string.
    pub borrowed: String,
    /// Borrow-index snapshot at the position's last accrual, decimal string.
    pub borrow_index_snapshot: String,
    /// Base asset held, decimal string.
    pub base_held: String,
    /// Accrued debt (`borrowed × index / snapshot`), decimal string.
    pub current_debt: String,
    /// Per-pair margin parameters; `null` when margin is disabled.
    #[serde(default)]
    pub params: Option<SpotMarginParams>,
}

/// `spot_margin_state` response — every spot-margin position of one user.
///
/// The request key is `user` (0x hex) — NOT `address`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SpotMarginState {
    /// Echo of the resolved user address.
    pub user: Address,
    /// Spot-margin positions, in pair-id order.
    #[serde(default)]
    pub accounts: Vec<SpotMarginAccount>,
}

/// One Earn lending pool inside an [`EarnState`] response.
///
/// `user_shares` / `user_value` are present ONLY when the request carried a
/// `user`. All magnitudes are full-precision normalized decimal strings; the
/// bps-rate parameters are decimal strings too.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct EarnPool {
    /// Pool asset id.
    pub asset: u32,
    /// Pool token symbol (e.g. `"USDC"`), else `asset:<id>`.
    pub name: String,
    /// Total supplied principal, decimal string.
    pub total_supplied: String,
    /// Total borrowed principal, decimal string.
    pub total_borrowed: String,
    /// Idle liquidity (`total_supplied − total_borrowed`), decimal string.
    pub idle: String,
    /// Total outstanding shares, decimal string.
    pub shares_total: String,
    /// Net asset value per share, decimal string.
    pub share_value: String,
    /// Borrow index, decimal string.
    pub borrow_index: String,
    /// Reserve factor, bps decimal string.
    pub reserve_factor_bps: String,
    /// Annualized borrow rate, bps decimal string.
    pub borrow_rate_bps_annual: String,
    /// Reserve accrued, decimal string.
    pub reserve_accrued: String,
    /// The requesting user's shares, decimal string. Present only when `user`
    /// was sent.
    #[serde(default)]
    pub user_shares: Option<String>,
    /// The requesting user's value (`user_shares × share_value`), decimal
    /// string. Present only when `user` was sent.
    #[serde(default)]
    pub user_value: Option<String>,
}

/// `earn_state` response — every Earn lending pool, plus one user's stake when
/// the request carried a `user`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct EarnState {
    /// Lending pools, in committed asset-id order.
    #[serde(default)]
    pub pools: Vec<EarnPool>,
}

/// `pm_summary` response — portfolio-margin enrollment + last-computed figures.
///
/// The request key is `address` (0x hex; an internal account id is rejected). The
/// cents fields are USD-CENTS-plane integer strings, NOT whole USDC. An unknown
/// address answers 200 with `enrolled:false` and zeroed figures.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PmSummary {
    /// Echo of the resolved account address.
    pub address: Address,
    /// Whether the account is enrolled in portfolio margin.
    pub enrolled: bool,
    /// Enrollment timestamp (unix ms; `0` when not enrolled).
    pub enrolled_at: u64,
    /// Block height of the last PM computation.
    pub last_computed_block: u64,
    /// Maintenance-margin requirement, USD-CENTS integer string.
    pub pm_maint_margin_cents: String,
    /// Net account value, USD-CENTS integer string.
    pub net_value_cents: String,
    /// Concentration penalty, USD-CENTS integer string.
    pub concentration_penalty_cents: String,
}

/// `user_fills` response — account-scoped fill history, newest first.
///
/// The gateway merges deep archive history into the node's own fill ring and
/// re-applies the request `limit`, so ONE DTO covers the node-direct read and
/// the gateway-merged read. Each record is the canonical [`Fill`]: `coin` a
/// market symbol, `px` an 8-dp tape string, `sz` on the size plane. A merged
/// archive-normalized fill may omit `block` (hence `Fill::block` is `Option`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct UserFills {
    /// Echo of the resolved account address.
    pub address: Address,
    /// Fills, newest first.
    #[serde(default)]
    pub fills: Vec<Fill>,
}

/// `user_fills_by_time` response — fill history filtered to an inclusive
/// `[start_time, end_time]` window over each record's consensus `time`. Records
/// are oldest first (ring order), the reverse of [`UserFills`]. Same [`Fill`]
/// record shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct UserFillsByTime {
    /// Echo of the resolved account address.
    pub address: Address,
    /// Echo of the request `start_time` (unix ms); `null` when absent.
    #[serde(default)]
    pub start_time: Option<u64>,
    /// Echo of the request `end_time` (unix ms); `null` when absent.
    #[serde(default)]
    pub end_time: Option<u64>,
    /// In-window fills, oldest first.
    #[serde(default)]
    pub fills: Vec<Fill>,
}

/// One funding-premium sample inside a [`FundingHistory`] response.
///
/// `premium` is the exact pre-clamp premium decimal string; `funding_rate` is
/// the same premium passed through the per-market per-hour cap — the realized
/// rate that settlement actually charged. Both ride the wire as strings so
/// precision survives.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct FundingSample {
    /// Sample timestamp (unix ms).
    pub ts: u64,
    /// Raw funding premium (signed, pre-clamp), decimal string.
    pub premium: String,
    /// Clamped realized rate settlement charged (premium through the cap),
    /// decimal string.
    pub funding_rate: String,
}

/// `funding_history` response — market-scoped funding-premium samples.
///
/// The request key is `coin` (market symbol; the only market selector). The
/// samples are the ordered ring the node keeps per asset.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct FundingHistory {
    /// Echo of the requested market symbol.
    pub coin: String,
    /// Funding-premium samples, ring order.
    #[serde(default)]
    pub samples: Vec<FundingSample>,
}

/// `active_asset_data` response — a user's per-asset leverage / margin-mode /
/// tradeable-size view, keyed by `(address, coin)`.
///
/// The `[buy, sell]` pairs: `available_to_trade` is the per-side notional still
/// openable (`free_collateral × leverage`, plus the existing position's notional
/// on the reducing side), whole-USDC decimal strings; `max_trade_szs` is the
/// same budget converted to base-unit size at the mark (round toward zero). The
/// node marks-to-market with `mark_px`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ActiveAssetData {
    /// Echo of the requested account address.
    pub address: Address,
    /// Echo of the requested market symbol.
    pub coin: String,
    /// Effective leverage (per-asset setting, else market max).
    pub leverage: u32,
    /// Effective margin mode (`"cross"` / `"isolated"` / `"strict_iso"`).
    pub margin_mode: String,
    /// Mark price used for the size conversion, whole-USDC decimal string.
    pub mark_px: String,
    /// `[buy, sell]` notional still openable, whole-USDC decimal strings.
    pub available_to_trade: [String; 2],
    /// `[buy, sell]` max order size, base-unit decimal strings.
    pub max_trade_szs: [String; 2],
    /// OI-cap-derived market-order size ceiling, decimal string.
    pub max_trade_size: String,
    /// Whether the user holds a non-zero position on the asset.
    pub has_position: bool,
}

/// One approved agent inside an [`Agents`] response.
///
/// `expires_at` is `null` for a never-expiring approval; `name` is `null`
/// when the approval carried no label.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AgentEntry {
    /// Approved agent wallet address (`0x`-hex).
    pub agent: String,
    /// Agent label; `null` when the approval carried none.
    #[serde(default)]
    pub name: Option<String>,
    /// Approval expiry (unix ms); `null` for a never-expiring approval.
    #[serde(default)]
    pub expires_at: Option<u64>,
}

/// `agents` response — approved agent / API wallets for an account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Agents {
    /// Echo of the resolved master address.
    pub address: Address,
    /// Approved agents.
    #[serde(default)]
    pub agents: Vec<AgentEntry>,
}

/// One sub-account inside a [`SubAccounts`] response.
///
/// `equity` is the sub-account's whole-USDC cross-account value (settled-PnL
/// inclusive), decimal string; `"0"` for a sub with no committed user state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SubAccountEntry {
    /// Sub-account index under the parent.
    pub index: u32,
    /// Sub-account address (`0x`-hex).
    pub address: String,
    /// Sub-account equity, whole-USDC decimal string.
    pub equity: String,
}

/// `sub_accounts` response — sub-accounts of an account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SubAccounts {
    /// Echo of the resolved parent address.
    pub address: Address,
    /// Sub-accounts, in index order.
    #[serde(default)]
    pub sub_accounts: Vec<SubAccountEntry>,
}

/// One follower stake in a vault, inside [`WebDataVault::equities`].
///
/// `shares` is on the WHOLE-share plane (already divided by the share scale) and
/// `equity` is whole USDC — neither needs client-side scaling.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct VaultEquity {
    /// Numeric vault id.
    pub vault_id: u64,
    /// Vault address (`0x`-hex).
    pub vault_address: String,
    /// Whole shares held, decimal string.
    pub shares: String,
    /// Value of those shares, whole-USDC decimal string.
    pub equity: String,
}

/// The vault facet of a [`WebData`] snapshot.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct WebDataVault {
    /// Stakes the account holds as a follower.
    #[serde(default)]
    pub equities: Vec<VaultEquity>,
    /// Full state of every vault the account follows or leads.
    #[serde(default)]
    pub vaults: Vec<VaultState>,
}

/// Aggregate delegator figures — the `delegator_summary` body.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DelegatorSummary {
    /// Total delegated stake, canonical decimal string.
    pub total_delegated: String,
    /// Stake queued for withdrawal, canonical decimal string.
    pub pending_withdrawal: String,
    /// Rewards claimable now, canonical decimal string.
    pub claimable_rewards: String,
    /// Number of active delegations.
    pub n_delegations: u64,
}

/// The staking facet of a [`WebData`] snapshot.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct WebDataStaking {
    /// Per-delegation staking detail.
    pub state: StakingSnapshot,
    /// Aggregate delegator figures.
    pub summary: DelegatorSummary,
}

/// The multisig facet of a [`WebData`] snapshot — the `user_to_multi_sig_signers`
/// body without its address.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MultiSigSigners {
    /// Whether the account is a multisig account.
    pub is_multi_sig: bool,
    /// Signatures required to authorize an action; `0` when not a multisig.
    pub threshold: u32,
    /// Authorized signer addresses (`0x`-hex).
    #[serde(default)]
    pub signers: Vec<String>,
}

/// `web_data` response — the consolidated account snapshot.
///
/// One read for the account facets `account_state` does NOT carry: vaults,
/// staking, sub-accounts, the multisig signer set, and agent (API) wallets.
/// Each facet is the same body the standalone read returns, minus the redundant
/// per-facet address.
///
/// `height` / `time` stamp the committed block the snapshot was read at, flat at
/// the top level.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct WebData {
    /// Echo of the requested address.
    pub address: Address,
    /// Vault follower stakes + followed / led vault states.
    #[serde(default)]
    pub vault: WebDataVault,
    /// Staking detail + aggregate delegator figures.
    #[serde(default)]
    pub staking: WebDataStaking,
    /// Sub-accounts, in index order.
    #[serde(default)]
    pub sub_accounts: Vec<SubAccountEntry>,
    /// Multisig signer set.
    #[serde(default)]
    pub multisig: MultiSigSigners,
    /// Approved agent / API wallets.
    #[serde(default)]
    pub agents: Vec<AgentEntry>,
    /// Committed block height the snapshot was read at.
    pub height: u64,
    /// Committed block timestamp the snapshot was read at (unix ms).
    pub time: u64,
}

/// One maker quote inside an [`RfqSession`].
///
/// `price` / `max_size` keep those names — the `px` / `sz` short keys are the
/// order-book dialect and do NOT apply to RFQ quotes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RfqQuote {
    /// Maker address (`0x`-hex).
    pub maker: String,
    /// Maker self-trade-prevention group.
    #[serde(default)]
    pub maker_stp_group: Option<u32>,
    /// Quoted price, tick-snapped whole-USDC decimal string.
    pub price: String,
    /// Largest size the maker will take, size-plane decimal string.
    pub max_size: String,
    /// Quote validity deadline (unix ms).
    pub valid_until: u64,
    /// Quote submission timestamp (unix ms).
    pub submitted_at: u64,
}

/// One open RFQ session plus its maker quotes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RfqSession {
    /// Request id.
    pub rfq_id: u64,
    /// Market symbol.
    pub coin: String,
    /// Side the requester intends to take, `"B"` / `"A"`.
    pub side: OrderSide,
    /// Requested size, size-plane decimal string.
    pub sz: String,
    /// Requester address (`0x`-hex).
    pub requester: String,
    /// Requester self-trade-prevention group.
    #[serde(default)]
    pub requester_stp_group: Option<u32>,
    /// Request expiry (unix ms).
    pub expiry: u64,
    /// Requester limit price, decimal string; `null` when the request is
    /// unpriced.
    #[serde(default)]
    pub limit_px: Option<String>,
    /// Request creation timestamp (unix ms).
    pub created_at: u64,
    /// Maker quotes submitted so far.
    #[serde(default)]
    pub quotes: Vec<RfqQuote>,
}

/// `rfq_open` response — every open RFQ request. No request parameters.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RfqOpen {
    /// Open requests, in request-id order.
    #[serde(default)]
    pub rfqs: Vec<RfqSession>,
}

/// `rfq_user` response — the open RFQ requests one account takes part in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RfqUser {
    /// Echo of the resolved account address.
    pub address: Address,
    /// Requests the account raised.
    #[serde(default)]
    pub requested: Vec<RfqSession>,
    /// Requests the account quoted on.
    #[serde(default)]
    pub quoted: Vec<RfqSession>,
}

/// Insert `start_time` / `end_time` into a request body only when present — the
/// node echoes an absent bound as `null`, so omitting the key is the honest
/// "open bound" request.
fn insert_time_window(body: &mut Value, start_time: Option<u64>, end_time: Option<u64>) {
    let obj = body.as_object_mut().expect("json! produced an object");
    if let Some(s) = start_time {
        obj.insert("start_time".into(), json!(s));
    }
    if let Some(e) = end_time {
        obj.insert("end_time".into(), json!(e));
    }
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

    /// List the STATIC per-market metadata (`markets_meta`).
    ///
    /// The long-cacheable subset of [`Info::markets`] — precision grids
    /// (`sz_decimals` / `tick_size` / `step_size`), the leverage + `margin_tiers`
    /// ladder, `min_order`, trade-control flags, `mark_source`, and the
    /// deprecated `asset_id` shim. These fields were split OFF the dynamic
    /// `markets` read (which now carries only live price / funding / OI), so a
    /// consumer that needs per-market precision must read `markets_meta` and
    /// merge by `coin`. Same `{ perp, spot }` envelope as `markets`; the returned
    /// perp records OMIT the dynamic price/funding/OI fields. Static → cache hard.
    ///
    /// A perp row now carries an optional [`MarketInfo::token`] block (the
    /// registered underlying token — EVM binding + `circulating_supply`),
    /// omitted when no underlying token is registered. Spot token rows carry
    /// `total_supply`; use [`Info::spot_meta`] for the `spot` sub-object.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn markets_meta(&self) -> Result<Vec<MarketInfo>, ClientError> {
        #[derive(serde::Deserialize)]
        struct MarketsResp {
            #[serde(default)]
            perp: Vec<MarketInfo>,
        }
        let resp: MarketsResp = self
            .client
            .post_json("/info", &json!({ "type": "markets_meta" }))
            .await?;
        Ok(resp.perp)
    }

    /// Fetch the L2 book snapshot for a market or spot pair.
    ///
    /// Per the `/info` contract (`l2_book`): keyed by `coin` — a perp market
    /// symbol (`"BTC"`) OR a spot pair (name `"BTC/USDC"` or the numeric pair
    /// id). The `data` payload is `{ bids, asks }` (spot pairs now render real
    /// depth).
    ///
    /// `params` optionally requests deterministic away-from-spread aggregation
    /// (`n_sig_figs` / `mantissa` / `n_levels` — see [`L2BookParams`]); the
    /// gateway validates the params strictly and returns the grouped book. Pass
    /// `None` for the ungrouped full book.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn l2_book(
        &self,
        coin: &str,
        params: Option<&L2BookParams>,
    ) -> Result<L2Book, ClientError> {
        let mut body = json!({ "type": "l2_book", "coin": coin });
        if let Some(p) = params {
            let obj = body.as_object_mut().expect("json! produced an object");
            if let Some(n) = p.n_sig_figs {
                obj.insert("n_sig_figs".into(), json!(n));
            }
            if let Some(m) = p.mantissa {
                obj.insert("mantissa".into(), json!(m));
            }
            if let Some(l) = p.n_levels {
                obj.insert("n_levels".into(), json!(l));
            }
        }
        self.client.post_json("/info", &body).await
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

    /// `vault_state` — snapshot of one vault, keyed by the vault ADDRESS.
    ///
    /// Values are on the human whole-USDC plane; see [`VaultState`] for the
    /// plane rules.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`]. A vault
    /// address the node does not know answers 404.
    pub async fn vault_state(&self, vault: Address) -> Result<VaultState, ClientError> {
        self.client
            .post_json("/info", &json!({ "type": "vault_state", "vault": vault }))
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

    /// `open_orders` — open orders for an account, keyed by `address`.
    ///
    /// The row set covers perp resting orders, spot resting orders, and parked
    /// TP / SL / stop triggers. A parked trigger reads `tif: "trigger"` with a
    /// populated `trigger` block — the detail the retired `frontend_open_orders`
    /// read carried.
    ///
    /// SPOT: a spot row's `coin` is the pair NAME (`"BTC/USDC"`) and its `px` /
    /// `sz` are in that pair's planes.
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

    /// Spot pair universe + token registry — convenience wrapper.
    ///
    /// The standalone `spot_meta` `/info` type was REMOVED server-side (it now
    /// returns 400 `unknown info type`); the SAME spot data is the `spot`
    /// sub-object of `markets_meta`. This wrapper posts
    /// `{"type":"markets_meta","kind":"spot"}` and unwraps the retained `spot`
    /// key, returning the identical [`SpotMeta`] shape.
    ///
    /// Each [`SpotPair`]'s `name` is derived as `{base}/{quote}` from the
    /// token registry; the numeric `id` is the compact `coin` label spot
    /// prints carry on the WS `trades` / `candles` / `fills` channels.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn spot_meta(&self) -> Result<SpotMeta, ClientError> {
        #[derive(serde::Deserialize)]
        struct Resp {
            #[serde(default)]
            spot: SpotMeta,
        }
        let resp: Resp = self
            .client
            .post_json("/info", &json!({ "type": "markets_meta", "kind": "spot" }))
            .await?;
        Ok(resp.spot)
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
        Ok(self.staking_state(addr).await?.state.delegations)
    }

    /// `pm_summary` — portfolio-margin enrollment + last-computed figures for an
    /// account, keyed by `address` (0x hex).
    ///
    /// The cents fields are USD-CENTS-plane integer strings. An unknown address
    /// answers with `enrolled:false` and zeroed figures.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn pm_summary(&self, addr: Address) -> Result<PmSummary, ClientError> {
        self.client
            .post_json("/info", &json!({ "type": "pm_summary", "address": addr }))
            .await
    }

    /// `order_status` — single-order lifecycle lookup by `oid`.
    ///
    /// Resolves the first hit: a live resting order, then a parked trigger, then
    /// the most recent matching fill, else [`OrderStatus::Unknown`].
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn order_status_by_oid(&self, oid: u64) -> Result<OrderStatus, ClientError> {
        self.client
            .post_json("/info", &json!({ "type": "order_status", "oid": oid }))
            .await
    }

    /// `order_status` — single-order lifecycle lookup by `cloid` (`0x` + 32 hex).
    ///
    /// A cloid-only query resolves resting / triggered hits only — the fill ring
    /// is oid-keyed, so a filled order that has left the book returns
    /// [`OrderStatus::Unknown`] by cloid.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn order_status_by_cloid(&self, cloid: &str) -> Result<OrderStatus, ClientError> {
        self.client
            .post_json("/info", &json!({ "type": "order_status", "cloid": cloid }))
            .await
    }

    /// `historical_orders` — an account's past (executed) orders, keyed by
    /// `address`. Optional `limit` caps the most-recent records.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn historical_orders(
        &self,
        addr: Address,
        limit: Option<u32>,
    ) -> Result<HistoricalOrders, ClientError> {
        let mut body = json!({ "type": "historical_orders", "address": addr });
        if let Some(l) = limit {
            let obj = body.as_object_mut().expect("json! produced an object");
            obj.insert("limit".into(), json!(l));
        }
        self.client.post_json("/info", &body).await
    }

    /// `user_funding` — realized funding-payment history, keyed by `address`.
    ///
    /// `start_time` / `end_time` bound a window (unix ms); each is inserted only
    /// when `Some`. The node returns `[]` today; the gateway archive leg returns
    /// real rows. A `usdc` payment may carry ~28 significant digits — keep it as a
    /// string.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn user_funding(
        &self,
        addr: Address,
        start_time: Option<u64>,
        end_time: Option<u64>,
    ) -> Result<UserFunding, ClientError> {
        let mut body = json!({ "type": "user_funding", "address": addr });
        insert_time_window(&mut body, start_time, end_time);
        self.client.post_json("/info", &body).await
    }

    /// `user_ledger_updates` — the NODE ledger kind, keyed by `address`.
    ///
    /// The node returns `[]` today and its record shape is not yet locked, so the
    /// records stay raw JSON. For the gateway-served NORMALIZED union use
    /// [`Info::user_non_funding_ledger_updates`].
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn user_ledger_updates(
        &self,
        addr: Address,
        start_time: Option<u64>,
        end_time: Option<u64>,
    ) -> Result<UserLedgerUpdates, ClientError> {
        let mut body = json!({ "type": "user_ledger_updates", "address": addr });
        insert_time_window(&mut body, start_time, end_time);
        self.client.post_json("/info", &body).await
    }

    /// `user_non_funding_ledger_updates` — the gateway-served normalized ledger
    /// union (deposits / withdrawals / transfers / trade rows), keyed by
    /// `address`. The collection wire key is camelCase `ledgerUpdates`.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn user_non_funding_ledger_updates(
        &self,
        addr: Address,
        start_time: Option<u64>,
        end_time: Option<u64>,
    ) -> Result<UserNonFundingLedgerUpdates, ClientError> {
        let mut body = json!({ "type": "user_non_funding_ledger_updates", "address": addr });
        insert_time_window(&mut body, start_time, end_time);
        self.client.post_json("/info", &body).await
    }

    /// `spot_margin_state` — every spot-margin position of one user.
    ///
    /// The request key is `user` (0x hex), NOT `address`.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn spot_margin_state(&self, user: Address) -> Result<SpotMarginState, ClientError> {
        self.client
            .post_json(
                "/info",
                &json!({ "type": "spot_margin_state", "user": user }),
            )
            .await
    }

    /// `earn_state` — every Earn lending pool. Pass `user` to also carry that
    /// user's `user_shares` / `user_value` per pool.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn earn_state(&self, user: Option<Address>) -> Result<EarnState, ClientError> {
        let mut body = json!({ "type": "earn_state" });
        if let Some(u) = user {
            let obj = body.as_object_mut().expect("json! produced an object");
            obj.insert("user".into(), json!(u));
        }
        self.client.post_json("/info", &body).await
    }

    /// `encode_action` — lower a wire action to its canonical core `Action` JSON.
    ///
    /// The returned STRING's exact bytes are the `inner_action_blob` every
    /// `multi_sig` member signs. The node lowers via the SAME `into_action` path
    /// admission uses, so the bytes a member signs match the bytes the `multi_sig`
    /// handler verifies. Pass `action` in the familiar `{type, params}` wire form.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`]; the node
    /// returns 400 on an unknown / missing action.
    pub async fn encode_action(&self, action: &Value) -> Result<String, ClientError> {
        #[derive(serde::Deserialize)]
        struct Resp {
            action_json: String,
        }
        let resp: Resp = self
            .client
            .post_json(
                "/info",
                &json!({ "type": "encode_action", "action": action }),
            )
            .await?;
        Ok(resp.action_json)
    }

    /// `rfq_open` — every open RFQ request with its maker quotes. No parameters.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn rfq_open(&self) -> Result<RfqOpen, ClientError> {
        self.client
            .post_json("/info", &json!({ "type": "rfq_open" }))
            .await
    }

    /// `rfq_user` — the open RFQ requests one account raised or quoted on,
    /// keyed by `address`.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn rfq_user(&self, addr: Address) -> Result<RfqUser, ClientError> {
        self.client
            .post_json("/info", &json!({ "type": "rfq_user", "address": addr }))
            .await
    }

    /// `user_fills` — account-scoped fill history, keyed by `address`, newest
    /// first. Optional `limit` caps the most-recent records (absent = the full
    /// ring).
    ///
    /// The gateway merges deep archive history into the node fill serializer's
    /// own response and re-applies `limit`. A SPOT `sz` rides the raw integer
    /// plane today; the human plane is the owner-ruled target, flipping under a
    /// fork-gated node-tape fix. A merged archive-normalized fill may omit `block`.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn user_fills(
        &self,
        addr: Address,
        limit: Option<u32>,
    ) -> Result<UserFills, ClientError> {
        let mut body = json!({ "type": "user_fills", "address": addr });
        if let Some(l) = limit {
            let obj = body.as_object_mut().expect("json! produced an object");
            obj.insert("limit".into(), json!(l));
        }
        self.client.post_json("/info", &body).await
    }

    /// `user_fills_by_time` — fill history filtered to an inclusive
    /// `[start_time, end_time]` window over each record's consensus `time`,
    /// keyed by `address`. Records are oldest first (the reverse of
    /// [`Info::user_fills`]). Each bound is inserted only when `Some`; an absent
    /// bound is open.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn user_fills_by_time(
        &self,
        addr: Address,
        start_time: Option<u64>,
        end_time: Option<u64>,
    ) -> Result<UserFillsByTime, ClientError> {
        let mut body = json!({ "type": "user_fills_by_time", "address": addr });
        insert_time_window(&mut body, start_time, end_time);
        self.client.post_json("/info", &body).await
    }

    /// `funding_history` — market-scoped funding-premium samples, keyed by
    /// `coin` (the market symbol; the only market selector).
    ///
    /// Each sample carries the pre-clamp `premium` and the realized
    /// `funding_rate` (the premium through the per-market per-hour cap). This is
    /// distinct from [`Info::user_funding`], which is account-scoped realized
    /// payments.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn funding_history(&self, coin: &str) -> Result<FundingHistory, ClientError> {
        self.client
            .post_json("/info", &json!({ "type": "funding_history", "coin": coin }))
            .await
    }

    /// `web_data` — the consolidated account snapshot (vaults / staking /
    /// sub-accounts / multisig / agents), keyed by `address`.
    ///
    /// One round trip replaces five facet reads. The same body streams on the
    /// `web_data` WS channel.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn web_data(&self, addr: Address) -> Result<WebData, ClientError> {
        self.client
            .post_json("/info", &json!({ "type": "web_data", "address": addr }))
            .await
    }

    /// `active_asset_data` — a user's per-asset leverage / margin-mode /
    /// tradeable-size view, keyed by `address` AND `coin` (both required; the
    /// node answers 404 when `coin` does not resolve).
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn active_asset_data(
        &self,
        addr: Address,
        coin: &str,
    ) -> Result<ActiveAssetData, ClientError> {
        self.client
            .post_json(
                "/info",
                &json!({ "type": "active_asset_data", "address": addr, "coin": coin }),
            )
            .await
    }

    /// `agents` — approved agent / API wallets for an account, keyed by
    /// `address`. A `null` `expires_at` is a never-expiring approval.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn agents(&self, addr: Address) -> Result<Agents, ClientError> {
        self.client
            .post_json("/info", &json!({ "type": "agents", "address": addr }))
            .await
    }

    /// `sub_accounts` — sub-accounts of an account, keyed by `address`. Each
    /// entry carries the sub's `equity` (whole-USDC, `"0"` for a sub with no
    /// committed user state).
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn sub_accounts(&self, addr: Address) -> Result<SubAccounts, ClientError> {
        self.client
            .post_json("/info", &json!({ "type": "sub_accounts", "address": addr }))
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

    /// The wire-v2 `account_state.data` body, exactly as the node serializes it.
    fn account_state_fixture() -> serde_json::Value {
        serde_json::json!({
            "address": "0x000000000000000000000000000000000000beef",
            "account_value": "100000000",
            "free_collateral": "80000000",
            "init_margin": "20000000",
            "health": "10000000",
            "tier": "Safe",
            "abstraction": "unified",
            "position_mode": "one_way",
            "clearinghouse_state": {
                "": { "positions": [{
                    "coin": "BTC",
                    "size": "-1.5",
                    "entry": "64000",
                    "upnl": "500000",
                    "isolated": false,
                    "lev": 10,
                    "liq": "71000",
                    "roe": "0.02",
                    "funding": "-1.25",
                    "margin": "9600",
                    "maint_margin": "480",
                    "notional": "96000"
                }] },
                "0x000000000000000000000000000000000000dead": { "positions": [{
                    "coin": "XYZ",
                    "size": "2",
                    "entry": "10",
                    "upnl": "0",
                    "isolated": true,
                    "lev": 3,
                    "liq": "5",
                    "roe": "0",
                    "funding": "0",
                    "margin": "6.66",
                    "maint_margin": "0.4",
                    "notional": "20",
                    "side": "long"
                }] }
            },
            "balances": [
                { "asset": 100, "name": "USDC", "total": "100000000", "hold": "0" },
                { "asset": 102, "name": "ETH", "total": "5000000000", "hold": "1" }
            ],
            "pm_maint_margin": "0",
            "pm_net_value": "0",
            "pm_concentration_penalty": "0",
            "height": 8_416_000u64,
            "time": 1_783_011_600_000u64
        })
    }

    #[test]
    fn account_state_decodes_the_wire_v2_body() {
        let a: AccountState = serde_json::from_value(account_state_fixture()).unwrap();
        assert_eq!(a.account_value, "100000000");
        assert_eq!(a.tier, Tier::Safe);
        assert_eq!(a.abstraction, Abstraction::Unified);
        assert_eq!(a.position_mode, PositionMode::OneWay);
        assert_eq!(a.height, 8_416_000);
        assert_eq!(a.time, 1_783_011_600_000);

        // Positions group by dex; the core dex is the empty-string key.
        assert_eq!(a.clearinghouse_state.len(), 2);
        let core = a.core_positions();
        assert_eq!(core.len(), 1);
        assert_eq!(core[0].coin, "BTC");
        // `size` is SIGNED and keeps the `size` key — the order/book `sz` key is
        // a different plane and must not be unified with it.
        assert_eq!(core[0].size, "-1.5");
        assert_eq!(core[0].maint_margin, "480");
        assert_eq!(core[0].position_value, "96000");
        // A one-way leg carries no side label.
        assert!(core[0].side.is_none());

        // A MIP-3 deployer dex keys on the deployer address.
        let dex = &a.clearinghouse_state["0x000000000000000000000000000000000000dead"];
        assert_eq!(dex.positions[0].side, Some(PositionSide::Long));

        // Balances are an ARRAY of token rows; USDC is first.
        assert_eq!(a.balances[0].name, "USDC");
        assert_eq!(a.balances[0].asset, 100);
        assert_eq!(a.balances[1].name, "ETH");
        assert_eq!(a.balances[1].hold, "1");

        // Portfolio-margin figures are always present, whole-USDC strings.
        assert_eq!(a.pm_maint_margin, "0");
        assert_eq!(a.pm_net_value, "0");
        assert_eq!(a.pm_concentration_penalty, "0");

        let dec: AccountState = serde_json::from_str(&serde_json::to_string(&a).unwrap()).unwrap();
        assert_eq!(a, dec);
    }

    /// The retired pre-wire-v2 keys must be gone from the body the SDK decodes.
    /// A flat `positions` array or an object `balances` means the fixture — or
    /// the DTO — slipped back to the old wire.
    #[test]
    fn account_state_body_drops_the_retired_keys() {
        let body = account_state_fixture();
        assert!(body.get("positions").is_none());
        assert!(body.get("maint_margin").is_none());
        assert!(body.get("mode").is_none());
        assert!(body.get("pm_enabled").is_none());
        assert!(body["balances"].is_array());
        assert!(
            body["clearinghouse_state"][""]["positions"][0]
                .get("asset")
                .is_none()
        );
    }

    /// The node emits `health_deferred` ONLY when the risk engine defers, so
    /// absent must read `false` and present must read `true`.
    #[test]
    fn account_state_reads_the_conditional_health_deferred_flag() {
        let body = account_state_fixture();
        assert!(body.get("health_deferred").is_none());
        let a: AccountState = serde_json::from_value(body.clone()).unwrap();
        assert!(!a.health_deferred);

        let mut deferred = body;
        deferred["health_deferred"] = serde_json::json!(true);
        let d: AccountState = serde_json::from_value(deferred).unwrap();
        assert!(d.health_deferred);
    }

    /// A dropped or renamed field on the money path must FAIL the decode. With
    /// `#[serde(default)]` a rename decoded fine and reported an account that
    /// holds nothing.
    #[test]
    fn account_state_rejects_a_dropped_or_renamed_field() {
        for key in [
            "clearinghouse_state",
            "balances",
            "abstraction",
            "position_mode",
            "account_value",
            "free_collateral",
            "init_margin",
            "health",
            "tier",
            "pm_maint_margin",
            "pm_net_value",
            "pm_concentration_penalty",
            "height",
            "time",
            "address",
        ] {
            let mut absent = account_state_fixture();
            absent.as_object_mut().unwrap().remove(key);
            assert!(
                serde_json::from_value::<AccountState>(absent).is_err(),
                "a missing `{key}` must fail the decode"
            );

            let mut renamed = account_state_fixture();
            let v = renamed.as_object_mut().unwrap().remove(key).unwrap();
            renamed[format!("{key}_v3")] = v;
            assert!(
                serde_json::from_value::<AccountState>(renamed).is_err(),
                "a renamed `{key}` must fail the decode"
            );
        }
    }

    /// The rename guard above must not be satisfied by an unrelated failure:
    /// the untouched fixture still decodes.
    #[test]
    fn account_state_fixture_still_decodes_unmodified() {
        assert!(serde_json::from_value::<AccountState>(account_state_fixture()).is_ok());
    }

    #[test]
    fn account_state_reads_a_portfolio_margin_account() {
        let mut body = account_state_fixture();
        body["abstraction"] = serde_json::json!("portfolio");
        body["pm_maint_margin"] = serde_json::json!("1234.56");
        let a: AccountState = serde_json::from_value(body).unwrap();
        assert_eq!(a.abstraction, Abstraction::Portfolio);
        assert_eq!(a.pm_maint_margin, "1234.56");
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
                    "next_payment_ts": 0 },
                "token": {
                    "id": 0, "wei_decimals": 8,
                    "token_id": "0x00000000000000000000000000000000000000000000000000000000000000aa",
                    "system_address": "0x0000000000000000000000000000000000000200",
                    "evm_contract": { "address": "0x0000000000000000000000000000000000012345",
                                      "evm_extra_wei_decimals": 0 },
                    "is_canonical": true, "circulating_supply": "21000000"
                }
            }, {
                // A perp with NO registered underlying token omits `token` -> None.
                "coin": "ETH", "asset_id": 1, "kind": "perp", "sz_decimals": 4,
                "mark_source": "oracle_median", "fba_enabled": false,
                "tick_size": "100000", "step_size": "1", "min_order": "1",
                "max_leverage": 25, "init_margin_ratio": "400", "maint_margin_ratio": "500"
            }],
            "spot": { "pairs": [], "tokens": [] }
        });
        let resp: MarketsResp = serde_json::from_value(data).unwrap();
        assert_eq!(resp.perp.len(), 2);
        assert_eq!(resp.perp[0].coin, "BTC");
        assert_eq!(resp.perp[0].margin_tiers.len(), 2);
        // Perp underlying-token block: EVM binding + circulating_supply.
        let tok = resp.perp[0].token.as_ref().unwrap();
        assert_eq!(tok.id, 0);
        assert_eq!(tok.circulating_supply, "21000000");
        assert_eq!(
            tok.evm_contract.as_ref().unwrap().address,
            "0x0000000000000000000000000000000000012345"
        );
        assert!(tok.is_canonical);
        // The second perp omits `token` entirely -> None.
        assert!(resp.perp[1].token.is_none());
    }

    /// Decode the exact `l2_book.data` payload from the `/info` contract.
    #[test]
    fn l2_book_decodes_doc_fixture() {
        let data = serde_json::json!({
            "bids": [{ "px": "100.49", "sz": "1", "n_orders": 5 }],
            "asks": [{ "px": "100.51", "sz": "2", "n_orders": 3 }]
        });
        // The retired `size` level key must NOT decode.
        assert!(
            serde_json::from_value::<L2Level>(
                serde_json::json!({ "px": "100.49", "size": "1", "n_orders": 5 })
            )
            .is_err()
        );
        let b: L2Book = serde_json::from_value(data).unwrap();
        assert_eq!(b.bids.len(), 1);
        assert_eq!(b.bids[0].px, "100.49");
        assert_eq!(b.bids[0].sz, "1");
        assert_eq!(b.bids[0].n_orders, 5);
        assert_eq!(b.asks[0].n_orders, 3);
        // px/sz serialize as strings.
        let j = serde_json::to_value(&b).unwrap();
        assert!(j["bids"][0]["px"].is_string());
        assert!(j["bids"][0]["sz"].is_string());
        assert!(j["bids"][0]["n_orders"].is_number());
    }

    /// Decode the live `spot_meta` payload (node 0.7.26): pair `name` derived as
    /// `{base}/{quote}`, numeric `id` (the WS spot `coin` label), `taker_fee_bps`
    /// as a STRING, the pair price/vol/supply context, plus the enriched token
    /// registry (object `evm_contract`, `token_id`, `system_address`,
    /// `is_canonical`, `total_supply`).
    #[test]
    fn spot_meta_decodes_node_fixture() {
        let data = serde_json::json!({
            "pairs": [{
                "id": 101,
                "name": "BTC/USDC",
                "base": 0,
                "quote": 100,
                "taker_fee_bps": "5",
                "min_notional": "1000",
                "active": true,
                "mark_px": "61550.2",
                "mid_px": "61551",
                "prev_day_px": "61200",
                "day_ntl_vlm": "0",
                "circulating_supply": "21000000"
            }],
            "tokens": [
                { "id": 0, "name": "BTC", "sz_decimals": 5, "wei_decimals": 8,
                  "token_id": "0x00000000000000000000000000000000000000000000000000000000000000aa",
                  "system_address": "0x0000000000000000000000000000000000000200",
                  "evm_contract": { "address": "0x0000000000000000000000000000000000012345",
                                    "evm_extra_wei_decimals": -2 },
                  "is_canonical": true, "total_supply": "21000000" },
                { "id": 100, "name": "USDC", "sz_decimals": 2, "wei_decimals": 6,
                  "token_id": "0x0000000000000000000000000000000000000000000000000000000000000064",
                  "system_address": "0x0000000000000000000000000000000000000201",
                  "evm_contract": null, "is_canonical": true, "total_supply": "0" }
            ]
        });
        let m: SpotMeta = serde_json::from_value(data).unwrap();
        assert_eq!(m.pairs.len(), 1);
        assert_eq!(m.pairs[0].id, 101);
        assert_eq!(m.pairs[0].name, "BTC/USDC");
        assert_eq!(m.pairs[0].base, 0);
        assert_eq!(m.pairs[0].quote, 100);
        assert_eq!(m.pairs[0].taker_fee_bps, "5");
        assert_eq!(m.pairs[0].min_notional, "1000");
        assert!(m.pairs[0].active);
        assert_eq!(m.pairs[0].mark_px, "61550.2");
        assert_eq!(m.pairs[0].mid_px.as_deref(), Some("61551"));
        assert_eq!(m.pairs[0].prev_day_px.as_deref(), Some("61200"));
        assert_eq!(m.pairs[0].circulating_supply, "21000000");
        assert_eq!(m.tokens.len(), 2);
        assert_eq!(m.tokens[0].name, "BTC");
        assert_eq!(m.tokens[0].wei_decimals, 8);
        // evm_contract is an OBJECT (not a bare address string).
        let evm = m.tokens[0].evm_contract.as_ref().unwrap();
        assert_eq!(evm.address, "0x0000000000000000000000000000000000012345");
        assert_eq!(evm.evm_extra_wei_decimals, -2);
        assert!(m.tokens[0].is_canonical);
        assert_eq!(m.tokens[0].total_supply, "21000000");
        assert_eq!(m.tokens[1].id, 100);
        assert_eq!(m.tokens[1].sz_decimals, 2);
        assert!(m.tokens[1].evm_contract.is_none());
        // `taker_fee_bps` / `min_notional` stay strings; ids stay numbers.
        let j = serde_json::to_value(&m).unwrap();
        assert!(j["pairs"][0]["taker_fee_bps"].is_string());
        assert!(j["pairs"][0]["min_notional"].is_string());
        assert!(j["pairs"][0]["id"].is_number());
        assert!(j["tokens"][0]["evm_contract"]["address"].is_string());
        // Round-trips.
        let dec: SpotMeta = serde_json::from_str(&serde_json::to_string(&m).unwrap()).unwrap();
        assert_eq!(m, dec);
    }

    /// The `spot_meta()` wrapper decodes the `markets_meta` kind=spot envelope:
    /// the `spot` sub-object is RETAINED even when kind-filtered.
    #[test]
    fn markets_meta_kind_spot_wrapper_decodes() {
        #[derive(serde::Deserialize)]
        struct Resp {
            #[serde(default)]
            spot: SpotMeta,
        }
        let data = serde_json::json!({
            "spot": {
                "pairs": [{
                    "id": 101, "name": "BTC/USDC", "base": 0, "quote": 100,
                    "taker_fee_bps": "5", "min_notional": "1000", "active": true
                }],
                "tokens": [
                    { "id": 0, "name": "BTC", "sz_decimals": 5, "wei_decimals": 8 }
                ]
            }
        });
        let resp: Resp = serde_json::from_value(data).unwrap();
        assert_eq!(resp.spot.pairs.len(), 1);
        assert_eq!(resp.spot.pairs[0].name, "BTC/USDC");
        assert_eq!(resp.spot.pairs[0].taker_fee_bps, "5");
        // Older/minimal token rows (no evm block) still decode via defaults.
        assert_eq!(resp.spot.tokens[0].name, "BTC");
        assert!(resp.spot.tokens[0].evm_contract.is_none());
        assert_eq!(resp.spot.tokens[0].total_supply, "");
    }

    /// `L2BookParams` serializes with snake_case keys and OMITS `None` fields,
    /// so a params-less request carries no aggregation keys.
    #[test]
    fn l2_book_params_serialize_omits_none() {
        let empty = L2BookParams::default();
        let j = serde_json::to_value(empty).unwrap();
        assert!(j.get("n_sig_figs").is_none());
        assert!(j.get("mantissa").is_none());
        assert!(j.get("n_levels").is_none());

        let p = L2BookParams {
            n_sig_figs: Some(5),
            mantissa: Some(2),
            n_levels: Some(20),
        };
        let j = serde_json::to_value(p).unwrap();
        assert_eq!(j["n_sig_figs"], 5);
        assert_eq!(j["mantissa"], 2);
        assert_eq!(j["n_levels"], 20);
    }

    /// A spot pair l2_book renders real depth and may echo `coin`.
    #[test]
    fn l2_book_decodes_spot_pair_with_coin_echo() {
        let data = serde_json::json!({
            "coin": "BTC/USDC",
            "bids": [{ "px": "61550", "sz": "1.5", "n_orders": 2 }],
            "asks": [{ "px": "61551", "sz": "0.8", "n_orders": 1 }]
        });
        let b: L2Book = serde_json::from_value(data).unwrap();
        assert_eq!(b.coin, "BTC/USDC");
        assert_eq!(b.bids.len(), 1);
        assert_eq!(b.asks[0].px, "61551");
    }

    /// Decode the exact `spot_clearinghouse_state.data` payload the node serves.
    #[test]
    fn spot_clearinghouse_state_decodes_node_fixture() {
        let data = serde_json::json!({
            "address": "0x4242424242424242424242424242424242424242",
            "balances": [
                { "asset": 101, "name": "BTC", "total": "500", "hold": "20" }
            ],
            "height": 8_416_000u64,
            "time": 1_783_011_600_000u64
        });
        let s: SpotClearinghouseState = serde_json::from_value(data).unwrap();
        assert_eq!(s.balances.len(), 1);
        assert_eq!(s.balances[0].asset, 101);
        assert_eq!(s.balances[0].name, "BTC");
        assert_eq!(s.balances[0].total, "500");
        assert_eq!(s.balances[0].hold, "20");
        assert_eq!(s.height, 8_416_000);
        assert_eq!(s.time, 1_783_011_600_000);
        // Magnitudes stay strings on the wire.
        let j = serde_json::to_value(&s).unwrap();
        assert!(j["balances"][0]["total"].is_string());
        assert!(j["balances"][0]["hold"].is_string());
        assert!(j["balances"][0]["asset"].is_number());
        assert!(j["balances"][0].get("balance").is_none());
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

    /// Decode the node `open_orders.data`. One canonical row serves the REST
    /// read, the WS snapshot, and the inner `order` of a WS `order_updates`
    /// record; parked triggers ride in the same set.
    #[test]
    fn open_orders_decodes_node_wire() {
        let data = serde_json::json!({
            "address": "0x000000000000000000000000000000000000beef",
            "orders": [
                { "oid": 4242, "coin": "BTC", "side": "B", "px": "25000", "sz": "60",
                  "orig_sz": null, "tif": "gtc", "reduce_only": false, "trigger": null,
                  "cloid": "0x0000000000000000000000000000abcd",
                  "inserted_at": 1_700_000_000_000u64 },
                { "oid": 4243, "coin": "BTC/USDC", "side": "A", "px": "35000", "sz": "10",
                  "orig_sz": null, "tif": "alo", "reduce_only": false, "trigger": null,
                  "cloid": null, "inserted_at": 1_700_000_000_001u64 },
                { "oid": 4244, "coin": "ETH", "side": "A", "px": "1800", "sz": "3",
                  "orig_sz": null, "tif": "trigger", "reduce_only": true,
                  "trigger": { "trigger_px": "1800", "trigger_above": false,
                               "is_parked": true, "is_market": false, "limit_px": "1795" },
                  "cloid": null, "inserted_at": 1_700_000_000_002u64 }
            ]
        });
        let o: OpenOrders = serde_json::from_value(data).unwrap();
        assert_eq!(o.orders.len(), 3);

        // Perp resting row.
        assert_eq!(o.orders[0].oid, 4242);
        assert_eq!(o.orders[0].coin, "BTC");
        assert_eq!(o.orders[0].side, OrderSide::Bid);
        assert_eq!(o.orders[0].sz, "60");
        assert_eq!(o.orders[0].tif.as_deref(), Some("gtc"));
        assert_eq!(o.orders[0].reduce_only, Some(false));
        assert_eq!(o.orders[0].orig_sz, None);
        assert_eq!(o.orders[0].inserted_at, 1_700_000_000_000);
        assert_eq!(
            o.orders[0].cloid.as_deref(),
            Some("0x0000000000000000000000000000abcd")
        );

        // Spot resting row: `coin` is the pair name; cloid absent -> None.
        assert_eq!(o.orders[1].coin, "BTC/USDC");
        assert_eq!(o.orders[1].side, OrderSide::Ask);
        assert_eq!(o.orders[1].cloid, None);

        // Parked trigger row: the detail the retired `frontend_open_orders` read
        // carried. `tif` is the non-TIF token "trigger", so the field stays a
        // String — a closed TIF enum would reject this row.
        let parked = &o.orders[2];
        assert_eq!(parked.tif.as_deref(), Some("trigger"));
        assert_eq!(parked.reduce_only, Some(true));
        let t = parked.trigger.as_ref().unwrap();
        assert_eq!(t.trigger_px, "1800");
        assert!(!t.trigger_above);
        assert_eq!(t.is_parked, Some(true));
        assert_eq!(t.is_market, Some(false));
        assert_eq!(t.limit_px.as_deref(), Some("1795"));

        let j = serde_json::to_value(&o).unwrap();
        assert_eq!(j["orders"][0]["side"], "B");
        assert_eq!(j["orders"][1]["side"], "A");
        assert!(j["orders"][0]["oid"].is_number());
        // The retired top-level `account_id` is never emitted.
        assert!(j.get("account_id").is_none());
        let dec: OpenOrders = serde_json::from_str(&serde_json::to_string(&o).unwrap()).unwrap();
        assert_eq!(o, dec);
    }

    /// The retired `"bid"` / `"ask"` side tokens and the retired `size` /
    /// `inserted_at_ms` keys must all fail to decode.
    #[test]
    fn open_order_rejects_the_pre_wire_v2_row() {
        let legacy = serde_json::json!({
            "oid": 1, "coin": "BTC", "side": "bid", "px": "1", "size": "2",
            "inserted_at_ms": 3u64
        });
        assert!(serde_json::from_value::<OpenOrder>(legacy).is_err());
        assert!(serde_json::from_value::<OrderSide>(serde_json::json!("bid")).is_err());
        assert_eq!(
            serde_json::from_value::<OrderSide>(serde_json::json!("B")).unwrap(),
            OrderSide::Bid
        );
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
            "next_funding_ts": 1783011600000u64
        });
        let p: PredictedFunding = serde_json::from_value(data).unwrap();
        assert_eq!(p.coin, "ETH");
        assert_eq!(p.next_funding_ts, 1_783_011_600_000);
        assert!(p.predicted_rate.starts_with("0.008"));
    }

    // ── P2 wave-1: typed /info read decodes (fixtures pinned to the node
    // serializer shapes) ──

    /// `order_status` filled branch = the canonical fill record (values from
    /// `perp_fill_canonical`): symbol coin, 8-dp tape `px`, size-plane `sz`,
    /// `time`, no `block` on the archive-normalized twin.
    #[test]
    fn order_status_filled_decodes_canonical_fill() {
        let data = serde_json::json!({
            "status": "filled",
            "fill": {
                "coin": "MTF", "side": "B", "px": "0.12126000", "sz": "112.22",
                "time": 1_784_820_001_998u64, "oid": 42u64, "tid": 7u64,
                "fee": "0.000952", "closed_pnl": "0", "dir": "Open Long",
                "start_position": "-357795.12", "hash": ""
            }
        });
        let st: OrderStatus = serde_json::from_value(data).unwrap();
        let OrderStatus::Filled { fill } = &st else {
            panic!("expected Filled, got {st:?}");
        };
        assert_eq!(fill.coin, "MTF");
        assert_eq!(fill.px, "0.12126000");
        assert_eq!(fill.sz, "112.22");
        assert_eq!(fill.start_position, "-357795.12");
        assert_eq!(fill.block, None); // archive-normalized fill carries no block
        assert!(fill.hash.is_empty());
        // A node-ring fill DOES carry `block` (Option::Some).
        let ring = serde_json::json!({
            "status": "filled",
            "fill": {
                "coin": "MTF", "side": "B", "px": "0.12126000", "sz": "112.22",
                "time": 1_784_820_001_998u64, "oid": 42u64, "tid": 7u64,
                "fee": "0.000952", "closed_pnl": "0", "dir": "Open Long",
                "start_position": "-357795.12", "block": 8_416_000u64, "hash": ""
            }
        });
        let OrderStatus::Filled { fill } = serde_json::from_value(ring).unwrap() else {
            panic!("expected Filled");
        };
        assert_eq!(fill.block, Some(8_416_000));
    }

    /// `order_status` resting branch: tick-snapped `px`, `"B"` / `"A"` side, cloid.
    #[test]
    fn order_status_resting_decodes() {
        let data = serde_json::json!({
            "status": "resting",
            "order": {
                "oid": 7u64, "coin": "BTC", "side": "A", "px": "62500.12",
                "sz": "1.5", "inserted_at": 1u64,
                "cloid": "0x0000000000000000000000000000abcd"
            }
        });
        let OrderStatus::Resting { order } = serde_json::from_value(data).unwrap() else {
            panic!("expected Resting");
        };
        assert_eq!(order.oid, 7);
        assert_eq!(order.side, OrderSide::Ask);
        assert_eq!(order.px, "62500.12");
        assert_eq!(order.sz, "1.5");
        assert_eq!(order.inserted_at, 1);
        assert_eq!(
            order.cloid.as_deref(),
            Some("0x0000000000000000000000000000abcd")
        );
        // cloid absent -> None.
        let no_cloid = serde_json::json!({
            "status": "resting",
            "order": { "oid": 8u64, "coin": "BTC", "side": "B", "px": "1",
                       "sz": "1", "inserted_at": 2u64, "cloid": null }
        });
        let OrderStatus::Resting { order } = serde_json::from_value(no_cloid).unwrap() else {
            panic!("expected Resting");
        };
        assert_eq!(order.side, OrderSide::Bid);
        assert_eq!(order.cloid, None);
    }

    /// `order_status` triggered branch: market vs limit trigger (`is_market` +
    /// `limit_px`).
    #[test]
    fn order_status_triggered_decodes() {
        let data = serde_json::json!({
            "status": "triggered",
            "trigger": {
                "oid": 9u64, "coin": "BTC", "side": "A", "trigger_px": "60000",
                "trigger_above": false, "sz": "1", "registered_at": 3u64,
                "fired": false, "is_market": false, "limit_px": "59900"
            }
        });
        let OrderStatus::Triggered { trigger } = serde_json::from_value(data).unwrap() else {
            panic!("expected Triggered");
        };
        assert!(!trigger.is_market);
        assert_eq!(trigger.limit_px.as_deref(), Some("59900"));
        assert!(!trigger.fired);
        // Market trigger: is_market true, limit_px null.
        let mkt = serde_json::json!({
            "status": "triggered",
            "trigger": { "oid": 9u64, "coin": "BTC", "side": "B",
                         "trigger_px": "60000", "trigger_above": true, "sz": "1",
                         "registered_at": 3u64, "fired": true,
                         "is_market": true, "limit_px": null }
        });
        let OrderStatus::Triggered { trigger } = serde_json::from_value(mkt).unwrap() else {
            panic!("expected Triggered");
        };
        assert!(trigger.is_market);
        assert_eq!(trigger.limit_px, None);
    }

    /// `order_status` unknown branch.
    #[test]
    fn order_status_unknown_decodes() {
        let st: OrderStatus =
            serde_json::from_value(serde_json::json!({ "status": "unknown" })).unwrap();
        assert!(matches!(st, OrderStatus::Unknown));
    }

    /// `historical_orders`: an archive superset row (from `order_canonical`) and a
    /// node-fold-only row (Always fields + `block`, no superset).
    #[test]
    fn historical_orders_decodes_superset_and_fold_rows() {
        let data = serde_json::json!({
            "address": "0x4242424242424242424242424242424242424242",
            "orders": [
                {
                    "oid": 9u64, "coin": "MTF", "side": "A", "status": "filled",
                    "time": 1_784_820_001_000u64, "px": "194.78000000",
                    "filled_sz": "112.2", "hash": "", "limit_px": "194.78000000",
                    "avg_px": "194.78000000", "sz": "112.2", "orig_sz": "112.2",
                    "total_sz": "112.2", "tif": "Gtc", "reduce_only": false
                },
                {
                    "oid": 8u64, "coin": "MTF", "side": "B", "status": "filled",
                    "px": "101", "filled_sz": "1.2", "time": 20u64,
                    "block": 2u64, "hash": ""
                }
            ]
        });
        let h: HistoricalOrders = serde_json::from_value(data).unwrap();
        assert_eq!(h.orders.len(), 2);
        // Archive superset row.
        let a = &h.orders[0];
        assert_eq!(a.oid, 9);
        assert_eq!(a.px, "194.78000000");
        assert_eq!(a.filled_sz, "112.2");
        assert_eq!(a.avg_px.as_deref(), Some("194.78000000"));
        assert_eq!(a.tif.as_deref(), Some("Gtc"));
        assert_eq!(a.reduce_only, Some(false));
        assert_eq!(a.block, None);
        // Node-fold-only row: superset fields absent -> None; block present.
        let b = &h.orders[1];
        assert_eq!(b.filled_sz, "1.2");
        assert_eq!(b.block, Some(2));
        assert_eq!(b.avg_px, None);
        assert_eq!(b.tif, None);
        assert_eq!(b.reduce_only, None);
    }

    /// `user_funding`: the 28-significant-digit `usdc` survives verbatim as a
    /// String (values from `funding_canonical`); the `payment` alias also decodes.
    #[test]
    fn user_funding_28_digit_usdc_survives_and_payment_aliases() {
        let data = serde_json::json!({
            "address": "0x4242424242424242424242424242424242424242",
            "start_time": null,
            "end_time": null,
            "fundings": [
                { "coin": "MTF", "time": 1_784_800_000_000u64,
                  "usdc": "0.0189543210987654321098765432",
                  "szi": "17415", "funding_rate": "-0.0005" }
            ]
        });
        let f: UserFunding = serde_json::from_value(data).unwrap();
        assert_eq!(f.start_time, None);
        assert_eq!(f.end_time, None);
        assert_eq!(f.fundings.len(), 1);
        // 28-digit value survives byte-for-byte.
        assert_eq!(f.fundings[0].usdc, "0.0189543210987654321098765432");
        assert_eq!(f.fundings[0].coin, "MTF");
        // The future `payment` field name decodes via the alias.
        let aliased = serde_json::json!({
            "coin": "MTF", "time": 1u64, "payment": "1.25",
            "szi": "1", "funding_rate": "0"
        });
        let rec: FundingRecord = serde_json::from_value(aliased).unwrap();
        assert_eq!(rec.usdc, "1.25");
    }

    /// `user_funding` unknown-address empty shape (node account-history contract).
    #[test]
    fn user_funding_empty_shape_decodes() {
        let data = serde_json::json!({
            "address": "0x4242424242424242424242424242424242424242",
            "start_time": null, "end_time": null, "fundings": []
        });
        let f: UserFunding = serde_json::from_value(data).unwrap();
        assert!(f.fundings.is_empty());
        assert_eq!(f.start_time, None);
    }

    /// `user_non_funding_ledger_updates`: the 3-row union under the camelCase
    /// `ledgerUpdates` key (values from `ledger_canonical`).
    #[test]
    fn user_non_funding_ledger_union_decodes_camel_key() {
        let data = serde_json::json!({
            "ledgerUpdates": [
                { "coin": "USDC", "time": 1_784_800_000_001u64, "kind": "deposit",
                  "delta": "100", "counterparty": "0xabc" },
                { "coin": "PURR", "time": 1_784_800_000_002u64,
                  "kind": "spot_transfer", "delta": "5" },
                { "coin": "MTF", "time": 1_784_800_000_003u64, "kind": "trade",
                  "tid": 77u64, "realized_pnl": "1.5", "fee": "0.02",
                  "fee_token": "USDC" }
            ]
        });
        let l: UserNonFundingLedgerUpdates = serde_json::from_value(data).unwrap();
        assert_eq!(l.ledger_updates.len(), 3);
        // Money-movement row.
        assert_eq!(l.ledger_updates[0].coin, "USDC");
        assert_eq!(l.ledger_updates[0].kind.as_deref(), Some("deposit"));
        assert_eq!(l.ledger_updates[0].counterparty.as_deref(), Some("0xabc"));
        assert_eq!(l.ledger_updates[0].tid, None);
        // Trade row.
        assert_eq!(l.ledger_updates[2].tid, Some(77));
        assert_eq!(l.ledger_updates[2].realized_pnl.as_deref(), Some("1.5"));
        assert_eq!(l.ledger_updates[2].fee_token.as_deref(), Some("USDC"));
        // Round-trips back to camelCase.
        let j = serde_json::to_value(&l).unwrap();
        assert!(j.get("ledgerUpdates").is_some());
    }

    /// `user_ledger_updates` (node kind): envelope decodes, records stay raw JSON.
    #[test]
    fn user_ledger_updates_envelope_decodes_raw_records() {
        let data = serde_json::json!({
            "address": "0x4242424242424242424242424242424242424242",
            "start_time": 5u64, "end_time": 9u64, "updates": []
        });
        let u: UserLedgerUpdates = serde_json::from_value(data).unwrap();
        assert_eq!(u.start_time, Some(5));
        assert_eq!(u.end_time, Some(9));
        assert!(u.updates.is_empty());
    }

    /// `spot_margin_state`: SYMBOLIZED pair name, `params` present and null.
    #[test]
    fn spot_margin_state_decodes() {
        let data = serde_json::json!({
            "user": "0x4242424242424242424242424242424242424242",
            "accounts": [
                { "pair": "BTC/USDC", "collateral": "1000", "borrowed": "250.5",
                  "borrow_index_snapshot": "1.02", "base_held": "3.14",
                  "current_debt": "255.51",
                  "params": { "init_bps": "1000", "maint_bps": "500" } },
                { "pair": "ETH/USDC", "collateral": "0", "borrowed": "0",
                  "borrow_index_snapshot": "1", "base_held": "0",
                  "current_debt": "0", "params": null }
            ]
        });
        let s: SpotMarginState = serde_json::from_value(data).unwrap();
        assert_eq!(s.accounts.len(), 2);
        assert_eq!(s.accounts[0].pair, "BTC/USDC");
        assert_eq!(s.accounts[1].pair, "ETH/USDC");
        assert_eq!(s.accounts[0].current_debt, "255.51");
        // A raw numeric pair id is the pre-wire-v2 shape and must not decode.
        assert!(
            serde_json::from_value::<SpotMarginAccount>(serde_json::json!({
                "pair": 200u32, "collateral": "0", "borrowed": "0",
                "borrow_index_snapshot": "1", "base_held": "0", "current_debt": "0",
                "params": null
            }))
            .is_err()
        );
        let p = s.accounts[0].params.as_ref().unwrap();
        assert_eq!(p.init_bps, "1000");
        assert_eq!(p.maint_bps, "500");
        // Margin-disabled pair: params null.
        assert!(s.accounts[1].params.is_none());
    }

    /// `earn_state`: pools with and without the per-user stake fields.
    #[test]
    fn earn_state_decodes_with_and_without_user() {
        let data = serde_json::json!({
            "pools": [
                { "asset": 0u32, "name": "USDC", "total_supplied": "10000", "total_borrowed": "4000",
                  "idle": "6000", "shares_total": "9500", "share_value": "1.0526",
                  "borrow_index": "1.03", "reserve_factor_bps": "1000",
                  "borrow_rate_bps_annual": "550", "reserve_accrued": "12.5",
                  "user_shares": "100", "user_value": "105.26" }
            ]
        });
        let e: EarnState = serde_json::from_value(data).unwrap();
        assert_eq!(e.pools.len(), 1);
        assert_eq!(e.pools[0].idle, "6000");
        // The pool token symbol rides beside the numeric asset id.
        assert_eq!(e.pools[0].name, "USDC");
        assert_eq!(e.pools[0].user_shares.as_deref(), Some("100"));
        assert_eq!(e.pools[0].user_value.as_deref(), Some("105.26"));
        // No user: the per-user fields are absent -> None.
        let no_user = serde_json::json!({
            "pools": [
                { "asset": 0u32, "name": "USDC", "total_supplied": "1", "total_borrowed": "0",
                  "idle": "1", "shares_total": "1", "share_value": "1",
                  "borrow_index": "1", "reserve_factor_bps": "0",
                  "borrow_rate_bps_annual": "0", "reserve_accrued": "0" }
            ]
        });
        let e2: EarnState = serde_json::from_value(no_user).unwrap();
        assert_eq!(e2.pools[0].user_shares, None);
        assert_eq!(e2.pools[0].user_value, None);
    }

    /// `pm_summary`: an enrolled account and the zeroed unknown-address shape.
    #[test]
    fn pm_summary_decodes_enrolled_and_zeroed() {
        let enrolled = serde_json::json!({
            "address": "0x4242424242424242424242424242424242424242",
            "enrolled": true, "enrolled_at": 1_700_000_000_000u64,
            "last_computed_block": 8_416_000u64,
            "pm_maint_margin_cents": "123456", "net_value_cents": "10000000",
            "concentration_penalty_cents": "250"
        });
        let p: PmSummary = serde_json::from_value(enrolled).unwrap();
        assert!(p.enrolled);
        assert_eq!(p.enrolled_at, 1_700_000_000_000);
        assert_eq!(p.pm_maint_margin_cents, "123456");
        assert_eq!(p.net_value_cents, "10000000");
        // Zeroed unknown address.
        let zeroed = serde_json::json!({
            "address": "0x0000000000000000000000000000000000000000",
            "enrolled": false, "enrolled_at": 0u64, "last_computed_block": 0u64,
            "pm_maint_margin_cents": "0", "net_value_cents": "0",
            "concentration_penalty_cents": "0"
        });
        let z: PmSummary = serde_json::from_value(zeroed).unwrap();
        assert!(!z.enrolled);
        assert_eq!(z.pm_maint_margin_cents, "0");
    }

    /// `user_fills`: a node-ring perp fill WITH `block` + `0x` hash, and a spot
    /// fill (raw-plane integer `sz`) WITHOUT `block` (archive-normalized). The
    /// canonical perp values mirror `order_status_filled_decodes_canonical_fill`.
    #[test]
    fn user_fills_decodes_canonical_fills() {
        let data = serde_json::json!({
            "address": "0x4242424242424242424242424242424242424242",
            "fills": [
                {
                    "coin": "MTF", "side": "B", "px": "0.12126000", "sz": "112.22",
                    "time": 1_784_820_001_998u64, "oid": 42u64, "tid": 7u64,
                    "fee": "0.000952", "closed_pnl": "0", "dir": "Open Long",
                    "start_position": "-357795.12", "block": 8_416_000u64,
                    "hash": "0xabcdef"
                },
                {
                    "coin": "MTF/USDC", "side": "A", "px": "0.12130000", "sz": "112",
                    "time": 1_784_820_002_000u64, "oid": 43u64, "tid": 8u64,
                    "fee": "0.0001", "closed_pnl": "0", "dir": "Sell",
                    "start_position": "500", "hash": ""
                }
            ]
        });
        let uf: UserFills = serde_json::from_value(data).unwrap();
        assert_eq!(uf.fills.len(), 2);
        // Node-ring perp fill: block present, 0x hash.
        let perp = &uf.fills[0];
        assert_eq!(perp.coin, "MTF");
        assert_eq!(perp.px, "0.12126000");
        assert_eq!(perp.sz, "112.22");
        assert_eq!(perp.start_position, "-357795.12");
        assert_eq!(perp.block, Some(8_416_000));
        assert_eq!(perp.hash, "0xabcdef");
        // Spot fill: raw-plane integer sz, no block, empty hash.
        let spot = &uf.fills[1];
        assert_eq!(spot.coin, "MTF/USDC");
        assert_eq!(spot.side, "A");
        assert_eq!(spot.sz, "112");
        assert_eq!(spot.block, None);
        assert!(spot.hash.is_empty());
        // Round-trips: address echo preserved.
        let j = serde_json::to_value(&uf).unwrap();
        assert_eq!(
            j.get("address").and_then(Value::as_str),
            Some("0x4242424242424242424242424242424242424242")
        );
    }

    /// `user_fills_by_time`: echoed window bounds (`null` when absent), oldest
    /// first, same `Fill` record shape.
    #[test]
    fn user_fills_by_time_decodes_window() {
        let data = serde_json::json!({
            "address": "0x4242424242424242424242424242424242424242",
            "start_time": 100u64, "end_time": null,
            "fills": [
                { "coin": "MTF", "side": "B", "px": "0.1", "sz": "1",
                  "time": 150u64, "oid": 1u64, "tid": 1u64, "fee": "0",
                  "closed_pnl": "0", "dir": "Open Long", "start_position": "0",
                  "block": 5u64, "hash": "" }
            ]
        });
        let f: UserFillsByTime = serde_json::from_value(data).unwrap();
        assert_eq!(f.start_time, Some(100));
        assert_eq!(f.end_time, None);
        assert_eq!(f.fills.len(), 1);
        assert_eq!(f.fills[0].block, Some(5));
    }

    /// `funding_history`: one unclamped sample (`premium == funding_rate`) and
    /// one clamped (`premium` beyond the cap → capped `funding_rate`).
    #[test]
    fn funding_history_decodes_samples() {
        let data = serde_json::json!({
            "coin": "MTF",
            "samples": [
                { "ts": 1_784_800_000_000u64, "premium": "0.01",
                  "funding_rate": "0.01" },
                { "ts": 1_784_800_003_600u64, "premium": "0.05",
                  "funding_rate": "0.04" }
            ]
        });
        let fh: FundingHistory = serde_json::from_value(data).unwrap();
        assert_eq!(fh.coin, "MTF");
        assert_eq!(fh.samples.len(), 2);
        assert_eq!(fh.samples[0].ts, 1_784_800_000_000);
        // Unclamped: premium and realized rate agree.
        assert_eq!(fh.samples[0].premium, "0.01");
        assert_eq!(fh.samples[0].funding_rate, "0.01");
        // Clamped: realized rate is the capped value below the premium.
        assert_eq!(fh.samples[1].premium, "0.05");
        assert_eq!(fh.samples[1].funding_rate, "0.04");
    }

    /// The trigger detail the retired `frontend_open_orders` read carried now
    /// rides the enriched `open_orders` row: a two-key block on a resting book
    /// order, and the full parked block on an off-book TP / SL row.
    #[test]
    fn open_orders_carries_the_folded_trigger_detail() {
        let data = serde_json::json!({
            "address": "0x4242424242424242424242424242424242424242",
            "orders": [
                { "oid": 1u64, "coin": "BTC", "side": "B", "px": "62500.12",
                  "sz": "1.5", "orig_sz": null, "tif": "gtc", "reduce_only": false,
                  "cloid": null, "trigger": null, "inserted_at": 10u64 },
                { "oid": 2u64, "coin": "BTC", "side": "A", "px": "63000",
                  "sz": "0.5", "orig_sz": null, "tif": "alo", "reduce_only": false,
                  "cloid": "0x0000000000000000000000000000abcd",
                  "trigger": { "trigger_px": "62000", "trigger_above": false },
                  "inserted_at": 11u64 },
                { "oid": 3u64, "coin": "BTC", "side": "A", "px": "61000",
                  "sz": "0.25", "orig_sz": null, "tif": "trigger", "reduce_only": true,
                  "cloid": null,
                  "trigger": { "trigger_px": "61000", "trigger_above": false,
                               "is_parked": true, "is_market": false,
                               "limit_px": "60950" },
                  "inserted_at": 12u64 }
            ]
        });
        let f: OpenOrders = serde_json::from_value(data).unwrap();
        assert_eq!(f.orders.len(), 3);
        // Plain resting order: no trigger, no cloid.
        let plain = &f.orders[0];
        assert_eq!(plain.side, OrderSide::Bid);
        assert_eq!(plain.tif.as_deref(), Some("gtc"));
        assert!(plain.cloid.is_none());
        assert!(plain.trigger.is_none());
        // Resting order with a two-key trigger block: parked keys are None.
        let resting_trig = f.orders[1].trigger.as_ref().unwrap();
        assert_eq!(resting_trig.trigger_px, "62000");
        assert!(!resting_trig.trigger_above);
        assert_eq!(resting_trig.is_parked, None);
        assert_eq!(resting_trig.is_market, None);
        assert_eq!(resting_trig.limit_px, None);
        assert_eq!(
            f.orders[1].cloid.as_deref(),
            Some("0x0000000000000000000000000000abcd")
        );
        // Parked TP/SL-LIMIT row: full trigger block.
        assert_eq!(f.orders[2].tif.as_deref(), Some("trigger"));
        let parked = f.orders[2].trigger.as_ref().unwrap();
        assert_eq!(parked.is_parked, Some(true));
        assert_eq!(parked.is_market, Some(false));
        assert_eq!(parked.limit_px.as_deref(), Some("60950"));
    }

    /// `active_asset_data`: `[buy, sell]` pairs as `[String; 2]`, margin_mode,
    /// has_position.
    #[test]
    fn active_asset_data_decodes() {
        let data = serde_json::json!({
            "address": "0x4242424242424242424242424242424242424242",
            "coin": "BTC", "leverage": 20u32, "margin_mode": "cross",
            "mark_px": "62500", "available_to_trade": ["100000", "150000"],
            "max_trade_szs": ["1.6", "2.4"], "max_trade_size": "500",
            "has_position": true
        });
        let a: ActiveAssetData = serde_json::from_value(data).unwrap();
        assert_eq!(a.coin, "BTC");
        assert_eq!(a.leverage, 20);
        assert_eq!(a.margin_mode, "cross");
        assert_eq!(
            a.available_to_trade,
            ["100000".to_string(), "150000".to_string()]
        );
        assert_eq!(a.max_trade_szs, ["1.6".to_string(), "2.4".to_string()]);
        assert_eq!(a.max_trade_size, "500");
        assert!(a.has_position);
    }

    /// `agents`: one never-expiring / unnamed entry (`name` + `expires_at`
    /// both `null`) and one with both set.
    #[test]
    fn agents_decodes_null_and_set_expiry() {
        let data = serde_json::json!({
            "address": "0x4242424242424242424242424242424242424242",
            "agents": [
                { "agent": "0x1111111111111111111111111111111111111111",
                  "name": null, "expires_at": null },
                { "agent": "0x2222222222222222222222222222222222222222",
                  "name": "bot-1", "expires_at": 1_800_000_000_000u64 }
            ]
        });
        let a: Agents = serde_json::from_value(data).unwrap();
        assert_eq!(a.agents.len(), 2);
        // Never-expiring, unnamed.
        assert_eq!(a.agents[0].name, None);
        assert_eq!(a.agents[0].expires_at, None);
        // Named with an expiry.
        assert_eq!(a.agents[1].name.as_deref(), Some("bot-1"));
        assert_eq!(a.agents[1].expires_at, Some(1_800_000_000_000));
    }

    /// `sub_accounts`: index, address, and the `equity` field the node always
    /// emits.
    #[test]
    fn sub_accounts_decodes_equity() {
        let data = serde_json::json!({
            "address": "0x4242424242424242424242424242424242424242",
            "sub_accounts": [
                { "index": 1u32,
                  "address": "0x3333333333333333333333333333333333333333",
                  "equity": "1234.5" },
                { "index": 2u32,
                  "address": "0x4444444444444444444444444444444444444444",
                  "equity": "0" }
            ]
        });
        let s: SubAccounts = serde_json::from_value(data).unwrap();
        assert_eq!(s.sub_accounts.len(), 2);
        assert_eq!(s.sub_accounts[0].index, 1);
        assert_eq!(s.sub_accounts[0].equity, "1234.5");
        assert_eq!(s.sub_accounts[1].equity, "0");
    }
}
