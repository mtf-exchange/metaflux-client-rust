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
//! Each question has exactly ONE read. A read that merely filtered or
//! projected another was removed and its ask became a PARAMETER on the read it
//! duplicated — `market_info` is `markets` / `markets_meta` with a `coin`,
//! `margin_summary` is [`Info::account_state`] with
//! [`AccountDetail::Margin`], `account_overview` is [`Info::account_state`]
//! with `detail: "overview"`, `recent_trades` / `trades_by_time` are
//! [`Info::trades`] with and without a window.
//!
//! - **Market reads** — [`Info::markets`], [`Info::markets_meta`],
//!   [`Info::l2_book`], [`Info::trades`], [`Info::candle_snapshot`],
//!   [`Info::funding_history`].
//! - **Account reads** — [`Info::account_state`],
//!   [`Info::clearinghouse_state`], [`Info::account_overview`],
//!   [`Info::open_orders`],
//!   [`Info::staking_state`], [`Info::order_status_by_oid`],
//!   [`Info::historical_orders`], [`Info::user_funding`],
//!   [`Info::spot_margin_state`], [`Info::earn_state`], [`Info::user_fills`],
//!   [`Info::user_position_history`],
//!   [`Info::user_position_history_by_time`],
//!   [`Info::active_asset_data`].
//! - **Static / misc** — [`Info::spot_meta`], [`Info::fee_schedule`],
//!   [`Info::vault_state`].
//! - **Option reads** — [`Info::option_series`], [`Info::option_state`].
//! - **Bridge reads** — [`Info::bridge_withdrawal_history`].
//! - **RFQ reads** — [`Info::rfq_open`], [`Info::rfq_user`].
//! - **Fee credit** — [`Info::referral_state`], [`Info::builder_state`],
//!   [`Info::delegator_rewards`], [`Info::approved_builders`].
//! - **Venue / validators / deploy auctions** — [`Info::exchange_status`],
//!   [`Info::vault_summaries`], [`Info::user_rate_limit`], [`Info::perp_dexs`],
//!   [`Info::validator_summaries`], [`Info::validator_l1_votes`],
//!   [`Info::mip3_active_bids`], [`Info::spot_deploy_auction`],
//!   [`Info::user_twaps`].
//! - **Peer discovery** — [`Info::gossip_root_ips`].

mod account;
mod bridge;
mod credit;
mod discovery;
mod options;
mod positions;
mod rfq;
mod venue;

pub use account::{
    AccountDetail, AccountState, MarginLane, OptionLane, PerpLane, SpotLane, TokenBalance,
};
pub use bridge::{
    BridgeChainConfigRow, BridgeOutboxEntry, BridgeOutboxStatus, BridgeScanPolicy,
    BridgeWithdrawalHistory,
};
pub use credit::{
    ApprovedBuilder, ApprovedBuilders, BuilderState, DelegatorRewardRow, DelegatorRewards,
    ReferralState,
};
pub use discovery::{AdvertisedPeer, GossipRootIps};
pub use options::{OptionKind, OptionPosition, OptionSeries, OptionSeriesRegistry, OptionState};
pub use positions::{AccountPosition, ClearinghouseState, DexPositions, PositionSide};
pub use rfq::{OpenRfq, RfqOpen, RfqQuoteRow, RfqUser};
pub use venue::{
    ExchangeStatus, Mip3ActiveBids, Mip3Bid, PerMarketLimits, PerpDex, PerpDexLimits, PerpDexs,
    SealedRound, SpotDeployAuction, UserRateLimit, UserTwap, UserTwaps, ValidatorL1Vote,
    ValidatorL1Votes, ValidatorSummaries, ValidatorSummary, VaultSummaries, VaultSummary,
};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::error::ClientError;
use crate::rest::RestClient;
use crate::types::candle::CandleType;
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
/// The same token pair is used by `open_orders` and `order_status`. It is NOT the position leg label — see [`PositionSide`],
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
///
/// [`Self::group`] and [`Self::trail_px`] are absent again on all of those. The
/// node writes each key only on the leg that owns it, so a row that carries
/// neither decodes exactly as it did before the two keys existed.
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
    /// Scaled-TP/SL LADDER handle, shared by every leg of one ladder.
    ///
    /// A `positionTpsl` batch of THREE or more protective legs parks a ladder.
    /// Its legs share this handle, and they are NOT OCO: a fill of one leg does
    /// not cancel the others. One or two legs are the older shapes — a lone
    /// trigger, or an OCO pair — and read `None` here. Group the rows by this
    /// value to render one ladder; the whole ladder retires together when the
    /// position it protects closes.
    #[serde(default)]
    pub group: Option<u64>,
    /// TRAILING callback, an absolute price offset as a decimal string.
    ///
    /// `Some(d)` means the parked level ratchets toward the mark by `d` and
    /// never away from it. Read [`OrderTrigger::trigger_px`] as the RATCHETED
    /// level, not the level the owner sent. `None` = a static level.
    ///
    /// READ-SIDE ONLY today. No SDK type can send it — see the note on
    /// [`crate::types::order::Trigger`].
    #[serde(default)]
    pub trail_px: Option<String>,
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
/// forming bar as price samples land, this read returns the history. Bars are
/// oldest-first by `open_time`; the newest element is the still-forming bar.
///
/// A bar folds a PRICE series, never executions — see [`CandleType`]. A bar
/// therefore needs no trade: a market that has never traded still has bars, and
/// a window with no sample carries the previous close forward as a flat bar
/// (`open == high == low == close`, `num_samples == 0`).
///
/// The bars come from a SAMPLED series, not the continuous price path.
/// `open` / `close` are the first / last sample of the window, and
/// `high` / `low` are the highest / lowest SAMPLE — not the true extremes. Do
/// not build wick analysis or any "did the price touch X?" test on them.
///
/// Wire fields use the compact single-letter keys the archive serves
/// (`t`/`T`/`o`/`c`/`h`/`l`/`v`/`q`/`n`/`s`/`i`); this struct renames them to
/// readable names. `open`/`close`/`high`/`low` are whole-USDC human-dollar
/// decimal strings (`"61652.7"`).
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
    /// Always `"0"`; wire key `v`. A price bar folds no trades, so it carries
    /// no base-asset volume.
    #[serde(rename = "v")]
    pub volume: String,
    /// Always `"0"`; wire key `q`. A price bar folds no trades, so it carries
    /// no quote volume.
    #[serde(rename = "q", default)]
    pub quote_volume: String,
    /// How many price samples the bar folded; wire key `n`. It is NOT a trade
    /// count. `0` on a carry-forward bar.
    #[serde(rename = "n")]
    pub num_samples: u64,
}

/// One public trade print from [`Info::trades`].
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
    /// 0x action hash that produced the fill.
    ///
    /// `None` = NOT RECORDED: an archive-served print, whose table stores no
    /// trace hash. `Some("")` = recorded, and there was no signed taker action
    /// (a systemic print). The two are different facts, so they get different
    /// values.
    #[serde(default)]
    pub hash: Option<String>,
    /// Trade timestamp (unix ms).
    pub time: u64,
}

/// One leverage / margin band inside a [`MarketMeta::margin_tiers`] ladder.
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
///
/// This read carries NO broker-rebate field. A broker's rate is the
/// `builder_fee` it sets per order, capped by the account's own
/// [`Info::approved_builders`] grant.
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
    /// Burn fraction of the non-referrer remainder, fraction in `[0, 1]`
    /// (e.g. `"0.8"`). NOT bps.
    pub burn_ratio: String,
    /// Per-tier maker/taker schedule (authoritative carrier of maker/taker).
    pub tiers: Vec<FeeTier>,
    /// The day the POOLED volume counter stops buying a discount and each
    /// product reads only its own volume. `0` = not armed yet. A server that
    /// predates per-product fees omits it.
    #[serde(default)]
    pub pooled_volume_sunset_day: Option<u64>,
    /// The same instant in milliseconds, as a decimal string. `"0"` = not armed.
    #[serde(default)]
    pub pooled_volume_sunset_ms: Option<String>,
    /// `true` while pooled volume still feeds a tier. On the sunset day this
    /// goes false and a tier resting on cross-product volume DROPS.
    #[serde(default)]
    pub pooled_volume_counts: Option<bool>,
    /// One account's RESOLVED rates. Present only when the request carried an
    /// `address` (see [`Info::fee_schedule_for`]); `None` on the ladder-only read.
    #[serde(default)]
    pub user: Option<FeeScheduleUser>,
}

/// One product's resolved rates inside [`FeeScheduleUser`].
///
/// The four products price APART: each carries its own ladder, its own base
/// rates and its own 30-day counters. Read the row for the product you are about
/// to trade — the top-level [`FeeScheduleUser`] rates are the PERP ones.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ProductFeeRow {
    /// `"perp"`, `"spot"`, `"spot_margin"` or `"option"`.
    pub product: String,
    /// The rate a fill on this product charges the taker, staking discount
    /// applied. Decimal bps string.
    ///
    /// `None` on the `option` row, which does not price on a volume ladder —
    /// read [`Self::option_taker_bps`] there instead.
    #[serde(default)]
    pub taker_bps: Option<String>,
    /// The rate a fill on this product charges the maker, rebate subtracted.
    /// Decimal bps string; NEGATIVE means a credit paid to the maker.
    ///
    /// `None` on a product with NO maker leg. A maker rests on the shared spot
    /// book and never carries a lane, so it is always priced as `spot` — which
    /// leaves `spot_margin` and `option` with a taker leg only.
    #[serde(default)]
    pub maker_bps: Option<String>,
    /// The trailing 30-day taker volume THIS product's tier reads.
    ///
    /// `None` on the `option` row: an option does not price on a volume ladder.
    #[serde(default)]
    pub taker_volume_30d: Option<String>,
    /// The trailing 30-day maker volume THIS product's maker tier reads.
    /// `None` on a product with no maker leg — see [`Self::maker_bps`].
    #[serde(default)]
    pub maker_volume_30d: Option<String>,
    /// OPTION ROW ONLY. The rate charged on the option's STRIKE FACE —
    /// `strike × units`, for a put and a call alike. Decimal bps string.
    ///
    /// The strike face is the put's maximum payout exactly. A call escrows one
    /// coin, whose USDC worth the chain cannot read without a price, so the
    /// strike is the bound it can read. The fee itself is USDC on both kinds.
    ///
    /// The fee is the SMALLER of this term and
    /// [`Self::option_premium_cap_ppm`] of the premium. Both start unset, which
    /// charges nothing.
    #[serde(default)]
    pub option_taker_bps: Option<String>,
    /// OPTION ROW ONLY. The fee ceiling as a fraction of the premium, in ppm.
    #[serde(default)]
    pub option_premium_cap_ppm: Option<u32>,
}

/// One account's resolved fee position, returned by [`Info::fee_schedule_for`].
///
/// Only the taker of a fill carries a product. A maker rests on the shared spot
/// book, so a maker is always priced as `spot` whichever lane crosses it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct FeeScheduleUser {
    /// The resolved account.
    pub address: String,
    /// POOLED trailing 30-day taker volume, every product together.
    pub taker_volume_30d: String,
    /// POOLED trailing 30-day maker volume.
    pub maker_volume_30d: String,
    /// The PERP base taker rate, before the discount. Decimal bps string.
    pub taker_bps: String,
    /// The PERP base maker rate, before the rebate. Decimal bps string.
    pub maker_bps: String,
    /// The PERP taker rate a fill charges, discount applied.
    pub effective_taker_bps: String,
    /// The PERP maker rate a fill charges, rebate subtracted.
    pub effective_maker_bps: String,
    /// Taker-only staking discount, per mille (`100` = 10%).
    pub staking_discount_permille: u32,
    /// The PERP maker rebate, before it is subtracted. Decimal bps string.
    pub maker_rebate_bps: String,
    /// Per-product resolved rates. A server that predates per-product fees sends
    /// no rows, so an empty vector means "not served", NOT "no products".
    #[serde(default)]
    pub products: Vec<ProductFeeRow>,
}

/// The staking facet body, without the account address.
///
/// The standalone `staking_state` read carries the address beside these fields;
/// [`Info::account_overview`] nests the same body under `staking.state` and
/// drops the address (it is carried once at the top). One type serves both.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct StakingSnapshot {
    /// DELEGATED stake only, canonical decimal string — the sum of
    /// [`Delegation::amount`]. It is NOT the account's whole staked balance;
    /// add [`Self::undelegated_pool_balance`].
    pub total_staked: String,
    /// Stake deposited but NOT delegated, on the same plane as
    /// [`Self::total_staked`].
    ///
    /// `stakingDeposit` credits this free pool and `stakingWithdraw` debits it,
    /// so stake can rest here undelegated indefinitely. A caller that reads only
    /// `total_staked` reports less than the account holds.
    ///
    /// This is not [`Self::pending_unstakes`]: the free pool is already free,
    /// while a pending unstake is locked until it matures.
    ///
    /// `None` on a node that predates the field. Absent means unknown, never a
    /// zero balance.
    #[serde(default)]
    pub undelegated_pool_balance: Option<String>,
    /// Active delegations (unclaimed rewards live per-delegation).
    #[serde(default)]
    pub delegations: Vec<Delegation>,
    /// Queued undelegations awaiting maturity.
    #[serde(default)]
    pub pending_unstakes: Vec<PendingUnstake>,
    /// What funds the staking reward. `None` on a node that predates the field.
    #[serde(default)]
    pub reward_pool: Option<RewardPool>,
}

/// What funds the staking reward — the committed inputs, and NO rate.
///
/// The emission era is over: rewards come from fees, not from a curve, so there
/// is no annual rate to publish and none to derive. The pending pool is a
/// snapshot of accrued fees, and it depends on volume that has not happened yet.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RewardPool {
    /// Total staked MTF across the chain, canonical decimal string.
    pub total_stake: String,
    /// Fees accrued to the validator pool and not yet distributed, whole USDC.
    pub pending_validator_pool_usdc: String,
    /// Always `"fee_funded_on_book_buy"` — a constant that tells a fee-funded
    /// chain from an emission-funded one without inferring it.
    pub reward_source: String,
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
    /// Per-product reservations: collateral one product has committed is not
    /// available to another. Set with `user_set_abstraction`.
    Standard,
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

/// EVM-side contract binding for a registered token.
///
/// Present on a [`SpotToken`] / [`PerpUnderlyingToken`] when the token BINDS an
/// EVM contract; the node emits it as an OBJECT (not a bare address string).
///
/// `address` is the bound contract a Core-to-EVM transfer credits. A contract a
/// deployer merely declared at `register_token` is never served.
/// `evm_extra_wei_decimals` is that declared value, signed. It does NOT change a
/// credit: a credit lands in the token's `wei_decimals`.
///
/// NEVER copy `address` into config or a constant. A `finalizeEvmContract`
/// quorum vote rotates it, and a frozen address sends a credit to a retired
/// contract. Read it here each time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TokenEvmContract {
    /// EVM contract address (`0x`-hex, 20 bytes).
    pub address: String,
    /// Deployer-declared signed offset. Metadata only — see the type doc.
    pub evm_extra_wei_decimals: i32,
    /// Binding-registry variant tag, from the retired `evm_contract_bindings`
    /// read. `None` for the built-in USDC binding, which the credit path
    /// answers with no registry row behind it.
    #[serde(default)]
    pub variant: Option<u8>,
}

/// The registered underlying-token block on a perp [`MarketMeta`].
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

/// Per-market funding parameters inside a [`MarketMeta`].
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

/// `markets_meta` response row — the STATIC per-market metadata.
///
/// Magnitudes (`tick_size`, `step_size`, `min_order`, ratios) are CANONICAL
/// decimal **string** numerics — NOT the raw 1e8 / raw-lot planes;
/// `max_leverage` is a JSON number. Narrow to one market with the `coin`
/// argument of [`Info::markets_meta`].
///
/// PLANE BRIDGE: `tick_size` is whole USDC while an order's `limit_px` is on the
/// 1e8 plane, and `step_size` / `min_order` are whole base units while an
/// order's `size` is raw lots (`whole × 10^sz_decimals`). Use
/// [`crate::round_order_to_grid`] to snap a desired price / size onto this grid.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MarketMeta {
    /// Market symbol (e.g. `"BTC"`) — the canonical market key.
    pub coin: String,
    /// The uint32 to put in the EIP-712 `market` field when SIGNING an order
    /// for this market. It has no other meaning: every read keys by `coin`, so
    /// never sort, join or identify a market by this number.
    ///
    /// The signing type string is consensus-frozen at `uint32 market`, so a
    /// signer needs a number. Publishing it here keeps that number on the wire
    /// instead of making it knowledge the client carries out of band.
    #[serde(default)]
    pub signing_id: u32,
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
    /// `markets_meta` read when the perp has a registered
    /// underlying token; OMITTED (→ `None`) otherwise. Carries the token's
    /// EVM binding + `circulating_supply`.
    #[serde(default)]
    pub token: Option<PerpUnderlyingToken>,
    /// Whether OPENING a position is PERMITTED. `None` = the read did not serve
    /// the flag (the dynamic `markets` read omits it), NOT "blocked": the wire
    /// says what is ALLOWED, so a `false` here really does block opening.
    #[serde(default)]
    pub open: Option<bool>,
    /// Whether CLOSING a position is PERMITTED. Same presence rule as
    /// [`MarketMeta::open`].
    #[serde(default)]
    pub close: Option<bool>,
    /// Whether the market is mode-2 only (cross opens rejected).
    #[serde(default)]
    pub strict_isolated: Option<bool>,
    /// Governance open-interest cap in whole base units. OMITTED (→ `None`)
    /// when the market is uncapped — an absent cap is not a cap of `0`.
    #[serde(default)]
    pub oi_cap: Option<String>,
    /// Remaining open-interest headroom in whole base units — `oi_cap` minus the
    /// market's live open interest, already computed by the node.
    ///
    /// `None` = UNCAPPED, so any size passes the cap; `Some("0")` = AT the cap,
    /// so no size does. The two say opposite things, and both are absent from a
    /// caller that reconstructs the figure from `oi_cap` and `open_interest`.
    /// Read this field instead of doing that arithmetic.
    #[serde(default)]
    pub max_market_order_ntl: Option<String>,
    /// Whether the market is halted. `None` on the static `markets_meta` read.
    #[serde(default)]
    pub halted: Option<bool>,
    /// Order-book mid price, whole-USDC decimal string; `None` when the book is
    /// one-sided or the read is static.
    #[serde(default)]
    pub mid_px: Option<String>,
    /// `[bid, ask]` impact prices. OMITTED (→ `None`) when the impact notional
    /// cannot fill against the current book.
    #[serde(default)]
    pub impact_pxs: Option<Vec<String>>,
    /// Present and `true` ONLY when the oracle index is stale. The market still
    /// advertises a `mark_px`, but no aggregation pass sourced it and every risk
    /// path defers on it. A healthy market omits the key.
    #[serde(default)]
    pub px_stale: Option<bool>,
    /// Mark-vs-oracle premium, signed decimal fraction string; `None` when the
    /// read is static or no premium is computable.
    #[serde(default)]
    pub premium: Option<String>,
    /// Previous-day oracle price, whole-USDC decimal string; `None` when no
    /// 24h-ago snapshot exists.
    #[serde(default)]
    pub prev_day_px: Option<String>,
    /// Signed 24h change fraction; `None` when there is no 24h-ago price.
    #[serde(default)]
    pub change_24h: Option<String>,
    /// 24h notional volume, whole-USDC decimal string; `None` on a static read.
    #[serde(default)]
    pub day_ntl_vlm: Option<String>,
    /// Oldest consensus ms that `day_ntl_vlm` speaks for. Present ⇒ the volume
    /// is a LOWER BOUND; absent ⇒ the figure covers the whole 24h window.
    #[serde(default)]
    pub day_ntl_vlm_lower_bound_from: Option<u64>,
    /// The governance risk override in force on this market.
    ///
    /// `None` means NO override exists. `Some` with every inner field `None`
    /// means an override record exists and overrides nothing — a different
    /// fact, and the one that used to be invisible.
    #[serde(default)]
    pub risk_override: Option<RiskOverride>,
}

/// A governance risk override on one market, from [`MarketMeta::risk_override`].
///
/// Every field is optional: an override that moves only `max_leverage` carries
/// only `max_leverage`. An absent field is NOT overridden — the market's
/// default (the sibling field on the same [`MarketMeta`]) applies.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RiskOverride {
    /// Overridden maximum leverage multiple.
    #[serde(default)]
    pub max_leverage: Option<u32>,
    /// Overridden maintenance margin ratio, decimal bps string.
    #[serde(default)]
    pub maint_margin_ratio: Option<String>,
    /// Overridden initial margin ratio, decimal bps string.
    #[serde(default)]
    pub init_margin_ratio: Option<String>,
    /// Overridden per-period funding-rate cap, decimal fraction string.
    #[serde(default)]
    pub funding_rate_cap: Option<String>,
    /// Overridden open-interest cap, whole base units as a decimal string.
    #[serde(default)]
    pub oi_cap: Option<String>,
}

/// One perp row of the DYNAMIC `markets` read.
///
/// This is NOT [`MarketMeta`]. The node splits the market surface in two:
/// `markets` serves the dynamic record (live price / funding / OI / 24h
/// ticker) and `markets_meta` the static record (precision grids, leverage
/// ladder, trade-control flags). Decoding a
/// `markets` row into [`MarketMeta`] fails outright — `sz_decimals`,
/// `tick_size`, `step_size`, `min_order`, `max_leverage`, the margin ratios,
/// `mark_source` and `fba_enabled` are all absent from it. Merge by `coin` when
/// a view needs both halves.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MarketDynamic {
    /// Market symbol (e.g. `"BTC"`) — the join key onto [`MarketMeta`].
    pub coin: String,
    /// Market kind (`"perp"`).
    pub kind: MarketKind,
    /// Mark price, whole-USDC decimal string (tick-snapped; `"0"` fallback).
    pub mark_px: String,
    /// Oracle / index price, whole-USDC decimal string.
    pub oracle_px: String,
    /// Present and `true` ONLY when the oracle index is stale — the market still
    /// advertises a `mark_px` that no aggregation pass sourced. A healthy market
    /// omits the key.
    #[serde(default)]
    pub px_stale: Option<bool>,
    /// Order-book mid price; `None` when the book is one-sided.
    #[serde(default)]
    pub mid_px: Option<String>,
    /// `[bid, ask]` impact prices; `None` when the impact notional is unfillable.
    #[serde(default)]
    pub impact_pxs: Option<Vec<String>>,
    /// Mark-vs-oracle premium, signed decimal fraction; `null` when uncomputable.
    #[serde(default)]
    pub premium: Option<String>,
    /// Funding parameters.
    #[serde(default)]
    pub funding: Funding,
    /// Open interest, whole base units as a decimal string.
    #[serde(default)]
    pub open_interest: String,
    /// 24h notional volume, whole-USDC decimal string.
    #[serde(default)]
    pub day_ntl_vlm: String,
    /// Oldest consensus ms that `day_ntl_vlm` speaks for. Present ⇒ the volume
    /// is a LOWER BOUND; absent ⇒ the figure covers the whole 24h window.
    #[serde(default)]
    pub day_ntl_vlm_lower_bound_from: Option<u64>,
    /// Previous-day oracle price; `null` when no 24h-ago snapshot exists.
    #[serde(default)]
    pub prev_day_px: Option<String>,
    /// Signed 24h change fraction; `null` when there is no 24h-ago price.
    #[serde(default)]
    pub change_24h: Option<String>,
    /// Whether the market is halted.
    #[serde(default)]
    pub halted: bool,
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
    /// Size precision of the pair's BASE token: a spot order `size` is
    /// `whole_units × 10^sz_decimals`. Load-bearing — do not derive it from the
    /// quote token or from a perp of the same symbol.
    #[serde(default)]
    pub sz_decimals: u8,
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
    /// Why this leg executed when the party did NOT cross by its own order:
    /// `"forced_close_partial"` / `"forced_close_full"` (the liquidation
    /// ladder), `"forced_close_isolated"`, `"trigger"`, or `"twap"`.
    ///
    /// Absent on an ordinary fill and on EVERY maker leg — a counterparty that
    /// was merely hit is not itself forced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cause: Option<String>,
    /// The account whose position was closed. Present on a forced-close leg, on
    /// BOTH sides of the print, so a taker can see whose liquidation it took on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub liquidated_user: Option<String>,
    /// The mark the liquidation ladder priced from when it classified — NOT the
    /// fill price. Present with `liquidated_user`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mark_px: Option<String>,
    /// The broker that routed the order. Taker leg only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub broker: Option<String>,
    /// The broker carve charged on this fill, whole-USDC decimal string. `"0"`
    /// is legal — a zero-rate broker is still attributed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub broker_fee: Option<String>,
    /// The parent TWAP this slice belongs to. Present when `cause` is `"twap"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub twap_id: Option<u64>,
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
    /// Scaled-TP/SL ladder handle — same rule as [`OrderTrigger::group`].
    /// Absent unless this leg belongs to a ladder.
    #[serde(default)]
    pub group: Option<u64>,
    /// Trailing callback — same rule as [`OrderTrigger::trail_px`]. Absent on a
    /// static level; when present, `trigger_px` is the RATCHETED level.
    #[serde(default)]
    pub trail_px: Option<String>,
}

/// `order_status` response — single-order lifecycle lookup by `oid` or `cloid`.
///
/// The node resolves the FIRST hit: a live resting order, then a parked trigger,
/// then the most recent matching fill, else unknown. Tagged by the wire `status`
/// field. A cloid-only query resolves resting / triggered hits only — the fill
/// ring is oid-keyed.
// The filled variant carries a whole `Fill`, which the attribution fields made
// much larger than its siblings. The shape mirrors the wire, so boxing it would
// buy a smaller enum at the cost of an allocation on the common path.
#[allow(clippy::large_enum_variant)]
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
/// A row always carries `oid`, `coin`, `side`, `status`, `filled_sz` and `time`.
/// A deep-history row adds the optional superset (`limit_px` / `avg_px` / `sz` /
/// `orig_sz` / `total_sz` / `tif` / `reduce_only` / `cloid` / `cancel_reason` /
/// `error`) and sends no `block`. `side` is the aggressor code (`"B"` / `"A"`).
///
/// `status` is a lifecycle label. `"filled"` is the common value, but a
/// deep-history read also returns non-executed rows, so do not assume `"filled"`.
/// `px` is absent on a row that has neither an average fill price nor a limit
/// price.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct HistoricalOrder {
    /// Order id.
    pub oid: u64,
    /// Market symbol (perp) or spot pair name.
    pub coin: String,
    /// Aggressor side code (`"B"` / `"A"`).
    pub side: String,
    /// Lifecycle status. `"filled"` is the common value; a deep-history read
    /// also returns non-executed rows.
    pub status: String,
    /// Fill price, 8-dp tape decimal string. Absent when the order has neither
    /// an average fill price nor a limit price — a market order that never
    /// rested. `None` means "the server sent no price"; do not read it as zero.
    #[serde(default)]
    pub px: Option<String>,
    /// Total filled size, normalized decimal string.
    pub filled_sz: String,
    /// Row timestamp (unix ms) — the most recent fill on a filled row.
    pub time: u64,
    /// Trace hash of the most recent fill; empty for a systemic fill.
    #[serde(default)]
    pub hash: String,
    /// Committed block height. A deep-history row sends no block height.
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
    /// Pool token symbol (e.g. `"USDC"`), else `asset:<id>`.
    pub name: String,
    /// The uint32 to put in the `asset` field of a signed `earnDeposit` /
    /// `earnWithdraw`. It has no other meaning: every row is keyed by `name`.
    #[serde(default)]
    pub signing_id: u32,
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
    /// Echo of the request `start_time` (unix ms); `None` when the ask carried
    /// no lower bound.
    #[serde(default)]
    pub start_time: Option<u64>,
    /// Echo of the request `end_time` (unix ms); `None` when the ask carried no
    /// upper bound.
    #[serde(default)]
    pub end_time: Option<u64>,
    /// Fills. Newest first on an un-ranged ask, oldest first on a ranged one.
    #[serde(default)]
    pub fills: Vec<Fill>,
}

/// One CLOSED position lifecycle inside a [`UserPositionHistory`] response.
///
/// A position that is still OPEN is never in this history. Read the live
/// position from the clearinghouse state instead; the archive emits a row only
/// once the lifecycle closes.
///
/// DERIVED, never stored: `realized_pnl = closed_pnl − fee_paid` and
/// `net_pnl = realized_pnl + funding_paid`. `closed_pnl` is the chain's own
/// lot-matched number — it is NOT `(avg_close_px − avg_entry_px) × closed_sz`
/// and must not be checked that way.
///
/// THE THREE COMPLETENESS FLAGS ARE THE HONESTY MECHANISM. The archive can be
/// cut by a recorded gap or a retention floor, and a cut row still has to be
/// served. Each flag says whether the numbers on that side of the life cover
/// the WHOLE life:
///   * `entry_complete = false` ⇒ the open side is partial, and `max_sz` /
///     `avg_entry_px` come back `None` rather than wrong.
///   * `close_complete = false` ⇒ every close-side number covers part of the
///     life. It follows `entry_complete`: the cut that hid the open can hide a
///     close too.
///   * `funding_complete = false` ⇒ `funding_paid` is UNKNOWN, not zero. The
///     row still reads `"0"`, and `net_pnl` then equals `realized_pnl` and
///     excludes funding.
///
/// Test the flag before you trust the number. A row is not rejected for being
/// degraded — it is served degraded on purpose.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PositionHistoryRow {
    /// Market symbol (`"BTC"`) or spot pair name. The gateway resolves the
    /// archive's numeric market id to this symbol.
    pub coin: String,
    /// Position direction over the life: `"long"` or `"short"`.
    pub side: String,
    /// Largest size the position ever held, decimal string on the size plane.
    /// `None` exactly when `entry_complete` is `false`.
    #[serde(default)]
    pub max_sz: Option<String>,
    /// Size closed over the life, decimal string on the size plane.
    #[serde(alias = "closed_qty")]
    pub closed_sz: String,
    /// Weighted average entry price, whole-USDC decimal string. `None` exactly
    /// when `entry_complete` is `false`.
    #[serde(default)]
    pub avg_entry_px: Option<String>,
    /// Weighted average close price, whole-USDC decimal string; `None` when the
    /// archive holds no priced close side.
    #[serde(default)]
    pub avg_close_px: Option<String>,
    /// Lot-matched realized PnL before fees, whole-USDC decimal string.
    pub closed_pnl: String,
    /// Fees paid over the life, whole-USDC decimal string.
    pub fee_paid: String,
    /// `closed_pnl − fee_paid`, whole-USDC decimal string.
    pub realized_pnl: String,
    /// Funding paid over the life, whole-USDC decimal string. `"0"` with
    /// `funding_complete = false` means UNKNOWN, not "no funding was paid".
    pub funding_paid: String,
    /// `realized_pnl + funding_paid`, whole-USDC decimal string.
    pub net_pnl: String,
    /// Consensus ms the position opened.
    pub opened_at: u64,
    /// Consensus ms the position closed.
    pub closed_at: u64,
    /// Committed height the position opened at.
    pub open_block: u64,
    /// Committed height the position closed at.
    pub close_block: u64,
    /// Whether the open side covers the whole life.
    pub entry_complete: bool,
    /// Whether the close side covers the whole life.
    pub close_complete: bool,
    /// Whether `funding_paid` covers the whole life.
    pub funding_complete: bool,
}

/// `user_position_history` / `user_position_history_by_time` response — one row
/// per CLOSED position lifecycle.
///
/// The envelope is the SAME shape `user_fills` uses: the echoed address and the
/// rows, nothing else. Neither variant echoes the request window, and neither
/// carries an account-wide coverage or completeness object — per-row
/// [`PositionHistoryRow`] flags are the only completeness report.
///
/// WINDOW: `_by_time` filters on `closed_at`. A lifecycle is a point event at
/// its close, so a position OPENED before the window but CLOSED inside it IS
/// returned. `user_position_history` pages newest-first; `_by_time` reads
/// oldest-first inside the window.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct UserPositionHistory {
    /// Echo of the resolved account address.
    pub address: Address,
    /// Closed position lifecycles.
    #[serde(default)]
    pub positions: Vec<PositionHistoryRow>,
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
/// openable (`withdrawable × leverage`, plus the existing position's notional
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
    /// Remaining market-wide OI headroom in size units, or `None` when the
    /// market is UNCAPPED. It is shared headroom other traders consume, not a
    /// per-user guarantee. The retired `"0"` sentinel meant uncapped, so a client
    /// that clamped order size to it refused to trade on exactly the markets that
    /// had no cap.
    #[serde(default)]
    pub max_trade_size: Option<String>,
    /// Whether the user holds a non-zero position on the asset.
    pub has_position: bool,
}

/// One approved agent inside [`AccountOverview::agents`].
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

/// One sub-account inside [`AccountOverview::sub_accounts`].
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

/// One follower stake in a vault, inside [`AccountOverviewVault::equities`].
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

/// The vault facet of an [`AccountOverview`] snapshot.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AccountOverviewVault {
    /// Stakes the account holds as a follower.
    #[serde(default)]
    pub equities: Vec<VaultEquity>,
    /// Full state of every vault the account follows or leads.
    #[serde(default)]
    pub vaults: Vec<VaultState>,
}

/// Aggregate delegator figures, inside [`AccountOverviewStaking`].
///
/// The three balances are DISJOINT — add them for the whole staked holding.
/// `undelegated` is the free pool a `token_delegate` draws from, and the only
/// one `staking_withdraw` returns to spot with no unbonding window.
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

/// The staking facet of an [`AccountOverview`] snapshot.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AccountOverviewStaking {
    /// Per-delegation staking detail.
    pub state: StakingSnapshot,
    /// Aggregate delegator figures.
    pub summary: DelegatorSummary,
}

/// The multisig facet of an [`AccountOverview`] snapshot.
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

/// The `account_state` `detail: "overview"` shape — the account's full
/// NON-TRADING state.
///
/// The companion shape to [`AccountState`]: the default depth owns margin,
/// positions and balances, this one owns vaults, staking, sub-accounts, the
/// multisig signer set, agent (API) wallets and the derived role. Every
/// sub-object is honest-empty rather than absent.
///
/// The standalone `account_overview` `/info` type was REMOVED server-side.
/// [`Info::account_overview`] now posts the `detail` parameter and returns this
/// same shape. The WS `account_state` frame carries the DEFAULT depth only —
/// these facets are REST-read, not pushed.
///
/// `height` / `time` stamp the committed block the snapshot was read at, flat at
/// the top level.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AccountOverview {
    /// Echo of the requested address.
    pub address: Address,
    /// Derived role: `"missing"` / `"user"` / `"agent"` / `"vault"` /
    /// `"sub_account"`. `None` on a node that predates the field.
    #[serde(default)]
    pub role: Option<String>,
    /// Vault follower stakes + followed / led vault states.
    #[serde(default)]
    pub vault: AccountOverviewVault,
    /// Staking detail + aggregate delegator figures.
    #[serde(default)]
    pub staking: AccountOverviewStaking,
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

/// Insert `coin` into a request body only when present — an absent `coin` asks
/// for every market, which is a different question from one unknown market.
fn insert_coin(body: &mut Value, coin: Option<&str>) {
    if let Some(c) = coin {
        let obj = body.as_object_mut().expect("json! produced an object");
        obj.insert("coin".into(), json!(c));
    }
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
    /// List the DYNAMIC per-market state (`markets`).
    ///
    /// Returns the perp [`MarketDynamic`] records — live price, funding, open
    /// interest and the 24h ticker. This read carries NO precision grid, NO
    /// leverage ladder and NO trade-control flag; read [`Info::markets_meta`]
    /// for those and merge by `coin`.
    ///
    /// `coin` narrows the answer to ONE market. It narrows the same rows and
    /// does not change the shape, so a caller that wants one market pays one
    /// round trip and parses one shape. `None` returns every market.
    ///
    /// The deployed gateway serves `markets.data` as an OBJECT
    /// `{ "perp": [...], "spot": { pairs, tokens } }`, NOT a flat array. We
    /// decode that wrapper and return the `perp` markets (use
    /// [`Info::spot_meta`] for spot).
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`]. A `coin` the
    /// node does not know answers 404.
    pub async fn markets(&self, coin: Option<&str>) -> Result<Vec<MarketDynamic>, ClientError> {
        #[derive(serde::Deserialize)]
        struct MarketsResp {
            #[serde(default)]
            perp: Vec<MarketDynamic>,
        }
        let mut body = json!({ "type": "markets" });
        insert_coin(&mut body, coin);
        let resp: MarketsResp = self.client.post_json("/info", &body).await?;
        Ok(resp.perp)
    }

    /// List the STATIC per-market metadata (`markets_meta`).
    ///
    /// The long-cacheable half of [`Info::markets`] — precision grids
    /// (`sz_decimals` / `tick_size` / `step_size`), the leverage + `margin_tiers`
    /// ladder, `min_order`, trade-control flags, `mark_source`, the
    /// [`MarketMeta::signing_id`] write handle, and the
    /// [`MarketMeta::risk_override`] governance override. These fields are split
    /// OFF the dynamic `markets` read (which carries only live price / funding /
    /// OI), so a consumer that needs per-market precision reads `markets_meta`
    /// and merges by `coin`. Same `{ perp, spot }` envelope as `markets`; the
    /// returned perp records OMIT the dynamic price/funding/OI fields.
    /// Static → cache hard.
    ///
    /// `coin` narrows the answer to ONE market; `None` returns every market.
    ///
    /// A perp row carries an optional [`MarketMeta::token`] block (the
    /// registered underlying token — EVM binding + `circulating_supply`),
    /// omitted when no underlying token is registered. Spot token rows carry
    /// `total_supply`; use [`Info::spot_meta`] for the `spot` sub-object.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`]. A `coin` the
    /// node does not know answers 404.
    pub async fn markets_meta(&self, coin: Option<&str>) -> Result<Vec<MarketMeta>, ClientError> {
        #[derive(serde::Deserialize)]
        struct MarketsResp {
            #[serde(default)]
            perp: Vec<MarketMeta>,
        }
        let mut body = json!({ "type": "markets_meta" });
        insert_coin(&mut body, coin);
        let resp: MarketsResp = self.client.post_json("/info", &body).await?;
        Ok(resp.perp)
    }

    /// Public trade prints for one market (`trades`), recent or windowed.
    ///
    /// One read answers both asks. Pass `None` / `None` for the recent tape,
    /// newest-first, from the node's bounded ring. Pass a bound to filter by
    /// consensus `time`; a RANGED ask reaches the gateway archive, and its rows
    /// come back oldest-first. An un-ranged ask always answers from the ring.
    ///
    /// An archive-served print OMITS `hash` rather than sending `""`: on a node
    /// print `""` means "there was no signed taker action", and the archive
    /// stores no trace hash at all. Absent is unknown, `""` is a known absence.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn trades(
        &self,
        coin: &str,
        start_time: Option<u64>,
        end_time: Option<u64>,
    ) -> Result<Vec<Trade>, ClientError> {
        #[derive(serde::Deserialize)]
        struct Resp {
            #[serde(default)]
            trades: Vec<Trade>,
        }
        let mut body = json!({ "type": "trades", "coin": coin });
        insert_time_window(&mut body, start_time, end_time);
        let resp: Resp = self.client.post_json("/info", &body).await?;
        Ok(resp.trades)
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

    /// `candle_snapshot` — historical OHLCV bars for
    /// `(coin, candle_type, interval)` over a window. This is the single candle
    /// query: archive-first, with a fold of the live price stream as fallback.
    ///
    /// `coin` is a market **symbol** (e.g. `"BTC"`). `interval` is one of
    /// `1m` / `5m` / `15m` / `1h` / `4h` / `1d`. `candle_type` picks the price
    /// series — [`CandleType::Mark`] is the node default and serves perp and
    /// spot markets; [`CandleType::Oracle`] serves perp markets only, and a spot
    /// pair asked for it always answers empty. The executed-trade candle is
    /// RETIRED, so a bar carries a price series and never executions.
    ///
    /// `start_time` / `end_time` bound the window (unix ms) and filter on the
    /// bar OPEN. Bars come oldest-first; the newest is the still-forming bar. An
    /// empty vec is the honest-empty answer for a market with no history in that
    /// series.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn candle_snapshot(
        &self,
        coin: &str,
        interval: &str,
        candle_type: CandleType,
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
                        "candle_type": candle_type,
                        "start_time": start_time,
                        "end_time": end_time,
                    },
                }),
            )
            .await?;
        Ok(resp.candles)
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

    /// Fetch the fee schedule WITH one account's resolved rates.
    ///
    /// The response `user` block carries the per-product rows. Use the row for
    /// the product you are about to trade: `perp`, `spot`, `spot_margin` and
    /// `option` price apart, and the top-level `effective_*_bps` fields are the
    /// PERP ones.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn fee_schedule_for(&self, address: &str) -> Result<FeeSchedule, ClientError> {
        self.client
            .post_json(
                "/info",
                &json!({ "type": "fee_schedule", "address": address }),
            )
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

    /// List active delegations for an account. Convenience wrapper that
    /// extracts the `delegations` field from [`Info::staking_state`].
    ///
    /// # Errors
    /// See [`Info::staking_state`].
    pub async fn delegations(&self, addr: Address) -> Result<Vec<Delegation>, ClientError> {
        Ok(self.staking_state(addr).await?.state.delegations)
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

    /// `user_fills` — account-scoped fill history, keyed by `address`.
    ///
    /// One read, two asks. Pass no window for the recent records, newest first;
    /// `limit` then caps the most-recent records (absent = the full ring). Pass
    /// `start_time` / `end_time` to filter the same records by consensus `time`,
    /// which returns them oldest first. Each bound is sent only when `Some`; an
    /// absent bound is open, and the response echoes both.
    ///
    /// The gateway merges deep archive history into the node fill serializer's
    /// own response and re-applies `limit`. A SPOT `sz` rides the raw integer
    /// plane today; the human plane is the owner-ruled target. A merged
    /// archive-normalized fill may omit `block`.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn user_fills(
        &self,
        addr: Address,
        limit: Option<u32>,
        start_time: Option<u64>,
        end_time: Option<u64>,
    ) -> Result<UserFills, ClientError> {
        let mut body = json!({ "type": "user_fills", "address": addr });
        if let Some(l) = limit {
            let obj = body.as_object_mut().expect("json! produced an object");
            obj.insert("limit".into(), json!(l));
        }
        insert_time_window(&mut body, start_time, end_time);
        self.client.post_json("/info", &body).await
    }

    /// `user_position_history` — one row per CLOSED position lifecycle, keyed by
    /// `address`, newest first.
    ///
    /// A position still OPEN is never returned; read the live position from the
    /// clearinghouse state. Check each row's `entry_complete` / `close_complete`
    /// / `funding_complete` before trusting its numbers — see
    /// [`PositionHistoryRow`].
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn user_position_history(
        &self,
        addr: Address,
        limit: Option<u32>,
    ) -> Result<UserPositionHistory, ClientError> {
        let mut body = json!({ "type": "user_position_history", "address": addr });
        if let Some(l) = limit {
            let obj = body.as_object_mut().expect("json! produced an object");
            obj.insert("limit".into(), json!(l));
        }
        self.client.post_json("/info", &body).await
    }

    /// `user_position_history_by_time` — closed position lifecycles filtered to
    /// an inclusive `[start_time, end_time]` window, oldest first.
    ///
    /// The window filters on `closed_at`, so a position OPENED before the window
    /// but CLOSED inside it IS returned. Each bound is inserted only when
    /// `Some`; an absent bound is open. The reply does NOT echo the window.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn user_position_history_by_time(
        &self,
        addr: Address,
        start_time: Option<u64>,
        end_time: Option<u64>,
    ) -> Result<UserPositionHistory, ClientError> {
        let mut body = json!({ "type": "user_position_history_by_time", "address": addr });
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

    /// The account's full NON-TRADING state (vaults / staking / sub-accounts /
    /// multisig / agents / role), keyed by `address`.
    ///
    /// One round trip for every facet the default [`Info::account_state`] depth
    /// does not carry. The standalone `account_overview` `/info` type was
    /// REMOVED server-side; this posts
    /// `{"type":"account_state","detail":"overview"}` and returns the same
    /// [`AccountOverview`] shape.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn account_overview(&self, addr: Address) -> Result<AccountOverview, ClientError> {
        self.client
            .post_json(
                "/info",
                &json!({ "type": "account_state", "address": addr, "detail": "overview" }),
            )
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

    /// Vault shares ride ONE plane on both the read and the write, so a
    /// redemption sends back the exact string the read gave.
    ///
    /// The pairs are the node's own: the raw share counts its share-rendering
    /// test sweeps, converted at the 10^18 share scale. The largest is the
    /// 96-bit decimal-mantissa ceiling, 2^96-1, where the conversion is still
    /// exact.
    #[test]
    fn vault_shares_read_then_withdraw_that_exact_string() {
        const GOLDENS: &[(u128, &str)] = &[
            (0, "0"),
            (1, "0.000000000000000001"),
            (1_000_000_000_000_000_000, "1"),
            (12_345_000_000_000_000_000_000, "12345"),
            (
                79_228_162_514_264_337_593_543_950_335,
                "79228162514.264337593543950335",
            ),
        ];

        for (raw, whole) in GOLDENS {
            let served = serde_json::json!({
                "vault_id": 7u64,
                "vault_address": "0x000000000000000000000000000000000000dead",
                "shares": whole,
                "equity": "5000000000",
            });
            let eq: VaultEquity = serde_json::from_value(served).unwrap();
            assert_eq!(eq.shares, *whole, "the read plane is whole shares");

            // The withdraw carries the read string unchanged.
            let shares = crate::types::WholeShares::from(eq.shares.as_str());
            assert_eq!(shares.to_string(), *whole);
            assert_eq!(
                serde_json::to_value(&shares).unwrap(),
                serde_json::json!(whole),
                "the newtype is transparent on the wire"
            );

            // A caller that believed the old "18-dec" claim would send this.
            if *raw != 0 {
                assert_ne!(
                    shares.to_string(),
                    raw.to_string(),
                    "raw={raw} must never ride the wire rescaled by 10^18"
                );
            }
        }
    }

    /// `undelegated_pool_balance` is absent on an older node. Absent must decode
    /// as unknown, never as a zero balance.
    #[test]
    fn staking_snapshot_absent_free_pool_is_none_not_zero() {
        let without = serde_json::json!({ "total_staked": "1000" });
        let s: StakingSnapshot = serde_json::from_value(without).unwrap();
        assert_eq!(s.undelegated_pool_balance, None);

        let with = serde_json::json!({
            "total_staked": "1000",
            "undelegated_pool_balance": "250",
        });
        let s: StakingSnapshot = serde_json::from_value(with).unwrap();
        assert_eq!(s.undelegated_pool_balance.as_deref(), Some("250"));
    }

    /// Stamp the committed as-of block onto an overview-shape fixture.
    fn with_as_of(mut body: serde_json::Value) -> serde_json::Value {
        body["height"] = serde_json::json!(562u64);
        body["time"] = serde_json::json!(1_700_000_000_555u64);
        body
    }

    /// Decode the DEPLOYED gateway `markets.data` shape: an object
    /// `{ "perp": [...], "spot": {...} }`, not a flat array. `markets` must
    /// return the perp records (pre-fix: `invalid type: map, expected sequence`).
    #[test]
    fn markets_meta_decodes_perp_spot_object() {
        #[derive(serde::Deserialize)]
        struct MarketsResp {
            #[serde(default)]
            perp: Vec<MarketMeta>,
        }
        let data = serde_json::json!({
            "perp": [{
                "coin": "BTC", "signing_id": 0, "kind": "perp", "sz_decimals": 5,
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
                "coin": "ETH", "signing_id": 1, "kind": "perp", "sz_decimals": 4,
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

    /// The DYNAMIC `markets` row, byte-for-byte from chain 114514 on 2026-08-08.
    ///
    /// It carries no `sz_decimals` / `tick_size` / `step_size` / `min_order` /
    /// `max_leverage` / margin ratios / `mark_source` / `fba_enabled`, so
    /// [`MarketMeta`] cannot decode it. The old hand-written fixture above did
    /// carry them, which is why the mismatch went unseen — pin the real reply.
    #[test]
    fn markets_dynamic_row_decodes_live_reply() {
        let row = serde_json::json!({
            "change_24h": "0.01186283",
            "coin": "BTC",
            "day_ntl_vlm": "0",
            "funding": { "cap_per_hr": "400", "interval_ms": 3_600_000u64,
                         "next_payment_ts": 1_786_165_200_000u64, "rate_per_hr": "-3" },
            "halted": false,
            "impact_pxs": ["64998", "65030.7"],
            "kind": "perp",
            "mark_px": "65013.3",
            "mid_px": "65014.4",
            "open_interest": "0.7895",
            "oracle_px": "65033.7",
            "premium": "-0.00029993",
            "prev_day_px": "64251.1"
        });
        assert!(
            serde_json::from_value::<MarketMeta>(row.clone()).is_err(),
            "the static type must not silently accept a dynamic row"
        );

        let m: MarketDynamic = serde_json::from_value(row).unwrap();
        assert_eq!(m.coin, "BTC");
        assert_eq!(m.mark_px, "65013.3");
        assert_eq!(m.mid_px.as_deref(), Some("65014.4"));
        assert_eq!(m.impact_pxs.unwrap(), vec!["64998", "65030.7"]);
        assert_eq!(m.funding.cap_per_hr, "400");
        assert!(!m.halted);
        // A healthy market omits both markers; neither may read as a value.
        assert!(m.px_stale.is_none());
        assert!(m.day_ntl_vlm_lower_bound_from.is_none());
    }

    /// `user_position_history`: the envelope is address + rows, and a degraded
    /// row keeps its numbers null rather than plausible.
    #[test]
    fn user_position_history_decodes_degraded_row() {
        let data = serde_json::json!({
            "address": "0x0c4ec1cba7310669b08145f17a29b1048d9196ab",
            "positions": [{
                "avg_close_px": "74.75000000", "avg_entry_px": null,
                "close_block": 6_831_775u64, "close_complete": false,
                "closed_at": 1_786_162_051_867u64, "closed_pnl": "0.8960000000",
                "closed_sz": "0.80", "coin": "SOL", "entry_complete": false,
                "fee_paid": "0.001794", "funding_complete": false, "funding_paid": "0",
                "max_sz": null, "net_pnl": "0.8942060000", "open_block": 6_831_775u64,
                "opened_at": 1_786_162_051_867u64, "realized_pnl": "0.8942060000",
                "side": "long"
            }]
        });
        let h: UserPositionHistory = serde_json::from_value(data).unwrap();
        let p = &h.positions[0];
        assert_eq!(p.coin, "SOL");
        assert_eq!(p.side, "long");
        assert_eq!(p.closed_sz, "0.80");
        assert!(!p.entry_complete);
        assert!(p.avg_entry_px.is_none());
        assert!(p.max_sz.is_none());
        // funding_paid reads "0" while funding_complete is false: UNKNOWN, not zero.
        assert_eq!(p.funding_paid, "0");
        assert!(!p.funding_complete);
    }

    /// TODAY'S live reply must decode, not just tomorrow's. Chain 114514 on
    /// 2026-08-08 still serves `closed_qty` AND the `coverage` envelope that the
    /// batch deletes. The gateway carries both size keys across the deploy
    /// window, so the client reads either into the one approved name, and the
    /// retired envelope must pass through as an ignored key rather than a
    /// decode error.
    #[test]
    fn position_history_accepts_the_old_size_key() {
        let data = serde_json::json!({
            "address": "0x0c4ec1cba7310669b08145f17a29b1048d9196ab",
            "coverage": { "fills_gaps": [{ "from": 336_421u64, "to": 336_421u64 }],
                          "truncated": false, "complete": false },
            "positions": [{
                "coin": "SOL", "side": "long", "max_sz": "1", "closed_qty": "0.80",
                "avg_entry_px": "70", "avg_close_px": "74.75", "closed_pnl": "3.8",
                "fee_paid": "0.001794", "realized_pnl": "3.798206",
                "funding_paid": "0", "net_pnl": "3.798206",
                "opened_at": 1u64, "closed_at": 2u64, "open_block": 1u64,
                "close_block": 2u64, "entry_complete": true, "close_complete": true,
                "funding_complete": true
            }]
        });
        let h: UserPositionHistory = serde_json::from_value(data).unwrap();
        assert_eq!(h.positions[0].closed_sz, "0.80");
    }

    /// `account_state.balances`: a row with no recorded basis says `null`, and
    /// a bought row carries the whole-row cost.
    #[test]
    fn token_balance_carries_optional_avg_entry_px() {
        let rows = serde_json::json!([
            { "name": "USDC", "signing_id": 100, "total": "390548", "hold": "390548" },
            { "name": "MTF", "signing_id": 104, "total": "10000039.5196599",
              "hold": "3000000", "avg_entry_px": "412.5" }
        ]);
        let b: Vec<TokenBalance> = serde_json::from_value(rows).unwrap();
        // Deposited / pre-basis holdings carry no entry — never a zero.
        assert!(b[0].avg_entry_px.is_none());
        assert_eq!(b[1].avg_entry_px.as_deref(), Some("412.5"));
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

    /// Decode the deployed gateway `fee_schedule.data`: string bps + tiers[].
    #[test]
    fn fee_schedule_decodes_gateway_fixture() {
        let data = serde_json::json!({
            "maker_bps": "1.0",
            "taker_bps": "5.0",
            "referrer_share_bps": "5.0",
            "burn_ratio": "0.8",
            "tiers": [{ "maker_bps": "1.0", "taker_bps": "5.0", "volume_30d": "0" }]
        });
        let f: FeeSchedule = serde_json::from_value(data).unwrap();
        assert_eq!(f.maker_bps.as_deref(), Some("1.0"));
        assert_eq!(f.referrer_share_bps, "5.0");
        assert_eq!(f.burn_ratio, "0.8");
        assert_eq!(f.tiers.len(), 1);
        assert_eq!(f.tiers[0].taker_bps, "5.0");
        assert_eq!(f.tiers[0].volume_30d, "0");
        let dec: FeeSchedule = serde_json::from_str(&serde_json::to_string(&f).unwrap()).unwrap();
        assert_eq!(f, dec);

        // A source-built node may omit the top-level maker/taker pair.
        let data2 = serde_json::json!({
            "referrer_share_bps": "5.0",
            "burn_ratio": "0.8",
            "tiers": [{ "maker_bps": "1.0", "taker_bps": "5.0", "volume_30d": "0" }]
        });
        let f2: FeeSchedule = serde_json::from_value(data2).unwrap();
        assert!(f2.maker_bps.is_none() && f2.taker_bps.is_none());
    }

    /// The address form carries a `user` block with per-product rows.
    #[test]
    fn fee_schedule_decodes_the_per_product_user_block() {
        let data = serde_json::json!({
            "type": "fee_schedule",
            "tiers": [],
            "burn_ratio": "0.30",
            "referrer_share_bps": "1.0",
            "user": {
                "address": "0x00000000000000000000000000000000000000aa",
                "taker_volume_30d": "12500000",
                "maker_volume_30d": "3100000",
                "taker_bps": "4.5",
                "maker_bps": "1.5",
                "effective_taker_bps": "4.05",
                "effective_maker_bps": "1.2",
                "staking_discount_permille": 100,
                "maker_rebate_bps": "0.3",
                "products": [
                    { "product": "perp", "taker_bps": "4.05", "maker_bps": "1.2",
                      "taker_volume_30d": "12500000", "maker_volume_30d": "3100000" },
                    { "product": "spot_margin", "taker_bps": "9.0", "taker_volume_30d": "0" },
                    { "product": "option", "option_taker_bps": "0.5",
                      "option_premium_cap_ppm": 150000 }
                ]
            }
        });
        let f: FeeSchedule = serde_json::from_value(data).unwrap();
        let u = f.user.expect("the address form carries a user block");
        assert_eq!(u.staking_discount_permille, 100);
        assert_eq!(u.products.len(), 3);
        // A maker rate CAN be negative — that is a credit, not a malformed rate.
        assert_eq!(u.products[0].maker_bps.as_deref(), Some("1.2"));
        assert_eq!(u.products[0].taker_bps.as_deref(), Some("4.05"));
        // A product with no maker leg OMITS both maker keys. `None` here is
        // "no maker leg", which is NOT the same fact as a maker rate of zero.
        assert_eq!(u.products[1].product, "spot_margin");
        assert_eq!(u.products[1].maker_bps, None);
        assert_eq!(u.products[1].maker_volume_30d, None);
        // The option row is a DIFFERENT shape: no ladder tier, no volume, and
        // the two rates that actually decide its fee.
        assert_eq!(u.products[2].product, "option");
        assert_eq!(u.products[2].taker_bps, None, "no ladder tier on an option");
        assert_eq!(u.products[2].taker_volume_30d, None);
        assert_eq!(u.products[2].option_taker_bps.as_deref(), Some("0.5"));
        assert_eq!(u.products[2].option_premium_cap_ppm, Some(150_000));
    }

    /// The ladder-only read carries no `user` key, and an older server carries
    /// no `products`. Neither may fail the decode.
    #[test]
    fn fee_schedule_tolerates_an_absent_user_and_absent_products() {
        let bare: FeeSchedule = serde_json::from_value(serde_json::json!({
            "type": "fee_schedule", "tiers": [],
            "burn_ratio": "0.30", "referrer_share_bps": "1.0"
        }))
        .unwrap();
        assert!(bare.user.is_none());

        let old: FeeSchedule = serde_json::from_value(serde_json::json!({
            "type": "fee_schedule", "tiers": [],
            "burn_ratio": "0.30", "referrer_share_bps": "1.0",
            "user": {
                "address": "0x00000000000000000000000000000000000000aa",
                "taker_volume_30d": "0", "maker_volume_30d": "0",
                "taker_bps": "4.5", "maker_bps": "1.5",
                "effective_taker_bps": "4.5", "effective_maker_bps": "1.5",
                "staking_discount_permille": 0, "maker_rebate_bps": "0"
            }
        }))
        .unwrap();
        assert!(old.user.expect("user present").products.is_empty());
    }

    /// The CURRENT node `fee_schedule` body, key for key. It carries no broker
    /// rebate at all — the field was removed server-side, and the node's own
    /// tests now assert its absence — so the SDK must not offer one to read.
    #[test]
    fn fee_schedule_decodes_the_current_node_body() {
        let data = serde_json::json!({
            "tiers": [
                { "volume_30d": "0", "maker_bps": "1.0", "taker_bps": "5.0" },
                { "volume_30d": "5000000", "maker_bps": "0.8", "taker_bps": "4.0" }
            ],
            "pooled_volume_sunset_day": 20_500,
            "pooled_volume_sunset_ms": "1771200000000",
            "pooled_volume_counts": true,
            "burn_ratio": "0.7",
            "referrer_share_bps": "1000"
        });
        let f: FeeSchedule = serde_json::from_value(data).unwrap();
        assert_eq!(f.tiers.len(), 2);
        assert_eq!(f.tiers[1].taker_bps, "4.0");
        assert_eq!(f.pooled_volume_sunset_day, Some(20_500));
        assert_eq!(f.pooled_volume_counts, Some(true));
        assert_eq!(f.referrer_share_bps, "1000");
        assert!(f.maker_bps.is_none() && f.taker_bps.is_none());
        assert!(f.user.is_none());

        let round_trip: FeeSchedule =
            serde_json::from_str(&serde_json::to_string(&f).unwrap()).unwrap();
        assert_eq!(f, round_trip);
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
    /// A price bar folds no trades: `v` and `q` are `"0"` and `n` counts price
    /// SAMPLES.
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
            "v": "0",
            "q": "0",
            "n": 12
        });
        let bar: Candle = serde_json::from_value(data).unwrap();
        assert_eq!(bar.coin, "BTC");
        assert_eq!(bar.interval, "1m");
        assert_eq!(bar.open_time, 1_700_000_040_000);
        assert_eq!(bar.close_time, 1_700_000_099_999);
        assert_eq!(bar.close, "67042.5");
        assert_eq!(bar.volume, "0");
        assert_eq!(bar.quote_volume, "0");
        assert_eq!(bar.num_samples, 12);
        // Round-trips back to the compact keys.
        let j = serde_json::to_value(&bar).unwrap();
        assert_eq!(j["s"], "BTC");
        assert!(j["o"].is_string());
        assert!(j["t"].is_number());
        assert!(j["n"].is_number());
    }

    /// A carry-forward bar: no sample in the window, so the previous close is
    /// carried and `n` is `0`.
    #[test]
    fn candle_snapshot_bar_decodes_a_carry_forward_bar() {
        let bar: Candle = serde_json::from_value(serde_json::json!({
            "s": "BTC", "i": "1m",
            "t": 1_700_000_100_000u64, "T": 1_700_000_159_999u64,
            "o": "67042.5", "c": "67042.5", "h": "67042.5", "l": "67042.5",
            "v": "0", "q": "0", "n": 0
        }))
        .unwrap();
        assert_eq!(bar.num_samples, 0);
        assert_eq!(bar.open, bar.close);
        assert_eq!(bar.high, bar.low);
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
        assert!(t.hash.as_deref().is_some_and(|h| h.starts_with("0x")));
        // The node sends `""` for a systemic print: recorded, and there was no
        // signed taker action.
        let systemic = serde_json::json!({
            "coin": "BTC", "px": "1", "sz": "1", "side": "B",
            "tid": 1u64, "block": 1, "time": 1u64, "hash": ""
        });
        let s: Trade = serde_json::from_value(systemic).unwrap();
        assert_eq!(s.hash.as_deref(), Some(""), "recorded, and there was none");
        // An archive-served print OMITS the key: the table stores no hash, so
        // the fact is unknown, not empty.
        let archived = serde_json::json!({
            "coin": "BTC", "px": "1", "sz": "1", "side": "B",
            "tid": 2u64, "block": 1, "time": 1u64
        });
        let a: Trade = serde_json::from_value(archived).unwrap();
        assert_eq!(a.hash, None, "not recorded is not the same as empty");
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
        // Neither key is written on an ordinary trigger, so both stay None.
        assert_eq!(trigger.group, None);
        assert_eq!(trigger.trail_px, None);

        // A ladder leg carries `group`; a trailing leg carries `trail_px`.
        let ladder = serde_json::json!({
            "status": "triggered",
            "trigger": { "oid": 11u64, "coin": "BTC", "side": "A",
                         "trigger_px": "59000", "trigger_above": false, "sz": "1",
                         "registered_at": 3u64, "fired": false,
                         "is_market": true, "limit_px": null,
                         "group": 9u64, "trail_px": "250.5" }
        });
        let OrderStatus::Triggered { trigger } = serde_json::from_value(ladder).unwrap() else {
            panic!("expected Triggered");
        };
        assert_eq!(trigger.group, Some(9));
        assert_eq!(trigger.trail_px.as_deref(), Some("250.5"));
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
        assert_eq!(a.px.as_deref(), Some("194.78000000"));
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

    /// A `historical_orders` row can carry NO price: an order with neither an
    /// average fill price nor a limit price sends no `px` key, and a row that
    /// reports the price sources sends them as JSON `null`. Both shapes decode to
    /// `None`, and neither fails the response.
    #[test]
    fn historical_orders_decodes_rows_with_no_price() {
        let data = serde_json::json!({
            "address": "0x4242424242424242424242424242424242424242",
            "orders": [
                {
                    "oid": 11u64, "coin": "MTF", "side": "B", "status": "error",
                    "time": 30u64, "filled_sz": "0", "hash": ""
                },
                {
                    "oid": 12u64, "coin": "MTF", "side": "B", "status": "resting",
                    "time": 31u64, "filled_sz": "0", "hash": "", "px": null,
                    "limit_px": null, "avg_px": null, "total_sz": null
                }
            ]
        });
        let h: HistoricalOrders = serde_json::from_value(data).unwrap();
        assert_eq!(h.orders.len(), 2);
        // Key absent.
        assert_eq!(h.orders[0].px, None);
        assert_eq!(h.orders[0].oid, 11);
        assert_eq!(h.orders[0].filled_sz, "0");
        // Key present, value null.
        assert_eq!(h.orders[1].px, None);
        assert_eq!(h.orders[1].limit_px, None);
        assert_eq!(h.orders[1].avg_px, None);
        assert_eq!(h.orders[1].total_sz, None);
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
                { "name": "USDC", "signing_id": 0u32, "total_supplied": "10000", "total_borrowed": "4000",
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
                { "name": "USDC", "signing_id": 0u32, "total_supplied": "1", "total_borrowed": "0",
                  "idle": "1", "shares_total": "1", "share_value": "1",
                  "borrow_index": "1", "reserve_factor_bps": "0",
                  "borrow_rate_bps_annual": "0", "reserve_accrued": "0" }
            ]
        });
        let e2: EarnState = serde_json::from_value(no_user).unwrap();
        assert_eq!(e2.pools[0].user_shares, None);
        assert_eq!(e2.pools[0].user_value, None);
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
        // Parked TP/SL-LIMIT row: full trigger block. It is neither a ladder
        // leg nor a trailing leg, so both of those keys stay absent.
        assert_eq!(f.orders[2].tif.as_deref(), Some("trigger"));
        let parked = f.orders[2].trigger.as_ref().unwrap();
        assert_eq!(parked.is_parked, Some(true));
        assert_eq!(parked.is_market, Some(false));
        assert_eq!(parked.limit_px.as_deref(), Some("60950"));
        assert_eq!(parked.group, None);
        assert_eq!(parked.trail_px, None);
    }

    /// A scaled TP/SL LADDER: three or more `positionTpsl` legs share one
    /// `group`, and a trailing leg adds `trail_px`. Both keys are absent on
    /// every other row, so the older shapes must keep decoding unchanged.
    #[test]
    fn open_orders_reads_the_ladder_handle_and_the_trailing_callback() {
        let leg = |oid: u64, group: serde_json::Value, trail: serde_json::Value| {
            let mut t = serde_json::json!({
                "trigger_px": "61000", "trigger_above": false,
                "is_parked": true, "is_market": true, "limit_px": null
            });
            let o = t.as_object_mut().unwrap();
            if !group.is_null() {
                o.insert("group".into(), group);
            }
            if !trail.is_null() {
                o.insert("trail_px".into(), trail);
            }
            serde_json::json!({
                "oid": oid, "coin": "BTC", "side": "A", "px": "61000", "sz": "0.25",
                "orig_sz": null, "tif": "trigger", "reduce_only": true,
                "cloid": null, "trigger": t, "inserted_at": oid
            })
        };
        let data = serde_json::json!({
            "address": "0x4242424242424242424242424242424242424242",
            "orders": [
                leg(7, serde_json::json!(7u64), serde_json::Value::Null),
                leg(8, serde_json::json!(7u64), serde_json::Value::Null),
                leg(9, serde_json::json!(7u64), serde_json::json!("120.25")),
            ]
        });
        let f: OpenOrders = serde_json::from_value(data).unwrap();
        let groups: Vec<Option<u64>> = f
            .orders
            .iter()
            .map(|o| o.trigger.as_ref().unwrap().group)
            .collect();
        // Every leg of one ladder shares the handle of its first leg.
        assert_eq!(groups, vec![Some(7), Some(7), Some(7)]);
        assert_eq!(f.orders[0].trigger.as_ref().unwrap().trail_px, None);
        assert_eq!(
            f.orders[2].trigger.as_ref().unwrap().trail_px.as_deref(),
            Some("120.25")
        );
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
        assert_eq!(a.max_trade_size.as_deref(), Some("500"));
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
        let a: AccountOverview = serde_json::from_value(with_as_of(data)).unwrap();
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
        let s: AccountOverview = serde_json::from_value(with_as_of(data)).unwrap();
        assert_eq!(s.sub_accounts.len(), 2);
        assert_eq!(s.sub_accounts[0].index, 1);
        assert_eq!(s.sub_accounts[0].equity, "1234.5");
        assert_eq!(s.sub_accounts[1].equity, "0");
    }
}
