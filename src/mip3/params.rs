//! Typed MIP-3 deployment params + per-step `Action` variants.
//!
//! MIP-3 (MetaFlux Improvement Proposal #3) lets any builder deploy a new
//! perp or spot market via a gas-auction credit + a sequence of signed
//! `perpDeploy` / `spotDeploy` sub-actions. This module mirrors the L1's
//! per-sub-action variants with strongly-typed Rust structs so callers
//! never need to hand-craft EIP-712 payloads.
//!
//! ## Per-sub-action mapping (perp track)
//!
//! The full perp deploy sequence is **8 actions** in this order:
//!
//! 1. `register_asset`     — book the asset name / symbol / size decimals.
//! 2. `set_oracle`         — pin the 10-source subset for the oracle (ADR-018).
//! 3. `set_leverage`       — max leverage (1..=50).
//! 4. `set_fees`           — taker/maker bps + the deployer's MIP-3 fee.
//! 5. `set_min_order_size` — floor on size in post-decimal units.
//! 6. `set_funding_params` — default funding clamps (handled by the SDK).
//! 7. `register_market`    — bind the asset to a new `market_id` slot.
//! 8. `activate_market`    — flip the market live (`status=active`).
//!
//! The spot track is similar but the sequence is shorter (4 actions):
//! 1. `register_pair` — bind `(base_asset_id, quote_asset_id) -> pair_id`.
//! 2. `set_fees`
//! 3. `set_min_notional`
//! 4. `activate_pair`
//!
//! ## Determinism
//!
//! - All sizes / notionals use `u128`; all fee bps are `i16` (negative = rebate).
//! - The output sequence is ordered deterministically; no `HashMap`.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::error::ClientError;

// ---- Oracle source enum (10 sources, ADR-018) ----

/// One oracle price source the deployer can include in the perp's price feed.
///
/// MTF maintains 10 candidate sources; the deployer picks a subset and the
/// L1 medianizer uses governance-weighted aggregation across the selected
/// subset (per ADR-018). The deployer cannot set weights — only inclusion.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleSource {
    /// Binance spot order book midpoint.
    Binance,
    /// OKX spot midpoint.
    Okx,
    /// Bybit spot midpoint.
    Bybit,
    /// Coinbase Advanced Trade midpoint.
    Coinbase,
    /// Kraken spot midpoint.
    Kraken,
    /// KuCoin spot midpoint.
    Kucoin,
    /// Gate.io spot midpoint.
    Gate,
    /// MEXC spot midpoint.
    Mexc,
    /// Bitget spot midpoint.
    Bitget,
    /// MetaFlux on-chain spot midpoint (only available once the matching MTF spot pair exists).
    MtfSpot,
}

impl OracleSource {
    /// All 10 sources, ordered as they appear in the L1 oracle config.
    #[must_use]
    pub const fn all() -> [Self; 10] {
        [
            Self::Binance,
            Self::Okx,
            Self::Bybit,
            Self::Coinbase,
            Self::Kraken,
            Self::Kucoin,
            Self::Gate,
            Self::Mexc,
            Self::Bitget,
            Self::MtfSpot,
        ]
    }
}

// ---- The typed Action variants this module builds ----

/// A single signed MIP-3 sub-action.
///
/// Each variant carries exactly the typed payload the L1 handler expects;
/// [`Action::to_json`] produces the canonical wire JSON the SDK posts to
/// `/exchange`. The variants intentionally match the L1's `perpDeploy` /
/// `spotDeploy` sub-discriminator naming so the L1-side reviewer can pair
/// each variant 1:1 with a handler.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Register a new perp asset name + decimals (sub-action 1/8).
    PerpRegisterAsset {
        /// Asset name, e.g. `"ETH-PERP"`.
        asset_name: String,
        /// Ticker symbol, e.g. `"ETH"`.
        asset_symbol: String,
        /// Number of decimals for the size field (typical 8).
        decimals: u8,
    },
    /// Pin the oracle source subset (sub-action 2/8).
    PerpSetOracle {
        /// Asset name (echo).
        asset_name: String,
        /// Selected sources, sorted in `OracleSource::all()` canonical order.
        oracle_sources: Vec<OracleSource>,
    },
    /// Set max leverage (sub-action 3/8).
    PerpSetLeverage {
        /// Asset name (echo).
        asset_name: String,
        /// 1..=50.
        max_leverage: u8,
    },
    /// Set taker/maker fee + MIP-3 deployer fee (sub-action 4/8).
    PerpSetFees {
        /// Asset name (echo).
        asset_name: String,
        /// Taker fee in bps × 10 (0..=50, i.e. ≤ 5 bps).
        taker_fee_bps: i16,
        /// Maker fee in bps × 10. Negative = rebate, floor -2.
        maker_fee_bps: i16,
        /// Deployer fee in bps × 10 (≤ 5 per ADR-012).
        deployer_fee_bps: u16,
    },
    /// Set minimum order size in size-decimal units (sub-action 5/8).
    PerpSetMinOrderSize {
        /// Asset name (echo).
        asset_name: String,
        /// Min size in post-decimal units.
        min_order_size: u128,
    },
    /// Set default funding params (sub-action 6/8).
    ///
    /// The SDK uses MTF defaults: 1h funding interval, clamp ±0.5% / 8h.
    /// These are not currently customizable through the SDK — open ticket
    /// to expose if the L1 handler ever surfaces per-market overrides.
    PerpSetFundingParams {
        /// Asset name (echo).
        asset_name: String,
    },
    /// Bind the asset to a new market id slot (sub-action 7/8).
    PerpRegisterMarket {
        /// Asset name (echo).
        asset_name: String,
    },
    /// Flip the market to `status=active` (sub-action 8/8).
    PerpActivateMarket {
        /// Asset name (echo).
        asset_name: String,
    },

    // ---- Spot track (4 sub-actions) ----
    /// Bind (base, quote) asset IDs to a fresh pair id (sub-action 1/4).
    SpotRegisterPair {
        /// Base asset id (from `register_asset` in the perp track or a pre-existing token).
        base_asset_id: u32,
        /// Quote asset id (typically USDC = 0).
        quote_asset_id: u32,
        /// Human-readable name, e.g. `"ETH-USDC"`.
        name: String,
    },
    /// Set taker/maker fees on the spot pair (sub-action 2/4).
    SpotSetFees {
        /// Pair name (echo).
        name: String,
        /// Taker fee bps × 10.
        taker_fee_bps: i16,
        /// Maker fee bps × 10. Negative = rebate.
        maker_fee_bps: i16,
    },
    /// Set min notional (in USD cents) for the spot pair (sub-action 3/4).
    SpotSetMinNotional {
        /// Pair name (echo).
        name: String,
        /// Minimum notional per fill in USD cents.
        min_notional_cents: u128,
    },
    /// Activate the spot pair (sub-action 4/4).
    SpotActivatePair {
        /// Pair name (echo).
        name: String,
    },
}

impl Action {
    /// Canonical wire-JSON shape this action serializes to when posted to
    /// `/exchange`. The `type` discriminator follows the L1 handler naming.
    #[must_use]
    pub fn to_json(&self) -> Value {
        match self {
            Self::PerpRegisterAsset {
                asset_name,
                asset_symbol,
                decimals,
            } => json!({
                "type": "perp_register_asset",
                "asset_name": asset_name,
                "asset_symbol": asset_symbol,
                "decimals": decimals,
            }),
            Self::PerpSetOracle {
                asset_name,
                oracle_sources,
            } => json!({
                "type": "perp_set_oracle",
                "asset_name": asset_name,
                "oracle_sources": oracle_sources,
            }),
            Self::PerpSetLeverage {
                asset_name,
                max_leverage,
            } => json!({
                "type": "perp_set_leverage",
                "asset_name": asset_name,
                "max_leverage": max_leverage,
            }),
            Self::PerpSetFees {
                asset_name,
                taker_fee_bps,
                maker_fee_bps,
                deployer_fee_bps,
            } => json!({
                "type": "perp_set_fees",
                "asset_name": asset_name,
                "taker_fee_bps": taker_fee_bps,
                "maker_fee_bps": maker_fee_bps,
                "deployer_fee_bps": deployer_fee_bps,
            }),
            Self::PerpSetMinOrderSize {
                asset_name,
                min_order_size,
            } => json!({
                "type": "perp_set_min_order_size",
                "asset_name": asset_name,
                "min_order_size": min_order_size,
            }),
            Self::PerpSetFundingParams { asset_name } => json!({
                "type": "perp_set_funding_params",
                "asset_name": asset_name,
            }),
            Self::PerpRegisterMarket { asset_name } => json!({
                "type": "perp_register_market",
                "asset_name": asset_name,
            }),
            Self::PerpActivateMarket { asset_name } => json!({
                "type": "perp_activate_market",
                "asset_name": asset_name,
            }),
            Self::SpotRegisterPair {
                base_asset_id,
                quote_asset_id,
                name,
            } => json!({
                "type": "spot_register_pair",
                "base_asset_id": base_asset_id,
                "quote_asset_id": quote_asset_id,
                "name": name,
            }),
            Self::SpotSetFees {
                name,
                taker_fee_bps,
                maker_fee_bps,
            } => json!({
                "type": "spot_set_fees",
                "name": name,
                "taker_fee_bps": taker_fee_bps,
                "maker_fee_bps": maker_fee_bps,
            }),
            Self::SpotSetMinNotional {
                name,
                min_notional_cents,
            } => json!({
                "type": "spot_set_min_notional",
                "name": name,
                "min_notional_cents": min_notional_cents,
            }),
            Self::SpotActivatePair { name } => json!({
                "type": "spot_activate_pair",
                "name": name,
            }),
        }
    }

    /// Discriminator string for this action — matches the wire `"type"` field.
    #[must_use]
    pub fn type_id(&self) -> &'static str {
        match self {
            Self::PerpRegisterAsset { .. } => "perp_register_asset",
            Self::PerpSetOracle { .. } => "perp_set_oracle",
            Self::PerpSetLeverage { .. } => "perp_set_leverage",
            Self::PerpSetFees { .. } => "perp_set_fees",
            Self::PerpSetMinOrderSize { .. } => "perp_set_min_order_size",
            Self::PerpSetFundingParams { .. } => "perp_set_funding_params",
            Self::PerpRegisterMarket { .. } => "perp_register_market",
            Self::PerpActivateMarket { .. } => "perp_activate_market",
            Self::SpotRegisterPair { .. } => "spot_register_pair",
            Self::SpotSetFees { .. } => "spot_set_fees",
            Self::SpotSetMinNotional { .. } => "spot_set_min_notional",
            Self::SpotActivatePair { .. } => "spot_activate_pair",
        }
    }
}

// ---- PerpDeployBuilder ----

/// Builder for a MIP-3 perp deploy sequence.
///
/// Construct with [`PerpDeployBuilder::new`] (validates ranges) or one of
/// the presets in [`crate::mip3::templates`]. Customise with `with_*`
/// setters, then call [`PerpDeployBuilder::deploy_sequence`] to get the
/// 8-action sequence ready for submission, or invoke any of the per-step
/// `build_*` constructors to inspect individual sub-actions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PerpDeployBuilder {
    /// Asset name, e.g. `"ETH-PERP"`.
    pub asset_name: String,
    /// Asset ticker symbol, e.g. `"ETH"`.
    pub asset_symbol: String,
    /// Decimals for size (typical 8).
    pub decimals: u8,
    /// Subset of the 10 supported oracle sources (ADR-018).
    pub oracle_sources: Vec<OracleSource>,
    /// Max leverage, in `1..=50`.
    pub max_leverage: u8,
    /// Taker fee in bps × 10. Hard cap 50 (5 bps).
    pub taker_fee_bps: i16,
    /// Maker fee in bps × 10. Negative = rebate, floor -2.
    pub maker_fee_bps: i16,
    /// Minimum order size in size-decimal units.
    pub min_order_size: u128,
    /// MIP-3 deployer fee in bps × 10 (≤ 5 per ADR-012).
    pub deployer_fee_bps: u16,
}

impl PerpDeployBuilder {
    /// Construct a builder with all required fields set and range-check
    /// each one.
    ///
    /// The argument list is intentionally long — the only sensible
    /// alternative is a typestate builder, which would explode the API
    /// surface for marginal benefit. Use the presets in
    /// [`crate::mip3::templates`] for typical configurations and chain
    /// `with_*` setters.
    ///
    /// # Errors
    /// Returns [`ClientError::Validation`] if any of the parameter ranges
    /// is violated (see the field docs for limits).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        asset_name: impl Into<String>,
        asset_symbol: impl Into<String>,
        decimals: u8,
        oracle_sources: Vec<OracleSource>,
        max_leverage: u8,
        taker_fee_bps: i16,
        maker_fee_bps: i16,
        min_order_size: u128,
        deployer_fee_bps: u16,
    ) -> Result<Self, ClientError> {
        let me = Self {
            asset_name: asset_name.into(),
            asset_symbol: asset_symbol.into(),
            decimals,
            oracle_sources,
            max_leverage,
            taker_fee_bps,
            maker_fee_bps,
            min_order_size,
            deployer_fee_bps,
        };
        me.validate()?;
        Ok(me)
    }

    /// Override asset name; returns `self` for chaining.
    #[must_use]
    pub fn with_asset_name(mut self, name: impl Into<String>) -> Self {
        self.asset_name = name.into();
        self
    }

    /// Override asset symbol; returns `self` for chaining.
    #[must_use]
    pub fn with_asset_symbol(mut self, symbol: impl Into<String>) -> Self {
        self.asset_symbol = symbol.into();
        self
    }

    /// Override max leverage; returns `self` for chaining. Caller is
    /// responsible for revalidating via [`PerpDeployBuilder::validate`] if
    /// the new value might be out of range.
    #[must_use]
    pub fn with_max_leverage(mut self, lev: u8) -> Self {
        self.max_leverage = lev;
        self
    }

    /// Override taker fee bps; returns `self` for chaining.
    #[must_use]
    pub fn with_taker_fee_bps(mut self, bps: i16) -> Self {
        self.taker_fee_bps = bps;
        self
    }

    /// Override maker fee bps; returns `self` for chaining.
    #[must_use]
    pub fn with_maker_fee_bps(mut self, bps: i16) -> Self {
        self.maker_fee_bps = bps;
        self
    }

    /// Override min order size; returns `self` for chaining.
    #[must_use]
    pub fn with_min_order_size(mut self, sz: u128) -> Self {
        self.min_order_size = sz;
        self
    }

    /// Override deployer fee bps; returns `self` for chaining.
    #[must_use]
    pub fn with_deployer_fee_bps(mut self, bps: u16) -> Self {
        self.deployer_fee_bps = bps;
        self
    }

    /// Override oracle sources subset; returns `self` for chaining.
    #[must_use]
    pub fn with_oracle_sources(mut self, sources: Vec<OracleSource>) -> Self {
        self.oracle_sources = sources;
        self
    }

    /// Validate the builder's parameters against the L1 limits.
    ///
    /// # Errors
    /// Returns [`ClientError::Validation`] on any violation:
    /// - asset name / symbol empty
    /// - max_leverage outside `1..=50`
    /// - taker_fee_bps > 100 (10 bps) or < 0  — same `bps × 10` convention as `fee_schedule`
    /// - maker_fee_bps > 100 or < -20 (rebate floor -2 bps)
    /// - deployer_fee_bps > 50 (5 bps per ADR-012, scaled ×10)
    /// - oracle_sources empty or contains duplicates
    /// - decimals > 18
    ///
    /// Note on the ×10 convention: this matches the existing
    /// [`crate::rest::info::FeeSchedule`] convention — `45` means 4.5 bps.
    /// The hard taker cap is `100` (= 10 bps) to permit long-tail markets
    /// where a higher take is appropriate; the L1 governance can still
    /// reject above the policy threshold (~5 bps for mainstream).
    pub fn validate(&self) -> Result<(), ClientError> {
        if self.asset_name.is_empty() {
            return Err(ClientError::Validation("asset_name is empty".into()));
        }
        if self.asset_symbol.is_empty() {
            return Err(ClientError::Validation("asset_symbol is empty".into()));
        }
        if self.decimals > 18 {
            return Err(ClientError::Validation(format!(
                "decimals {} exceeds max 18",
                self.decimals
            )));
        }
        if self.max_leverage == 0 || self.max_leverage > 50 {
            return Err(ClientError::Validation(format!(
                "max_leverage {} out of range [1, 50]",
                self.max_leverage
            )));
        }
        if self.taker_fee_bps < 0 || self.taker_fee_bps > 100 {
            return Err(ClientError::Validation(format!(
                "taker_fee_bps {} out of range [0, 100] (bps×10)",
                self.taker_fee_bps
            )));
        }
        if self.maker_fee_bps > 100 || self.maker_fee_bps < -20 {
            return Err(ClientError::Validation(format!(
                "maker_fee_bps {} out of range [-20, 100] (bps×10)",
                self.maker_fee_bps
            )));
        }
        if self.deployer_fee_bps > 50 {
            return Err(ClientError::Validation(format!(
                "deployer_fee_bps {} exceeds 5 bps cap (50 in bps×10) per ADR-012",
                self.deployer_fee_bps
            )));
        }
        if self.oracle_sources.is_empty() {
            return Err(ClientError::Validation(
                "oracle_sources cannot be empty".into(),
            ));
        }
        // Duplicate check using sorted Vec rather than HashSet (CLAUDE.md determinism rule).
        let mut sorted = self.oracle_sources.clone();
        sorted.sort();
        for w in sorted.windows(2) {
            if w[0] == w[1] {
                return Err(ClientError::Validation(format!(
                    "duplicate oracle source: {:?}",
                    w[0]
                )));
            }
        }
        Ok(())
    }

    /// Build the `perp_register_asset` action (step 1/8).
    #[must_use]
    pub fn build_register_asset(&self) -> Action {
        Action::PerpRegisterAsset {
            asset_name: self.asset_name.clone(),
            asset_symbol: self.asset_symbol.clone(),
            decimals: self.decimals,
        }
    }

    /// Build the `perp_set_oracle` action (step 2/8).
    ///
    /// Sources are emitted in `OracleSource::all()` canonical order regardless
    /// of the order they were inserted in the builder.
    #[must_use]
    pub fn build_set_oracle(&self) -> Action {
        let mut sources = self.oracle_sources.clone();
        sources.sort();
        Action::PerpSetOracle {
            asset_name: self.asset_name.clone(),
            oracle_sources: sources,
        }
    }

    /// Build the `perp_set_leverage` action (step 3/8).
    #[must_use]
    pub fn build_set_leverage(&self) -> Action {
        Action::PerpSetLeverage {
            asset_name: self.asset_name.clone(),
            max_leverage: self.max_leverage,
        }
    }

    /// Build the `perp_set_fees` action (step 4/8).
    #[must_use]
    pub fn build_set_fees(&self) -> Action {
        Action::PerpSetFees {
            asset_name: self.asset_name.clone(),
            taker_fee_bps: self.taker_fee_bps,
            maker_fee_bps: self.maker_fee_bps,
            deployer_fee_bps: self.deployer_fee_bps,
        }
    }

    /// Build the `perp_set_min_order_size` action (step 5/8).
    #[must_use]
    pub fn build_set_min_order_size(&self) -> Action {
        Action::PerpSetMinOrderSize {
            asset_name: self.asset_name.clone(),
            min_order_size: self.min_order_size,
        }
    }

    /// Build the `perp_set_funding_params` action (step 6/8).
    #[must_use]
    pub fn build_set_funding_params(&self) -> Action {
        Action::PerpSetFundingParams {
            asset_name: self.asset_name.clone(),
        }
    }

    /// Build the `perp_register_market` action (step 7/8).
    #[must_use]
    pub fn build_register_market(&self) -> Action {
        Action::PerpRegisterMarket {
            asset_name: self.asset_name.clone(),
        }
    }

    /// Build the `perp_activate_market` action (step 8/8).
    #[must_use]
    pub fn build_activate_market(&self) -> Action {
        Action::PerpActivateMarket {
            asset_name: self.asset_name.clone(),
        }
    }

    /// Produce the full ordered 8-action deploy sequence.
    ///
    /// Each item is independently signable; the SDK does not implicitly
    /// chain them. Callers MUST submit them in order; the L1 handler
    /// rejects out-of-order or skipped steps.
    #[must_use]
    pub fn deploy_sequence(&self) -> Vec<Action> {
        vec![
            self.build_register_asset(),
            self.build_set_oracle(),
            self.build_set_leverage(),
            self.build_set_fees(),
            self.build_set_min_order_size(),
            self.build_set_funding_params(),
            self.build_register_market(),
            self.build_activate_market(),
        ]
    }
}

// ---- SpotDeployBuilder ----

/// Builder for a MIP-3 spot pair deploy sequence (4 actions).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpotDeployBuilder {
    /// Base asset id (typically obtained via a prior token register / perp deploy).
    pub base_asset_id: u32,
    /// Quote asset id (typically USDC = 0).
    pub quote_asset_id: u32,
    /// Human-readable name, e.g. `"ETH-USDC"`.
    pub name: String,
    /// Taker fee bps × 10.
    pub taker_fee_bps: i16,
    /// Maker fee bps × 10. Negative = rebate.
    pub maker_fee_bps: i16,
    /// Min notional per fill in USD cents.
    pub min_notional_cents: u128,
}

impl SpotDeployBuilder {
    /// Construct + validate.
    ///
    /// # Errors
    /// Returns [`ClientError::Validation`] on:
    /// - `name` empty
    /// - taker_fee_bps > 100 or < 0 (bps×10 convention)
    /// - maker_fee_bps > 100 or < -20 (bps×10)
    /// - base == quote (would create a degenerate pair)
    pub fn new(
        base_asset_id: u32,
        quote_asset_id: u32,
        name: impl Into<String>,
        taker_fee_bps: i16,
        maker_fee_bps: i16,
        min_notional_cents: u128,
    ) -> Result<Self, ClientError> {
        let me = Self {
            base_asset_id,
            quote_asset_id,
            name: name.into(),
            taker_fee_bps,
            maker_fee_bps,
            min_notional_cents,
        };
        me.validate()?;
        Ok(me)
    }

    /// Validate this spot builder.
    ///
    /// # Errors
    /// See [`SpotDeployBuilder::new`].
    pub fn validate(&self) -> Result<(), ClientError> {
        if self.name.is_empty() {
            return Err(ClientError::Validation("name is empty".into()));
        }
        if self.base_asset_id == self.quote_asset_id {
            return Err(ClientError::Validation(format!(
                "base ({}) == quote ({}) — degenerate pair",
                self.base_asset_id, self.quote_asset_id
            )));
        }
        if self.taker_fee_bps < 0 || self.taker_fee_bps > 100 {
            return Err(ClientError::Validation(format!(
                "taker_fee_bps {} out of range [0, 100] (bps×10)",
                self.taker_fee_bps
            )));
        }
        if self.maker_fee_bps > 100 || self.maker_fee_bps < -20 {
            return Err(ClientError::Validation(format!(
                "maker_fee_bps {} out of range [-20, 100] (bps×10)",
                self.maker_fee_bps
            )));
        }
        Ok(())
    }

    /// Override name; returns `self` for chaining.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Override base asset id; returns `self` for chaining.
    #[must_use]
    pub fn with_base_asset_id(mut self, id: u32) -> Self {
        self.base_asset_id = id;
        self
    }

    /// Override quote asset id; returns `self` for chaining.
    #[must_use]
    pub fn with_quote_asset_id(mut self, id: u32) -> Self {
        self.quote_asset_id = id;
        self
    }

    /// Override taker fee bps.
    #[must_use]
    pub fn with_taker_fee_bps(mut self, bps: i16) -> Self {
        self.taker_fee_bps = bps;
        self
    }

    /// Override maker fee bps.
    #[must_use]
    pub fn with_maker_fee_bps(mut self, bps: i16) -> Self {
        self.maker_fee_bps = bps;
        self
    }

    /// Override min notional.
    #[must_use]
    pub fn with_min_notional_cents(mut self, n: u128) -> Self {
        self.min_notional_cents = n;
        self
    }

    /// Build `spot_register_pair` (step 1/4).
    #[must_use]
    pub fn build_register_pair(&self) -> Action {
        Action::SpotRegisterPair {
            base_asset_id: self.base_asset_id,
            quote_asset_id: self.quote_asset_id,
            name: self.name.clone(),
        }
    }

    /// Build `spot_set_fees` (step 2/4).
    #[must_use]
    pub fn build_set_fees(&self) -> Action {
        Action::SpotSetFees {
            name: self.name.clone(),
            taker_fee_bps: self.taker_fee_bps,
            maker_fee_bps: self.maker_fee_bps,
        }
    }

    /// Build `spot_set_min_notional` (step 3/4).
    #[must_use]
    pub fn build_set_min_notional(&self) -> Action {
        Action::SpotSetMinNotional {
            name: self.name.clone(),
            min_notional_cents: self.min_notional_cents,
        }
    }

    /// Build `spot_activate_pair` (step 4/4).
    #[must_use]
    pub fn build_activate_pair(&self) -> Action {
        Action::SpotActivatePair {
            name: self.name.clone(),
        }
    }

    /// Full 4-action deploy sequence in order.
    #[must_use]
    pub fn deploy_sequence(&self) -> Vec<Action> {
        vec![
            self.build_register_pair(),
            self.build_set_fees(),
            self.build_set_min_notional(),
            self.build_activate_pair(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_perp() -> PerpDeployBuilder {
        PerpDeployBuilder::new(
            "FOO-PERP",
            "FOO",
            8,
            vec![OracleSource::Binance, OracleSource::Okx],
            10,
            45,
            15,
            1_000,
            5,
        )
        .unwrap()
    }

    #[test]
    fn perp_builder_validates_leverage_range() {
        let e = PerpDeployBuilder::new(
            "X-PERP",
            "X",
            8,
            vec![OracleSource::Binance],
            51, // out of range
            10,
            10,
            10,
            5,
        )
        .unwrap_err();
        assert!(matches!(e, ClientError::Validation(_)));
    }

    #[test]
    fn perp_builder_validates_taker_fee_cap() {
        let e = PerpDeployBuilder::new(
            "X-PERP",
            "X",
            8,
            vec![OracleSource::Binance],
            10,
            101, // > 100 → reject (cap is 10 bps in bps×10)
            10,
            10,
            5,
        )
        .unwrap_err();
        assert!(matches!(e, ClientError::Validation(_)));
    }

    #[test]
    fn perp_builder_validates_deployer_cap() {
        let e = PerpDeployBuilder::new(
            "X-PERP",
            "X",
            8,
            vec![OracleSource::Binance],
            10,
            10,
            10,
            10,
            60, // > 50 → reject
        )
        .unwrap_err();
        assert!(matches!(e, ClientError::Validation(_)));
    }

    #[test]
    fn perp_builder_rejects_empty_oracle_sources() {
        let e = PerpDeployBuilder::new("X-PERP", "X", 8, vec![], 10, 10, 10, 10, 5).unwrap_err();
        assert!(matches!(e, ClientError::Validation(_)));
    }

    #[test]
    fn perp_builder_rejects_duplicate_oracle_sources() {
        let e = PerpDeployBuilder::new(
            "X-PERP",
            "X",
            8,
            vec![OracleSource::Binance, OracleSource::Binance],
            10,
            10,
            10,
            10,
            5,
        )
        .unwrap_err();
        assert!(matches!(e, ClientError::Validation(_)));
    }

    #[test]
    fn perp_builder_allows_negative_maker_rebate() {
        let b = PerpDeployBuilder::new(
            "X-PERP",
            "X",
            8,
            vec![OracleSource::Binance],
            10,
            10,
            -10, // rebate
            10,
            5,
        );
        assert!(b.is_ok());
    }

    #[test]
    fn perp_deploy_sequence_has_eight_actions_in_order() {
        let b = ok_perp();
        let seq = b.deploy_sequence();
        assert_eq!(seq.len(), 8);
        assert_eq!(
            seq.iter().map(Action::type_id).collect::<Vec<_>>(),
            vec![
                "perp_register_asset",
                "perp_set_oracle",
                "perp_set_leverage",
                "perp_set_fees",
                "perp_set_min_order_size",
                "perp_set_funding_params",
                "perp_register_market",
                "perp_activate_market",
            ]
        );
    }

    #[test]
    fn perp_action_json_uses_snake_case_and_plain_integers() {
        let b = ok_perp();
        let json = b.build_set_fees().to_json();
        assert!(json.get("taker_fee_bps").is_some());
        assert!(json.get("maker_fee_bps").is_some());
        assert!(json.get("deployer_fee_bps").is_some());
        assert!(json["taker_fee_bps"].is_number());
        assert!(json["maker_fee_bps"].is_number());
    }

    #[test]
    fn perp_set_oracle_sorts_sources_deterministically() {
        let b = PerpDeployBuilder::new(
            "X-PERP",
            "X",
            8,
            vec![
                OracleSource::Okx,
                OracleSource::Binance,
                OracleSource::Coinbase,
            ],
            10,
            10,
            10,
            10,
            5,
        )
        .unwrap();
        let a = b.build_set_oracle();
        let b2 = b.build_set_oracle();
        assert_eq!(a, b2, "deterministic output");
        let j = a.to_json();
        let sources: Vec<String> = j["oracle_sources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert_eq!(sources, vec!["binance", "okx", "coinbase"]);
    }

    #[test]
    fn perp_with_chaining_preserves_other_fields() {
        let b = ok_perp().with_asset_name("BAR-PERP").with_max_leverage(20);
        assert_eq!(b.asset_name, "BAR-PERP");
        assert_eq!(b.max_leverage, 20);
        assert_eq!(b.asset_symbol, "FOO"); // unchanged
    }

    #[test]
    fn spot_builder_rejects_same_base_quote() {
        let e = SpotDeployBuilder::new(1, 1, "X-X", 10, 10, 1000).unwrap_err();
        assert!(matches!(e, ClientError::Validation(_)));
    }

    #[test]
    fn spot_deploy_sequence_has_four_actions() {
        let b = SpotDeployBuilder::new(2, 0, "ETH-USDC", 10, -5, 1_000).unwrap();
        let seq = b.deploy_sequence();
        assert_eq!(seq.len(), 4);
        assert_eq!(
            seq.iter().map(Action::type_id).collect::<Vec<_>>(),
            vec![
                "spot_register_pair",
                "spot_set_fees",
                "spot_set_min_notional",
                "spot_activate_pair",
            ]
        );
    }

    #[test]
    fn action_type_id_matches_json_type_field() {
        let a = Action::PerpRegisterAsset {
            asset_name: "FOO".into(),
            asset_symbol: "F".into(),
            decimals: 8,
        };
        assert_eq!(a.type_id(), "perp_register_asset");
        assert_eq!(a.to_json()["type"], "perp_register_asset");
    }

    #[test]
    fn oracle_source_all_returns_ten_sources() {
        assert_eq!(OracleSource::all().len(), 10);
        // Should not contain duplicates.
        let mut sorted = OracleSource::all().to_vec();
        sorted.sort();
        for w in sorted.windows(2) {
            assert_ne!(w[0], w[1]);
        }
    }
}
