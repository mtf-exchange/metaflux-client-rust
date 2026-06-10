//! Preset [`PerpDeployBuilder`] configurations for common MIP-3 deployments.
//!
//! Each preset is a *starting point* — callers should `with_*`-chain to
//! customize asset name / symbol / fee tiers as appropriate. The presets
//! are deliberately conservative; they pick mainstream defaults that match
//! the L1's S10 launch parameters.
//!
//! Listed presets:
//!
//! | Preset                    | Leverage | Taker | Maker  | Min size | Oracle sources |
//! |---------------------------|---------:|------:|-------:|---------:|---------------:|
//! | `btc_standard`       |       50 |  4.5  |  -1.0  |   10_000 |   all 10       |
//! | `eth_standard`       |       50 |  4.5  |  -1.0  |   10_000 |   all 10       |
//! | `long_tail_default`  |       10 |  8.0  |   0.0  |   10_000 |   8/10 (no CB/Kraken) |
//! | `mm_friendly`        |       20 |  3.0  |  -2.0  |    1_000 |   all 10       |
//!
//! Notes:
//! - All fee bps are stored ×10 internally (so 4.5 bps is `45`).
//! - Deployer fee is the builder's take (capped at 5 bps, i.e. `50`).
//! - The `long_tail_default` excludes Coinbase + Kraken because they
//!   rarely list long-tail / new assets quickly, so their data would be
//!   stale; better to drop them and let the medianizer use the listed venues.

use crate::mip3::params::{OracleSource, PerpDeployBuilder};

/// Standard BTC-PERP preset.
///
/// Leverage 50, taker 4.5 bps / maker -1 bps, all 10 oracle sources,
/// min order size 10_000 (= 0.0001 BTC at 8 decimals).
///
/// # Panics
/// Never panics in practice — all preset values are within the
/// validation bounds defined by [`PerpDeployBuilder::new`]. Marked
/// `#[must_use]` so callers don't forget to chain `with_*` modifiers.
#[must_use]
pub fn btc_standard() -> PerpDeployBuilder {
    PerpDeployBuilder::new(
        "BTC",
        "BTC",
        8,
        OracleSource::all().to_vec(),
        50,     // leverage
        45,     // taker 4.5 bps
        -10,    // maker -1 bps (rebate)
        10_000, // min size in size-decimal units
        0,      // deployer fee = 0 for "standard" preset
    )
    .expect("static preset always valid")
}

/// Standard ETH-PERP preset.
///
/// Mirrors BTC params; leverage 50, taker 4.5 bps / maker -1 bps.
///
/// # Panics
/// Never panics — see [`btc_standard`].
#[must_use]
pub fn eth_standard() -> PerpDeployBuilder {
    PerpDeployBuilder::new(
        "ETH",
        "ETH",
        8,
        OracleSource::all().to_vec(),
        50,
        45,
        -10,
        10_000,
        0,
    )
    .expect("static preset always valid")
}

/// Long-tail asset preset (low leverage, exclude Coinbase + Kraken).
///
/// Leverage 10, taker 8 bps, maker 0 bps (neutral), min size 10_000.
/// Oracle subset excludes Coinbase + Kraken since they rarely list long-tail
/// alts; the remaining 8 sources keep the medianizer well-fed.
///
/// # Panics
/// Never panics — see [`btc_standard`].
#[must_use]
pub fn long_tail_default() -> PerpDeployBuilder {
    let sources: Vec<OracleSource> = OracleSource::all()
        .iter()
        .copied()
        .filter(|s| !matches!(s, OracleSource::Coinbase | OracleSource::Kraken))
        .collect();
    PerpDeployBuilder::new(
        "ALT-PERP", // placeholder — caller customizes via `with_asset_name`
        "ALT", 8, sources, 10, 80, // 8 bps taker
        0,  // 0 maker
        10_000, 5, // 0.5 bps deployer take by default — caller can zero out
    )
    .expect("static preset always valid")
}

/// MM-friendly preset.
///
/// Leverage 20, taker 3 bps / maker -2 bps (rebate), min size 1_000.
/// All 10 oracle sources. Suitable for actively-quoted markets where you
/// want to incentivise resting liquidity.
///
/// # Panics
/// Never panics — see [`btc_standard`].
#[must_use]
pub fn mm_friendly() -> PerpDeployBuilder {
    PerpDeployBuilder::new(
        "MM-PERP",
        "MM",
        8,
        OracleSource::all().to_vec(),
        20,
        30,  // 3.0 bps taker
        -20, // -2 bps maker
        1_000,
        0,
    )
    .expect("static preset always valid")
}

/// All preset names, in stable order. Used by the CLI's `templates list`
/// subcommand to enumerate available starting points.
pub const PRESET_NAMES: [&str; 4] = [
    "btc_standard",
    "eth_standard",
    "long_tail_default",
    "mm_friendly",
];

/// Look up a preset by its CLI-name; returns `None` if unknown.
#[must_use]
pub fn preset_by_name(name: &str) -> Option<PerpDeployBuilder> {
    match name {
        "btc_standard" => Some(btc_standard()),
        "eth_standard" => Some(eth_standard()),
        "long_tail_default" => Some(long_tail_default()),
        "mm_friendly" => Some(mm_friendly()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mip3::params::Action;

    #[test]
    fn btc_preset_has_full_oracle_set() {
        let b = btc_standard();
        assert_eq!(b.oracle_sources.len(), 10);
        assert_eq!(b.max_leverage, 50);
        assert_eq!(b.taker_fee_bps, 45);
        assert_eq!(b.maker_fee_bps, -10);
    }

    #[test]
    fn eth_preset_has_full_oracle_set() {
        let b = eth_standard();
        assert_eq!(b.asset_name, "ETH");
        assert_eq!(b.asset_symbol, "ETH");
        assert_eq!(b.oracle_sources.len(), 10);
    }

    #[test]
    fn long_tail_preset_excludes_coinbase_kraken() {
        let b = long_tail_default();
        assert_eq!(b.oracle_sources.len(), 8);
        assert!(!b.oracle_sources.contains(&OracleSource::Coinbase));
        assert!(!b.oracle_sources.contains(&OracleSource::Kraken));
        assert_eq!(b.max_leverage, 10);
    }

    #[test]
    fn mm_friendly_preset_has_negative_maker_fee() {
        let b = mm_friendly();
        assert!(b.maker_fee_bps < 0, "rebate expected");
        assert_eq!(b.max_leverage, 20);
        assert_eq!(b.min_order_size, 1_000);
    }

    #[test]
    fn preset_names_has_four_entries() {
        assert_eq!(PRESET_NAMES.len(), 4);
        let mut sorted = PRESET_NAMES.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 4, "preset names must be unique");
    }

    #[test]
    fn every_preset_produces_eight_actions() {
        for name in PRESET_NAMES {
            let b = preset_by_name(name).expect("preset_by_name");
            let seq = b.deploy_sequence();
            assert_eq!(seq.len(), 8, "preset {name} must yield 8 actions");
            assert_eq!(seq[0].type_id(), "perp_register_asset");
            assert_eq!(seq[7].type_id(), "perp_activate_market");
        }
    }

    #[test]
    fn preset_by_name_returns_none_for_unknown() {
        assert!(preset_by_name("zz_unknown").is_none());
    }

    #[test]
    fn preset_chained_with_modifiers_still_validates() {
        let b = btc_standard().with_asset_name("BTC-PERP-2026");
        b.validate().expect("post-chain validation");
        let seq = b.deploy_sequence();
        // The asset_name must propagate to every sub-action that echoes it.
        for action in &seq {
            if let Action::PerpRegisterAsset { asset_name, .. } = action {
                assert_eq!(asset_name, "BTC-PERP-2026");
            }
        }
    }
}
