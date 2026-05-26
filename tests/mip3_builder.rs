//! Unit-level integration tests for the MIP-3 builder kit.
//!
//! These exercise the public API at the crate boundary (i.e. through
//! `metaflux_client::mip3::*` re-exports) so we catch any surface-level
//! regressions in addition to the per-module unit tests.

use metaflux_client::mip3::{
    Action, AuctionBid, AuctionKind, OracleSource, PerpDeployBuilder, SpotDeployBuilder,
    btc_standard, eth_standard, long_tail_default, mm_friendly, preset_by_name,
};
use metaflux_client::rest::exchange::{_action_digest_for_test, _recover_for_test};
use metaflux_client::wallet::Wallet;

// ---- Builder semantics ----

#[test]
fn perp_builder_yields_eight_actions_in_canonical_order() {
    let b = btc_standard().with_asset_name("BTC-PERP-NEW");
    let seq = b.deploy_sequence();
    assert_eq!(seq.len(), 8);

    let types: Vec<_> = seq.iter().map(Action::type_id).collect();
    assert_eq!(
        types,
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

    // Asset name propagates to every step that echoes it.
    for action in &seq {
        let json = action.to_json();
        if let Some(name) = json.get("asset_name").and_then(|v| v.as_str()) {
            assert_eq!(name, "BTC-PERP-NEW", "asset_name propagation");
        }
    }
}

#[test]
fn perp_builder_register_asset_carries_symbol_and_decimals() {
    let b = eth_standard().with_asset_name("ETH-PERP-X");
    let json = b.build_register_asset().to_json();
    assert_eq!(json["asset_name"], "ETH-PERP-X");
    assert_eq!(json["asset_symbol"], "ETH");
    assert_eq!(json["decimals"], 8);
}

#[test]
fn perp_set_fees_action_contains_all_three_fee_fields() {
    let b = mm_friendly();
    let json = b.build_set_fees().to_json();
    assert_eq!(json["taker_fee_bps"], 30);
    assert_eq!(json["maker_fee_bps"], -20);
    assert_eq!(json["deployer_fee_bps"], 0);
}

#[test]
fn perp_builder_rejects_leverage_over_fifty() {
    let err = PerpDeployBuilder::new(
        "FOO",
        "F",
        8,
        vec![OracleSource::Binance],
        51, // > 50
        10,
        10,
        100,
        5,
    )
    .unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("max_leverage"),
        "expected leverage error, got: {msg}"
    );
}

#[test]
fn perp_builder_rejects_zero_leverage() {
    let err = PerpDeployBuilder::new("X", "X", 8, vec![OracleSource::Binance], 0, 10, 10, 1, 0)
        .unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("max_leverage"),
        "expected leverage error, got: {msg}"
    );
}

#[test]
fn perp_builder_rejects_excess_deployer_fee() {
    let err = PerpDeployBuilder::new("X", "X", 8, vec![OracleSource::Binance], 10, 10, 10, 1, 51)
        .unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("deployer_fee_bps"), "msg: {msg}");
}

#[test]
fn perp_builder_rejects_empty_oracle_sources() {
    let err = PerpDeployBuilder::new("X", "X", 8, vec![], 10, 10, 10, 1, 0).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("oracle_sources"), "msg: {msg}");
}

// ---- Templates ----

#[test]
fn all_four_presets_resolve_and_validate() {
    for name in [
        "btc_standard",
        "eth_standard",
        "long_tail_default",
        "mm_friendly",
    ] {
        let b = preset_by_name(name).unwrap_or_else(|| panic!("preset {name} missing"));
        b.validate()
            .unwrap_or_else(|e| panic!("preset {name} fails validation: {e}"));
        let seq = b.deploy_sequence();
        assert_eq!(seq.len(), 8, "preset {name} must produce 8 actions");
    }
}

#[test]
fn long_tail_preset_correctly_excludes_two_sources() {
    let b = long_tail_default();
    assert_eq!(b.oracle_sources.len(), 8);
    assert!(!b.oracle_sources.contains(&OracleSource::Coinbase));
    assert!(!b.oracle_sources.contains(&OracleSource::Kraken));
}

// ---- Spot builder ----

#[test]
fn spot_builder_yields_four_actions_in_order() {
    let b = SpotDeployBuilder::new(2, 0, "ETH/USDC", 30, -10, 1_000).unwrap();
    let seq = b.deploy_sequence();
    let types: Vec<_> = seq.iter().map(Action::type_id).collect();
    assert_eq!(
        types,
        vec![
            "spot_register_pair",
            "spot_set_fees",
            "spot_set_min_notional",
            "spot_activate_pair",
        ]
    );
}

#[test]
fn spot_builder_rejects_base_equals_quote() {
    let err = SpotDeployBuilder::new(0, 0, "USDC-USDC", 10, 10, 1).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("base") && msg.contains("quote"), "msg: {msg}");
}

// ---- Auction ----

#[test]
fn auction_bid_serializes_with_snake_case_kind_field() {
    let b = AuctionBid {
        kind: AuctionKind::PerpDeploy,
        bid_amount_usdc_cents: 150_000_000,
    };
    let j = serde_json::to_value(&b).unwrap();
    assert_eq!(j["kind"], "perp_deploy");
    assert!(j["bid_amount_usdc_cents"].is_number());
}

// ---- EIP-712 sign / recover round-trip on a built action ----

#[test]
fn signed_action_roundtrips_through_sign_and_recover() {
    // Pick a deterministic wallet so the test is reproducible.
    let wallet =
        Wallet::from_hex("4646464646464646464646464646464646464646464646464646464646464646")
            .unwrap();
    let b = btc_standard().with_asset_name("BTC-PERP-RT");
    let action = b.build_register_asset();
    let action_json = action.to_json();
    let nonce: u64 = 1_700_000_000_000;

    // Reproduce the SDK's digest from the test helper.
    let digest = _action_digest_for_test(&action_json, nonce);
    let sig = wallet.sign_digest(&digest).unwrap();
    let recovered = _recover_for_test(&digest, &sig).unwrap();
    assert_eq!(
        recovered,
        wallet.address(),
        "recovered signer must equal wallet"
    );
}

// ---- Action json shape sanity ----

#[test]
fn every_action_json_has_a_type_field_matching_type_id() {
    let b = mm_friendly().with_asset_name("MM-PERP-1");
    for action in b.deploy_sequence() {
        let json = action.to_json();
        assert_eq!(
            json.get("type").and_then(|v| v.as_str()),
            Some(action.type_id()),
            "type field mismatch for {:?}",
            action
        );
    }
}

#[test]
fn action_json_uses_plain_integer_numerics_not_strings() {
    let b = btc_standard();
    // Min order size is a u128 — serde_json serializes it as a Number, not String.
    let json = b.build_set_min_order_size().to_json();
    assert!(json["min_order_size"].is_number());
    // Max leverage too.
    let json = b.build_set_leverage().to_json();
    assert!(json["max_leverage"].is_number());
}
