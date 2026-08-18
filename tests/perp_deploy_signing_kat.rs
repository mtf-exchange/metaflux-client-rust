//! The nine MIP-3 perp-deployer signing strings, pinned by digest.
//!
//! `perp_deploy` is an internal handler name. A caller never sends it. It sends
//! one of NINE distinct typed actions, each with its own frozen EIP-712 string.
//! Every client that builds one must reproduce the digest byte-for-byte.
//!
//! The fixture table and the expected hex below are COPIED from the chain's own
//! cross-language vector set (domain chain 114514 = `"Testnet"`). They are not
//! computed here: a client that hashes its own construction only ever agrees
//! with its own bug.

use metaflux_client::{
    rest::exchange_typed::_typed_digest_for_test,
    wallet::{Address, TypedAction},
};

const CHAIN: &str = "Testnet";

/// Deterministic fixture address: all twenty bytes equal `b`.
fn addr(b: u8) -> Address {
    Address::from_bytes([b; 20])
}

#[test]
fn the_nine_perp_deploy_signing_strings_keep_their_digests() {
    let cases: Vec<(&str, TypedAction, &str)> = vec![
        (
            "perp_register_asset",
            TypedAction::PerpRegisterAsset {
                metaflux_chain: CHAIN.to_string(),
                symbol: "WIF".to_string(),
                decimals: 8,
                nonce: 201,
            },
            "ed8d4dbc9462484893615eb0dba08fe55b08d187e9346ad66e6a0e0f2ba786c8",
        ),
        (
            "perp_set_oracle",
            TypedAction::PerpSetOracle {
                metaflux_chain: CHAIN.to_string(),
                asset: 1001,
                oracle_source_mask: 0x03ff,
                nonce: 202,
            },
            "ba16e9a9767306835ed196b3bc4261c35491ae0e9c1d41887fe1cc77a7e960c0",
        ),
        (
            "perp_set_leverage",
            TypedAction::PerpSetLeverage {
                metaflux_chain: CHAIN.to_string(),
                asset: 1001,
                max_leverage: 20,
                nonce: 203,
            },
            "536be19f9cd4572c2bf2cefdfa8fdb1fbedbe5f8667f9ca7b82f25122f14a223",
        ),
        (
            "perp_set_fee_tier",
            TypedAction::PerpSetFeeTier {
                metaflux_chain: CHAIN.to_string(),
                asset: 1001,
                taker_fee_dbps: 45,
                maker_fee_dbps: 12,
                deployer_fee_bps: 6,
                nonce: 204,
            },
            "c54b9157d397ffc3f295314e35b636bd46be99baf8f3842e9438c015ca55189a",
        ),
        (
            "perp_set_maker_rebate",
            TypedAction::PerpSetMakerRebate {
                metaflux_chain: CHAIN.to_string(),
                asset: 1001,
                rebate_bps: 2,
                nonce: 205,
            },
            "a88cfd6fd468a694c9bb519b75c2e9e20ae8fe828329a627a7bea7ddc28fe858",
        ),
        (
            "perp_set_min_size",
            TypedAction::PerpSetMinSize {
                metaflux_chain: CHAIN.to_string(),
                asset: 1001,
                min_order_size: 1000,
                nonce: 206,
            },
            "db58e1837626e4e08b8887e6055cf0fb35a7016d1b9efe6e1a0e0f4302dc131c",
        ),
        (
            "perp_activate_market",
            TypedAction::PerpActivateMarket {
                metaflux_chain: CHAIN.to_string(),
                asset: 1001,
                nonce: 207,
            },
            "e2abbf93054c43fb4b85376fa40e48e7942caf539bf13555bc6d1ff229171c13",
        ),
        (
            "perp_deactivate_market",
            TypedAction::PerpDeactivateMarket {
                metaflux_chain: CHAIN.to_string(),
                asset: 1001,
                nonce: 208,
            },
            "8134fe45117bb61f29586b1da5ade99df583faeeadaac6ed3371d309c3b6d183",
        ),
        (
            "perp_set_sub_deployers",
            TypedAction::PerpSetSubDeployers {
                metaflux_chain: CHAIN.to_string(),
                asset: 1001,
                sub_deployer: addr(0xaa),
                add: true,
                nonce: 209,
            },
            "6e39d36bdd1f80375e71c3609d10ee15ad030004d3c41c246fcfbcb93df6750d",
        ),
    ];

    assert_eq!(cases.len(), 9, "all nine perp deploy actions covered");
    for (label, action, want) in &cases {
        assert_eq!(
            &hex::encode(_typed_digest_for_test(action)),
            want,
            "{label} digest drifted from the node vector"
        );
    }
}

/// Activate and deactivate carry the SAME three fields. Only the type string
/// separates them, so a client that reused one string would open a market when
/// it meant to close it, under a signature that still recovers.
#[test]
fn activate_and_deactivate_differ_on_identical_fields() {
    let activate = TypedAction::PerpActivateMarket {
        metaflux_chain: CHAIN.to_string(),
        asset: 1001,
        nonce: 207,
    };
    let deactivate = TypedAction::PerpDeactivateMarket {
        metaflux_chain: CHAIN.to_string(),
        asset: 1001,
        nonce: 207,
    };
    assert_ne!(
        _typed_digest_for_test(&activate),
        _typed_digest_for_test(&deactivate),
        "the type string is the only thing separating these two"
    );
}

/// The delegate and the direction are both inside the digest, so a relay can
/// neither re-target the grant nor flip a removal into one.
#[test]
fn sub_deployer_target_and_direction_are_both_signed() {
    let build = |who: Address, add: bool| TypedAction::PerpSetSubDeployers {
        metaflux_chain: CHAIN.to_string(),
        asset: 1001,
        sub_deployer: who,
        add,
        nonce: 209,
    };
    let grant = build(addr(0xaa), true);
    assert_ne!(
        _typed_digest_for_test(&grant),
        _typed_digest_for_test(&build(addr(0xaa), false)),
        "flipping `add` must move the digest"
    );
    assert_ne!(
        _typed_digest_for_test(&grant),
        _typed_digest_for_test(&build(addr(0xbb), true)),
        "re-targeting the delegate must move the digest"
    );
}

/// The fee legs occupy three distinct signed slots. Swapping taker and maker
/// must not land on the same digest, or a mispriced tier would verify.
#[test]
fn the_three_fee_legs_occupy_distinct_slots() {
    let build = |taker: u32, maker: u32, deployer: u32| TypedAction::PerpSetFeeTier {
        metaflux_chain: CHAIN.to_string(),
        asset: 1001,
        taker_fee_dbps: taker,
        maker_fee_dbps: maker,
        deployer_fee_bps: deployer,
        nonce: 204,
    };
    assert_ne!(
        _typed_digest_for_test(&build(45, 12, 6)),
        _typed_digest_for_test(&build(12, 45, 6))
    );
    assert_ne!(
        _typed_digest_for_test(&build(45, 12, 6)),
        _typed_digest_for_test(&build(45, 6, 12))
    );
}

/// `decimals` of `0` means "the node default of 8" but is a DIFFERENT signature
/// from an explicit 8. Sending one and signing the other fails recovery.
#[test]
fn a_zero_decimals_is_not_an_explicit_eight() {
    let build = |decimals: u8| TypedAction::PerpRegisterAsset {
        metaflux_chain: CHAIN.to_string(),
        symbol: "WIF".to_string(),
        decimals,
        nonce: 201,
    };
    assert_ne!(
        _typed_digest_for_test(&build(0)),
        _typed_digest_for_test(&build(8))
    );
}
