//! The six spot-deployer signing strings, pinned by digest.
//!
//! `spot_deploy` is an internal handler name. A caller never sends it. It sends
//! one of SIX distinct typed actions, each with its own frozen EIP-712 string.
//! Every client that builds one must reproduce the digest byte-for-byte.
//!
//! The fixture table and the expected hex below are COPIED from the chain's own
//! cross-language vector set — the same table the web repeats. They are not
//! computed here: a client that hashes its own construction only ever agrees
//! with its own bug.
//!
//! `max_deploy_fee` keeps a trailing zero and `amounts` mixes scales on purpose.
//! The kernel hashes the VERBATIM decimal string, so `"980.00"` and `"980"` are
//! different digests. A client that re-formats breaks here.

use metaflux_client::{
    rest::exchange_typed::_typed_digest_for_test,
    wallet::{Address, TypedAction},
};

fn addr(hex: &str) -> Address {
    Address::from_hex(hex).expect("fixture address parses")
}

#[test]
fn the_six_spot_deploy_signing_strings_keep_their_digests() {
    let cases: Vec<(&str, TypedAction, &str)> = vec![
        (
            "spot_register_token",
            TypedAction::SpotRegisterToken {
                metaflux_chain: "Testnet".to_string(),
                symbol: "MTFX".to_string(),
                sz_decimals: 2,
                wei_decimals: 8,
                max_deploy_fee: "1250.50".to_string(),
                nonce: 101,
            },
            "8335cb87f269b85887717f43d0cc190fa5be56483df31ed9e274cb5d5f94a4dc",
        ),
        (
            "spot_register_pair",
            TypedAction::SpotRegisterPair {
                metaflux_chain: "Testnet".to_string(),
                base: 42,
                quote: 0,
                name: "MTFX/USDC".to_string(),
                max_deploy_fee: "980.00".to_string(),
                nonce: 102,
            },
            "a39d66c15ed7956e38c58908f016dba7e555e322fb41ee964390afac1a609bf1",
        ),
        (
            "spot_set_pair_params",
            TypedAction::SpotSetPairParams {
                metaflux_chain: "Testnet".to_string(),
                pair: 7,
                taker_fee_dbps: 350,
                maker_fee_dbps: 120,
                min_notional_cents: 1000,
                nonce: 103,
            },
            "525adaf10213a6b46fc01f496c38cb24cc942d0abbfac88f983bf0d251f5c67f",
        ),
        (
            "spot_set_pair_active",
            TypedAction::SpotSetPairActive {
                metaflux_chain: "Testnet".to_string(),
                pair: 7,
                active: true,
                nonce: 104,
            },
            "12a8f0dca316f124ab658983fec7ed8151a7e0d08b5f627d768898b7e02e22fc",
        ),
        (
            "spot_seed_holders",
            TypedAction::SpotSeedHolders {
                metaflux_chain: "Testnet".to_string(),
                asset: 42,
                holders: vec![
                    addr("0x1111111111111111111111111111111111111111"),
                    addr("0x00000000000000000000000000000000000000aB"),
                    addr("0xFf00000000000000000000000000000000000001"),
                ],
                amounts: vec![
                    "1000.5".to_string(),
                    "250".to_string(),
                    "0.000001".to_string(),
                ],
                nonce: 105,
            },
            "aefe50cf70bbc40ccf8efe03648e42aaa225717f2b6a0dc820567c97d2e6f168",
        ),
        (
            "spot_finalize_supply",
            TypedAction::SpotFinalizeSupply {
                metaflux_chain: "Testnet".to_string(),
                asset: 42,
                max_supply: "1250.500001".to_string(),
                nonce: 106,
            },
            "5d6ff5f0f43303faa202d4f1715f737b4c5119895aa840fe42a18b68b64214ac",
        ),
    ];

    for (label, action, want) in &cases {
        assert_eq!(
            &hex::encode(_typed_digest_for_test(action)),
            want,
            "{label} digest moved"
        );
    }
}

/// The staged rows are INSIDE the digest, so a relay cannot re-order them under
/// a replayed signature.
#[test]
fn seed_holder_row_order_is_inside_the_digest() {
    let a = addr("0x1111111111111111111111111111111111111111");
    let b = addr("0x2222222222222222222222222222222222222222");
    let build = |holders: Vec<Address>, amounts: Vec<String>| TypedAction::SpotSeedHolders {
        metaflux_chain: "Testnet".to_string(),
        asset: 42,
        holders,
        amounts,
        nonce: 105,
    };
    let forward = build(vec![a, b], vec!["1".to_string(), "2".to_string()]);
    let swapped = build(vec![b, a], vec!["2".to_string(), "1".to_string()]);
    assert_ne!(
        _typed_digest_for_test(&forward),
        _typed_digest_for_test(&swapped),
        "re-ordering staged rows must move the digest"
    );
}

/// Re-formatting a decimal moves the digest. The kernel hashes the string, so
/// `"980"` is a different signature from `"980.00"` — a client that normalises
/// decimals signs something the chain will not accept.
#[test]
fn a_reformatted_decimal_is_a_different_signature() {
    let build = |fee: &str| TypedAction::SpotRegisterPair {
        metaflux_chain: "Testnet".to_string(),
        base: 42,
        quote: 0,
        name: "MTFX/USDC".to_string(),
        max_deploy_fee: fee.to_string(),
        nonce: 102,
    };
    assert_ne!(
        _typed_digest_for_test(&build("980.00")),
        _typed_digest_for_test(&build("980")),
        "trailing zeros are part of the signed bytes"
    );
}
