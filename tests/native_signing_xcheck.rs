//! Server-compatibility cross-check for the MTF-native TYPED `/exchange` signing
//! path.
//!
//! The node is TYPED-ONLY: every write action signs a structured `TypedAction`
//! (or `TypedTradingAction`) EIP-712 digest — the opaque
//! `MetaFluxAction(string action,uint64 nonce)` scheme is rejected. This test
//! drives the REAL SDK code path for a spread of actions and proves the produced
//! 65-byte `r||s||v` signature recovers the signing wallet — the exact contract
//! the node's recovery verifier enforces. It recovers via BOTH the SDK helper and
//! an independent server-mirror recovery half.
//!
//! The digest VALUES are pinned separately in `typed_signing_kat.rs` against the
//! node's frozen KAT vectors; here we pin the wire-shape bytes the node hashes.

use k256::ecdsa::{RecoveryId, Signature as K256Sig, VerifyingKey};
use serde_json::json;
use tiny_keccak::{Hasher, Keccak};

use metaflux_client::{
    rest::exchange::{_recover_for_test, MTF_CHAIN_ID},
    rest::exchange_typed::{_typed_digest_for_test, _typed_trade_digest_for_test},
    types::{
        MarketId,
        order::{Order, OrderKind, PositionSide, Side, StpMode, TimeInForce},
        spot::{SpotCancel, SpotOrder},
    },
    wallet::{Signature, TypedAction, TypedTradingAction, Wallet, metaflux_chain_tag},
};

/// The fixed signing key the SDK cross-check tests use (`[0x42; 32]`).
const FIXED_KEY: [u8; 32] = [0x42; 32];

fn keccak(input: &[u8]) -> [u8; 32] {
    let mut h = Keccak::v256();
    h.update(input);
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    out
}

/// Recover the 20-byte signer from a digest + `(r,s,v)` — byte-for-byte mirror
/// of the node's typed-action recovery half. Accepts legacy `v ∈ {27,28}`.
fn recover(digest: &[u8; 32], r: &[u8; 32], s: &[u8; 32], v: u8) -> [u8; 20] {
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(r);
    sig_bytes[32..].copy_from_slice(s);
    let sig = K256Sig::from_slice(&sig_bytes).expect("sig parse");
    let recid_byte = match v {
        0 | 1 => v,
        27 | 28 => v - 27,
        _ => panic!("invalid v"),
    };
    let recid = RecoveryId::from_byte(recid_byte).expect("recid");
    let vk = VerifyingKey::recover_from_prehash(digest, &sig, recid).expect("recover");
    let point = vk.to_encoded_point(false);
    let h = keccak(&point.as_bytes()[1..]);
    let mut a = [0u8; 20];
    a.copy_from_slice(&h[12..32]);
    a
}

/// Sign the TYPED TRADING digest for `typed` + `nonce` with the fixed key, then
/// recover via BOTH the SDK helper and the server-mirror recover — both must
/// yield the wallet address. This is what makes the node accept the action.
fn assert_typed_trade_round_trips(typed: TypedTradingAction, nonce: u64) {
    let wallet = Wallet::from_bytes(FIXED_KEY).expect("wallet");
    let digest = _typed_trade_digest_for_test(typed, nonce);
    let sig: Signature = wallet.sign_digest(&digest).expect("sign");
    assert!(
        sig.v == 27 || sig.v == 28,
        "legacy v must be 27/28, got {}",
        sig.v
    );

    let via_sdk = _recover_for_test(&digest, &sig).expect("sdk recover");
    assert_eq!(
        via_sdk,
        wallet.address(),
        "SDK round-trip must recover wallet"
    );

    let via_mirror = recover(&digest, &sig.r, &sig.s, sig.v);
    assert_eq!(
        &via_mirror,
        wallet.address().as_bytes(),
        "server-mirror recover over the typed digest must yield the wallet"
    );
}

/// Same, for a non-trading [`TypedAction`].
fn assert_typed_action_round_trips(action: &TypedAction) {
    let wallet = Wallet::from_bytes(FIXED_KEY).expect("wallet");
    let digest = _typed_digest_for_test(action);
    let sig: Signature = wallet.sign_digest(&digest).expect("sign");

    let via_sdk = _recover_for_test(&digest, &sig).expect("sdk recover");
    assert_eq!(
        via_sdk,
        wallet.address(),
        "SDK round-trip must recover wallet"
    );

    let via_mirror = recover(&digest, &sig.r, &sig.s, sig.v);
    assert_eq!(
        &via_mirror,
        wallet.address().as_bytes(),
        "server-mirror recover over the typed digest must yield the wallet"
    );
}

fn chain_tag() -> String {
    metaflux_chain_tag(MTF_CHAIN_ID).to_string()
}

/// The REAL SDK perp-order path signs the TYPED `SubmitOrder` trading digest and
/// recovers the wallet.
#[test]
fn sdk_submit_order_path_round_trips() {
    let wallet = Wallet::from_bytes(FIXED_KEY).expect("wallet");
    let order = Order {
        owner: wallet.address(),
        market: MarketId(1),
        side: Side::Bid,
        kind: OrderKind::Limit,
        size: 1000,
        limit_px: 5_000_000_000_000,
        tif: TimeInForce::Gtc,
        stp_mode: StpMode::CancelOldest,
        reduce_only: false,
        cloid: None,
        builder: None,
        position_side: None,
        trigger: None,
    };
    assert_typed_trade_round_trips(TypedTradingAction::SubmitOrder(&order), 7);
}

/// `set_position_mode` — the typed `SetPositionMode` digest recovers the signer,
/// and the wire the SDK posts is the canonical `{type, params}` object.
#[test]
fn sdk_set_position_mode_path_round_trips() {
    for hedge in [true, false] {
        let action = TypedAction::SetPositionMode {
            metaflux_chain: chain_tag(),
            hedge,
            nonce: 7,
        };
        assert_typed_action_round_trips(&action);
    }
    // The typed wire action object; `serde_json::Value` object keys serialize in
    // BTreeMap (alphabetical) order — `params` before `type` — the exact bytes
    // the node hashes.
    let action = json!({ "type": "set_position_mode", "params": { "hedge": true } });
    assert_eq!(
        serde_json::to_string(&action).unwrap(),
        r#"{"params":{"hedge":true},"type":"set_position_mode"}"#
    );
}

/// `spot_order` — the typed `SpotOrder` trading digest recovers the signer; the
/// order body carries no owner field (the node binds the recovered signer).
#[test]
fn sdk_spot_order_path_round_trips() {
    let mut order = SpotOrder::ioc_limit(3, Side::Bid, 1000, 5_000_000_000);
    order.stp_mode = StpMode::CancelNewest;
    assert_typed_trade_round_trips(TypedTradingAction::SpotOrder(&order), 7);

    // Canonical signed bytes: ioc tif, 1e8 px plane, no cloid key when None.
    let order = SpotOrder::ioc_limit(3, Side::Bid, 1000, 5_000_000_000);
    let action = json!({ "type": "spot_order", "order": order });
    assert_eq!(
        serde_json::to_string(&action).unwrap(),
        r#"{"order":{"limit_px":5000000000,"pair":3,"side":"bid","size":1000,"stp_mode":"cancel_oldest","tif":"ioc"},"type":"spot_order"}"#
    );
}

/// `spot_cancel` — cancel a resting spot order by `(pair, oid)` under the typed
/// `SpotCancel` digest.
#[test]
fn sdk_spot_cancel_path_round_trips() {
    let cancel = SpotCancel {
        pair: 3,
        oid: 12345,
    };
    assert_typed_trade_round_trips(TypedTradingAction::SpotCancel(&cancel), 7);

    let action = json!({ "type": "spot_cancel", "cancel": cancel });
    assert_eq!(
        serde_json::to_string(&action).unwrap(),
        r#"{"cancel":{"oid":12345,"pair":3},"type":"spot_cancel"}"#
    );
}

/// A hedge-mode perp order carries `position_side`; the typed round-trip holds
/// and the field appears in the canonical order bytes.
#[test]
fn sdk_hedge_perp_order_path_round_trips() {
    let wallet = Wallet::from_bytes(FIXED_KEY).expect("wallet");
    let order = Order {
        owner: wallet.address(),
        market: MarketId(1),
        side: Side::Bid,
        kind: OrderKind::Limit,
        size: 1000,
        limit_px: 5_000_000_000_000,
        tif: TimeInForce::Gtc,
        stp_mode: StpMode::CancelOldest,
        reduce_only: false,
        cloid: None,
        builder: None,
        position_side: Some(PositionSide::Long),
        trigger: None,
    };
    assert_typed_trade_round_trips(TypedTradingAction::SubmitOrder(&order), 7);

    let s = serde_json::to_string(&order).unwrap();
    assert!(
        s.contains(r#""position_side":"long""#),
        "hedge order must serialize position_side; got {s}"
    );
}

/// A one-way perp order (default) omits `position_side`, so the `Order` struct
/// serializes byte-identically to the pre-hedge-mode shape — the order body the
/// node hashes for the typed `SubmitOrder` digest.
#[test]
fn one_way_perp_order_bytes_match_legacy_shape() {
    let order = Order {
        owner: metaflux_client::wallet::Address::from_hex(
            "0x000000000000000000000000000000000000beef",
        )
        .unwrap(),
        market: MarketId(1),
        side: Side::Bid,
        kind: OrderKind::Limit,
        size: 1000,
        limit_px: 5_000_000_000_000,
        tif: TimeInForce::Gtc,
        stp_mode: StpMode::CancelOldest,
        reduce_only: false,
        cloid: None,
        builder: None,
        position_side: None,
        trigger: None,
    };
    assert_eq!(
        serde_json::to_string(&order).unwrap(),
        r#"{"owner":"0x000000000000000000000000000000000000beef","market":1,"side":"bid","kind":"limit","size":1000,"limit_px":5000000000000,"tif":"gtc","stp_mode":"cancel_oldest","reduce_only":false}"#,
        "one-way order body must equal the committed order shape"
    );
}
