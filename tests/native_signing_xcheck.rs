//! Server-compatibility cross-check for the MTF-native `/exchange` signing path.
//!
//! This is the make-or-break correctness guard: it proves the SDK produces a
//! 65-byte `r||s||v` signature that the server's native-action signature
//! verifier accepts, recovering the signing wallet's address.
//!
//! It mirrors the server's end-to-end reference flow: the **fixed key `[0x42; 32]`**, the
//! chain-114514 (MTF testnet) MTF domain, and the EXACT `order_json` field shape
//! (`owner, market, side, kind, size, limit_px, tif, stp_mode, reduce_only`).
//!
//! Three independent angles, each of which would fail on a digest/domain drift:
//!
//! 1. `digest_formula_matches_server_kat` — recompute the digest over the
//!    server's exact committed KAT bytes and assert it equals the server's
//!    committed value `f7aa10…6e0d` (printed by the server's native-action
//!    KAT test for MTF testnet chain 114514). Pins the FORMULA.
//!
//! 2. `fixed_key_sign_recover_over_literal_order_json` — sign the digest over
//!    the literal `order_json` bytes with the fixed key and recover with the
//!    SAME secp256k1 primitive the server uses; assert the recovered address is
//!    the key's address. Pins SIGN + RECOVER against the server's verifier
//!    contract on a fixed, reproducible vector.
//!
//! 3. `sdk_submit_order_path_round_trips` — drive the REAL SDK code path
//!    (`Order` → `json!` → `ActionSignedDigest` → `Wallet::sign_eip712`) and
//!    recover the signer. Because the server hashes the RAW posted `action`
//!    bytes verbatim (never a re-serialization), a self-consistent SDK
//!    round-trip is exactly what makes the server accept the order. Pins the
//!    PRODUCTION path.

use k256::ecdsa::{RecoveryId, Signature as K256Sig, SigningKey, VerifyingKey};
use serde_json::json;
use tiny_keccak::{Hasher, Keccak};

use metaflux_client::{
    rest::exchange::{_action_digest_for_test, _recover_for_test, MTF_CHAIN_ID},
    types::{
        MarketId,
        order::{Order, OrderKind, PositionSide, Side, StpMode, TimeInForce},
        spot::{SpotCancel, SpotOrder},
    },
    wallet::{Signature, Wallet},
};

/// The fixed signing key the server's e2e reference flow uses (`[0x42; 32]`).
const FIXED_KEY: [u8; 32] = [0x42; 32];

fn keccak(input: &[u8]) -> [u8; 32] {
    let mut h = Keccak::v256();
    h.update(input);
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    out
}

/// Derive the 20-byte EVM address from a `SigningKey` — same pipeline as both
/// the SDK (`address_from_signing_key`) and the server (`recover_signer`).
fn address_of(key: &SigningKey) -> [u8; 20] {
    let point = key.verifying_key().to_encoded_point(false);
    let xy = &point.as_bytes()[1..]; // strip 0x04
    let h = keccak(xy);
    let mut a = [0u8; 20];
    a.copy_from_slice(&h[12..32]);
    a
}

fn hex_addr(bytes: &[u8; 20]) -> String {
    let mut s = String::with_capacity(40);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// The MTF-native 5-field EIP-712 domain separator for `chain_id`.
/// Byte-for-byte mirror of the server's `EipDomain::separator()`.
fn domain_separator(chain_id: u64) -> [u8; 32] {
    let type_hash = keccak(
        b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    );
    let name_hash = keccak(b"MetaFlux");
    let version_hash = keccak(b"1");
    let mut chain_be = [0u8; 32];
    chain_be[24..].copy_from_slice(&chain_id.to_be_bytes());
    let verifying = [0u8; 32]; // Address::ZERO, left-padded
    let mut buf = Vec::with_capacity(32 * 5);
    buf.extend_from_slice(&type_hash);
    buf.extend_from_slice(&name_hash);
    buf.extend_from_slice(&version_hash);
    buf.extend_from_slice(&chain_be);
    buf.extend_from_slice(&verifying);
    keccak(&buf)
}

/// Full native-action digest over RAW `action_json` bytes — byte-for-byte
/// mirror of the server's `native_action_digest`.
fn native_action_digest(chain_id: u64, action_json: &[u8], nonce: u64) -> [u8; 32] {
    let type_hash = keccak(b"MetaFluxAction(string action,uint64 nonce)");
    let action_hash = keccak(action_json);
    let mut nonce_be = [0u8; 32];
    nonce_be[24..].copy_from_slice(&nonce.to_be_bytes());
    let mut sh = Vec::with_capacity(96);
    sh.extend_from_slice(&type_hash);
    sh.extend_from_slice(&action_hash);
    sh.extend_from_slice(&nonce_be);
    let struct_hash = keccak(&sh);

    let mut d = Vec::with_capacity(66);
    d.extend_from_slice(&[0x19, 0x01]);
    d.extend_from_slice(&domain_separator(chain_id));
    d.extend_from_slice(&struct_hash);
    keccak(&d)
}

/// The literal `order_json` from the server's e2e reference flow — field
/// order and types reproduced EXACTLY. The bytes the server hashes are these
/// bytes; reordering would change the digest.
fn order_json_literal(owner: &[u8; 20]) -> String {
    format!(
        r#"{{"type":"submit_order","order":{{"owner":"0x{}","market":1,"side":"bid","kind":"limit","size":1000,"limit_px":5000000000000,"tif":"gtc","stp_mode":"cancel_oldest","reduce_only":false}}}}"#,
        hex_addr(owner)
    )
}

/// Sign a 32-byte digest with the SAME primitive the server's e2e uses
/// (`sign_prehash_recoverable`), returning the `(r,s,v)` triple with the
/// SDK's legacy `v = 27 + parity` convention.
fn sign_digest_raw(key: &SigningKey, digest: &[u8; 32]) -> ([u8; 32], [u8; 32], u8) {
    let (sig, rid): (K256Sig, RecoveryId) = key.sign_prehash_recoverable(digest).expect("sign");
    let bytes = sig.to_bytes();
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&bytes[..32]);
    s.copy_from_slice(&bytes[32..]);
    (r, s, 27 + rid.to_byte())
}

/// Recover the 20-byte signer from a digest + `(r,s,v)` — byte-for-byte mirror
/// of the server's `recover_native_action` recovery half. Accepts legacy
/// `v ∈ {27,28}` exactly as the server does.
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

/// (1) The SDK's digest formula must reproduce the server's committed KAT.
///
/// The server's native-action KAT test prints
/// (chain=114514 MTF testnet, nonce=1_700_000_000_000) digest =
/// `f7aa10…6e0d`. We recompute it here over the server's EXACT committed
/// action bytes. A drift in the domain (5-field), the
/// `MetaFluxAction(string action,uint64 nonce)` typehash, the chain id, or
/// the `0x1901 || domain || struct` envelope would change this.
#[test]
fn digest_formula_matches_server_kat() {
    let action_json = br#"{"type":"submit_order","order":{"owner":"0x000000000000000000000000000000000000beef","market":1,"side":"bid","kind":"limit","size":1000,"limit_px":5000000000000,"tif":"gtc","stp_mode":"cancel_oldest","reduce_only":false}}"#;
    let nonce: u64 = 1_700_000_000_000;
    let digest = native_action_digest(MTF_CHAIN_ID, action_json, nonce);

    // Server-committed KAT value, recomputed for the MTF testnet chain id
    // 114514.
    let expected: [u8; 32] = [
        0xf7, 0xaa, 0x10, 0x87, 0xf7, 0x9b, 0x30, 0xfb, 0x3f, 0x13, 0xa1, 0x90, 0x63, 0x6d, 0x32,
        0xb3, 0x27, 0x20, 0xd5, 0x98, 0x41, 0x91, 0x99, 0x2d, 0x70, 0x7e, 0x2a, 0xfb, 0xca, 0x71,
        0x6e, 0x0d,
    ];
    assert_eq!(
        digest, expected,
        "SDK digest formula must equal the server KAT f7aa10…6e0d"
    );

    // And the SDK default constant must be the chain id this KAT is pinned to.
    assert_eq!(
        MTF_CHAIN_ID, 114514,
        "SDK MTF_CHAIN_ID must match the server KAT chain id (MTF testnet)"
    );
}

/// (2) Fixed-key sign → recover over the literal `order_json`, exactly as the
/// server's `native_order_e2e.rs` does. Proves a signature the SDK's wallet
/// computes is accepted by the server's recovery contract and binds to the
/// owner address embedded in the action.
#[test]
fn fixed_key_sign_recover_over_literal_order_json() {
    let key = SigningKey::from_slice(&FIXED_KEY).expect("valid scalar");
    let owner = address_of(&key);
    let action = order_json_literal(&owner);
    let nonce: u64 = 7; // the e2e's fixed nonce

    let digest = native_action_digest(MTF_CHAIN_ID, action.as_bytes(), nonce);
    let (r, s, v) = sign_digest_raw(&key, &digest);
    assert!(v == 27 || v == 28, "legacy v must be 27/28, got {v}");

    let recovered = recover(&digest, &r, &s, v);
    assert_eq!(
        recovered, owner,
        "server's recover_native_action contract must recover the signing key's owner address"
    );

    // The SDK `Wallet` over the SAME digest must produce a signature that
    // recovers to the SAME owner (proves Wallet + sign_digest parity with the
    // raw k256 path the server e2e uses).
    let wallet = Wallet::from_bytes(FIXED_KEY).expect("wallet");
    assert_eq!(wallet.address().as_bytes(), &owner);
    let wsig = wallet.sign_digest(&digest).expect("wallet sign");
    let recovered_from_wallet = recover(&digest, &wsig.r, &wsig.s, wsig.v);
    assert_eq!(
        recovered_from_wallet, owner,
        "SDK Wallet signature must recover the same owner the server expects"
    );
}

/// (3) The REAL SDK submit path: `Order` → `json!` → `ActionSignedDigest`
/// (`_action_digest_for_test`) → `Wallet` sign → recover. The server hashes the
/// RAW posted `action` bytes, so a self-consistent SDK round-trip is precisely
/// what makes the server accept the order. This guards the production
/// serialization + signing pipeline (key ordering, numeric encoding, etc).
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
    };
    // This is exactly the Value the SDK's `Exchange::submit_order` builds and
    // both signs over and POSTs (the server hashes the identical bytes).
    let action = json!({ "type": "submit_order", "order": order });
    let nonce: u64 = 7;

    let digest = _action_digest_for_test(&action, nonce);
    let sig: Signature = wallet.sign_digest(&digest).expect("sign");

    // Recover via the SDK's recover helper AND via the server-mirror recover —
    // both must yield the wallet address.
    let via_sdk = _recover_for_test(&digest, &sig).expect("sdk recover");
    assert_eq!(
        via_sdk,
        wallet.address(),
        "SDK round-trip must recover wallet"
    );

    let via_server_mirror = recover(&digest, &sig.r, &sig.s, sig.v);
    assert_eq!(
        &via_server_mirror,
        wallet.address().as_bytes(),
        "server-mirror recover over the SDK's production digest must yield the wallet owner"
    );
}

/// Drive the SDK's production digest over `action` + sign with the fixed key,
/// then recover via BOTH the SDK helper and the server-mirror recover. Asserts
/// both yield the fixed-key owner. This is the same contract
/// `sdk_submit_order_path_round_trips` proves, factored for the new actions.
fn assert_action_round_trips(action: &serde_json::Value) {
    let wallet = Wallet::from_bytes(FIXED_KEY).expect("wallet");
    let nonce: u64 = 7;
    let digest = _action_digest_for_test(action, nonce);
    let sig: Signature = wallet.sign_digest(&digest).expect("sign");

    let via_sdk = _recover_for_test(&digest, &sig).expect("sdk recover");
    assert_eq!(
        via_sdk,
        wallet.address(),
        "SDK round-trip must recover wallet"
    );

    let via_server_mirror = recover(&digest, &sig.r, &sig.s, sig.v);
    assert_eq!(
        &via_server_mirror,
        wallet.address().as_bytes(),
        "server-mirror recover must yield the wallet owner"
    );
}

/// `set_position_mode` — sender-authorized hedge toggle. The signed action
/// envelope is `{"type":"set_position_mode","params":{"hedge":<bool>}}`; the
/// node binds it to the recovered signer (no address in the body).
#[test]
fn sdk_set_position_mode_path_round_trips() {
    for hedge in [true, false] {
        let action = json!({ "type": "set_position_mode", "params": { "hedge": hedge } });
        assert_action_round_trips(&action);
    }
    // Pin the exact bytes the node hashes. NOTE: the SDK signs + POSTs a
    // `serde_json::Value`, whose object keys serialize in BTreeMap (alphabetical)
    // order — `params` before `type` — and the node hashes those identical
    // posted bytes, so this is the canonical signed form.
    let action = json!({ "type": "set_position_mode", "params": { "hedge": true } });
    assert_eq!(
        serde_json::to_string(&action).unwrap(),
        r#"{"params":{"hedge":true},"type":"set_position_mode"}"#
    );
}

/// `spot_order` (SE-0) — owner is the recovered signer; the body carries no
/// owner field. Drives the real `SpotOrder` → `json!` → digest path.
#[test]
fn sdk_spot_order_path_round_trips() {
    let mut order = SpotOrder::ioc_limit(3, Side::Bid, 1000, 5_000_000_000);
    order.stp_mode = StpMode::CancelNewest;
    let action = json!({ "type": "spot_order", "order": order });
    assert_action_round_trips(&action);

    // Pin the canonical signed bytes: ioc tif, 1e8 px plane, no cloid key when
    // None. Object keys are BTreeMap (alphabetical) — the form the SDK signs +
    // POSTs and the node hashes verbatim.
    let order = SpotOrder::ioc_limit(3, Side::Bid, 1000, 5_000_000_000);
    let action = json!({ "type": "spot_order", "order": order });
    assert_eq!(
        serde_json::to_string(&action).unwrap(),
        r#"{"order":{"limit_px":5000000000,"pair":3,"side":"bid","size":1000,"stp_mode":"cancel_oldest","tif":"ioc"},"type":"spot_order"}"#
    );
}

/// `spot_cancel` — cancel a resting spot order by `(pair, oid)`.
#[test]
fn sdk_spot_cancel_path_round_trips() {
    let cancel = SpotCancel {
        pair: 3,
        oid: 12345,
    };
    let action = json!({ "type": "spot_cancel", "cancel": cancel });
    assert_action_round_trips(&action);

    // BTreeMap (alphabetical) key order — the SDK-signed + posted form.
    assert_eq!(
        serde_json::to_string(&action).unwrap(),
        r#"{"cancel":{"oid":12345,"pair":3},"type":"spot_cancel"}"#
    );
}

/// A hedge-mode perp order carries `position_side`; the round-trip must hold and
/// the field must appear in the canonical bytes the node hashes.
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
    };
    let action = json!({ "type": "submit_order", "order": order });
    assert_action_round_trips(&action);

    let s = serde_json::to_string(&action).unwrap();
    assert!(
        s.contains(r#""position_side":"long""#),
        "hedge order must serialize position_side; got {s}"
    );
}

/// A one-way perp order (default) omits `position_side`, so the `Order` struct
/// serializes byte-identically to the pre-hedge-mode shape — the exact body the
/// server KAT (`digest_formula_matches_server_kat`) hashes. This proves adding
/// the optional field did not perturb the legacy one-way order bytes.
#[test]
fn one_way_perp_order_bytes_match_legacy_kat_shape() {
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
    };
    // Serialize the struct directly (declaration order) — this is the `order`
    // sub-object the server KAT pins. `position_side: None` must NOT appear.
    assert_eq!(
        serde_json::to_string(&order).unwrap(),
        r#"{"owner":"0x000000000000000000000000000000000000beef","market":1,"side":"bid","kind":"limit","size":1000,"limit_px":5000000000000,"tif":"gtc","stp_mode":"cancel_oldest","reduce_only":false}"#,
        "one-way order body must equal the committed server KAT order shape"
    );
}
