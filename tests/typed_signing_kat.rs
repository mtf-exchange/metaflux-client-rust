//! Known-answer + sign/recover cross-check for the structured (typed-scheme)
//! `/exchange` signing path.
//!
//! Two angles:
//!
//! 1. `kat_vectors_match_pinned_digests` — reproduce the three fully specified
//!    typed-action digests (chain id 114514 / `"Testnet"`) byte-for-byte. A
//!    drift in any encodeType string, the field encoding, the domain, or the
//!    `0x1901 || domain || hashStruct` envelope would change these.
//!
//! 2. `every_typed_action_signs_and_recovers` — sign each of the typed actions
//!    with a fixed key and recover the signer via the same secp256k1 primitive
//!    the node uses; assert it yields the signing wallet's address. Pins
//!    SIGN + RECOVER for the whole typed surface.

use metaflux_client::{
    rest::exchange_typed::_typed_digest_for_test,
    wallet::{Address, Signature, TypedAction, Wallet},
};

use k256::ecdsa::{RecoveryId, Signature as K256Sig, SigningKey, VerifyingKey};
use tiny_keccak::{Hasher, Keccak};

/// The fixed signing key used across the SDK's cross-check tests (`[0x42; 32]`).
const FIXED_KEY: [u8; 32] = [0x42; 32];

fn addr(byte: u8) -> Address {
    Address::from_bytes([byte; 20])
}

fn keccak(input: &[u8]) -> [u8; 32] {
    let mut h = Keccak::v256();
    h.update(input);
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    out
}

/// Recover the 20-byte signer from a digest + `(r,s,v)` — the same recovery
/// half the node's typed-action verifier runs. Accepts legacy `v ∈ {27,28}`.
fn recover(digest: &[u8; 32], sig: &Signature) -> [u8; 20] {
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&sig.r);
    sig_bytes[32..].copy_from_slice(&sig.s);
    let k_sig = K256Sig::from_slice(&sig_bytes).expect("sig parse");
    let recid_byte = match sig.v {
        0 | 1 => sig.v,
        27 | 28 => sig.v - 27,
        other => panic!("invalid v {other}"),
    };
    let recid = RecoveryId::from_byte(recid_byte).expect("recid");
    let vk = VerifyingKey::recover_from_prehash(digest, &k_sig, recid).expect("recover");
    let point = vk.to_encoded_point(false);
    let h = keccak(&point.as_bytes()[1..]);
    let mut a = [0u8; 20];
    a.copy_from_slice(&h[12..32]);
    a
}

/// Derive the 20-byte address of a `SigningKey` (matches the node + SDK).
fn address_of(key: &SigningKey) -> [u8; 20] {
    let point = key.verifying_key().to_encoded_point(false);
    let h = keccak(&point.as_bytes()[1..]);
    let mut a = [0u8; 20];
    a.copy_from_slice(&h[12..32]);
    a
}

/// (1) The three fully specified KAT vectors must reproduce byte-for-byte.
#[test]
fn kat_vectors_match_pinned_digests() {
    let approve_agent = TypedAction::ApproveAgent {
        metaflux_chain: "Testnet".into(),
        agent_address: addr(0xA1),
        agent_name: "trading-bot".into(),
        nonce: 1,
    };
    assert_eq!(
        hex::encode(_typed_digest_for_test(&approve_agent)),
        "b5a1178200a97f6ea644abdf4eb21525ad8e13c8ff07b5c4a6809815e6c91820",
        "ApproveAgent digest drift"
    );

    let send_asset = TypedAction::SendAsset {
        metaflux_chain: "Testnet".into(),
        source_dex: 0,
        destination_dex: 1,
        asset: 2,
        destination: addr(0x3C),
        amount: "750.25".into(),
        to_perp: true,
        nonce: 28,
    };
    assert_eq!(
        hex::encode(_typed_digest_for_test(&send_asset)),
        "88aa17af1dc0d6d35934ada321549a4b8b6a4d964f9c5263e1200b4f696cac4d",
        "SendAsset digest drift"
    );

    let multi_sig = TypedAction::ConvertToMultiSigUser {
        metaflux_chain: "Testnet".into(),
        signers: vec![addr(0x11), addr(0x22), addr(0x33)],
        threshold: 2,
        nonce: 7,
    };
    assert_eq!(
        hex::encode(_typed_digest_for_test(&multi_sig)),
        "981a2b3adb1d0c03a7af30076f3c6497ffeabe79e380b01be4f1f14eb1252e84",
        "ConvertToMultiSigUser digest (address[] rule) drift"
    );
}

/// (2) Every typed action signs to a 65-byte `r||s||v` that recovers the
/// signing wallet — proving the SDK's digest + signature are accepted by the
/// node's recovery contract across the whole typed surface.
#[test]
fn every_typed_action_signs_and_recovers() {
    let wallet = Wallet::from_bytes(FIXED_KEY).expect("wallet");
    let key = SigningKey::from_slice(&FIXED_KEY).expect("scalar");
    let owner = address_of(&key);
    assert_eq!(wallet.address().as_bytes(), &owner);

    let chain = "Testnet".to_string();
    let actions = vec![
        TypedAction::SendAsset {
            metaflux_chain: chain.clone(),
            source_dex: 0,
            destination_dex: 1,
            asset: 2,
            destination: addr(0x3C),
            amount: "750.25".into(),
            to_perp: true,
            nonce: 28,
        },
        TypedAction::UsdClassTransfer {
            metaflux_chain: chain.clone(),
            ntl: "1500.5".into(),
            to_perp: false,
            nonce: 3,
        },
        TypedAction::Withdraw {
            metaflux_chain: chain.clone(),
            asset: 0,
            amount: "100".into(),
            destination_chain_id: 8453,
            use_cctp: true,
            nonce: 9,
        },
        TypedAction::ApproveAgent {
            metaflux_chain: chain.clone(),
            agent_address: addr(0xA1),
            agent_name: "trading-bot".into(),
            nonce: 1,
        },
        TypedAction::SetReferrer {
            metaflux_chain: chain.clone(),
            referrer: addr(0xBB),
            nonce: 2,
        },
        TypedAction::ApproveBuilderFee {
            metaflux_chain: chain.clone(),
            builder: addr(0xCC),
            max_fee_bps: 25,
            nonce: 4,
        },
        TypedAction::SetDisplayName {
            metaflux_chain: chain.clone(),
            display_name: "alice.mtf".into(),
            nonce: 5,
        },
        TypedAction::SetPositionMode {
            metaflux_chain: chain.clone(),
            hedge: true,
            nonce: 6,
        },
        TypedAction::UserPortfolioMargin {
            metaflux_chain: chain.clone(),
            enroll: true,
            nonce: 8,
        },
        TypedAction::ConvertToMultiSigUser {
            metaflux_chain: chain.clone(),
            signers: vec![addr(0x11), addr(0x22), addr(0x33)],
            threshold: 2,
            nonce: 7,
        },
        TypedAction::UpdateLeverage {
            metaflux_chain: chain.clone(),
            asset: 1,
            leverage: 10,
            is_isolated: true,
            nonce: 10,
        },
        TypedAction::ClaimRewards {
            metaflux_chain: chain.clone(),
            validator: Address::ZERO,
            nonce: 11,
        },
        TypedAction::LinkStakingUser {
            metaflux_chain: chain.clone(),
            target: addr(0xDD),
            nonce: 12,
        },
        TypedAction::CreateVault {
            metaflux_chain: chain.clone(),
            name: "mlp".into(),
            lock_period_secs: 604_800,
            kind: 1,
            nonce: 13,
        },
        TypedAction::VaultModify {
            metaflux_chain: chain.clone(),
            vault_id: 42,
            new_name: "renamed".into(),
            nonce: 14,
        },
        TypedAction::SpotMarginClose {
            metaflux_chain: chain.clone(),
            pair: 200,
            limit_px: 190_000_000,
            nonce: 15,
        },
        TypedAction::REDACTED {
            metaflux_chain: chain.clone(),
            account: addr(0xEE),
            allowed: true,
            nonce: 16,
        },
        TypedAction::REDACTED {
            metaflux_chain: chain,
            vault_id: 42,
            operator: addr(0xFA),
            allowed: true,
            expires_at_ms: 1_700_000_000_000,
            nonce: 17,
        },
    ];
    assert_eq!(actions.len(), 18, "all 18 reachable typed actions covered");

    for action in &actions {
        let digest = _typed_digest_for_test(action);
        assert_ne!(digest, [0u8; 32], "non-zero digest for {action:?}");
        let sig: Signature = wallet.sign_digest(&digest).expect("sign");
        assert!(sig.v == 27 || sig.v == 28, "legacy v for {action:?}");
        let recovered = recover(&digest, &sig);
        assert_eq!(
            recovered, owner,
            "typed action must recover the signing wallet: {action:?}"
        );
    }
}
