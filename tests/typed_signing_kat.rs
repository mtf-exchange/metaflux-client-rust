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

/// (1b) The twelve formerly-deferred typed actions must reproduce the frozen
/// contract digests (chain id 114514 / `"Testnet"`) byte-for-byte. Covers the
/// decimal-string (`delta`/`amount`/`shares`/`borrow`), `uint8` (`kind`/
/// `chain`), `uint64 amount` (mb_withdraw), and verbatim-string (`value`) rules.
#[test]
fn extended_kat_vectors_match_pinned_digests() {
    let cases: Vec<(TypedAction, &str)> = vec![
        (
            TypedAction::UpdateIsolatedMargin {
                metaflux_chain: "Testnet".into(),
                asset: 1,
                delta: "-100.5".into(),
                nonce: 9,
            },
            "f3ca20d10ce710d31de3d321d61d60b53550adbb4dfd09fca9b7a8c8dbc08162",
        ),
        (
            TypedAction::TopUpIsolatedOnlyMargin {
                metaflux_chain: "Testnet".into(),
                asset: 1,
                amount: "50".into(),
                nonce: 10,
            },
            "47647d208358a681eb657867da2ce00dfeb010a7f2023ecb69e195642da24c8a",
        ),
        (
            TypedAction::TokenDelegate {
                metaflux_chain: "Testnet".into(),
                validator: addr(0xD4),
                amount: "1000".into(),
                is_undelegate: false,
                nonce: 11,
            },
            "5327737fefc7ee3b38b59743fb4ba311d9142a7c672ec59ca92c5a871173008b",
        ),
        (
            TypedAction::VaultTransfer {
                metaflux_chain: "Testnet".into(),
                vault_id: 42,
                deposit: true,
                amount: "250.75".into(),
                nonce: 16,
            },
            "d5da325a4e1331ebd6a158d7192795a3eeaf2a39c86b90d44cd5506c98ececc9",
        ),
        (
            TypedAction::VaultWithdraw {
                metaflux_chain: "Testnet".into(),
                vault_id: 42,
                shares: "10.5".into(),
                nonce: 18,
            },
            "ca6c76e49c7cedd99df8d27ee85d14175b954d25bdac53f9525e6b8c71f6b5a7",
        ),
        (
            TypedAction::SpotMarginDeposit {
                metaflux_chain: "Testnet".into(),
                pair: 5,
                amount: "100".into(),
                nonce: 20,
            },
            "3d2f440131e3059d8ac4329864f258ae8c799f82323785a36420182ed3e304fd",
        ),
        (
            TypedAction::SpotMarginWithdraw {
                metaflux_chain: "Testnet".into(),
                pair: 5,
                amount: "50".into(),
                nonce: 21,
            },
            "44540925574b90c68c0cb4c5773d2d51e14d3c3ddd6c9fe5b97e81aba67e768c",
        ),
        (
            TypedAction::SpotMarginOpen {
                metaflux_chain: "Testnet".into(),
                pair: 5,
                size: 1_000,
                limit_px: 5_000_000_000,
                borrow: "200".into(),
                nonce: 22,
            },
            "d56110f1e4adb4fbd07a72b870678425bd5440d2119e3d9d9f205469c6dbd4c1",
        ),
        (
            TypedAction::EarnDeposit {
                metaflux_chain: "Testnet".into(),
                asset: 0,
                amount: "500".into(),
                nonce: 24,
            },
            "947530d85221850f892412799ef45baef7f5a75663272bc565e81c519879664e",
        ),
        (
            TypedAction::EarnWithdraw {
                metaflux_chain: "Testnet".into(),
                asset: 0,
                shares: "25.5".into(),
                nonce: 25,
            },
            "5244365c226ab1b7ec786129f134d104a2923a57b9cc2588d6b215aef5b55018",
        ),
        (
            TypedAction::AgentSetAbstraction {
                metaflux_chain: "Testnet".into(),
                user: addr(0xF6),
                kind: 3,
                value: "abstraction-value".into(),
                nonce: 14,
            },
            "0dd8a92857e2f4aafd97dd0131704bab22969345844389d2b214d55f2a7de71e",
        ),
        (
            TypedAction::MbWithdraw {
                metaflux_chain: "Testnet".into(),
                chain: 2,
                asset: 1,
                amount: 1_000_000,
                dst_addr: "0xdeadbeef".into(),
                nonce: 19,
            },
            "423f327abdec7b3469b6dc5d4993ac4a11f0a09487cec564b85d8162abdee2e8",
        ),
    ];
    assert_eq!(cases.len(), 12, "all 12 formerly-deferred actions pinned");
    for (action, want) in &cases {
        assert_eq!(
            hex::encode(_typed_digest_for_test(action)),
            *want,
            "extended typed digest drift for {action:?}"
        );
    }
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
        TypedAction::SetMetaliquiditySet {
            metaflux_chain: chain.clone(),
            account: addr(0xEE),
            allowed: true,
            nonce: 16,
        },
        TypedAction::RegisterMetaliquidityOperator {
            metaflux_chain: chain.clone(),
            vault_id: 42,
            operator: addr(0xFA),
            allowed: true,
            expires_at_ms: 1_700_000_000_000,
            nonce: 17,
        },
        TypedAction::UpdateIsolatedMargin {
            metaflux_chain: chain.clone(),
            asset: 1,
            delta: "-100.5".into(),
            nonce: 18,
        },
        TypedAction::TopUpIsolatedOnlyMargin {
            metaflux_chain: chain.clone(),
            asset: 1,
            amount: "50".into(),
            nonce: 19,
        },
        TypedAction::TokenDelegate {
            metaflux_chain: chain.clone(),
            validator: addr(0xD4),
            amount: "1000".into(),
            is_undelegate: false,
            nonce: 20,
        },
        TypedAction::VaultTransfer {
            metaflux_chain: chain.clone(),
            vault_id: 42,
            deposit: true,
            amount: "250.75".into(),
            nonce: 21,
        },
        TypedAction::VaultWithdraw {
            metaflux_chain: chain.clone(),
            vault_id: 42,
            shares: "10.5".into(),
            nonce: 22,
        },
        TypedAction::SpotMarginDeposit {
            metaflux_chain: chain.clone(),
            pair: 5,
            amount: "100".into(),
            nonce: 23,
        },
        TypedAction::SpotMarginWithdraw {
            metaflux_chain: chain.clone(),
            pair: 5,
            amount: "50".into(),
            nonce: 24,
        },
        TypedAction::SpotMarginOpen {
            metaflux_chain: chain.clone(),
            pair: 5,
            size: 1_000,
            limit_px: 5_000_000_000,
            borrow: "200".into(),
            nonce: 25,
        },
        TypedAction::EarnDeposit {
            metaflux_chain: chain.clone(),
            asset: 0,
            amount: "500".into(),
            nonce: 26,
        },
        TypedAction::EarnWithdraw {
            metaflux_chain: chain.clone(),
            asset: 0,
            shares: "25.5".into(),
            nonce: 27,
        },
        TypedAction::AgentSetAbstraction {
            metaflux_chain: chain.clone(),
            user: addr(0xF6),
            kind: 3,
            value: "abstraction-value".into(),
            nonce: 28,
        },
        TypedAction::MbWithdraw {
            metaflux_chain: chain,
            chain: 2,
            asset: 1,
            amount: 1_000_000,
            dst_addr: "0xdeadbeef".into(),
            nonce: 29,
        },
    ];
    assert_eq!(actions.len(), 30, "all 30 reachable typed actions covered");

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
