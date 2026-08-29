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
    rest::exchange_typed::{_typed_digest_for_test, _typed_digest_for_test_with_expiry},
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
        expires_at_ms: 1_700_000_000_000,
        nonce: 1,
    };
    assert_eq!(
        hex::encode(_typed_digest_for_test(&approve_agent)),
        "569bb62f0cd468264550e8bdc4c37abcf273bdd48569bed37b985c5d6e94693e",
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
/// `chain`), `uint64 amount` (bridge_withdraw), and verbatim-string (`value`) rules.
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
                lock_months: 0,
                nonce: 11,
            },
            "cc3d9e5ed170fc39028ebe587af079e42968a1c5e324da20bc584ddc28711a98",
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
            TypedAction::BridgeWithdraw {
                metaflux_chain: "Testnet".into(),
                chain: 2,
                asset: 1,
                amount: 1_000_000,
                dst_addr: "0xdeadbeef".into(),
                nonce: 19,
            },
            "3a3f54fcf37ab322eaea12dee2696e11048c107c344a8b59c962dc1e8e65cfa4",
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

/// (1c) The ten newly-typed actions (`core_evm_transfer` + the account /
/// sub-account / staking / abstraction / priority / encrypted set) must
/// reproduce the frozen contract digests (chain id 114514 / `"Testnet"`) — the
/// SAME byte-for-byte digests the TS SDK and the server pin. Covers the
/// optional-flatten (`create_sub_account` / `cancel_all_orders` present AND
/// absent), the `bytes` / `bytes32` rule (`submit_encrypted_order`), and the
/// verbatim-decimal-string rule (`amount` / `value`).
#[test]
fn newly_typed_kat_vectors_match_pinned_digests() {
    let cases: Vec<(TypedAction, &str)> = vec![
        (
            TypedAction::CoreEvmTransfer {
                metaflux_chain: "Testnet".into(),
                amount: "250.5".into(),
                to_evm: true,
                destination: addr(0xCE),
                asset: 0,
                nonce: 52,
            },
            "c4ea0f4c7ac7aad20c157bda62198070e6f1a3af941945726a7d09004ee2e27d",
        ),
        (
            // explicit_index present => hasExplicitIndex=true, explicitIndex=5.
            TypedAction::CreateSubAccount {
                metaflux_chain: "Testnet".into(),
                name: "bot".into(),
                has_explicit_index: true,
                explicit_index: 5,
                shared_stp_group: true,
                nonce: 53,
            },
            "d4ab521e447ba69431403946797bc4fed4f7ab1c395fbde55170dae5cd5872ef",
        ),
        (
            TypedAction::SubAccountTransfer {
                metaflux_chain: "Testnet".into(),
                sub_index: 0,
                deposit: true,
                amount: "100.5".into(),
                nonce: 55,
            },
            "741b3707a6530c4410d54ed1f80a9581ad3d7255a8d84dc93356adf71fb90910",
        ),
        (
            TypedAction::SubAccountSpotTransfer {
                metaflux_chain: "Testnet".into(),
                sub_index: 2,
                token: 7,
                deposit: false,
                amount: "42.0".into(),
                nonce: 56,
            },
            "0c2e9be9c1372f62cbd6f6122a9d5f48589ae966ec1717ddd1fe8a56984997d4",
        ),
        (
            TypedAction::CDeposit {
                metaflux_chain: "Testnet".into(),
                amount: "500".into(),
                nonce: 57,
            },
            "59e1ad2f5970799c5ac2f84f859757c6b102bfefa0e42edc1068ed2a33240d39",
        ),
        (
            TypedAction::CWithdraw {
                metaflux_chain: "Testnet".into(),
                amount: "500".into(),
                nonce: 58,
            },
            "66466daf4a1f531f167ea4d131ee4c41c5e16d75e3a85bd0cc739633b763b4cf",
        ),
        (
            TypedAction::UserSetAbstraction {
                metaflux_chain: "Testnet".into(),
                kind: 3,
                value: "9.9".into(),
                nonce: 60,
            },
            "8a84c2fe0594d1db9f4bb6c3db0c539cec75b7c759d053818db92d7acc107148",
        ),
        (
            TypedAction::PriorityBid {
                metaflux_chain: "Testnet".into(),
                asset: 8,
                bid_bps: 6,
                nonce: 61,
            },
            "aaffc74728255d071f7c3033ddb4aa81f822269e7ba3742172933fd238cc3522",
        ),
        (
            // asset present => hasAsset=true, asset=4.
            TypedAction::CancelAllOrders {
                metaflux_chain: "Testnet".into(),
                owner: None,
                has_asset: true,
                asset: 4,
                nonce: 62,
            },
            "9088140fe0311f99071e2c45e5eff506052fa787e6eb44e0d110a198fb5a3bf7",
        ),
        (
            TypedAction::SubmitEncryptedOrder {
                metaflux_chain: "Testnet".into(),
                ciphertext: vec![1, 2, 3, 4],
                commitment: [0x11; 32],
                threshold: 2,
                target_block: 1000,
                reveal_deadline_ms: 5000,
                nonce: 64,
            },
            "86657cd5b8920543f8e4ec41790aeb0957af3c4d2440e25d8009cfa9e5fc9675",
        ),
    ];
    assert_eq!(cases.len(), 10, "all 10 newly-typed actions pinned");
    for (action, want) in &cases {
        assert_eq!(
            hex::encode(_typed_digest_for_test(action)),
            *want,
            "newly-typed digest drift for {action:?}"
        );
    }
}

/// (1d) The optional-flatten ABSENT variants must reproduce the frozen
/// contract digests the TS SDK + server pin: `create_sub_account` with NO index
/// (`hasExplicitIndex=false`, `explicitIndex=0`) and `cancel_all_orders` with NO
/// asset (`hasAsset=false`, `asset=0`). These are the highest-risk regressions —
/// an absent optional must still sign the flattened `(false, 0)` pair.
#[test]
fn optional_absent_typed_kat_vectors_match_pinned_digests() {
    let create_sub_account_no_index = TypedAction::CreateSubAccount {
        metaflux_chain: "Testnet".into(),
        name: "bot".into(),
        has_explicit_index: false,
        explicit_index: 0,
        shared_stp_group: false,
        nonce: 54,
    };
    assert_eq!(
        hex::encode(_typed_digest_for_test(&create_sub_account_no_index)),
        "9a8663dc58851e1e0baf4a04a1fcdc38ca5b13b8017eb49554a10b9060ae5eff",
        "create_sub_account (no index) digest drift"
    );

    let cancel_all_orders_no_asset = TypedAction::CancelAllOrders {
        metaflux_chain: "Testnet".into(),
        owner: None,
        has_asset: false,
        asset: 0,
        nonce: 63,
    };
    assert_eq!(
        hex::encode(_typed_digest_for_test(&cancel_all_orders_no_asset)),
        "cd7cb102701e9d114bad62d2b693a3f1d4ea78ae5e6ea243a496720debac97e4",
        "cancel_all_orders (no asset) digest drift"
    );
}

/// (1e) The three W1 microstructure typed actions (`rfq_request` / `rfq_accept`
/// / `fba_submit`) must reproduce the node's frozen contract digests
/// byte-for-byte. The pinned literals are the EXACT bytes the node emits for the
/// same field values (chain id 114514 / `"Testnet"`); a drift in any encodeType
/// string, the `uint8` side / `uint64` numeric encoding, the optional-flatten
/// (`hasLimitPx` / `hasStpGroup`), the domain, or the envelope would change them.
///
/// `pm_unenroll` is NOT pinned here: it is a pure wire-tag ALIAS that reuses the
/// already-pinned `UserPortfolioMargin` digest (see (1c) + the sign/recover
/// sweep).
#[test]
fn w1_micro_typed_kat_vectors_match_pinned_digests() {
    // side 0 = Bid; numeric fields are the raw u64 wire form (NOT decimal-scaled).
    let rfq_request = TypedAction::RfqRequest {
        metaflux_chain: "Testnet".into(),
        owner: None,
        market: 7,
        side: 0,
        size: 1_000,
        has_limit_px: true,
        limit_px: 105,
        expiry_ms: 0,
        has_stp_group: false,
        stp_group: 0,
        nonce: 53,
    };
    assert_eq!(
        hex::encode(_typed_digest_for_test(&rfq_request)),
        "0f5ddd54fd82663e103728721fffa73a50c28f639373597d2c46bd6de16d459f",
        "RfqRequest digest drift vs node"
    );

    let rfq_accept = TypedAction::RfqAccept {
        metaflux_chain: "Testnet".into(),
        owner: None,
        rfq_id: 9,
        quote_idx: 2,
        size: 500,
        nonce: 55,
    };
    assert_eq!(
        hex::encode(_typed_digest_for_test(&rfq_accept)),
        "fc8da74189fbbaf2a10430dc41df54e0495b2489ab8d79f2a5f0fe4920df0f3d",
        "RfqAccept digest drift vs node"
    );

    // Owner-bound RFQ taker pair (an approved agent opens then accepts AS a
    // vault). Both legs must carry the SAME owner: the node captures
    // `requester = sender` at request time and gates the accept on
    // `requester == sender`.
    let rfq_request_owner = TypedAction::RfqRequest {
        metaflux_chain: "Testnet".into(),
        owner: Some(addr(0xE4)),
        market: 7,
        side: 0,
        size: 1_000,
        has_limit_px: true,
        limit_px: 105,
        expiry_ms: 0,
        has_stp_group: false,
        stp_group: 0,
        nonce: 53,
    };
    assert_eq!(
        hex::encode(_typed_digest_for_test(&rfq_request_owner)),
        "6eb97ef8c8b73fd2bf5058c999f499d7d88b6523a57429602f178c5631c88973",
        "RfqRequestWithOwner digest drift vs node"
    );
    assert_ne!(
        _typed_digest_for_test(&rfq_request),
        _typed_digest_for_test(&rfq_request_owner),
        "binding owner must change the RfqRequest digest"
    );

    let rfq_accept_owner = TypedAction::RfqAccept {
        metaflux_chain: "Testnet".into(),
        owner: Some(addr(0xE4)),
        rfq_id: 9,
        quote_idx: 2,
        size: 500,
        nonce: 55,
    };
    assert_eq!(
        hex::encode(_typed_digest_for_test(&rfq_accept_owner)),
        "5d68b024f940cf5d0e7d1f3ebe9dbc744b0c7fe805abb4e492b81faac48e2b95",
        "RfqAcceptWithOwner digest drift vs node"
    );
    assert_ne!(
        _typed_digest_for_test(&rfq_accept),
        _typed_digest_for_test(&rfq_accept_owner),
        "binding owner must change the RfqAccept digest"
    );

    let fba_submit = TypedAction::FbaSubmit {
        metaflux_chain: "Testnet".into(),
        market: 7,
        side: 0,
        size: 1_000,
        price: 100,
        has_stp_group: true,
        stp_group: 5,
        nonce: 56,
    };
    assert_eq!(
        hex::encode(_typed_digest_for_test(&fba_submit)),
        "3cc62ef670c2f4276cd3aad36c3c073173bd3fd215f797af25f67ed7cc945d86",
        "FbaSubmit digest drift vs node"
    );

    let noop = TypedAction::Noop {
        metaflux_chain: "Testnet".into(),
        nonce: 57,
    };
    assert_eq!(
        hex::encode(_typed_digest_for_test(&noop)),
        "64c8dcfe04b60e572df9b22536e82c46020d6953a36a3a5619307b0ef1fb1a1b",
        "Noop digest drift vs node"
    );
}

/// (1f) The P1 additions (`vault_distribute` / `claim_builder_rewards` /
/// `claim_referral_rewards` / `rfq_quote` owner-less + with-owner) must reproduce
/// the node's frozen contract digests byte-for-byte. Inputs mirror the node's
/// cross-language vector entries (domain chain 114514 / `"Testnet"`); `owner` = the
/// all-`0xE4` address, exactly as the node's `RfqQuoteWithOwner` vector.
#[test]
fn p1_typed_kat_vectors_match_pinned_digests() {
    let vault_distribute = TypedAction::VaultDistribute {
        metaflux_chain: "Testnet".into(),
        vault_id: 42,
        pnl: "250.75".into(),
        nonce: 18,
    };
    assert_eq!(
        hex::encode(_typed_digest_for_test(&vault_distribute)),
        "a51d392ef7a24aef8600eaa3e31ff67b32f9c35ed3383045c33f330b605f3939",
        "VaultDistribute digest drift vs node"
    );

    let claim_builder = TypedAction::ClaimBuilderRewards {
        metaflux_chain: "Testnet".into(),
        nonce: 31,
    };
    assert_eq!(
        hex::encode(_typed_digest_for_test(&claim_builder)),
        "af77c478f442d240a28321177569a43a3300cd890e123bc0e9c677117d48655e",
        "ClaimBuilderRewards digest drift vs node"
    );

    let claim_referral = TypedAction::ClaimReferralRewards {
        metaflux_chain: "Testnet".into(),
        nonce: 32,
    };
    assert_eq!(
        hex::encode(_typed_digest_for_test(&claim_referral)),
        "d451acc374db4aa01a301690ccf847c96cdec0c37cb7fbbac6c4890b9ca3687e",
        "ClaimReferralRewards digest drift vs node"
    );

    // Owner-less RFQ maker quote.
    let rfq_quote = TypedAction::RfqQuote {
        metaflux_chain: "Testnet".into(),
        owner: None,
        rfq_id: 9,
        price: 105,
        max_size: 500,
        valid_until_ms: 9_000,
        has_stp_group: false,
        stp_group: 0,
        nonce: 54,
    };
    assert_eq!(
        hex::encode(_typed_digest_for_test(&rfq_quote)),
        "86ea54e354da6e4626aeaf4001a27bee86793e4fde366d0cfa8662ace831ee25",
        "RfqQuote (owner-less) digest drift vs node"
    );

    // Owner-bound RFQ maker quote (agent quotes AS a vault).
    let rfq_quote_owner = TypedAction::RfqQuote {
        metaflux_chain: "Testnet".into(),
        owner: Some(addr(0xE4)),
        rfq_id: 9,
        price: 105,
        max_size: 500,
        valid_until_ms: 9_000,
        has_stp_group: false,
        stp_group: 0,
        nonce: 54,
    };
    assert_eq!(
        hex::encode(_typed_digest_for_test(&rfq_quote_owner)),
        "6583f5d725c522a8a0adbec966da23784dff48c90be3835086e0a4f070179bed",
        "RfqQuoteWithOwner digest drift vs node"
    );
    // The owner word must actually change the digest.
    assert_ne!(
        _typed_digest_for_test(&rfq_quote),
        _typed_digest_for_test(&rfq_quote_owner),
        "binding owner must change the RfqQuote digest"
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
            expires_at_ms: 1_700_000_000_000,
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
            lock_months: 0,
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
        TypedAction::BridgeWithdraw {
            metaflux_chain: chain.clone(),
            chain: 2,
            asset: 1,
            amount: 1_000_000,
            dst_addr: "0xdeadbeef".into(),
            nonce: 29,
        },
        TypedAction::CoreEvmTransfer {
            metaflux_chain: chain.clone(),
            amount: "250.5".into(),
            to_evm: true,
            destination: addr(0xCE),
            asset: 0,
            nonce: 30,
        },
        TypedAction::CreateSubAccount {
            metaflux_chain: chain.clone(),
            name: "bot".into(),
            has_explicit_index: true,
            explicit_index: 5,
            shared_stp_group: true,
            nonce: 31,
        },
        TypedAction::SubAccountTransfer {
            metaflux_chain: chain.clone(),
            sub_index: 0,
            deposit: true,
            amount: "100.5".into(),
            nonce: 32,
        },
        TypedAction::SubAccountSpotTransfer {
            metaflux_chain: chain.clone(),
            sub_index: 2,
            token: 7,
            deposit: false,
            amount: "42.0".into(),
            nonce: 33,
        },
        TypedAction::CDeposit {
            metaflux_chain: chain.clone(),
            amount: "500".into(),
            nonce: 34,
        },
        TypedAction::CWithdraw {
            metaflux_chain: chain.clone(),
            amount: "500".into(),
            nonce: 35,
        },
        TypedAction::UserSetAbstraction {
            metaflux_chain: chain.clone(),
            kind: 3,
            value: "9.9".into(),
            nonce: 37,
        },
        TypedAction::PriorityBid {
            metaflux_chain: chain.clone(),
            asset: 8,
            bid_bps: 6,
            nonce: 38,
        },
        TypedAction::CancelAllOrders {
            metaflux_chain: chain.clone(),
            owner: None,
            has_asset: false,
            asset: 0,
            nonce: 39,
        },
        TypedAction::SubmitEncryptedOrder {
            metaflux_chain: chain.clone(),
            ciphertext: vec![1, 2, 3, 4],
            commitment: [0x11; 32],
            threshold: 2,
            target_block: 1000,
            reveal_deadline_ms: 5000,
            nonce: 40,
        },
        TypedAction::RfqRequest {
            metaflux_chain: chain.clone(),
            owner: None,
            market: 7,
            side: 0,
            size: 1_000,
            has_limit_px: true,
            limit_px: 105,
            expiry_ms: 0,
            has_stp_group: false,
            stp_group: 0,
            nonce: 41,
        },
        TypedAction::RfqRequest {
            metaflux_chain: chain.clone(),
            owner: Some(addr(0xE4)),
            market: 7,
            side: 0,
            size: 1_000,
            has_limit_px: true,
            limit_px: 105,
            expiry_ms: 0,
            has_stp_group: false,
            stp_group: 0,
            nonce: 41,
        },
        TypedAction::RfqAccept {
            metaflux_chain: chain.clone(),
            owner: None,
            rfq_id: 9,
            quote_idx: 2,
            size: 500,
            nonce: 42,
        },
        TypedAction::RfqAccept {
            metaflux_chain: chain.clone(),
            owner: Some(addr(0xE4)),
            rfq_id: 9,
            quote_idx: 2,
            size: 500,
            nonce: 42,
        },
        TypedAction::FbaSubmit {
            metaflux_chain: chain.clone(),
            market: 7,
            side: 1,
            size: 1_000,
            price: 100,
            has_stp_group: true,
            stp_group: 5,
            nonce: 43,
        },
        TypedAction::Noop {
            metaflux_chain: chain.clone(),
            nonce: 44,
        },
        TypedAction::VaultDistribute {
            metaflux_chain: chain.clone(),
            vault_id: 42,
            pnl: "250.75".into(),
            nonce: 45,
        },
        TypedAction::ClaimBuilderRewards {
            metaflux_chain: chain.clone(),
            nonce: 46,
        },
        TypedAction::ClaimReferralRewards {
            metaflux_chain: chain.clone(),
            nonce: 47,
        },
        TypedAction::RfqQuote {
            metaflux_chain: chain.clone(),
            owner: None,
            rfq_id: 9,
            price: 105,
            max_size: 500,
            valid_until_ms: 9_000,
            has_stp_group: false,
            stp_group: 0,
            nonce: 48,
        },
        TypedAction::RfqQuote {
            metaflux_chain: chain.clone(),
            owner: Some(addr(0xE4)),
            rfq_id: 9,
            price: 105,
            max_size: 500,
            valid_until_ms: 9_000,
            has_stp_group: false,
            stp_group: 0,
            nonce: 49,
        },
        // The accepted shape: source_dex 0, to_perp false, local delivery (0).
        TypedAction::SendToEvmWithData {
            metaflux_chain: chain.clone(),
            token: 7,
            amount: "12.5".into(),
            source_dex: 0,
            destination_recipient: addr(0xE7),
            to_perp: false,
            destination_chain_id: 0,
            data: vec![0xCA, 0xFE],
            transfer_nonce: 5,
            nonce: 50,
        },
        TypedAction::BorrowLend {
            metaflux_chain: chain.clone(),
            kind: 1,
            amount: "1000".into(),
            nonce: 51,
        },
        TypedAction::RegisterMetaliquidityOperator {
            metaflux_chain: chain.clone(),
            vault_id: 42,
            operator: addr(0x70),
            allowed: true,
            expires_at_ms: 1_700_000_000_000,
            nonce: 52,
        },
        TypedAction::SpotRegisterToken {
            metaflux_chain: chain.clone(),
            symbol: "MTFX".into(),
            sz_decimals: 2,
            wei_decimals: 8,
            max_deploy_fee: "1250.50".into(),
            nonce: 53,
        },
        TypedAction::SpotRegisterPair {
            metaflux_chain: chain.clone(),
            base: 42,
            quote: 0,
            name: "MTFX/USDC".into(),
            max_deploy_fee: "980.00".into(),
            nonce: 54,
        },
        TypedAction::SpotSetPairParams {
            metaflux_chain: chain.clone(),
            pair: 7,
            taker_fee_dbps: 350,
            maker_fee_dbps: 120,
            min_notional_cents: 1000,
            nonce: 55,
        },
        TypedAction::SpotSetPairActive {
            metaflux_chain: chain.clone(),
            pair: 7,
            active: true,
            nonce: 56,
        },
        TypedAction::SpotSeedHolders {
            metaflux_chain: chain.clone(),
            asset: 42,
            holders: vec![addr(0x11), addr(0x22)],
            amounts: vec!["1000.5".into(), "250".into()],
            nonce: 57,
        },
        TypedAction::SpotFinalizeSupply {
            metaflux_chain: chain.clone(),
            asset: 42,
            max_supply: "1250.5".into(),
            nonce: 58,
        },
        TypedAction::PerpRegisterAsset {
            metaflux_chain: chain.clone(),
            symbol: "WIF".into(),
            decimals: 8,
            nonce: 59,
        },
        TypedAction::PerpSetOracle {
            metaflux_chain: chain.clone(),
            asset: 1001,
            oracle_source_mask: 0x03ff,
            nonce: 60,
        },
        TypedAction::PerpSetLeverage {
            metaflux_chain: chain.clone(),
            asset: 1001,
            max_leverage: 20,
            nonce: 61,
        },
        TypedAction::PerpSetFeeTier {
            metaflux_chain: chain.clone(),
            asset: 1001,
            taker_fee_dbps: 45,
            maker_fee_dbps: 12,
            deployer_fee_bps: 6,
            nonce: 62,
        },
        TypedAction::PerpSetMakerRebate {
            metaflux_chain: chain.clone(),
            asset: 1001,
            rebate_bps: 2,
            nonce: 63,
        },
        TypedAction::PerpSetMinSize {
            metaflux_chain: chain.clone(),
            asset: 1001,
            min_order_size: 1000,
            nonce: 64,
        },
        TypedAction::PerpActivateMarket {
            metaflux_chain: chain.clone(),
            asset: 1001,
            nonce: 65,
        },
        TypedAction::PerpDeactivateMarket {
            metaflux_chain: chain.clone(),
            asset: 1001,
            nonce: 66,
        },
        TypedAction::PerpSetSubDeployers {
            metaflux_chain: chain.clone(),
            asset: 1001,
            sub_deployer: addr(0xaa),
            add: true,
            nonce: 67,
        },
        TypedAction::MultiSig {
            metaflux_chain: chain,
            user: addr(0x22),
            inner_action_blob: br#"{"type":"noop","params":{}}"#.to_vec(),
            signatures: vec![vec![0x11; 65], vec![0x22; 65]],
            nonce: 44,
        },
    ];
    assert_eq!(actions.len(), 68, "all 68 reachable typed actions covered");

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

        // expires_after == 0 MUST reproduce the plain digest byte-for-byte
        // (mirrors the node's `expires_after_zero_is_byte_identical_digest`);
        // a non-zero expiry MUST change it (the expiry is truly signed).
        assert_eq!(
            _typed_digest_for_test_with_expiry(action, 0),
            digest,
            "expires_after=0 must be byte-identical for {action:?}"
        );
        let with_expiry = _typed_digest_for_test_with_expiry(action, 1_735_693_200_000);
        assert_ne!(
            with_expiry, digest,
            "non-zero expires_after must fold into the digest for {action:?}"
        );
    }
}

/// The OPTIONAL top-level `expiresAfter` fold, pinned byte-for-byte against the
/// chain itself (fixtures generated by executing the chain at the release pin;
/// chain id 114514 / `"Testnet"`, nonce 1_735_689_600_000, expiry
/// 1_735_693_200_000):
///
/// - `Withdraw` (a field-bearing account action): plain digest unchanged, and the
///   expiry-folded digest matches the node's `digest_with_expiry`.
/// - `MultiSig` (the outer envelope with `bytes` + `bytes[]` fields): both the
///   plain and expiry-folded digests match — this is the three-way KAT for the
///   `enc_bytes` + `enc_bytes_array` outer encoding.
#[test]
fn expires_after_fold_matches_chain() {
    const NONCE: u64 = 1_735_689_600_000;
    const EXPIRY: u64 = 1_735_693_200_000;

    let withdraw = TypedAction::Withdraw {
        metaflux_chain: "Testnet".into(),
        asset: 0,
        amount: "100.5".into(),
        destination_chain_id: 8453,
        use_cctp: false,
        nonce: NONCE,
    };
    // expiry 0 == plain, byte-identical (chain fixture E2.withdraw_digest_plain).
    assert_eq!(
        hex::encode(_typed_digest_for_test(&withdraw)),
        "425495f369661cdff0c274cd16ee5ad91294892a924b9a84033f09183b087c0e",
        "withdraw plain digest drift"
    );
    assert_eq!(
        hex::encode(_typed_digest_for_test_with_expiry(&withdraw, 0)),
        "425495f369661cdff0c274cd16ee5ad91294892a924b9a84033f09183b087c0e",
        "withdraw expiry=0 must equal plain"
    );
    // Non-zero expiry (chain fixture E2.withdraw_digest_expiry).
    assert_eq!(
        hex::encode(_typed_digest_for_test_with_expiry(&withdraw, EXPIRY)),
        "9ad23a96bb83b8bdd427fe9023b4855e8689be66da73da745f9af0acb59f5833",
        "withdraw expiry-folded digest drift vs chain"
    );

    // Outer MultiSig envelope: user = 0x22..22, inner blob = the noop bytes, two
    // fixed 65-byte signatures (r=0x11.., s=0x22.., v=0x1b / r=0x33.., s=0x44..,
    // v=0x1c) — matches the fixture generator's Fixture O.
    let mut sig_a = vec![0x11u8; 32];
    sig_a.extend_from_slice(&[0x22u8; 32]);
    sig_a.push(0x1b);
    let mut sig_b = vec![0x33u8; 32];
    sig_b.extend_from_slice(&[0x44u8; 32]);
    sig_b.push(0x1c);
    let multi_sig = TypedAction::MultiSig {
        metaflux_chain: "Testnet".into(),
        user: addr(0x22),
        inner_action_blob: br#"{"type":"noop","params":{}}"#.to_vec(),
        signatures: vec![sig_a, sig_b],
        nonce: NONCE,
    };
    // Chain fixture O.multisig_outer_digest_plain.
    assert_eq!(
        hex::encode(_typed_digest_for_test(&multi_sig)),
        "f5ea6e0bb193d12e7c74c0ed1efe06d84da404c087836e1801c565530e29027b",
        "outer MultiSig plain digest drift vs chain"
    );
    // Chain fixture O.multisig_outer_digest_expiry.
    assert_eq!(
        hex::encode(_typed_digest_for_test_with_expiry(&multi_sig, EXPIRY)),
        "54e5f5d4fe4f8bf2767539fd0d88ab4d5ed0ecae1ccdd604a8c984016227561c",
        "outer MultiSig expiry-folded digest drift vs chain"
    );
}

/// `SendToEvmWithData`, pinned byte-for-byte against the chain crate's own
/// fixture (chain id 114514 / `"Testnet"`). The digest was READ from the chain
/// crate, not computed here: the same fixture run also reproduces the `SendAsset`
/// digest already pinned above, which proves the two sides build the digest the
/// same way.
///
/// The fixture deliberately carries `source_dex: 1` and a remote
/// `destination_chain_id`. Both values are REFUSED at submission, and neither
/// changes what the signer signs — this test pins the signing form, not what the
/// chain accepts. Signing the wrong form is the failure it guards: the chain then
/// rejects the signature, and the caller cannot tell why.
#[test]
fn send_to_evm_with_data_matches_chain_fixture() {
    let action = TypedAction::SendToEvmWithData {
        metaflux_chain: "Testnet".into(),
        token: 7,
        amount: "12.5".into(),
        source_dex: 1,
        destination_recipient: addr(0xE7),
        to_perp: false,
        destination_chain_id: 8964,
        data: vec![0xCA, 0xFE],
        transfer_nonce: 5,
        nonce: 18,
    };
    assert_eq!(
        hex::encode(_typed_digest_for_test(&action)),
        "6dd606a21f9786874a3215903bce4d713379222d7e67311c2876a4fd288bd452",
        "SendToEvmWithData digest drift vs chain"
    );

    // The two nonces are separate signed fields. Swapping them must move the
    // digest, else a client could sign one for the other and the chain would
    // deliver a transfer labelled with the wrong number.
    let swapped = TypedAction::SendToEvmWithData {
        metaflux_chain: "Testnet".into(),
        token: 7,
        amount: "12.5".into(),
        source_dex: 1,
        destination_recipient: addr(0xE7),
        to_perp: false,
        destination_chain_id: 8964,
        data: vec![0xCA, 0xFE],
        transfer_nonce: 18,
        nonce: 5,
    };
    assert_ne!(
        _typed_digest_for_test(&action),
        _typed_digest_for_test(&swapped),
        "transferNonce and the envelope nonce must occupy distinct signed slots"
    );
}

// ---- `borrow_lend` + `register_metaliquidity_operator` ----
//
// The chain publishes no cross-language vector for these two. So the expected
// digest below is rebuilt from the frozen type string and one explicit word per
// field, NOT from the encoder under test: a wrong field order or a wrong word
// width in the encoder fails against this reconstruction. The pinned hex then
// holds the value still.

/// One 32-byte word per EIP-712 atomic type, written out by hand.
mod word {
    use tiny_keccak::{Hasher, Keccak};

    pub fn keccak(input: &[u8]) -> [u8; 32] {
        let mut h = Keccak::v256();
        h.update(input);
        let mut out = [0u8; 32];
        h.finalize(&mut out);
        out
    }

    pub fn string(s: &str) -> [u8; 32] {
        keccak(s.as_bytes())
    }

    pub fn uint(v: u64) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[24..].copy_from_slice(&v.to_be_bytes());
        out
    }

    pub fn bool_word(v: bool) -> [u8; 32] {
        uint(u64::from(v))
    }

    pub fn address(a: &metaflux_client::wallet::Address) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[12..].copy_from_slice(a.as_bytes());
        out
    }
}

/// Rebuild `keccak256(0x1901 ‖ domain ‖ keccak256(typeHash ‖ words))` from the
/// parts, independently of the crate's encoder.
fn digest_from_parts(type_string: &[u8], words: &[[u8; 32]]) -> [u8; 32] {
    let mut k = Keccak::v256();
    k.update(&word::keccak(type_string));
    for w in words {
        k.update(w);
    }
    let mut hash_struct = [0u8; 32];
    k.finalize(&mut hash_struct);

    let domain = metaflux_client::wallet::metaflux_domain_separator(
        metaflux_client::rest::exchange::MTF_CHAIN_ID,
    );
    let mut k = Keccak::v256();
    k.update(&[0x19, 0x01]);
    k.update(&domain);
    k.update(&hash_struct);
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out
}

const BORROW_LEND_TYPE: &[u8] =
    b"MetaFluxTransaction:BorrowLend(string metafluxChain,uint8 kind,string amount,uint64 nonce)";
const REGISTER_METALIQUIDITY_OPERATOR_TYPE: &[u8] =
    b"MetaFluxTransaction:RegisterMetaliquidityOperator(string metafluxChain,uint64 vaultId,address operator,bool allowed,uint64 expiresAtMs,uint64 nonce)";

#[test]
fn borrow_lend_matches_an_independent_reconstruction() {
    let action = TypedAction::BorrowLend {
        metaflux_chain: "Testnet".into(),
        kind: 1,
        amount: "1000".into(),
        nonce: 18,
    };
    assert_eq!(
        action.type_hash(),
        word::keccak(BORROW_LEND_TYPE),
        "encodeType drift makes every borrow_lend signature unrecoverable"
    );
    let want = digest_from_parts(
        BORROW_LEND_TYPE,
        &[
            word::string("Testnet"),
            word::uint(1),
            word::string("1000"),
            word::uint(18),
        ],
    );
    assert_eq!(_typed_digest_for_test(&action), want);
    assert_eq!(
        hex::encode(want),
        "ef1af8c9c6e9850fb704694e9034dea700914ba60704c297c3274dc2122b7a5f"
    );

    // Pinned against the NODE's own cross-language vector set (domain
    // chain 114514): the SDK reconstruction above proves self-consistency, this
    // proves cross-implementation agreement.
    let node_fixture = TypedAction::BorrowLend {
        metaflux_chain: "Testnet".into(),
        kind: 0,
        amount: "1000".into(),
        nonce: 18,
    };
    assert_eq!(
        hex::encode(_typed_digest_for_test(&node_fixture)),
        "3e5afde6b9f0d0b1c0b2f9f55234c62ca9487d8d46f990ae0593ff147dfc3bb5",
        "borrow_lend digest drifted from the node vector"
    );

    // `kind` is a signed field: lending is not unlending.
    let lend = TypedAction::BorrowLend {
        metaflux_chain: "Testnet".into(),
        kind: 0,
        amount: "1000".into(),
        nonce: 18,
    };
    assert_ne!(
        _typed_digest_for_test(&action),
        _typed_digest_for_test(&lend)
    );
}

#[test]
fn register_metaliquidity_operator_matches_an_independent_reconstruction() {
    let operator = addr(0x70);
    let action = TypedAction::RegisterMetaliquidityOperator {
        metaflux_chain: "Testnet".into(),
        vault_id: 42,
        operator,
        allowed: true,
        expires_at_ms: 1_700_000_000_000,
        nonce: 34,
    };
    assert_eq!(
        action.type_hash(),
        word::keccak(REGISTER_METALIQUIDITY_OPERATOR_TYPE),
        "encodeType drift makes every operator grant unrecoverable"
    );
    let want = digest_from_parts(
        REGISTER_METALIQUIDITY_OPERATOR_TYPE,
        &[
            word::string("Testnet"),
            word::uint(42),
            word::address(&operator),
            word::bool_word(true),
            word::uint(1_700_000_000_000),
            word::uint(34),
        ],
    );
    assert_eq!(_typed_digest_for_test(&action), want);
    assert_eq!(
        hex::encode(want),
        "4de965c3bc25f15ddafa0b778179909f50cd0930bf4f58a652dde93bce524c80"
    );

    // Revoking is not granting.
    let revoke = TypedAction::RegisterMetaliquidityOperator {
        metaflux_chain: "Testnet".into(),
        vault_id: 42,
        operator,
        allowed: false,
        expires_at_ms: 1_700_000_000_000,
        nonce: 34,
    };
    assert_ne!(
        _typed_digest_for_test(&action),
        _typed_digest_for_test(&revoke)
    );
}
