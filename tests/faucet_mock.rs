//! Mock-server tests for the devnet / testnet faucet helper.
//!
//! Spin up a `wiremock::MockServer` (a stand-in for the faucet's OWN origin —
//! NOT the trading API), register `POST /faucet` responses, and assert the
//! signed request body, the success decode, and the refusal mapping.

use std::time::{SystemTime, UNIX_EPOCH};

use metaflux_client::wallet::{Address, Wallet};
use metaflux_client::{
    ClientError, FAUCET_CLAIM_TTL_SECS, FaucetClaim, FaucetResponse, faucet_claim_message,
    request_faucet, request_faucet_with_claim,
};
use serde_json::{Value, json};
use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// The EIP-155 specification's example key. Public, so never fund it.
const KAT_KEY: &str = "0x4646464646464646464646464646464646464646464646464646464646464646";
const KAT_ADDRESS: &str = "0x9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f";
const KAT_EXPIRES: u64 = 1_791_000_300;
// Computed with @noble/curves, an implementation independent of this crate.
const KAT_SIGNATURE: &str = "0x40cc298fe68bb92f1cc2877f7840a0be5332c8db90b840ba830d8b8a3c7c114c547db1a452ec9a05d8e522fb3607a7b8fe0edb8a7e50455fdf65e4e44e47c5d41c";

fn kat_wallet() -> Wallet {
    Wallet::from_hex(KAT_KEY).unwrap()
}

fn queued(address: &str) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "address": address,
        "usdc": 3000,
        "mtf": 10,
        "status": "queued"
    }))
}

#[test]
fn claim_message_is_the_four_line_text() {
    let address = Address::from_hex("0x9D8A62F656A8D1615C1294FD71E9CFB3E4855A4F").unwrap();
    assert_eq!(
        faucet_claim_message(address, 114_514, KAT_EXPIRES),
        "MetaFlux faucet claim\naddress: 0x9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f\nchain: 114514\nexpires: 1791000300"
    );
}

#[test]
fn claim_signature_matches_the_known_answer() {
    let claim = FaucetClaim::sign_with_expiry(&kat_wallet(), 114_514, KAT_EXPIRES).unwrap();
    assert_eq!(claim.address.to_string(), KAT_ADDRESS);
    assert_eq!(claim.expires, KAT_EXPIRES);
    assert_eq!(claim.signature, KAT_SIGNATURE);
}

#[test]
fn chain_id_is_part_of_the_signed_text() {
    let testnet = FaucetClaim::sign_with_expiry(&kat_wallet(), 114_514, KAT_EXPIRES).unwrap();
    let devnet = FaucetClaim::sign_with_expiry(&kat_wallet(), 31_337, KAT_EXPIRES).unwrap();
    assert_ne!(testnet.signature, devnet.signature);
}

#[tokio::test]
async fn request_faucet_signs_and_sends_the_claim() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/faucet"))
        .respond_with(queued(KAT_ADDRESS))
        .mount(&server)
        .await;

    let before = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let res = request_faucet(&server.uri(), &kat_wallet(), 114_514)
        .await
        .unwrap();
    assert_eq!(
        res,
        FaucetResponse {
            address: KAT_ADDRESS.into(),
            usdc: 3000,
            mtf: 10,
            status: "queued".into(),
        }
    );

    let sent = server.received_requests().await.unwrap();
    let body: Value = serde_json::from_slice(&sent[0].body).unwrap();
    assert_eq!(body.as_object().unwrap().len(), 3, "only the claim: {body}");
    assert_eq!(body["address"], KAT_ADDRESS);
    let expires = body["expires"].as_u64().unwrap();
    assert!(
        (before + FAUCET_CLAIM_TTL_SECS..=before + FAUCET_CLAIM_TTL_SECS + 5).contains(&expires),
        "expires {expires} is not now + {FAUCET_CLAIM_TTL_SECS} s"
    );
    let resigned = FaucetClaim::sign_with_expiry(&kat_wallet(), 114_514, expires).unwrap();
    assert_eq!(body["signature"], resigned.signature.as_str());
}

#[tokio::test]
async fn a_precomputed_claim_is_sent_as_is() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/faucet"))
        .and(body_json(json!({
            "address": KAT_ADDRESS,
            "expires": KAT_EXPIRES,
            "signature": KAT_SIGNATURE
        })))
        .respond_with(queued(KAT_ADDRESS))
        .mount(&server)
        .await;

    let claim = FaucetClaim {
        address: Address::from_hex(KAT_ADDRESS).unwrap(),
        expires: KAT_EXPIRES,
        signature: KAT_SIGNATURE.into(),
    };
    let res = request_faucet_with_claim(&server.uri(), &claim)
        .await
        .unwrap();
    assert_eq!(res.status, "queued");
}

#[tokio::test]
async fn a_refusal_keeps_the_node_text() {
    let refusal = "faucet needs mainnet activity: this wallet must hold at least 0.01 ETH on Ethereum mainnet";
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/faucet"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({ "error": refusal })))
        .mount(&server)
        .await;

    let err = request_faucet(&server.uri(), &kat_wallet(), 114_514)
        .await
        .unwrap_err();
    match err {
        ClientError::ProtocolError { code, msg } => {
            assert_eq!(code, 403);
            assert_eq!(msg, refusal);
        }
        other => panic!("expected ProtocolError, got {other:?}"),
    }
}

#[tokio::test]
async fn faucet_429_maps_to_protocol_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/faucet"))
        .respond_with(ResponseTemplate::new(429).set_body_json(json!({
            "error": "address already funded"
        })))
        .mount(&server)
        .await;

    let err = request_faucet(&server.uri(), &kat_wallet(), 114_514)
        .await
        .unwrap_err();
    match err {
        ClientError::ProtocolError { code, msg } => {
            assert_eq!(code, 429);
            assert!(msg.contains("already funded"), "got: {msg}");
        }
        other => panic!("expected ProtocolError, got {other:?}"),
    }
}
