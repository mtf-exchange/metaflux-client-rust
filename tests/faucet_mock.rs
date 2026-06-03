//! Mock-server tests for the devnet / testnet faucet helper.
//!
//! Spin up a `wiremock::MockServer` (a stand-in for the faucet's OWN origin —
//! NOT the trading API), register `POST /faucet` responses, and assert
//! [`request_faucet`] decodes the success body and maps the `429` rate-limit
//! error envelope into a [`ClientError::ProtocolError`].

use metaflux_client::{ClientError, FaucetResponse, request_faucet};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn faucet_decodes_queued_success() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/faucet"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "address": "0x000000000000000000000000000000000000beef",
            "usdc": 1000,
            "mtf": 10,
            "status": "queued"
        })))
        .mount(&server)
        .await;

    let res = request_faucet(
        &server.uri(),
        "0x000000000000000000000000000000000000beef",
        Some(1000),
    )
    .await
    .unwrap();
    assert_eq!(
        res,
        FaucetResponse {
            address: "0x000000000000000000000000000000000000beef".into(),
            usdc: 1000,
            mtf: 10,
            status: "queued".into(),
        }
    );
}

#[tokio::test]
async fn faucet_omits_amount_when_none() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/faucet"))
        // Body must carry `address` but NOT `amount` when the caller passes None.
        .and(wiremock::matchers::body_json(json!({
            "address": "0x000000000000000000000000000000000000beef"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "address": "0x000000000000000000000000000000000000beef",
            "usdc": 10000,
            "mtf": 10,
            "status": "queued"
        })))
        .mount(&server)
        .await;

    let res = request_faucet(
        &server.uri(),
        "0x000000000000000000000000000000000000beef",
        None,
    )
    .await
    .unwrap();
    assert_eq!(res.usdc, 10000);
    assert_eq!(res.mtf, 10);
    assert_eq!(res.status, "queued");
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

    let err = request_faucet(
        &server.uri(),
        "0x000000000000000000000000000000000000beef",
        None,
    )
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
