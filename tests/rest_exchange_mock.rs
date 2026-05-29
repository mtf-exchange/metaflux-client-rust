//! Mock-server tests for `/exchange`.
//!
//! Confirms:
//! 1. The SDK posts a `{ action, nonce, signature }` envelope.
//! 2. The signature included is exactly the EIP-712 signature the SDK
//!    computes for the same `(action, nonce)` digest — recovered signer
//!    must equal the wallet address.
//! 3. The mock's typed response decodes through `OrderResponse`.

use metaflux_client::{
    Client,
    rest::exchange::{_action_digest_for_test, _recover_for_test},
    types::{
        MarketId, OrderId,
        order::{CancelOrder, Order, OrderKind, Side, StpMode, TimeInForce},
    },
    wallet::Wallet,
};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::Mutex;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// Mock responder that captures the last request body so the test can
/// assert signature correctness.
#[derive(Clone, Default)]
struct CapturingResponder {
    last: Arc<Mutex<Option<Value>>>,
    response: Value,
}

impl Respond for CapturingResponder {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let body: Value =
            serde_json::from_slice(&req.body).expect("mock should receive valid JSON");
        let last = self.last.clone();
        // Sync lock blocking would deadlock if the runtime is single-threaded;
        // wiremock requires a sync respond. Use try_lock + fallback.
        if let Ok(mut g) = last.try_lock() {
            *g = Some(body);
        }
        ResponseTemplate::new(200).set_body_json(self.response.clone())
    }
}

fn sample_wallet() -> Wallet {
    // Distinct from the wallet_eip712 vectors so tests don't share state.
    Wallet::from_hex("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899").unwrap()
}

#[tokio::test]
async fn submit_order_envelope_includes_valid_signature() {
    let server = MockServer::start().await;
    let captor = CapturingResponder {
        last: Arc::new(Mutex::new(None)),
        response: json!({
            "oid": 1234,
            "status": "accepted",
            "filled_size": 0,
            "avg_px": 0
        }),
    };
    Mock::given(method("POST"))
        .and(path("/exchange"))
        .respond_with(captor.clone())
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let wallet = sample_wallet();
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
    };
    let resp = client
        .exchange()
        .submit_order(&wallet, &order)
        .await
        .unwrap();
    assert_eq!(resp.oid.0, 1234);
    assert_eq!(resp.status, "accepted");

    // Recover the body the SDK posted.
    let captured = captor.last.lock().await.clone().expect("body captured");
    let action = captured.get("action").expect("envelope has action").clone();
    let nonce = captured
        .get("nonce")
        .and_then(Value::as_u64)
        .expect("envelope has nonce");
    let sig_hex = captured
        .get("signature")
        .and_then(Value::as_str)
        .expect("envelope has signature");

    // Confirm the action is the typed submit_order shape.
    assert_eq!(
        action.get("type").and_then(Value::as_str),
        Some("submit_order")
    );
    assert!(action.get("order").is_some());

    // Reproduce the same EIP-712 digest and recover the signer.
    let digest = _action_digest_for_test(&action, nonce);
    let sig = decode_sig(sig_hex);
    let recovered = _recover_for_test(&digest, &sig).expect("recover");
    assert_eq!(
        recovered,
        wallet.address(),
        "recovered signer must equal the wallet address"
    );
}

#[tokio::test]
async fn cancel_order_round_trips_through_exchange() {
    let server = MockServer::start().await;
    let captor = CapturingResponder {
        last: Arc::new(Mutex::new(None)),
        response: json!({ "cancelled": true }),
    };
    Mock::given(method("POST"))
        .and(path("/exchange"))
        .respond_with(captor.clone())
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let wallet = sample_wallet();
    let cancel = CancelOrder {
        owner: wallet.address(),
        market: MarketId(1),
        oid: Some(OrderId(1234)),
        cloid: None,
    };
    let resp = client
        .exchange()
        .cancel_order(&wallet, &cancel)
        .await
        .unwrap();
    assert_eq!(resp["cancelled"], true);

    // Sanity check on the signature path.
    let body = captor.last.lock().await.clone().expect("body captured");
    let action = body["action"].clone();
    let nonce = body["nonce"].as_u64().unwrap();
    let sig_hex = body["signature"].as_str().unwrap();
    assert_eq!(action["type"].as_str(), Some("cancel_order"));
    let digest = _action_digest_for_test(&action, nonce);
    let sig = decode_sig(sig_hex);
    let recovered = _recover_for_test(&digest, &sig).expect("recover");
    assert_eq!(recovered, wallet.address());
}

#[tokio::test]
async fn submit_order_rejects_mismatched_owner_locally() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/exchange"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let wallet = sample_wallet();
    let other =
        Wallet::from_hex("1111111111111111111111111111111111111111111111111111111111111111")
            .unwrap();
    let order = Order {
        owner: other.address(),
        market: MarketId(1),
        side: Side::Bid,
        kind: OrderKind::Limit,
        size: 1,
        limit_px: 1,
        tif: TimeInForce::Gtc,
        stp_mode: StpMode::CancelOldest,
        reduce_only: false,
        cloid: None,
    };
    let err = client
        .exchange()
        .submit_order(&wallet, &order)
        .await
        .unwrap_err();
    assert!(matches!(err, metaflux_client::ClientError::Validation(_)));
}

fn decode_sig(hex_str: &str) -> metaflux_client::wallet::Signature {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(stripped).unwrap();
    assert_eq!(bytes.len(), 65);
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&bytes[..32]);
    s.copy_from_slice(&bytes[32..64]);
    metaflux_client::wallet::Signature { r, s, v: bytes[64] }
}
