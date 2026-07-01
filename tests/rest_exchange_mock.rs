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
    rest::exchange_typed::_typed_trade_digest_for_test,
    types::{
        MarketId, OrderId,
        account::UpdateLeverage,
        order::{
            BatchOrder, CancelOrder, Order, OrderKind, OrderStatus, Side, StpMode, TimeInForce,
        },
        spot::{EarnWithdraw, SpotMarginOpen},
        vault::{CreateVault, VaultKind},
    },
    wallet::{TypedTradingAction, Wallet},
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
    // The /exchange order path returns the ExchangeResponse body DIRECTLY (NOT
    // the `{type,data}` envelope — that is the /info read contract): the per-order
    // status union is a top-level `statuses` array. One resting order here.
    let captor = CapturingResponder {
        last: Arc::new(Mutex::new(None)),
        response: json!({
            "statuses": [
                { "resting": { "oid": 1234, "cloid": "0x000102030405060708090a0b0c0d0e0f" } }
            ]
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
        builder: None,
        position_side: None,
        trigger: None,
    };
    let resp = client
        .exchange()
        .submit_order(&wallet, &order)
        .await
        .unwrap();
    // Response decodes through the per-order status union and the envelope is
    // peeled (the `data` array becomes the transparent OrderResponse vec).
    assert_eq!(resp.statuses.len(), 1);
    match resp.first().expect("one status") {
        OrderStatus::Resting(r) => assert_eq!(r.oid, OrderId(1234)),
        other => panic!("expected resting status, got {other:?}"),
    }
    assert_eq!(resp.first().and_then(OrderStatus::oid), Some(OrderId(1234)));

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

    // Confirm the action is the typed submit_order shape, signed under the
    // typed scheme (the node no longer admits orders under the opaque envelope).
    assert_eq!(
        action.get("type").and_then(Value::as_str),
        Some("submit_order")
    );
    assert!(action.get("order").is_some());
    assert!(
        captured.get("sig_scheme").is_none(),
        "the vestigial sig_scheme field must no longer be sent"
    );

    // Reproduce the typed trading digest and recover the signer.
    let digest = _typed_trade_digest_for_test(TypedTradingAction::SubmitOrder(&order), nonce);
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
    assert!(body.get("sig_scheme").is_none(), "vestigial sig_scheme must not be sent");
    let digest = _typed_trade_digest_for_test(TypedTradingAction::CancelOrder(&cancel), nonce);
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
        builder: None,
        position_side: None,
        trigger: None,
    };
    let err = client
        .exchange()
        .submit_order(&wallet, &order)
        .await
        .unwrap_err();
    assert!(matches!(err, metaflux_client::ClientError::Validation(_)));
}

#[tokio::test]
async fn spot_margin_open_posts_signed_sender_authorized_envelope() {
    let server = MockServer::start().await;
    // Non-order actions get the 202 admission envelope, not a synchronous oid.
    let captor = CapturingResponder {
        last: Arc::new(Mutex::new(None)),
        response: json!({ "accepted": true, "action_hash": "0xabc", "mempool_depth": 1 }),
    };
    Mock::given(method("POST"))
        .and(path("/exchange"))
        .respond_with(captor.clone())
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let wallet = sample_wallet();
    let open = SpotMarginOpen {
        pair: 200,
        size: 200,
        limit_px: 200_000_000,
        borrow: "400".into(),
    };
    let resp: Value = client
        .exchange()
        .spot_margin_open(&wallet, &open)
        .await
        .unwrap();
    assert_eq!(resp["accepted"], true);

    // Confirm the action shape: sender-authorized params body, decimal-string
    // borrow, integer-plane size / limit_px, no owner field.
    let body = captor.last.lock().await.clone().expect("body captured");
    let action = body["action"].clone();
    assert_eq!(action["type"].as_str(), Some("spot_margin_open"));
    let p = &action["params"];
    assert_eq!(p["pair"], json!(200));
    assert_eq!(p["size"], json!(200));
    assert_eq!(p["limit_px"], json!(200_000_000));
    assert_eq!(p["borrow"], json!("400"));
    assert!(p["borrow"].is_string(), "borrow must ride as a JSON string");
    assert!(
        action.get("owner").is_none(),
        "sender-authorized: no owner field"
    );

    // The signature recovers to the wallet (the actor is the signer).
    let nonce = body["nonce"].as_u64().unwrap();
    let sig_hex = body["signature"].as_str().unwrap();
    let digest = _action_digest_for_test(&action, nonce);
    let sig = decode_sig(sig_hex);
    let recovered = _recover_for_test(&digest, &sig).expect("recover");
    assert_eq!(recovered, wallet.address());
}

#[tokio::test]
async fn earn_withdraw_keeps_fractional_shares_as_string() {
    let server = MockServer::start().await;
    let captor = CapturingResponder {
        last: Arc::new(Mutex::new(None)),
        response: json!({ "accepted": true }),
    };
    Mock::given(method("POST"))
        .and(path("/exchange"))
        .respond_with(captor.clone())
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let wallet = sample_wallet();
    let wd = EarnWithdraw {
        asset: 100,
        shares: "1234.5".into(),
    };
    let resp: Value = client.exchange().earn_withdraw(&wallet, &wd).await.unwrap();
    assert_eq!(resp["accepted"], true);

    let body = captor.last.lock().await.clone().expect("body captured");
    let action = body["action"].clone();
    assert_eq!(action["type"].as_str(), Some("earn_withdraw"));
    assert_eq!(action["params"]["asset"], json!(100));
    assert_eq!(action["params"]["shares"], json!("1234.5"));
    assert!(
        action["params"]["shares"].is_string(),
        "fractional shares must survive as a decimal string"
    );

    let nonce = body["nonce"].as_u64().unwrap();
    let digest = _action_digest_for_test(&action, nonce);
    let sig = decode_sig(body["signature"].as_str().unwrap());
    let recovered = _recover_for_test(&digest, &sig).expect("recover");
    assert_eq!(recovered, wallet.address());
}

#[tokio::test]
async fn update_leverage_posts_sender_authorized_envelope() {
    let server = MockServer::start().await;
    let captor = CapturingResponder {
        last: Arc::new(Mutex::new(None)),
        response: json!({ "accepted": true }),
    };
    Mock::given(method("POST"))
        .and(path("/exchange"))
        .respond_with(captor.clone())
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let wallet = sample_wallet();
    let params = UpdateLeverage {
        asset: MarketId(2),
        leverage: 10,
        is_isolated: false,
    };
    let resp: Value = client
        .exchange()
        .update_leverage(&wallet, &params)
        .await
        .unwrap();
    assert_eq!(resp["accepted"], true);

    let body = captor.last.lock().await.clone().expect("body captured");
    let action = body["action"].clone();
    assert_eq!(action["type"].as_str(), Some("update_leverage"));
    let p = &action["params"];
    assert_eq!(p["asset"], json!(2));
    assert_eq!(p["leverage"], json!(10));
    assert_eq!(p["is_isolated"], json!(false));
    assert!(
        action.get("owner").is_none(),
        "sender-authorized: no owner field"
    );

    let nonce = body["nonce"].as_u64().unwrap();
    let digest = _action_digest_for_test(&action, nonce);
    let sig = decode_sig(body["signature"].as_str().unwrap());
    assert_eq!(_recover_for_test(&digest, &sig).unwrap(), wallet.address());
}

#[tokio::test]
async fn create_vault_posts_signed_params_envelope() {
    let server = MockServer::start().await;
    let captor = CapturingResponder {
        last: Arc::new(Mutex::new(None)),
        response: json!({ "accepted": true }),
    };
    Mock::given(method("POST"))
        .and(path("/exchange"))
        .respond_with(captor.clone())
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let wallet = sample_wallet();
    let create = CreateVault {
        name: "v".into(),
        lock_period_secs: 345_600,
        parent: None,
        kind: VaultKind::User,
    };
    let resp: Value = client
        .exchange()
        .create_vault(&wallet, &create)
        .await
        .unwrap();
    assert_eq!(resp["accepted"], true);

    let body = captor.last.lock().await.clone().expect("body captured");
    let action = body["action"].clone();
    assert_eq!(action["type"].as_str(), Some("create_vault"));
    assert_eq!(action["params"]["name"], json!("v"));
    assert_eq!(action["params"]["kind"], json!("User"));
    assert!(
        action["params"].get("parent").is_none(),
        "None parent omitted"
    );

    let nonce = body["nonce"].as_u64().unwrap();
    let digest = _action_digest_for_test(&action, nonce);
    let sig = decode_sig(body["signature"].as_str().unwrap());
    assert_eq!(_recover_for_test(&digest, &sig).unwrap(), wallet.address());
}

#[tokio::test]
async fn batch_order_accepts_params_level_owner() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/exchange"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let wallet = sample_wallet();
    let vault =
        Wallet::from_hex("1111111111111111111111111111111111111111111111111111111111111111")
            .unwrap();
    let mk = |owner| Order {
        owner,
        market: MarketId(1),
        side: Side::Bid,
        kind: OrderKind::Limit,
        size: 1,
        limit_px: 1,
        tif: TimeInForce::Gtc,
        stp_mode: StpMode::CancelOldest,
        reduce_only: false,
        cloid: None,
        builder: None,
        position_side: None,
        trigger: None,
    };
    // The params-level owner is a VAULT distinct from the signer (operator
    // trading). The SDK no longer enforces owner == signer — the node authorizes
    // the registered operator — so batch_order posts instead of rejecting locally.
    let batch = BatchOrder {
        owner: vault.address(),
        orders: vec![mk(vault.address())],
        grouping: Default::default(),
    };
    client
        .exchange()
        .batch_order(&wallet, &batch)
        .await
        .unwrap();
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
