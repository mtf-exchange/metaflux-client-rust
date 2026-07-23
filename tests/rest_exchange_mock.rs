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
    rest::exchange::{_action_digest_for_test, _recover_for_test, MTF_CHAIN_ID},
    rest::exchange_typed::{_typed_digest_for_test, _typed_trade_digest_for_test},
    types::{
        Cloid, MarketId, OrderId,
        account::UpdateLeverage,
        chase::{CancelChaseParams, ChaseParams},
        order::{
            BatchCancel, BatchModify, BatchOrder, CancelByCloid, CancelOrder, Modify, Order,
            OrderKind, OrderStatus, PositionSide, Side, StpMode, TimeInForce,
        },
        spot::{EarnWithdraw, SpotMarginOpen},
        vault::{CreateVault, VaultKind},
    },
    wallet::{
        Address, TypedAction, TypedTradingAction, TypedTradingDigest, Wallet, metaflux_chain_tag,
    },
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
    assert!(
        body.get("sig_scheme").is_none(),
        "vestigial sig_scheme must not be sent"
    );
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

#[tokio::test]
async fn cancel_all_orders_as_carries_owner_and_signs_owner_form() {
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
    // The signing wallet is the AGENT; `owner` is a DISTINCT account whose
    // orders are being cancelled (operator / vault trading).
    let agent = sample_wallet();
    let owner =
        Wallet::from_hex("1111111111111111111111111111111111111111111111111111111111111111")
            .unwrap()
            .address();

    let resp: Value = client
        .exchange()
        .cancel_all_orders_as(&agent, owner, Some(7))
        .await
        .unwrap();
    assert_eq!(resp["accepted"], true);

    let body = captor.last.lock().await.clone().expect("body captured");
    let action = body["action"].clone();
    assert_eq!(action["type"].as_str(), Some("cancel_all_orders"));
    assert_eq!(action["params"]["asset"], json!(7));
    // (1) The wire carries the agent-resolved owner as a `0x`-hex field so the
    // node's NativeCancelAllOrders.owner is set.
    let owner_str = action["params"]["owner"]
        .as_str()
        .expect("params.owner is a string");
    assert!(owner_str.starts_with("0x"), "owner must be 0x-hex");
    assert_eq!(action["params"]["owner"], json!(owner));

    // (2) The signature is over the OWNER-FORM typed digest, recovered to the
    // AGENT signer (NOT the owner).
    let nonce = body["nonce"].as_u64().unwrap();
    let reconstructed = TypedAction::CancelAllOrders {
        metaflux_chain: metaflux_chain_tag(MTF_CHAIN_ID).to_string(),
        owner: Some(owner),
        has_asset: true,
        asset: 7,
        nonce,
    };
    let digest = _typed_digest_for_test(&reconstructed);
    let sig = decode_sig(body["signature"].as_str().unwrap());
    assert_eq!(_recover_for_test(&digest, &sig).unwrap(), agent.address());

    // Guard: the vestigial sig_scheme field must not be reintroduced.
    assert!(
        body.get("sig_scheme").is_none(),
        "sig_scheme must not be sent"
    );
}

/// The agent-resolved owner (a DISTINCT account whose orders are managed) used
/// by the owner-bound `*_as` tests. Differs from `sample_wallet` (the agent).
fn vault_owner() -> Address {
    Wallet::from_hex("1111111111111111111111111111111111111111111111111111111111111111")
        .unwrap()
        .address()
}

/// Assert the captured `/exchange` body for an owner-bound `*_as` call: the wire
/// carries a params-level `0x`-hex `owner`, and the signature is over the
/// OWNER-FORM (`*_WITH_OWNER`) typed digest, recovering to the AGENT signer.
fn assert_owner_bound(
    body: &Value,
    ty: &str,
    owner: Address,
    agent: &Wallet,
    typed: TypedTradingAction,
) {
    let action = body["action"].clone();
    assert_eq!(action["type"].as_str(), Some(ty));
    // (1) params-level owner is present, 0x-hex, and equals the vault.
    let owner_str = action["params"]["owner"]
        .as_str()
        .expect("params.owner is a string");
    assert!(owner_str.starts_with("0x"), "owner must be 0x-hex");
    assert_eq!(action["params"]["owner"], json!(owner));
    // (2) signature is over the owner-BOUND typed digest, recovered to the AGENT.
    let nonce = body["nonce"].as_u64().unwrap();
    let digest = TypedTradingDigest::new_with_owner(typed, owner, MTF_CHAIN_ID, nonce)
        .digest()
        .unwrap();
    let sig = decode_sig(body["signature"].as_str().unwrap());
    assert_eq!(_recover_for_test(&digest, &sig).unwrap(), agent.address());
    // Guard: the vestigial sig_scheme field must not be reintroduced.
    assert!(
        body.get("sig_scheme").is_none(),
        "sig_scheme must not be sent"
    );
}

/// Spin up a capturing `/exchange` mock, returning `(client, captor, agent)`.
async fn capturing_exchange() -> (Client, CapturingResponder, Wallet) {
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
    // Leak the server so it outlives this fn (the client holds only the uri).
    let client = Client::new(server.uri()).unwrap();
    std::mem::forget(server);
    (client, captor, sample_wallet())
}

#[tokio::test]
async fn batch_cancel_as_carries_owner_and_signs_owner_form() {
    let (client, captor, agent) = capturing_exchange().await;
    let owner = vault_owner();
    // Each cancel's owner is the VAULT (distinct from the signing agent) — the
    // `_as` path has NO owner == signer guard.
    let batch = BatchCancel {
        cancels: vec![
            CancelOrder {
                owner,
                market: MarketId(1),
                oid: Some(OrderId(1234)),
                cloid: None,
            },
            CancelOrder {
                owner,
                market: MarketId(2),
                oid: Some(OrderId(5678)),
                cloid: None,
            },
        ],
    };
    let _: Value = client
        .exchange()
        .batch_cancel_as(&agent, owner, &batch)
        .await
        .unwrap();
    let body = captor.last.lock().await.clone().expect("body captured");
    assert_owner_bound(
        &body,
        "batch_cancel",
        owner,
        &agent,
        TypedTradingAction::BatchCancel(&batch),
    );
}

#[tokio::test]
async fn batch_modify_as_carries_owner_and_signs_owner_form() {
    let (client, captor, agent) = capturing_exchange().await;
    let owner = vault_owner();
    let params = BatchModify {
        modifications: vec![Modify {
            market: MarketId(1),
            oid: OrderId(1234),
            new_px: Some(6_900_000_000_000),
            new_size: Some(200),
        }],
    };
    let _: Value = client
        .exchange()
        .batch_modify_as(&agent, owner, &params)
        .await
        .unwrap();
    let body = captor.last.lock().await.clone().expect("body captured");
    assert_owner_bound(
        &body,
        "batch_modify",
        owner,
        &agent,
        TypedTradingAction::BatchModify(&params),
    );
}

#[tokio::test]
async fn modify_as_carries_owner_and_signs_owner_form() {
    let (client, captor, agent) = capturing_exchange().await;
    let owner = vault_owner();
    let params = Modify {
        market: MarketId(1),
        oid: OrderId(1234),
        new_px: Some(6_900_000_000_000),
        new_size: Some(200),
    };
    let _: Value = client
        .exchange()
        .modify_as(&agent, owner, &params)
        .await
        .unwrap();
    let body = captor.last.lock().await.clone().expect("body captured");
    assert_owner_bound(
        &body,
        "modify",
        owner,
        &agent,
        TypedTradingAction::Modify(&params),
    );
}

#[tokio::test]
async fn cancel_by_cloid_as_carries_owner_and_signs_owner_form() {
    let (client, captor, agent) = capturing_exchange().await;
    let owner = vault_owner();
    let params = CancelByCloid {
        asset: MarketId(1),
        cloid: Cloid([0xAB; 16]),
    };
    let _: Value = client
        .exchange()
        .cancel_by_cloid_as(&agent, owner, &params)
        .await
        .unwrap();
    let body = captor.last.lock().await.clone().expect("body captured");
    assert_owner_bound(
        &body,
        "cancel_by_cloid",
        owner,
        &agent,
        TypedTradingAction::CancelByCloid(&params),
    );
}

/// Canonical [`ChaseParams`] for the mock tests (self-owned, one-way, cloid set).
fn chase_params() -> ChaseParams {
    ChaseParams {
        market: MarketId(3),
        side: Side::Bid,
        size: 4_000_000_000,
        cloid: Some(Cloid([0xCD; 16])),
        stp_mode: StpMode::CancelOldest,
        position_side: None,
        interval_blocks: 4,
        ttl_ms: 3_600_000,
        max_reprices: 500,
        owner: None,
    }
}

/// `chase_order` (self-owned) posts the compact `{type,params}` wire shape and
/// the signature recovers to the wallet over the OWNER-LESS ChaseOrder digest.
#[tokio::test]
async fn chase_order_envelope_signs_and_recovers() {
    let (client, captor, wallet) = capturing_exchange().await;
    let params = chase_params();
    let _: Value = client
        .exchange()
        .chase_order(&wallet, &params)
        .await
        .unwrap();

    let body = captor.last.lock().await.clone().expect("body captured");
    let action = body["action"].clone();
    assert_eq!(action["type"].as_str(), Some("chase_order"));
    // Compact snake_case params ride the wire; sizes / ids are plain integers.
    assert_eq!(action["params"]["market"], json!(3));
    assert_eq!(action["params"]["side"], json!("bid"));
    assert_eq!(action["params"]["size"], json!(4_000_000_000u64));
    assert_eq!(action["params"]["stp_mode"], json!("cancel_oldest"));
    assert_eq!(action["params"]["interval_blocks"], json!(4));
    assert_eq!(action["params"]["ttl_ms"], json!(3_600_000u64));
    assert_eq!(action["params"]["max_reprices"], json!(500));
    assert_eq!(
        action["params"]["cloid"],
        json!("0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd")
    );
    // one-way + self-owned: the optional fields are omitted from the wire.
    assert!(action["params"].get("position_side").is_none());
    assert!(action["params"].get("owner").is_none());

    // The signature is over the OWNER-LESS ChaseOrder typed digest, recovering
    // the wallet.
    let nonce = body["nonce"].as_u64().unwrap();
    let digest = _typed_trade_digest_for_test(TypedTradingAction::ChaseOrder(&params), nonce);
    let sig = decode_sig(body["signature"].as_str().unwrap());
    assert_eq!(_recover_for_test(&digest, &sig).unwrap(), wallet.address());
    assert!(
        body.get("sig_scheme").is_none(),
        "sig_scheme must not be sent"
    );
}

/// A hedge-account chase carries `position_side` on the wire and still recovers.
#[tokio::test]
async fn chase_order_hedge_carries_position_side() {
    let (client, captor, wallet) = capturing_exchange().await;
    let params = ChaseParams {
        position_side: Some(PositionSide::Short),
        ..chase_params()
    };
    let _: Value = client
        .exchange()
        .chase_order(&wallet, &params)
        .await
        .unwrap();
    let body = captor.last.lock().await.clone().expect("body captured");
    assert_eq!(body["action"]["params"]["position_side"], json!("short"));
    let nonce = body["nonce"].as_u64().unwrap();
    let digest = _typed_trade_digest_for_test(TypedTradingAction::ChaseOrder(&params), nonce);
    let sig = decode_sig(body["signature"].as_str().unwrap());
    assert_eq!(_recover_for_test(&digest, &sig).unwrap(), wallet.address());
}

/// `cancel_chase` (self-owned) posts `{market, chase_oid}` and recovers.
#[tokio::test]
async fn cancel_chase_envelope_signs_and_recovers() {
    let (client, captor, wallet) = capturing_exchange().await;
    let params = CancelChaseParams {
        market: MarketId(3),
        chase_oid: 12345,
        owner: None,
    };
    let _: Value = client
        .exchange()
        .cancel_chase(&wallet, &params)
        .await
        .unwrap();
    let body = captor.last.lock().await.clone().expect("body captured");
    let action = body["action"].clone();
    assert_eq!(action["type"].as_str(), Some("cancel_chase"));
    assert_eq!(action["params"]["market"], json!(3));
    assert_eq!(action["params"]["chase_oid"], json!(12345));
    assert!(action["params"].get("owner").is_none());

    let nonce = body["nonce"].as_u64().unwrap();
    let digest = _typed_trade_digest_for_test(TypedTradingAction::CancelChase(&params), nonce);
    let sig = decode_sig(body["signature"].as_str().unwrap());
    assert_eq!(_recover_for_test(&digest, &sig).unwrap(), wallet.address());
}

/// `chase_order_as` carries a params-level `0x`-hex owner and signs the
/// OWNER-FORM digest, recovering to the AGENT.
#[tokio::test]
async fn chase_order_as_carries_owner_and_signs_owner_form() {
    let (client, captor, agent) = capturing_exchange().await;
    let owner = vault_owner();
    let params = chase_params();
    let _: Value = client
        .exchange()
        .chase_order_as(&agent, owner, &params)
        .await
        .unwrap();
    let body = captor.last.lock().await.clone().expect("body captured");
    assert_owner_bound(
        &body,
        "chase_order",
        owner,
        &agent,
        TypedTradingAction::ChaseOrder(&params),
    );
}

/// `cancel_chase_as` carries a params-level owner and signs the OWNER-FORM digest.
#[tokio::test]
async fn cancel_chase_as_carries_owner_and_signs_owner_form() {
    let (client, captor, agent) = capturing_exchange().await;
    let owner = vault_owner();
    let params = CancelChaseParams {
        market: MarketId(3),
        chase_oid: 12345,
        owner: None,
    };
    let _: Value = client
        .exchange()
        .cancel_chase_as(&agent, owner, &params)
        .await
        .unwrap();
    let body = captor.last.lock().await.clone().expect("body captured");
    assert_owner_bound(
        &body,
        "cancel_chase",
        owner,
        &agent,
        TypedTradingAction::CancelChase(&params),
    );
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
