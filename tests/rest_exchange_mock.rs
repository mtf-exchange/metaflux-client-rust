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
    rest::exchange::{_recover_for_test, MTF_CHAIN_ID},
    rest::exchange_typed::{_typed_digest_for_test, _typed_trade_digest_for_test},
    types::{
        Cloid, MarketId, OrderId, VaultId,
        account::{ApproveBrokerFee, UpdateLeverage},
        chase::{CancelChaseParams, ChaseParams},
        defi::{BorrowLend, BorrowLendKind},
        order::{
            BatchCancel, BatchModify, BatchOrder, CancelByCloid, CancelOrder, Modify, Order,
            OrderKind, OrderStatus, PositionSide, Side, StpMode, TimeInForce,
        },
        perp::{
            Mip3SetOraclePx, PerpActivateMarket, PerpDeactivateMarket, PerpRegisterAsset,
            PerpSetFeeTier, PerpSetLeverage, PerpSetMakerRebate, PerpSetMinSize, PerpSetOracle,
            PerpSetSubDeployers,
        },
        spot::{
            EarnWithdraw, SpotFinalizeSupply, SpotMarginOpen, SpotRegisterPair, SpotRegisterToken,
            SpotSeedHolders, SpotSetPairActive, SpotSetPairParams,
        },
        vault::{CreateVault, RegisterMetaliquidityOperator, VaultKind},
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
        // The node wraps every success payload under `data`.
        ResponseTemplate::new(200).set_body_json(json!({ "data": self.response }))
    }
}

fn sample_wallet() -> Wallet {
    // Distinct from the wallet_eip712 vectors so tests don't share state.
    Wallet::from_hex("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899").unwrap()
}

#[tokio::test]
async fn submit_order_envelope_includes_valid_signature() {
    let server = MockServer::start().await;
    // The /exchange order path answers the shared envelope, so the per-order
    // status union sits at `data.statuses`. The responder wraps `response` in
    // `data`. One resting order here.
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

/// The vault-operator lane: the operator holds the key, the VAULT owns the
/// order. The SDK used to recover the signer and reject the mismatch, which made
/// the lane unreachable. The node authorizes the signer — the account itself, an
/// approved agent, or a registered metaliquidity operator — so the order must go
/// out on the wire carrying the OTHER account's address.
#[tokio::test]
async fn submit_order_sends_an_order_whose_owner_is_not_the_signer() {
    let server = MockServer::start().await;
    let captor = CapturingResponder {
        last: Arc::new(Mutex::new(None)),
        response: json!({ "statuses": [] }),
    };
    Mock::given(method("POST"))
        .and(path("/exchange"))
        .respond_with(captor.clone())
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
    client
        .exchange()
        .submit_order(&wallet, &order)
        .await
        .expect("an order owned by another account must reach the node");
    let body = captor.last.lock().await.clone().expect("a request body");
    assert_eq!(
        body["action"]["order"]["owner"],
        json!(format!("{}", other.address())),
        "the wire must carry the OWNER, not the signer"
    );
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

    // The redirect signs the TYPED SpotMarginOpen digest, recovering the wallet.
    let nonce = body["nonce"].as_u64().unwrap();
    let sig_hex = body["signature"].as_str().unwrap();
    let reconstructed = TypedAction::SpotMarginOpen {
        metaflux_chain: metaflux_chain_tag(MTF_CHAIN_ID).to_string(),
        pair: 200,
        size: 200,
        limit_px: 200_000_000,
        borrow: "400".into(),
        nonce,
    };
    let digest = _typed_digest_for_test(&reconstructed);
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
    let reconstructed = TypedAction::EarnWithdraw {
        metaflux_chain: metaflux_chain_tag(MTF_CHAIN_ID).to_string(),
        asset: 100,
        shares: "1234.5".into(),
        nonce,
    };
    let digest = _typed_digest_for_test(&reconstructed);
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
    let reconstructed = TypedAction::UpdateLeverage {
        metaflux_chain: metaflux_chain_tag(MTF_CHAIN_ID).to_string(),
        asset: 2,
        leverage: 10,
        is_isolated: false,
        nonce,
    };
    let digest = _typed_digest_for_test(&reconstructed);
    let sig = decode_sig(body["signature"].as_str().unwrap());
    assert_eq!(_recover_for_test(&digest, &sig).unwrap(), wallet.address());
}

/// The action tag moved to `approve_broker_fee`; the EIP-712 type string stays
/// `ApproveBuilderFee`. The recovery below proves the digest did not move with
/// the tag.
#[tokio::test]
async fn approve_broker_fee_posts_the_broker_tag_under_the_old_typed_digest() {
    let (client, captor, wallet) = capturing_exchange().await;
    let broker = Address([0x20; 20]);
    let params = ApproveBrokerFee {
        builder: broker,
        max_bps: 7,
    };
    let resp: Value = client
        .exchange()
        .approve_broker_fee(&wallet, &params)
        .await
        .unwrap();
    assert_eq!(resp["accepted"], true);

    let body = captor.last.lock().await.clone().expect("body captured");
    let action = body["action"].clone();
    assert_eq!(action["type"].as_str(), Some("approve_broker_fee"));
    assert_eq!(action["params"]["max_bps"], json!(7));
    assert!(
        action["params"].get("builder").is_some(),
        "the wire key stays `builder`"
    );

    let nonce = body["nonce"].as_u64().unwrap();
    let reconstructed = TypedAction::ApproveBuilderFee {
        metaflux_chain: metaflux_chain_tag(MTF_CHAIN_ID).to_string(),
        builder: broker,
        max_fee_bps: 7,
        nonce,
    };
    let digest = _typed_digest_for_test(&reconstructed);
    let sig = decode_sig(body["signature"].as_str().unwrap());
    assert_eq!(_recover_for_test(&digest, &sig).unwrap(), wallet.address());
}

/// The old method name must keep compiling and must emit the SAME new tag.
#[tokio::test]
async fn the_old_approve_builder_fee_method_emits_the_new_tag() {
    let (client, captor, wallet) = capturing_exchange().await;
    let _: Value = client
        .exchange()
        .approve_builder_fee_typed(&wallet, Address([0x20; 20]), 7)
        .await
        .unwrap();
    let body = captor.last.lock().await.clone().expect("body captured");
    assert_eq!(body["action"]["type"].as_str(), Some("approve_broker_fee"));
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
    let reconstructed = TypedAction::CreateVault {
        metaflux_chain: metaflux_chain_tag(MTF_CHAIN_ID).to_string(),
        name: "v".into(),
        lock_period_secs: 345_600,
        kind: 0,
        nonce,
    };
    let digest = _typed_digest_for_test(&reconstructed);
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
/// OWNER-FORM digest, recovering to the AGENT. The owner rides on the params,
/// so the POSTed body and the digest read the SAME value.
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
    let owned = ChaseParams {
        owner: Some(owner),
        ..params
    };
    assert_owner_bound(
        &body,
        "chase_order",
        owner,
        &agent,
        TypedTradingAction::ChaseOrder(&owned),
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
    let owned = CancelChaseParams {
        owner: Some(owner),
        ..params
    };
    assert_owner_bound(
        &body,
        "cancel_chase",
        owner,
        &agent,
        TypedTradingAction::CancelChase(&owned),
    );
}

/// Redirect equivalence: a redirected plain method emits the SAME wire `action`
/// object (`type` + `params`) as its typed twin. The nonce / signature differ
/// per call, so this compares the nonce-independent `action` object.
#[tokio::test]
async fn redirect_emits_same_action_as_typed_twin() {
    let (client, captor, wallet) = capturing_exchange().await;

    // update_leverage (plain, `&UpdateLeverage`) vs update_leverage_typed.
    let params = UpdateLeverage {
        asset: MarketId(2),
        leverage: 10,
        is_isolated: true,
    };
    let _: Value = client
        .exchange()
        .update_leverage(&wallet, &params)
        .await
        .unwrap();
    let plain = captor.last.lock().await.clone().unwrap()["action"].clone();
    let _: Value = client
        .exchange()
        .update_leverage_typed(&wallet, 2, 10, true)
        .await
        .unwrap();
    let typed = captor.last.lock().await.clone().unwrap()["action"].clone();
    assert_eq!(
        plain, typed,
        "update_leverage redirect must emit the typed twin's action"
    );

    // earn_withdraw (plain, `&EarnWithdraw`) vs earn_withdraw_typed.
    let wd = EarnWithdraw {
        asset: 100,
        shares: "1234.5".into(),
    };
    let _: Value = client.exchange().earn_withdraw(&wallet, &wd).await.unwrap();
    let plain = captor.last.lock().await.clone().unwrap()["action"].clone();
    let _: Value = client
        .exchange()
        .earn_withdraw_typed(&wallet, 100, "1234.5")
        .await
        .unwrap();
    let typed = captor.last.lock().await.clone().unwrap()["action"].clone();
    assert_eq!(
        plain, typed,
        "earn_withdraw redirect must emit the typed twin's action"
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

// ---- BOLE pool, vault operators, and the spot deployer lane ----

/// `kind` has TWO spellings: the POST carries the PascalCase name, the digest
/// signs the `uint8`. A client that sends `"unlend"` is refused at the node's
/// serde, and one that signs the wrong number is refused at recovery.
#[tokio::test]
async fn borrow_lend_posts_the_pascal_case_kind_and_signs_the_uint8() {
    let (client, captor, wallet) = capturing_exchange().await;
    let params = BorrowLend {
        kind: BorrowLendKind::UnLend,
        amount: "1000".into(),
    };
    let _: Value = client
        .exchange()
        .borrow_lend(&wallet, &params)
        .await
        .unwrap();

    let body = captor.last.lock().await.clone().expect("body captured");
    let action = body["action"].clone();
    assert_eq!(action["type"].as_str(), Some("borrow_lend"));
    assert_eq!(action["params"]["kind"], json!("UnLend"));
    assert_eq!(action["params"]["amount"], json!("1000"));
    assert!(action["params"]["amount"].is_string());

    let nonce = body["nonce"].as_u64().unwrap();
    let digest = _typed_digest_for_test(&TypedAction::BorrowLend {
        metaflux_chain: metaflux_chain_tag(MTF_CHAIN_ID).to_string(),
        kind: 1,
        amount: "1000".into(),
        nonce,
    });
    let sig = decode_sig(body["signature"].as_str().unwrap());
    assert_eq!(
        _recover_for_test(&digest, &sig).expect("recover"),
        wallet.address()
    );
}

#[tokio::test]
async fn register_metaliquidity_operator_omits_a_zero_expiry() {
    // The node refuses an explicit `expires_at_ms: 0`, so a never-expiring
    // operator MUST leave the key out. Sending it is a guaranteed 400.
    let (client, captor, wallet) = capturing_exchange().await;
    let params = RegisterMetaliquidityOperator {
        vault_id: VaultId(42),
        operator: Address::from_bytes([0x70; 20]),
        allowed: true,
        expires_at_ms: 0,
    };
    let _: Value = client
        .exchange()
        .register_metaliquidity_operator(&wallet, &params)
        .await
        .unwrap();

    let body = captor.last.lock().await.clone().expect("body captured");
    assert!(
        body["action"]["params"].get("expires_at_ms").is_none(),
        "a zero expiry must be omitted, not sent"
    );
}

#[tokio::test]
async fn register_metaliquidity_operator_posts_hex_operator_and_signs_the_expiry() {
    let (client, captor, wallet) = capturing_exchange().await;
    let operator = Address::from_bytes([0x70; 20]);
    let params = RegisterMetaliquidityOperator {
        vault_id: VaultId(42),
        operator,
        allowed: true,
        expires_at_ms: 1_700_000_000_000,
    };
    let _: Value = client
        .exchange()
        .register_metaliquidity_operator(&wallet, &params)
        .await
        .unwrap();

    let body = captor.last.lock().await.clone().expect("body captured");
    let action = body["action"].clone();
    assert_eq!(
        action["type"].as_str(),
        Some("register_metaliquidity_operator")
    );
    assert_eq!(action["params"]["vault_id"], json!(42));
    assert_eq!(
        action["params"]["operator"],
        json!("0x7070707070707070707070707070707070707070")
    );
    assert_eq!(action["params"]["allowed"], json!(true));
    assert_eq!(
        action["params"]["expires_at_ms"],
        json!(1_700_000_000_000u64)
    );

    let nonce = body["nonce"].as_u64().unwrap();
    let digest = _typed_digest_for_test(&TypedAction::RegisterMetaliquidityOperator {
        metaflux_chain: metaflux_chain_tag(MTF_CHAIN_ID).to_string(),
        vault_id: 42,
        operator,
        allowed: true,
        expires_at_ms: 1_700_000_000_000,
        nonce,
    });
    let sig = decode_sig(body["signature"].as_str().unwrap());
    assert_eq!(
        _recover_for_test(&digest, &sig).expect("recover"),
        wallet.address()
    );
}

/// Each of the six deployer actions posts its OWN tag with its own field names.
/// A wrong tag or a renamed field is refused at the node's serde before any
/// handler runs, and the caller cannot tell that from a rejected signature.
#[tokio::test]
async fn the_spot_deployer_lane_posts_its_six_tags_with_their_own_fields() {
    let (client, captor, wallet) = capturing_exchange().await;
    let ex = client.exchange();

    let _: Value = ex
        .spot_register_token(
            &wallet,
            &SpotRegisterToken {
                symbol: "MTFX".into(),
                sz_decimals: 2,
                wei_decimals: 8,
                max_deploy_fee: "1250.50".into(),
            },
        )
        .await
        .unwrap();
    let a = captor.last.lock().await.clone().unwrap()["action"].clone();
    assert_eq!(a["type"].as_str(), Some("spot_register_token"));
    assert_eq!(a["params"]["symbol"], json!("MTFX"));
    assert_eq!(a["params"]["sz_decimals"], json!(2));
    assert_eq!(a["params"]["wei_decimals"], json!(8));
    assert_eq!(
        a["params"]["max_deploy_fee"],
        json!("1250.50"),
        "the fee is the verbatim signed string, not a number"
    );

    let _: Value = ex
        .spot_register_pair(
            &wallet,
            &SpotRegisterPair {
                base: 42,
                quote: 0,
                name: "MTFX/USDC".into(),
                max_deploy_fee: "980.00".into(),
            },
        )
        .await
        .unwrap();
    let a = captor.last.lock().await.clone().unwrap()["action"].clone();
    assert_eq!(a["type"].as_str(), Some("spot_register_pair"));
    assert_eq!(a["params"]["base"], json!(42));
    assert_eq!(a["params"]["quote"], json!(0));
    assert_eq!(a["params"]["max_deploy_fee"], json!("980.00"));

    let _: Value = ex
        .spot_set_pair_params(
            &wallet,
            &SpotSetPairParams {
                pair: 7,
                taker_fee_dbps: 350,
                maker_fee_dbps: 120,
                min_notional_cents: 1000,
            },
        )
        .await
        .unwrap();
    let a = captor.last.lock().await.clone().unwrap()["action"].clone();
    assert_eq!(a["type"].as_str(), Some("spot_set_pair_params"));
    assert_eq!(a["params"]["taker_fee_dbps"], json!(350));
    assert_eq!(a["params"]["min_notional_cents"], json!(1000));

    let _: Value = ex
        .spot_set_pair_active(
            &wallet,
            &SpotSetPairActive {
                pair: 7,
                active: false,
            },
        )
        .await
        .unwrap();
    let a = captor.last.lock().await.clone().unwrap()["action"].clone();
    assert_eq!(a["type"].as_str(), Some("spot_set_pair_active"));
    assert_eq!(a["params"]["active"], json!(false));

    let holders = vec![
        Address::from_bytes([0x11; 20]),
        Address::from_bytes([0x22; 20]),
    ];
    let _: Value = ex
        .spot_seed_holders(
            &wallet,
            &SpotSeedHolders {
                asset: 42,
                holders: holders.clone(),
                amounts: vec!["1000.5".into(), "250".into()],
            },
        )
        .await
        .unwrap();
    let body = captor.last.lock().await.clone().unwrap();
    let a = body["action"].clone();
    assert_eq!(a["type"].as_str(), Some("spot_seed_holders"));
    assert_eq!(a["params"]["amounts"], json!(["1000.5", "250"]));
    assert_eq!(
        a["params"]["holders"],
        json!([
            "0x1111111111111111111111111111111111111111",
            "0x2222222222222222222222222222222222222222"
        ])
    );
    let nonce = body["nonce"].as_u64().unwrap();
    let digest = _typed_digest_for_test(&TypedAction::SpotSeedHolders {
        metaflux_chain: metaflux_chain_tag(MTF_CHAIN_ID).to_string(),
        asset: 42,
        holders,
        amounts: vec!["1000.5".into(), "250".into()],
        nonce,
    });
    let sig = decode_sig(body["signature"].as_str().unwrap());
    assert_eq!(
        _recover_for_test(&digest, &sig).expect("recover"),
        wallet.address(),
        "the staged rows must be signed exactly as posted"
    );

    let _: Value = ex
        .spot_finalize_supply(
            &wallet,
            &SpotFinalizeSupply {
                asset: 42,
                max_supply: "1250.500001".into(),
            },
        )
        .await
        .unwrap();
    let a = captor.last.lock().await.clone().unwrap()["action"].clone();
    assert_eq!(a["type"].as_str(), Some("spot_finalize_supply"));
    assert_eq!(a["params"]["max_supply"], json!("1250.500001"));
    assert!(a["params"]["max_supply"].is_string());
}

/// Staged rows are refused BEFORE signing when the two arrays cannot pair up.
/// The node refuses the same call, but a client that signs it burns a nonce.
#[tokio::test]
async fn spot_seed_holders_refuses_unpaired_rows_before_signing() {
    let (client, _captor, wallet) = capturing_exchange().await;
    let bad = SpotSeedHolders {
        asset: 42,
        holders: vec![Address::from_bytes([0x11; 20])],
        amounts: vec!["1".into(), "2".into()],
    };
    let err = client
        .exchange()
        .spot_seed_holders(&wallet, &bad)
        .await
        .unwrap_err();
    assert!(matches!(err, metaflux_client::ClientError::Validation(_)));

    let empty = SpotSeedHolders {
        asset: 42,
        holders: Vec::new(),
        amounts: Vec::new(),
    };
    let err = client
        .exchange()
        .spot_seed_holders(&wallet, &empty)
        .await
        .unwrap_err();
    assert!(matches!(err, metaflux_client::ClientError::Validation(_)));
}

// ---- MIP-3 perp deployer lane ----

/// Each of the nine deployer actions posts its OWN tag with its own field
/// names. A wrong tag or a renamed field is refused at the node's serde before
/// any handler runs, and the caller cannot tell that from a rejected signature.
#[tokio::test]
#[allow(deprecated)]
async fn the_perp_deployer_lane_posts_its_nine_tags_with_their_own_fields() {
    let (client, captor, wallet) = capturing_exchange().await;
    let ex = client.exchange();

    let _: Value = ex
        .perp_register_asset(
            &wallet,
            &PerpRegisterAsset {
                symbol: "GRAD:WIF".into(),
                decimals: 8,
                name: "GRAD".into(),
            },
        )
        .await
        .unwrap();
    let a = captor.last.lock().await.clone().unwrap()["action"].clone();
    assert_eq!(a["type"].as_str(), Some("perp_register_asset"));
    assert_eq!(a["params"]["symbol"], json!("GRAD:WIF"));
    assert_eq!(a["params"]["decimals"], json!(8));
    assert_eq!(a["params"]["name"], json!("GRAD"));
    assert!(a["params"].get("bid").is_none(), "the bid lane is dead");
    assert!(
        a["params"].get("asset").is_none(),
        "the node assigns the id"
    );

    let _: Value = ex
        .perp_set_oracle(
            &wallet,
            &PerpSetOracle {
                asset: 1001,
                oracle_source_mask: 0x03ff,
            },
        )
        .await
        .unwrap();
    let a = captor.last.lock().await.clone().unwrap()["action"].clone();
    assert_eq!(a["type"].as_str(), Some("perp_set_oracle"));
    assert_eq!(a["params"]["asset"], json!(1001));
    assert_eq!(a["params"]["oracle_source_mask"], json!(1023));

    let _: Value = ex
        .perp_set_leverage(
            &wallet,
            &PerpSetLeverage {
                asset: 1001,
                max_leverage: 20,
            },
        )
        .await
        .unwrap();
    let a = captor.last.lock().await.clone().unwrap()["action"].clone();
    assert_eq!(a["type"].as_str(), Some("perp_set_leverage"));
    assert_eq!(a["params"]["max_leverage"], json!(20));

    let _: Value = ex
        .perp_set_fee_tier(
            &wallet,
            &PerpSetFeeTier {
                asset: 1001,
                taker_fee_dbps: 45,
                maker_fee_dbps: 12,
                deployer_fee_bps: 6,
            },
        )
        .await
        .unwrap();
    let a = captor.last.lock().await.clone().unwrap()["action"].clone();
    assert_eq!(a["type"].as_str(), Some("perp_set_fee_tier"));
    assert_eq!(
        a["params"]["taker_fee_dbps"],
        json!(45),
        "the three legs post separately; the node packs them"
    );
    assert_eq!(a["params"]["maker_fee_dbps"], json!(12));
    assert_eq!(a["params"]["deployer_fee_bps"], json!(6));
    assert!(
        a["params"].get("value").is_none(),
        "no packed value on the wire"
    );

    let _: Value = ex
        .perp_set_maker_rebate(
            &wallet,
            &PerpSetMakerRebate {
                asset: 1001,
                rebate_bps: 2,
            },
        )
        .await
        .unwrap();
    let a = captor.last.lock().await.clone().unwrap()["action"].clone();
    assert_eq!(a["type"].as_str(), Some("perp_set_maker_rebate"));
    assert_eq!(a["params"]["rebate_bps"], json!(2));

    let _: Value = ex
        .perp_set_min_size(
            &wallet,
            &PerpSetMinSize {
                asset: 1001,
                min_order_size: 1000,
            },
        )
        .await
        .unwrap();
    let a = captor.last.lock().await.clone().unwrap()["action"].clone();
    assert_eq!(a["type"].as_str(), Some("perp_set_min_size"));
    assert_eq!(a["params"]["min_order_size"], json!(1000));

    let _: Value = ex
        .perp_activate_market(&wallet, &PerpActivateMarket { asset: 1001 })
        .await
        .unwrap();
    let a = captor.last.lock().await.clone().unwrap()["action"].clone();
    assert_eq!(a["type"].as_str(), Some("perp_activate_market"));
    assert_eq!(a["params"]["asset"], json!(1001));

    let _: Value = ex
        .perp_deactivate_market(&wallet, &PerpDeactivateMarket { asset: 1001 })
        .await
        .unwrap();
    let a = captor.last.lock().await.clone().unwrap()["action"].clone();
    assert_eq!(
        a["type"].as_str(),
        Some("perp_deactivate_market"),
        "closing a market must not post the activate tag"
    );

    let _: Value = ex
        .perp_set_sub_deployers(
            &wallet,
            &PerpSetSubDeployers {
                asset: 1001,
                sub_deployer: Address::from_bytes([0xaa; 20]),
                add: true,
            },
        )
        .await
        .unwrap();
    let a = captor.last.lock().await.clone().unwrap()["action"].clone();
    assert_eq!(a["type"].as_str(), Some("perp_set_sub_deployers"));
    assert_eq!(
        a["params"]["sub_deployer"],
        json!("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );
    assert_eq!(a["params"]["add"], json!(true));
}

/// The delegate grant is the lane's authority handover, so pin that what the
/// signer signs is exactly what the POST carries.
#[tokio::test]
async fn perp_set_sub_deployers_signs_the_posted_delegate() {
    let (client, captor, wallet) = capturing_exchange().await;
    let sub_deployer = Address::from_bytes([0xaa; 20]);
    let _: Value = client
        .exchange()
        .perp_set_sub_deployers(
            &wallet,
            &PerpSetSubDeployers {
                asset: 1001,
                sub_deployer,
                add: true,
            },
        )
        .await
        .unwrap();

    let body = captor.last.lock().await.clone().expect("body captured");
    let nonce = body["nonce"].as_u64().unwrap();
    let digest = _typed_digest_for_test(&TypedAction::PerpSetSubDeployers {
        metaflux_chain: metaflux_chain_tag(MTF_CHAIN_ID).to_string(),
        asset: 1001,
        sub_deployer,
        add: true,
        nonce,
    });
    let sig = decode_sig(body["signature"].as_str().unwrap());
    assert_eq!(
        _recover_for_test(&digest, &sig).expect("recover"),
        wallet.address()
    );
}

/// The node hashes the px string it is SENT. If the SDK ever re-formatted the
/// string between signing and posting, every push would fail signer auth, so
/// pin that the posted px is the exact string the digest covers.
#[tokio::test]
async fn mip3_oracle_px_posts_the_exact_string_it_signs() {
    let (client, captor, wallet) = capturing_exchange().await;
    let px = "1250.500001";
    let _: Value = client
        .exchange()
        .mip3_set_oracle_px(
            &wallet,
            &Mip3SetOraclePx {
                asset: 42,
                px: px.to_string(),
            },
        )
        .await
        .unwrap();

    let body = captor.last.lock().await.clone().expect("body captured");
    let action = body["action"].clone();
    assert_eq!(action["type"].as_str(), Some("mip3_set_oracle_px"));
    assert_eq!(action["params"]["asset"], json!(42));
    assert_eq!(action["params"]["px"], json!(px));
    assert!(
        action["params"]["px"].is_string(),
        "px must ride as a string, never a number"
    );

    let nonce = body["nonce"].as_u64().unwrap();
    let digest = _typed_digest_for_test(&TypedAction::Mip3SetOraclePx {
        metaflux_chain: metaflux_chain_tag(MTF_CHAIN_ID).to_string(),
        asset: 42,
        px: px.to_string(),
        nonce,
    });
    let sig = decode_sig(body["signature"].as_str().unwrap());
    assert_eq!(
        _recover_for_test(&digest, &sig).expect("recover"),
        wallet.address()
    );
}

#[tokio::test]
async fn noop_posts_a_bare_tag_and_signs_the_chain_and_nonce() {
    // The chain's wire form carries no `params` key. Sending one is an unknown
    // field, so the shape matters as much as the digest.
    let (client, captor, wallet) = capturing_exchange().await;
    let _: Value = client.exchange().noop_typed(&wallet).await.unwrap();

    let body = captor.last.lock().await.clone().expect("body captured");
    let action = body["action"].clone();
    assert_eq!(action["type"].as_str(), Some("noop"));
    assert!(
        action.get("params").is_none(),
        "noop must post no params key"
    );

    let nonce = body["nonce"].as_u64().unwrap();
    let digest = _typed_digest_for_test(&TypedAction::Noop {
        metaflux_chain: metaflux_chain_tag(MTF_CHAIN_ID).to_string(),
        nonce,
    });
    let sig = decode_sig(body["signature"].as_str().unwrap());
    assert_eq!(
        _recover_for_test(&digest, &sig).expect("recover"),
        wallet.address()
    );
}
