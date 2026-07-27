//! Mock-server tests for the unified `place_order` entry point.
//!
//! Confirms the routing table and, most importantly, that the unified path
//! posts the SAME wire action bytes as the existing per-action methods:
//!
//! 1. one perp leg  → ONE `batch_order` action.
//! 2. N perp legs   → ONE `batch_order` action carrying N orders.
//! 3. N spot orders → N `spot_order` actions, one per order.
//! 4. mixed venues  → refused, nothing sent.
//! 5. the posted `action` bytes are byte-identical to `batch_order` /
//!    `spot_order` for the same input.

use metaflux_client::{
    Client, PlaceRequest, Placement,
    rest::exchange::_recover_for_test,
    rest::exchange_typed::{_typed_trade_digest_for_test, _typed_trade_digest_for_test_as},
    types::{
        MarketId, OrderId,
        order::{
            BatchOrder, Order, OrderGrouping, OrderKind, OrderStatus, Side, StpMode, TimeInForce,
        },
        place::OrderLeg,
        spot::SpotOrder,
    },
    wallet::{Address, Signature, TypedTradingAction, Wallet},
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// Responder that keeps every RAW request body, so a test can compare the
/// posted bytes rather than a re-serialized `Value`. `ok_calls` answers `200`
/// for the first N requests and `500` after that.
#[derive(Clone)]
struct BodyRecorder {
    bodies: Arc<Mutex<Vec<String>>>,
    response: Value,
    ok_calls: usize,
}

impl BodyRecorder {
    fn new(response: Value) -> Self {
        Self {
            bodies: Arc::new(Mutex::new(Vec::new())),
            response,
            ok_calls: usize::MAX,
        }
    }

    fn failing_after(response: Value, ok_calls: usize) -> Self {
        Self {
            ok_calls,
            ..Self::new(response)
        }
    }

    fn bodies(&self) -> Vec<String> {
        self.bodies.lock().unwrap().clone()
    }

    fn count(&self) -> usize {
        self.bodies.lock().unwrap().len()
    }
}

impl Respond for BodyRecorder {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let raw = String::from_utf8(req.body.clone()).expect("body is UTF-8");
        let seen = {
            let mut g = self.bodies.lock().unwrap();
            g.push(raw);
            g.len()
        };
        if seen > self.ok_calls {
            return ResponseTemplate::new(500).set_body_json(json!({ "error": "boom" }));
        }
        ResponseTemplate::new(200).set_body_json(self.response.clone())
    }
}

/// The raw `action` bytes out of a posted envelope. The envelope serializes as
/// `{"action":<action>,"nonce":…,"signature":…}`, so the action is everything
/// between those two markers. Slicing keeps the comparison at the BYTE level;
/// re-serializing a parsed `Value` would hide a key-order or number-format
/// difference.
fn action_bytes(body: &str) -> &str {
    const HEAD: &str = "{\"action\":";
    const TAIL: &str = ",\"nonce\":";
    let start = body.find(HEAD).expect("envelope starts with action") + HEAD.len();
    let end = body.rfind(TAIL).expect("envelope carries a nonce");
    &body[start..end]
}

fn action_json(body: &str) -> Value {
    serde_json::from_str(action_bytes(body)).expect("action is JSON")
}

fn wallet() -> Wallet {
    Wallet::from_hex("11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff").unwrap()
}

fn perp_order(owner: Address, market: u32, size: u64) -> Order {
    Order {
        owner,
        market: MarketId(market),
        side: Side::Bid,
        kind: OrderKind::Limit,
        size,
        limit_px: 5_000_000_000_000,
        tif: TimeInForce::Gtc,
        stp_mode: StpMode::CancelOldest,
        reduce_only: false,
        cloid: None,
        builder: None,
        position_side: None,
        trigger: None,
    }
}

fn spot_order(pair: u32, size: u64) -> SpotOrder {
    SpotOrder::ioc_limit(pair, Side::Ask, size, 5_000_000_000)
}

fn one_resting(oid: u64) -> Value {
    json!({ "statuses": [ { "resting": { "oid": oid } } ] })
}

async fn mock(response: Value) -> (MockServer, BodyRecorder) {
    let server = MockServer::start().await;
    let rec = BodyRecorder::new(response);
    Mock::given(method("POST"))
        .and(path("/exchange"))
        .respond_with(rec.clone())
        .mount(&server)
        .await;
    (server, rec)
}

#[tokio::test]
async fn one_perp_leg_routes_to_batch_order() {
    let (server, rec) = mock(one_resting(11)).await;
    let client = Client::new(server.uri()).unwrap();
    let w = wallet();

    let req = PlaceRequest::perp(w.address(), [perp_order(w.address(), 1, 1_000)]);
    let placed = client.exchange().place_order(&w, &req).await.unwrap();

    assert_eq!(rec.count(), 1, "one order must cost exactly one action");
    let action = action_json(&rec.bodies()[0]);
    assert_eq!(action["type"], json!("batch_order"));
    assert_eq!(action["params"]["orders"].as_array().unwrap().len(), 1);
    assert!(
        action["order"].is_null(),
        "the single-order `order` action must not be used"
    );

    match placed {
        Placement::BatchAction(b) => {
            assert_eq!(b.statuses.len(), 1);
            assert_eq!(b.statuses[0].oid(), Some(OrderId(11)));
        }
        other => panic!("expected BatchAction, got {other:?}"),
    }
}

#[tokio::test]
async fn several_perp_legs_route_to_one_batch_order() {
    let (server, rec) = mock(json!({ "statuses": [
        { "resting": { "oid": 1 } },
        { "filled": { "oid": 2, "total_sz": "100000000", "avg_px": "5000000000000" } },
        { "error": "size below market minimum" }
    ]}))
    .await;
    let client = Client::new(server.uri()).unwrap();
    let w = wallet();

    let req = PlaceRequest::perp(
        w.address(),
        [
            perp_order(w.address(), 1, 1_000),
            perp_order(w.address(), 2, 2_000),
            perp_order(w.address(), 3, 3_000),
        ],
    );
    let placed = client.exchange().place_order(&w, &req).await.unwrap();

    assert_eq!(
        rec.count(),
        1,
        "three legs must ride ONE batch_order action"
    );
    let action = action_json(&rec.bodies()[0]);
    assert_eq!(action["type"], json!("batch_order"));
    let orders = action["params"]["orders"].as_array().unwrap();
    assert_eq!(orders.len(), 3);
    assert_eq!(orders[2]["market"], json!(3));

    match &placed {
        Placement::BatchAction(b) => {
            assert_eq!(b.statuses.len(), 3, "one status per placed leg");
            assert_eq!(b.statuses[0].oid(), Some(OrderId(1)));
            assert!(matches!(
                b.statuses[1].known(),
                Some(OrderStatus::Filled(_))
            ));
            assert!(b.statuses[2].is_error());
        }
        other => panic!("expected BatchAction, got {other:?}"),
    }
    assert_eq!(placed.action_count(), 1);
    assert!(placed.has_failure(), "a leg errored");
}

#[tokio::test]
async fn spot_legs_route_to_one_spot_order_each() {
    let (server, rec) = mock(one_resting(77)).await;
    let client = Client::new(server.uri()).unwrap();
    let w = wallet();

    let req = PlaceRequest::spot([spot_order(3, 100), spot_order(4, 200)]);
    let placed = client.exchange().place_order(&w, &req).await.unwrap();

    assert_eq!(
        rec.count(),
        2,
        "the wire cannot batch spot: one action each"
    );
    for (i, body) in rec.bodies().iter().enumerate() {
        let action = action_json(body);
        assert_eq!(action["type"], json!("spot_order"), "body {i}");
        assert!(action["order"]["pair"].is_number());
    }
    assert_eq!(action_json(&rec.bodies()[0])["order"]["pair"], json!(3));
    assert_eq!(action_json(&rec.bodies()[1])["order"]["pair"], json!(4));

    // Every envelope carries its own nonce + signature — the actions are NOT
    // one atomic submission.
    let nonces: Vec<u64> = rec
        .bodies()
        .iter()
        .map(|b| {
            serde_json::from_str::<Value>(b).unwrap()["nonce"]
                .as_u64()
                .unwrap()
        })
        .collect();
    assert_ne!(nonces[0], nonces[1]);

    match placed {
        Placement::SeparateSpotActions(p) => {
            assert_eq!(p.sent.len(), 2);
            assert!(p.not_sent.is_empty());
            assert_eq!(p.sent[0].pair, 3);
            assert_eq!(p.sent[1].pair, 4);
            assert_eq!(
                p.sent[0].result.as_ref().unwrap()[0].oid(),
                Some(OrderId(77))
            );
        }
        other => panic!("expected SeparateSpotActions, got {other:?}"),
    }
}

#[tokio::test]
async fn mixed_request_is_refused_and_sends_nothing() {
    let (server, rec) = mock(one_resting(1)).await;
    let client = Client::new(server.uri()).unwrap();
    let w = wallet();

    let err = PlaceRequest::from_legs([
        OrderLeg::Perp(perp_order(w.address(), 1, 1_000)),
        OrderLeg::Spot(spot_order(3, 100)),
    ])
    .expect_err("a mixed request must be refused");
    let msg = err.to_string();
    assert!(msg.contains("mixed venues"), "names the reason: {msg}");
    assert!(msg.contains("batch_order"), "names the perp action: {msg}");
    assert!(msg.contains("spot_order"), "names the spot action: {msg}");

    assert_eq!(rec.count(), 0, "a refused request must not reach the wire");
    // Keep the client alive so the assertion above is about routing, not drop
    // order.
    drop(client);
}

#[tokio::test]
async fn empty_request_is_refused() {
    let (server, rec) = mock(one_resting(1)).await;
    let client = Client::new(server.uri()).unwrap();
    let w = wallet();

    let err = client
        .exchange()
        .place_order(&w, &PlaceRequest::spot([]))
        .await
        .expect_err("an empty request must be refused");
    assert!(err.to_string().contains("no orders"));
    assert_eq!(rec.count(), 0);
}

/// The important one: the unified path must not invent a different wire shape.
#[tokio::test]
async fn perp_route_posts_byte_identical_action_to_batch_order() {
    let (server, rec) = mock(one_resting(1)).await;
    let client = Client::new(server.uri()).unwrap();
    let w = wallet();

    let orders = vec![
        perp_order(w.address(), 1, 1_000),
        perp_order(w.address(), 2, 2_000),
    ];
    let batch = BatchOrder {
        owner: w.address(),
        orders: orders.clone(),
        grouping: OrderGrouping::NormalTpsl,
    };
    client.exchange().batch_order(&w, &batch).await.unwrap();

    let req = PlaceRequest::perp(w.address(), orders).with_grouping(OrderGrouping::NormalTpsl);
    client.exchange().place_order(&w, &req).await.unwrap();

    let bodies = rec.bodies();
    assert_eq!(bodies.len(), 2);
    assert_eq!(
        action_bytes(&bodies[0]),
        action_bytes(&bodies[1]),
        "place_order must post the SAME batch_order bytes"
    );
}

#[tokio::test]
async fn spot_route_posts_byte_identical_action_to_spot_order() {
    let (server, rec) = mock(one_resting(1)).await;
    let client = Client::new(server.uri()).unwrap();
    let w = wallet();

    let order = spot_order(3, 100);
    client.exchange().spot_order(&w, &order).await.unwrap();

    let req = PlaceRequest::spot([order]);
    client.exchange().place_order(&w, &req).await.unwrap();

    let bodies = rec.bodies();
    assert_eq!(bodies.len(), 2);
    assert_eq!(
        action_bytes(&bodies[0]),
        action_bytes(&bodies[1]),
        "place_order must post the SAME spot_order bytes"
    );
}

/// BYTE PIN: a spot order with no `owner` posts exactly the bytes it posted
/// before the field existed, through BOTH the per-action method and the unified
/// entry point.
#[tokio::test]
async fn spot_without_owner_posts_the_pre_owner_bytes() {
    let (server, rec) = mock(one_resting(1)).await;
    let client = Client::new(server.uri()).unwrap();
    let w = wallet();

    let order = spot_order(3, 100);
    assert!(order.owner.is_none());
    client.exchange().spot_order(&w, &order).await.unwrap();
    client
        .exchange()
        .place_order(&w, &PlaceRequest::spot([order]))
        .await
        .unwrap();

    for body in rec.bodies() {
        assert_eq!(
            action_bytes(&body),
            r#"{"order":{"limit_px":5000000000,"pair":3,"side":"ask","size":100,"stp_mode":"cancel_oldest","tif":"ioc"},"type":"spot_order"}"#
        );
    }
}

/// An approved agent reaches the spot book through the unified entry point:
/// `PlaceRequest::spot_as` stamps `owner` on every leg, each `spot_order` action
/// carries it, and the bytes match the per-action method for the same input.
#[tokio::test]
async fn spot_route_carries_the_agent_owner() {
    let (server, rec) = mock(one_resting(1)).await;
    let client = Client::new(server.uri()).unwrap();
    let w = wallet();
    let owner = Address([0xbb; 20]);
    assert_ne!(w.address(), owner, "the signer is the AGENT, not the owner");

    let direct = spot_order(3, 100).with_owner(owner);
    client.exchange().spot_order(&w, &direct).await.unwrap();

    let req = PlaceRequest::spot_as(owner, [spot_order(3, 100), spot_order(4, 200)]);
    client.exchange().place_order(&w, &req).await.unwrap();

    let bodies = rec.bodies();
    assert_eq!(bodies.len(), 3);
    assert_eq!(
        action_bytes(&bodies[0]),
        action_bytes(&bodies[1]),
        "the unified path must post the SAME owner-bearing bytes"
    );
    for body in &bodies[1..] {
        assert_eq!(
            action_json(body)["order"]["owner"],
            json!("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        );
    }
    assert_eq!(action_json(&bodies[2])["order"]["pair"], json!(4));
}

/// The `owner` is bound into the SIGNATURE, not carried as an advisory body
/// field. The posted signature recovers the agent under the `*_WITH_OWNER`
/// digest ONLY — the owner-less digest recovers a different address, which is
/// what makes a stripped or swapped `owner` fail at the node.
#[tokio::test]
async fn spot_owner_is_bound_into_the_posted_signature() {
    let (server, rec) = mock(one_resting(1)).await;
    let client = Client::new(server.uri()).unwrap();
    let w = wallet();
    let owner = Address([0xbb; 20]);

    let order = spot_order(3, 100).with_owner(owner);
    client.exchange().spot_order(&w, &order).await.unwrap();

    let envelope: Value = serde_json::from_str(&rec.bodies()[0]).unwrap();
    let nonce = envelope["nonce"].as_u64().expect("nonce");
    let sig = parse_signature(envelope["signature"].as_str().expect("signature"));

    let bound =
        _typed_trade_digest_for_test_as(TypedTradingAction::SpotOrder(&order), owner, nonce);
    assert_eq!(
        _recover_for_test(&bound, &sig).unwrap(),
        w.address(),
        "the owner-bound digest must recover the AGENT"
    );

    let unbound = _typed_trade_digest_for_test(TypedTradingAction::SpotOrder(&order), nonce);
    assert_ne!(bound, unbound);
    assert_ne!(
        _recover_for_test(&unbound, &sig).unwrap(),
        w.address(),
        "the owner-less digest must NOT recover the agent"
    );
}

/// Split a `0x`-hex 65-byte `r || s || v` signature.
fn parse_signature(hex_sig: &str) -> Signature {
    let raw = hex::decode(hex_sig.trim_start_matches("0x")).expect("hex signature");
    assert_eq!(raw.len(), 65);
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&raw[..32]);
    s.copy_from_slice(&raw[32..64]);
    Signature { r, s, v: raw[64] }
}

/// A Market leg keeps the `batch_order` IOC coercion — the unified path routes
/// through the same method, so the guard cannot drift.
#[tokio::test]
async fn perp_route_keeps_the_market_tif_coercion() {
    let (server, rec) = mock(one_resting(1)).await;
    let client = Client::new(server.uri()).unwrap();
    let w = wallet();

    let mut market = perp_order(w.address(), 1, 1_000);
    market.kind = OrderKind::Market;
    market.tif = TimeInForce::Gtc;
    let req = PlaceRequest::perp(w.address(), [market]);
    client.exchange().place_order(&w, &req).await.unwrap();

    let action = action_json(&rec.bodies()[0]);
    assert_eq!(action["params"]["orders"][0]["tif"], json!("ioc"));
}

#[tokio::test]
async fn spot_route_stops_at_the_first_failed_action() {
    let server = MockServer::start().await;
    // The first action answers; the second returns a server error, so the third
    // order is never sent.
    let rec = BodyRecorder::failing_after(one_resting(1), 1);
    Mock::given(method("POST"))
        .and(path("/exchange"))
        .respond_with(rec.clone())
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let w = wallet();
    let req = PlaceRequest::spot([spot_order(3, 1), spot_order(4, 2), spot_order(5, 3)]);
    let placed = client.exchange().place_order(&w, &req).await.unwrap();

    match placed {
        Placement::SeparateSpotActions(p) => {
            assert_eq!(p.sent.len(), 2, "the third order must not be sent");
            assert!(p.sent[0].result.is_ok());
            assert!(p.sent[1].result.is_err());
            assert_eq!(p.not_sent, vec![2]);
        }
        other => panic!("expected SeparateSpotActions, got {other:?}"),
    }
}
