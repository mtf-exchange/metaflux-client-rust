//! Mock-server tests for the `/info` namespace.
//!
//! Spin up a `wiremock::MockServer`, register MTF-native shaped responses,
//! and assert the SDK decodes them correctly. No real network involved.

use metaflux_client::{
    Client,
    types::{MarketId, VaultId},
    wallet::Address,
};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn markets_decodes_array_of_market_meta() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {
                "market_id": 1,
                "symbol": "BTC-PERP",
                "size_decimals": 6,
                "px_decimals": 4,
                "max_leverage": 50,
                "tick_size": 1,
                "min_size": 1
            },
            {
                "market_id": 2,
                "symbol": "ETH-PERP",
                "size_decimals": 5,
                "px_decimals": 4,
                "max_leverage": 40,
                "tick_size": 1,
                "min_size": 1
            }
        ])))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let markets = client.rest().info().markets().await.unwrap();
    assert_eq!(markets.len(), 2);
    assert_eq!(markets[0].symbol, "BTC-PERP");
    assert_eq!(markets[0].market_id.0, 1);
    assert_eq!(markets[1].symbol, "ETH-PERP");
    assert_eq!(markets[1].max_leverage, 40);
}

#[tokio::test]
async fn user_state_decodes_positions() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "address": "0x0000000000000000000000000000000000000001",
            "account_value_cents": 10_000_000i64,
            "total_unrealised_pnl_cents": 1_234i64,
            "position_count": 1,
            "positions": [{
                "owner": "0x0000000000000000000000000000000000000001",
                "market": 1,
                "size": 500,
                "entry_px": 4_999_500_000_000u64,
                "unrealised_pnl_cents": 1_234i64,
                "margin_cents": 500_000u64,
                "funding_paid_cents": -42i64
            }]
        })))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let addr = Address::from_hex("0x0000000000000000000000000000000000000001").unwrap();
    let state = client.rest().info().user_state(addr).await.unwrap();
    assert_eq!(state.position_count, 1);
    assert_eq!(state.positions.len(), 1);
    assert_eq!(state.positions[0].size, 500);
    assert_eq!(state.account_value_cents, 10_000_000);
}

#[tokio::test]
async fn vault_state_decodes_pinned_constants() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "vault_id": 42,
            "leader": "0x0000000000000000000000000000000000000002",
            "total_shares": 1_000_000u64,
            "nav_usd_cents": 5_000_000i64,
            "paused": false,
            "management_fee_bps": 1000,
            "withdrawal_lock_ms": 345_600_000u64,
            "created_at_ms": 1_700_000_000_000u64,
            "follower_count": 3
        })))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let v = client.rest().info().vault_state(VaultId(42)).await.unwrap();
    assert_eq!(v.vault_id.0, 42);
    assert_eq!(v.management_fee_bps, 1000);
    assert_eq!(v.withdrawal_lock_ms, 345_600_000);
    assert!(!v.paused);
}

#[tokio::test]
async fn fee_schedule_decodes_plan_l_split() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "taker_bps": 45,
            "maker_bps": 15,
            "referrer_share_bps": 1000,
            "builder_cap_bps": 8,
            "deployer_cap_bps": 5,
            "burn_bps": 5000,
            "vault_bps": 2500,
            "validator_bps": 1500,
            "treasury_bps": 1000
        })))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let f = client.rest().info().fee_schedule().await.unwrap();
    assert_eq!(f.taker_bps, 45);
    assert_eq!(f.maker_bps, 15);
    let sum = u64::from(f.burn_bps)
        + u64::from(f.vault_bps)
        + u64::from(f.validator_bps)
        + u64::from(f.treasury_bps);
    assert_eq!(sum, 10_000, "PLAN.md §L.2 split must sum to 10000 bps");
}

#[tokio::test]
async fn error_envelope_surfaces_as_protocol_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/info"))
        .respond_with(
            ResponseTemplate::new(400).set_body_json(json!({"error": "unknown request type: wat"})),
        )
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let err = client.rest().info().markets().await.unwrap_err();
    match err {
        metaflux_client::ClientError::ProtocolError { code, msg } => {
            assert_eq!(code, 400);
            assert!(msg.contains("unknown request type"));
        }
        other => panic!("expected ProtocolError, got {other:?}"),
    }
}

#[tokio::test]
async fn l2_book_decodes_levels() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "market_id": 1,
            "ts_ms": 1_700_000_000_000u64,
            "bids": [{ "px": 4_990_000_000_000u64, "size": 1000, "n_orders": 3 }],
            "asks": [{ "px": 5_010_000_000_000u64, "size": 800, "n_orders": 2 }]
        })))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let book = client.rest().info().l2_book(MarketId(1)).await.unwrap();
    assert_eq!(book.bids.len(), 1);
    assert_eq!(book.bids[0].size, 1000);
    assert_eq!(book.asks[0].n_orders, 2);
}
