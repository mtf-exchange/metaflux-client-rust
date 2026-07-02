//! Mock-server tests for the `/info` namespace.
//!
//! Spin up a `wiremock::MockServer`, register MTF-native shaped responses,
//! and assert the SDK decodes them correctly. No real network involved.
//!
//! Every fixture is wrapped in the committed `{ "type": ..., "data": ... }`
//! envelope (`api/rest/info.md` §Envelope) so these tests also exercise the
//! REST layer's envelope-unwrap path.

use metaflux_client::{
    Client,
    rest::info::{MarginMode, MarketKind, Tier},
    types::VaultId,
    wallet::Address,
};
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Wrap a payload in the committed `{ type, data }` info envelope.
fn envelope(ty: &str, data: Value) -> Value {
    json!({ "type": ty, "data": data })
}

#[tokio::test]
async fn markets_decodes_array_of_market_info() {
    let server = MockServer::start().await;
    let market = |asset_id: u32, coin: &str, max_lev: u32| {
        json!({
            "coin": coin,
            "asset_id": asset_id,
            "kind": "perp",
            "sz_decimals": 5,
            "mark_px": "50000",
            "oracle_px": "50000",
            "tick_size": "100",
            "step_size": "10000",
            "min_order": "10000",
            "max_leverage": max_lev,
            "maint_margin_ratio": "5000",
            "init_margin_ratio": "10000",
            "funding": {
                "rate_per_hr": "1000",
                "cap_per_hr": "50000",
                "interval_ms": 3_600_000u64,
                "next_payment_ts": 1_735_693_200_000u64
            },
            "margin_tiers": [
                { "max_open_interest": "100000", "max_leverage": max_lev, "maint_margin_ratio": "100" },
                { "max_open_interest": null, "max_leverage": 5, "maint_margin_ratio": "1000" }
            ],
            "mark_source": "MedianOfOraclesAndMid",
            "fba_enabled": false,
            "open_interest": "5000000000"
        })
    };
    Mock::given(method("POST"))
        .and(path("/info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(
            "markets",
            json!({
                "perp": [market(0, "BTC", 50), market(1, "ETH", 40)],
                "spot": { "pairs": [], "tokens": [] }
            }),
        )))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let markets = client.rest().info().markets().await.unwrap();
    assert_eq!(markets.len(), 2);
    assert_eq!(markets[0].coin, "BTC");
    assert_eq!(markets[0].asset_id, 0);
    assert_eq!(markets[0].kind, MarketKind::Perp);
    assert_eq!(markets[0].margin_tiers.len(), 2);
    assert!(markets[0].margin_tiers[1].max_open_interest.is_none());
    assert_eq!(markets[1].coin, "ETH");
    assert_eq!(markets[1].max_leverage, 40);
}

#[tokio::test]
async fn user_state_decodes_positions() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(
            "user_state",
            json!({
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
            }),
        )))
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
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(
            "vault_state",
            json!({
                "vault_id": 42,
                "leader": "0x0000000000000000000000000000000000000002",
                "total_shares": 1_000_000u64,
                "nav_usd_cents": 5_000_000i64,
                "paused": false,
                "management_fee_bps": 1000,
                "withdrawal_lock_ms": 345_600_000u64,
                "created_at_ms": 1_700_000_000_000u64,
                "follower_count": 3
            }),
        )))
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
async fn fee_schedule_decodes_gateway_shape() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(
            "fee_schedule",
            json!({
                "maker_bps": "1.0",
                "taker_bps": "5.0",
                "referrer_share_bps": "5.0",
                "builder_rebate_bps": "0",
                "burn_ratio": "0.8",
                "tiers": [{ "maker_bps": "1.0", "taker_bps": "5.0", "volume_30d": "0" }]
            }),
        )))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let f = client.rest().info().fee_schedule().await.unwrap();
    assert_eq!(f.taker_bps.as_deref(), Some("5.0"));
    assert_eq!(f.maker_bps.as_deref(), Some("1.0"));
    assert_eq!(f.burn_ratio, "0.8");
    assert_eq!(f.tiers.len(), 1);
    assert_eq!(f.tiers[0].volume_30d, "0");
}

#[tokio::test]
async fn spot_meta_decodes_pairs_and_tokens() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(
            "spot_meta",
            json!({
                "pairs": [{
                    "id": 101,
                    "name": "BTC/USDC",
                    "base": 0,
                    "quote": 100,
                    "taker_fee_bps": 5,
                    "min_notional": "1000",
                    "active": true
                }],
                "tokens": [
                    { "id": 0, "name": "BTC", "sz_decimals": 5, "wei_decimals": 8 },
                    { "id": 100, "name": "USDC", "sz_decimals": 2, "wei_decimals": 6 }
                ]
            }),
        )))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let m = client.rest().info().spot_meta().await.unwrap();
    assert_eq!(m.pairs.len(), 1);
    // `name` is the derived `{base}/{quote}` display name; `id` is the numeric
    // pair id spot prints carry as `coin` on the WS feeds.
    assert_eq!(m.pairs[0].id, 101);
    assert_eq!(m.pairs[0].name, "BTC/USDC");
    assert_eq!(m.pairs[0].base, 0);
    assert_eq!(m.pairs[0].quote, 100);
    assert_eq!(m.pairs[0].taker_fee_bps, 5);
    assert_eq!(m.pairs[0].min_notional, "1000");
    assert!(m.pairs[0].active);
    assert_eq!(m.tokens.len(), 2);
    assert_eq!(m.tokens[0].name, "BTC");
    assert_eq!(m.tokens[0].sz_decimals, 5);
    assert_eq!(m.tokens[1].name, "USDC");
    assert_eq!(m.tokens[1].wei_decimals, 6);
}

#[tokio::test]
async fn spot_clearinghouse_state_decodes_balances_by_address() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(
            "spot_clearinghouse_state",
            json!({
                "address": "0x4242424242424242424242424242424242424242",
                "balances": [
                    { "asset": 101, "name": "BTC/USDC", "balance": "500" }
                ]
            }),
        )))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let addr = Address::from_hex("0x4242424242424242424242424242424242424242").unwrap();
    let s = client
        .rest()
        .info()
        .spot_clearinghouse_state(addr)
        .await
        .unwrap();
    assert_eq!(s.address, addr);
    assert_eq!(s.balances.len(), 1);
    assert_eq!(s.balances[0].asset, 101);
    assert_eq!(s.balances[0].name, "BTC/USDC");
    assert_eq!(s.balances[0].balance, "500");
}

#[tokio::test]
async fn error_envelope_surfaces_as_protocol_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/info"))
        .respond_with(
            ResponseTemplate::new(400).set_body_json(json!({"error": "unknown info type: wat"})),
        )
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let err = client.rest().info().markets().await.unwrap_err();
    match err {
        metaflux_client::ClientError::ProtocolError { code, msg } => {
            assert_eq!(code, 400);
            assert!(msg.contains("unknown info type"));
        }
        other => panic!("expected ProtocolError, got {other:?}"),
    }
}

#[tokio::test]
async fn node_info_decodes() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(
            "node_info",
            json!({
                "network": "devnet",
                "chain_id": 31337,
                "protocol_version": "1.0.0",
                "validator_index": 3,
                "build_commit": "deadbeef",
                "uptime_seconds": 123_456u64
            }),
        )))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let n = client.rest().info().node_info().await.unwrap();
    assert_eq!(n.network, "devnet");
    assert_eq!(n.chain_id, 31337);
    assert_eq!(n.protocol_version, "1.0.0");
    assert_eq!(n.validator_index, 3);
}

#[tokio::test]
async fn account_state_decodes_rich_shape_by_address() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(
            "account_state",
            json!({
                "address": "0x000000000000000000000000000000000000beef",
                "account_value": "100000000",
                "free_collateral": "80000000",
                "maint_margin": "10000000",
                "init_margin": "20000000",
                "health": "10000000",
                "tier": "Safe",
                "mode": "Cross",
                "pm_enabled": false,
                "positions": [{
                    "asset": 0,
                    "size": "100000000",
                    "entry": "10000000000",
                    "upnl": "500000",
                    "isolated": false,
                    "lev": 10
                }],
                "balances": {
                    "usdc": "100000000",
                    "spot": { "ETH": { "asset_id": 102, "total": "5000000000", "hold": "0", "value": "0" } }
                }
            }),
        )))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let addr = Address::from_hex("0x000000000000000000000000000000000000beef").unwrap();
    let a = client.rest().info().account_state(addr).await.unwrap();
    assert_eq!(a.account_value, "100000000");
    assert_eq!(a.free_collateral, "80000000");
    assert_eq!(a.tier, Tier::Safe);
    assert_eq!(a.margin_mode, MarginMode::Cross);
    assert!(!a.pm_enabled);
    assert_eq!(a.positions.len(), 1);
    assert_eq!(a.positions[0].leverage, 10);
    assert_eq!(a.balances.usdc, "100000000");
    assert_eq!(
        a.balances.spot.get("ETH").map(|b| b.total.as_str()),
        Some("5000000000")
    );
}

#[tokio::test]
async fn market_info_decodes_rich_shape_by_coin() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(
            "market_info",
            json!({
                "coin": "BTC",
                "asset_id": 0,
                "kind": "perp",
                "sz_decimals": 5,
                "mark_px": "50000",
                "oracle_px": "50000",
                "tick_size": "0.01",
                "step_size": "0.1",
                "min_order": "0.1",
                "max_leverage": 50,
                "maint_margin_ratio": "5000",
                "init_margin_ratio": "10000",
                "funding": {
                    "rate_per_hr": "1000",
                    "cap_per_hr": "50000",
                    "interval_ms": 3_600_000u64,
                    "next_payment_ts": 1_735_693_200_000u64
                },
                "margin_tiers": [
                    { "max_open_interest": "100000", "max_leverage": 50, "maint_margin_ratio": "100" },
                    { "max_open_interest": null, "max_leverage": 5, "maint_margin_ratio": "1000" }
                ],
                "mark_source": "MedianOfOraclesAndMid",
                "fba_enabled": false,
                "open_interest": "5000000000"
            }),
        )))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let m = client.rest().info().market_info("BTC").await.unwrap();
    assert_eq!(m.coin, "BTC");
    assert_eq!(m.sz_decimals, 5);
    assert_eq!(m.mark_px, "50000");
    assert_eq!(m.tick_size, "0.01");
    assert_eq!(m.open_interest, "5000000000");
    assert_eq!(m.funding.interval_ms, 3_600_000);
    assert_eq!(m.margin_tiers.len(), 2);
    assert_eq!(m.margin_tiers[0].maint_margin_ratio, "100");
}

#[tokio::test]
async fn staking_state_decodes_by_address() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(
            "staking_state",
            json!({
                "address": "0x0000000000000000000000000000000000000003",
                "total_staked": "0",
                "pending_rewards": "0",
                "delegations": [],
                "unbonding": []
            }),
        )))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let addr = Address::from_hex("0x0000000000000000000000000000000000000003").unwrap();
    let s = client.rest().info().staking_state(addr).await.unwrap();
    assert_eq!(s.total_staked, "0");
    assert!(s.delegations.is_empty());
}

#[tokio::test]
async fn l2_book_decodes_levels() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(
            "l2_book",
            json!({
                "bids": [{ "px": "4990000000000", "size": "1000", "n_orders": 3 }],
                "asks": [{ "px": "5010000000000", "size": "800", "n_orders": 2 }]
            }),
        )))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let book = client.rest().info().l2_book("BTC", 20).await.unwrap();
    assert_eq!(book.bids.len(), 1);
    assert_eq!(book.bids[0].size, "1000");
    assert_eq!(book.asks[0].n_orders, 2);
}

#[tokio::test]
async fn candle_snapshot_decodes_gateway_envelope() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(
            "candle_snapshot",
            json!({
                "candles": [
                    {
                        "s": "BTC", "i": "1m",
                        "t": 1_700_000_040_000u64, "T": 1_700_000_099_999u64,
                        "o": "67000.0", "c": "67042.5",
                        "h": "67080.0", "l": "66990.0",
                        "v": "12.5", "q": "838031.25", "n": 37
                    }
                ]
            }),
        )))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let bars = client
        .rest()
        .info()
        .candle_snapshot("BTC", "1m", 1_700_000_000_000, 1_700_000_100_000)
        .await
        .unwrap();
    assert_eq!(bars.len(), 1);
    assert_eq!(bars[0].coin, "BTC");
    assert_eq!(bars[0].close, "67042.5");
    assert_eq!(bars[0].quote_volume, "838031.25");
    assert_eq!(bars[0].num_trades, 37);
}

#[tokio::test]
async fn trades_by_time_decodes_symbol_prints() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(
            "trades_by_time",
            json!({
                "coin": "BTC",
                "start_time": 0u64,
                "end_time": 9_999_999_999_999u64,
                "trades": [{
                    "coin": "BTC", "px": "61643.70000000", "sz": "0.00024",
                    "side": "A", "tid": 18_232_248_797_686_447_553u64, "block": 37697,
                    "hash": "0xd3c94e061264a4e9fd3090f0a65da636377737bc7b8e6e5b0ee839ed3e5d07d7",
                    "time": 1_783_000_783_768u64
                }]
            }),
        )))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let trades = client
        .rest()
        .info()
        .trades_by_time("BTC", 0, 9_999_999_999_999)
        .await
        .unwrap();
    assert_eq!(trades.len(), 1);
    assert_eq!(trades[0].coin, "BTC");
    assert_eq!(trades[0].side, "A");
    assert_eq!(trades[0].tid, 18_232_248_797_686_447_553);
    assert!(trades[0].hash.starts_with("0x"));
}

#[tokio::test]
async fn predicted_fundings_decodes_entries() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(
            "predicted_fundings",
            json!([
                { "coin": "BTC", "predicted_rate": "0.00176", "next_funding_time": 1_783_011_600_000u64 },
                { "coin": "ETH", "predicted_rate": "-0.0087", "next_funding_time": 1_783_011_600_000u64 }
            ]),
        )))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let pf = client.rest().info().predicted_fundings().await.unwrap();
    assert_eq!(pf.len(), 2);
    assert_eq!(pf[0].coin, "BTC");
    assert_eq!(pf[0].next_funding_time, 1_783_011_600_000);
    assert_eq!(pf[1].predicted_rate, "-0.0087");
}
