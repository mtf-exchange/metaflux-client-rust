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
    rest::info::{MarginMode, MarketKind, OrderStatus, Tier},
    types::VaultId,
    wallet::Address,
};
use serde_json::{Value, json};
use wiremock::matchers::{body_json, body_partial_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// The canonical test account (`0x42…42`) shared by the account-scoped reads.
const ADDR: &str = "0x4242424242424242424242424242424242424242";

fn test_addr() -> Address {
    Address::from_hex(ADDR).unwrap()
}

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
            // `spot_meta()` now posts `markets_meta` kind=spot; the node wraps
            // the spot universe under the retained `spot` key.
            "markets_meta",
            json!({
                "spot": {
                    "pairs": [{
                        "id": 101,
                        "name": "BTC/USDC",
                        "base": 0,
                        "quote": 100,
                        "taker_fee_bps": "5",
                        "min_notional": "1000",
                        "active": true,
                        "mark_px": "61550.2",
                        "mid_px": "61551",
                        "circulating_supply": "21000000"
                    }],
                    "tokens": [
                        { "id": 0, "name": "BTC", "sz_decimals": 5, "wei_decimals": 8,
                          "token_id": "0x00000000000000000000000000000000000000000000000000000000000000aa",
                          "system_address": "0x0000000000000000000000000000000000000200",
                          "evm_contract": { "address": "0x0000000000000000000000000000000000012345",
                                            "evm_extra_wei_decimals": -2 },
                          "is_canonical": true, "total_supply": "21000000" },
                        { "id": 100, "name": "USDC", "sz_decimals": 2, "wei_decimals": 6 }
                    ]
                }
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
    // `taker_fee_bps` is a STRING on the live wire.
    assert_eq!(m.pairs[0].taker_fee_bps, "5");
    assert_eq!(m.pairs[0].min_notional, "1000");
    assert!(m.pairs[0].active);
    assert_eq!(m.pairs[0].mark_px, "61550.2");
    assert_eq!(m.tokens.len(), 2);
    assert_eq!(m.tokens[0].name, "BTC");
    assert_eq!(m.tokens[0].sz_decimals, 5);
    // Enriched token row: object `evm_contract` + `total_supply`.
    assert_eq!(
        m.tokens[0]
            .evm_contract
            .as_ref()
            .unwrap()
            .evm_extra_wei_decimals,
        -2
    );
    assert_eq!(m.tokens[0].total_supply, "21000000");
    assert_eq!(m.tokens[1].name, "USDC");
    assert_eq!(m.tokens[1].wei_decimals, 6);
    // Minimal token row (no evm block) still decodes via defaults.
    assert!(m.tokens[1].evm_contract.is_none());
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
                "delegations": [],
                "pending_unstakes": []
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
    let book = client.rest().info().l2_book("BTC", None).await.unwrap();
    assert_eq!(book.bids.len(), 1);
    assert_eq!(book.bids[0].size, "1000");
    assert_eq!(book.asks[0].n_orders, 2);
}

#[tokio::test]
async fn l2_book_spot_pair_with_aggregation_params() {
    use metaflux_client::rest::info::L2BookParams;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(
            "l2_book",
            json!({
                "coin": "BTC/USDC",
                "bids": [{ "px": "61550", "size": "1.5", "n_orders": 2 }],
                "asks": [{ "px": "61600", "size": "0.8", "n_orders": 1 }]
            }),
        )))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let params = L2BookParams {
        n_sig_figs: Some(5),
        mantissa: Some(2),
        n_levels: Some(20),
    };
    let book = client
        .rest()
        .info()
        .l2_book("BTC/USDC", Some(&params))
        .await
        .unwrap();
    assert_eq!(book.coin, "BTC/USDC");
    assert_eq!(book.bids[0].size, "1.5");
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

// ── P2 wave-1: typed /info reads (request-body + envelope round-trip) ──

/// `order_status_by_oid` posts `{type, oid}` (no `cloid`) and decodes the filled
/// branch = the canonical fill record.
#[tokio::test]
async fn order_status_by_oid_posts_oid_and_decodes_filled() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/info"))
        .and(body_partial_json(
            json!({ "type": "order_status", "oid": 42 }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(
            "order_status",
            json!({
                "status": "filled",
                "fill": {
                    "coin": "MTF", "side": "B", "px": "0.12126000", "sz": "112.22",
                    "time": 1_784_820_001_998u64, "oid": 42u64, "tid": 7u64,
                    "fee": "0.000952", "closed_pnl": "0", "dir": "Open Long",
                    "start_position": "-357795.12", "block": 8_416_000u64, "hash": ""
                }
            }),
        )))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let st = client.rest().info().order_status_by_oid(42).await.unwrap();
    let OrderStatus::Filled { fill } = st else {
        panic!("expected Filled");
    };
    assert_eq!(fill.coin, "MTF");
    assert_eq!(fill.px, "0.12126000");
    assert_eq!(fill.block, Some(8_416_000));
}

/// `order_status_by_cloid` posts `{type, cloid}` (no `oid`) and decodes the
/// resting branch.
#[tokio::test]
async fn order_status_by_cloid_posts_cloid_and_decodes_resting() {
    let cloid = "0x0000000000000000000000000000abcd";
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/info"))
        .and(body_partial_json(
            json!({ "type": "order_status", "cloid": cloid }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(
            "order_status",
            json!({
                "status": "resting",
                "order": { "oid": 7u64, "coin": "BTC", "side": "ask", "px": "62500.12",
                           "size": "1.5", "inserted_at_ms": 1u64, "cloid": cloid }
            }),
        )))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let st = client
        .rest()
        .info()
        .order_status_by_cloid(cloid)
        .await
        .unwrap();
    let OrderStatus::Resting { order } = st else {
        panic!("expected Resting");
    };
    assert_eq!(order.oid, 7);
    assert_eq!(order.cloid.as_deref(), Some(cloid));
}

/// `historical_orders` posts `{type, address, limit}` and decodes the fold rows.
#[tokio::test]
async fn historical_orders_posts_address_and_limit() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/info"))
        .and(body_partial_json(json!({
            "type": "historical_orders", "address": ADDR, "limit": 5
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(
            "historical_orders",
            json!({
                "address": ADDR,
                "orders": [
                    { "oid": 9u64, "coin": "MTF", "side": "A", "status": "filled",
                      "time": 1_784_820_001_000u64, "px": "194.78000000",
                      "filled_sz": "112.2", "hash": "", "block": 2u64 }
                ]
            }),
        )))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let h = client
        .rest()
        .info()
        .historical_orders(test_addr(), Some(5))
        .await
        .unwrap();
    assert_eq!(h.address, Some(test_addr()));
    assert_eq!(h.orders.len(), 1);
    assert_eq!(h.orders[0].oid, 9);
    assert_eq!(h.orders[0].filled_sz, "112.2");
    assert_eq!(h.orders[0].block, Some(2));
}

/// `user_funding` omits the window keys when both bounds are `None` (exact body
/// match) and preserves a 28-digit `usdc` verbatim.
#[tokio::test]
async fn user_funding_omits_window_and_keeps_28_digit_usdc() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/info"))
        // EXACT body: no start_time / end_time keys when both are None.
        .and(body_json(
            json!({ "type": "user_funding", "address": ADDR }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(
            "user_funding",
            json!({
                "address": ADDR, "start_time": null, "end_time": null,
                "fundings": [
                    { "coin": "MTF", "time": 1_784_800_000_000u64,
                      "usdc": "0.0189543210987654321098765432",
                      "szi": "17415", "funding_rate": "-0.0005" }
                ]
            }),
        )))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let f = client
        .rest()
        .info()
        .user_funding(test_addr(), None, None)
        .await
        .unwrap();
    assert_eq!(f.fundings.len(), 1);
    assert_eq!(f.fundings[0].usdc, "0.0189543210987654321098765432");
    assert_eq!(f.start_time, None);
}

/// `user_funding` inserts the window bounds only when `Some`.
#[tokio::test]
async fn user_funding_inserts_window_when_present() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/info"))
        .and(body_json(json!({
            "type": "user_funding", "address": ADDR,
            "start_time": 5u64, "end_time": 9u64
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(
            "user_funding",
            json!({ "address": ADDR, "start_time": 5u64, "end_time": 9u64, "fundings": [] }),
        )))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let f = client
        .rest()
        .info()
        .user_funding(test_addr(), Some(5), Some(9))
        .await
        .unwrap();
    assert_eq!(f.start_time, Some(5));
    assert_eq!(f.end_time, Some(9));
}

/// `user_ledger_updates` (node kind) posts `{type, address}` and decodes the
/// envelope with raw records.
#[tokio::test]
async fn user_ledger_updates_node_kind_decodes_envelope() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/info"))
        .and(body_partial_json(json!({
            "type": "user_ledger_updates", "address": ADDR
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(
            "user_ledger_updates",
            json!({ "address": ADDR, "start_time": null, "end_time": null, "updates": [] }),
        )))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let u = client
        .rest()
        .info()
        .user_ledger_updates(test_addr(), None, None)
        .await
        .unwrap();
    assert!(u.updates.is_empty());
}

/// `user_non_funding_ledger_updates` decodes the camelCase `ledgerUpdates` union.
#[tokio::test]
async fn user_non_funding_ledger_updates_decodes_camel_union() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/info"))
        .and(body_partial_json(json!({
            "type": "user_non_funding_ledger_updates", "address": ADDR
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(
            "user_non_funding_ledger_updates",
            json!({
                "ledgerUpdates": [
                    { "coin": "USDC", "time": 1_784_800_000_001u64, "kind": "deposit",
                      "delta": "100", "counterparty": "0xabc" },
                    { "coin": "MTF", "time": 1_784_800_000_003u64, "kind": "trade",
                      "tid": 77u64, "realized_pnl": "1.5", "fee": "0.02",
                      "fee_token": "USDC" }
                ]
            }),
        )))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let l = client
        .rest()
        .info()
        .user_non_funding_ledger_updates(test_addr(), None, None)
        .await
        .unwrap();
    assert_eq!(l.ledger_updates.len(), 2);
    assert_eq!(l.ledger_updates[0].coin, "USDC");
    assert_eq!(l.ledger_updates[1].tid, Some(77));
}

/// `spot_margin_state` posts the `user` key (NOT `address`) — asserted by an
/// EXACT body match.
#[tokio::test]
async fn spot_margin_state_posts_user_key() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/info"))
        .and(body_json(
            json!({ "type": "spot_margin_state", "user": ADDR }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(
            "spot_margin_state",
            json!({
                "user": ADDR,
                "accounts": [
                    { "pair": 200u32, "collateral": "1000", "borrowed": "250.5",
                      "borrow_index_snapshot": "1.02", "base_held": "3.14",
                      "current_debt": "255.51",
                      "params": { "init_bps": "1000", "maint_bps": "500" } }
                ]
            }),
        )))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let s = client
        .rest()
        .info()
        .spot_margin_state(test_addr())
        .await
        .unwrap();
    assert_eq!(s.user, test_addr());
    assert_eq!(s.accounts.len(), 1);
    assert_eq!(s.accounts[0].pair, 200);
    assert_eq!(
        s.accounts[0].params.as_ref().unwrap().maint_bps.as_str(),
        "500"
    );
}

/// `earn_state` with a `user` inserts the `user` key and decodes per-user fields.
#[tokio::test]
async fn earn_state_with_user_inserts_key_and_decodes_user_fields() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/info"))
        .and(body_json(json!({ "type": "earn_state", "user": ADDR })))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(
            "earn_state",
            json!({
                "pools": [
                    { "asset": 0u32, "total_supplied": "10000", "total_borrowed": "4000",
                      "idle": "6000", "shares_total": "9500", "share_value": "1.0526",
                      "borrow_index": "1.03", "reserve_factor_bps": "1000",
                      "borrow_rate_bps_annual": "550", "reserve_accrued": "12.5",
                      "user_shares": "100", "user_value": "105.26" }
                ]
            }),
        )))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let e = client
        .rest()
        .info()
        .earn_state(Some(test_addr()))
        .await
        .unwrap();
    assert_eq!(e.pools.len(), 1);
    assert_eq!(e.pools[0].user_shares.as_deref(), Some("100"));
}

/// `earn_state` without a `user` omits the key (exact body = `{type}` only).
#[tokio::test]
async fn earn_state_without_user_omits_key() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/info"))
        .and(body_json(json!({ "type": "earn_state" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(
            "earn_state",
            json!({
                "pools": [
                    { "asset": 0u32, "total_supplied": "1", "total_borrowed": "0",
                      "idle": "1", "shares_total": "1", "share_value": "1",
                      "borrow_index": "1", "reserve_factor_bps": "0",
                      "borrow_rate_bps_annual": "0", "reserve_accrued": "0" }
                ]
            }),
        )))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let e = client.rest().info().earn_state(None).await.unwrap();
    assert_eq!(e.pools[0].user_shares, None);
}

/// `pm_summary` posts the `address` key (NOT `user`) — asserted by an EXACT body
/// match — and decodes the enrolled shape.
#[tokio::test]
async fn pm_summary_posts_address_key() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/info"))
        .and(body_json(json!({ "type": "pm_summary", "address": ADDR })))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(
            "pm_summary",
            json!({
                "address": ADDR, "enrolled": true,
                "enrolled_at_ms": 1_700_000_000_000u64, "last_computed_block": 8_416_000u64,
                "pm_maint_margin_cents": "123456", "net_value_cents": "10000000",
                "concentration_penalty_cents": "250"
            }),
        )))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let p = client.rest().info().pm_summary(test_addr()).await.unwrap();
    assert!(p.enrolled);
    assert_eq!(p.address, test_addr());
    assert_eq!(p.pm_maint_margin_cents, "123456");
}

/// `encode_action` posts `{type, action}` and returns the `action_json` STRING.
#[tokio::test]
async fn encode_action_returns_action_json_string() {
    let action = json!({ "type": "cancel_all_orders", "params": {} });
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/info"))
        .and(body_partial_json(json!({
            "type": "encode_action", "action": action
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(
            "encode_action",
            json!({ "action_json": "{\"CancelAllOrders\":{}}" }),
        )))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let blob = client.rest().info().encode_action(&action).await.unwrap();
    assert_eq!(blob, "{\"CancelAllOrders\":{}}");
}
