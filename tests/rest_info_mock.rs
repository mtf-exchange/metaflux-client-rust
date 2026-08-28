//! Mock-server tests for the `/info` namespace.
//!
//! Spin up a `wiremock::MockServer`, register MTF-native shaped responses,
//! and assert the SDK decodes them correctly. No real network involved.
//!
//! Every fixture is wrapped in the committed `{ "type": ..., "data": ... }`
//! envelope (`api/rest/info.md` §Envelope) so these tests also exercise the
//! REST layer's envelope-unwrap path.

use metaflux_client::{
    CandleType, Client, MarketId,
    rest::info::{Abstraction, MarketKind, OptionKind, OrderSide, OrderStatus, Tier},
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
async fn markets_meta_decodes_the_static_row() {
    let server = MockServer::start().await;
    let market = |signing_id: u32, coin: &str, max_lev: u32| {
        json!({
            "coin": coin,
            "signing_id": signing_id,
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
            "open_interest": "5000000000",
            "risk_override": null
        })
    };
    Mock::given(method("POST"))
        .and(path("/info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(
            "markets_meta",
            json!({
                "perp": [market(0, "BTC", 50), market(1, "ETH", 40)],
                "spot": { "pairs": [], "tokens": [] }
            }),
        )))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let markets = client.rest().info().markets_meta(None).await.unwrap();
    assert_eq!(markets.len(), 2);
    assert_eq!(markets[0].coin, "BTC");
    // The write handle rides the read; a null override is "no override".
    assert_eq!(markets[0].signing_id, 0);
    assert!(markets[0].risk_override.is_none());
    assert_eq!(markets[0].kind, MarketKind::Perp);
    assert_eq!(markets[0].margin_tiers.len(), 2);
    assert!(markets[0].margin_tiers[1].max_open_interest.is_none());
    assert_eq!(markets[1].coin, "ETH");
    assert_eq!(markets[1].max_leverage, 40);
}

/// The DYNAMIC `markets` read, shaped as chain 114514 served it on 2026-08-08.
/// It carries no precision grid and no leverage ladder, so it decodes into
/// `MarketDynamic`, not `MarketMeta`.
#[tokio::test]
async fn markets_decodes_the_dynamic_row() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/info"))
        .and(body_partial_json(json!({ "type": "markets" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(
            "markets",
            json!({
                "perp": [{
                    "change_24h": "0.01186283", "coin": "BTC", "day_ntl_vlm": "0",
                    "funding": { "cap_per_hr": "400", "interval_ms": 3_600_000u64,
                                 "next_payment_ts": 1_786_165_200_000u64,
                                 "rate_per_hr": "-3" },
                    "halted": false, "impact_pxs": ["64998", "65030.7"],
                    "kind": "perp", "mark_px": "65013.3", "mid_px": "65014.4",
                    "open_interest": "0.7895", "oracle_px": "65033.7",
                    "premium": "-0.00029993", "prev_day_px": "64251.1"
                }],
                "spot": { "pairs": [], "tokens": [] }
            }),
        )))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let markets = client.rest().info().markets(None).await.unwrap();
    assert_eq!(markets.len(), 1);
    assert_eq!(markets[0].coin, "BTC");
    assert_eq!(markets[0].kind, MarketKind::Perp);
    assert_eq!(markets[0].mark_px, "65013.3");
    assert_eq!(markets[0].open_interest, "0.7895");
    assert!(!markets[0].halted);
}

/// `user_position_history` is keyed by `address` and answers with the fills-style
/// envelope: the echoed address and the rows, nothing else.
#[tokio::test]
async fn user_position_history_decodes_the_fills_style_envelope() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/info"))
        .and(body_json(json!({
            "type": "user_position_history", "address": ADDR, "limit": 2
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(
            "user_position_history",
            json!({
                "address": ADDR,
                "positions": [{
                    "avg_close_px": "74.75000000", "avg_entry_px": null,
                    "close_block": 6_831_775u64, "close_complete": false,
                    "closed_at": 1_786_162_051_867u64, "closed_pnl": "0.8960000000",
                    "closed_sz": "0.80", "coin": "SOL", "entry_complete": false,
                    "fee_paid": "0.001794", "funding_complete": false,
                    "funding_paid": "0", "max_sz": null, "net_pnl": "0.8942060000",
                    "open_block": 6_831_775u64, "opened_at": 1_786_162_051_867u64,
                    "realized_pnl": "0.8942060000", "side": "long"
                }]
            }),
        )))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let h = client
        .rest()
        .info()
        .user_position_history(test_addr(), Some(2))
        .await
        .unwrap();
    assert_eq!(h.address, test_addr());
    let p = &h.positions[0];
    assert_eq!(p.coin, "SOL");
    assert_eq!(p.closed_sz, "0.80");
    // A degraded row reports itself and nulls the numbers it cannot stand behind.
    assert!(!p.entry_complete);
    assert!(p.avg_entry_px.is_none());
    assert!(p.max_sz.is_none());
}

/// `user_position_history_by_time` sends the window and does NOT get it echoed
/// back — unlike a ranged `user_fills`, whose reply carries the bounds.
#[tokio::test]
async fn user_position_history_by_time_sends_the_window() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/info"))
        .and(body_json(json!({
            "type": "user_position_history_by_time", "address": ADDR,
            "start_time": 1_786_000_000_000u64, "end_time": 1_786_200_000_000u64
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(
            "user_position_history_by_time",
            json!({ "address": ADDR, "positions": [] }),
        )))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let h = client
        .rest()
        .info()
        .user_position_history_by_time(
            test_addr(),
            Some(1_786_000_000_000),
            Some(1_786_200_000_000),
        )
        .await
        .unwrap();
    assert!(h.positions.is_empty());
}

#[tokio::test]
async fn vault_state_is_keyed_by_address_and_reads_the_human_plane() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/info"))
        .and(body_partial_json(
            json!({ "type": "vault_state", "vault": ADDR }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(
            "vault_state",
            json!({
                "vault": ADDR,
                "name": "mlp",
                "tvl": "50000",
                "share_price": "1.000000000000000001",
                "depositor_count": 3,
                "high_water_mark": "50000",
                "performance_fee_bps": "1000",
                "lock_period_ms": 345_600_000u64,
                "strategy": "Metaliquidity"
            }),
        )))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let v = client.rest().info().vault_state(test_addr()).await.unwrap();
    assert_eq!(v.vault, ADDR);
    assert_eq!(v.name, "mlp");
    // Whole USDC, not cents.
    assert_eq!(v.tvl, "50000");
    assert_eq!(v.high_water_mark, "50000");
    // Whole USDC per WHOLE share, full precision — no client-side share scaling.
    assert_eq!(v.share_price, "1.000000000000000001");
    assert_eq!(v.performance_fee_bps, "1000");
    // A DURATION keeps its `_ms` suffix.
    assert_eq!(v.lock_period_ms, 345_600_000);
    assert_eq!(v.strategy, "Metaliquidity");
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
    assert_eq!(f.builder_rebate_bps.as_deref(), Some("0"));
}

/// A current server sends no `builder_rebate_bps`. The read must still succeed.
#[tokio::test]
async fn fee_schedule_decodes_without_builder_rebate() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(
            "fee_schedule",
            json!({
                "maker_bps": "1.0",
                "taker_bps": "5.0",
                "referrer_share_bps": "5.0",
                "burn_ratio": "0.8",
                "tiers": [{ "maker_bps": "1.0", "taker_bps": "5.0", "volume_30d": "0" }]
            }),
        )))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let f = client.rest().info().fee_schedule().await.unwrap();
    assert!(f.builder_rebate_bps.is_none());
    assert_eq!(f.referrer_share_bps, "5.0");
    assert_eq!(f.tiers.len(), 1);
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
                                            "evm_extra_wei_decimals": -2, "variant": 2 },
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
    // `variant` folds in from the retired `evm_contract_bindings` read.
    assert_eq!(m.tokens[0].evm_contract.as_ref().unwrap().variant, Some(2));
    assert_eq!(m.tokens[0].total_supply, "21000000");
    assert_eq!(m.tokens[1].name, "USDC");
    assert_eq!(m.tokens[1].wei_decimals, 6);
    // Minimal token row (no evm block) still decodes via defaults.
    assert!(m.tokens[1].evm_contract.is_none());
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
    let err = client.rest().info().markets(None).await.unwrap_err();
    match err {
        metaflux_client::ClientError::ProtocolError { code, msg } => {
            assert_eq!(code, 400);
            assert!(msg.contains("unknown info type"));
        }
        other => panic!("expected ProtocolError, got {other:?}"),
    }
}

#[tokio::test]
async fn option_series_posts_the_bare_type_and_decodes_both_kinds() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/info"))
        .and(body_json(json!({ "type": "option_series" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(
            "option_series",
            json!({
                "series": [
                    { "signing_id": 2_147_483_649u32, "underlying": "BTC", "kind": "put",
                      "strike": "100000", "expiry": 1_735_689_600_000u64, "sz_decimals": 5,
                      "escrow_per_unit": "100000" },
                    { "signing_id": 2_147_483_650u32, "underlying": "BTC", "kind": "capped_call",
                      "strike": "100000", "cap": "130000", "expiry": 1_735_689_600_000u64,
                      "sz_decimals": 5, "escrow_per_unit": "30000" }
                ]
            }),
        )))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let r = client.rest().info().option_series().await.unwrap();
    assert_eq!(r.series.len(), 2);
    // The signing id is served whole — it is the number an RFQ action carries.
    assert_eq!(r.series[0].signing_id, MarketId(2_147_483_649));
    assert_eq!(r.series[0].kind, OptionKind::Put);
    assert_eq!(r.series[0].cap, None);
    // A capped call escrows the WIDTH, not the strike.
    assert_eq!(r.series[1].kind, OptionKind::CappedCall);
    assert_eq!(r.series[1].cap.as_deref(), Some("130000"));
    assert_eq!(r.series[1].escrow_per_unit, "30000");
}

#[tokio::test]
async fn option_positions_sends_the_address_and_keeps_the_two_planes_apart() {
    let server = MockServer::start().await;
    let who = "0xa1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
    Mock::given(method("POST"))
        .and(path("/info"))
        .and(body_json(
            json!({ "type": "option_positions", "address": who }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(
            "option_positions",
            json!({
                "address": who,
                "positions": [
                    { "signing_id": 2_147_483_650u32, "underlying": "BTC",
                      "kind": "capped_call", "strike": "100000",
                      "expiry": 1_735_689_600_000u64,
                      "long": "0", "short": "1.5", "escrow": "45000" }
                ]
            }),
        )))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let r = client
        .rest()
        .info()
        .option_positions(Address::from_hex(who).unwrap())
        .await
        .unwrap();
    assert_eq!(r.positions.len(), 1);
    assert_eq!(r.positions[0].signing_id, MarketId(2_147_483_650));
    assert_eq!(r.positions[0].kind, OptionKind::CappedCall);
    // `short` is a UNIT count on the series size scale ...
    assert_eq!(r.positions[0].short, "1.5");
    // ... and `escrow` is USDC. Reading one as the other is the failure the
    // read documents; both are strings, so only the field name separates them.
    assert_eq!(r.positions[0].escrow, "45000");
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
                "withdrawable": "80000000",
                "total_margin_used": "20000000",
                "total_raw_usd": "99500000",
                "total_ntl_pos": "64000",
                "health": "10000000",
                "tier": "Safe",
                "abstraction": "unified",
                "position_mode": "one_way",
                "clearinghouse_state": {
                    "": { "positions": [{
                        "coin": "BTC", "size": "1", "entry": "64000", "upnl": "500000",
                        "isolated": false, "lev": 10, "liq": "58000", "roe": "0.01",
                        "funding": "0", "margin": "6400", "maint_margin": "320",
                        "notional": "64000"
                    }] }
                },
                "balances": [
                    { "name": "USDC", "signing_id": 0, "total": "100000000", "hold": "0" },
                    { "name": "ETH", "signing_id": 102, "total": "5000000000", "hold": "0" }
                ],
                "pm_maint_margin": "0",
                "pm_net_value": "0",
                "pm_concentration_penalty": "0",
                "height": 8_416_000u64,
                "time": 1_783_011_600_000u64
            }),
        )))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let addr = Address::from_hex("0x000000000000000000000000000000000000beef").unwrap();
    let a = client
        .rest()
        .info()
        .account_state(addr, None)
        .await
        .unwrap();
    assert_eq!(a.account_value, "100000000");
    assert_eq!(a.withdrawable, "80000000");
    assert_eq!(a.total_margin_used, "20000000");
    assert_eq!(a.total_raw_usd, "99500000");
    assert_eq!(a.total_ntl_pos.as_deref(), Some("64000"));
    assert_eq!(a.tier, Tier::Safe);
    assert_eq!(a.abstraction, Abstraction::Unified);
    // Positions live under the core dex key `""`.
    assert_eq!(a.core_positions().len(), 1);
    assert_eq!(a.core_positions()[0].coin, "BTC");
    assert_eq!(a.core_positions()[0].leverage, 10);
    assert_eq!(a.core_positions()[0].maint_margin, "320");
    // Balances are an array; USDC first.
    assert_eq!(a.balances[0].name, "USDC");
    assert_eq!(a.balances[1].name, "ETH");
    assert_eq!(a.balances[1].total, "5000000000");
    assert_eq!(a.pm_net_value, "0");
    assert_eq!(a.height, 8_416_000);
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
    assert_eq!(s.state.total_staked, "0");
    assert!(s.state.delegations.is_empty());
}

#[tokio::test]
async fn l2_book_decodes_levels() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(
            "l2_book",
            json!({
                "bids": [{ "px": "4990000000000", "sz": "1000", "n_orders": 3 }],
                "asks": [{ "px": "5010000000000", "sz": "800", "n_orders": 2 }]
            }),
        )))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let book = client.rest().info().l2_book("BTC", None).await.unwrap();
    assert_eq!(book.bids.len(), 1);
    assert_eq!(book.bids[0].sz, "1000");
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
                "bids": [{ "px": "61550", "sz": "1.5", "n_orders": 2 }],
                "asks": [{ "px": "61600", "sz": "0.8", "n_orders": 1 }]
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
    assert_eq!(book.bids[0].sz, "1.5");
}

fn price_bar(n: u64) -> Value {
    json!({
        "s": "BTC", "i": "1m",
        "t": 1_700_000_040_000u64, "T": 1_700_000_099_999u64,
        "o": "67000.0", "c": "67042.5",
        "h": "67080.0", "l": "66990.0",
        "v": "0", "q": "0", "n": n
    })
}

#[tokio::test]
async fn candle_snapshot_decodes_gateway_envelope() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(
            "candle_snapshot",
            json!({ "candles": [price_bar(12)] }),
        )))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let bars = client
        .rest()
        .info()
        .candle_snapshot(
            "BTC",
            "1m",
            CandleType::Mark,
            1_700_000_000_000,
            1_700_000_100_000,
        )
        .await
        .unwrap();
    assert_eq!(bars.len(), 1);
    assert_eq!(bars[0].coin, "BTC");
    assert_eq!(bars[0].close, "67042.5");
    // A price bar folds no trades.
    assert_eq!(bars[0].volume, "0");
    assert_eq!(bars[0].quote_volume, "0");
    assert_eq!(bars[0].num_samples, 12);
}

/// The request carries `candle_type` inside `req`, spelled with the node's
/// field name. Without it the node serves the DEFAULT series, so an oracle
/// chart would silently render mark prices.
#[tokio::test]
async fn candle_snapshot_sends_the_requested_candle_type() {
    for (ct, token) in [(CandleType::Mark, "mark"), (CandleType::Oracle, "oracle")] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/info"))
            .and(body_json(json!({
                "type": "candle_snapshot",
                "req": {
                    "coin": "BTC",
                    "interval": "1m",
                    "candle_type": token,
                    "start_time": 0,
                    "end_time": 1_700_000_100_000u64,
                },
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(envelope(
                "candle_snapshot",
                json!({ "candles": [price_bar(3)] }),
            )))
            .mount(&server)
            .await;

        let client = Client::new(server.uri()).unwrap();
        let bars = client
            .rest()
            .info()
            .candle_snapshot("BTC", "1m", ct, 0, 1_700_000_100_000)
            .await
            .unwrap();
        assert_eq!(bars.len(), 1, "{token} request body must match exactly");
    }
}

#[tokio::test]
async fn ranged_trades_decode_symbol_prints() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(
            "trades",
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
        .trades("BTC", Some(0), Some(9_999_999_999_999))
        .await
        .unwrap();
    assert_eq!(trades.len(), 1);
    assert_eq!(trades[0].coin, "BTC");
    assert_eq!(trades[0].side, "A");
    assert_eq!(trades[0].tid, 18_232_248_797_686_447_553);
    assert!(
        trades[0]
            .hash
            .as_deref()
            .is_some_and(|h| h.starts_with("0x"))
    );
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
                "order": { "oid": 7u64, "coin": "BTC", "side": "A", "px": "62500.12",
                           "sz": "1.5", "inserted_at": 1u64, "cloid": cloid }
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
    assert_eq!(order.side, OrderSide::Ask);
    assert_eq!(order.sz, "1.5");
    assert_eq!(order.inserted_at, 1);
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
    assert_eq!(h.orders[0].px.as_deref(), Some("194.78000000"));
}

/// `historical_orders` decodes a row that carries no price. A market order that
/// never rested has no average fill price and no limit price, so the server sends
/// no `px` key. A row that reports the price sources sends them as `null`. Both
/// shapes must decode, and one such row must not fail the whole response.
#[tokio::test]
async fn historical_orders_decodes_rows_with_no_price() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/info"))
        .and(body_partial_json(json!({
            "type": "historical_orders", "address": ADDR
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(
            "historical_orders",
            json!({
                "address": ADDR,
                "orders": [
                    { "oid": 11u64, "coin": "MTF", "side": "B", "status": "error",
                      "time": 30u64, "filled_sz": "0", "hash": "" },
                    { "oid": 12u64, "coin": "MTF", "side": "B", "status": "resting",
                      "time": 31u64, "filled_sz": "0", "hash": "", "px": null,
                      "limit_px": null, "avg_px": null },
                    { "oid": 13u64, "coin": "MTF", "side": "A", "status": "filled",
                      "time": 32u64, "filled_sz": "1.5", "hash": "",
                      "px": "194.78000000" }
                ]
            }),
        )))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let h = client
        .rest()
        .info()
        .historical_orders(test_addr(), None)
        .await
        .unwrap();
    assert_eq!(h.orders.len(), 3);
    assert_eq!(h.orders[0].px, None);
    assert_eq!(h.orders[1].px, None);
    assert_eq!(h.orders[2].px.as_deref(), Some("194.78000000"));
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
                    { "pair": "BTC/USDC", "collateral": "1000", "borrowed": "250.5",
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
    // The pair is SYMBOLIZED — a raw numeric pair id no longer reaches a client.
    assert_eq!(s.accounts[0].pair, "BTC/USDC");
    // `init_bps` / `maint_bps` are JSON STRINGS of integers; do not normalize
    // them to numbers.
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
                    { "name": "USDC", "signing_id": 0, "total_supplied": "10000", "total_borrowed": "4000",
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
                    { "name": "USDC", "signing_id": 0, "total_supplied": "1", "total_borrowed": "0",
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
    // Every numeric asset id now travels beside its symbol.
    assert_eq!(e.pools[0].name, "USDC");
}

/// `open_orders` decodes ONE canonical row set: a perp resting order, a spot
/// resting order, and a parked TP / SL trigger. The trigger detail the retired
/// `frontend_open_orders` read carried now rides this row.
#[tokio::test]
async fn open_orders_decodes_the_enriched_canonical_row() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/info"))
        .and(body_json(json!({ "type": "open_orders", "address": ADDR })))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(
            "open_orders",
            json!({
                "address": ADDR,
                "orders": [
                    { "oid": 1u64, "coin": "BTC", "side": "B", "px": "62500.12",
                      "sz": "1.5", "orig_sz": null, "cloid": null, "tif": "gtc",
                      "reduce_only": false, "trigger": null, "inserted_at": 10u64 },
                    { "oid": 2u64, "coin": "BTC/USDC", "side": "A", "px": "62800",
                      "sz": "0.5", "orig_sz": null, "cloid": null, "tif": "alo",
                      "reduce_only": false, "trigger": null, "inserted_at": 11u64 },
                    { "oid": 3u64, "coin": "BTC", "side": "A", "px": "61000",
                      "sz": "0.25", "orig_sz": null, "cloid": null, "tif": "trigger",
                      "reduce_only": true,
                      "trigger": { "trigger_px": "61000", "trigger_above": false,
                                   "is_parked": true, "is_market": true,
                                   "limit_px": null },
                      "inserted_at": 12u64 }
                ]
            }),
        )))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let o = client.rest().info().open_orders(test_addr()).await.unwrap();
    assert_eq!(o.orders.len(), 3);
    assert_eq!(o.orders[0].side, OrderSide::Bid);
    assert_eq!(o.orders[0].sz, "1.5");
    assert_eq!(o.orders[0].inserted_at, 10);
    // A spot row's coin is the pair NAME.
    assert_eq!(o.orders[1].coin, "BTC/USDC");
    assert_eq!(o.orders[1].side, OrderSide::Ask);
    // A parked market trigger: `tif` is the non-TIF token, `limit_px` is null.
    assert_eq!(o.orders[2].tif.as_deref(), Some("trigger"));
    let t = o.orders[2].trigger.as_ref().unwrap();
    assert_eq!(t.is_market, Some(true));
    assert!(t.limit_px.is_none());
}

/// The `detail: "overview"` shape of `account_state`: one round trip for the
/// vault / staking / sub-account / multisig / agent facets, plus the flat
/// `height` / `time` stamp. The EXACT body match pins the folded parameter.
#[tokio::test]
async fn account_overview_decodes_every_facet() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/info"))
        .and(body_json(
            json!({ "type": "account_state", "address": ADDR, "detail": "overview" }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(
            "account_state",
            json!({
                "address": ADDR,
                "vault": {
                    "equities": [
                        { "vault_id": 7u64,
                          "vault_address": "0x00000000000000000000000000000000000000aa",
                          "shares": "12.5", "equity": "1250" }
                    ],
                    "vaults": [
                        { "vault": "0x00000000000000000000000000000000000000aa",
                          "name": "mlp", "tvl": "50000",
                          "share_price": "1.000000000000000001", "depositor_count": 3,
                          "high_water_mark": "50000", "performance_fee_bps": "1000",
                          "lock_period_ms": 345_600_000u64, "strategy": "Metaliquidity" }
                    ]
                },
                "staking": {
                    "state": {
                        "total_staked": "500",
                        "delegations": [
                            { "validator": "0x00000000000000000000000000000000000000bb",
                              "amount": "500", "since_ts": 1_700_000_000_000u64,
                              "pending_rewards": "2.5" }
                        ],
                        "pending_unstakes": [
                            { "amount": "100", "matures_at_ts": 1_800_000_000_000u64 }
                        ]
                    },
                    "summary": {
                        "total_delegated": "500", "pending_withdrawal": "100",
                        "claimable_rewards": "2.5", "n_delegations": 1u64
                    }
                },
                "sub_accounts": [
                    { "index": 0u32,
                      "address": "0x00000000000000000000000000000000000000cc",
                      "equity": "42" }
                ],
                "multisig": {
                    "is_multi_sig": true, "threshold": 2u32,
                    "signers": ["0x00000000000000000000000000000000000000dd"]
                },
                "agents": [
                    { "agent": "0x00000000000000000000000000000000000000ee",
                      "name": "bot-1", "expires_at": 1_800_000_000_000u64 }
                ],
                "height": 8_416_000u64,
                "time": 1_783_011_600_000u64
            }),
        )))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let w = client
        .rest()
        .info()
        .account_overview(test_addr())
        .await
        .unwrap();
    assert_eq!(w.address, test_addr());

    // Vault facet: whole-share equity + the full vault body on the human plane.
    assert_eq!(w.vault.equities[0].vault_id, 7);
    assert_eq!(w.vault.equities[0].shares, "12.5");
    assert_eq!(w.vault.vaults[0].share_price, "1.000000000000000001");
    // A DURATION keeps `_ms`.
    assert_eq!(w.vault.vaults[0].lock_period_ms, 345_600_000);

    // Staking facet: the per-facet address is stripped; `_ts` suffixes stay.
    assert_eq!(w.staking.state.total_staked, "500");
    assert_eq!(w.staking.state.delegations[0].since_ts, 1_700_000_000_000);
    assert_eq!(
        w.staking.state.pending_unstakes[0].matures_at_ts,
        1_800_000_000_000
    );
    assert_eq!(w.staking.summary.n_delegations, 1);

    assert_eq!(w.sub_accounts[0].equity, "42");
    assert!(w.multisig.is_multi_sig);
    assert_eq!(w.multisig.threshold, 2);
    // The agent expiry dropped its `_ms` suffix.
    assert_eq!(w.agents[0].expires_at, Some(1_800_000_000_000));

    // The stamp is FLAT at the top level, not nested under `as_of`.
    assert_eq!(w.height, 8_416_000);
    assert_eq!(w.time, 1_783_011_600_000);
}

/// `funding_history` samples key on `ts`, and the `markets` funding block keys on
/// `next_funding_ts` — the `_ms` suffix is gone from every /info timestamp.
#[tokio::test]
async fn funding_history_sample_keys_on_ts() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/info"))
        .and(body_json(
            json!({ "type": "funding_history", "coin": "MTF" }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(
            "funding_history",
            json!({
                "coin": "MTF",
                "samples": [
                    { "ts": 1_783_011_600_000u64, "premium": "0.01",
                      "funding_rate": "0.01" }
                ]
            }),
        )))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let fh = client.rest().info().funding_history("MTF").await.unwrap();
    assert_eq!(fh.samples[0].ts, 1_783_011_600_000);
    assert_eq!(fh.samples[0].premium, "0.01");
}

/// The node answers an unknown `/info` kind with 400. `frontend_open_orders`
/// was removed, so the SDK must no longer expose a method for it — this test
/// pins the server behavior a caller now sees.
#[tokio::test]
async fn retired_frontend_open_orders_kind_is_rejected() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/info"))
        .and(body_partial_json(json!({ "type": "frontend_open_orders" })))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_json(json!({ "error": "unknown info type: frontend_open_orders" })),
        )
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let err = client
        .rest()
        .info()
        .raw(json!({ "type": "frontend_open_orders", "address": ADDR }))
        .await
        .unwrap_err();
    assert!(format!("{err}").contains("frontend_open_orders"));
}

/// `bridge_withdrawal_history` carries the folded deployment rows: a depositor with no
/// in-flight withdrawal still gets `withdrawals_halted` + `configs`, so the
/// retired `bridge_chain_configs` ask costs one round trip here too.
#[tokio::test]
async fn bridge_withdrawal_history_carries_the_folded_configs() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/info"))
        .and(body_json(
            json!({ "type": "bridge_withdrawal_history", "address": ADDR }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(
            "bridge_withdrawal_history",
            json!({
                "entries": [],
                "truncated": false,
                "withdrawals_halted": true,
                "configs": [{
                    "chain": 1u8,
                    "contract_address": "0x0000000000000000000000000000000000000000000000000000000000000abc",
                    "validator_quorum_threshold_bps": "6700",
                    "replay_nonce": 42u64,
                    "paused": false,
                    "evm_chain_id": 8453u64,
                    "evm_contract_address": "0x0000000000000000000000000000000000000abc",
                    "validator_set_epoch": 7u64,
                    "release_retention_ms": 0u64,
                    "effective_release_retention_ms": 86_400_000u64,
                    "scan_policy": {
                        "confirmations_only": false,
                        "confirmations": 0u64,
                        "effective_confirmations": 5u64,
                        "confirmations_only_depth": 0u64,
                        "usdc_token": "0x0000000000000000000000000000000000000def",
                        "raw_transfer_credit": true
                    }
                }]
            }),
        )))
        .mount(&server)
        .await;

    let client = Client::new(server.uri()).unwrap();
    let o = client
        .rest()
        .info()
        .bridge_withdrawal_history(test_addr(), None)
        .await
        .unwrap();
    assert!(o.entries.is_empty());
    assert!(o.withdrawals_halted);
    assert_eq!(o.configs.len(), 1);
    let row = &o.configs[0];
    assert_eq!(row.chain, 1);
    assert_eq!(row.evm_chain_id, 8453);
    assert_eq!(row.validator_set_epoch, 7);
    // Read the effective window, never the 0-as-unset raw one.
    assert_eq!(row.effective_release_retention_ms, 86_400_000);
    assert_eq!(row.scan_policy.effective_confirmations, 5);
}
