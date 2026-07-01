//! Decisive LIVE matcher probe: two FRESH fauceted accounts. A rests a GTC bid;
//! B immediately crosses it with an IOC ask. Both via the `batch_order` path the
//! data bot uses. This bypasses the stale-`l2_book`-publication question: if B
//! fills A, the live matcher works (so frozen volume = makers not replenishing /
//! stale publication). If B does NOT fill A, the live matcher is genuinely broken.
//!
//! Env: MTF_API (gateway base URL).

use metaflux_client::{
    Client,
    faucet::request_faucet,
    types::{
        MarketId,
        order::{BatchOrder, Order, OrderGrouping, OrderKind, Side, StpMode, TimeInForce},
    },
    wallet::Wallet,
};
use serde_json::Value;

fn ord(owner: metaflux_client::wallet::Address, side: Side, px: u64, tif: TimeInForce) -> Order {
    Order {
        owner,
        market: MarketId(0),
        side,
        kind: OrderKind::Limit,
        size: 1_007,
        limit_px: px,
        tif,
        stp_mode: StpMode::CancelOldest,
        reduce_only: false,
        cloid: None,
        builder: None,
        position_side: None,
        trigger: None,
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = std::env::var("MTF_API").unwrap_or_else(|_| "http://127.0.0.1:8080".into());
    let a = Wallet::from_hex("0x9a7c3f11de42b8061122334455667788990011223344556677889900aabbccdd")?;
    let b = Wallet::from_hex("0x4b2e8d6604f1a93cc0ddee0011223344556677889900aabbccddeeff00112233")?;
    println!("A(maker) {} / B(taker) {}", a.address(), b.address());

    for (who, w) in [("A", &a), ("B", &b)] {
        match request_faucet(&base, &w.address().to_string(), None).await {
            Ok(r) => println!("faucet {who}: usdc={} {}", r.usdc, r.status),
            Err(e) => println!("faucet {who}: skipped ({e})"),
        }
    }
    tokio::time::sleep(std::time::Duration::from_millis(5000)).await;

    let client = Client::new(&base)?;

    // A rests a GTC BID at $64,000 (x1e8) — below the resting ask side so it rests.
    let a_bid = ord(a.address(), Side::Bid, 6_400_700_000_000, TimeInForce::Gtc);
    let ra: Value = client
        .exchange()
        .batch_order(
            &a,
            &BatchOrder {
                owner: a.address(),
                orders: vec![a_bid],
                grouping: OrderGrouping::Na,
            },
        )
        .await?;
    println!("A rest bid: {ra}");
    tokio::time::sleep(std::time::Duration::from_millis(2500)).await;

    // B crosses with an IOC ASK at $63,000 — crosses A's $64,000 bid.
    let b_ask = ord(b.address(), Side::Ask, 6_300_700_000_000, TimeInForce::Ioc);
    let rb: Value = client
        .exchange()
        .batch_order(
            &b,
            &BatchOrder {
                owner: b.address(),
                orders: vec![b_ask],
                grouping: OrderGrouping::Na,
            },
        )
        .await?;
    println!("B cross ask: {rb}");
    println!("A addr {} / B addr {}", a.address(), b.address());
    Ok(())
}
