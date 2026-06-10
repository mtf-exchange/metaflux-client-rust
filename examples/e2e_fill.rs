//! End-to-end fill driver: faucet two fresh accounts, A rests an ask, B crosses
//! it with a marketable bid — produces a real fill on market 0, so the node's
//! node_fills / node_trades streams emit and the indexer materialises it.
//!
//! Env: MTF_KEY_A, MTF_KEY_B (32-byte hex), MTF_API (default 127.0.0.1:8080).

use metaflux_client::{
    Client, request_faucet,
    types::{
        MarketId,
        order::{Order, OrderKind, Side, StpMode, TimeInForce},
    },
    wallet::Wallet,
};
use serde_json::json;

fn order(owner: metaflux_client::wallet::Address, side: Side, px: u64) -> Order {
    Order {
        owner,
        market: MarketId(0),
        side,
        kind: OrderKind::Limit,
        size: 1_000,
        limit_px: px,
        tif: TimeInForce::Gtc,
        stp_mode: StpMode::CancelOldest,
        reduce_only: false,
        cloid: None,
        builder: None,
        position_side: None,
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = std::env::var("MTF_API").unwrap_or_else(|_| "http://127.0.0.1:8080".into());
    let a = Wallet::from_hex(&std::env::var("MTF_KEY_A")?)?;
    let b = Wallet::from_hex(&std::env::var("MTF_KEY_B")?)?;
    println!("A {} / B {}", a.address(), b.address());

    // A is the pre-funded dev account (genesis USDC). Only B needs the faucet —
    // a single request avoids the per-IP rate limit (both would share one IP via
    // the tunnel).
    let r = request_faucet(&base, &b.address().to_string(), None).await?;
    println!(
        "faucet B {}: usdc={} mtf={} {}",
        r.address, r.usdc, r.mtf, r.status
    );
    // Faucet credit lands on the NEXT block; give it a couple blocks.
    tokio::time::sleep(std::time::Duration::from_millis(3000)).await;

    let client = Client::new(&base)?;
    let ask = order(a.address(), Side::Ask, 6_200_000_000_000);
    let ra: serde_json::Value = client
        .exchange()
        .post_signed(&a, json!({ "type": "submit_order", "order": &ask }))
        .await?;
    println!("A-ask: {ra}");

    tokio::time::sleep(std::time::Duration::from_millis(2500)).await;

    let bid = order(b.address(), Side::Bid, 6_250_000_000_000);
    let rb: serde_json::Value = client
        .exchange()
        .post_signed(&b, json!({ "type": "submit_order", "order": &bid }))
        .await?;
    println!("B-bid: {rb}");
    Ok(())
}
