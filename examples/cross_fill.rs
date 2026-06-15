//! Drive a real fill on the local devnet: account A rests an ask, account B
//! crosses it with a marketable bid. Raw `Value` responses (bypasses the typed
//! OrderResponse) so we see exactly what the node returns. Used to live-verify
//! the WS `candles` channel (the fill folds into an OHLCV bar pushed per commit).

use metaflux_client::{
    Client,
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
        position_side: None, // one-way account
        trigger: None,
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let a = Wallet::from_hex(&std::env::var("MTF_KEY_A")?)?;
    let b = Wallet::from_hex(&std::env::var("MTF_KEY_B")?)?;
    println!("A (maker/ask): {}", a.address());
    println!("B (taker/bid): {}", b.address());
    let client = Client::new("http://127.0.0.1:8080")?;

    let ask = order(a.address(), Side::Ask, 6_200_000_000_000);
    let ra: serde_json::Value = client
        .exchange()
        .post_signed(&a, json!({ "type": "submit_order", "order": &ask }))
        .await?;
    println!("A-ask raw: {ra}");

    tokio::time::sleep(std::time::Duration::from_millis(2500)).await;

    let bid = order(b.address(), Side::Bid, 6_250_000_000_000);
    let rb: serde_json::Value = client
        .exchange()
        .post_signed(&b, json!({ "type": "submit_order", "order": &bid }))
        .await?;
    println!("B-bid raw: {rb}");
    Ok(())
}
