//! Submit a small limit order on a hard-coded market.
//!
//! Requires `MTF_PRIVATE_KEY` env var. Run with:
//!
//! ```bash
//! MTF_PRIVATE_KEY=0x... cargo run --example submit_limit_order
//! ```

use metaflux_client::{
    Client,
    types::{
        MarketId,
        order::{Order, OrderKind, Side, StpMode, TimeInForce},
    },
    wallet::Wallet,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let priv_hex = std::env::var("MTF_PRIVATE_KEY")
        .map_err(|_| "set MTF_PRIVATE_KEY=<64-char hex> to run this example")?;
    let wallet = Wallet::from_hex(&priv_hex)?;
    println!("wallet address: {}", wallet.address());

    let client = Client::new("https://api.mtf.exchange")?;

    // Pull the market list to confirm we're talking to a live node.
    let markets = client.rest().info().markets().await?;
    println!("found {} markets", markets.len());
    let market = markets
        .iter()
        .find(|m| m.symbol == "BTC")
        .ok_or("no BTC-PERP market available")?;
    println!("using {}", market.symbol);

    // Build a tiny resting bid 10% below mark — won't fill, easy to cancel.
    let order = Order {
        owner: wallet.address(),
        market: MarketId(market.market_id.0),
        side: Side::Bid,
        kind: OrderKind::Limit,
        size: 1_000,                 // 0.001 BTC if size_decimals = 6
        limit_px: 4_000_000_000_000, // $40,000 in tick units
        tif: TimeInForce::Gtc,
        stp_mode: StpMode::CancelOldest,
        reduce_only: false,
        coid: None,
    };
    let resp = client.exchange().submit_order(&wallet, &order).await?;
    println!("submitted: {resp:?}");
    Ok(())
}
