//! Place a resting BTC bid against a local devnet node and print the returned
//! per-order status (oid if it rested, fill detail if it crossed).
//!
//! Targets a node at `http://127.0.0.1:8080`. The SDK signs against the
//! MTF testnet/devnet EIP-712 domain chain id (`MTF_CHAIN_ID` = 114514;
//! mainnet is 8964); signing against the wrong chain id makes the node
//! recover a different address and reject (401).
//!
//! Dev key (address `0x17c5185167401ed00cf5f5b2fc97d9bbfdb7d025`): pass
//! `MTF_PRIVATE_KEY=0x4242424242424242424242424242424242424242424242424242424242424242`.
//!
//! ```bash
//! MTF_PRIVATE_KEY=0x4242...4242 cargo run --example submit_limit_order
//! ```

use metaflux_client::{
    Client,
    rest::exchange::MTF_CHAIN_ID,
    types::{
        MarketId,
        order::{Order, OrderKind, OrderStatus, Side, StpMode, TimeInForce},
    },
    wallet::Wallet,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let priv_hex = std::env::var("MTF_PRIVATE_KEY")
        .map_err(|_| "set MTF_PRIVATE_KEY=<64-char hex> to run this example")?;
    let wallet = Wallet::from_hex(&priv_hex)?;
    println!("wallet address: {}", wallet.address());
    println!("signing against devnet chain id {MTF_CHAIN_ID}");

    let client = Client::new("http://127.0.0.1:8080")?;

    // Devnet: BTC is genesis market 0.
    let btc = MarketId(0);
    println!("using BTC market {}", btc.0);

    // A tiny resting bid below mark — won't fill, easy to cancel.
    let order = Order {
        owner: wallet.address(),
        market: btc,
        side: Side::Bid,
        kind: OrderKind::Limit,
        size: 1_000,                 // 0.001 BTC if size_decimals = 6
        limit_px: 4_000_000_000_000, // $40,000 in tick units
        tif: TimeInForce::Gtc,
        stp_mode: StpMode::CancelOldest,
        reduce_only: false,
        cloid: None,
        builder: None,
        position_side: None, // one-way account
    };

    let resp = client.exchange().submit_order(&wallet, &order).await?;
    // The `Order` action returns a per-order status union, one entry per order.
    for (i, status) in resp.statuses.iter().enumerate() {
        match status {
            OrderStatus::Resting(r) => {
                println!("order[{i}] resting: oid={} cloid={:?}", r.oid.0, r.cloid);
            }
            OrderStatus::Filled(f) => {
                println!(
                    "order[{i}] filled: oid={} total_sz={} avg_px={}",
                    f.oid.0, f.total_sz, f.avg_px
                );
            }
            OrderStatus::Error(msg) => {
                println!("order[{i}] rejected: {msg}");
            }
        }
    }
    Ok(())
}
