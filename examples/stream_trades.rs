//! Connect to the MTF WS endpoint, subscribe to BTC-PERP trades, print first 10.
//!
//! Run with:
//!
//! ```bash
//! cargo run --example stream_trades
//! ```

use metaflux_client::{
    types::MarketId,
    ws::{WsClient, WsMessage},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ws_url = std::env::var("MTF_WS_URL")
        .unwrap_or_else(|_| "wss://api.devnet.mtf.exchange/ws".into());
    println!("connecting to {ws_url}");
    let ws = WsClient::connect(ws_url).await?;
    let mut rx = ws.messages();

    // Subscribe to BTC-PERP (assumed market_id = 1).
    ws.subscribe_trades(MarketId(1)).await?;

    let mut got = 0u32;
    while got < 10 {
        let msg = rx.recv().await?;
        if let WsMessage::Trades(payload) = &msg {
            println!("trade: {payload}");
            got += 1;
        }
    }
    ws.shutdown().await;
    Ok(())
}
