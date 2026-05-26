//! End-to-end MIP-3 deploy demo.
//!
//! Steps:
//! 1. Read `MTF_PRIVATE_KEY` and build a wallet.
//! 2. Bid in the perp-deploy gas auction.
//! 3. Await our pending deploy credit (2-minute timeout for the demo).
//! 4. Customise [`metaflux_client::mip3::templates::long_tail_perp_default`]
//!    and submit the 8-action deploy sequence.
//! 5. Print the resulting `asset_id` parsed from the final activate response.
//!
//! Run with:
//!
//! ```bash
//! MTF_PRIVATE_KEY=0x... cargo run --example mip3_full_deploy
//! ```

use std::time::Duration;

use metaflux_client::{
    Client,
    mip3::{
        auction::{AuctionBid, AuctionKind},
        templates,
    },
    wallet::Wallet,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let priv_hex = std::env::var("MTF_PRIVATE_KEY")
        .map_err(|_| "set MTF_PRIVATE_KEY=<64-char hex> to run this example")?;
    let wallet = Wallet::from_hex(&priv_hex)?;
    let client = Client::new("https://api.mtf.exchange")?;
    println!("wallet address: {}", wallet.address());

    // 1. Bid in the gas auction. The amount here is a placeholder — query
    // the current auction state first in real flows to avoid underbidding.
    let receipt = client
        .submit_gas_auction_bid(
            &wallet,
            AuctionBid {
                kind: AuctionKind::PerpDeploy,
                bid_amount_usdc_cents: 150_000_000, // $1.5M
            },
        )
        .await?;
    println!(
        "bid receipt: round={} accepted={}c status={}",
        receipt.round_id, receipt.accepted_amount_usdc_cents, receipt.status
    );

    // 2. Wait for the credit (2-minute timeout for demo).
    client
        .await_deploy_credit(&wallet, Duration::from_secs(120))
        .await?;
    println!("deploy credit acquired");

    // 3. Customise the long-tail preset.
    let builder = templates::long_tail_perp_default()
        .with_asset_name("BANANA-PERP")
        .with_asset_symbol("BANANA");
    builder.validate()?;
    let sequence = builder.deploy_sequence();
    println!("submitting {} actions...", sequence.len());

    // 4. Submit each action in order. Assert each succeeds (any HTTP error
    // bubbles up via `?` and aborts the demo).
    let mut last_resp = serde_json::Value::Null;
    for (i, action) in sequence.iter().enumerate() {
        let resp: serde_json::Value = client
            .rest()
            .exchange()
            .post_signed(&wallet, action.to_json())
            .await?;
        println!(
            "  [{}/{}] {} -> {}",
            i + 1,
            sequence.len(),
            action.type_id(),
            resp
        );
        last_resp = resp;
    }

    // 5. Extract `asset_id` from the final activate response (best-effort).
    if let Some(id) = last_resp.get("asset_id").and_then(|v| v.as_u64()) {
        println!("new asset_id: {id}");
    } else {
        println!("(no `asset_id` field in final response; check explorer)");
    }
    Ok(())
}
