//! Create a user vault, query its NAV.
//!
//! Requires `MTF_PRIVATE_KEY` env var. Run with:
//!
//! ```bash
//! MTF_PRIVATE_KEY=0x... cargo run --example create_vault
//! ```

use metaflux_client::{Client, types::VaultId, types::vault::VaultCreate, wallet::Wallet};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let priv_hex = std::env::var("MTF_PRIVATE_KEY")
        .map_err(|_| "set MTF_PRIVATE_KEY=<64-char hex> to run this example")?;
    let wallet = Wallet::from_hex(&priv_hex)?;
    let client = Client::new("https://api.mtf.xyz")?;

    let create = VaultCreate {
        leader: wallet.address(),
        seed_cents: 1_000_000, // $10,000
        management_fee_bps: 1000,
    };
    let resp = client.exchange().vault_create(&wallet, &create).await?;
    println!("vault_create response: {resp:?}");

    // Try to query the newly created vault's NAV.
    // The action response typically carries the assigned vault_id; we
    // demonstrate the info call against vault_id = 1 here.
    let nav = client.rest().info().vault_state(VaultId(1)).await?;
    println!("vault state: {nav:?}");
    Ok(())
}
