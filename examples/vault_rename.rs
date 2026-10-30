//! Rename a vault. The LEADER signs it; every other setting stays unchanged.
//!
//! ```bash
//! MTF_LEADER_KEY=0x... cargo run --example vault_rename -- <vault_id> "<new name>"
//! ```

use metaflux_client::{
    Client,
    types::{VaultId, vault::VaultModify},
    wallet::Wallet,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 2 {
        eprintln!("usage: vault_rename <vault_id> \"<new name>\"");
        eprintln!("       MTF_LEADER_KEY must hold the vault leader private key");
        std::process::exit(2);
    }
    let vault_id: u64 = args[0].parse()?;
    let new_name = args[1].clone();

    let key = std::env::var("MTF_LEADER_KEY")
        .map_err(|_| "set MTF_LEADER_KEY=<0x + 64 hex> — the VAULT LEADER key")?;
    let wallet = Wallet::from_hex(key.trim())?;
    let base = std::env::var("MTF_API_URL")
        .unwrap_or_else(|_| "https://api.testnet.mtf.exchange".to_string());
    let client = Client::new(&base)?;
    println!("signing as  : {:?}", wallet.address());
    println!("vault_id    : {vault_id}");
    println!("new name    : {new_name}");

    let params = VaultModify {
        vault_id: VaultId(vault_id),
        new_name: Some(new_name),
        new_lock_period_secs: None,
        new_management_fee_bps: None,
        new_paused: None,
    };
    let resp = client.exchange().vault_modify(&wallet, &params).await?;
    println!("response    : {resp}");
    Ok(())
}
