//! Move capital between a vault leader and the vault. The LEADER signs it.
//!
//! The leader key never appears in a command line. Put it in the environment:
//!
//! ```bash
//! MTF_LEADER_KEY=0x... cargo run --example vault_transfer -- <vault_id> <deposit|withdraw> <amount USD>
//! ```
//!
//! `amount` is whole USD as a decimal string. A deposit moves the leader's
//! spot USDC into the vault; a Metaliquidity vault locks it for 7 days.

use metaflux_client::{
    Client,
    types::{VaultId, vault::VaultTransfer},
    wallet::Wallet,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 3 {
        eprintln!("usage: vault_transfer <vault_id> <deposit|withdraw> <amount USD>");
        eprintln!("       MTF_LEADER_KEY must hold the vault leader private key");
        std::process::exit(2);
    }
    let vault_id: u64 = args[0].parse()?;
    let deposit = match args[1].as_str() {
        "deposit" => true,
        "withdraw" => false,
        other => return Err(format!("direction must be deposit or withdraw, got {other}").into()),
    };
    let amount = args[2].clone();

    let key = std::env::var("MTF_LEADER_KEY")
        .map_err(|_| "set MTF_LEADER_KEY=<0x + 64 hex> — the VAULT LEADER key")?;
    let wallet = Wallet::from_hex(key.trim())?;
    let base = std::env::var("MTF_API_URL")
        .unwrap_or_else(|_| "https://api.testnet.mtf.exchange".to_string());
    let client = Client::new(&base)?;
    println!("endpoint    : {base}");
    println!("signing as  : {:?}", wallet.address());
    println!("vault_id    : {vault_id}");
    println!(
        "direction   : {}",
        if deposit { "deposit" } else { "withdraw" }
    );
    println!("amount USD  : {amount}");

    let params = VaultTransfer {
        vault_id: VaultId(vault_id),
        deposit,
        amount,
    };
    let resp = client.exchange().vault_transfer(&wallet, &params).await?;
    println!("response    : {resp}");
    Ok(())
}
