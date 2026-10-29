//! Set a vault's leverage and margin mode on one market. The vault OPERATOR
//! signs it, as an approved agent of the vault.
//!
//! The operator key never appears in a command line. Put it in the environment:
//!
//! ```bash
//! MTF_OPERATOR_KEY=0x... cargo run --example vault_leverage -- <vault 0x…> <asset> <leverage> <cross|isolated>
//! ```
//!
//! Rules this example relies on:
//! - The signer must be an approved agent of the vault. A vault operator is one
//!   (`register_metaliquidity_operator` writes the approval). Any other signer
//!   gets `Unauthorized`.
//! - A deployer-oracle market (asset id 1000 or more) refuses a CROSS open. Set
//!   `isolated` on every such market before the vault quotes it.
//! - A Metaliquidity vault is capped at 20x on every market. A higher value is
//!   refused.
//! - Leverage is not readable back from `/info`. The response is the only
//!   signal.

use metaflux_client::{
    Client,
    types::{MarketId, account::UpdateLeverage},
    wallet::{Address, Wallet},
};

fn parse_address(s: &str) -> Result<Address, String> {
    let h = s.strip_prefix("0x").unwrap_or(s);
    if h.len() != 40 {
        return Err(format!("address needs 40 hex chars, got {}", h.len()));
    }
    let mut out = [0u8; 20];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).map_err(|e| format!("bad hex: {e}"))?;
    }
    Ok(Address(out))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 4 {
        eprintln!("usage: vault_leverage <vault 0x…> <asset> <leverage> <cross|isolated>");
        eprintln!("       MTF_OPERATOR_KEY must hold the vault operator private key");
        std::process::exit(2);
    }
    let vault = parse_address(&args[0])?;
    let asset: u32 = args[1].parse()?;
    let leverage: u32 = args[2].parse()?;
    let is_isolated = match args[3].as_str() {
        "isolated" => true,
        "cross" => false,
        other => return Err(format!("margin mode must be cross or isolated, got {other}").into()),
    };

    let key = std::env::var("MTF_OPERATOR_KEY")
        .map_err(|_| "set MTF_OPERATOR_KEY=<0x + 64 hex> — the vault OPERATOR key")?;
    let wallet = Wallet::from_hex(&key)?;
    let base = std::env::var("MTF_API_URL")
        .unwrap_or_else(|_| "https://api.testnet.mtf.exchange".to_string());
    let client = Client::new(&base)?;
    println!("endpoint    : {base}");
    println!("signing as  : {:?}", wallet.address());
    println!("vault       : {vault:?}");
    println!("asset       : {asset}");
    println!(
        "leverage    : {leverage}x {}",
        if is_isolated { "isolated" } else { "cross" }
    );

    let params = UpdateLeverage {
        asset: MarketId(asset),
        leverage,
        is_isolated,
    };
    let resp = client
        .exchange()
        .update_leverage_as(&wallet, vault, &params)
        .await?;
    println!("response    : {resp}");
    Ok(())
}
