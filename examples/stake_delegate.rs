//! Delegate stake to a validator, or start an undelegation.
//!
//! The key never appears in a command line. Put it in the environment:
//!
//! ```bash
//! MTF_PRIVATE_KEY=0x... cargo run --example stake_delegate -- <validator> <amount> [undelegate]
//! ```
//!
//! Two properties that decide how this behaves, both read from the node:
//! - A DELEGATE raises the validator's vote power at once.
//! - An UNDELEGATE does NOT lower it. The amount enters an unbonding window of
//!   at least seven days and stays counted, and slashable, for the whole window.
//!   So undelegation cannot be used to change a quorum today.
//!
//! `lock_months` is 0 here (flexible). A locked tier is admitted only for an
//! allowlisted validator, and it cannot start unbonding before the lock matures.

use metaflux_client::{
    Client,
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
    if args.len() < 2 || args.len() > 3 {
        eprintln!("usage: stake_delegate <validator 0x…> <amount> [undelegate]");
        std::process::exit(2);
    }
    let validator = parse_address(&args[0])?;
    let amount = args[1].clone();
    let undelegate = args.get(2).map(|s| s == "undelegate").unwrap_or(false);

    let key = std::env::var("MTF_PRIVATE_KEY")
        .map_err(|_| "set MTF_PRIVATE_KEY=<0x + 64 hex> — the account whose stake moves")?;
    let wallet = Wallet::from_hex(&key)?;
    let base = std::env::var("MTF_API_URL")
        .unwrap_or_else(|_| "https://api.testnet.mtf.exchange".to_string());
    let client = Client::new(&base)?;
    println!("endpoint   : {base}");

    println!("signing as : {:?}", wallet.address());
    println!("validator  : {validator:?}");
    println!("amount     : {amount}");
    println!(
        "action     : {}",
        if undelegate { "UNDELEGATE" } else { "DELEGATE" }
    );

    let resp = client
        .exchange()
        .token_delegate_typed(&wallet, validator, amount, undelegate, 0)
        .await?;
    println!("response   : {resp}");
    Ok(())
}
