//! Grant or revoke a metaliquidity vault operator. The VAULT LEADER signs it.
//!
//! The leader key never appears in a command line. Put it in the environment:
//!
//! ```bash
//! MTF_LEADER_KEY=0x... cargo run --example mlp_operator -- <vault_id> <operator> <true|false>
//! ```
//!
//! Rules this example relies on:
//! - The signer must be the vault leader. Any other signer gets `Unauthorized`.
//! - A GRANT also needs the operator address to be an approved liquidity
//!   provider already. That approval is arranged out of band. Until it exists
//!   the node answers `Unauthorized` — the SAME message a wrong signer gets, so
//!   do not read that error as a bad key.
//! - A grant is refused while the vault holds a DIFFERENT operator. Revoke the
//!   old one first.
//! - `expires_at_ms = 0` means never expires. The SDK omits the field in that
//!   case, because the node refuses an explicit zero: absent and zero produce
//!   one signed digest, so they cannot be told apart.

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
    if args.len() != 3 {
        eprintln!("usage: mlp_operator <vault_id> <operator 0x…> <true|false>");
        eprintln!("       MTF_LEADER_KEY must hold the vault leader private key");
        std::process::exit(2);
    }
    let vault_id: u64 = args[0].parse()?;
    let operator = parse_address(&args[1])?;
    let allowed: bool = args[2].parse()?;

    let key = std::env::var("MTF_LEADER_KEY")
        .map_err(|_| "set MTF_LEADER_KEY=<0x + 64 hex> — the VAULT LEADER key")?;
    let wallet = Wallet::from_hex(&key)?;
    let base = std::env::var("MTF_API_URL")
        .unwrap_or_else(|_| "https://api.testnet.mtf.exchange".to_string());
    let client = Client::new(&base)?;
    println!("endpoint   : {base}");

    println!("signing as  : {:?}", wallet.address());
    println!("vault_id    : {vault_id}");
    println!("operator    : {operator:?}");
    println!("allowed     : {allowed}");

    let resp = client
        .exchange()
        .register_metaliquidity_operator_typed(&wallet, vault_id, operator, allowed, 0)
        .await?;
    println!("response    : {resp}");
    Ok(())
}
