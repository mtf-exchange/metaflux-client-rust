//! Print the address a private key signs as. Nothing is sent.
//!
//! ```bash
//! MTF_PRIVATE_KEY=0x... cargo run --example address
//! ```

use metaflux_client::wallet::Wallet;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = std::env::var("MTF_PRIVATE_KEY").map_err(|_| "set MTF_PRIVATE_KEY=<0x + 64 hex>")?;
    let wallet = Wallet::from_hex(key.trim())?;
    println!("{:?}", wallet.address());
    Ok(())
}
