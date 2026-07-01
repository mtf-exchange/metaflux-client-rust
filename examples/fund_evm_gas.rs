//! One-shot: transfer Core MTF → MetaFluxEVM as native gas for a derived bot
//! wallet, so an EVM tx from it can pay for gas. Diagnostic for the EVM ingest
//! end-to-end path.
//!
//! Env: MTF_BASE_URL, MTF_MAKER_KEY (seed), MTF_ACCOUNT (index, default 0),
//!      MTF_AMOUNT (MTF to move, default "5"), MTF_ASSET (asset id, default 104).

use tiny_keccak::{Hasher, Keccak};

use metaflux_client::{Client, wallet::Wallet};

fn env_or(k: &str, d: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| d.to_string())
}

fn derive_key(seed: &[u8; 32], i: usize) -> [u8; 32] {
    let mut k = Keccak::v256();
    k.update(seed);
    k.update(&(i as u64).to_le_bytes());
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out
}

fn parse_seed(hex: &str) -> [u8; 32] {
    let h = hex.strip_prefix("0x").unwrap_or(hex);
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap_or(0);
    }
    out
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = env_or("MTF_BASE_URL", "http://127.0.0.1:8080");
    let idx: usize = env_or("MTF_ACCOUNT", "0").parse().unwrap_or(0);
    let amount = env_or("MTF_AMOUNT", "5");
    let asset: u32 = env_or("MTF_ASSET", "104").parse().unwrap_or(104);

    let seed = parse_seed(&std::env::var("MTF_MAKER_KEY").map_err(|_| "set MTF_MAKER_KEY")?);
    let wallet = Wallet::from_bytes(derive_key(&seed, idx))?;
    let client = Client::new(&base)?;
    let dest = wallet.address();
    println!("wallet {dest}: transferring {amount} MTF (asset {asset}) Core -> EVM");

    let res = client
        .exchange()
        .core_evm_transfer_typed(&wallet, amount, true, dest, asset)
        .await;
    match res {
        Ok(v) => println!("OK: {v}"),
        Err(e) => println!("ERR: {e}"),
    }
    Ok(())
}
