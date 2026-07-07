//! Create a Metaliquidity (MLP) vault + register the operator — TYPED scheme.
//!
//! MTF_PRIVATE_KEY=0x... cargo run --example create_mlp_vault

use metaflux_client::{Client, wallet::Wallet};

fn extract_vault_id(v: &serde_json::Value) -> Option<u64> {
    for key in ["vault_id", "vaultId"] {
        if let Some(id) = v.get(key).and_then(|x| x.as_u64()) {
            return Some(id);
        }
        if let Some(id) = v
            .get("data")
            .and_then(|d| d.get(key))
            .and_then(|x| x.as_u64())
        {
            return Some(id);
        }
    }
    None
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let priv_hex = std::env::var("MTF_PRIVATE_KEY").map_err(|_| "set MTF_PRIVATE_KEY")?;
    let wallet = Wallet::from_hex(&priv_hex)?;
    let endpoint = std::env::var("MTF_ENDPOINT")
        .unwrap_or_else(|_| "https://api.devnet.mtf.exchange".into());
    let client = Client::new(&endpoint)?;
    println!("leader/operator = {:?}", wallet.address());

    // If MTF_VAULT_ID is set, the vault already exists — skip create, just register.
    let vault_id = match std::env::var("MTF_VAULT_ID")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
    {
        Some(vid) => {
            println!("using existing vault_id = {vid}");
            vid
        }
        None => {
            // 1. Create the metaliquidity vault — TYPED, kind = 1 (Metaliquidity).
            let resp = client
                .exchange()
                .create_vault_typed(&wallet, "MLP", 4 * 86_400, 1)
                .await?;
            println!("create_vault_typed response:\n{resp:#}");
            match extract_vault_id(&resp) {
                Some(id) => id,
                None => {
                    println!(
                        "(no vault_id in response — re-run with MTF_VAULT_ID=<id> after the commit)"
                    );
                    return Ok(());
                }
            }
        }
    };

    // 2. Rename the vault (if MTF_NEW_NAME is set) — TYPED.
    if let Ok(new_name) = std::env::var("MTF_NEW_NAME") {
        let resp = client
            .exchange()
            .vault_modify_typed(&wallet, vault_id, &new_name)
            .await?;
        println!("vault_modify_typed (rename -> {new_name}) response:\n{resp:#}");
    }

    // 3. Register the operator (self = 0x4f67) — TYPED, unless MTF_SKIP_REGISTER=1.
    if std::env::var("MTF_SKIP_REGISTER").is_err() {
        let resp2 = client
            .exchange()
            .REDACTED_typed(&wallet, vault_id, wallet.address(), true, 0)
            .await?;
        println!("REDACTED_typed response:\n{resp2:#}");
    }
    Ok(())
}
