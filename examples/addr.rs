use metaflux_client::wallet::Wallet;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let w = Wallet::from_hex(&std::env::var("KEY")?)?;
    println!("MLP_ADDRESS={}", w.address());
    Ok(())
}
