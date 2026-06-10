# metaflux

[![crates.io](https://img.shields.io/crates/v/metaflux.svg)](https://crates.io/crates/metaflux)
[![docs.rs](https://img.shields.io/docsrs/metaflux)](https://docs.rs/metaflux)

A short alias for [`metaflux-client`](https://crates.io/crates/metaflux-client) —
the Rust SDK for the MetaFlux derivatives L1.

This crate re-exports the entire `metaflux-client` public API. Depend on
`metaflux` and use it exactly as you would `metaflux_client`:

```toml
[dependencies]
metaflux = "0.1"
```

```rust,no_run
use metaflux::{Client, wallet::Wallet};

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let wallet = Wallet::from_hex(&std::env::var("MTF_PRIVATE_KEY")?)?;
let client = Client::new("https://api.mtf.exchange")?;
let markets = client.rest().info().markets().await?;
println!("{} markets available", markets.len());
# let _ = wallet; Ok(())
# }
```

For documentation, examples, and the full feature surface, see the
[`metaflux-client`](https://crates.io/crates/metaflux-client) crate.

## License

MIT — see [LICENSE](../LICENSE).
