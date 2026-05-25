# metaflux-client

Rust SDK for the MetaFlux derivatives L1 — **MTF-native** protocol (REST + WS +
gRPC), EIP-712 signing, full feature surface incl. RFQ / FBA / PM / CrossChain
/ EncryptedOrder.

## Identity (ADR-019)

This SDK speaks **only the MTF-native protocol**:

- REST `/info` / `/exchange` / `/explorer` — snake_case JSON fields, plain
  integer numerics (no decimal-string convention).
- WebSocket subscriptions — MTF-native shape (snake_case channel discriminators,
  `market_id` not `coin`).
- gRPC over mTLS — for power users; gated behind the `grpc` feature flag.

It exposes every MTF differentiation feature with first-class types:

- **RFQ** — request-for-quote sessions
- **FBA** — frequent batch auctions
- **PM** — portfolio margin enroll / rebalance
- **CrossChain** — outbound bridge messages
- **EncryptedOrder** — threshold-encrypted MEV-resistant orders
- **batch-2 endpoints** — `vault_state` / `staking_state` / `fee_schedule`

There is **no HL-compat code path** in this SDK. HL migrants should keep using
[`hyperliquid-rust-sdk`](https://github.com/hyperliquid-dex/hyperliquid-rust-sdk)
against the MTF gateway URL `https://api.mtf.xyz/hl-compat/` — the gateway
translates between HL surface and MTF internals at the protocol layer.

## Quick start

```rust,no_run
use metaflux_client::{
    Client,
    types::order::{Order, OrderKind, Side, TimeInForce},
    wallet::Wallet,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Build a wallet from a 32-byte secp256k1 private key.
    let priv_key_hex = std::env::var("MTF_PRIVATE_KEY")?;
    let wallet = Wallet::from_hex(&priv_key_hex)?;
    println!("wallet address: 0x{}", hex::encode(wallet.address()));

    // 2. Construct the client (MTF testnet).
    let client = Client::new("https://api.mtf.xyz")?;

    // 3. Build + sign + submit a limit order.
    let order = Order {
        oid: 0, // assigned by node
        owner: wallet.address(),
        market: metaflux_client::types::MarketId(1), // BTC-PERP
        side: Side::Bid,
        kind: OrderKind::Limit,
        size: 1_000, // 0.001 BTC if size_decimals = 6
        limit_px: 5_000_000_000_000, // $50,000.0000 in tick units
        tif: TimeInForce::Gtc,
        stp_mode: metaflux_client::types::order::StpMode::CancelOldest,
        reduce_only: false,
        client_order_id: None,
    };

    let resp = client.exchange().submit_order(&wallet, &order).await?;
    println!("submitted: {resp:?}");
    Ok(())
}
```

## Module overview

| Module | Purpose |
|--------|---------|
| [`wallet`] | secp256k1 keypair management + EIP-712 signing (RFC-6979 deterministic nonces) |
| [`rest`]   | `RestClient` — `/info`, `/exchange`, `/explorer` MTF-native endpoints |
| [`ws`]     | `WsClient` — MTF-native subscriptions with reconnect-with-backoff |
| [`grpc`]   | tonic-based gRPC client (feature-gated) for high-throughput consumers |
| [`types`]  | Domain types: `Order`, `Position`, `Vault`, RFQ / FBA / PM / CrossChain / EncryptedOrder |

[`wallet`]: ./src/wallet/mod.rs
[`rest`]: ./src/rest/mod.rs
[`ws`]: ./src/ws/mod.rs
[`grpc`]: ./src/grpc/mod.rs
[`types`]: ./src/types/mod.rs

## Feature flags

| Flag | Default | Effect |
|------|:-------:|--------|
| `grpc` | off | pulls in `tonic` + `prost` and exposes [`grpc::Client`] |

## Examples

Three runnable examples live under [`examples/`](./examples/):

- `submit_limit_order.rs` — fetches `markets()`, signs a limit order, posts to `/exchange`.
- `stream_trades.rs` — opens a WS connection, subscribes to BTC-PERP trades, prints first 10.
- `create_vault.rs` — creates a user vault, seeds it, queries NAV.

Run with `cargo run --example <name>`. Examples expect `MTF_PRIVATE_KEY` env var.

## Versioning

Pre-1.0: **minor bumps may break**. We will follow strict SemVer once we tag
`v1.0`. The wire schema is governed by the gateway, not this SDK — the SDK
re-exposes wire types verbatim, so wire-breaking changes upstream cascade.

## License

MIT — see [LICENSE](./LICENSE).
