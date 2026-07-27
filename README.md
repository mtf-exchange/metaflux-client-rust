# MetaFlux client rust

[![crates.io](https://img.shields.io/crates/v/metaflux-client.svg)](https://crates.io/crates/metaflux-client)
[![docs.rs](https://img.shields.io/docsrs/metaflux-client)](https://docs.rs/metaflux-client)
[![CI](https://github.com/mtf-exchange/metaflux-client-rust/actions/workflows/ci.yml/badge.svg)](https://github.com/mtf-exchange/metaflux-client-rust/actions/workflows/ci.yml)
[![license](https://img.shields.io/crates/l/metaflux-client.svg)](./LICENSE)

Rust SDK for the MetaFlux derivatives L1 — REST + WebSocket, EIP-712 signing,
and typed builders for the node's full signed-action surface.

## Installation

Published on [crates.io](https://crates.io/crates/metaflux-client):

```toml
[dependencies]
metaflux-client = "0.10"
```

or `cargo add metaflux-client`. The crate is imported as `metaflux_client`.

A short alias crate, [`metaflux`](https://crates.io/crates/metaflux), re-exports
the entire API — `metaflux = "0.10"` and `use metaflux::...` work identically.

## What it does

- **REST** `/info` / `/exchange` / `/explorer` — snake_case JSON. `/info` reads
  are keyed by `coin` (the market symbol, e.g. `"BTC"`) and `address` (0x hex);
  responses render coin symbols everywhere.
- **WebSocket** subscriptions — reconnect with backoff + heartbeat.
- **EIP-712 signing** — secp256k1 with deterministic (RFC-6979) nonces. Signed
  `/exchange` actions keep the numeric `asset` on the wire (consensus-frozen).

The `/exchange` surface is fully typed. Every signed action the node accepts has
a first-class request type and an `Exchange` method, including:

- **Orders** — submit / cancel / cancel-by-cloid / modify, plus batched
  variants, schedule-cancel and cancel-all.
- **TWAP** — sliced orders and cancellation.
- **Leverage & margin** — update leverage, isolated-margin adjust / top-up,
  portfolio-margin enroll.
- **Vaults** — create, transfer, modify, follower withdraw.
- **Staking** — delegate / undelegate, claim rewards, link staking user.
- **Spot & Earn** — spot CLOB orders, leveraged spot margin, Earn lending.
- **Account & agents** — display name, referrer, agent approval, builder-fee
  approval, multisig conversion, abstraction settings, priority bids.
- **Encrypted orders** — threshold-encrypted, MEV-resistant submissions.
- **MetaBridge** — cross-collateral withdrawals to other chains.

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

    // 2. Construct the client.
    let client = Client::new("https://api.devnet.mtf.exchange")?;

    // 3. Build + sign + submit a limit order. The node assigns the oid and
    //    returns it in the response — the submit shape never declares one.
    let order = Order {
        owner: wallet.address(),
        market: metaflux_client::types::MarketId(1), // BTC-PERP
        side: Side::Bid,
        kind: OrderKind::Limit,
        size: 1_000, // 0.001 BTC if size_decimals = 6
        limit_px: 5_000_000_000_000, // $50,000.0000 in tick units
        tif: TimeInForce::Gtc,
        stp_mode: metaflux_client::types::order::StpMode::CancelOldest,
        reduce_only: false,
        cloid: None,
        builder: None,
        position_side: None,
    };

    let resp = client.exchange().submit_order(&wallet, &order).await?;
    println!("submitted: {resp:?}");
    Ok(())
}
```

## Placing orders — one entry point

The wire carries three order actions: `order` (one perp order), `batch_order` (N
perp orders) and `spot_order` (one spot order, on its own id space).
`place_order` is one entry point over all of them, so a caller does not pick the
wire action. It is a convenience over the wire, never a replacement — every
per-action method stays, and `place_order` posts the same bytes.

| request | wire action | actions sent |
|---|---|---|
| perp, any count | `batch_order` | 1 |
| spot, N orders | `spot_order` | N — **not atomic** |
| mixed perp and spot | none — refused | 0 |

```rust,ignore
use metaflux_client::{PlaceRequest, Placement, types::order::OrderGrouping};

// Any number of perp orders ride ONE batch_order action, so the node returns a
// status per leg. `owner` is the params-level batch owner: the wallet for
// self-trading, or a vault address for operator-driven vault trading.
let req = PlaceRequest::perp(wallet.address(), vec![order_a, order_b])
    .with_grouping(OrderGrouping::Na);
match client.exchange().place_order(&wallet, &req).await? {
    Placement::BatchAction(b) => println!("{} leg statuses", b.statuses.len()),
    Placement::SeparateSpotActions(p) => println!("{} separate actions", p.sent.len()),
}
```

The wire cannot batch spot orders, so a spot request sends one `spot_order`
action per order. The result is `Placement::SeparateSpotActions`, which reports
each action on its own — read it as N independent submissions, not one atomic
one. A request that mixes perp and spot orders is refused, never split: build it
with `PlaceRequest::from_legs` to get that refusal before any signing. An
approved agent places spot legs here too — build the request with
`PlaceRequest::spot_as(owner, orders)`.

## Market data reads

`/info` market reads are keyed by `coin` (the market symbol). Prices/sizes come
back as canonical decimal strings; the maintenance-margin ladder rides inline on
each market as `margin_tiers` (upper-bound bands; `max_open_interest = None` on
the unbounded top tier).

```rust,ignore
// `client` as in the Quick start above.

// All perp markets, with the inline margin-tier ladder.
let markets = client.rest().info().markets().await?;
for m in &markets {
    println!("{}: mark {} tiers {}", m.coin, m.mark_px, m.margin_tiers.len());
}

// Depth, a bounded window of recent prints, and the single candle query.
let book = client.rest().info().l2_book("BTC", 20).await?;
let trades = client.rest().info().recent_trades("BTC").await?;
let recent = client
    .rest()
    .info()
    .trades_by_time("BTC", 0, u64::MAX)
    .await?;
let bars = client
    .rest()
    .info()
    .candle_snapshot("BTC", "1m", 0, u64::MAX)
    .await?;

// Predicted per-asset funding — the clamped rate charged at the next boundary.
for pf in client.rest().info().predicted_fundings().await? {
    println!("{}: {} @ {}", pf.coin, pf.predicted_rate, pf.next_funding_ts);
}
println!(
    "book {}x{}, {} recent, {} windowed, {} bars",
    book.bids.len(), book.asks.len(), trades.len(), recent.len(), bars.len()
);
```

## Spot trading

The spot CLOB is a separate book from the perp engine, keyed by a numeric **pair
id**. `tif` accepts `ioc`, `gtc` and `alo`; a `gtc` / `alo` residual rests
against escrowed funds. `limit_px` must be `> 0`, on the 1e8 price plane.
Discover pairs via `spot_meta()`, trade with `spot_order` / `spot_cancel`, and
read balances back with `spot_clearinghouse_state(address)`:

```rust,ignore
use metaflux_client::types::{
    order::Side,
    spot::{SpotCancel, SpotOrder},
};

// `client` and `wallet` as in the Quick start above.

// 1. Discover pairs. `name` is derived as "{base}/{quote}" from the token
//    registry; `id` is the numeric pair id.
let meta = client.rest().info().spot_meta().await?;
let pair = meta
    .pairs
    .iter()
    .find(|p| p.name == "BTC/USDC")
    .expect("pair listed");

// 2. Place an IOC limit spot order (signed, POST /exchange).
let order = SpotOrder::ioc_limit(pair.id, Side::Bid, 1_000, 5_000_000_000);
let resp = client.exchange().spot_order(&wallet, &order).await?;
println!("spot order: {resp:?}");

// 3. Read balances back.
let bals = client
    .rest()
    .info()
    .spot_clearinghouse_state(wallet.address())
    .await?;
for b in &bals.balances {
    println!("{} ({}) total={} hold={}", b.name, b.asset, b.total, b.hold);
}

// 4. Cancel a resting order by oid.
client
    .exchange()
    .spot_cancel(&wallet, &SpotCancel::new(pair.id, 12345))
    .await?;
```

On the WebSocket `trades` / `candles` / `fills` channels, spot prints carry the
**numeric pair id** as the `coin` label (e.g. `"101"`), not the display name —
use `spot_meta()` to map `id` to its `"{base}/{quote}"` name.

### Placing spot orders as an approved agent

A spot order and a spot cancel each carry an optional `owner`. Set it and the
signing wallet acts as an approved **agent** of that address: the node places or
cancels the order AS the owner, and `owner` is bound into the EIP-712 digest, so
a relay can neither strip nor swap it. Leave it unset and the signer trades for
itself — the signed bytes are unchanged.

```rust,ignore
let vault = wallet.address(); // the account whose agent this wallet is

// One order, placed as the owner.
let order = SpotOrder::ioc_limit(pair.id, Side::Bid, 1_000, 5_000_000_000)
    .with_owner(vault);
client.exchange().spot_order(&agent_wallet, &order).await?;

// The same through the unified entry point, for every leg at once.
let req = PlaceRequest::spot_as(vault, [order]);
client.exchange().place_order(&agent_wallet, &req).await?;

// Cancels take the same owner.
client
    .exchange()
    .spot_cancel(&agent_wallet, &SpotCancel::new(pair.id, 12345).with_owner(vault))
    .await?;
```

### Spot margin & Earn (devnet preview)

Leveraged spot borrows quote from the **Earn** lending pool. It is **available on
devnet (preview)**: the full deposit → borrow → leveraged-buy → close loop works,
but forced-liquidation settlement is not yet wired and per-pair maintenance ratios
are still being calibrated — don't treat it as production-ready. All six actions
are sender-authorized (the signer is the actor) and return the `202 Accepted`
admission envelope, not a synchronous oid; observe committed state via `/info`
`spot_margin_state` / `earn_state`. Decimal amounts (`amount` / `borrow` /
`shares`) are passed as **strings**; `size` / `limit_px` are integers on the
raw-lot / 1e8 planes.

`spot_margin_deposit` and `spot_margin_withdraw` are **dead**. Collateral is the
one unified USDC account, so there is no per-pair bucket to post into or
withdraw from. The node rejects both actions whenever the cross-margin model is
active, which on the live chain is from genesis. Both stay on the wire, and both
types keep their EIP-712 type strings, only so old signatures stay verifiable.
Fund the unified USDC account instead, then open and close.

```rust,ignore
use metaflux_client::types::spot::{EarnDeposit, SpotMarginClose, SpotMarginOpen};

// `client`, `wallet`, `pair` as above.

// Supply side: a lender funds the pool (asset = the pair's quote token id).
client
    .exchange()
    .earn_deposit(&wallet, &EarnDeposit { asset: pair.quote, amount: "5000".into() })
    .await?;

// Borrow side: the margin is drawn from the unified USDC account — there is no
// separate deposit step.
client
    .exchange()
    .spot_margin_open(
        &wallet,
        &SpotMarginOpen { pair: pair.id, size: 200, limit_px: 200_000_000, borrow: "400".into() },
    )
    .await?;

// Close the position (sells the held base, repays principal + interest to the
// Earn pool, returns the remainder; a partial fill keeps the account open).
client
    .exchange()
    .spot_margin_close(&wallet, &SpotMarginClose { pair: pair.id, limit_px: 200_000_000 })
    .await?;
```

Read the committed state over `POST /info` with `{ "type": "spot_margin_state",
"user": "0x.." }` (collateral / borrowed / base_held / current_debt per margin
account) and `{ "type": "earn_state", "user": "0x.." }` (per-pool supplied /
borrowed / idle / share_value, plus your shares when `user` is supplied).

## Module overview

| Module | Purpose |
|--------|---------|
| [`wallet`] | secp256k1 keypair management + EIP-712 signing (RFC-6979 deterministic nonces) |
| [`rest`]   | `RestClient` — `/info`, `/exchange`, `/explorer` endpoints |
| [`ws`]     | `WsClient` — subscriptions with reconnect-with-backoff |
| [`types`]  | Domain types: orders, TWAP, margin, vaults, staking, spot / Earn |

[`wallet`]: ./src/wallet/mod.rs
[`rest`]: ./src/rest/mod.rs
[`ws`]: ./src/ws/mod.rs
[`types`]: ./src/types/mod.rs

## Examples

Runnable examples live under [`examples/`](./examples/):

- `submit_limit_order.rs` — fetches `markets()`, signs a limit order, posts to `/exchange`.
- `stream_trades.rs` — opens a WS connection, subscribes to BTC-PERP trades, prints first 10.
- `create_vault.rs` — creates a vault, queries its state.

Run with `cargo run --example <name>`. Examples expect `MTF_PRIVATE_KEY` env var.

## Versioning

Pre-1.0: **minor bumps may break**. We will follow strict SemVer once we tag
`v1.0`. The wire schema is governed by the node, not this SDK — the SDK
re-exposes wire types verbatim, so wire-breaking changes upstream cascade.

## License

MIT — see [LICENSE](./LICENSE).
