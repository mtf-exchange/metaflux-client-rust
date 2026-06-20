//! Devnet/testnet market-maker bot — keeps every perp order book full AND prints
//! a steady trade tape (so candles/K-lines form) using N accounts quoting around
//! REAL reference prices pulled from a public CEX (Binance).
//!
//! Each cycle: fetch CEX spot prices; for every perp market pick a reference
//! (CEX `<NAME>USDT` when available, else the node mark); every bot wallet
//! re-ladders resting bids/asks around it AND fires one marketable order that
//! crosses another wallet's book — those fills drive the candle stream.
//!
//! N wallets are derived deterministically from MTF_MAKER_KEY (keccak(seed‖i)),
//! so re-runs reuse the same funded accounts. All self-faucet on startup.
//!
//! Env:
//!   MTF_BASE_URL    trading API base (default `http://127.0.0.1:8080`)
//!   MTF_MAKER_KEY   64-char hex seed key (required) — N accounts derive from it
//!   MTF_ACCOUNTS    number of bot wallets (default 6)
//!   MTF_LEVELS      ladder depth per side (default 8)
//!   MTF_NOTIONAL    per-order notional in USD (default 60)
//!   MTF_REFRESH     seconds between cycles (default 10)
//!   MTF_CEX_URL     CEX ticker URL (default Binance /api/v3/ticker/price)
//!
//! ```bash
//! MTF_BASE_URL=<gateway> MTF_MAKER_KEY=0x.. MTF_ACCOUNTS=6 \
//!   cargo run --release --example devnet_market_maker
//! ```

use std::collections::HashMap;
use std::time::Duration;

use serde_json::{json, Value};
use tiny_keccak::{Hasher, Keccak};

use metaflux_client::{
    faucet::request_faucet,
    types::{
        order::{CancelAllOrders, Order, OrderKind, OrderStatus, Side, StpMode, TimeInForce},
        MarketId,
    },
    wallet::{Address, Wallet},
    Client,
};

/// A perp market reduced to what the bot needs to quote it.
struct Mkt {
    asset_id: u32,
    name: String,
    mark: f64,
    tick: u64,
    sz_decimals: u8,
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn to_limit_px(price_usd: f64, tick: u64) -> u64 {
    let q = ((price_usd * 1e8) / tick as f64).round().max(1.0) as u64;
    (q * tick).max(tick)
}

fn to_size(base_units: f64, sz_decimals: u8) -> u64 {
    (base_units * 10f64.powi(sz_decimals as i32)).round().max(1.0) as u64
}

fn make_order(
    owner: Address,
    market: MarketId,
    side: Side,
    size: u64,
    limit_px: u64,
    tif: TimeInForce,
) -> Order {
    Order {
        owner,
        market,
        side,
        kind: OrderKind::Limit,
        size,
        limit_px,
        tif,
        stp_mode: StpMode::CancelOldest,
        reduce_only: false,
        cloid: None,
        builder: None,
        position_side: None,
        trigger: None,
    }
}

/// Derive the i-th bot key from a seed: `keccak256(seed_bytes ‖ i_le)`.
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

/// Fetch `<SYMBOL>` → USD spot from the CEX ticker (`[{symbol, price}]`). Keyed by
/// the bare base asset (`BTCUSDT` → `BTC`). Best-effort: returns empty on failure.
async fn fetch_cex_prices(url: &str) -> HashMap<String, f64> {
    let mut out = HashMap::new();
    let resp = match reqwest::get(url).await {
        Ok(r) => r,
        Err(_) => return out,
    };
    let arr: Vec<Value> = resp.json().await.unwrap_or_default();
    for t in arr {
        let (Some(sym), Some(px)) = (t.get("symbol").and_then(Value::as_str), t.get("price")) else {
            continue;
        };
        let price: f64 = px.as_str().and_then(|s| s.parse().ok()).unwrap_or(0.0);
        if price > 0.0 {
            if let Some(base) = sym.strip_suffix("USDT") {
                out.insert(base.to_string(), price);
            }
        }
    }
    out
}

fn parse_perps(v: &Value) -> Vec<Mkt> {
    let perp = v
        .get("perp")
        .or_else(|| v.get("data").and_then(|d| d.get("perp")));
    let arr = perp.and_then(Value::as_array).cloned().unwrap_or_default();
    arr.iter()
        .filter_map(|m| {
            let asset_id = m.get("asset_id")?.as_u64()? as u32;
            let name = m.get("name")?.as_str()?.to_string();
            let mark: f64 = m.get("mark_px")?.as_str()?.parse().ok()?;
            let tick: u64 = m.get("tick_size")?.as_str()?.parse().ok()?;
            let sz_decimals = m.get("sz_decimals")?.as_u64()? as u8;
            (mark > 0.0 && tick > 0).then_some(Mkt {
                asset_id,
                name,
                mark,
                tick,
                sz_decimals,
            })
        })
        .collect()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = env_or("MTF_BASE_URL", "http://127.0.0.1:8080");
    let n_accounts: usize = env_or("MTF_ACCOUNTS", "6").parse().unwrap_or(6).max(2);
    let levels: usize = env_or("MTF_LEVELS", "8").parse().unwrap_or(8);
    let notional: f64 = env_or("MTF_NOTIONAL", "60").parse().unwrap_or(60.0);
    let refresh: u64 = env_or("MTF_REFRESH", "10").parse().unwrap_or(10);
    let cex_url = env_or(
        "MTF_CEX_URL",
        "https://api.binance.com/api/v3/ticker/price",
    );

    let seed = parse_seed(&std::env::var("MTF_MAKER_KEY").map_err(|_| "set MTF_MAKER_KEY")?);
    let wallets: Vec<Wallet> = (0..n_accounts)
        .map(|i| Wallet::from_bytes(derive_key(&seed, i)))
        .collect::<Result<_, _>>()?;
    let client = Client::new(&base)?;

    println!("{n_accounts} bot wallets @ {base}");
    for w in &wallets {
        println!("  {}", w.address());
    }

    // Top up every wallet a few times so reserved margin is comfortable.
    for _ in 0..5 {
        for w in &wallets {
            let _ = request_faucet(&base, &w.address().to_string(), None).await;
        }
    }
    tokio::time::sleep(Duration::from_secs(3)).await;

    let mut cycle: u64 = 0;
    loop {
        cycle += 1;
        let raw = match client.rest().info().raw(json!({ "type": "markets" })).await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("markets read failed: {e}; retrying");
                tokio::time::sleep(Duration::from_secs(refresh)).await;
                continue;
            }
        };
        let perps = parse_perps(&raw);
        if perps.is_empty() {
            tokio::time::sleep(Duration::from_secs(refresh)).await;
            continue;
        }
        let cex = fetch_cex_prices(&cex_url).await;

        let mut resting = 0usize;
        let mut trades = 0usize;

        // First half = MAKERS (rest depth, refreshed every 5th cycle — cancel +
        // re-ladder is the slow op). Second half = TAKERS (cross EVERY market each
        // cycle with IOC orders that hit the makers' books — different accounts, so
        // no self-trade STP — printing the fills that drive the candle stream).
        let n_makers = (wallets.len() / 2).max(1);
        let reladder = cycle % 5 == 1;

        if reladder {
            for w in &wallets[..n_makers] {
                let _ = client
                    .exchange()
                    .cancel_all_orders(w, &CancelAllOrders { asset: None })
                    .await;
                for m in &perps {
                    let refpx = *cex.get(&m.name).unwrap_or(&m.mark);
                    let market = MarketId(m.asset_id);
                    for k in 1..=levels {
                        let off = 0.0006 * k as f64;
                        let sz = notional * (1.0 + 0.12 * (k % 3) as f64);
                        for (side, price) in [
                            (Side::Bid, refpx * (1.0 - off)),
                            (Side::Ask, refpx * (1.0 + off)),
                        ] {
                            let order = make_order(
                                w.address(),
                                market,
                                side,
                                to_size(sz / refpx, m.sz_decimals),
                                to_limit_px(price, m.tick),
                                TimeInForce::Gtc,
                            );
                            if let Ok(resp) = client.exchange().submit_order(w, &order).await {
                                resting += resp
                                    .statuses
                                    .iter()
                                    .filter(|s| !matches!(s, OrderStatus::Error(_)))
                                    .count();
                            }
                        }
                    }
                }
            }
        }

        for (ti, w) in wallets[n_makers..].iter().enumerate() {
            for (mi, m) in perps.iter().enumerate() {
                let refpx = *cex.get(&m.name).unwrap_or(&m.mark);
                let side = if (cycle as usize + ti + mi) % 2 == 0 {
                    Side::Bid
                } else {
                    Side::Ask
                };
                // Cross ~0.3% through the reference so it sweeps the top levels;
                // IOC fills what's resting and cancels the rest (no taker overhang).
                let px = if side == Side::Bid {
                    refpx * 1.003
                } else {
                    refpx * 0.997
                };
                let order = make_order(
                    w.address(),
                    MarketId(m.asset_id),
                    side,
                    to_size((notional * 0.6) / refpx, m.sz_decimals),
                    to_limit_px(px, m.tick),
                    TimeInForce::Ioc,
                );
                if let Ok(resp) = client.exchange().submit_order(w, &order).await {
                    trades += resp
                        .statuses
                        .iter()
                        .filter(|s| matches!(s, OrderStatus::Filled(_)))
                        .count();
                }
            }
        }

        println!(
            "cycle {cycle}: {} perps, {} CEX refs, +{resting} resting, {trades} fills",
            perps.len(),
            cex.len()
        );
        tokio::time::sleep(Duration::from_secs(refresh)).await;
    }
}
