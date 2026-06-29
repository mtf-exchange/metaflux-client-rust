//! Devnet/testnet market-maker bot — keeps every perp order book full AND prints
//! a steady trade tape (so candles/K-lines form) using N accounts quoting around
//! REAL reference prices pulled from a public CEX (Binance).
//!
//! Each cycle: fetch CEX spot prices; for every perp pick a reference (CEX
//! `<NAME>USDT` when available, else the node mark). Wallets split into MAKERS
//! (rest a full GTC ladder, refreshed periodically) and TAKERS (cross every
//! market with IOC each cycle, hitting the makers' books) — those cross-account
//! fills drive the candle stream.
//!
//! HEAVY by construction: each wallet submits its whole ladder / cross-set as one
//! BATCH (single signature + nonce + round-trip, up to 1000 orders), and all
//! wallets' batches fire CONCURRENTLY — a cycle is one parallel wave, not
//! hundreds of serial POSTs.
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

use futures_util::future::join_all;
use serde_json::{json, Value};
use tiny_keccak::{Hasher, Keccak};

use metaflux_client::{
    faucet::request_faucet,
    types::{
        order::{
            BatchOrder, CancelAllOrders, Order, OrderGrouping, OrderKind, Side, StpMode,
            TimeInForce,
        },
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

/// Reference price for a market at phase `t` (advances once per cycle):
/// - listed on the CEX → its live spot price;
/// - `MTF` (our own coin, on no CEX) → a deterministic oscillation in 4..8 so it
///   prints a lively candle instead of a flat line;
/// - any other unlisted coin → a gentle ±1.5% wobble around the node mark.
/// The per-market phase offset (`asset_id`) decorrelates the synthetic markets.
fn reference_px(m: &Mkt, cex: &HashMap<String, f64>, t: f64) -> f64 {
    if let Some(&p) = cex.get(&m.name) {
        return p;
    }
    let phase = t * 0.4 + m.asset_id as f64;
    if m.name == "MTF" {
        return 6.0 + 2.0 * phase.sin();
    }
    m.mark * (1.0 + 0.015 * phase.sin())
}

/// Build a wallet's full resting GTC ladder across every perp, as one batch.
fn build_ladder(
    owner: Address,
    perps: &[Mkt],
    cex: &HashMap<String, f64>,
    t: f64,
    levels: usize,
    notional: f64,
) -> Vec<Order> {
    let mut out = Vec::new();
    for m in perps {
        let refpx = reference_px(m, cex, t);
        let market = MarketId(m.asset_id);
        for k in 1..=levels {
            let off = 0.0006 * k as f64;
            let sz = notional * (1.0 + 0.12 * (k % 3) as f64);
            for (side, price) in [
                (Side::Bid, refpx * (1.0 - off)),
                (Side::Ask, refpx * (1.0 + off)),
            ] {
                out.push(make_order(
                    owner,
                    market,
                    side,
                    to_size(sz / refpx, m.sz_decimals),
                    to_limit_px(price, m.tick),
                    TimeInForce::Gtc,
                ));
            }
        }
    }
    out
}

/// Build a wallet's DIRECTIONAL IOC trades — one per market, as a batch. The
/// side is chosen by the live CEX vs the on-chain mark (NOT alternating): when
/// the CEX is above the stale on-chain mark the market is under-priced → BUY
/// (lift offers, drag the mark up toward the CEX); when below → SELL. So the
/// on-chain price TRACKS the real CEX trend, the tape is directional (real
/// momentum, not churn), and these accounts accumulate real positions/PnL.
/// `wobble` injects a per-(wallet,market) counter-trade fraction so the tape
/// stays two-sided (real markets have both) and candles keep an OHLC range.
fn build_crosses(
    owner: Address,
    perps: &[Mkt],
    cex: &HashMap<String, f64>,
    t: f64,
    notional: f64,
    wobble: usize,
) -> Vec<Order> {
    let mut out = Vec::new();
    for (mi, m) in perps.iter().enumerate() {
        let refpx = reference_px(m, cex, t);
        // Dominant direction = trade toward the CEX (close the on-chain gap);
        // ~1 in 4 (wobble) takes the other side so the book gets two-sided flow.
        let toward_cex = refpx >= m.mark;
        let contrarian = (wobble + mi) % 4 == 0;
        let side = if toward_cex != contrarian {
            Side::Bid
        } else {
            Side::Ask
        };
        // Cross ~0.3% through the reference so it sweeps the resting top levels;
        // IOC fills what's there and cancels the rest (no taker overhang).
        let px = if side == Side::Bid {
            refpx * 1.003
        } else {
            refpx * 0.997
        };
        // Size scales with the CEX↔mark gap so a bigger dislocation trades more
        // (faster convergence + a livelier candle on real moves).
        let gap = ((refpx - m.mark).abs() / m.mark).min(0.02);
        let sz_usd = notional * (0.6 + 20.0 * gap);
        out.push(make_order(
            owner,
            MarketId(m.asset_id),
            side,
            to_size(sz_usd / refpx, m.sz_decimals),
            to_limit_px(px, m.tick),
            TimeInForce::Ioc,
        ));
    }
    out
}

/// `/exchange` admits actions ASYNCHRONOUSLY — a `batch_order` returns an ack
/// (`{accepted, action_hash, mempool_depth, nonce}`), and the orders match in a
/// later block. So success here means "admitted to the mempool", and fills are
/// observed out-of-band via `recent_trades` / `candle`, not in this response.
fn accepted(v: &Value) -> bool {
    v.get("accepted").and_then(Value::as_bool).unwrap_or(false)
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
            // tick_size is a CANONICAL whole-USDC decimal string ("0.01"); rescale
            // to the 1e8 limit_px plane to_limit_px / the tick>0 filter expect.
            let tick_dec: f64 = m.get("tick_size")?.as_str()?.parse().ok()?;
            let tick = (tick_dec * 1e8).round() as u64;
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
    let n_accounts: usize = env_or("MTF_ACCOUNTS", "8").parse().unwrap_or(8).max(2);
    let levels: usize = env_or("MTF_LEVELS", "8").parse().unwrap_or(8);
    let notional: f64 = env_or("MTF_NOTIONAL", "60").parse().unwrap_or(60.0);
    let refresh: u64 = env_or("MTF_REFRESH", "5").parse().unwrap_or(5);
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

        // MAKERS (first half) rest a full GTC ladder; TAKERS (second half) cross
        // EVERY market with IOC — different accounts, so no self-trade STP cancel,
        // and the cross-account fills drive the candle stream. The book is refreshed
        // EVERY cycle so takers always have depth to hit (and stale prices clear as
        // the reference drifts).
        //
        // THROUGHPUT: each wallet places its WHOLE ladder / cross-set in ONE batch
        // (one signature, one nonce, one round-trip — `MAX_BATCH` = 1000), and every
        // wallet's batch is fired CONCURRENTLY via `join_all`. A cycle is one wave of
        // N parallel requests regardless of order count, not hundreds of serial POSTs.
        let t = cycle as f64;
        let n_makers = (wallets.len() / 2).max(1);

        // Capture a shared reference in the per-wallet async blocks (each `async
        // move` then moves only the Copy `&Client`, not the client itself).
        let client = &client;

        let mfuts = wallets[..n_makers].iter().map(|w| {
            let orders = build_ladder(w.address(), &perps, &cex, t, levels, notional);
            let n = orders.len();
            async move {
                let _ = client
                    .exchange()
                    .cancel_all_orders(w, &CancelAllOrders { asset: None })
                    .await;
                let ok = client
                    .exchange()
                    .batch_order(
                        w,
                        &BatchOrder {
                            owner: w.address(),
                            orders,
                            grouping: OrderGrouping::Na,
                        },
                    )
                    .await
                    .map(|v| accepted(&v))
                    .unwrap_or(false);
                (ok, n)
            }
        });
        let (mut maker_ok, mut placed) = (0usize, 0usize);
        for (ok, n) in join_all(mfuts).await {
            if ok {
                maker_ok += 1;
                placed += n;
            }
        }

        let tfuts = wallets[n_makers..].iter().enumerate().map(|(ti, w)| {
            let orders = build_crosses(w.address(), &perps, &cex, t, notional, cycle as usize + ti);
            let n = orders.len();
            async move {
                let ok = client
                    .exchange()
                    .batch_order(
                        w,
                        &BatchOrder {
                            owner: w.address(),
                            orders,
                            grouping: OrderGrouping::Na,
                        },
                    )
                    .await
                    .map(|v| accepted(&v))
                    .unwrap_or(false);
                (ok, n)
            }
        });
        let (mut taker_ok, mut crossed) = (0usize, 0usize);
        let t0 = std::time::Instant::now();
        for (ok, n) in join_all(tfuts).await {
            if ok {
                taker_ok += 1;
                crossed += n;
            }
        }
        let taker_ms = t0.elapsed().as_millis();

        println!(
            "cycle {cycle}: {} perps, {} CEX refs | makers {maker_ok}/{n_makers} ({placed} resting) | takers {taker_ok} ({crossed} crosses) | taker wave {taker_ms}ms",
            perps.len(),
            cex.len(),
        );
        tokio::time::sleep(Duration::from_secs(refresh)).await;
    }
}
