//! Devnet/testnet market-maker bot — keeps every perp order book full and the
//! trade tape alive so a UI has realistic-looking data.
//!
//! Each cycle: a MAKER wallet refreshes a laddered set of resting bids/asks
//! around every perp market's mark; an optional TAKER wallet crosses one market
//! with a small marketable order to print a trade. Sizes are tuned so the faucet
//! grant covers the reserved margin.
//!
//! Env:
//!   MTF_BASE_URL   trading API base (default `http://127.0.0.1:8080`)
//!   MTF_MAKER_KEY  64-char hex private key, faucet-funded (required)
//!   MTF_TAKER_KEY  optional second hex key for crossing trades
//!   MTF_LEVELS     ladder depth per side (default 8)
//!   MTF_NOTIONAL   per-order notional in USD (default 60)
//!   MTF_REFRESH    seconds between cycles (default 12)
//!
//! ```bash
//! MTF_BASE_URL=<gateway> MTF_MAKER_KEY=0x.. MTF_TAKER_KEY=0x.. \
//!   cargo run --release --example devnet_market_maker
//! ```

use std::time::Duration;

use serde_json::{json, Value};

use metaflux_client::{
    faucet::request_faucet,
    types::{
        MarketId,
        order::{CancelAllOrders, Order, OrderKind, OrderStatus, Side, StpMode, TimeInForce},
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

/// Quantize a USD price to the market's tick: `round(px * 1e8 / tick) * tick`.
fn to_limit_px(price_usd: f64, tick: u64) -> u64 {
    let q = ((price_usd * 1e8) / tick as f64).round().max(1.0) as u64;
    (q * tick).max(tick)
}

/// Raw order size = `base_units * 10^sz_decimals`.
fn to_size(base_units: f64, sz_decimals: u8) -> u64 {
    (base_units * 10f64.powi(sz_decimals as i32)).round().max(1.0) as u64
}

fn make_order(owner: Address, market: MarketId, side: Side, size: u64, limit_px: u64) -> Order {
    Order {
        owner,
        market,
        side,
        kind: OrderKind::Limit,
        size,
        limit_px,
        tif: TimeInForce::Gtc,
        stp_mode: StpMode::CancelOldest,
        reduce_only: false,
        cloid: None,
        builder: None,
        position_side: None,
        trigger: None,
    }
}

/// Parse the `markets` /info reply (`{data:{perp:[...]}}`) into the perp list.
fn parse_perps(v: &Value) -> Vec<Mkt> {
    // The client unwraps the `{data, type}` envelope, so `data` (`{perp, spot}`)
    // arrives directly; tolerate the wrapped form too.
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
            if mark > 0.0 && tick > 0 {
                Some(Mkt {
                    asset_id,
                    name,
                    mark,
                    tick,
                    sz_decimals,
                })
            } else {
                None
            }
        })
        .collect()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = env_or("MTF_BASE_URL", "http://127.0.0.1:8080");
    let levels: usize = env_or("MTF_LEVELS", "8").parse().unwrap_or(8);
    let notional: f64 = env_or("MTF_NOTIONAL", "60").parse().unwrap_or(60.0);
    let refresh: u64 = env_or("MTF_REFRESH", "12").parse().unwrap_or(12);

    let maker = Wallet::from_hex(&std::env::var("MTF_MAKER_KEY").map_err(|_| "set MTF_MAKER_KEY")?)?;
    let taker = std::env::var("MTF_TAKER_KEY")
        .ok()
        .and_then(|k| Wallet::from_hex(&k).ok());
    let client = Client::new(&base)?;

    println!("maker {} @ {base}", maker.address());
    if let Some(t) = &taker {
        println!("taker {}", t.address());
    }

    // Top up both wallets a few times so reserved margin is comfortable, then
    // let the credits land before quoting.
    for _ in 0..6 {
        let _ = request_faucet(&base, &maker.address().to_string(), None).await;
        if let Some(t) = &taker {
            let _ = request_faucet(&base, &t.address().to_string(), None).await;
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
            eprintln!("no perp markets parsed; retrying");
            tokio::time::sleep(Duration::from_secs(refresh)).await;
            continue;
        }

        // Fresh quotes: cancel everything, then re-ladder each market.
        let _ = client
            .exchange()
            .cancel_all_orders(&maker, &CancelAllOrders { asset: None })
            .await;

        let mut placed = 0usize;
        let mut first_err: Option<String> = None;
        for m in &perps {
            let market = MarketId(m.asset_id);
            for k in 1..=levels {
                // Widen ~6 bps per level; vary size so the book looks organic.
                let off = 0.0006 * k as f64;
                let sz = notional * (1.0 + 0.15 * ((k % 3) as f64));
                for (side, price) in [
                    (Side::Bid, m.mark * (1.0 - off)),
                    (Side::Ask, m.mark * (1.0 + off)),
                ] {
                    let order = make_order(
                        maker.address(),
                        market,
                        side,
                        to_size(sz / m.mark, m.sz_decimals),
                        to_limit_px(price, m.tick),
                    );
                    match client.exchange().submit_order(&maker, &order).await {
                        Ok(resp) => {
                            for s in &resp.statuses {
                                if let OrderStatus::Error(msg) = s {
                                    first_err.get_or_insert_with(|| format!("{}: {msg}", m.name));
                                } else {
                                    placed += 1;
                                }
                            }
                        }
                        Err(e) => {
                            first_err.get_or_insert_with(|| format!("{} submit: {e}", m.name));
                        }
                    }
                }
            }
        }

        // One marketable cross per cycle to print a trade + tape/candle/volume.
        if let Some(t) = &taker {
            let m = &perps[(cycle as usize) % perps.len()];
            let side = if cycle % 2 == 0 { Side::Bid } else { Side::Ask };
            let px = if side == Side::Bid {
                m.mark * 1.003
            } else {
                m.mark * 0.997
            };
            let order = make_order(
                t.address(),
                MarketId(m.asset_id),
                side,
                to_size((notional * 0.8) / m.mark, m.sz_decimals),
                to_limit_px(px, m.tick),
            );
            let _ = client.exchange().submit_order(t, &order).await;
        }

        println!(
            "cycle {cycle}: {} perps, {placed} resting orders{}",
            perps.len(),
            first_err.map(|e| format!(" (e.g. {e})")).unwrap_or_default()
        );
        tokio::time::sleep(Duration::from_secs(refresh)).await;
    }
}
