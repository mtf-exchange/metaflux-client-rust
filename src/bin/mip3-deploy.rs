//! `mip3-deploy` — CLI driver for the MIP-3 builder kit.
//!
//! See README for usage. Subcommands:
//!
//! - `bid`            — submit a gas-auction bid.
//! - `check-credit`   — poll for a pending deploy credit.
//! - `perp`           — build + submit a perp deploy from a preset.
//! - `spot`           — build + submit a spot pair deploy.
//! - `templates list` — list available presets.
//! - `templates show` — print full preset detail JSON.
//!
//! Auth: the wallet private key is read from `MTF_PRIVATE_KEY` env var (never
//! via a flag — shell history is hostile to secrets).
//!
//! Output: human-readable lines by default; `--json` prints structured output
//! one line at a time.

#![allow(missing_docs)] // binary crate
#![allow(clippy::print_stdout, clippy::print_stderr)] // CLI is allowed to use stdout/err

use std::process::ExitCode;

use clap::{ArgGroup, Parser, Subcommand};
use metaflux_client::Client;
use metaflux_client::mip3::auction::{AuctionBid, AuctionKind};
use metaflux_client::mip3::params::{PerpDeployBuilder, SpotDeployBuilder};
use metaflux_client::mip3::templates::{PRESET_NAMES, preset_by_name};
use metaflux_client::wallet::{Address, Wallet};

const DEFAULT_RPC: &str = "https://api.devnet.mtf.exchange";

#[derive(Parser, Debug)]
#[command(
    name = "mip3-deploy",
    version,
    about = "MetaFlux MIP-3 builder kit CLI — submit gas-auction bids and deploy new markets."
)]
struct Cli {
    /// MetaFlux RPC base URL (override the default).
    #[arg(long, global = true, default_value = DEFAULT_RPC)]
    rpc: String,

    /// Emit one JSON object per logical step instead of human text.
    #[arg(long, global = true)]
    json: bool,

    /// Print the actions but do not submit them. Equivalent to a `--check-only` mode.
    #[arg(long, global = true)]
    dry_run: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Submit a gas-auction bid.
    Bid {
        /// Auction class. One of `token_register`, `perp_deploy`, `spot_pair_deploy`.
        auction_kind: AuctionKindArg,
        /// Bid amount in USDC cents (smallest unit).
        #[arg(long)]
        amount: u128,
    },
    /// Build + submit a perp deploy sequence from a preset.
    Perp {
        /// Preset name (see `mip3-deploy templates list`).
        preset: String,
        /// Override asset name, e.g. `BANANA-PERP`.
        #[arg(long)]
        name: String,
        /// Override asset ticker symbol, e.g. `BANANA`. Defaults to the
        /// preset's symbol if not given.
        #[arg(long)]
        symbol: Option<String>,
        /// Override max leverage.
        #[arg(long)]
        leverage: Option<u8>,
        /// Override taker fee (bps × 10).
        #[arg(long)]
        taker_fee_bps: Option<i16>,
        /// Override maker fee (bps × 10).
        #[arg(long)]
        maker_fee_bps: Option<i16>,
        /// Override deployer fee (bps × 10; ≤ 50).
        #[arg(long)]
        deployer_fee_bps: Option<u16>,
        /// Override min order size in size-decimal units.
        #[arg(long)]
        min_order_size: Option<u128>,
    },
    /// Build + submit a spot pair deploy sequence.
    #[command(group(
        ArgGroup::new("spot_required")
            .args(["base_asset", "quote_asset", "name"])
            .multiple(true)
            .required(true)
    ))]
    Spot {
        /// Base asset id.
        #[arg(long)]
        base_asset: u32,
        /// Quote asset id.
        #[arg(long)]
        quote_asset: u32,
        /// Pair name, e.g. `ETH-USDC`.
        #[arg(long)]
        name: String,
        /// Taker fee bps × 10. Default: 30 (3 bps).
        #[arg(long, default_value_t = 30)]
        taker_fee_bps: i16,
        /// Maker fee bps × 10. Default: -10 (-1 bps rebate).
        #[arg(long, default_value_t = -10)]
        maker_fee_bps: i16,
        /// Min notional in USD cents. Default: 1000 ($10).
        #[arg(long, default_value_t = 1000)]
        min_notional_cents: u128,
    },
    /// Check whether an address has pending deploy credits.
    CheckCredit {
        /// 20-byte hex address (with or without `0x` prefix).
        address: String,
    },
    /// Preset listing / inspection.
    Templates {
        #[command(subcommand)]
        sub: TemplatesSub,
    },
}

#[derive(Subcommand, Debug)]
enum TemplatesSub {
    /// Print preset names, one per line.
    List,
    /// Print the full preset detail (JSON).
    Show {
        /// Preset name (see `templates list`).
        preset: String,
    },
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum AuctionKindArg {
    TokenRegister,
    PerpDeploy,
    SpotPairDeploy,
}

impl From<AuctionKindArg> for AuctionKind {
    fn from(v: AuctionKindArg) -> Self {
        match v {
            AuctionKindArg::TokenRegister => Self::TokenRegister,
            AuctionKindArg::PerpDeploy => Self::PerpDeploy,
            AuctionKindArg::SpotPairDeploy => Self::SpotPairDeploy,
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match &cli.command {
        Command::Templates { sub } => handle_templates(sub, cli.json),
        Command::CheckCredit { address } => handle_check_credit(&cli, address).await,
        Command::Bid {
            auction_kind,
            amount,
        } => handle_bid(&cli, *auction_kind, *amount).await,
        Command::Perp {
            preset,
            name,
            symbol,
            leverage,
            taker_fee_bps,
            maker_fee_bps,
            deployer_fee_bps,
            min_order_size,
        } => {
            handle_perp(
                &cli,
                preset,
                name,
                symbol.as_deref(),
                *leverage,
                *taker_fee_bps,
                *maker_fee_bps,
                *deployer_fee_bps,
                *min_order_size,
            )
            .await
        }
        Command::Spot {
            base_asset,
            quote_asset,
            name,
            taker_fee_bps,
            maker_fee_bps,
            min_notional_cents,
        } => {
            handle_spot(
                &cli,
                *base_asset,
                *quote_asset,
                name,
                *taker_fee_bps,
                *maker_fee_bps,
                *min_notional_cents,
            )
            .await
        }
    }
}

// ---- templates ----

fn handle_templates(sub: &TemplatesSub, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    match sub {
        TemplatesSub::List => {
            if json {
                let arr: Vec<serde_json::Value> =
                    PRESET_NAMES.iter().map(|n| serde_json::json!(n)).collect();
                println!("{}", serde_json::to_string(&arr)?);
            } else {
                for name in PRESET_NAMES {
                    println!("{name}");
                }
            }
            Ok(())
        }
        TemplatesSub::Show { preset } => {
            let b = preset_by_name(preset)
                .ok_or_else(|| format!("unknown preset `{preset}`; see `templates list`"))?;
            print_preset(&b, json)?;
            Ok(())
        }
    }
}

fn print_preset(b: &PerpDeployBuilder, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let sources: Vec<String> = b
        .oracle_sources
        .iter()
        .map(|s| {
            serde_json::to_string(s)
                .unwrap_or_default()
                .trim_matches('"')
                .to_string()
        })
        .collect();
    if json {
        let v = serde_json::json!({
            "asset_name": b.asset_name,
            "asset_symbol": b.asset_symbol,
            "decimals": b.decimals,
            "oracle_sources": sources,
            "max_leverage": b.max_leverage,
            "taker_fee_bps": b.taker_fee_bps,
            "maker_fee_bps": b.maker_fee_bps,
            "min_order_size": b.min_order_size,
            "deployer_fee_bps": b.deployer_fee_bps,
        });
        println!("{}", serde_json::to_string_pretty(&v)?);
    } else {
        println!("asset_name:       {}", b.asset_name);
        println!("asset_symbol:     {}", b.asset_symbol);
        println!("decimals:         {}", b.decimals);
        println!("max_leverage:     {}", b.max_leverage);
        println!("taker_fee_bps:    {} (×10)", b.taker_fee_bps);
        println!("maker_fee_bps:    {} (×10)", b.maker_fee_bps);
        println!("deployer_fee_bps: {} (×10)", b.deployer_fee_bps);
        println!("min_order_size:   {}", b.min_order_size);
        println!("oracle_sources:   [{}]", sources.join(", "));
    }
    Ok(())
}

// ---- bid / check-credit / spot / perp ----

fn read_wallet() -> Result<Wallet, Box<dyn std::error::Error>> {
    let key_hex = std::env::var("MTF_PRIVATE_KEY")
        .map_err(|_| "MTF_PRIVATE_KEY env var not set (64-char hex secp256k1 secret)")?;
    Ok(Wallet::from_hex(&key_hex)?)
}

async fn handle_check_credit(
    cli: &Cli,
    address_hex: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let addr = Address::from_hex(address_hex)?;
    if cli.dry_run {
        report_dry_run(
            "check_credit",
            &serde_json::json!({ "address": address_hex }),
            cli.json,
        );
        return Ok(());
    }
    let client = Client::new(&cli.rpc)?;
    let count = client.check_deploy_credit(addr).await?;
    if cli.json {
        println!(
            "{}",
            serde_json::json!({ "address": format!("{addr}"), "credit_count": count })
        );
    } else {
        println!("address {addr} has {count} pending deploy credit(s)");
    }
    Ok(())
}

async fn handle_bid(
    cli: &Cli,
    kind: AuctionKindArg,
    amount: u128,
) -> Result<(), Box<dyn std::error::Error>> {
    let bid = AuctionBid {
        kind: AuctionKind::from(kind),
        bid_amount_usdc_cents: amount,
    };
    if cli.dry_run {
        let v = serde_json::json!({
            "kind": bid.kind,
            "bid_amount_usdc_cents": bid.bid_amount_usdc_cents,
        });
        report_dry_run("submit_gas_auction_bid", &v, cli.json);
        return Ok(());
    }
    let wallet = read_wallet()?;
    let client = Client::new(&cli.rpc)?;
    let receipt = client.submit_gas_auction_bid(&wallet, bid).await?;
    if cli.json {
        println!("{}", serde_json::to_string(&receipt)?);
    } else {
        println!(
            "bid accepted: round={} amount={}c status={}",
            receipt.round_id, receipt.accepted_amount_usdc_cents, receipt.status
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_perp(
    cli: &Cli,
    preset: &str,
    name: &str,
    symbol: Option<&str>,
    leverage: Option<u8>,
    taker_fee_bps: Option<i16>,
    maker_fee_bps: Option<i16>,
    deployer_fee_bps: Option<u16>,
    min_order_size: Option<u128>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut b = preset_by_name(preset)
        .ok_or_else(|| format!("unknown preset `{preset}`; see `templates list`"))?
        .with_asset_name(name);
    if let Some(s) = symbol {
        b = b.with_asset_symbol(s);
    }
    if let Some(lev) = leverage {
        b = b.with_max_leverage(lev);
    }
    if let Some(t) = taker_fee_bps {
        b = b.with_taker_fee_bps(t);
    }
    if let Some(m) = maker_fee_bps {
        b = b.with_maker_fee_bps(m);
    }
    if let Some(d) = deployer_fee_bps {
        b = b.with_deployer_fee_bps(d);
    }
    if let Some(s) = min_order_size {
        b = b.with_min_order_size(s);
    }
    b.validate()?;
    let seq = b.deploy_sequence();

    if cli.dry_run {
        for action in &seq {
            report_dry_run(action.type_id(), &action.to_json(), cli.json);
        }
        return Ok(());
    }

    let wallet = read_wallet()?;
    let client = Client::new(&cli.rpc)?;
    for (i, action) in seq.iter().enumerate() {
        let resp: serde_json::Value = client
            .rest()
            .exchange()
            .submit_deploy_action(&wallet, action.to_json())
            .await?;
        if cli.json {
            println!(
                "{}",
                serde_json::json!({
                    "step": i + 1,
                    "type": action.type_id(),
                    "response": resp,
                })
            );
        } else {
            println!(
                "step {}/{} ({}) -> {}",
                i + 1,
                seq.len(),
                action.type_id(),
                resp
            );
        }
    }
    Ok(())
}

async fn handle_spot(
    cli: &Cli,
    base_asset: u32,
    quote_asset: u32,
    name: &str,
    taker_fee_bps: i16,
    maker_fee_bps: i16,
    min_notional_cents: u128,
) -> Result<(), Box<dyn std::error::Error>> {
    let b = SpotDeployBuilder::new(
        base_asset,
        quote_asset,
        name,
        taker_fee_bps,
        maker_fee_bps,
        min_notional_cents,
    )?;
    let seq = b.deploy_sequence();

    if cli.dry_run {
        for action in &seq {
            report_dry_run(action.type_id(), &action.to_json(), cli.json);
        }
        return Ok(());
    }

    let wallet = read_wallet()?;
    let client = Client::new(&cli.rpc)?;
    for (i, action) in seq.iter().enumerate() {
        let resp: serde_json::Value = client
            .rest()
            .exchange()
            .submit_deploy_action(&wallet, action.to_json())
            .await?;
        if cli.json {
            println!(
                "{}",
                serde_json::json!({
                    "step": i + 1,
                    "type": action.type_id(),
                    "response": resp,
                })
            );
        } else {
            println!(
                "step {}/{} ({}) -> {}",
                i + 1,
                seq.len(),
                action.type_id(),
                resp
            );
        }
    }
    Ok(())
}

fn report_dry_run(label: &str, payload: &serde_json::Value, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::json!({ "dry_run": true, "type": label, "payload": payload })
        );
    } else {
        println!("[dry-run] {label}: {payload}");
    }
}
