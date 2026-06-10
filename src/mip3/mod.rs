//! MIP-3 builder kit — typed deploy params, gas-auction helpers, presets.
//!
//! MIP-3 (MetaFlux Improvement Proposal #3) is the permissionless market-
//! deploy mechanism: any builder can use a gas auction + a deploy-credit
//! to ship a new perp or spot market on MetaFlux. This module is the
//! flagship client-side surface for that workflow.
//!
//! ## Typical flow
//!
//! ```no_run
//! # use std::time::Duration;
//! # use metaflux_client::{Client, wallet::Wallet};
//! # use metaflux_client::mip3::{
//! #     auction::{AuctionBid, AuctionKind},
//! #     params::PerpDeployBuilder,
//! #     templates,
//! # };
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let wallet = Wallet::from_hex(&std::env::var("MTF_PRIVATE_KEY")?)?;
//! let client = Client::new("https://devnet-gateway.mtf.exchange")?;
//!
//! // 1. Bid in the gas auction.
//! let receipt = client.submit_gas_auction_bid(&wallet, AuctionBid {
//!     kind: AuctionKind::PerpDeploy,
//!     bid_amount_usdc_cents: 1_500_000_00,
//! }).await?;
//! println!("bid accepted: round {}", receipt.round_id);
//!
//! // 2. Wait for the credit to land.
//! client.await_deploy_credit(&wallet, Duration::from_secs(120)).await?;
//!
//! // 3. Customise a preset and submit the 8-action deploy sequence.
//! let builder = templates::long_tail_default()
//!     .with_asset_name("BANANA-PERP")
//!     .with_asset_symbol("BANANA");
//! for action in builder.deploy_sequence() {
//!     client.rest().exchange().post_signed::<serde_json::Value>(&wallet, action.to_json()).await?;
//! }
//! # Ok(()) }
//! ```
//!
//! ## Modules
//!
//! - [`params`]    — typed builders + the `Action` enum (one variant per
//!   sub-action of the deploy sequence).
//! - [`auction`]   — gas-auction bid submission + credit polling helpers.
//! - [`templates`] — pre-fab presets (BTC / ETH / long-tail / MM-friendly).

pub mod auction;
pub mod params;
pub mod templates;

pub use auction::{AuctionBid, AuctionKind, BidReceipt};
pub use params::{Action, OracleSource, PerpDeployBuilder, SpotDeployBuilder};
pub use templates::{
    PRESET_NAMES, btc_standard, eth_standard, long_tail_default, mm_friendly, preset_by_name,
};
