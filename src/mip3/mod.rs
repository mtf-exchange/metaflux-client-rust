//! MIP-3 builder kit — typed deploy params, gas-auction helpers, presets.
//!
//! MIP-3 (MetaFlux Improvement Proposal #3) is the permissionless market-
//! deploy mechanism: any builder can use a gas auction + a deploy-credit
//! to ship a new perp or spot market on MetaFlux. This module is the
//! flagship client-side surface for that workflow.
//!
//! ## DEPRECATED — operator-injected lane
//!
//! The deploy-submit path ([`crate::Client::submit_gas_auction_bid`] and
//! [`crate::rest::exchange::Exchange::submit_deploy_action`]) is DEPRECATED. The
//! node rejects the opaque deploy digest at serde (400) — MIP-3 deploy actions
//! are operator-injected today, NOT client-signed. The typed builders / presets
//! stay useful to shape a deploy sequence, but the submit call does not clear.
//! The module is retained for reference; it is not removed this wave.
//!
//! The credit pre-flight ([`crate::Client::check_deploy_credit`] and
//! [`crate::Client::await_deploy_credit`]) is DEPRECATED for a second reason:
//! the chain serves no `deploy_credit` info type at all, so the read is a 400
//! and the wait can only time out. Read the live auction with
//! [`crate::rest::info::Info::mip3_active_bids`] instead.
//!
//! ## Typical flow
//!
//! ```no_run
//! # #![allow(deprecated)]
//! # use std::time::Duration;
//! # use metaflux_client::{Client, wallet::Wallet};
//! # use metaflux_client::mip3::{
//! #     auction::{AuctionBid, AuctionKind},
//! #     params::PerpDeployBuilder,
//! #     templates,
//! # };
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let wallet = Wallet::from_hex(&std::env::var("MTF_PRIVATE_KEY")?)?;
//! let client = Client::new("https://api.devnet.mtf.exchange")?;
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
//! // The dex name is the asset namespace, so the symbol carries it as a
//! // prefix. The first deploy by a deployer creates the dex and is REJECTED
//! // without a name.
//! let builder = templates::long_tail_default()
//!     .with_dex_name("BANANA")
//!     .with_asset_name("BANANA-PERP")
//!     .with_asset_symbol("BANANA:PERP");
//! for action in builder.deploy_sequence() {
//!     client.rest().exchange().submit_deploy_action::<serde_json::Value>(&wallet, action.to_json()).await?;
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
