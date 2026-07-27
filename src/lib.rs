//! # metaflux-client — Rust SDK for the MetaFlux L1
//!
//! A typed client for the MetaFlux (MTF) derivatives L1. Every type, request
//! shape, and channel discriminator follows the wire convention: snake_case
//! JSON, plain-integer numerics (sizes / prices on fixed-point planes), and
//! `market_id` rather than `coin`.
//!
//! The SDK signs and submits the node's full signed-action surface — perp and
//! spot orders, TWAP, modify / batch, leverage and margin, vaults, staking,
//! agent / account settings, and spot-margin / Earn — and reads market and
//! account state over REST and WebSocket.
//!
//! ## Modules
//!
//! - [`wallet`] — secp256k1 keypair + EIP-712 signer (deterministic nonces).
//! - [`rest`]   — `/info`, `/exchange`, `/explorer` HTTP endpoints.
//! - [`ws`]     — WebSocket subscriptions, reconnect + heartbeat.
//! - [`types`]  — domain types shared by all transports.
//! - [`grid`]   — snap an order price / size onto a market's tick / lot grid.
//! - [`faucet`] — devnet / testnet test-USDC faucet helper.
//! - [`error`]  — single [`ClientError`] thiserror enum.
//!
//! ## Quick start
//!
//! ```no_run
//! use metaflux_client::{Client, wallet::Wallet};
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let wallet = Wallet::from_hex(&std::env::var("MTF_PRIVATE_KEY")?)?;
//! let client = Client::new("https://api.devnet.mtf.exchange")?;
//! let markets = client.rest().info().markets().await?;
//! println!("{} markets available", markets.len());
//! # let _ = wallet; Ok(())
//! # }
//! ```

#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod error;
pub mod faucet;
pub mod grid;
pub mod mip3;
pub mod rest;
pub mod types;
pub mod wallet;
pub mod ws;

pub use error::ClientError;
pub use faucet::{FaucetResponse, request_faucet};
pub use grid::{GridError, GridOrder, round_order_to_grid};
pub use rest::RestClient;
pub use types::candle::CandleType;
pub use types::chase::{CancelChaseParams, ChaseParams};
pub use types::place::{OrderLeg, PlaceRequest, Placement};
pub use types::scale::{CancelScaleParams, ScaleDist, ScaleParams};
pub use types::{MarketId, OrderId, VaultId};
pub use wallet::Wallet;

/// Top-level convenience bundle.
///
/// Holds a single [`RestClient`] and a base URL re-used to construct WS
/// clients on demand. The fields are owned and `Clone`able cheaply so a
/// long-lived `Client` instance is the recommended pattern.
#[derive(Debug, Clone)]
pub struct Client {
    base_url: String,
    rest: RestClient,
}

impl Client {
    /// Build a client targeting the given base URL.
    ///
    /// `base_url` should be of the form `https://api.devnet.mtf.exchange` (no trailing
    /// path). The REST client will append `/info`, `/exchange`, etc.; the WS
    /// client derives a `wss://` URL from this base.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Builder`] if the URL is malformed or the
    /// underlying `reqwest::Client` cannot be constructed.
    pub fn new(base_url: impl Into<String>) -> Result<Self, ClientError> {
        let base_url = base_url.into();
        let rest = RestClient::new(&base_url)?;
        Ok(Self { base_url, rest })
    }

    /// Access the REST sub-client.
    #[must_use]
    pub fn rest(&self) -> &RestClient {
        &self.rest
    }

    /// The base URL this client targets.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Convenience: REST `exchange` namespace.
    ///
    /// Equivalent to `self.rest().exchange()`.
    #[must_use]
    pub fn exchange(&self) -> rest::exchange::Exchange<'_> {
        self.rest.exchange()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_builds_with_valid_base_url() {
        let c = Client::new("https://api.devnet.mtf.exchange").unwrap();
        assert_eq!(c.base_url(), "https://api.devnet.mtf.exchange");
    }
}
