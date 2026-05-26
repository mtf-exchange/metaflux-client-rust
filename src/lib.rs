//! # metaflux-client — MTF-native Rust SDK
//!
//! This crate is the flagship Rust client for the MetaFlux (MTF) L1. It is
//! **MTF-native only** per [ADR-019]: every type, request shape and channel
//! discriminator follows the MTF-native wire convention (snake_case JSON,
//! plain-integer numerics, `market_id` not `coin`, etc).
//!
//! It exposes every MTF differentiation feature with first-class types:
//! RFQ ([`types::rfq`]), FBA ([`types::fba`]), portfolio margin
//! ([`types::pm`]), cross-chain ([`types::cross_chain`]), encrypted orders
//! ([`types::encrypted`]) plus the batch-2 endpoints (`vault_state`,
//! `staking_state`, `fee_schedule`).
//!
//! HL migrants are **not** served by this SDK. Per [ADR-019] they should
//! keep their existing `hyperliquid-rust-sdk` dependency and point it at
//! the MTF gateway URL `https://api.mtf.exchange/hl-compat/`. The gateway does
//! the surface translation at the protocol layer.
//!
//! ## Modules
//!
//! - [`wallet`] — secp256k1 keypair + EIP-712 signer (RFC-6979 deterministic).
//! - [`rest`]   — `/info`, `/exchange`, `/explorer` HTTP endpoints.
//! - [`ws`]     — WebSocket subscriptions, reconnect + heartbeat.
//! - [`grpc`]   — feature-gated tonic client over mTLS (enable `grpc`).
//! - [`types`]  — MTF-native domain types shared by all transports.
//! - [`error`]  — single [`ClientError`] thiserror enum.
//!
//! ## Quick start
//!
//! ```no_run
//! use metaflux_client::{Client, wallet::Wallet};
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let wallet = Wallet::from_hex(&std::env::var("MTF_PRIVATE_KEY")?)?;
//! let client = Client::new("https://api.mtf.exchange")?;
//! let markets = client.rest().info().markets().await?;
//! println!("{} markets available", markets.len());
//! # let _ = wallet; Ok(())
//! # }
//! ```
//!
//! [ADR-019]: https://github.com/mtf-exchange/metaflux/blob/main/docs/adr/ADR-019-client-rust-mtf-native-only.md

#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod error;
pub mod mip3;
pub mod rest;
pub mod types;
pub mod wallet;
pub mod ws;

#[cfg(feature = "grpc")]
#[cfg_attr(docsrs, doc(cfg(feature = "grpc")))]
pub mod grpc;

pub use error::ClientError;
pub use rest::RestClient;
pub use types::{MarketId, OrderId, VaultId};
pub use wallet::Wallet;

/// Top-level convenience bundle.
///
/// Holds a single [`RestClient`] and a base URL re-used to construct WS /
/// gRPC clients on demand. The fields are owned and `Clone`able cheaply so a
/// long-lived `Client` instance is the recommended pattern.
#[derive(Debug, Clone)]
pub struct Client {
    base_url: String,
    rest: RestClient,
}

impl Client {
    /// Build a client targeting the given base URL.
    ///
    /// `base_url` should be of the form `https://api.mtf.exchange` (no trailing
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
        let c = Client::new("https://api.mtf.exchange").unwrap();
        assert_eq!(c.base_url(), "https://api.mtf.exchange");
    }
}
