//! gRPC client (feature-gated under `grpc`).
//!
//! Wraps the tonic-generated `MarketDataServiceClient` and
//! `TradingServiceClient` with a thin facade so callers don't have to import
//! tonic directly.
//!
//! ## When to use gRPC over REST / WS?
//!
//! - Throughput: gRPC over HTTP/2 multiplexes many concurrent streams on one
//!   TCP connection. For high-volume MM / arb deployments this matters.
//! - mTLS: the gateway's gRPC endpoint requires mTLS client certs; the
//!   provisioning flow is documented separately.
//! - Native MTF: the gateway↔node internal channel is gRPC, so gRPC clients
//!   are "closer to the metal" than REST/WS which go through the JSON gateway.
//!
//! ## Status
//!
//! v0 stub — the proto schema is intentionally minimal (`stream_fills` +
//! `submit_action`). Real protobuf shapes land alongside the gateway's gRPC
//! exposure in S6+.

use crate::error::ClientError;

/// Generated protobuf bindings (included from `OUT_DIR`).
pub mod proto {
    //! tonic-generated bindings for `proto/metaflux.proto`.
    #![allow(missing_docs, clippy::all)]
    tonic::include_proto!("metaflux.v1");
}

/// Thin facade over the generated tonic clients.
#[derive(Debug, Clone)]
pub struct GrpcClient {
    endpoint: String,
}

impl GrpcClient {
    /// Build a client targeting `endpoint` (e.g. `https://api.mtf.exchange:8443`).
    ///
    /// Note: real production usage requires an mTLS-provisioned client cert.
    /// This v0 stub does not yet wire that in; PR welcome once the gateway
    /// exposes a tls config.
    #[must_use]
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
        }
    }

    /// gRPC endpoint this client targets.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Connect the trading-service client.
    ///
    /// # Errors
    /// [`ClientError::Builder`] on connection / TLS failure.
    pub async fn trading(
        &self,
    ) -> Result<
        proto::trading_service_client::TradingServiceClient<tonic::transport::Channel>,
        ClientError,
    > {
        proto::trading_service_client::TradingServiceClient::connect(self.endpoint.clone())
            .await
            .map_err(|e| ClientError::Builder(format!("tonic connect: {e}")))
    }

    /// Connect the market-data client.
    ///
    /// # Errors
    /// [`ClientError::Builder`] on connection / TLS failure.
    pub async fn market_data(
        &self,
    ) -> Result<
        proto::market_data_service_client::MarketDataServiceClient<tonic::transport::Channel>,
        ClientError,
    > {
        proto::market_data_service_client::MarketDataServiceClient::connect(self.endpoint.clone())
            .await
            .map_err(|e| ClientError::Builder(format!("tonic connect: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grpc_client_records_endpoint() {
        let c = GrpcClient::new("https://api.mtf.exchange:8443");
        assert_eq!(c.endpoint(), "https://api.mtf.exchange:8443");
    }
}
