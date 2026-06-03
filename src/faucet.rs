//! Devnet / testnet faucet helper.
//!
//! The node exposes a faucet at `POST <faucet_base_url>/faucet` that credits an
//! address with test USDC + MTF. It runs on its OWN origin (devnet node port 8080;
//! production `https://faucet.devnet.mtf.exchange`), SEPARATE from the trading
//! API base URL — so [`request_faucet`] takes a dedicated `faucet_base_url`
//! rather than reusing a [`crate::Client`]'s trading `base_url`.
//!
//! The grant is staged for the NEXT block: a `200` response carries
//! `status: "queued"` and the credited balance lands after ~1 block, not
//! synchronously.
//!
//! Devnet / testnet only — mainnet refuses the request (surfaced as a
//! [`ClientError::ProtocolError`]).

use std::time::Duration;

use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::ClientError;

/// Successful faucet response (`200`).
///
/// `status` is `"queued"` — the credit is staged for the next block, so the
/// balance updates after ~1 block rather than synchronously.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaucetResponse {
    /// Echo of the credited address (`0x`-prefixed 20-byte hex).
    pub address: String,
    /// Whole-USDC cross-collateral granted (capped server-side, default 3000).
    pub usdc: u64,
    /// MTF spot tokens granted (fixed, default 10).
    pub mtf: u64,
    /// Always `"queued"` — credit staged for the next block.
    pub status: String,
}

/// Faucet request body. `amount` is omitted when `None` (the faucet then
/// grants its full default, capped server-side).
#[derive(Serialize)]
struct FaucetRequest<'a> {
    address: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    amount: Option<u64>,
}

/// Request test USDC from a devnet / testnet faucet.
///
/// POSTs `{ "address": ..., "amount"?: ... }` to `<faucet_base_url>/faucet`.
/// Grants both USDC (cap `amount`) and a fixed MTF amount.
/// `amount` is a whole-USDC integer; pass `None` for the faucet's full
/// default grant (capped server-side).
///
/// `faucet_base_url` is the faucet's OWN origin (e.g.
/// `http://localhost:8080` on devnet, `https://faucet.devnet.mtf.exchange` in
/// production) — NOT the trading API base URL.
///
/// On success the credit is `"queued"` for the next block; the balance updates
/// after ~1 block, not synchronously.
///
/// # Errors
/// - [`ClientError::Builder`] if `faucet_base_url` is not `http(s)://` or the
///   HTTP client cannot be constructed.
/// - [`ClientError::ProtocolError`] on a non-2xx status, carrying the server's
///   `{ "error": ... }` message — notably `429` (rate-limited: per-address
///   once-ever, per-IP 1/minute), `400` (bad/zero address), `503` (backlog full),
///   or a mainnet refusal.
/// - [`ClientError::Http`] / [`ClientError::Decode`] on transport / decode
///   failure.
pub async fn request_faucet(
    faucet_base_url: &str,
    address: &str,
    amount: Option<u64>,
) -> Result<FaucetResponse, ClientError> {
    if !faucet_base_url.starts_with("http://") && !faucet_base_url.starts_with("https://") {
        return Err(ClientError::Builder(format!(
            "faucet_base_url must start with http(s)://, got `{faucet_base_url}`"
        )));
    }
    let base = faucet_base_url.trim_end_matches('/');
    let url = format!("{base}/faucet");

    let http = HttpClient::builder()
        .user_agent(concat!("metaflux-client/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| ClientError::Builder(e.to_string()))?;

    let body = FaucetRequest { address, amount };
    let resp = http.post(&url).json(&body).send().await?;
    let status = resp.status();
    let bytes = resp.bytes().await?;

    if !status.is_success() {
        if let Ok(env) = serde_json::from_slice::<Value>(&bytes) {
            if let Some(msg) = env.get("error").and_then(Value::as_str) {
                return Err(ClientError::ProtocolError {
                    code: status.as_u16(),
                    msg: msg.into(),
                });
            }
        }
        return Err(ClientError::ProtocolError {
            code: status.as_u16(),
            msg: String::from_utf8_lossy(&bytes).into_owned(),
        });
    }

    serde_json::from_slice(&bytes).map_err(ClientError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_non_http_url() {
        let err = request_faucet("ftp://faucet", "0x00", None)
            .await
            .unwrap_err();
        assert!(matches!(err, ClientError::Builder(_)));
    }
}
