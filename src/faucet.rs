//! Devnet / testnet faucet helper.
//!
//! The node exposes a faucet at `POST <faucet_base_url>/faucet` that credits an
//! address with test USDC + MTF. The testnet gateway serves it at
//! `https://api.testnet.mtf.exchange/faucet`. A devnet node serves it on its own
//! port, so [`request_faucet`] takes a dedicated `faucet_base_url` rather than
//! reusing a [`crate::Client`]'s trading `base_url`.
//!
//! The recipient signs every claim. The signature is an EIP-191 `personal_sign`
//! over [`faucet_claim_message`], so the address that receives the grant is the
//! address that asked for it. [`request_faucet`] signs with a [`Wallet`];
//! [`request_faucet_with_claim`] sends a [`FaucetClaim`] that an external
//! wallet signed.
//!
//! The grant is staged for the NEXT block: a `200` response carries
//! `status: "queued"` and the credited balance lands after ~1 block, not
//! synchronously.
//!
//! Devnet / testnet only — mainnet refuses the request (surfaced as a
//! [`ClientError::ProtocolError`]).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tiny_keccak::{Hasher, Keccak};

use crate::error::ClientError;
use crate::wallet::{Address, Wallet};

/// How long a claim signed by [`FaucetClaim::sign`] stays valid, in seconds.
///
/// The node refuses an `expires` in the past and an `expires` more than 600 s
/// ahead of its own clock.
pub const FAUCET_CLAIM_TTL_SECS: u64 = 300;

/// Successful faucet response (`200`).
///
/// `status` is `"queued"` — the credit is staged for the next block, so the
/// balance updates after ~1 block rather than synchronously.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaucetResponse {
    /// Echo of the credited address (`0x`-prefixed 20-byte hex).
    pub address: String,
    /// Whole-USDC cross-collateral granted (fixed, default 3000).
    pub usdc: u64,
    /// MTF spot tokens granted (fixed, default 10).
    pub mtf: u64,
    /// Always `"queued"` — credit staged for the next block.
    pub status: String,
}

/// The signed fields of a faucet request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaucetClaim {
    /// The recipient. It is also the signer.
    pub address: Address,
    /// Unix seconds after which the node refuses the claim.
    pub expires: u64,
    /// `0x`-prefixed 65-byte `r || s || v` hex, with `v` 27 or 28.
    pub signature: String,
}

impl FaucetClaim {
    /// Sign a claim for the wallet's own address. It expires
    /// [`FAUCET_CLAIM_TTL_SECS`] from now.
    ///
    /// `chain_id` is the MetaFlux chain id, e.g.
    /// [`crate::rest::exchange::MTF_TESTNET_CHAIN_ID`].
    ///
    /// # Errors
    /// [`ClientError::Signature`] if the signer fails.
    pub fn sign(wallet: &Wallet, chain_id: u64) -> Result<Self, ClientError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        Self::sign_with_expiry(wallet, chain_id, now + FAUCET_CLAIM_TTL_SECS)
    }

    /// Sign a claim that expires at `expires` (unix seconds).
    ///
    /// # Errors
    /// [`ClientError::Signature`] if the signer fails.
    pub fn sign_with_expiry(
        wallet: &Wallet,
        chain_id: u64,
        expires: u64,
    ) -> Result<Self, ClientError> {
        let address = wallet.address();
        let message = faucet_claim_message(address, chain_id, expires);
        let signature = wallet.sign_digest(&eip191_digest(message.as_bytes()))?;
        Ok(Self {
            address,
            expires,
            signature: signature.to_hex(),
        })
    }
}

/// The exact text the recipient signs with `personal_sign`.
///
/// Four lines joined by `\n`, with no trailing newline:
///
/// ```text
/// MetaFlux faucet claim
/// address: <0x lowercase address>
/// chain: <chain id as decimal>
/// expires: <unix seconds>
/// ```
#[must_use]
pub fn faucet_claim_message(address: Address, chain_id: u64, expires: u64) -> String {
    format!("MetaFlux faucet claim\naddress: {address}\nchain: {chain_id}\nexpires: {expires}")
}

fn eip191_digest(message: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(format!("\x19Ethereum Signed Message:\n{}", message.len()).as_bytes());
    hasher.update(message);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

/// Request test USDC from a devnet / testnet faucet. Signs the claim with
/// `wallet`, which is also the recipient.
///
/// POSTs `{ "address", "expires", "signature" }` to `<faucet_base_url>/faucet`.
/// `chain_id` is the chain the faucet serves. The grant is fixed: 3000 USDC and
/// 10 MTF, once per address, ever.
///
/// **The recipient must hold at least 0.01 ETH on Ethereum mainnet.** The node
/// refuses any other address. Show the refusal message to the user as it is.
///
/// The per-IP limits live in the faucet node's memory and reset when it
/// restarts, so they are a speed bump, not a sybil control.
///
/// `faucet_base_url` is the origin that serves `/faucet`: `http://localhost:8080`
/// on devnet, `https://api.testnet.mtf.exchange` on testnet.
///
/// On success the credit is `"queued"` for the next block; the balance updates
/// after ~1 block, not synchronously.
///
/// # Errors
/// See [`request_faucet_with_claim`].
pub async fn request_faucet(
    faucet_base_url: &str,
    wallet: &Wallet,
    chain_id: u64,
) -> Result<FaucetResponse, ClientError> {
    let claim = FaucetClaim::sign(wallet, chain_id)?;
    request_faucet_with_claim(faucet_base_url, &claim).await
}

/// Send a claim that is already signed, e.g. by a browser or hardware wallet
/// over [`faucet_claim_message`]. Otherwise the same as [`request_faucet`].
///
/// # Errors
/// - [`ClientError::Builder`] if `faucet_base_url` is not `http(s)://` or the
///   HTTP client cannot be constructed.
/// - [`ClientError::ProtocolError`] on a non-2xx status, carrying the server's
///   `{ "error": ... }` message as it is. The message is prose: show it, and
///   do not match on it. `400` refuses a bad address and a missing, malformed
///   or expired claim. `403` refuses a signature from another wallet and a
///   recipient under the 0.01 ETH balance. `429` refuses an address that
///   already claimed, the per-IP window and too many balance checks from one
///   IP. `503` answers an empty reserve, a full backlog and a balance check
///   that cannot run now.
/// - [`ClientError::Http`] / [`ClientError::Decode`] on transport / decode
///   failure.
pub async fn request_faucet_with_claim(
    faucet_base_url: &str,
    claim: &FaucetClaim,
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

    let resp = http.post(&url).json(claim).send().await?;
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
        let claim = FaucetClaim::sign(&Wallet::random_for_testing(), 114_514).unwrap();
        let err = request_faucet_with_claim("ftp://faucet", &claim)
            .await
            .unwrap_err();
        assert!(matches!(err, ClientError::Builder(_)));
    }
}
