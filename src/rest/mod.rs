//! REST client — `/info`, `/exchange`, `/explorer` MTF-native endpoints.
//!
//! The [`RestClient`] is constructed via [`Client::new`] (in the crate root)
//! or built directly with [`RestClient::new`]. It holds a long-lived
//! `reqwest::Client` so connection pooling is reused across calls.
//!
//! Three sub-namespaces:
//!
//! - [`info`]      — read-only queries (no signing required).
//! - [`exchange`]  — write actions (EIP-712 signed; takes `&Wallet`).
//! - [`explorer`]  — block / tx lookups.
//!
//! Every method returns [`Result<T, crate::ClientError>`].
//!
//! [`Client::new`]: crate::Client::new

use std::time::Duration;

use reqwest::Client as HttpClient;
use serde::Serialize;
use serde_json::Value;

use crate::error::ClientError;

pub mod exchange;
pub mod explorer;
pub mod info;

/// REST client. Cheap to clone (uses an `Arc` internally via `reqwest::Client`).
#[derive(Debug, Clone)]
pub struct RestClient {
    base_url: String,
    http: HttpClient,
}

impl RestClient {
    /// Build a REST client pointing at the given base URL.
    ///
    /// `base_url` should be of the form `https://api.mtf.xyz` (no trailing
    /// slash). Endpoints are appended as `/info`, `/exchange`, etc.
    ///
    /// # Errors
    /// Returns [`ClientError::Builder`] on TLS / config failure.
    pub fn new(base_url: impl Into<String>) -> Result<Self, ClientError> {
        let base_url = base_url.into();
        if !base_url.starts_with("http://") && !base_url.starts_with("https://") {
            return Err(ClientError::Builder(format!(
                "base_url must start with http(s)://, got `{base_url}`"
            )));
        }
        let base_url = base_url.trim_end_matches('/').to_string();
        let http = HttpClient::builder()
            .user_agent(concat!("metaflux-client/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(30))
            .pool_idle_timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| ClientError::Builder(e.to_string()))?;
        Ok(Self { base_url, http })
    }

    /// Build with a pre-configured `reqwest::Client` (e.g. proxy, custom TLS roots).
    #[must_use]
    pub fn from_http(base_url: impl Into<String>, http: HttpClient) -> Self {
        let base_url = base_url.into().trim_end_matches('/').to_string();
        Self { base_url, http }
    }

    /// Access the info (read-only) namespace.
    #[must_use]
    pub fn info(&self) -> info::Info<'_> {
        info::Info { client: self }
    }

    /// Access the exchange (signed write) namespace.
    #[must_use]
    pub fn exchange(&self) -> exchange::Exchange<'_> {
        exchange::Exchange { client: self }
    }

    /// Access the explorer (block / tx lookup) namespace.
    #[must_use]
    pub fn explorer(&self) -> explorer::Explorer<'_> {
        explorer::Explorer { client: self }
    }

    /// Base URL this client targets (without trailing slash).
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Internal HTTP client accessor (sub-namespaces use this to POST).
    #[allow(dead_code)]
    pub(crate) fn http(&self) -> &HttpClient {
        &self.http
    }

    /// POST JSON to `<base_url>/<path>` and decode the response.
    ///
    /// On HTTP error status, attempts to decode the MTF-native error
    /// envelope (`{"error": "..."}`) into a [`ClientError::ProtocolError`].
    pub(crate) async fn post_json<Req, Resp>(
        &self,
        path: &str,
        body: &Req,
    ) -> Result<Resp, ClientError>
    where
        Req: Serialize + ?Sized,
        Resp: serde::de::DeserializeOwned,
    {
        let url = format!("{}{path}", self.base_url);
        let resp = self.http.post(&url).json(body).send().await?;
        let status = resp.status();
        let bytes = resp.bytes().await?;

        if !status.is_success() {
            // Try to surface the server's error envelope.
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_http_url() {
        let err = RestClient::new("ftp://api.mtf.xyz").unwrap_err();
        assert!(matches!(err, ClientError::Builder(_)));
    }

    #[test]
    fn strips_trailing_slash() {
        let c = RestClient::new("https://api.mtf.xyz/").unwrap();
        assert_eq!(c.base_url(), "https://api.mtf.xyz");
    }
}
