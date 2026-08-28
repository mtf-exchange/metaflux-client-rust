//! REST client — `/info` and `/exchange` MTF-native endpoints.
//!
//! The [`RestClient`] is constructed via [`Client::new`] (in the crate root)
//! or built directly with [`RestClient::new`]. It holds a long-lived
//! `reqwest::Client` so connection pooling is reused across calls.
//!
//! Two sub-namespaces:
//!
//! - [`info`]      — read-only queries (no signing required).
//! - [`exchange`]  — write actions (EIP-712 signed; takes `&Wallet`).
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
pub mod exchange_typed;
pub mod info;
pub mod place;

/// REST client. Cheap to clone (uses an `Arc` internally via `reqwest::Client`).
#[derive(Debug, Clone)]
pub struct RestClient {
    base_url: String,
    http: HttpClient,
}

impl RestClient {
    /// Build a REST client pointing at the given base URL.
    ///
    /// `base_url` should be of the form `https://api.devnet.mtf.exchange` (no trailing
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
        exchange::Exchange {
            client: self,
            expires_after_ms: 0,
        }
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
    /// Splits the response envelope through [`decode_envelope`]: a success
    /// decodes the `data` payload, a rejection becomes
    /// [`ClientError::Api`]. A failure status with no typed error envelope
    /// becomes [`ClientError::ProtocolError`], carrying the raw body.
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

        let value: Value = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(e) => {
                return Err(if status.is_success() {
                    ClientError::from(e)
                } else {
                    protocol_error(status.as_u16(), &bytes)
                });
            }
        };

        // The body decides, not the status: a committed `/exchange` action the
        // node then refused answers `200` with an `error` half.
        let payload = decode_envelope(value)?;
        if !status.is_success() {
            return Err(protocol_error(status.as_u16(), &bytes));
        }
        serde_json::from_value(payload).map_err(ClientError::from)
    }
}

fn protocol_error(code: u16, bytes: &[u8]) -> ClientError {
    ClientError::ProtocolError {
        code,
        msg: String::from_utf8_lossy(bytes).into_owned(),
    }
}

/// Split the shared `/info` + `/exchange` response envelope.
///
/// The two keys are asymmetric on purpose:
///
/// - success — `{"data": <payload>}`; `error` is absent.
/// - failure — `{"error": {"code", "message", "details"?}}`; `data` is absent.
///
/// `data` may itself be `null`: a read can succeed with no content. A
/// present-and-null `data` is therefore a success, never an error.
///
/// `/info` folds its `type` discriminator INSIDE `data`, so a payload field
/// stays at the same path it had before.
///
/// A body carrying neither key is returned verbatim, so a non-enveloped
/// endpoint still decodes.
///
/// # Errors
/// [`ClientError::Api`] when the body carries a non-null `error` half.
pub(crate) fn decode_envelope(value: Value) -> Result<Value, ClientError> {
    match value {
        // A null `error` is not a rejection — it is a success on a node build
        // that still emits both keys.
        Value::Object(mut map) if map.get("error").is_some_and(|e| !e.is_null()) => {
            let raw = map.remove("error").unwrap_or(Value::Null);
            Err(ClientError::Api(serde_json::from_value(raw)?))
        }
        Value::Object(mut map) if map.contains_key("data") => {
            Ok(map.remove("data").unwrap_or(Value::Null))
        }
        other => Ok(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorCode;

    #[test]
    fn rejects_non_http_url() {
        let err = RestClient::new("ftp://api.devnet.mtf.exchange").unwrap_err();
        assert!(matches!(err, ClientError::Builder(_)));
    }

    #[test]
    fn strips_trailing_slash() {
        let c = RestClient::new("https://api.devnet.mtf.exchange/").unwrap();
        assert_eq!(c.base_url(), "https://api.devnet.mtf.exchange");
    }

    #[test]
    fn peels_data_and_keeps_the_type_inside_it() {
        let env = serde_json::json!({
            "data": { "type": "fee_schedule", "chain_id": 114514, "epoch": 1 }
        });
        let inner = decode_envelope(env).expect("success");
        assert_eq!(inner["type"], "fee_schedule");
        assert_eq!(inner["chain_id"], 114514);
    }

    #[test]
    fn a_null_data_is_a_success_not_an_error() {
        let inner = decode_envelope(serde_json::json!({ "data": null })).expect("success");
        assert_eq!(inner, Value::Null);
    }

    #[test]
    fn error_half_decodes_typed() {
        let env = serde_json::json!({
            "error": {
                "code": "ORDER_INVALID_PRICE",
                "message": "price off grid: 12345 is not a multiple of tick_size 100",
                "details": { "field": "px", "limit": "100", "actual": "12345" }
            }
        });
        let ClientError::Api(e) = decode_envelope(env).unwrap_err() else {
            panic!("expected Api");
        };
        assert_eq!(e.code, ErrorCode::OrderInvalidPrice);
        let d = e.details.expect("details");
        assert_eq!(d.field.as_deref(), Some("px"));
        assert_eq!(d.limit.as_deref(), Some("100"));
        assert_eq!(d.actual.as_deref(), Some("12345"));
    }

    #[test]
    fn absent_details_stays_none() {
        let env = serde_json::json!({
            "error": { "code": "ORDER_NOT_FOUND", "message": "order not found" }
        });
        let ClientError::Api(e) = decode_envelope(env).unwrap_err() else {
            panic!("expected Api");
        };
        assert!(
            e.details.is_none(),
            "absent details must not decode as empty"
        );
    }

    /// A partial `details` — the shape a missing-argument rejection carries.
    #[test]
    fn partial_details_decodes() {
        let env = serde_json::json!({
            "error": {
                "code": "INVALID_REQUEST",
                "message": "missing field `type`",
                "details": { "field": "type" }
            }
        });
        let ClientError::Api(e) = decode_envelope(env).unwrap_err() else {
            panic!("expected Api");
        };
        let d = e.details.expect("details");
        assert_eq!(d.field.as_deref(), Some("type"));
        assert!(d.limit.is_none() && d.actual.is_none());
    }

    /// A code a newer node adds must not fail the parse.
    #[test]
    fn unknown_code_keeps_the_wire_string() {
        let env = serde_json::json!({
            "error": { "code": "ORDER_FROM_THE_FUTURE", "message": "nope" }
        });
        let ClientError::Api(e) = decode_envelope(env).unwrap_err() else {
            panic!("expected Api");
        };
        assert_eq!(e.code, ErrorCode::Unknown("ORDER_FROM_THE_FUTURE".into()));
        assert_eq!(e.code.as_str(), "ORDER_FROM_THE_FUTURE");
    }

    #[test]
    fn passes_bare_object_through_unchanged() {
        let bare = serde_json::json!({ "accepted": true, "mempool_depth": 3 });
        assert_eq!(decode_envelope(bare.clone()).unwrap(), bare);
    }

    #[test]
    fn passes_array_through_unchanged() {
        let arr = serde_json::json!([1, 2, 3]);
        assert_eq!(decode_envelope(arr.clone()).unwrap(), arr);
    }

    /// A node build that emits both keys with a null `error` is a success.
    #[test]
    fn null_error_half_is_not_a_rejection() {
        let env = serde_json::json!({ "data": { "x": 1 }, "error": null });
        assert_eq!(decode_envelope(env).unwrap(), serde_json::json!({ "x": 1 }));
    }
}
