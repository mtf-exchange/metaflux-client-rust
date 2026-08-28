//! Crate-wide error type, and the typed rejection the node answers with.
//!
//! Every fallible SDK operation returns [`Result<T, ClientError>`]. The
//! variants are deliberately coarse — enough to discriminate the failure
//! mode for retry policy, but not so granular that callers have to match on
//! every wire field.
//!
//! A node rejection arrives as [`ClientError::Api`], carrying an [`ApiError`].
//! Match on [`ApiError::code`]; never on [`ApiError::message`], which is prose
//! and may change in any release.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable machine-readable rejection code — the part of an error a caller may
/// match on.
///
/// The node namespaces the codes by prefix: `ORDER_`, `MARGIN_`, `AUTH_`,
/// `MARKET_`, `ASSET_`, `RATE_`, plus the generic request-shape codes.
///
/// [`ErrorCode::Unknown`] keeps the wire string of a code this SDK build does
/// not know. A newer node can add a code without breaking the decode, so an
/// SDK upgrade is never required to read a rejection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
#[non_exhaustive]
pub enum ErrorCode {
    /// `ORDER_NOT_FOUND`
    OrderNotFound,
    /// `ORDER_ZERO_SIZE`
    OrderZeroSize,
    /// `ORDER_INVALID_PRICE` — carries `details` with the tick bound.
    OrderInvalidPrice,
    /// `ORDER_INVALID_SIZE` — carries `details` with the lot bound.
    OrderInvalidSize,
    /// `ORDER_BELOW_MIN_NOTIONAL`
    OrderBelowMinNotional,
    /// `ORDER_SELF_TRADE`
    OrderSelfTrade,
    /// `ORDER_DUPLICATE_CLOID`
    OrderDuplicateCloid,
    /// `MARGIN_INSUFFICIENT` — carries `details` with the collateral bound.
    MarginInsufficient,
    /// `AUTH_UNAUTHORIZED`
    AuthUnauthorized,
    /// `AUTH_BAD_SIGNATURE`
    AuthBadSignature,
    /// `AUTH_AGENT_FORBIDDEN`
    AuthAgentForbidden,
    /// `MARKET_NOT_FOUND`
    MarketNotFound,
    /// `MARKET_INACTIVE`
    MarketInactive,
    /// `MARKET_OI_CAP`
    MarketOiCap,
    /// `ASSET_INSUFFICIENT_BALANCE`
    AssetInsufficientBalance,
    /// `RATE_LIMITED` — back off and retry.
    RateLimited,
    /// `INVALID_REQUEST` — a missing, unparseable or out-of-range field.
    InvalidRequest,
    /// `UNKNOWN_TYPE` — the `/info` `type` discriminator names no read.
    UnknownType,
    /// `NOT_FOUND` — a named resource, such as a vault or an account.
    NotFound,
    /// `ACTION_UNSUPPORTED` — the action decodes but this node build cannot
    /// apply it.
    ActionUnsupported,
    /// `PRECONDITION_FAILED` — a state precondition the taxonomy does not
    /// name. Read `message` for the reason.
    PreconditionFailed,
    /// `INTERNAL` — a node defect, not caller input. Retry is safe.
    Internal,
    /// `UNAVAILABLE` — an upstream the request needs is down.
    Unavailable,
    /// A code this SDK build does not know, kept verbatim.
    Unknown(String),
}

impl ErrorCode {
    /// The wire string of this code.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::OrderNotFound => "ORDER_NOT_FOUND",
            Self::OrderZeroSize => "ORDER_ZERO_SIZE",
            Self::OrderInvalidPrice => "ORDER_INVALID_PRICE",
            Self::OrderInvalidSize => "ORDER_INVALID_SIZE",
            Self::OrderBelowMinNotional => "ORDER_BELOW_MIN_NOTIONAL",
            Self::OrderSelfTrade => "ORDER_SELF_TRADE",
            Self::OrderDuplicateCloid => "ORDER_DUPLICATE_CLOID",
            Self::MarginInsufficient => "MARGIN_INSUFFICIENT",
            Self::AuthUnauthorized => "AUTH_UNAUTHORIZED",
            Self::AuthBadSignature => "AUTH_BAD_SIGNATURE",
            Self::AuthAgentForbidden => "AUTH_AGENT_FORBIDDEN",
            Self::MarketNotFound => "MARKET_NOT_FOUND",
            Self::MarketInactive => "MARKET_INACTIVE",
            Self::MarketOiCap => "MARKET_OI_CAP",
            Self::AssetInsufficientBalance => "ASSET_INSUFFICIENT_BALANCE",
            Self::RateLimited => "RATE_LIMITED",
            Self::InvalidRequest => "INVALID_REQUEST",
            Self::UnknownType => "UNKNOWN_TYPE",
            Self::NotFound => "NOT_FOUND",
            Self::ActionUnsupported => "ACTION_UNSUPPORTED",
            Self::PreconditionFailed => "PRECONDITION_FAILED",
            Self::Internal => "INTERNAL",
            Self::Unavailable => "UNAVAILABLE",
            Self::Unknown(s) => s,
        }
    }

    /// Parse a wire code. An unrecognized code becomes
    /// [`ErrorCode::Unknown`], so a newer node never breaks the decode.
    #[must_use]
    pub fn from_wire(s: &str) -> Self {
        match s {
            "ORDER_NOT_FOUND" => Self::OrderNotFound,
            "ORDER_ZERO_SIZE" => Self::OrderZeroSize,
            "ORDER_INVALID_PRICE" => Self::OrderInvalidPrice,
            "ORDER_INVALID_SIZE" => Self::OrderInvalidSize,
            "ORDER_BELOW_MIN_NOTIONAL" => Self::OrderBelowMinNotional,
            "ORDER_SELF_TRADE" => Self::OrderSelfTrade,
            "ORDER_DUPLICATE_CLOID" => Self::OrderDuplicateCloid,
            "MARGIN_INSUFFICIENT" => Self::MarginInsufficient,
            "AUTH_UNAUTHORIZED" => Self::AuthUnauthorized,
            "AUTH_BAD_SIGNATURE" => Self::AuthBadSignature,
            "AUTH_AGENT_FORBIDDEN" => Self::AuthAgentForbidden,
            "MARKET_NOT_FOUND" => Self::MarketNotFound,
            "MARKET_INACTIVE" => Self::MarketInactive,
            "MARKET_OI_CAP" => Self::MarketOiCap,
            "ASSET_INSUFFICIENT_BALANCE" => Self::AssetInsufficientBalance,
            "RATE_LIMITED" => Self::RateLimited,
            "INVALID_REQUEST" => Self::InvalidRequest,
            "UNKNOWN_TYPE" => Self::UnknownType,
            "NOT_FOUND" => Self::NotFound,
            "ACTION_UNSUPPORTED" => Self::ActionUnsupported,
            "PRECONDITION_FAILED" => Self::PreconditionFailed,
            "INTERNAL" => Self::Internal,
            "UNAVAILABLE" => Self::Unavailable,
            other => Self::Unknown(other.to_string()),
        }
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<String> for ErrorCode {
    fn from(s: String) -> Self {
        Self::from_wire(&s)
    }
}

impl From<ErrorCode> for String {
    fn from(c: ErrorCode) -> Self {
        match c {
            ErrorCode::Unknown(s) => s,
            other => other.as_str().to_string(),
        }
    }
}

/// The bound a rejection violated.
///
/// Every field is optional: a missing-argument rejection names only the
/// `field`, while a grid or margin rejection also carries `limit` and
/// `actual`. Both numbers are canonical decimal strings, so precision
/// survives past 2^53.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorDetails {
    /// Request field the bound applies to, such as `px` or `sz`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// The bound itself — a tick size, a lot size, or the balance available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<String>,
    /// The value the request carried, or the amount it required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual: Option<String>,
}

/// A typed node rejection: the `error` half of the response envelope, and the
/// per-order rejection entry inside a `statuses` array.
///
/// `code` is the stable contract. `message` is prose and may change in any
/// release, so never match on it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiError {
    /// Stable machine-readable code. Match on this.
    pub code: ErrorCode,
    /// Human sentence. Prose — do not match on it.
    pub message: String,
    /// The bound that was violated. Absent when the rejection carries none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<ErrorDetails>,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

/// The single error type returned by every fallible operation in this SDK.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ClientError {
    /// Client setup failure (bad URL, TLS init, etc.).
    #[error("client builder error: {0}")]
    Builder(String),

    /// HTTP transport failure (connection refused, timeout, etc.).
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON encode / decode failure.
    #[error("decode error: {0}")]
    Decode(#[from] serde_json::Error),

    /// The node rejected the request. Carries the typed [`ApiError`] from the
    /// `error` half of the response envelope.
    ///
    /// A commit-time `/exchange` verdict answers `200` and still rejects, so
    /// this variant does not imply a failure HTTP status.
    #[error("api error {0}")]
    Api(ApiError),

    /// The server answered a failure status with no typed error envelope —
    /// a proxy page, an empty body, or a non-JSON response.
    ///
    /// `code` is the HTTP status code; `msg` is the raw body.
    #[error("protocol error ({code}): {msg}")]
    ProtocolError {
        /// HTTP status code returned by the server.
        code: u16,
        /// Raw response body.
        msg: String,
    },

    /// EIP-712 signature production failed.
    #[error("signature error: {0}")]
    Signature(String),

    /// The signature recovered does not match the wallet's address.
    ///
    /// This indicates an internal bug — the SDK signed a message but
    /// recovering the signer from the digest + signature did not yield the
    /// expected address. Should never happen in practice.
    #[error("signature mismatch: expected signer {expected}, recovered {recovered}")]
    SignatureMismatch {
        /// Expected signer address (hex, no 0x prefix).
        expected: String,
        /// Recovered signer address (hex, no 0x prefix).
        recovered: String,
    },

    /// Private key parsing failed (wrong length / not hex / out of curve).
    #[error("invalid key: {0}")]
    InvalidKey(String),

    /// WebSocket transport failure.
    #[error("websocket error: {0}")]
    WebSocket(String),

    /// User input failed local validation before any network call.
    #[error("validation error: {0}")]
    Validation(String),
}

impl From<k256::ecdsa::Error> for ClientError {
    fn from(e: k256::ecdsa::Error) -> Self {
        Self::Signature(e.to_string())
    }
}

impl From<tokio_tungstenite::tungstenite::Error> for ClientError {
    fn from(e: tokio_tungstenite::tungstenite::Error) -> Self {
        Self::WebSocket(e.to_string())
    }
}
