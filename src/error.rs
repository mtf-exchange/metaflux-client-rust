//! Crate-wide error type.
//!
//! Every fallible SDK operation returns [`Result<T, ClientError>`]. The
//! variants are deliberately coarse — enough to discriminate the failure
//! mode for retry policy, but not so granular that callers have to match on
//! every wire field.

use thiserror::Error;

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

    /// The server returned an error envelope with a code + message.
    ///
    /// `code` is the HTTP status code; `msg` is the `error` field from the
    /// MTF-native error envelope (`{"error": "..."}`).
    #[error("protocol error ({code}): {msg}")]
    ProtocolError {
        /// HTTP status code returned by the server.
        code: u16,
        /// Error message from the server's error envelope.
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
