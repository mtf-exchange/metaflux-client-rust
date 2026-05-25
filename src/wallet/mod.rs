//! Wallet — secp256k1 keypair management + EIP-712 signing.
//!
//! Determinism: ECDSA signatures use [RFC-6979] deterministic nonces (k256's
//! default), so a given key + message produces a fixed signature. This is
//! important for replay-based tests and for any deduplication on the server
//! side.
//!
//! Address: the 20-byte EVM address is `keccak256(uncompressed_pubkey[1..])[12..]`
//! — i.e. the last 20 bytes of the keccak256 of the 64-byte uncompressed
//! pubkey (skip the `0x04` prefix).
//!
//! EIP-712: see [`Eip712`] for the per-domain struct contract; [`Wallet::sign_eip712`]
//! computes the 32-byte digest and signs it with secp256k1, returning a
//! 65-byte `r || s || v` signature where `v ∈ {27, 28}`.
//!
//! No clipboard / no env-var auto-pickup — callers pass key bytes
//! explicitly. We intentionally do not bundle keystore parsing in the SDK
//! itself; users who need that wire up their preferred crate (e.g. `eth-keystore`).
//!
//! [RFC-6979]: https://datatracker.ietf.org/doc/html/rfc6979

mod key;
mod sign;

pub use key::{Address, Wallet};
pub use sign::{Eip712, Signature};

// Test-only escape hatch used by integration tests + the exchange module's
// `_recover_for_test` shim. Not part of the stable public API.
#[doc(hidden)]
pub fn sign_recover_for_test_only(
    digest: &[u8; 32],
    sig: &Signature,
) -> Result<Address, crate::error::ClientError> {
    sign::recover_address(digest, sig)
}
