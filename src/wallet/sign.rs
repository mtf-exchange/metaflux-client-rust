//! EIP-712 signing.
//!
//! Implements:
//!
//! ```text
//!   digest = keccak256(0x19 || 0x01 || domain_separator || struct_hash)
//!   sig    = ECDSA-RFC6979(secret, digest)  // 32-byte r || 32-byte s
//!   v      = recovery_id + 27               // {27, 28}
//! ```
//!
//! Per-domain types implement [`Eip712`] (one trait impl per typed message).
//! The default [`Eip712::to_digest`] does the standard EIP-712 envelope —
//! types only need to provide `domain_separator()` + `struct_hash()`.

use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{RecoveryId, Signature as K256Sig};
use tiny_keccak::{Hasher, Keccak};

use crate::error::ClientError;
use crate::wallet::key::Wallet;

/// A 65-byte EIP-712 signature: `r (32) || s (32) || v (1)`.
///
/// `v ∈ {27, 28}` follows the "legacy" Ethereum-style recovery id. The MTF
/// node's signature verifier expects this layout.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature {
    /// First 32 bytes of the signature.
    pub r: [u8; 32],
    /// Second 32 bytes of the signature.
    pub s: [u8; 32],
    /// Recovery id, encoded as `27 + parity` (matches Ethereum legacy txs).
    pub v: u8,
}

impl Signature {
    /// Encode as a 65-byte big-endian blob (`r || s || v`).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 65] {
        let mut out = [0u8; 65];
        out[..32].copy_from_slice(&self.r);
        out[32..64].copy_from_slice(&self.s);
        out[64] = self.v;
        out
    }

    /// Hex-encode as a 0x-prefixed lowercase string (132 chars).
    #[must_use]
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.to_bytes()))
    }
}

impl core::fmt::Debug for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Signature")
            .field("r", &hex::encode(self.r))
            .field("s", &hex::encode(self.s))
            .field("v", &self.v)
            .finish()
    }
}

/// EIP-712 typed-data trait.
///
/// Domains implement this once per typed message; the SDK provides
/// [`Eip712::to_digest`] as a default that builds the standard envelope.
///
/// Implementers MUST encode the domain separator and the struct hash per
/// the EIP-712 spec — typically:
///
/// ```text
///   domain_separator = keccak256(encode(EIP712Domain, domain))
///   struct_hash      = keccak256(typeHash || encode(field_1) || encode(field_2) || ...)
/// ```
pub trait Eip712 {
    /// 32-byte EIP-712 domain separator.
    fn domain_separator(&self) -> [u8; 32];

    /// 32-byte EIP-712 struct hash for this typed message.
    fn struct_hash(&self) -> [u8; 32];

    /// Produce the 32-byte EIP-712 digest for this message.
    ///
    /// `keccak256(0x19 || 0x01 || domain_separator || struct_hash)`.
    fn to_digest(&self) -> [u8; 32] {
        let domain = self.domain_separator();
        let strukt = self.struct_hash();
        let mut hasher = Keccak::v256();
        hasher.update(&[0x19, 0x01]);
        hasher.update(&domain);
        hasher.update(&strukt);
        let mut out = [0u8; 32];
        hasher.finalize(&mut out);
        out
    }
}

impl Wallet {
    /// Sign an EIP-712 typed message and produce a 65-byte signature.
    ///
    /// The signing is deterministic (RFC-6979 nonces).
    ///
    /// # Errors
    /// Returns [`ClientError::Signature`] only if the k256 prehash signer
    /// fails, which is extremely rare (essentially never in practice for
    /// valid keys + 32-byte digests).
    pub fn sign_eip712<T: Eip712>(&self, msg: &T) -> Result<Signature, ClientError> {
        let digest = msg.to_digest();
        self.sign_digest(&digest)
    }

    /// Sign an arbitrary 32-byte digest with the wallet key.
    ///
    /// Lower-level than [`Wallet::sign_eip712`] — use only when you already
    /// have the EIP-712 digest computed externally.
    ///
    /// # Errors
    /// See [`Wallet::sign_eip712`].
    pub fn sign_digest(&self, digest: &[u8; 32]) -> Result<Signature, ClientError> {
        let signing_key = self.signing_key();
        let (sig, recid): (K256Sig, RecoveryId) = signing_key.sign_prehash(digest)?;
        // k256 returns a normalized (low-S) signature; legacy v = 27 + parity.
        let bytes = sig.to_bytes();
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&bytes[..32]);
        s.copy_from_slice(&bytes[32..]);
        let v = 27 + recid.to_byte();
        Ok(Signature { r, s, v })
    }
}

/// Convenience: recover the signer address from a digest + signature.
///
/// Used in tests to assert sign/recover round-trips. Not pub in the
/// stable API surface because production code paths verify on the server,
/// but exposed for the integration tests in `tests/` via
/// [`crate::wallet::sign_recover_for_test_only`].
pub(crate) fn recover_address(
    digest: &[u8; 32],
    sig: &Signature,
) -> Result<crate::wallet::key::Address, ClientError> {
    use k256::ecdsa::VerifyingKey;

    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&sig.r);
    sig_bytes[32..].copy_from_slice(&sig.s);
    let k_sig = K256Sig::from_slice(&sig_bytes)
        .map_err(|e| ClientError::Signature(format!("sig decode: {e}")))?;
    let recid_byte = sig
        .v
        .checked_sub(27)
        .ok_or_else(|| ClientError::Signature(format!("invalid v = {}", sig.v)))?;
    let recid = RecoveryId::from_byte(recid_byte)
        .ok_or_else(|| ClientError::Signature(format!("invalid recovery id = {recid_byte}")))?;

    let verifying = VerifyingKey::recover_from_prehash(digest, &k_sig, recid)?;
    let point = verifying.to_encoded_point(false);
    let pubkey_bytes = point.as_bytes();
    let mut hasher = Keccak::v256();
    hasher.update(&pubkey_bytes[1..]);
    let mut h = [0u8; 32];
    hasher.finalize(&mut h);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&h[12..]);
    Ok(crate::wallet::key::Address::from_bytes(addr))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Toy `Eip712` impl whose domain + struct hash are fixed bytes —
    /// used to exercise the digest formula.
    struct ToyMsg {
        domain: [u8; 32],
        strukt: [u8; 32],
    }
    impl Eip712 for ToyMsg {
        fn domain_separator(&self) -> [u8; 32] {
            self.domain
        }
        fn struct_hash(&self) -> [u8; 32] {
            self.strukt
        }
    }

    #[test]
    fn signature_round_trip_recovers_signer() {
        let wallet = Wallet::random_for_testing();
        let msg = ToyMsg {
            domain: [0xAAu8; 32],
            strukt: [0xBBu8; 32],
        };
        let sig = wallet.sign_eip712(&msg).unwrap();
        let recovered = recover_address(&msg.to_digest(), &sig).unwrap();
        assert_eq!(recovered, wallet.address());
    }

    #[test]
    fn rfc6979_signing_is_deterministic() {
        let wallet = Wallet::random_for_testing();
        let msg = ToyMsg {
            domain: [0x01u8; 32],
            strukt: [0x02u8; 32],
        };
        let sig_a = wallet.sign_eip712(&msg).unwrap();
        let sig_b = wallet.sign_eip712(&msg).unwrap();
        assert_eq!(sig_a, sig_b, "RFC-6979 must produce identical signatures");
    }

    #[test]
    fn digest_matches_keccak_envelope() {
        let domain = [0xAAu8; 32];
        let strukt = [0xBBu8; 32];
        let msg = ToyMsg { domain, strukt };

        // Hand-computed expected digest.
        let mut hasher = Keccak::v256();
        hasher.update(&[0x19, 0x01]);
        hasher.update(&domain);
        hasher.update(&strukt);
        let mut expected = [0u8; 32];
        hasher.finalize(&mut expected);

        assert_eq!(msg.to_digest(), expected);
    }

    #[test]
    fn signature_hex_is_132_chars() {
        let wallet = Wallet::random_for_testing();
        let msg = ToyMsg {
            domain: [0u8; 32],
            strukt: [0u8; 32],
        };
        let sig = wallet.sign_eip712(&msg).unwrap();
        let h = sig.to_hex();
        assert!(h.starts_with("0x"));
        assert_eq!(h.len(), 132); // 2 + 130 (65 bytes * 2)
    }
}
