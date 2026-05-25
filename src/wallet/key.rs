//! Key + address derivation.
//!
//! Holds the [`Wallet`] struct (an owning wrapper around a `SecretKey`) and
//! the [`Address`] newtype representing a 20-byte EVM address.
//!
//! Signing methods live in [`crate::wallet::sign`]; this file only handles
//! key parsing, address derivation, and key lifecycle (construction, debug
//! redaction).

use core::fmt;

use k256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Keccak};

use crate::error::ClientError;

/// 20-byte EVM-compatible address (last 20 bytes of `keccak256(pubkey)`).
///
/// The address is the canonical user identifier in EIP-712 messages and in
/// the MTF state machine's `Address` field.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Address(#[serde(with = "hex_array_20")] pub [u8; 20]);

impl Address {
    /// Zero address (all 20 bytes = 0).
    pub const ZERO: Self = Self([0u8; 20]);

    /// Wrap a raw 20-byte address.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    /// Parse a hex address (with or without `0x` prefix).
    ///
    /// # Errors
    /// Returns [`ClientError::InvalidKey`] if the input is not 40 hex chars
    /// or not valid hex.
    pub fn from_hex(s: &str) -> Result<Self, ClientError> {
        let stripped = s.strip_prefix("0x").unwrap_or(s);
        if stripped.len() != 40 {
            return Err(ClientError::InvalidKey(format!(
                "address hex must be 40 chars, got {}",
                stripped.len()
            )));
        }
        let bytes = hex::decode(stripped)
            .map_err(|e| ClientError::InvalidKey(format!("address hex decode: {e}")))?;
        let mut out = [0u8; 20];
        out.copy_from_slice(&bytes);
        Ok(Self(out))
    }

    /// Raw 20-byte payload.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

/// Serde helper: encode `[u8; 20]` as a 0x-prefixed lowercase hex string.
mod hex_array_20 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 20], s: S) -> Result<S::Ok, S::Error> {
        let hex_str = format!("0x{}", hex::encode(bytes));
        s.serialize_str(&hex_str)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 20], D::Error> {
        let s: String = String::deserialize(d)?;
        let stripped = s.strip_prefix("0x").unwrap_or(&s);
        if stripped.len() != 40 {
            return Err(serde::de::Error::custom(format!(
                "address hex must be 40 chars, got {}",
                stripped.len()
            )));
        }
        let bytes = hex::decode(stripped).map_err(serde::de::Error::custom)?;
        let mut out = [0u8; 20];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

/// An owning secp256k1 wallet.
///
/// Construction is explicit (`from_bytes` / `from_hex` / `random_for_testing`).
/// The inner `SigningKey` zeroizes on drop automatically. `Debug` does **not**
/// reveal the key material — only the derived address.
#[derive(Clone)]
pub struct Wallet {
    key: SigningKey,
    address: Address,
}

impl Wallet {
    /// Construct from a 32-byte secret scalar.
    ///
    /// # Errors
    /// Returns [`ClientError::InvalidKey`] if the bytes are not a valid
    /// secp256k1 scalar (zero or ≥ curve order).
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, ClientError> {
        let key = SigningKey::from_bytes(&bytes.into())
            .map_err(|e| ClientError::InvalidKey(e.to_string()))?;
        let address = address_from_signing_key(&key);
        Ok(Self { key, address })
    }

    /// Construct from a hex private key (with or without `0x` prefix).
    ///
    /// # Errors
    /// Returns [`ClientError::InvalidKey`] on wrong length / non-hex / not a
    /// valid scalar.
    pub fn from_hex(s: &str) -> Result<Self, ClientError> {
        let stripped = s.strip_prefix("0x").unwrap_or(s);
        if stripped.len() != 64 {
            return Err(ClientError::InvalidKey(format!(
                "private key hex must be 64 chars, got {}",
                stripped.len()
            )));
        }
        let raw = hex::decode(stripped)
            .map_err(|e| ClientError::InvalidKey(format!("private key hex decode: {e}")))?;
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&raw);
        Self::from_bytes(bytes)
    }

    /// Generate a random wallet for tests.
    ///
    /// **Do not use this for production keys.** It pulls from `OsRng`; for
    /// non-test paths, derive keys deterministically from a known seed (e.g.
    /// BIP-39 mnemonic via a separate crate).
    #[doc(hidden)]
    #[must_use]
    pub fn random_for_testing() -> Self {
        let key = SigningKey::random(&mut k256::elliptic_curve::rand_core::OsRng);
        let address = address_from_signing_key(&key);
        Self { key, address }
    }

    /// Derived 20-byte EVM address.
    #[must_use]
    pub const fn address(&self) -> Address {
        self.address
    }

    /// Internal accessor for the signing key (kept crate-private to keep
    /// the secret surface tight; signing goes through [`Wallet::sign_eip712`]
    /// and friends).
    pub(crate) const fn signing_key(&self) -> &SigningKey {
        &self.key
    }
}

impl fmt::Debug for Wallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Wallet")
            .field("address", &self.address)
            .field("key", &"<redacted>")
            .finish()
    }
}

/// Compute the 20-byte EVM address from a `SigningKey`.
///
/// Returns `keccak256(uncompressed_pubkey_64)[12..32]` where
/// `uncompressed_pubkey_64` is the 64-byte X || Y of the public key (without
/// the `0x04` SEC1 prefix).
fn address_from_signing_key(key: &SigningKey) -> Address {
    let verifying = key.verifying_key();
    let point = verifying.to_encoded_point(/* compress= */ false);
    let pubkey_bytes = point.as_bytes(); // 65 bytes (0x04 || X || Y)
    debug_assert_eq!(pubkey_bytes.len(), 65);
    debug_assert_eq!(pubkey_bytes[0], 0x04);

    let mut hasher = Keccak::v256();
    hasher.update(&pubkey_bytes[1..]); // skip the 0x04 prefix
    let mut digest = [0u8; 32];
    hasher.finalize(&mut digest);

    let mut addr = [0u8; 20];
    addr.copy_from_slice(&digest[12..32]);
    Address(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// EIP-55 spec vector: private key `0x4646...4646` -> address
    /// `0x9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f`. We don't enforce
    /// EIP-55 checksum casing here since the SDK uses raw 20-byte
    /// `Address`, but the lowercase hex must match.
    #[test]
    fn known_vector_eip55_book_example() {
        // From the EIP-55 reference test vectors.
        let priv_hex = "4646464646464646464646464646464646464646464646464646464646464646";
        let wallet = Wallet::from_hex(priv_hex).unwrap();
        let got = hex::encode(wallet.address().as_bytes());
        // Address derived from this private key:
        //   pubkey = secp256k1_g^k
        //   keccak256(pubkey[1..])[12..]
        // Calculated reference: 9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f
        assert_eq!(got, "9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f");
    }

    #[test]
    fn from_hex_accepts_0x_prefix() {
        let a =
            Wallet::from_hex("0x4646464646464646464646464646464646464646464646464646464646464646")
                .unwrap();
        let b =
            Wallet::from_hex("4646464646464646464646464646464646464646464646464646464646464646")
                .unwrap();
        assert_eq!(a.address(), b.address());
    }

    #[test]
    fn from_hex_rejects_short_input() {
        let e = Wallet::from_hex("dead").unwrap_err();
        assert!(matches!(e, ClientError::InvalidKey(_)));
    }

    #[test]
    fn from_hex_rejects_non_hex() {
        let e = Wallet::from_hex(&"z".repeat(64)).unwrap_err();
        assert!(matches!(e, ClientError::InvalidKey(_)));
    }

    #[test]
    fn address_parses_with_and_without_prefix() {
        let a = Address::from_hex("0x9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f").unwrap();
        let b = Address::from_hex("9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn address_display_lowercase_hex() {
        let a = Address::from_bytes([0x9du8; 20]);
        let s = format!("{a}");
        assert!(s.starts_with("0x"));
        assert_eq!(s.len(), 42);
    }

    #[test]
    fn debug_redacts_secret() {
        let w = Wallet::random_for_testing();
        let dbg = format!("{w:?}");
        assert!(dbg.contains("redacted"));
        assert!(!dbg.to_lowercase().contains("signingkey"));
    }
}
