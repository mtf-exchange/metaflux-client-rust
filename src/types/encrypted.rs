//! Encrypted orders — threshold-encrypted, MEV-resistant order submissions.
//!
//! Flow:
//! 1. The trader encrypts an order against the validator-committee public key
//!    and commits to the plaintext.
//! 2. The trader submits the ciphertext + commitment to `/exchange` with type
//!    `submit_encrypted_order`.
//! 3. Once `threshold` validators publish decryption shares, the ciphertext is
//!    decrypted and the revealed order is matched (bound to the commitment).

use serde::{Deserialize, Serialize};

use crate::wallet::Address;

/// Action — submit a threshold-encrypted order ciphertext.
///
/// Sender-authorized: the recovered signer is the submitter. Decryption shares
/// accumulate over subsequent blocks until `threshold` is met; the order is
/// then revealed (and checked against `commitment`) and matched.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SubmitEncryptedOrder {
    /// Ciphertext bytes (committee-encrypted).
    pub ciphertext: Vec<u8>,
    /// 32-byte `keccak(plaintext‖salt)` commitment binding the revealed order.
    pub commitment: [u8; 32],
    /// Threshold of decryption shares required to reveal (`≥ 1`).
    pub threshold: u8,
    /// Earliest block at which the ciphertext can be revealed.
    pub target_block: u64,
    /// Deadline (unix ms) by which the order must be revealed, else it expires.
    pub reveal_deadline_ms: u64,
}

/// Snapshot of a pending encrypted-order entry (returned by
/// `info: encrypted_order_state`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct EncryptedOrderState {
    /// Submitter address.
    pub submitter: Address,
    /// Ciphertext bytes (echo).
    pub ciphertext: Vec<u8>,
    /// Number of decryption shares received so far.
    pub decryption_share_count: u8,
    /// Threshold required.
    pub threshold: u8,
    /// Earliest block at which decryption may proceed.
    pub target_block: u64,
    /// Lifecycle: `pending` / `revealed` / `expired`.
    pub status: String,
}

/// Action — `encrypted_order_submit`: submit a threshold-encrypted order under
/// the node's `evm_integration` `EncryptedOrderSubmitParams`.
///
/// The action envelope wraps this under the key **`encrypted`**.
///
/// **Distinct from [`SubmitEncryptedOrder`]:** that 5-field type backs the
/// *different* `submit_encrypted_order` tag (key `params`, the real bridged
/// handler). This 3-field type has **no** `threshold` / `target_block`.
///
/// Forward-compat: the node currently answers this tag with `UnsupportedAction`
/// on the public `/exchange` path; the SDK emits the byte-correct shape the
/// core handler will accept once the bridge lands.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct EncryptedOrderSubmit {
    /// Threshold-encrypted order bytes (node decoder bounds this at 4096).
    /// Serializes as a JSON array of byte-numbers.
    pub ciphertext: Vec<u8>,
    /// 32-byte `keccak(plaintext‖salt)` commitment. Serializes as a JSON array
    /// of 32 byte-numbers.
    pub commitment: [u8; 32],
    /// Absolute consensus-time ms by which a valid plaintext must be revealed.
    pub reveal_deadline_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_order_submit_has_three_fields() {
        let e = EncryptedOrderSubmit {
            ciphertext: vec![1, 2, 3],
            commitment: [9u8; 32],
            reveal_deadline_ms: 123,
        };
        let j = serde_json::to_value(&e).unwrap();
        assert!(j["ciphertext"].is_array());
        assert_eq!(j["commitment"].as_array().unwrap().len(), 32);
        assert_eq!(j["reveal_deadline_ms"], 123);
        // This tag's params carry NO threshold / target_block.
        assert!(j.get("threshold").is_none());
        assert!(j.get("target_block").is_none());
        let dec: EncryptedOrderSubmit = serde_json::from_value(j).unwrap();
        assert_eq!(dec, e);
    }

    #[test]
    fn submit_encrypted_order_round_trips() {
        let s = SubmitEncryptedOrder {
            ciphertext: vec![0xAB; 64],
            commitment: [0u8; 32],
            threshold: 5,
            target_block: 1_000_000,
            reveal_deadline_ms: 5_000,
        };
        let j = serde_json::to_string(&s).unwrap();
        let dec: SubmitEncryptedOrder = serde_json::from_str(&j).unwrap();
        assert_eq!(s, dec);
    }

    #[test]
    fn encrypted_order_state_uses_snake_case() {
        let s = EncryptedOrderState {
            submitter: Address::ZERO,
            ciphertext: vec![],
            decryption_share_count: 0,
            threshold: 5,
            target_block: 1_000_000,
            status: "pending".into(),
        };
        let j = serde_json::to_value(&s).unwrap();
        for key in ["decryption_share_count", "target_block"] {
            assert!(j.get(key).is_some());
        }
        for key in ["decryptionShareCount", "targetBlock"] {
            assert!(j.get(key).is_none());
        }
    }
}
