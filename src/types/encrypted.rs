//! Encrypted orders (action field 60) — threshold-encrypted
//! MEV-resistant order submissions.
//!
//! Flow:
//! 1. Trader encrypts an order against the validator-committee public key.
//! 2. Trader submits the ciphertext to `/exchange` with type `encrypted_order_submit`.
//! 3. Once the configured number of validators sign decryption shares
//!    (`threshold` per protocol), the ciphertext is decrypted and the
//!    revealed order is matched.

use serde::{Deserialize, Serialize};

use crate::wallet::Address;

/// Action — submit a threshold-encrypted order ciphertext.
///
/// The decryption shares accumulate over subsequent blocks until the
/// threshold is met; the order is then revealed and matched.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct EncryptedOrderSubmit {
    /// Submitter on MTF (used for slot accounting; not necessarily the trader).
    pub submitter: Address,
    /// Ciphertext bytes (committee-encrypted).
    pub ciphertext: Vec<u8>,
    /// Threshold of decryption shares required (e.g. 2/3 of `n` validators).
    pub threshold: u8,
    /// Earliest block at which the ciphertext can be revealed.
    pub target_block: u64,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_order_submit_round_trips() {
        let s = EncryptedOrderSubmit {
            submitter: Address::ZERO,
            ciphertext: vec![0xAB; 64],
            threshold: 5,
            target_block: 1_000_000,
        };
        let j = serde_json::to_string(&s).unwrap();
        let dec: EncryptedOrderSubmit = serde_json::from_str(&j).unwrap();
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
