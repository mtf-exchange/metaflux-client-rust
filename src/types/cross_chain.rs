//! Cross-chain — outbound bridge message read types.
//!
//! Withdrawals to other chains queue an outbound message (see the `bridge_withdraw`
//! action in [`crate::types::meta_bridge`]); this module models the message
//! snapshot read back over `/info`.

use serde::{Deserialize, Serialize};

use crate::wallet::Address;

/// Snapshot of an outbound cross-chain message (returned over `/info`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CrossChainMsg {
    /// Destination chain id.
    pub dst_chain: u32,
    /// Opaque bridge payload — interpretation depends on the bridge provider.
    pub payload: Vec<u8>,
    /// Anti-replay nonce.
    pub nonce: u64,
    /// Sender on MTF.
    pub sender: Address,
    /// Submission timestamp (unix ms).
    pub ts_ms: u64,
    /// Lifecycle: `pending` / `submitted` / `confirmed` / `failed`.
    pub status: String,
}

/// Action — `cross_chain_send`: initiate a chain-agnostic cross-chain transfer
/// (queued to the bridge outbox).
///
/// Mirrors the node's `evm_integration` `CrossChainSendParams`. The action
/// envelope wraps this under the key **`msg`**.
///
/// **Traps:** the action field is `dst_chain_id` (the read-only
/// [`CrossChainMsg`] snapshot uses a different `dst_chain`); and under the
/// node's plain `#[derive(Serialize)]`, `recipient: [u8; 32]` is a JSON **array
/// of 32 byte-numbers** and `amount: u128` is a JSON **number** — not 0x-hex
/// strings.
///
/// Forward-compat: the node currently answers this tag with `UnsupportedAction`
/// on the public `/exchange` path; the SDK emits the byte-correct shape the
/// core handler will accept once the bridge lands.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CrossChainSend {
    /// Destination chain id.
    pub dst_chain_id: u32,
    /// Chain-agnostic 32-byte recipient (EVM = left-padded 20-byte address).
    /// Serializes as a JSON array of 32 byte-numbers.
    pub recipient: [u8; 32],
    /// MTF asset id (not a destination-chain token address).
    pub token: u32,
    /// Amount in the MTF asset's native fixed-point (JSON number).
    pub amount: u128,
    /// Application-supplied idempotency nonce; `(sender, nonce)` is the key.
    pub nonce: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cross_chain_send_recipient_is_array_amount_is_number() {
        let m = CrossChainSend {
            dst_chain_id: 8453,
            recipient: [7u8; 32],
            token: 1,
            amount: 1_000_000,
            nonce: 7,
        };
        let j = serde_json::to_value(&m).unwrap();
        assert_eq!(j["dst_chain_id"], 8453);
        // recipient => 32-element JSON array; amount => bare number.
        assert!(j["recipient"].is_array());
        assert_eq!(j["recipient"].as_array().unwrap().len(), 32);
        assert!(j["amount"].is_number());
        let dec: CrossChainSend = serde_json::from_value(j).unwrap();
        assert_eq!(dec, m);
    }

    #[test]
    fn cross_chain_msg_round_trips() {
        let m = CrossChainMsg {
            dst_chain: 8453,
            payload: vec![1, 2, 3],
            nonce: 1,
            sender: Address::ZERO,
            ts_ms: 1_700_000_000_000,
            status: "pending".into(),
        };
        let j = serde_json::to_value(&m).unwrap();
        for key in ["dst_chain", "ts_ms"] {
            assert!(j.get(key).is_some());
        }
        for key in ["dstChain", "tsMs"] {
            assert!(j.get(key).is_none());
        }
        let dec: CrossChainMsg = serde_json::from_value(j).unwrap();
        assert_eq!(m, dec);
    }
}
