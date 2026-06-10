//! Cross-chain — outbound bridge message read types.
//!
//! Withdrawals to other chains queue an outbound message (see the `mb_withdraw`
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

#[cfg(test)]
mod tests {
    use super::*;

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
