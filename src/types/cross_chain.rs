//! Cross-chain — outbound bridge messages (PLAN.md §G / field 61).
//!
//! ADR-005 picked a hybrid bridge: USDC over Circle CCTP, other assets over a
//! third-party bridge (LayerZero / Across / Wormhole — pending S10 eval). The
//! MTF L1 surfaces a uniform `cross_chain_send` action to the user; the
//! bridge integration layer dispatches to the right provider per asset.

use serde::{Deserialize, Serialize};

use crate::wallet::Address;

/// Action — send a cross-chain message / value transfer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CrossChainSend {
    /// Sender on MTF.
    pub sender: Address,
    /// Destination chain id (EVM chain id; CCTP-domain id for USDC routes).
    pub dst_chain: u32,
    /// Destination address on the target chain (20-byte EVM).
    pub dst_address: Address,
    /// Asset symbol (e.g. `"USDC"`, `"ETH"`). Length ≤ 12 bytes per protocol limits.
    pub asset: String,
    /// Amount in base units of the asset (e.g. USDC = 6 decimals; ETH = 18).
    pub amount: u128,
    /// Anti-replay nonce — must be strictly monotonic per sender.
    pub nonce: u64,
}

/// Snapshot of an outbound cross-chain message (returned by `info: cross_chain_msg`).
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
    fn cross_chain_send_round_trips() {
        let s = CrossChainSend {
            sender: Address::ZERO,
            dst_chain: 8453, // Base
            dst_address: Address::ZERO,
            asset: "USDC".into(),
            amount: 1_000_000, // 1 USDC at 6 decimals
            nonce: 1,
        };
        let j = serde_json::to_string(&s).unwrap();
        let dec: CrossChainSend = serde_json::from_str(&j).unwrap();
        assert_eq!(s, dec);
    }

    #[test]
    fn cross_chain_send_uses_snake_case() {
        let s = CrossChainSend {
            sender: Address::ZERO,
            dst_chain: 1,
            dst_address: Address::ZERO,
            asset: "ETH".into(),
            amount: 1_000_000_000_000_000_000,
            nonce: 0,
        };
        let j = serde_json::to_value(&s).unwrap();
        for key in ["dst_chain", "dst_address"] {
            assert!(j.get(key).is_some());
        }
        for key in ["dstChain", "dstAddress"] {
            assert!(j.get(key).is_none());
        }
    }
}
