//! MetaBridge withdrawal — debit cross-collateral and queue an outbound release.
//!
//! Sender-authorized: the signer is the account whose cross-collateral is
//! debited. The withdrawal queues an outbound message for validator co-signing,
//! which releases funds on the destination chain.

use serde::{Deserialize, Serialize};

/// Destination chain for a MetaBridge withdrawal. Serializes in PascalCase to
/// match the node's chain enum (`"Base"` / `"Arbitrum"`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BridgeChain {
    /// Base.
    Base,
    /// Arbitrum.
    Arbitrum,
}

/// Action — withdraw cross-collateral to a destination chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct BridgeWithdraw {
    /// Destination chain.
    pub chain: BridgeChain,
    /// MetaFlux asset id (currently only `0` = USDC cross-collateral).
    pub asset: u32,
    /// Amount in base units.
    pub amount: u64,
    /// Destination address as `0x`-hex: a 20-byte EVM address.
    pub dst_addr: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mb_chain_serializes_pascal_case() {
        assert_eq!(
            serde_json::to_string(&BridgeChain::Base).unwrap(),
            "\"Base\""
        );
        assert_eq!(
            serde_json::to_string(&BridgeChain::Arbitrum).unwrap(),
            "\"Arbitrum\""
        );
    }

    #[test]
    fn mb_withdraw_round_trips() {
        let a = BridgeWithdraw {
            chain: BridgeChain::Base,
            asset: 0,
            amount: 1_000_000,
            dst_addr: "0xabababababababababababababababababababab".into(),
        };
        let j = serde_json::to_value(&a).unwrap();
        assert!(j["amount"].is_number(), "amount is a plain integer");
        assert_eq!(j["chain"], serde_json::json!("Base"));
        let dec: BridgeWithdraw = serde_json::from_value(j).unwrap();
        assert_eq!(a, dec);
    }
}
