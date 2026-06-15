//! Core ↔ MetaFluxEVM transfer.
//!
//! Moves USDC between the Core (clearinghouse) balance and the MetaFluxEVM
//! sidechain. Sender-authorized: the recovered signer is the Core-side account;
//! `destination` is the MetaFluxEVM-side recipient. `amount` rides the wire as a
//! decimal **string** (whole-USDC plane) to preserve precision.

use serde::{Deserialize, Serialize};

use crate::wallet::Address;

/// Action — transfer USDC between Core and MetaFluxEVM.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CoreEvmTransfer {
    /// Amount as a decimal string (whole-USDC plane).
    pub amount: String,
    /// Direction: `true` = Core → MetaFluxEVM, `false` = MetaFluxEVM → Core.
    pub to_evm: bool,
    /// MetaFluxEVM-side recipient address.
    pub destination: Address,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amount_rides_as_string_and_snake_case() {
        let a = CoreEvmTransfer {
            amount: "250.5".into(),
            to_evm: true,
            destination: Address::from_bytes([0xCE; 20]),
        };
        let j = serde_json::to_value(&a).unwrap();
        assert!(j["amount"].is_string());
        assert_eq!(j["amount"], serde_json::json!("250.5"));
        assert_eq!(j["to_evm"], serde_json::json!(true));
        assert!(j.get("toEvm").is_none(), "no camelCase leak");
        let dec: CoreEvmTransfer = serde_json::from_value(j).unwrap();
        assert_eq!(a, dec);
    }
}
