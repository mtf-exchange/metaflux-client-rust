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
    /// MetaFluxEVM-side recipient address, and the target of `data`.
    pub destination: Address,
    /// MTF asset id to move. `0` (the default) is USDC cross-collateral; a
    /// non-zero asset moves that spot token instead.
    #[serde(default, skip_serializing_if = "crate::types::is_zero_u32")]
    pub asset: u32,
    /// Optional EVM calldata, run against `destination` AFTER the credit lands.
    ///
    /// A reverting payload NEVER unwinds the credit: Core was debited, the EVM
    /// was credited, and the call is additional. Read its receipt.
    ///
    /// **Presence selects the signing type.** See [`CoreEvmTransfer::is_v2`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Vec<u8>>,
    /// Optional delivery chain. `0` or the local EVM chain id only — any other
    /// value is rejected, because cross-chain delivery is not built. The field
    /// exists so the capability has a signed slot.
    ///
    /// **Presence selects the signing type.** See [`CoreEvmTransfer::is_v2`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_chain_id: Option<u32>,
}

impl CoreEvmTransfer {
    /// `true` when this transfer signs under `CoreEvmTransferV2`.
    ///
    /// The selector is PRESENCE, not emptiness: an empty `data` and a
    /// `destination_chain_id` of `0` both count as present. An envelope with
    /// NEITHER key signs under the original `CoreEvmTransfer` string, digesting
    /// byte-identically to one built before these fields existed.
    #[must_use]
    pub const fn is_v2(&self) -> bool {
        self.data.is_some() || self.destination_chain_id.is_some()
    }
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
            asset: 0,
            data: None,
            destination_chain_id: None,
        };
        let j = serde_json::to_value(&a).unwrap();
        assert!(j["amount"].is_string());
        assert_eq!(j["amount"], serde_json::json!("250.5"));
        assert_eq!(j["to_evm"], serde_json::json!(true));
        assert!(j.get("toEvm").is_none(), "no camelCase leak");
        let dec: CoreEvmTransfer = serde_json::from_value(j).unwrap();
        assert_eq!(a, dec);
    }

    /// PRESENCE selects the signing type, not emptiness. An EMPTY payload and a
    /// chain id of `0` are both present, so both choose V2 — a transfer signed
    /// under the wrong string is rejected on arrival.
    #[test]
    fn presence_not_emptiness_selects_the_v2_signing_type() {
        let base = CoreEvmTransfer {
            amount: "1".into(),
            to_evm: true,
            destination: Address::from_bytes([0xCE; 20]),
            asset: 0,
            data: None,
            destination_chain_id: None,
        };
        assert!(
            !base.is_v2(),
            "neither key present stays on the original type"
        );

        let empty_payload = CoreEvmTransfer {
            data: Some(Vec::new()),
            ..base.clone()
        };
        assert!(empty_payload.is_v2(), "an EMPTY payload is still present");

        let zero_chain = CoreEvmTransfer {
            destination_chain_id: Some(0),
            ..base.clone()
        };
        assert!(zero_chain.is_v2(), "a chain id of 0 is still present");
    }

    /// An envelope with neither key must serialize to exactly the pre-existing
    /// three-field object — no new keys — so an older reader is unaffected.
    #[test]
    fn a_plain_transfer_gains_no_wire_keys() {
        let a = CoreEvmTransfer {
            amount: "1".into(),
            to_evm: true,
            destination: Address::from_bytes([0xCE; 20]),
            asset: 0,
            data: None,
            destination_chain_id: None,
        };
        let j = serde_json::to_value(&a).unwrap();
        for k in ["asset", "data", "destination_chain_id"] {
            assert!(j.get(k).is_none(), "{k} must be omitted when defaulted");
        }
    }
}
