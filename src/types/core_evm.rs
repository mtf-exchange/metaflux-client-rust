//! Core ↔ MetaFluxEVM transfers.
//!
//! Two actions move value one way, Core → MetaFluxEVM: [`CoreEvmTransfer`] and
//! [`SendToEvmWithData`]. Both are sender-authorized — the recovered signer is
//! the Core-side account, and the recipient field names the MetaFluxEVM-side
//! account. `amount` rides the wire as a decimal **string** (whole-token plane)
//! to preserve precision.
//!
//! # The Core to EVM fee
//!
//! Both actions can charge a fee, and neither is the cheaper lane. The fee is a
//! quantity of MTF. It is a SECOND debit, on top of the amount, and it is
//! unrelated to the asset you move: a transfer of BTC debits BTC for the amount
//! and MTF for the fee.
//!
//! The chain chooses the currency, never the caller, and it never splits the fee:
//!
//! 1. **Spot MTF**, when the balance covers the fee. A transfer OF MTF needs
//!    `amount + fee`, because both debits hit one balance.
//! 2. **USDC at the MTF reference price**, when spot MTF is short. It comes out of
//!    withdrawable collateral, so collateral that backs a position cannot pay it.
//! 3. **Neither covers the fee** — the whole transfer is refused:
//!    `insufficient MTF or USDC for the core->evm fee`.
//!
//! **A transfer can fail for a reason that has nothing to do with the asset you
//! move, or your balance of it.** MTF is priced from its own book. When no usable
//! price exists, the chain refuses the transfer instead of quoting a guess:
//! `MTF price unavailable; the core->evm fee cannot be quoted in USDC`. The fee
//! must also quote to a positive USDC amount. Only a sender that is short of MTF
//! meets either answer, because a fee that spot MTF covers reads no price.
//!
//! A refused transfer pays nothing: the chain charges the fee only after it
//! accepts the amount. The proceeds are validator revenue.
//!
//! ## The fee is zero today
//!
//! The amount is **zero**, so no fee is charged and none of the refusals above can
//! happen. Validator governance sets the amount, and no endpoint serves the
//! current value, so a caller can neither read it nor predict a change. Hold a
//! small spot MTF balance to stay payable, and handle the two refusals above.

use serde::{Deserialize, Serialize};

use crate::wallet::Address;

/// Action — transfer USDC between Core and MetaFluxEVM.
///
/// A Core → MetaFluxEVM move can charge a fee in MTF, with a USDC fallback, on
/// top of `amount`. The fee is **zero today**, and the chain refuses the transfer
/// rather than guess when the MTF reference price is unusable — see
/// [the fee rules](self#the-core-to-evm-fee).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CoreEvmTransfer {
    /// Amount as a decimal string (whole-USDC plane).
    pub amount: String,
    /// Direction: `true` = Core → MetaFluxEVM, `false` = MetaFluxEVM → Core.
    ///
    /// `false` is refused on this endpoint. The return leg must originate as a
    /// MetaFluxEVM transaction, not as a signed action.
    pub to_evm: bool,
    /// MetaFluxEVM-side recipient address, and the target of `data`.
    ///
    /// The zero address is refused, because the credit is a mint and nobody could
    /// spend it.
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

/// Action — move a spot token to MetaFluxEVM and run a payload against the
/// recipient.
///
/// The chain debits the sender's spot balance of `token`, credits
/// `destination_recipient` on MetaFluxEVM, and runs `data` against that address.
/// Wire tag: `send_to_evm_with_data`.
///
/// **Every field is required on the wire.** The chain reads all eight keys; an
/// omitted key fails the whole action.
///
/// **A field the chain cannot honour is REFUSED, never ignored.** `source_dex`,
/// `to_perp` and a remote `destination_chain_id` were all signed and then
/// dropped in silence by an older node — a caller who named a remote chain got a
/// LOCAL delivery and no warning. Each one is now a rejection. Read the rule on
/// the field.
///
/// The transfer queue is bounded. A full queue rejects the action until it
/// drains, so treat that answer as "retry", not "invalid".
///
/// This action can charge a fee in MTF, with a USDC fallback, on top of `amount`.
/// It is the SAME fee [`CoreEvmTransfer`] charges, so neither action is the cheaper
/// lane. The fee is **zero today**, and the chain refuses the transfer rather than
/// guess when the MTF reference price is unusable — see
/// [the fee rules](self#the-core-to-evm-fee).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SendToEvmWithData {
    /// Spot token id to move.
    ///
    /// The token needs an EVM contract link, or the chain rejects the action.
    /// The native gas token is the one exception — it funds gas and always has a
    /// credit path.
    pub token: u32,
    /// Amount as a canonical decimal string (whole-token plane). Sign and send
    /// the identical text.
    ///
    /// The chain truncates the amount to one EVM quantum — first to 8 decimal
    /// places, then to the token's EVM decimals — and debits exactly what it
    /// credits. An amount under one quantum credits nothing, so the chain
    /// rejects it rather than take a debit for a zero credit.
    pub amount: String,
    /// Source book. `0` is the only accepted value: this action debits the spot
    /// ledger and no other ledger.
    ///
    /// **This is the row an older caller hits.** A payload built for the earlier
    /// node carries `1`, which was ignored. It is now rejected. Send `0`.
    pub source_dex: u32,
    /// MetaFluxEVM-side recipient, and the target of `data`.
    ///
    /// **The zero address is refused**, as it is on [`CoreEvmTransfer`]. The credit
    /// is a mint to the named address and no owner check follows it, so a zero
    /// recipient would burn the debit with nobody able to spend the credit.
    pub destination_recipient: Address,
    /// Credit a perp account. `false` is the only accepted value: the
    /// MetaFluxEVM side has no perp account, so the credit is always an EVM
    /// balance. `true` was ignored before; it is now rejected.
    pub to_perp: bool,
    /// Delivery chain. `0`, or the local EVM chain id. Any other value is
    /// rejected, because delivery to a remote chain is not built.
    ///
    /// Send `0` — it means "the local chain" and needs no lookup. A remote id
    /// used to be signed and then delivered locally in silence.
    pub destination_chain_id: u32,
    /// EVM payload run against `destination_recipient` AFTER the credit lands.
    /// An empty payload is valid.
    ///
    /// 4096 bytes at most; a longer payload is rejected.
    ///
    /// A reverting payload NEVER unwinds the credit: Core is debited, the EVM is
    /// credited, and the call is additional. Read its receipt.
    pub data: Vec<u8>,
    /// Per-transfer nonce, carried into the queued transfer.
    ///
    /// This is NOT the action envelope nonce. The envelope nonce orders the
    /// account's actions; this one labels the transfer, and it signs as
    /// `transferNonce`. The two may differ.
    pub nonce: u64,
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
            ..base
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

    /// The chain reads all eight keys of `send_to_evm_with_data`, so none may be
    /// skipped — an omitted key fails the action. The payload rides as a byte
    /// array and `amount` as a string.
    #[test]
    fn send_to_evm_with_data_carries_every_key() {
        let a = SendToEvmWithData {
            token: 7,
            amount: "12.5".into(),
            source_dex: 0,
            destination_recipient: Address::from_bytes([0xE7; 20]),
            to_perp: false,
            destination_chain_id: 0,
            data: Vec::new(),
            nonce: 5,
        };
        let j = serde_json::to_value(&a).unwrap();
        for k in [
            "token",
            "amount",
            "source_dex",
            "destination_recipient",
            "to_perp",
            "destination_chain_id",
            "data",
            "nonce",
        ] {
            assert!(j.get(k).is_some(), "{k} must ride the wire");
        }
        assert_eq!(j["amount"], serde_json::json!("12.5"));
        assert_eq!(j["data"], serde_json::json!([]));
        assert!(j.get("sourceDex").is_none(), "no camelCase leak");
        let dec: SendToEvmWithData = serde_json::from_value(j).unwrap();
        assert_eq!(a, dec);
    }

    /// The chain resolves the Core → EVM fee, so it rides NO wire key on either
    /// action. A caller cannot set the fee, choose its currency, or read it back
    /// from the envelope it signed.
    #[test]
    fn neither_action_carries_a_fee_key() {
        let transfer = serde_json::to_value(CoreEvmTransfer {
            amount: "1".into(),
            to_evm: true,
            destination: Address::from_bytes([0xCE; 20]),
            asset: 0,
            data: None,
            destination_chain_id: None,
        })
        .unwrap();
        let with_data = serde_json::to_value(SendToEvmWithData {
            token: 7,
            amount: "1".into(),
            source_dex: 0,
            destination_recipient: Address::from_bytes([0xE7; 20]),
            to_perp: false,
            destination_chain_id: 0,
            data: Vec::new(),
            nonce: 5,
        })
        .unwrap();
        for j in [transfer, with_data] {
            let keys: Vec<&String> = j.as_object().unwrap().keys().collect();
            assert!(
                keys.iter().all(|k| !k.contains("fee")),
                "the fee is not a caller field: {keys:?}"
            );
        }
    }
}
