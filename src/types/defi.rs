//! BOLE pool types — `borrow_lend` (`/exchange`).
//!
//! The BOLE pool is the USD-class liquidity pool the liquidation engine draws
//! on. One action moves value in four directions, selected by
//! [`BorrowLendKind`]. It is sender-authorized: the recovered signer is the
//! actor, so there is no `owner` field.
//!
//! ## Two spellings of one direction
//!
//! The POST carries `kind` as its PascalCase NAME (`"UnLend"`, capital `L`);
//! the EIP-712 digest signs the same direction as a `uint8` (`0`..=`3`). Both
//! come from this one enum through
//! [`Exchange::borrow_lend`](crate::rest::exchange::Exchange::borrow_lend), so
//! they cannot drift.
//!
//! Wire shape (MTF-native, snake_case):
//!
//! ```json
//! { "kind": "Lend", "amount": "1000" }
//! ```
//!
//! `amount` rides the wire as a decimal **string** and is hashed verbatim, so
//! `"1000"` and `"1000.00"` are different signatures.

use serde::{Deserialize, Serialize};

/// Direction of a [`BorrowLend`] flow.
///
/// The wire name is PascalCase and the signed `uint8` is the declaration order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum BorrowLendKind {
    /// Add liquidity to the pool (`0`).
    Lend,
    /// Withdraw lent liquidity (`1`).
    UnLend,
    /// Draw on the pool's credit line (`2`).
    Borrow,
    /// Repay borrowed liquidity (`3`).
    Repay,
}

impl BorrowLendKind {
    /// The `uint8` this direction signs in the EIP-712 digest.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Lend => 0,
            Self::UnLend => 1,
            Self::Borrow => 2,
            Self::Repay => 3,
        }
    }

    /// The PascalCase name this direction carries in the POST `params.kind`.
    #[must_use]
    pub fn wire_name(self) -> &'static str {
        match self {
            Self::Lend => "Lend",
            Self::UnLend => "UnLend",
            Self::Borrow => "Borrow",
            Self::Repay => "Repay",
        }
    }
}

/// Lend, un-lend, borrow or repay against the BOLE pool.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct BorrowLend {
    /// Direction of the flow.
    pub kind: BorrowLendKind,
    /// Amount in USD-class whole units, as a decimal string (`> 0`).
    pub amount: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `UnLend` keeps its inner capital `L` on the wire. A snake_case or
    /// lowercase spelling is refused at the node's serde, and the action never
    /// reaches a handler.
    #[test]
    fn kind_wire_name_is_pascal_case() {
        let b = BorrowLend {
            kind: BorrowLendKind::UnLend,
            amount: "1000".into(),
        };
        let j = serde_json::to_value(&b).unwrap();
        assert_eq!(j["kind"], serde_json::json!("UnLend"));
        assert_eq!(j["amount"], serde_json::json!("1000"));
        assert!(j["amount"].is_string(), "amount is a decimal JSON string");
        assert_eq!(b, serde_json::from_value(j).unwrap());

        for k in [
            BorrowLendKind::Lend,
            BorrowLendKind::UnLend,
            BorrowLendKind::Borrow,
            BorrowLendKind::Repay,
        ] {
            assert_eq!(
                serde_json::to_value(k).unwrap(),
                serde_json::json!(k.wire_name())
            );
        }
    }

    /// The signed `uint8` is the declaration order. A drift here signs one
    /// direction and posts another, and the node rejects the signature.
    #[test]
    fn kind_signed_discriminant_is_declaration_order() {
        assert_eq!(BorrowLendKind::Lend.as_u8(), 0);
        assert_eq!(BorrowLendKind::UnLend.as_u8(), 1);
        assert_eq!(BorrowLendKind::Borrow.as_u8(), 2);
        assert_eq!(BorrowLendKind::Repay.as_u8(), 3);
    }
}
