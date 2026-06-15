//! Sub-account actions — create a sub-account and move collateral between a
//! parent account and its sub-accounts.
//!
//! All sender-authorized (the recovered signer is the parent account). Decimal
//! magnitudes ride the wire as decimal **strings**; ids are plain integers.

use serde::{Deserialize, Serialize};

use crate::types::MarketId;

/// Action — create a sub-account under the signing (parent) account.
///
/// `explicit_index` is optional: when `None` the node assigns the next free
/// index, and the wire omits the field entirely. `shared_stp_group` opts the
/// sub-account into the parent's self-trade-prevention group.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CreateSubAccount {
    /// Human-readable sub-account name.
    pub name: String,
    /// Optional explicit sub-account index. `None` lets the node assign one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explicit_index: Option<u32>,
    /// Share the parent's STP group.
    pub shared_stp_group: bool,
}

/// Action — move quote collateral between the parent and a sub-account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SubAccountTransfer {
    /// Sub-account index (relative to the parent).
    pub sub_index: u32,
    /// Direction (`true` = parent → sub, `false` = sub → parent).
    pub deposit: bool,
    /// Amount as a decimal string.
    pub amount: String,
}

/// Action — move a spot token between the parent and a sub-account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SubAccountSpotTransfer {
    /// Sub-account index (relative to the parent).
    pub sub_index: u32,
    /// Spot token (asset) id.
    pub token: MarketId,
    /// Direction (`true` = parent → sub, `false` = sub → parent).
    pub deposit: bool,
    /// Amount as a decimal string.
    pub amount: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_sub_account_omits_absent_index() {
        let a = CreateSubAccount {
            name: "bot".into(),
            explicit_index: None,
            shared_stp_group: false,
        };
        let j = serde_json::to_value(&a).unwrap();
        assert!(j.get("explicit_index").is_none(), "absent index omitted");
        assert_eq!(j["name"], serde_json::json!("bot"));
        let dec: CreateSubAccount = serde_json::from_value(j).unwrap();
        assert_eq!(a, dec);
    }

    #[test]
    fn create_sub_account_keeps_present_index() {
        let a = CreateSubAccount {
            name: "bot".into(),
            explicit_index: Some(5),
            shared_stp_group: true,
        };
        let j = serde_json::to_value(&a).unwrap();
        assert_eq!(j["explicit_index"], serde_json::json!(5));
    }

    #[test]
    fn sub_account_transfer_amount_rides_as_string() {
        let a = SubAccountTransfer {
            sub_index: 0,
            deposit: true,
            amount: "100.5".into(),
        };
        let j = serde_json::to_value(&a).unwrap();
        assert!(j["amount"].is_string());
        assert_eq!(j["amount"], serde_json::json!("100.5"));
    }

    #[test]
    fn sub_account_spot_transfer_token_is_plain_integer() {
        let a = SubAccountSpotTransfer {
            sub_index: 2,
            token: MarketId(7),
            deposit: false,
            amount: "42.0".into(),
        };
        let j = serde_json::to_value(&a).unwrap();
        assert_eq!(j["token"], serde_json::json!(7));
        assert_eq!(j["amount"], serde_json::json!("42.0"));
    }
}
