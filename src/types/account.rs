//! Account, margin, and agent settings actions.
//!
//! Most are **sender-authorized**: the recovered signer is the account whose
//! state mutates, and the wire carries no `owner`. The three margin actions are
//! the exception. [`UpdateLeverage`], [`UpdateIsolatedMargin`] and
//! [`TopUpIsolatedOnlyMargin`] each accept an agent-resolved `owner` on the
//! wire, which this SDK does not build yet. That `owner` routes admission only;
//! the EIP-712 digest stays owner-less for all three. Decimal magnitudes
//! (`delta` / `amount` / `value`) ride the wire as JSON **strings** to preserve
//! fractional precision; ids, leverage, and bps are plain integers.

use serde::{Deserialize, Serialize};

use crate::types::MarketId;
use crate::wallet::Address;

/// Action — set the per-asset leverage (and optionally flip to isolated mode).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct UpdateLeverage {
    /// Target asset / market id.
    pub asset: MarketId,
    /// New leverage multiplier (e.g. `10`).
    pub leverage: u32,
    /// `true` also switches the asset to isolated margin.
    pub is_isolated: bool,
}

/// Action — add or remove isolated margin on an open position.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct UpdateIsolatedMargin {
    /// Target asset / market id.
    pub asset: MarketId,
    /// Signed margin delta as a decimal string (`+` adds, `-` withdraws).
    pub delta: String,
}

/// Action — top up the margin of a strict-isolated-only position.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TopUpIsolatedOnlyMargin {
    /// Target asset / market id.
    pub asset: MarketId,
    /// Amount to add, as a positive decimal string.
    pub amount: String,
}

/// Action — enroll into or out of portfolio margin.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct UserPortfolioMargin {
    /// `true` = enroll, `false` = unenroll.
    pub enroll: bool,
}

/// Action — set the account display name (handle).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SetDisplayName {
    /// Human-readable handle (e.g. `alice.mtf`).
    pub display_name: String,
}

/// Action — set the account referrer (one-time, immutable once set).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SetReferrer {
    /// Referrer address.
    pub referrer: Address,
}

/// Action — approve an agent wallet to sign on behalf of this account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ApproveAgent {
    /// Agent address being approved.
    pub agent: Address,
    /// Optional human-readable agent label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Optional expiry (unix ms). `None` never expires.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<u64>,
}

/// Action — approve a builder to charge a fee up to `max_bps` on this account's
/// orders. `max_bps = 0` revokes the approval.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ApproveBuilderFee {
    /// Builder address being approved.
    pub builder: Address,
    /// Maximum approved fee in basis points (the node caps the effective fee).
    pub max_bps: u16,
}

/// Action — convert the account to an M-of-N multisig.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ConvertToMultiSigUser {
    /// Authorized signer addresses.
    pub signers: Vec<Address>,
    /// Signature threshold (`M` of `signers.len()`).
    pub threshold: u32,
}

/// Action — set a self-scoped abstraction config value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct UserSetAbstraction {
    /// Sub-type tag (`0..=255`); interpretation is config-defined.
    pub kind: u8,
    /// Setting value as a decimal string.
    pub value: String,
}

/// Action — an approved agent sets an abstraction config value for `user`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AgentSetAbstraction {
    /// The account whose config the agent is updating. The node verifies the
    /// signer is an approved agent of this address.
    pub user: Address,
    /// Sub-type tag (`0..=255`).
    pub kind: u8,
    /// Setting value as a decimal string.
    pub value: String,
}

/// Action — pay a priority fee (bps) for block-front placement on an asset.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PriorityBid {
    /// Asset this bid is bound to.
    pub asset: MarketId,
    /// Bid in basis points.
    pub bid_bps: u16,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_leverage_serializes_snake_case_integers() {
        let a = UpdateLeverage {
            asset: MarketId(2),
            leverage: 10,
            is_isolated: true,
        };
        let j = serde_json::to_value(a).unwrap();
        assert_eq!(j["asset"], serde_json::json!(2));
        assert_eq!(j["leverage"], serde_json::json!(10));
        assert_eq!(j["is_isolated"], serde_json::json!(true));
        assert!(j.get("isIsolated").is_none(), "no camelCase leak");
    }

    #[test]
    fn isolated_margin_delta_rides_as_string() {
        let a = UpdateIsolatedMargin {
            asset: MarketId(1),
            delta: "-12.5".into(),
        };
        let j = serde_json::to_value(&a).unwrap();
        assert!(
            j["delta"].is_string(),
            "signed decimal must be a JSON string"
        );
        assert_eq!(j["delta"], serde_json::json!("-12.5"));
    }

    #[test]
    fn approve_agent_omits_optional_fields() {
        let a = ApproveAgent {
            agent: Address::ZERO,
            name: None,
            expires_at_ms: None,
        };
        let j = serde_json::to_value(&a).unwrap();
        assert!(j.get("name").is_none());
        assert!(j.get("expires_at_ms").is_none());
        let dec: ApproveAgent = serde_json::from_value(j).unwrap();
        assert_eq!(a, dec);
    }

    #[test]
    fn user_portfolio_margin_round_trips() {
        let a = UserPortfolioMargin { enroll: true };
        let j = serde_json::to_string(&a).unwrap();
        assert_eq!(serde_json::from_str::<UserPortfolioMargin>(&j).unwrap(), a);
    }
}
