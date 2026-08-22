//! MIP-3 perp deployer types — the nine `perp_*` deploy actions and the
//! deployer-oracle push (`/exchange`).
//!
//! Nine sender-authorized actions build a perp market. The signer IS the
//! deployer, so no action carries an `owner`. `perp_deploy` is a node-internal
//! handler name that no caller sends: each sub-action posts its OWN tag and
//! signs its OWN frozen EIP-712 string.
//!
//! The usual order is: register the asset, bind its oracle sources, set
//! leverage, fees, the maker rebate and the min size, then activate the market.
//! [`PerpSetSubDeployers`] delegates the lane to another address, and
//! [`PerpDeactivateMarket`] closes the market to new orders.
//!
//! [`Mip3SetOraclePx`] is the tenth action and the only repeating one. A market
//! may run its OWN index feed instead of the venue-weighted median; the
//! deployer then pushes every price. It rides a SEPARATE fork feature from the
//! nine, so read its doc before you build against it.
//!
//! Wire shape (MTF-native, snake_case):
//!
//! ```json
//! { "type": "perp_set_leverage", "params": { "asset": 1001, "max_leverage": 20 } }
//! ```
//!
//! ## Availability
//!
//! Availability is PER NETWORK. Do not assume it — probe one call against your
//! target network and read the error.
//!
//! On the primary networks the node knows all ten tags: an unknown action gets
//! `unknown variant`, and these do not. A malformed one gets a field or
//! signature error instead, which means the tag resolved.
//!
//! [`Mip3SetOraclePx`] additionally sits behind the `mip3_deployer_oracle` fork
//! feature. That feature is ACTIVE FROM GENESIS on a fresh chain; only a legacy
//! or unknown network keeps it dormant until a two-thirds stake vote arms it,
//! and there the node answers `mip3_deployer_oracle feature not active`.
//!
//! ## No `bid` field
//!
//! The legacy gas-auction outbid lane is dead. The node rejects a non-zero bid,
//! and no digest here carries one.
//!
//! ## Unit traps
//!
//! - [`PerpRegisterAsset::decimals`] of `0` is not "zero decimals". The node
//!   reads it as its default of 8.
//! - In [`PerpSetFeeTier`], the taker and maker legs are DECI-bps (tenths of a
//!   basis point) and the deployer leg is WHOLE bps. Mixing the two planes
//!   misprices the market by 10x.
//! - [`PerpSetMakerRebate::rebate_bps`] is whole bps, not deci-bps.
//!
//! These types carry no client-side bounds check. The node is the authority and
//! rejects an out-of-range value; the doc comments name each bound so a caller
//! can refuse earlier.

use serde::{Deserialize, Serialize};

use crate::wallet::Address;

/// Allocate a fresh perp market (step 1 of the deployer sequence).
///
/// The node assigns the asset id. Read it back from `/info` before sending any
/// of the eight actions below — every one of them targets an id, not a symbol.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PerpRegisterAsset {
    /// Market symbol, e.g. `"WIF"`.
    pub symbol: String,
    /// Token decimals. `0` selects the node default of 8; the node rejects a
    /// value above 18.
    pub decimals: u8,
}

/// Bind the enabled oracle-source subset for a market.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PerpSetOracle {
    /// Target market asset id.
    pub asset: u32,
    /// Bitmask of enabled oracle sources. The node bounds it to the ten defined
    /// sources.
    pub oracle_source_mask: u16,
}

/// Set a market's max leverage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PerpSetLeverage {
    /// Target market asset id.
    pub asset: u32,
    /// Max leverage. The node bounds it to 1..=50.
    pub max_leverage: u8,
}

/// Set the three fee legs in one intent.
///
/// **Unit trap:** `taker_fee_dbps` and `maker_fee_dbps` are DECI-bps;
/// `deployer_fee_bps` is WHOLE bps. The node rejects any leg at 1000 or above,
/// because it packs the three into one encoded value and a leg at 1000 would
/// carry into its neighbour.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PerpSetFeeTier {
    /// Target market asset id.
    pub asset: u32,
    /// Taker fee in deci-bps (`< 1000`).
    pub taker_fee_dbps: u32,
    /// Maker fee in deci-bps (`< 1000`).
    pub maker_fee_dbps: u32,
    /// Deployer cut in whole bps (`< 1000`).
    pub deployer_fee_bps: u32,
}

/// Set a market's maker rebate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PerpSetMakerRebate {
    /// Target market asset id.
    pub asset: u32,
    /// Rebate in WHOLE bps. The node bounds it to 0..=2.
    pub rebate_bps: u16,
}

/// Set a market's minimum order size.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PerpSetMinSize {
    /// Target market asset id.
    pub asset: u32,
    /// Min order size in the market's size plane.
    pub min_order_size: u64,
}

/// Open a market to trading.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PerpActivateMarket {
    /// Target market asset id.
    pub asset: u32,
}

/// Close a market to new orders.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PerpDeactivateMarket {
    /// Target market asset id.
    pub asset: u32,
}

/// Add or remove one delegated deployer on a market.
///
/// Both `sub_deployer` and `add` ride INSIDE the signed digest, so a relay can
/// neither re-target the delegate nor flip a removal into a grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PerpSetSubDeployers {
    /// Target market asset id.
    pub asset: u32,
    /// The delegate address.
    pub sub_deployer: Address,
    /// `true` adds the delegate, `false` removes it.
    pub add: bool,
}

/// Push the market's index px (`mip3_set_oracle_px`, the deployer oracle).
///
/// The action sits behind the `mip3_deployer_oracle` fork feature, which is
/// ACTIVE FROM GENESIS on a fresh chain. A legacy or unknown network keeps it
/// dormant and answers `mip3_deployer_oracle feature not active` until a
/// two-thirds stake vote arms it. Probe your target network; do not assume.
///
/// Only the market's deployer or a registered sub-deployer may sign one. No
/// relay and no system sender can inject one.
///
/// The feed is load-bearing, not advisory. Where the feature is active:
///
/// - The FIRST push force-migrates every existing cross leg on the market to
///   strict-isolated margin, and every later leg opens strict-isolated.
/// - A feed that goes stale flips the market reduce-only: opens are refused and
///   closes always pass. Push faster than the staleness window.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Mip3SetOraclePx {
    /// Target market asset id.
    pub asset: u32,
    /// The pushed index px, as a WHOLE-USDC decimal string — never the 1e8
    /// book plane.
    ///
    /// The node hashes this string VERBATIM, so the signature covers the
    /// SPELLING and not the value: `"1250.5"` and `"1250.50"` are one price and
    /// two digests. Build the string once, then sign and send the same bytes.
    pub px: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn perp_deploy_params_serialize_snake_case() {
        let r = PerpRegisterAsset {
            symbol: "WIF".into(),
            decimals: 8,
        };
        let jr = serde_json::to_value(&r).unwrap();
        assert_eq!(jr, serde_json::json!({ "symbol": "WIF", "decimals": 8 }));
        assert_eq!(r, serde_json::from_value(jr).unwrap());

        let o = PerpSetOracle {
            asset: 1001,
            oracle_source_mask: 0x03ff,
        };
        let jo = serde_json::to_value(o).unwrap();
        assert_eq!(jo["oracle_source_mask"], serde_json::json!(1023));
        assert!(jo.get("oracleSourceMask").is_none(), "no camelCase leak");
        assert_eq!(o, serde_json::from_value(jo).unwrap());

        let m = PerpSetMinSize {
            asset: 1001,
            min_order_size: 1000,
        };
        let jm = serde_json::to_value(m).unwrap();
        assert_eq!(jm["min_order_size"], serde_json::json!(1000));
        assert_eq!(m, serde_json::from_value(jm).unwrap());
    }

    /// The two fee planes sit side by side in ONE struct, so pin that they stay
    /// separate keys. A collapsed pair would misprice the market by 10x.
    #[test]
    fn fee_tier_keeps_the_three_legs_apart() {
        let f = PerpSetFeeTier {
            asset: 1001,
            taker_fee_dbps: 45,
            maker_fee_dbps: 12,
            deployer_fee_bps: 6,
        };
        let j = serde_json::to_value(f).unwrap();
        assert_eq!(j["taker_fee_dbps"], serde_json::json!(45));
        assert_eq!(j["maker_fee_dbps"], serde_json::json!(12));
        assert_eq!(j["deployer_fee_bps"], serde_json::json!(6));
        assert_eq!(f, serde_json::from_value(j).unwrap());
    }

    #[test]
    fn sub_deployer_rides_as_a_hex_string() {
        let s = PerpSetSubDeployers {
            asset: 1001,
            sub_deployer: Address::from_bytes([0xaa; 20]),
            add: true,
        };
        let j = serde_json::to_value(s).unwrap();
        assert_eq!(
            j["sub_deployer"],
            serde_json::json!("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
        assert_eq!(j["add"], serde_json::json!(true));
        assert_eq!(s, serde_json::from_value(j).unwrap());
    }

    /// The px must reach the wire as the SAME string the wallet signed. A
    /// number here would respell the value and unsign the push.
    #[test]
    fn oracle_px_rides_as_a_verbatim_string() {
        let p = Mip3SetOraclePx {
            asset: 42,
            px: "1250.500001".into(),
        };
        let j = serde_json::to_value(&p).unwrap();
        assert_eq!(j["px"], serde_json::json!("1250.500001"));
        assert!(j["px"].is_string(), "px must not degrade to a number");
        assert_eq!(p, serde_json::from_value(j).unwrap());

        let trailing = Mip3SetOraclePx {
            asset: 42,
            px: "1250.5000010".into(),
        };
        assert_ne!(p, trailing, "spelling is part of the payload");
    }
}
