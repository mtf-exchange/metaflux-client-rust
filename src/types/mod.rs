//! Domain types shared by all transports.
//!
//! Types use `#[serde(rename_all = "snake_case")]` to match the wire
//! convention. Sizes / prices / ids are plain-integer fields on fixed-point
//! planes; fractional magnitudes (margin deltas, stake, vault amounts) ride the
//! wire as decimal **strings** to preserve precision.
//!
//! ## ID newtypes
//!
//! Three identifier newtypes are re-exported from this module:
//!
//! - [`OrderId`] — server-assigned order identifier (`u64`).
//! - [`MarketId`] — internal market id (`u32`), sequentially allocated.
//! - [`VaultId`] — vault id (`u64`), assigned at vault creation.

use serde::{Deserialize, Serialize};

pub mod account;
pub mod core_evm;
pub mod cross_chain;
pub mod encrypted;
pub mod fba;
pub mod meta_bridge;
pub mod order;
pub mod pm;
pub mod position;
pub mod rfq;
pub mod spot;
pub mod staking;
pub mod sub_account;
pub mod twap;
pub mod vault;

// ---- ID newtypes ----

/// Server-assigned order identifier.
///
/// `0` means "not yet assigned" — the server fills this on accept. The wire
/// shape is a plain JSON integer.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct OrderId(pub u64);

/// Market identifier.
///
/// Sequentially allocated; permissionless perp deploys receive fresh ids.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct MarketId(pub u32);

/// User-vault identifier.
///
/// Assigned by the node at vault creation.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct VaultId(pub u64);

/// Client-supplied order identifier (16 bytes / 128 bits) for idempotency.
///
/// MTF-native uses `cloid` as a 32-char hex `0x...` string on the wire so it
/// survives JS-safe-integer limits. We expose it as a `[u8; 16]` newtype
/// internally and serialize as hex.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Cloid(pub [u8; 16]);

impl Serialize for Cloid {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("0x{}", hex::encode(self.0)))
    }
}

impl<'de> Deserialize<'de> for Cloid {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s: String = String::deserialize(d)?;
        let stripped = s.strip_prefix("0x").unwrap_or(&s);
        if stripped.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "cloid hex must be 32 chars, got {}",
                stripped.len()
            )));
        }
        let bytes = hex::decode(stripped).map_err(serde::de::Error::custom)?;
        let mut out = [0u8; 16];
        out.copy_from_slice(&bytes);
        Ok(Self(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_id_round_trips_as_plain_integer() {
        let oid = OrderId(42);
        let j = serde_json::to_string(&oid).unwrap();
        assert_eq!(j, "42");
        let dec: OrderId = serde_json::from_str(&j).unwrap();
        assert_eq!(oid, dec);
    }

    #[test]
    fn market_id_round_trips_as_plain_integer() {
        let m = MarketId(7);
        let j = serde_json::to_string(&m).unwrap();
        assert_eq!(j, "7");
    }

    #[test]
    fn cloid_round_trips_as_hex_string() {
        let cloid = Cloid([0xABu8; 16]);
        let j = serde_json::to_string(&cloid).unwrap();
        assert_eq!(j, "\"0xabababababababababababababababab\"");
        let dec: Cloid = serde_json::from_str(&j).unwrap();
        assert_eq!(cloid, dec);
    }
}
