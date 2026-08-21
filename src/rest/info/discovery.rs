//! `/info` — peer discovery.
//!
//! One PUBLIC query: [`Info::gossip_root_ips`]. It returns the nodes a
//! deployment advertises, so a joining node can dial them.
//!
//! ## A node that advertises nothing is absent
//!
//! Each node serves an operator-curated roster from its own config. The roster
//! states public reachability. It is NOT the node's internal dial list, and
//! there is no fallback to that list. A validator can run, vote and serve while
//! publishing no address — it simply does not appear in the rows. An empty
//! [`GossipRootIps::peers`] is therefore the honest answer for a deployment
//! that advertises nothing, not an error.

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::error::ClientError;
use crate::rest::info::Info;

/// One advertised node.
///
/// The fields map one-to-one onto a joining node's own peer config, so a row is
/// copied field-for-field and dialed. That is why all three ports and the
/// public key ship together.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AdvertisedPeer {
    /// The node's numeric id.
    pub id: u16,
    /// Public gossip endpoint, `host:port`.
    pub gossip: String,
    /// Public peer-RPC endpoint, `host:port`.
    pub peer_rpc: String,
    /// Public auth endpoint, `host:port`.
    pub auth: String,
    /// Compressed secp256k1 public key for this peer's TCP auth. `None` when
    /// the operator did not publish it — the node omits the field.
    #[serde(default)]
    pub pubkey_hex: Option<String>,
}

/// The advertised peer roster (`gossip_root_ips`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct GossipRootIps {
    /// One row per advertised node. Empty when the deployment advertises
    /// nothing.
    pub peers: Vec<AdvertisedPeer>,
}

impl Info<'_> {
    /// Read the advertised peer roster (`gossip_root_ips`).
    ///
    /// Per-node config, NOT committed state: nodes that carry the same roster
    /// answer identically, and nodes that do not may differ.
    ///
    /// The node release that serves this shape has not fired yet. Against an
    /// older node the decode fails on the missing `peers` field, which is
    /// deliberate — a silent empty roster is indistinguishable from a
    /// deployment that advertises nothing.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn gossip_root_ips(&self) -> Result<GossipRootIps, ClientError> {
        self.client
            .post_json("/info", &json!({ "type": "gossip_root_ips" }))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn row_decodes_and_omitted_pubkey_is_none() {
        let v: GossipRootIps = serde_json::from_str(
            r#"{"peers":[
                {"id":3,"gossip":"203.0.113.7:4001","peer_rpc":"203.0.113.7:4002",
                 "auth":"203.0.113.7:4003","pubkey_hex":"02ab"},
                {"id":4,"gossip":"seed-a.example:4011","peer_rpc":"seed-a.example:4012",
                 "auth":"seed-a.example:4013"}
            ]}"#,
        )
        .expect("decode roster");
        assert_eq!(v.peers.len(), 2);
        assert_eq!(v.peers[0].id, 3);
        assert_eq!(v.peers[0].pubkey_hex.as_deref(), Some("02ab"));
        assert_eq!(v.peers[1].pubkey_hex, None);
    }

    #[test]
    fn empty_roster_decodes() {
        let v: GossipRootIps = serde_json::from_str(r#"{"peers":[]}"#).expect("decode empty");
        assert!(v.peers.is_empty());
    }
}
