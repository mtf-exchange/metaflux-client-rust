//! `/explorer` — block / tx lookups.
//!
//! Read-only queries with the same MTF-native shape conventions as `/info`:
//! snake_case JSON, plain-integer numerics.

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::error::ClientError;
use crate::rest::RestClient;

/// `explorer` namespace handle. Constructed via [`RestClient::explorer`].
#[derive(Debug)]
pub struct Explorer<'a> {
    pub(crate) client: &'a RestClient,
}

/// A block header + tx ids. Full bodies retrievable via `tx_by_hash`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Block {
    /// Block height.
    pub height: u64,
    /// 32-byte block hash, 0x-prefixed lowercase hex.
    pub hash: String,
    /// Parent block hash.
    pub parent_hash: String,
    /// Block timestamp (unix ms).
    pub ts_ms: u64,
    /// Validator that proposed this block.
    pub proposer: String,
    /// Transaction hashes in inclusion order.
    pub tx_hashes: Vec<String>,
    /// Application state commitment post-block — an opaque 0x-hex 32-byte hash
    /// (a pure full-state fold of the server's `Exchange` ledger). Does NOT
    /// encode height/epoch, so an unchanged-state chain reports a constant
    /// value. Round-tripped verbatim; the client does not recompute or verify it.
    pub app_hash: String,
}

/// A decoded transaction record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Transaction {
    /// 32-byte tx hash, 0x-prefixed lowercase hex.
    pub hash: String,
    /// Block height the tx was included in.
    pub block_height: u64,
    /// Action `type` discriminator.
    pub action_type: String,
    /// 20-byte signer address, 0x-prefixed hex.
    pub signer: String,
    /// EIP-712 nonce used by the signer.
    pub nonce: u64,
    /// Outcome: `accepted` / `rejected` / `error`.
    pub status: String,
    /// Optional error message (present only when `status != "accepted"`).
    #[serde(default)]
    pub error: Option<String>,
}

impl<'a> Explorer<'a> {
    /// Look up a block by height.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn block_by_height(&self, height: u64) -> Result<Block, ClientError> {
        self.client
            .post_json(
                "/explorer",
                &json!({ "type": "block_by_height", "height": height }),
            )
            .await
    }

    /// Look up a transaction by 32-byte hash (0x-prefixed lowercase hex).
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn tx_by_hash(&self, hash: &str) -> Result<Transaction, ClientError> {
        self.client
            .post_json("/explorer", &json!({ "type": "tx_by_hash", "hash": hash }))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_round_trips() {
        let b = Block {
            height: 100,
            hash: "0xdeadbeef".repeat(8),
            parent_hash: "0xcafebabe".repeat(8),
            ts_ms: 1_700_000_000_000,
            proposer: "0x".to_string() + &"ab".repeat(20),
            tx_hashes: vec!["0x01".into(), "0x02".into()],
            app_hash: "0x".to_string() + &"00".repeat(32),
        };
        let j = serde_json::to_string(&b).unwrap();
        let dec: Block = serde_json::from_str(&j).unwrap();
        assert_eq!(b, dec);
    }

    #[test]
    fn transaction_uses_snake_case_fields() {
        let t = Transaction {
            hash: "0x01".into(),
            block_height: 100,
            action_type: "submit_order".into(),
            signer: "0xab".into(),
            nonce: 1_700_000_000_000,
            status: "accepted".into(),
            error: None,
        };
        let j = serde_json::to_value(&t).unwrap();
        for key in ["block_height", "action_type"] {
            assert!(j.get(key).is_some(), "missing {key}");
        }
        for key in ["blockHeight", "actionType"] {
            assert!(j.get(key).is_none(), "wire leak: {key}");
        }
    }
}
