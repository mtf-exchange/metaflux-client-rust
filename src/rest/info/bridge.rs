//! `/info` — custody bridge reads.
//!
//! Two PUBLIC queries: [`Info::bridge_chain_configs`] and
//! [`Info::bridge_user_outbox`]. The node also serves `bridge_outbox` and
//! `bridge_finalized_cosignatures`, but the public gateway REFUSES both (they
//! are operator reads), so this SDK does not type them.
//!
//! ## The message id moves
//!
//! A withdrawal's `message_id` is the SIGNING digest, and it folds the chain's
//! committed deployment row (`evm_chain_id`, `evm_contract_address`,
//! `validator_set_epoch`). Governance can rotate that row, and the same
//! withdrawal then gets a NEW `message_id`. The value on
//! [`BridgeOutboxEntry::message_id`] is always the id under the CURRENT row —
//! the only id a caller should act on.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::error::ClientError;
use crate::rest::info::Info;
use crate::wallet::Address;

/// Where one pending withdrawal stands against the CURRENT deployment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeOutboxStatus {
    /// Validators are still co-signing. Normal, and it SURVIVES a deployment
    /// rotation: the relay re-derives the new id and re-signs under it. Only
    /// partial-signature progress resets.
    AwaitingCosignatures,
    /// A releasable ⅔ multisig exists under the current deployment. The relay
    /// can submit it now. This is the ONLY status a rotation can break.
    ReadyToRelease,
    /// Quorum was reached under a RETIRED deployment. The replay guard keys on a
    /// rotation-invariant id, so the chain deliberately refuses to re-finalize
    /// under the new deployment and no releasable multisig can ever appear.
    ///
    /// TERMINAL: waiting does not clear it and no relay action can. Recovery
    /// needs a governance re-credit vote.
    StrandedOnRetiredDomain,
    /// The destination-chain release is quorum-confirmed. The entry is retained
    /// for the chain's release-retention window so a destination reorg can be
    /// re-relayed, then it leaves the outbox.
    Released,
}

/// One pending withdrawal in the bridge outbox.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct BridgeOutboxEntry {
    /// Destination chain: `1` = Base, `2` = Arbitrum.
    pub chain: u8,
    /// MetaFlux asset id.
    pub asset: u32,
    /// Spot-token symbol for [`Self::asset`].
    pub token: String,
    /// Amount in the destination chain's BASE UNITS, not whole coins — USDC has
    /// 6 decimals, so `"1000000"` is 1.0 USDC. A string because the value is a
    /// `u128` and does not fit a JSON number.
    pub amount_units: String,
    /// 32-byte destination address (`0x` + 64 hex; an EVM address is
    /// left-padded).
    pub dst_addr: String,
    /// Anti-replay nonce.
    pub nonce: u64,
    /// Consensus ts the withdrawal was queued (ms).
    pub ts_ms: u64,
    /// The CURRENT-domain signing digest (`0x` + 64 hex). See the module docs:
    /// this value moves when governance rotates the deployment.
    pub message_id: String,
    /// Where the entry stands against the current deployment.
    pub status: BridgeOutboxStatus,
    /// Validators that have co-signed so far. Only meaningful while
    /// [`BridgeOutboxStatus::AwaitingCosignatures`].
    #[serde(default)]
    pub pending_cosigner_count: u32,
    /// Release ts (ms) for a [`BridgeOutboxStatus::Released`] entry; `None` for
    /// every other status.
    #[serde(default)]
    pub released_at_ms: Option<u64>,
}

/// One user's pending bridge withdrawals (`bridge_user_outbox`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct BridgeUserOutbox {
    /// Pending withdrawals, oldest first. Empty means no withdrawal is in
    /// flight — it does NOT mean a past withdrawal failed.
    #[serde(default)]
    pub entries: Vec<BridgeOutboxEntry>,
    /// `true` if the 256-entry cap truncated the list.
    #[serde(default)]
    pub truncated: bool,
}

/// The governed deposit-scan policy on one chain.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct BridgeScanPolicy {
    /// `false` = the scan keeps the finalized floor. Not a setting a real-funds
    /// chain changes.
    #[serde(default)]
    pub confirmations_only: bool,
    /// RAW confirmations lag. `0` means UNSET — read
    /// [`Self::effective_confirmations`] for the value in force.
    #[serde(default)]
    pub confirmations: u64,
    /// The confirmations lag actually in force (default `5`).
    #[serde(default)]
    pub effective_confirmations: u64,
    /// Reorg depth, read ONLY while [`Self::confirmations_only`] is `true`.
    #[serde(default)]
    pub confirmations_only_depth: u64,
    /// The USDC ERC-20 the raw-transfer deposit lane credits (`0x` + 40 hex).
    /// Zero disables the lane.
    #[serde(default)]
    pub usdc_token: String,
    /// Master switch for the raw-transfer (credit-the-sender) deposit lane.
    #[serde(default)]
    pub raw_transfer_credit: bool,
}

/// One chain's committed bridge deployment row.
///
/// The `(evm_chain_id, evm_contract_address, validator_set_epoch)` triple IS the
/// message-id domain. Rotating any of the three moves the `message_id` of every
/// in-flight withdrawal on that chain.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct BridgeChainConfigRow {
    /// `1` = Base, `2` = Arbitrum.
    pub chain: u8,
    /// 32-byte deployment id (`0x` + 64 hex) — the EVM address left-padded.
    pub contract_address: String,
    /// Stake share required to co-sign, in basis points (`6700` = 67%).
    pub validator_quorum_threshold_bps: String,
    /// Per-chain replay counter, shared by both directions.
    pub replay_nonce: u64,
    /// Per-chain kill switch. Blocks withdrawals AND deposit attestation.
    pub paused: bool,
    /// EVM `block.chainid` of the deployed contract.
    pub evm_chain_id: u64,
    /// 20-byte `address(this)` of the deployed contract (`0x` + 40 hex).
    pub evm_contract_address: String,
    /// Validator-set epoch the deployed contract pins.
    pub validator_set_epoch: u64,
    /// RAW retention window (ms). `0` means UNSET — read
    /// [`Self::effective_release_retention_ms`] for the window in force.
    #[serde(default)]
    pub release_retention_ms: u64,
    /// The release-retention window actually in force (default 24 h). A released
    /// entry stays in the outbox this long so a destination reorg can be
    /// re-relayed.
    #[serde(default)]
    pub effective_release_retention_ms: u64,
    /// The governed deposit-scan policy.
    #[serde(default)]
    pub scan_policy: BridgeScanPolicy,
}

/// Every committed bridge deployment row (`bridge_chain_configs`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct BridgeChainConfigs {
    /// Chain-wide refusal of NEW withdrawals, all chains, until governance
    /// clears it. A bridge can be unable to PAY while still able to ACCEPT; this
    /// flag stops the accept.
    #[serde(default)]
    pub withdrawals_halted: bool,
    /// One row per configured chain.
    #[serde(default)]
    pub configs: Vec<BridgeChainConfigRow>,
}

impl Info<'_> {
    /// Read every committed bridge deployment row (`bridge_chain_configs`).
    ///
    /// Each field is independently verifiable against the deployed contract on
    /// Base or Arbitrum. Read the `effective_*` fields, not the raw ones: the
    /// raw values are 0-as-unset sentinels.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn bridge_chain_configs(&self) -> Result<BridgeChainConfigs, ClientError> {
        self.client
            .post_json("/info", &json!({ "type": "bridge_chain_configs" }))
            .await
    }

    /// Read one account's pending bridge withdrawals (`bridge_user_outbox`).
    ///
    /// `chain` restricts the answer to `1` (Base) or `2` (Arbitrum); `None`
    /// reads every chain. Check [`BridgeOutboxEntry::status`] on each entry —
    /// [`BridgeOutboxStatus::StrandedOnRetiredDomain`] is terminal and needs
    /// operator action, not a retry.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn bridge_user_outbox(
        &self,
        address: Address,
        chain: Option<u8>,
    ) -> Result<BridgeUserOutbox, ClientError> {
        let mut body = json!({ "type": "bridge_user_outbox", "address": address });
        if let Some(c) = chain {
            let obj = body.as_object_mut().expect("json! produced an object");
            obj.insert("chain".into(), Value::from(c));
        }
        self.client.post_json("/info", &body).await
    }
}
