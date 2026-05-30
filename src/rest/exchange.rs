//! `/exchange` — signed write actions.
//!
//! Each method takes `&Wallet` and a typed action; the SDK builds an
//! EIP-712 digest from the action, signs it deterministically, and posts:
//!
//! ```json
//! {
//!   "action":    { "type": "<action>", ... },
//!   "nonce":     <unix_ms>,
//!   "signature": "0x<65-byte-hex>"
//! }
//! ```
//!
//! The MTF-native gateway recovers the signer from the signature against
//! the EIP-712 digest, validates the `action.owner`/`action.user`/`action.sender`
//! field equals the recovered address, and forwards to the node.
//!
//! ## EIP-712 domain
//!
//! Every action shares the same MTF-native EIP-712 domain:
//!
//! ```text
//!   name             = "MetaFlux"
//!   version          = "1"
//!   chain_id         = <chain id>
//!   verifying_contract = <gateway-fixed; 0x0 in v0>
//! ```
//!
//! The per-action struct hash is computed from the action's typed-data
//! schema (matches the `crates/api-gateway` decoder in the L1 monorepo).

use serde::Serialize;
use serde_json::{Value, json};
use tiny_keccak::{Hasher, Keccak};

use crate::error::ClientError;
use crate::rest::RestClient;
use crate::types::{
    cross_chain::CrossChainSend,
    encrypted::EncryptedOrderSubmit,
    fba::FbaSubmit,
    order::{CancelOrder, Order, OrderResponse},
    pm::{PmEnroll, PmRebalance, PmUnenroll},
    rfq::{RfqAccept, RfqRequest},
    vault::{VaultCreate, VaultDistribute, VaultWithdraw},
};
use crate::wallet::{Eip712, Signature, Wallet};

/// MTF EIP-712 domain chain id.
///
/// Pinned to `998` provisionally — the real value lands when the L1 genesis
/// is set in S10. Once configurable chain ids land we'll switch this to a
/// builder field on [`Exchange`] (see TODO in the exchange module).
pub const MTF_CHAIN_ID: u64 = 998;

/// `/exchange` namespace handle. Constructed via [`RestClient::exchange`].
///
/// Uses the global [`MTF_CHAIN_ID`] constant for EIP-712 domain
/// construction. Configurable chain ids will arrive once testnet / devnet
/// chain ids are pinned (post-S10).
#[derive(Debug)]
pub struct Exchange<'a> {
    pub(crate) client: &'a RestClient,
}

/// Convenience: a signed action ready to POST to `/exchange`.
#[derive(Clone, Debug, Serialize)]
struct SignedEnvelope<'a> {
    action: &'a Value,
    nonce: u64,
    signature: String,
}

impl<'a> Exchange<'a> {
    /// Submit a limit / market / trigger order.
    ///
    /// The order's `owner` field MUST equal the wallet's address; the server
    /// verifies this against the recovered signer.
    ///
    /// # Errors
    /// - [`ClientError::Validation`] if `order.owner != wallet.address()`.
    /// - [`ClientError::Http`] / [`ClientError::ProtocolError`] on transport.
    /// - [`ClientError::Signature`] on signing failure (extremely rare).
    pub async fn submit_order(
        &self,
        wallet: &Wallet,
        order: &Order,
    ) -> Result<OrderResponse, ClientError> {
        if order.owner != wallet.address() {
            return Err(ClientError::Validation(format!(
                "order.owner {} != wallet address {}",
                order.owner,
                wallet.address()
            )));
        }
        let action = json!({ "type": "submit_order", "order": order });
        self.post_signed(wallet, action).await
    }

    /// Cancel an order by `oid` or by `cloid`.
    ///
    /// # Errors
    /// See [`Exchange::submit_order`].
    pub async fn cancel_order(
        &self,
        wallet: &Wallet,
        cancel: &CancelOrder,
    ) -> Result<Value, ClientError> {
        if cancel.owner != wallet.address() {
            return Err(ClientError::Validation(format!(
                "cancel.owner {} != wallet address {}",
                cancel.owner,
                wallet.address()
            )));
        }
        let action = json!({ "type": "cancel_order", "cancel": cancel });
        self.post_signed(wallet, action).await
    }

    /// Create a new user vault. Signer must equal `vault.leader`.
    ///
    /// # Errors
    /// See [`Exchange::submit_order`].
    pub async fn vault_create(
        &self,
        wallet: &Wallet,
        vault: &VaultCreate,
    ) -> Result<Value, ClientError> {
        if vault.leader != wallet.address() {
            return Err(ClientError::Validation(format!(
                "vault.leader {} != wallet address {}",
                vault.leader,
                wallet.address()
            )));
        }
        let action = json!({ "type": "vault_create", "vault": vault });
        self.post_signed(wallet, action).await
    }

    /// Distribute realised PnL to followers (leader-only).
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn vault_distribute(
        &self,
        wallet: &Wallet,
        d: &VaultDistribute,
    ) -> Result<Value, ClientError> {
        let action = json!({ "type": "vault_distribute", "params": d });
        self.post_signed(wallet, action).await
    }

    /// Withdraw shares from a vault (subject to the per-vault lock).
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn vault_withdraw(
        &self,
        wallet: &Wallet,
        w: &VaultWithdraw,
    ) -> Result<Value, ClientError> {
        let action = json!({ "type": "vault_withdraw", "params": w });
        self.post_signed(wallet, action).await
    }

    /// Enrol into portfolio margin.
    ///
    /// # Errors
    /// See [`Exchange::submit_order`].
    pub async fn pm_enroll(&self, wallet: &Wallet, e: &PmEnroll) -> Result<Value, ClientError> {
        if e.user != wallet.address() {
            return Err(ClientError::Validation(format!(
                "pm.user {} != wallet address {}",
                e.user,
                wallet.address()
            )));
        }
        let action = json!({ "type": "pm_enroll", "params": e });
        self.post_signed(wallet, action).await
    }

    /// Un-enrol from portfolio margin.
    ///
    /// # Errors
    /// See [`Exchange::submit_order`].
    pub async fn pm_unenroll(&self, wallet: &Wallet, e: &PmUnenroll) -> Result<Value, ClientError> {
        if e.user != wallet.address() {
            return Err(ClientError::Validation(format!(
                "pm.user {} != wallet address {}",
                e.user,
                wallet.address()
            )));
        }
        let action = json!({ "type": "pm_unenroll", "params": e });
        self.post_signed(wallet, action).await
    }

    /// Trigger a PM margin recompute.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn pm_rebalance(
        &self,
        wallet: &Wallet,
        e: &PmRebalance,
    ) -> Result<Value, ClientError> {
        let action = json!({ "type": "pm_rebalance", "params": e });
        self.post_signed(wallet, action).await
    }

    /// Open an RFQ session as the taker.
    ///
    /// # Errors
    /// See [`Exchange::submit_order`].
    pub async fn rfq_request(&self, wallet: &Wallet, r: &RfqRequest) -> Result<Value, ClientError> {
        if r.taker != wallet.address() {
            return Err(ClientError::Validation(format!(
                "rfq.taker {} != wallet address {}",
                r.taker,
                wallet.address()
            )));
        }
        let action = json!({ "type": "rfq_request", "rfq": r });
        self.post_signed(wallet, action).await
    }

    /// Accept an MM quote and cross the trade.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn rfq_accept(&self, wallet: &Wallet, a: &RfqAccept) -> Result<Value, ClientError> {
        let action = json!({ "type": "rfq_accept", "accept": a });
        self.post_signed(wallet, action).await
    }

    /// Submit an order into an FBA batch.
    ///
    /// # Errors
    /// See [`Exchange::submit_order`].
    pub async fn fba_submit(&self, wallet: &Wallet, s: &FbaSubmit) -> Result<Value, ClientError> {
        if s.owner != wallet.address() {
            return Err(ClientError::Validation(format!(
                "fba.owner {} != wallet address {}",
                s.owner,
                wallet.address()
            )));
        }
        let action = json!({ "type": "fba_submit", "submit": s });
        self.post_signed(wallet, action).await
    }

    /// Send a cross-chain message.
    ///
    /// # Errors
    /// See [`Exchange::submit_order`].
    pub async fn cross_chain_send(
        &self,
        wallet: &Wallet,
        s: &CrossChainSend,
    ) -> Result<Value, ClientError> {
        if s.sender != wallet.address() {
            return Err(ClientError::Validation(format!(
                "cross_chain.sender {} != wallet address {}",
                s.sender,
                wallet.address()
            )));
        }
        let action = json!({ "type": "cross_chain_send", "msg": s });
        self.post_signed(wallet, action).await
    }

    /// Submit a threshold-encrypted order ciphertext.
    ///
    /// # Errors
    /// See [`Exchange::submit_order`].
    pub async fn encrypted_order_submit(
        &self,
        wallet: &Wallet,
        e: &EncryptedOrderSubmit,
    ) -> Result<Value, ClientError> {
        if e.submitter != wallet.address() {
            return Err(ClientError::Validation(format!(
                "encrypted.submitter {} != wallet address {}",
                e.submitter,
                wallet.address()
            )));
        }
        let action = json!({ "type": "encrypted_order_submit", "encrypted": e });
        self.post_signed(wallet, action).await
    }

    // --- Internals ---

    /// Sign + POST an arbitrary action JSON. Public for power users.
    ///
    /// # Errors
    /// See [`Exchange::submit_order`].
    pub async fn post_signed<R: serde::de::DeserializeOwned>(
        &self,
        wallet: &Wallet,
        action: Value,
    ) -> Result<R, ClientError> {
        let nonce = next_nonce();
        let signed = ActionSignedDigest {
            action: &action,
            nonce,
        };
        let sig = wallet.sign_eip712(&signed)?;
        let envelope = SignedEnvelope {
            action: &action,
            nonce,
            signature: sig.to_hex(),
        };
        // `/exchange` is the node's MTF-native signed-action front door. The
        // `{action, nonce, signature}` envelope + EIP-712-over-canonical-JSON
        // digest match the server's handler byte-for-byte (cross-impl KAT in
        // this module + `core-state/src/signing.rs`).
        self.client.post_json("/exchange", &envelope).await
    }
}

/// EIP-712 typed-data hash for an `(action, nonce)` pair.
///
/// The MTF-native domain is:
///
/// ```text
///   EIP712Domain(name string, version string, chainId uint256, verifyingContract address)
///   MetaFluxAction(action string, nonce uint64)  -- action is the canonical-JSON action body
/// ```
///
/// Canonical-JSON = `serde_json::to_string()` with no whitespace. This is
/// deliberately simple for v0; the gateway's verifier uses the same rule.
struct ActionSignedDigest<'a> {
    action: &'a Value,
    nonce: u64,
}

impl Eip712 for ActionSignedDigest<'_> {
    fn domain_separator(&self) -> [u8; 32] {
        // EIP712Domain typeHash and the encoded domain struct. 5-field form,
        // byte-for-byte mirroring the server `EipDomain::separator()` in
        // metaflux/crates/core-state/src/signing.rs.
        //
        // typeHash = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
        // domain   = keccak256( typeHash || keccak256(name) || keccak256(version) || chainId || verifyingContract )
        let name = "MetaFlux";
        let version = "1";
        let chain_id: u64 = MTF_CHAIN_ID;

        let type_hash = keccak(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                .as_bytes(),
        );
        let name_hash = keccak(name.as_bytes());
        let version_hash = keccak(version.as_bytes());

        let mut buf = Vec::with_capacity(32 * 5);
        buf.extend_from_slice(&type_hash);
        buf.extend_from_slice(&name_hash);
        buf.extend_from_slice(&version_hash);
        // chain_id encoded as 32-byte big-endian uint256
        let mut chain_be = [0u8; 32];
        chain_be[24..].copy_from_slice(&chain_id.to_be_bytes());
        buf.extend_from_slice(&chain_be);
        // verifyingContract = 20-byte zero address (L1 actions), left-padded to 32.
        let verifying_contract = [0u8; 20];
        let mut verifying_padded = [0u8; 32];
        verifying_padded[12..].copy_from_slice(&verifying_contract);
        buf.extend_from_slice(&verifying_padded);
        keccak(&buf)
    }

    fn struct_hash(&self) -> [u8; 32] {
        // typeHash = keccak256("MetaFluxAction(string action,uint64 nonce)")
        // struct   = keccak256( typeHash || keccak256(action_json) || nonce )
        let type_hash = keccak("MetaFluxAction(string action,uint64 nonce)".as_bytes());
        let action_json = serde_json::to_string(self.action).unwrap_or_default();
        let action_hash = keccak(action_json.as_bytes());

        let mut nonce_be = [0u8; 32];
        nonce_be[24..].copy_from_slice(&self.nonce.to_be_bytes());

        let mut buf = Vec::with_capacity(32 * 3);
        buf.extend_from_slice(&type_hash);
        buf.extend_from_slice(&action_hash);
        buf.extend_from_slice(&nonce_be);
        keccak(&buf)
    }
}

fn keccak(input: &[u8]) -> [u8; 32] {
    let mut h = Keccak::v256();
    h.update(input);
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    out
}

/// Current unix-time in milliseconds.
fn current_unix_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Strictly-increasing EIP-712 nonce — at least the current unix-ms, but bumped
/// past the last issued value so a burst of actions within one millisecond gets
/// distinct nonces. The server's per-account window (`check_and_advance_nonce`)
/// tolerates out-of-order delivery within 64 but rejects *collisions*, so a raw
/// `unix_ms` would drop the 2nd-and-later order in a same-ms burst.
fn next_nonce() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NONCE_CLOCK: AtomicU64 = AtomicU64::new(0);
    let now = current_unix_ms();
    let mut prev = NONCE_CLOCK.load(Ordering::Relaxed);
    loop {
        let next = now.max(prev.saturating_add(1));
        match NONCE_CLOCK.compare_exchange_weak(prev, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return next,
            Err(observed) => prev = observed,
        }
    }
}

/// Test-only escape hatch: compute the EIP-712 digest the SDK would sign
/// for the given action + nonce. Used by the integration tests under
/// `tests/`. Not part of the stable public API.
#[doc(hidden)]
pub fn _action_digest_for_test(action: &Value, nonce: u64) -> [u8; 32] {
    let d = ActionSignedDigest { action, nonce };
    d.to_digest()
}

/// Test-only escape hatch: recover the signer address from a digest + 65-byte
/// signature. Used by the integration tests under `tests/`. Not part of the
/// stable public API.
#[doc(hidden)]
pub fn _recover_for_test(
    digest: &[u8; 32],
    sig: &Signature,
) -> Result<crate::wallet::Address, ClientError> {
    crate::wallet::sign_recover_for_test_only(digest, sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_separator_is_deterministic() {
        let a = ActionSignedDigest {
            action: &json!({"type": "submit_order"}),
            nonce: 1,
        };
        let b = ActionSignedDigest {
            action: &json!({"type": "submit_order"}),
            nonce: 1,
        };
        assert_eq!(a.domain_separator(), b.domain_separator());
    }

    #[test]
    fn struct_hash_changes_with_nonce() {
        let a = ActionSignedDigest {
            action: &json!({"type": "submit_order"}),
            nonce: 1,
        };
        let b = ActionSignedDigest {
            action: &json!({"type": "submit_order"}),
            nonce: 2,
        };
        assert_ne!(a.struct_hash(), b.struct_hash());
    }

    #[test]
    fn struct_hash_changes_with_action() {
        let a = ActionSignedDigest {
            action: &json!({"type": "submit_order"}),
            nonce: 1,
        };
        let b = ActionSignedDigest {
            action: &json!({"type": "cancel_order"}),
            nonce: 1,
        };
        assert_ne!(a.struct_hash(), b.struct_hash());
    }

    /// Cross-impl known-answer vector. Pins the SDK's EIP-712 domain (now
    /// 5-field) + digest FORMULA against the server's committed value
    /// (`metaflux/crates/core-state/src/signing.rs::native_action_kat_vector`).
    ///
    /// We hash the LITERAL action_json bytes via the keccak primitives directly
    /// — NOT through `ActionSignedDigest`, which serializes a `serde_json::Value`
    /// and may reorder keys. This isolates the test to the domain + composition,
    /// the only thing the SDK fix touched.
    #[test]
    fn native_action_kat_matches_server() {
        // EXACT bytes the server hashed in its KAT vector.
        let action_json = br#"{"type":"submit_order","order":{"owner":"0x000000000000000000000000000000000000beef","market":1,"side":"bid","kind":"limit","size":1000,"limit_px":5000000000000,"tif":"gtc","stp_mode":"cancel_oldest","reduce_only":false}}"#;
        let nonce: u64 = 1_700_000_000_000;

        // Reuse the SDK's fixed 5-field domain separator.
        let domain = ActionSignedDigest {
            action: &json!({}),
            nonce: 0,
        }
        .domain_separator();

        // struct_hash = keccak( typeHash || keccak(action_json) || nonce_be32 )
        let type_hash = keccak("MetaFluxAction(string action,uint64 nonce)".as_bytes());
        let action_hash = keccak(action_json);
        let mut nonce_be = [0u8; 32];
        nonce_be[24..].copy_from_slice(&nonce.to_be_bytes());
        let mut sh_buf = Vec::with_capacity(32 * 3);
        sh_buf.extend_from_slice(&type_hash);
        sh_buf.extend_from_slice(&action_hash);
        sh_buf.extend_from_slice(&nonce_be);
        let struct_hash = keccak(&sh_buf);

        // digest = keccak( 0x19 0x01 || domain || struct_hash )
        let mut d_buf = Vec::with_capacity(2 + 64);
        d_buf.extend_from_slice(&[0x19, 0x01]);
        d_buf.extend_from_slice(&domain);
        d_buf.extend_from_slice(&struct_hash);
        let digest = keccak(&d_buf);

        // Server's committed value (core-state signing::native_action_kat_vector):
        // bc1fa314ad46f9aa0b146623144ef6f7efff7d43a8998d7bf63ef018c21352f2
        let expected: [u8; 32] = [
            0xbc, 0x1f, 0xa3, 0x14, 0xad, 0x46, 0xf9, 0xaa, 0x0b, 0x14, 0x66, 0x23, 0x14, 0x4e,
            0xf6, 0xf7, 0xef, 0xff, 0x7d, 0x43, 0xa8, 0x99, 0x8d, 0x7b, 0xf6, 0x3e, 0xf0, 0x18,
            0xc2, 0x13, 0x52, 0xf2,
        ];
        assert_eq!(
            digest, expected,
            "SDK digest must equal server KAT bc1fa3..52f2; got {digest:02x?}"
        );
    }
}
