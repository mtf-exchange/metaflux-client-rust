//! Multisig INNER roster-signature digests.
//!
//! A multisig-acting bundle has two layers:
//!
//! - the OUTER envelope — a [`crate::wallet::TypedAction::MultiSig`] typed
//!   action that carries the acting account (`user`), the inner action blob, and
//!   the roster signatures. It holds no authority of its own and may be POSTed by
//!   any account.
//! - the INNER roster signatures — each authorized roster member signs the exact
//!   `inner_action_blob` bytes (the canonical `Action` JSON) here. The acting
//!   authority is the set of recovered inner signers.
//!
//! ## User-bound vs legacy inner digest
//!
//! There are two inner-digest schemes, and the network admits exactly ONE at a
//! time (there is no dual-accept window):
//!
//! - [`MultisigInnerScheme::UserBound`] — the current scheme. Each member signs
//!   the EIP-712 struct
//!   `MetaFluxMultiSigInner(address user,string action,uint64 nonce)`, binding
//!   the acting account `user`. A roster signature therefore authorizes exactly
//!   ONE account, so two accounts that share a roster (hot/cold, per-desk) can no
//!   longer replay each other's public inner blob + signatures.
//! - [`MultisigInnerScheme::Legacy`] — the previous unbound scheme, signing
//!   `MetaFluxAction(string action,uint64 nonce)` (no `user` word). Valid only
//!   BEFORE the user-bound activation; rejected from that point on.
//!
//! This SDK defaults to [`MultisigInnerScheme::UserBound`] everywhere; use
//! `Legacy` only to interoperate with a network that has not yet activated the
//! user-bound scheme.
//!
//! ## `action` bytes are hashed raw
//!
//! Both schemes hash the EXACT `inner_action_blob` bytes the roster signed
//! (`keccak256(blob)`), never a re-serialization. The same bytes MUST then ride
//! in the outer envelope's `inner_action_blob` (`0x`-hex) — the node hashes the
//! received bytes before decoding them.
//!
//! ## Chain id
//!
//! The inner digest is verified under the node's EVM domain chain id, which today
//! equals the signing chain id ([`crate::rest::exchange::MTF_CHAIN_ID`]) on both
//! mainnet and testnet. Source `chain_id` from that one constant. (On the node
//! these are two distinct state fields that happen to be equal; if they ever
//! diverge this constant would be wrong for one path.)

use crate::error::ClientError;
use crate::wallet::Wallet;
use crate::wallet::key::Address;
use crate::wallet::sign::Signature;
use crate::wallet::typed::{enc_addr, enc_u64, keccak, metaflux_domain_separator};

/// EIP-712 type string for a USER-BOUND multisig inner roster signature.
///
/// Copied VERBATIM from the node's signing contract — changing it invalidates
/// every collected roster signature once the user-bound scheme is active.
pub const MULTI_SIG_INNER_TYPE: &str =
    "MetaFluxMultiSigInner(address user,string action,uint64 nonce)";

/// EIP-712 type string for a LEGACY (unbound) inner roster signature — the same
/// envelope the single-sig `/exchange` path uses.
pub const MULTI_SIG_INNER_LEGACY_TYPE: &str = "MetaFluxAction(string action,uint64 nonce)";

/// Which inner-digest scheme a roster member signs under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MultisigInnerScheme {
    /// The current, user-bound scheme (`MetaFluxMultiSigInner`). Binds the acting
    /// account so a roster signature authorizes exactly one account.
    UserBound,
    /// The legacy, unbound scheme (`MetaFluxAction`). Valid only BEFORE the
    /// network activates the user-bound scheme.
    Legacy,
}

/// The 32-byte EIP-712 digest a roster member signs under the USER-BOUND scheme.
///
/// `keccak256(0x1901 ‖ domainSeparator(chain_id) ‖ structHash)` where
/// `structHash = keccak256(typeHash ‖ pad32(user) ‖ keccak256(blob) ‖ be32(nonce))`.
///
/// - `user` is the acting multisig account (NOT a roster member).
/// - `inner_action_json` is the exact `inner_action_blob` bytes (hashed raw).
/// - `nonce` is the outer-envelope nonce.
#[must_use]
pub fn multi_sig_inner_digest(
    chain_id: u64,
    user: Address,
    inner_action_json: &[u8],
    nonce: u64,
) -> [u8; 32] {
    let type_hash = keccak(MULTI_SIG_INNER_TYPE.as_bytes());
    let struct_hash = keccak(
        &[
            type_hash.as_slice(),
            enc_addr(&user).as_slice(),
            keccak(inner_action_json).as_slice(),
            enc_u64(nonce).as_slice(),
        ]
        .concat(),
    );
    eip712_digest(chain_id, &struct_hash)
}

/// The 32-byte EIP-712 digest a roster member signs under the LEGACY scheme.
///
/// `keccak256(0x1901 ‖ domainSeparator(chain_id) ‖ structHash)` where
/// `structHash = keccak256(typeHash ‖ keccak256(blob) ‖ be32(nonce))` over the
/// `MetaFluxAction(string action,uint64 nonce)` type — the exact `blob` bytes are
/// hashed (never a re-serialization).
#[must_use]
pub fn multi_sig_inner_digest_legacy(
    chain_id: u64,
    inner_action_json: &[u8],
    nonce: u64,
) -> [u8; 32] {
    let type_hash = keccak(MULTI_SIG_INNER_LEGACY_TYPE.as_bytes());
    let struct_hash = keccak(
        &[
            type_hash.as_slice(),
            keccak(inner_action_json).as_slice(),
            enc_u64(nonce).as_slice(),
        ]
        .concat(),
    );
    eip712_digest(chain_id, &struct_hash)
}

/// The inner-digest for `scheme` (dispatches to the user-bound / legacy form).
#[must_use]
pub fn multi_sig_inner_digest_for(
    scheme: MultisigInnerScheme,
    chain_id: u64,
    user: Address,
    inner_action_json: &[u8],
    nonce: u64,
) -> [u8; 32] {
    match scheme {
        MultisigInnerScheme::UserBound => {
            multi_sig_inner_digest(chain_id, user, inner_action_json, nonce)
        }
        MultisigInnerScheme::Legacy => {
            multi_sig_inner_digest_legacy(chain_id, inner_action_json, nonce)
        }
    }
}

/// Sign the inner roster digest for `scheme` with `wallet`, producing the 65-byte
/// `r‖s‖v` signature that rides in the outer envelope's `signatures` array.
///
/// `user` is ignored for [`MultisigInnerScheme::Legacy`] (the legacy digest binds
/// no account), but pass the real acting account anyway so a caller can flip
/// schemes without touching the call site.
///
/// # Errors
/// [`ClientError::Signature`] on a signing failure (essentially never for valid
/// keys + a 32-byte digest).
pub fn sign_multisig_inner(
    wallet: &Wallet,
    scheme: MultisigInnerScheme,
    chain_id: u64,
    user: Address,
    inner_action_json: &[u8],
    nonce: u64,
) -> Result<Signature, ClientError> {
    let digest = multi_sig_inner_digest_for(scheme, chain_id, user, inner_action_json, nonce);
    wallet.sign_digest(&digest)
}

/// `keccak256(0x19 0x01 ‖ domainSeparator(chain_id) ‖ struct_hash)`.
fn eip712_digest(chain_id: u64, struct_hash: &[u8; 32]) -> [u8; 32] {
    let domain = metaflux_domain_separator(chain_id);
    keccak(&[&[0x19u8, 0x01], domain.as_slice(), struct_hash.as_slice()].concat())
}
