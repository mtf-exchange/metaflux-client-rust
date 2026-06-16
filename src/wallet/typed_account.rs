//! Account / sub-account / staking / abstraction / priority / encrypted EIP-712
//! typed-action support — the formerly-unsigned set.
//!
//! Split out of [`crate::wallet::typed`] to keep that file readable, mirroring
//! [`crate::wallet::typed_orders`]. These are sender-authorized USER actions
//! that previously had no structured signing form. The variants + dispatch live
//! in the unified [`crate::wallet::TypedAction`] enum; the bulky frozen type
//! strings and `encodeData` word builders live here as free functions.
//!
//! Same frozen atomic encoding as the rest of the typed set: each field becomes
//! one 32-byte word in declared order. Decimal fields (`amount` / `value`) are
//! EIP-712 `string` and hashed verbatim — set them to the canonical text you
//! send on the wire. Optionals flatten to a presence `bool` + value pair
//! (`explicitIndex`, `asset`): the presence half signs `true`/`false` and the
//! value half signs the value (or `0` when absent), while the POST `params`
//! carries only the original optional key (present or omitted). `bytes` /
//! `bytes32` (`ciphertext` / `commitment`): `bytes` hashes `keccak256(raw)`,
//! `bytes32` is the raw 32 bytes carried verbatim into one word.

use crate::wallet::typed::{
    enc_addr, enc_bool, enc_bytes, enc_string, enc_u8, enc_u16, enc_u32, enc_u64,
};

// ===== Type strings (signing order = encodeType order = message field order) =====
//
// CONSENSUS-FROZEN: changing any string invalidates every client signature.

/// `MetaFluxTransaction:CoreEvmTransfer` // CONSENSUS-FROZEN
pub(crate) const CORE_EVM_TRANSFER_TYPE: &[u8] =
    b"MetaFluxTransaction:CoreEvmTransfer(string metafluxChain,string amount,bool toEvm,address destination,uint32 asset,uint64 nonce)";
/// `MetaFluxTransaction:CreateSubAccount` // CONSENSUS-FROZEN. The optional
/// `explicitIndex` flattens to a presence `bool` + value (`0` when absent).
pub(crate) const CREATE_SUB_ACCOUNT_TYPE: &[u8] =
    b"MetaFluxTransaction:CreateSubAccount(string metafluxChain,string name,bool hasExplicitIndex,uint32 explicitIndex,bool sharedStpGroup,uint64 nonce)";
/// `MetaFluxTransaction:SubAccountTransfer` // CONSENSUS-FROZEN
pub(crate) const SUB_ACCOUNT_TRANSFER_TYPE: &[u8] =
    b"MetaFluxTransaction:SubAccountTransfer(string metafluxChain,uint32 subIndex,bool deposit,string amount,uint64 nonce)";
/// `MetaFluxTransaction:SubAccountSpotTransfer` // CONSENSUS-FROZEN
pub(crate) const SUB_ACCOUNT_SPOT_TRANSFER_TYPE: &[u8] =
    b"MetaFluxTransaction:SubAccountSpotTransfer(string metafluxChain,uint32 subIndex,uint32 token,bool deposit,string amount,uint64 nonce)";
/// `MetaFluxTransaction:CDeposit` // CONSENSUS-FROZEN (spot MTF → free staking pool)
pub(crate) const C_DEPOSIT_TYPE: &[u8] =
    b"MetaFluxTransaction:CDeposit(string metafluxChain,string amount,uint64 nonce)";
/// `MetaFluxTransaction:CWithdraw` // CONSENSUS-FROZEN (free staking pool → spot MTF)
pub(crate) const C_WITHDRAW_TYPE: &[u8] =
    b"MetaFluxTransaction:CWithdraw(string metafluxChain,string amount,uint64 nonce)";
/// `MetaFluxTransaction:UserDexAbstraction` // CONSENSUS-FROZEN
pub(crate) const USER_DEX_ABSTRACTION_TYPE: &[u8] =
    b"MetaFluxTransaction:UserDexAbstraction(string metafluxChain,bool enabled,uint64 nonce)";
/// `MetaFluxTransaction:UserSetAbstraction` // CONSENSUS-FROZEN
pub(crate) const USER_SET_ABSTRACTION_TYPE: &[u8] =
    b"MetaFluxTransaction:UserSetAbstraction(string metafluxChain,uint8 kind,string value,uint64 nonce)";
/// `MetaFluxTransaction:PriorityBid` // CONSENSUS-FROZEN
pub(crate) const PRIORITY_BID_TYPE: &[u8] =
    b"MetaFluxTransaction:PriorityBid(string metafluxChain,uint32 asset,uint16 bidBps,uint64 nonce)";
/// `MetaFluxTransaction:CancelAllOrders` // CONSENSUS-FROZEN. The optional asset
/// filter flattens to a presence `bool` + value (`0` when "all assets").
pub(crate) const CANCEL_ALL_ORDERS_TYPE: &[u8] =
    b"MetaFluxTransaction:CancelAllOrders(string metafluxChain,bool hasAsset,uint32 asset,uint64 nonce)";
/// `MetaFluxTransaction:SubmitEncryptedOrder` // CONSENSUS-FROZEN. `ciphertext`
/// is EIP-712 `bytes` (hashed `keccak256(raw)`); `commitment` is `bytes32`.
pub(crate) const SUBMIT_ENCRYPTED_ORDER_TYPE: &[u8] =
    b"MetaFluxTransaction:SubmitEncryptedOrder(string metafluxChain,bytes ciphertext,bytes32 commitment,uint8 threshold,uint64 targetBlock,uint64 revealDeadlineMs,uint64 nonce)";

// ===== encodeData builders (called by `TypedAction::encode_data`) =====

/// `CoreEvmTransfer` words. `amount` is the verbatim canonical decimal string.
pub(crate) fn core_evm_transfer_words(
    chain: &str,
    amount: &str,
    to_evm: bool,
    destination: &crate::wallet::Address,
    asset: u32,
    nonce: u64,
) -> Vec<[u8; 32]> {
    vec![
        enc_string(chain),
        enc_string(amount),
        enc_bool(to_evm),
        enc_addr(destination),
        enc_u32(asset),
        enc_u64(nonce),
    ]
}

/// `CreateSubAccount` words. `explicit_index` flattens to presence + value.
pub(crate) fn create_sub_account_words(
    chain: &str,
    name: &str,
    has_explicit_index: bool,
    explicit_index: u32,
    shared_stp_group: bool,
    nonce: u64,
) -> Vec<[u8; 32]> {
    vec![
        enc_string(chain),
        enc_string(name),
        enc_bool(has_explicit_index),
        enc_u32(explicit_index),
        enc_bool(shared_stp_group),
        enc_u64(nonce),
    ]
}

/// `SubAccountTransfer` words. `amount` is the verbatim canonical decimal string.
pub(crate) fn sub_account_transfer_words(
    chain: &str,
    sub_index: u32,
    deposit: bool,
    amount: &str,
    nonce: u64,
) -> Vec<[u8; 32]> {
    vec![
        enc_string(chain),
        enc_u32(sub_index),
        enc_bool(deposit),
        enc_string(amount),
        enc_u64(nonce),
    ]
}

/// `SubAccountSpotTransfer` words. `amount` is the verbatim canonical decimal
/// string; `token` is a `uint32` spot-asset id.
pub(crate) fn sub_account_spot_transfer_words(
    chain: &str,
    sub_index: u32,
    token: u32,
    deposit: bool,
    amount: &str,
    nonce: u64,
) -> Vec<[u8; 32]> {
    vec![
        enc_string(chain),
        enc_u32(sub_index),
        enc_u32(token),
        enc_bool(deposit),
        enc_string(amount),
        enc_u64(nonce),
    ]
}

/// `CDeposit` / `CWithdraw` words — a single verbatim decimal `amount`.
pub(crate) fn staking_move_words(chain: &str, amount: &str, nonce: u64) -> Vec<[u8; 32]> {
    vec![enc_string(chain), enc_string(amount), enc_u64(nonce)]
}

/// `UserDexAbstraction` words.
pub(crate) fn user_dex_abstraction_words(chain: &str, enabled: bool, nonce: u64) -> Vec<[u8; 32]> {
    vec![enc_string(chain), enc_bool(enabled), enc_u64(nonce)]
}

/// `UserSetAbstraction` words. `value` is the verbatim canonical decimal string.
pub(crate) fn user_set_abstraction_words(
    chain: &str,
    kind: u8,
    value: &str,
    nonce: u64,
) -> Vec<[u8; 32]> {
    vec![
        enc_string(chain),
        enc_u8(kind),
        enc_string(value),
        enc_u64(nonce),
    ]
}

/// `PriorityBid` words.
pub(crate) fn priority_bid_words(
    chain: &str,
    asset: u32,
    bid_bps: u16,
    nonce: u64,
) -> Vec<[u8; 32]> {
    vec![
        enc_string(chain),
        enc_u32(asset),
        enc_u16(bid_bps),
        enc_u64(nonce),
    ]
}

/// `CancelAllOrders` words. The optional asset flattens to presence + value.
pub(crate) fn cancel_all_orders_words(
    chain: &str,
    has_asset: bool,
    asset: u32,
    nonce: u64,
) -> Vec<[u8; 32]> {
    vec![
        enc_string(chain),
        enc_bool(has_asset),
        enc_u32(asset),
        enc_u64(nonce),
    ]
}

/// `SubmitEncryptedOrder` words. `ciphertext` hashes as `bytes` (`keccak256(raw)`);
/// `commitment` is a `bytes32` carried verbatim into one word.
pub(crate) fn submit_encrypted_order_words(
    chain: &str,
    ciphertext: &[u8],
    commitment: &[u8; 32],
    threshold: u8,
    target_block: u64,
    reveal_deadline_ms: u64,
    nonce: u64,
) -> Vec<[u8; 32]> {
    vec![
        enc_string(chain),
        enc_bytes(ciphertext),
        *commitment,
        enc_u8(threshold),
        enc_u64(target_block),
        enc_u64(reveal_deadline_ms),
        enc_u64(nonce),
    ]
}
