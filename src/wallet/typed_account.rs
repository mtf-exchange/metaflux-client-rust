//! Account / sub-account / staking / abstraction / priority / encrypted EIP-712
//! typed-action support — the formerly-unsigned set.
//!
//! Split out of [`crate::wallet::typed`] to keep that file readable, mirroring
//! [`crate::wallet::typed_orders`]. These USER actions previously had no
//! structured signing form. Most are sender-authorized — the recovered signer is
//! the actor. `cancel_all_orders` and `rfq_quote` are not: each carries an
//! agent-resolved `owner` and selects a `*_WITH_OWNER` type string when it is
//! present. The variants + dispatch live in the unified
//! [`crate::wallet::TypedAction`] enum; the bulky frozen type strings and
//! `encodeData` word builders live here as free functions.
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

/// `CoreEvmTransferV2` — the payload-carrying form. Selected when the envelope
/// carries `data` or `destination_chain_id`; PRESENCE is the selector, so an
/// empty payload and a chain id of `0` both choose this string.
pub(crate) const CORE_EVM_TRANSFER_V2_TYPE: &[u8] =
    b"MetaFluxTransaction:CoreEvmTransferV2(string metafluxChain,string amount,bool toEvm,address destination,uint32 asset,uint32 destinationChainId,bytes data,uint64 nonce)";
/// `MetaFluxTransaction:SendToEvmWithData` // CONSENSUS-FROZEN. `transferNonce`
/// is the params-level per-transfer nonce; the trailing `nonce` is the envelope
/// nonce. Both are signed, and they may differ.
pub(crate) const SEND_TO_EVM_WITH_DATA_TYPE: &[u8] =
    b"MetaFluxTransaction:SendToEvmWithData(string metafluxChain,uint32 token,string amount,uint32 sourceDex,address destinationRecipient,bool toPerp,uint32 destinationChainId,bytes data,uint64 transferNonce,uint64 nonce)";
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
/// `MetaFluxTransaction:CancelAllOrders` with the agent-resolved params-level
/// `owner` bound (operator / vault trading) // CONSENSUS-FROZEN. `owner` sits
/// right after `metafluxChain`, mirroring the orders set's `*_WITH_OWNER` shapes;
/// used ONLY when the wire action carries an `owner` (absent →
/// [`CANCEL_ALL_ORDERS_TYPE`], byte-identical to today).
pub(crate) const CANCEL_ALL_ORDERS_WITH_OWNER_TYPE: &[u8] =
    b"MetaFluxTransaction:CancelAllOrders(string metafluxChain,address owner,bool hasAsset,uint32 asset,uint64 nonce)";
/// `MetaFluxTransaction:SubmitEncryptedOrder` // CONSENSUS-FROZEN. `ciphertext`
/// is EIP-712 `bytes` (hashed `keccak256(raw)`); `commitment` is `bytes32`.
pub(crate) const SUBMIT_ENCRYPTED_ORDER_TYPE: &[u8] =
    b"MetaFluxTransaction:SubmitEncryptedOrder(string metafluxChain,bytes ciphertext,bytes32 commitment,uint8 threshold,uint64 targetBlock,uint64 revealDeadlineMs,uint64 nonce)";
/// `MetaFluxTransaction:RfqRequest` // CONSENSUS-FROZEN. `side` is a `uint8`
/// (`0` = bid, `1` = ask); numeric fields are the raw `uint64` wire form (NOT
/// decimal-scaled). The optional `limitPx` / `stpGroup` each flatten to a
/// presence `bool` + value (`0` when absent).
pub(crate) const RFQ_REQUEST_TYPE: &[u8] =
    b"MetaFluxTransaction:RfqRequest(string metafluxChain,uint32 market,uint8 side,uint64 size,bool hasLimitPx,uint64 limitPx,uint64 expiryMs,bool hasStpGroup,uint64 stpGroup,uint64 nonce)";
/// `MetaFluxTransaction:RfqAccept` // CONSENSUS-FROZEN. Binds the parent `rfqId`,
/// the accepted `quoteIdx`, and the accepted `uint64` `size`.
pub(crate) const RFQ_ACCEPT_TYPE: &[u8] =
    b"MetaFluxTransaction:RfqAccept(string metafluxChain,uint64 rfqId,uint32 quoteIdx,uint64 size,uint64 nonce)";
/// `MetaFluxTransaction:RfqQuote` // CONSENSUS-FROZEN. Maker quote onto an open
/// RFQ session: `price` / `maxSize` are the raw `uint64` wire form
/// (digest-symmetric with `RfqRequest`, NOT decimal-scaled); the optional
/// `stpGroup` flattens to a presence `bool` + value (`0` when absent).
pub(crate) const RFQ_QUOTE_TYPE: &[u8] =
    b"MetaFluxTransaction:RfqQuote(string metafluxChain,uint64 rfqId,uint64 price,uint64 maxSize,uint64 validUntilMs,bool hasStpGroup,uint64 stpGroup,uint64 nonce)";
/// `MetaFluxTransaction:RfqQuote` with the params-level `owner` bound (an
/// approved agent quotes AS a vault) // CONSENSUS-FROZEN. `owner` sits right
/// after `metafluxChain`, mirroring the RFQ taker pair's `*_WITH_OWNER` shapes;
/// used ONLY when the wire action carries an `owner` (absent → [`RFQ_QUOTE_TYPE`]).
pub(crate) const RFQ_QUOTE_WITH_OWNER_TYPE: &[u8] =
    b"MetaFluxTransaction:RfqQuote(string metafluxChain,address owner,uint64 rfqId,uint64 price,uint64 maxSize,uint64 validUntilMs,bool hasStpGroup,uint64 stpGroup,uint64 nonce)";
/// `MetaFluxTransaction:FbaSubmit` // CONSENSUS-FROZEN. `side` is a `uint8`;
/// `size` / `price` are the raw `uint64` wire form; the optional `stpGroup`
/// flattens to a presence `bool` + value (`0` when absent).
pub(crate) const FBA_SUBMIT_TYPE: &[u8] =
    b"MetaFluxTransaction:FbaSubmit(string metafluxChain,uint32 market,uint8 side,uint64 size,uint64 price,bool hasStpGroup,uint64 stpGroup,uint64 nonce)";

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

/// `CoreEvmTransferV2` words. Field order copies the retired transfer-and-call
/// action: the chain id precedes the payload.
// One argument per signed field, in the frozen order. Collapsing them into a
// struct would hide the order the digest depends on.
#[allow(clippy::too_many_arguments)]
pub(crate) fn core_evm_transfer_v2_words(
    chain: &str,
    amount: &str,
    to_evm: bool,
    destination: &crate::wallet::Address,
    asset: u32,
    destination_chain_id: u32,
    data: &[u8],
    nonce: u64,
) -> Vec<[u8; 32]> {
    vec![
        enc_string(chain),
        enc_string(amount),
        enc_bool(to_evm),
        enc_addr(destination),
        enc_u32(asset),
        enc_u32(destination_chain_id),
        enc_bytes(data),
        enc_u64(nonce),
    ]
}

/// `SendToEvmWithData` words. `amount` is the verbatim canonical decimal string;
/// `data` hashes as `bytes`. The two nonces are separate signed fields, the
/// per-transfer one first.
// One argument per signed field, in the frozen order. Collapsing them into a
// struct would hide the order the digest depends on.
#[allow(clippy::too_many_arguments)]
pub(crate) fn send_to_evm_with_data_words(
    chain: &str,
    token: u32,
    amount: &str,
    source_dex: u32,
    destination_recipient: &crate::wallet::Address,
    to_perp: bool,
    destination_chain_id: u32,
    data: &[u8],
    transfer_nonce: u64,
    nonce: u64,
) -> Vec<[u8; 32]> {
    vec![
        enc_string(chain),
        enc_u32(token),
        enc_string(amount),
        enc_u32(source_dex),
        enc_addr(destination_recipient),
        enc_bool(to_perp),
        enc_u32(destination_chain_id),
        enc_bytes(data),
        enc_u64(transfer_nonce),
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

/// `CancelAllOrders` words with the agent-resolved `owner` bound, after
/// `metafluxChain` and before the asset-filter presence flag.
pub(crate) fn cancel_all_orders_words_with_owner(
    chain: &str,
    owner: &crate::wallet::Address,
    has_asset: bool,
    asset: u32,
    nonce: u64,
) -> Vec<[u8; 32]> {
    vec![
        enc_string(chain),
        enc_addr(owner),
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

/// `RfqRequest` words. `side` is a `uint8` (`0` = bid, `1` = ask); numeric fields
/// are the raw `uint64` wire form; the optionals flatten to presence + value.
#[allow(clippy::too_many_arguments)]
pub(crate) fn rfq_request_words(
    chain: &str,
    market: u32,
    side: u8,
    size: u64,
    has_limit_px: bool,
    limit_px: u64,
    expiry_ms: u64,
    has_stp_group: bool,
    stp_group: u64,
    nonce: u64,
) -> Vec<[u8; 32]> {
    vec![
        enc_string(chain),
        enc_u32(market),
        enc_u8(side),
        enc_u64(size),
        enc_bool(has_limit_px),
        enc_u64(limit_px),
        enc_u64(expiry_ms),
        enc_bool(has_stp_group),
        enc_u64(stp_group),
        enc_u64(nonce),
    ]
}

/// `RfqAccept` words — `rfqId` / `quoteIdx` / the accepted `uint64` `size`.
pub(crate) fn rfq_accept_words(
    chain: &str,
    rfq_id: u64,
    quote_idx: u32,
    size: u64,
    nonce: u64,
) -> Vec<[u8; 32]> {
    vec![
        enc_string(chain),
        enc_u64(rfq_id),
        enc_u32(quote_idx),
        enc_u64(size),
        enc_u64(nonce),
    ]
}

/// `RfqQuote` words. `price` / `maxSize` are the raw `uint64` wire form; the
/// optional STP group flattens to presence + value.
#[allow(clippy::too_many_arguments)]
pub(crate) fn rfq_quote_words(
    chain: &str,
    rfq_id: u64,
    price: u64,
    max_size: u64,
    valid_until_ms: u64,
    has_stp_group: bool,
    stp_group: u64,
    nonce: u64,
) -> Vec<[u8; 32]> {
    vec![
        enc_string(chain),
        enc_u64(rfq_id),
        enc_u64(price),
        enc_u64(max_size),
        enc_u64(valid_until_ms),
        enc_bool(has_stp_group),
        enc_u64(stp_group),
        enc_u64(nonce),
    ]
}

/// `RfqQuote` words with the params-level `owner` bound, after `metafluxChain`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn rfq_quote_words_with_owner(
    chain: &str,
    owner: &crate::wallet::Address,
    rfq_id: u64,
    price: u64,
    max_size: u64,
    valid_until_ms: u64,
    has_stp_group: bool,
    stp_group: u64,
    nonce: u64,
) -> Vec<[u8; 32]> {
    vec![
        enc_string(chain),
        enc_addr(owner),
        enc_u64(rfq_id),
        enc_u64(price),
        enc_u64(max_size),
        enc_u64(valid_until_ms),
        enc_bool(has_stp_group),
        enc_u64(stp_group),
        enc_u64(nonce),
    ]
}

/// `FbaSubmit` words. `side` is a `uint8`; `size` / `price` are the raw `uint64`
/// wire form; the optional STP group flattens to presence + value.
#[allow(clippy::too_many_arguments)]
pub(crate) fn fba_submit_words(
    chain: &str,
    market: u32,
    side: u8,
    size: u64,
    price: u64,
    has_stp_group: bool,
    stp_group: u64,
    nonce: u64,
) -> Vec<[u8; 32]> {
    vec![
        enc_string(chain),
        enc_u32(market),
        enc_u8(side),
        enc_u64(size),
        enc_u64(price),
        enc_bool(has_stp_group),
        enc_u64(stp_group),
        enc_u64(nonce),
    ]
}
