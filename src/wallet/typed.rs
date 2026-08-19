//! Structured EIP-712 typed-action signing.
//!
//! Each wallet-signed action here is a proper EIP-712 struct, so wallets that
//! render `eth_signTypedData_v4` show named fields instead of one opaque blob.
//! The primary type is `MetaFluxTransaction:<PascalAction>`.
//!
//! ## Atomic encoding
//!
//! - `hashStruct(s) = keccak256(typeHash ‖ encodeData(s))`, where
//!   `typeHash = keccak256(encodeType)`.
//! - Each field becomes one 32-byte word, concatenated in declared order:
//!   - `address` → 20 bytes right-aligned (12 zero-byte left pad).
//!   - `uintN` / `bool` → big-endian, zero-left-padded to 32 (`bool` = `uint8` `0`/`1`).
//!   - `string` → `keccak256(utf8)`; `T[]` → `keccak256(concat of element words)`.
//! - Final digest: `keccak256(0x19 0x01 ‖ domainSeparator ‖ hashStruct)`.
//!
//! ## Decimal fields
//!
//! Decimal magnitudes (`amount` / `ntl` / etc.) are EIP-712 `string`s carrying
//! the canonical decimal text (for example `"1500.5"`). The signer hashes the
//! exact UTF-8 bytes; the same string MUST then be sent verbatim in the POST
//! `action` JSON, since the server hashes the received string before parsing it.
//! Pick one canonical form — `"1.0"` and `"1.00"` hash differently.

use tiny_keccak::{Hasher, Keccak};

use crate::wallet::key::Address;
use crate::wallet::sign::Eip712;
use crate::wallet::typed_account as account;

/// EIP-712 chain tag (`metafluxChain`) for a domain chain id.
///
/// This is the first signed field of every typed action and must match the
/// node's mapping exactly: `8964` → `"Mainnet"`, `114514` → `"Testnet"`,
/// `31337` → `"Devnet"`; any other id falls back to `"Devnet"`.
#[must_use]
pub fn metaflux_chain_tag(chain_id: u64) -> &'static str {
    match chain_id {
        8964 => "Mainnet",
        114514 => "Testnet",
        31337 => "Devnet",
        _ => "Devnet",
    }
}

// ===== Encoder toolkit =====

pub(crate) fn keccak(input: &[u8]) -> [u8; 32] {
    let mut h = Keccak::v256();
    h.update(input);
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    out
}

/// `address` → 20 bytes right-aligned in a 32-byte word (12 zero-byte left pad).
pub(crate) fn enc_addr(a: &Address) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(a.as_bytes());
    out
}

/// `uint256(u64)` → big-endian, zero-left-padded to 32 bytes.
pub(crate) fn enc_u64(v: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&v.to_be_bytes());
    out
}

/// `uint256(u32)` → big-endian, zero-left-padded to 32 bytes.
pub(crate) fn enc_u32(v: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[28..].copy_from_slice(&v.to_be_bytes());
    out
}

/// `uint256(u16)` → big-endian, zero-left-padded to 32 bytes.
pub(crate) fn enc_u16(v: u16) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[30..].copy_from_slice(&v.to_be_bytes());
    out
}

/// `uint256(u8)` → big-endian, zero-left-padded to 32 bytes.
pub(crate) fn enc_u8(v: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[31] = v;
    out
}

/// `bool` → `uint8` `0`/`1`, zero-left-padded to 32 bytes.
pub(crate) fn enc_bool(v: bool) -> [u8; 32] {
    enc_u8(u8::from(v))
}

/// `string` → `keccak256(utf8)`. Decimal fields use the same hashing — the
/// caller hashes the verbatim canonical string and resends it unchanged.
pub(crate) fn enc_string(s: &str) -> [u8; 32] {
    keccak(s.as_bytes())
}

/// `bytes` → `keccak256(raw)`. Used for the encrypted-order ciphertext and the
/// multisig `innerActionBlob`.
pub(crate) fn enc_bytes(b: &[u8]) -> [u8; 32] {
    keccak(b)
}

/// `bytes[]` → `keccak256(concat(keccak256(eᵢ)))` — the EIP-712 dynamic-array
/// encoding where each element is itself `bytes`. Mirrors the node's
/// `enc_bytes_array`; used for the multisig `signatures` field.
fn enc_bytes_array(items: &[Vec<u8>]) -> [u8; 32] {
    let mut k = Keccak::v256();
    for b in items {
        k.update(&enc_bytes(b));
    }
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out
}

/// `address[]` → `keccak256(concat(enc_addr(eᵢ)))`.
fn enc_addr_array(addrs: &[Address]) -> [u8; 32] {
    let mut k = Keccak::v256();
    for a in addrs {
        k.update(&enc_addr(a));
    }
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out
}

/// `string[]` → `keccak256(concat(keccak256(eᵢ)))` — the same dynamic-array rule
/// as [`enc_bytes_array`], over elements hashed as `string`. Decimal elements are
/// hashed verbatim, so `"1.0"` and `"1.00"` are different array digests.
fn enc_string_array(items: &[String]) -> [u8; 32] {
    let mut k = Keccak::v256();
    for s in items {
        k.update(&enc_string(s));
    }
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out
}

// ===== Type strings (signing order = encodeType order = message field order) =====

const SEND_ASSET_TYPE: &[u8] =
    b"MetaFluxTransaction:SendAsset(string metafluxChain,uint32 sourceDex,uint32 destinationDex,uint32 asset,address destination,string amount,bool toPerp,uint64 nonce)";
const USD_CLASS_TRANSFER_TYPE: &[u8] =
    b"MetaFluxTransaction:UsdClassTransfer(string metafluxChain,string ntl,bool toPerp,uint64 nonce)";
const WITHDRAW_TYPE: &[u8] =
    b"MetaFluxTransaction:Withdraw(string metafluxChain,uint32 asset,string amount,uint32 destinationChainId,bool useCctp,uint64 nonce)";
const APPROVE_AGENT_TYPE: &[u8] =
    b"MetaFluxTransaction:ApproveAgent(string metafluxChain,address agentAddress,string agentName,uint64 expiresAtMs,uint64 nonce)";
const SET_REFERRER_TYPE: &[u8] =
    b"MetaFluxTransaction:SetReferrer(string metafluxChain,address referrer,uint64 nonce)";
const APPROVE_BUILDER_FEE_TYPE: &[u8] =
    b"MetaFluxTransaction:ApproveBuilderFee(string metafluxChain,address builder,uint16 maxFeeBps,uint64 nonce)";
const SET_DISPLAY_NAME_TYPE: &[u8] =
    b"MetaFluxTransaction:SetDisplayName(string metafluxChain,string displayName,uint64 nonce)";
const SET_POSITION_MODE_TYPE: &[u8] =
    b"MetaFluxTransaction:SetPositionMode(string metafluxChain,bool hedge,uint64 nonce)";
const USER_PORTFOLIO_MARGIN_TYPE: &[u8] =
    b"MetaFluxTransaction:UserPortfolioMargin(string metafluxChain,bool enroll,uint64 nonce)";
const CONVERT_TO_MULTI_SIG_USER_TYPE: &[u8] =
    b"MetaFluxTransaction:ConvertToMultiSigUser(string metafluxChain,address[] signers,uint32 threshold,uint64 nonce)";
const MULTI_SIG_TYPE: &[u8] =
    b"MetaFluxTransaction:MultiSig(string metafluxChain,address user,bytes innerActionBlob,bytes[] signatures,uint64 nonce)";
const UPDATE_LEVERAGE_TYPE: &[u8] =
    b"MetaFluxTransaction:UpdateLeverage(string metafluxChain,uint32 asset,uint32 leverage,bool isIsolated,uint64 nonce)";
const CLAIM_REWARDS_TYPE: &[u8] =
    b"MetaFluxTransaction:ClaimRewards(string metafluxChain,address validator,uint64 nonce)";
const LINK_STAKING_USER_TYPE: &[u8] =
    b"MetaFluxTransaction:LinkStakingUser(string metafluxChain,address target,uint64 nonce)";
const CREATE_VAULT_TYPE: &[u8] =
    b"MetaFluxTransaction:CreateVault(string metafluxChain,string name,uint64 lockPeriodSecs,uint8 kind,uint64 nonce)";
const VAULT_MODIFY_TYPE: &[u8] =
    b"MetaFluxTransaction:VaultModify(string metafluxChain,uint64 vaultId,string newName,uint64 nonce)";
const SPOT_MARGIN_CLOSE_TYPE: &[u8] =
    b"MetaFluxTransaction:SpotMarginClose(string metafluxChain,uint32 pair,uint64 limitPx,uint64 nonce)";
const UPDATE_ISOLATED_MARGIN_TYPE: &[u8] =
    b"MetaFluxTransaction:UpdateIsolatedMargin(string metafluxChain,uint32 asset,string delta,uint64 nonce)";
const TOP_UP_ISOLATED_ONLY_MARGIN_TYPE: &[u8] =
    b"MetaFluxTransaction:TopUpIsolatedOnlyMargin(string metafluxChain,uint32 asset,string amount,uint64 nonce)";
const TOKEN_DELEGATE_TYPE: &[u8] =
    b"MetaFluxTransaction:TokenDelegate(string metafluxChain,address validator,string amount,bool isUndelegate,uint8 lockMonths,uint64 nonce)";
const VAULT_TRANSFER_TYPE: &[u8] =
    b"MetaFluxTransaction:VaultTransfer(string metafluxChain,uint64 vaultId,bool deposit,string amount,uint64 nonce)";
const VAULT_WITHDRAW_TYPE: &[u8] =
    b"MetaFluxTransaction:VaultWithdraw(string metafluxChain,uint64 vaultId,string shares,uint64 nonce)";
const SPOT_MARGIN_DEPOSIT_TYPE: &[u8] =
    b"MetaFluxTransaction:SpotMarginDeposit(string metafluxChain,uint32 pair,string amount,uint64 nonce)";
const SPOT_MARGIN_WITHDRAW_TYPE: &[u8] =
    b"MetaFluxTransaction:SpotMarginWithdraw(string metafluxChain,uint32 pair,string amount,uint64 nonce)";
const SPOT_MARGIN_OPEN_TYPE: &[u8] =
    b"MetaFluxTransaction:SpotMarginOpen(string metafluxChain,uint32 pair,uint64 size,uint64 limitPx,string borrow,uint64 nonce)";
const EARN_DEPOSIT_TYPE: &[u8] =
    b"MetaFluxTransaction:EarnDeposit(string metafluxChain,uint32 asset,string amount,uint64 nonce)";
const EARN_WITHDRAW_TYPE: &[u8] =
    b"MetaFluxTransaction:EarnWithdraw(string metafluxChain,uint32 asset,string shares,uint64 nonce)";
const AGENT_SET_ABSTRACTION_TYPE: &[u8] =
    b"MetaFluxTransaction:AgentSetAbstraction(string metafluxChain,address user,uint8 kind,string value,uint64 nonce)";
const MB_WITHDRAW_TYPE: &[u8] =
    b"MetaFluxTransaction:MbWithdraw(string metafluxChain,uint8 chain,uint32 asset,uint64 amount,string dstAddr,uint64 nonce)";
const VAULT_DISTRIBUTE_TYPE: &[u8] =
    b"MetaFluxTransaction:VaultDistribute(string metafluxChain,uint64 vaultId,string pnl,uint64 nonce)";
const CLAIM_BUILDER_REWARDS_TYPE: &[u8] =
    b"MetaFluxTransaction:ClaimBuilderRewards(string metafluxChain,uint64 nonce)";
const CLAIM_REFERRAL_REWARDS_TYPE: &[u8] =
    b"MetaFluxTransaction:ClaimReferralRewards(string metafluxChain,uint64 nonce)";
const BORROW_LEND_TYPE: &[u8] =
    b"MetaFluxTransaction:BorrowLend(string metafluxChain,uint8 kind,string amount,uint64 nonce)";
const REGISTER_METALIQUIDITY_OPERATOR_TYPE: &[u8] =
    b"MetaFluxTransaction:RegisterMetaliquidityOperator(string metafluxChain,uint64 vaultId,address operator,bool allowed,uint64 expiresAtMs,uint64 nonce)";

// The six spot-deployer signing strings. Each sub-action is its own frozen
// string: `spot_deploy` is a node-internal handler name that no caller sends.
// `maxDeployFee` is a whole-USDC Dutch accept price, NOT gas.
const SPOT_REGISTER_TOKEN_TYPE: &[u8] =
    b"MetaFluxTransaction:SpotRegisterToken(string metafluxChain,string symbol,uint8 szDecimals,uint8 weiDecimals,string maxDeployFee,uint64 nonce)";
const SPOT_REGISTER_PAIR_TYPE: &[u8] =
    b"MetaFluxTransaction:SpotRegisterPair(string metafluxChain,uint32 base,uint32 quote,string name,string maxDeployFee,uint64 nonce)";
const SPOT_SET_PAIR_PARAMS_TYPE: &[u8] =
    b"MetaFluxTransaction:SpotSetPairParams(string metafluxChain,uint32 pair,uint32 takerFeeDbps,uint32 makerFeeDbps,uint64 minNotionalCents,uint64 nonce)";
const SPOT_SET_PAIR_ACTIVE_TYPE: &[u8] =
    b"MetaFluxTransaction:SpotSetPairActive(string metafluxChain,uint32 pair,bool active,uint64 nonce)";
const SPOT_SEED_HOLDERS_TYPE: &[u8] =
    b"MetaFluxTransaction:SpotSeedHolders(string metafluxChain,uint32 asset,address[] holders,string[] amounts,uint64 nonce)";
const SPOT_FINALIZE_SUPPLY_TYPE: &[u8] =
    b"MetaFluxTransaction:SpotFinalizeSupply(string metafluxChain,uint32 asset,string maxSupply,uint64 nonce)";

// The nine MIP-3 perp-deployer signing strings, one per sub-action. Each binds
// ONLY the fields its own sub-handler reads. None carries `bid`: the legacy
// gas-auction lane is dead and the node rejects a non-zero bid.
const PERP_REGISTER_ASSET_TYPE: &[u8] =
    b"MetaFluxTransaction:PerpRegisterAsset(string metafluxChain,string symbol,uint8 decimals,uint64 nonce)";
const PERP_SET_ORACLE_TYPE: &[u8] =
    b"MetaFluxTransaction:PerpSetOracle(string metafluxChain,uint32 asset,uint16 oracleSourceMask,uint64 nonce)";
const PERP_SET_LEVERAGE_TYPE: &[u8] =
    b"MetaFluxTransaction:PerpSetLeverage(string metafluxChain,uint32 asset,uint8 maxLeverage,uint64 nonce)";
const PERP_SET_FEE_TIER_TYPE: &[u8] =
    b"MetaFluxTransaction:PerpSetFeeTier(string metafluxChain,uint32 asset,uint32 takerFeeDbps,uint32 makerFeeDbps,uint32 deployerFeeBps,uint64 nonce)";
const PERP_SET_MAKER_REBATE_TYPE: &[u8] =
    b"MetaFluxTransaction:PerpSetMakerRebate(string metafluxChain,uint32 asset,uint16 rebateBps,uint64 nonce)";
const PERP_SET_MIN_SIZE_TYPE: &[u8] =
    b"MetaFluxTransaction:PerpSetMinSize(string metafluxChain,uint32 asset,uint64 minOrderSize,uint64 nonce)";
const PERP_ACTIVATE_MARKET_TYPE: &[u8] =
    b"MetaFluxTransaction:PerpActivateMarket(string metafluxChain,uint32 asset,uint64 nonce)";
const PERP_DEACTIVATE_MARKET_TYPE: &[u8] =
    b"MetaFluxTransaction:PerpDeactivateMarket(string metafluxChain,uint32 asset,uint64 nonce)";
const PERP_SET_SUB_DEPLOYERS_TYPE: &[u8] =
    b"MetaFluxTransaction:PerpSetSubDeployers(string metafluxChain,uint32 asset,address subDeployer,bool add,uint64 nonce)";

// ===== TypedAction =====

/// One wallet-signed action per variant, carrying exactly its EIP-712 fields in
/// declared (= `encodeType` = message) order.
///
/// These are the actions the node accepts under the typed signing scheme.
/// Decimal magnitudes are `String` and hashed verbatim — set them to the
/// canonical text you intend to send on the wire.
///
/// The leading `metaflux_chain` tag is filled in for you when you build a
/// variant through [`crate::rest::exchange::Exchange`]; if you construct one
/// directly, use [`metaflux_chain_tag`] for the target chain id.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TypedAction {
    /// `SendAsset(string metafluxChain,uint32 sourceDex,uint32 destinationDex,uint32 asset,address destination,string amount,bool toPerp,uint64 nonce)`
    SendAsset {
        /// Chain tag (`"Mainnet"` / `"Testnet"` / `"Devnet"`).
        metaflux_chain: String,
        /// Source dex id.
        source_dex: u32,
        /// Destination dex id.
        destination_dex: u32,
        /// Asset id.
        asset: u32,
        /// Recipient address.
        destination: Address,
        /// Amount as a canonical decimal string.
        amount: String,
        /// Move to the perp side.
        to_perp: bool,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `UsdClassTransfer(string metafluxChain,string ntl,bool toPerp,uint64 nonce)`
    UsdClassTransfer {
        /// Chain tag.
        metaflux_chain: String,
        /// Notional as a canonical decimal string.
        ntl: String,
        /// Move to the perp side.
        to_perp: bool,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `Withdraw(string metafluxChain,uint32 asset,string amount,uint32 destinationChainId,bool useCctp,uint64 nonce)`
    Withdraw {
        /// Chain tag.
        metaflux_chain: String,
        /// Asset id.
        asset: u32,
        /// Amount as a canonical decimal string.
        amount: String,
        /// Destination EVM chain id.
        destination_chain_id: u32,
        /// Route via CCTP.
        use_cctp: bool,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `ApproveAgent(string metafluxChain,address agentAddress,string agentName,uint64 expiresAtMs,uint64 nonce)`
    ApproveAgent {
        /// Chain tag.
        metaflux_chain: String,
        /// Agent address being approved.
        agent_address: Address,
        /// Human-readable agent name.
        agent_name: String,
        /// Approval expiry (ms since epoch). `0` = never expires.
        expires_at_ms: u64,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `SetReferrer(string metafluxChain,address referrer,uint64 nonce)`
    SetReferrer {
        /// Chain tag.
        metaflux_chain: String,
        /// Referrer address.
        referrer: Address,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `ApproveBuilderFee(string metafluxChain,address builder,uint16 maxFeeBps,uint64 nonce)`
    ApproveBuilderFee {
        /// Chain tag.
        metaflux_chain: String,
        /// Builder address.
        builder: Address,
        /// Max builder fee in basis points.
        max_fee_bps: u16,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `SetDisplayName(string metafluxChain,string displayName,uint64 nonce)`
    SetDisplayName {
        /// Chain tag.
        metaflux_chain: String,
        /// Display name.
        display_name: String,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `SetPositionMode(string metafluxChain,bool hedge,uint64 nonce)`
    SetPositionMode {
        /// Chain tag.
        metaflux_chain: String,
        /// Hedge mode enabled.
        hedge: bool,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `UserPortfolioMargin(string metafluxChain,bool enroll,uint64 nonce)`
    UserPortfolioMargin {
        /// Chain tag.
        metaflux_chain: String,
        /// Enroll in portfolio margin.
        enroll: bool,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `ConvertToMultiSigUser(string metafluxChain,address[] signers,uint32 threshold,uint64 nonce)`
    ConvertToMultiSigUser {
        /// Chain tag.
        metaflux_chain: String,
        /// Authorized signer set.
        signers: Vec<Address>,
        /// Required signatures.
        threshold: u32,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `MultiSig(string metafluxChain,address user,bytes innerActionBlob,bytes[] signatures,uint64 nonce)`
    ///
    /// The outer envelope of a multisig-acting bundle. It carries no authority of
    /// its own — the acting authority is the roster signer set recovered from the
    /// inner blob (see [`crate::wallet::multisig`]), so this envelope may be POSTed
    /// by any account. `inner_action_blob` is the exact canonical `Action` JSON
    /// bytes the roster signed (hashed as EIP-712 `bytes`); each element of
    /// `signatures` is a 65-byte `r‖s‖v` roster signature (hashed as `bytes`). The
    /// envelope `nonce` MUST equal the inner nonce the roster signed — it advances
    /// against `user`'s window, not the POSTing account's.
    MultiSig {
        /// Chain tag.
        metaflux_chain: String,
        /// The acting multisig account (`MultiSigParams::user`) — the account the
        /// bundle acts as, NOT a roster member.
        user: Address,
        /// Exact canonical `Action` JSON bytes the roster signed (hashed as
        /// `bytes`; never re-serialized).
        inner_action_blob: Vec<u8>,
        /// Roster signatures, each a 65-byte `r‖s‖v` blob (hashed as `bytes`).
        signatures: Vec<Vec<u8>>,
        /// Envelope nonce — equals the inner nonce the roster signed.
        nonce: u64,
    },
    /// `UpdateLeverage(string metafluxChain,uint32 asset,uint32 leverage,bool isIsolated,uint64 nonce)`
    UpdateLeverage {
        /// Chain tag.
        metaflux_chain: String,
        /// Asset id.
        asset: u32,
        /// Leverage multiplier.
        leverage: u32,
        /// Isolated (vs cross) margin.
        is_isolated: bool,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `ClaimRewards(string metafluxChain,address validator,uint64 nonce)`. The
    /// zero address means "claim all".
    ClaimRewards {
        /// Chain tag.
        metaflux_chain: String,
        /// Validator address, or [`Address::ZERO`] to claim everything.
        validator: Address,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `LinkStakingUser(string metafluxChain,address target,uint64 nonce)`
    LinkStakingUser {
        /// Chain tag.
        metaflux_chain: String,
        /// Linked staking target address.
        target: Address,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `CreateVault(string metafluxChain,string name,uint64 lockPeriodSecs,uint8 kind,uint64 nonce)`
    CreateVault {
        /// Chain tag.
        metaflux_chain: String,
        /// Vault name.
        name: String,
        /// Lock period in seconds.
        lock_period_secs: u64,
        /// Vault kind (`0` = user, `1` = metaliquidity).
        kind: u8,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `VaultModify(string metafluxChain,uint64 vaultId,string newName,uint64 nonce)`
    VaultModify {
        /// Chain tag.
        metaflux_chain: String,
        /// Vault id.
        vault_id: u64,
        /// New vault name.
        new_name: String,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `SpotMarginClose(string metafluxChain,uint32 pair,uint64 limitPx,uint64 nonce)`
    SpotMarginClose {
        /// Chain tag.
        metaflux_chain: String,
        /// Spot margin pair id.
        pair: u32,
        /// Limit price on the 1e8 plane.
        limit_px: u64,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `UpdateIsolatedMargin(string metafluxChain,uint32 asset,string delta,uint64 nonce)`
    UpdateIsolatedMargin {
        /// Chain tag.
        metaflux_chain: String,
        /// Asset id.
        asset: u32,
        /// Signed margin delta as a canonical decimal string (e.g. `"-100.5"`).
        delta: String,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `TopUpIsolatedOnlyMargin(string metafluxChain,uint32 asset,string amount,uint64 nonce)`
    TopUpIsolatedOnlyMargin {
        /// Chain tag.
        metaflux_chain: String,
        /// Asset id.
        asset: u32,
        /// Top-up amount as a canonical decimal string.
        amount: String,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `TokenDelegate(string metafluxChain,address validator,string amount,bool isUndelegate,uint8 lockMonths,uint64 nonce)`
    TokenDelegate {
        /// Chain tag.
        metaflux_chain: String,
        /// Validator address.
        validator: Address,
        /// Stake amount as a canonical decimal string.
        amount: String,
        /// Undelegate (vs delegate).
        is_undelegate: bool,
        /// Lock tier in months — one of `0` (flexible), `1`, `6`, `24`. Ignored
        /// on undelegate.
        lock_months: u8,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `VaultTransfer(string metafluxChain,uint64 vaultId,bool deposit,string amount,uint64 nonce)`
    VaultTransfer {
        /// Chain tag.
        metaflux_chain: String,
        /// Vault id.
        vault_id: u64,
        /// Deposit (vs withdraw).
        deposit: bool,
        /// Amount as a canonical decimal string.
        amount: String,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `VaultWithdraw(string metafluxChain,uint64 vaultId,string shares,uint64 nonce)`
    VaultWithdraw {
        /// Chain tag.
        metaflux_chain: String,
        /// Vault id.
        vault_id: u64,
        /// Share count as a canonical decimal string.
        shares: String,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `VaultDistribute(string metafluxChain,uint64 vaultId,string pnl,uint64 nonce)`
    ///
    /// Follower deposit into a vault (mints shares at the current NAV). The
    /// deposit amount rides the `pnl` field (a legacy name on the node) as a
    /// positive canonical decimal string, hashed VERBATIM.
    VaultDistribute {
        /// Chain tag.
        metaflux_chain: String,
        /// Vault id.
        vault_id: u64,
        /// Deposit amount as a canonical decimal string (node field name `pnl`).
        pnl: String,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `ClaimBuilderRewards(string metafluxChain,uint64 nonce)`
    ///
    /// Drain the sender's accrued builder-code fee credit. No params.
    ClaimBuilderRewards {
        /// Chain tag.
        metaflux_chain: String,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `ClaimReferralRewards(string metafluxChain,uint64 nonce)`
    ///
    /// Drain the sender's accrued referrer fee credit. No params.
    ClaimReferralRewards {
        /// Chain tag.
        metaflux_chain: String,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `SpotMarginDeposit(string metafluxChain,uint32 pair,string amount,uint64 nonce)`
    SpotMarginDeposit {
        /// Chain tag.
        metaflux_chain: String,
        /// Spot margin pair id.
        pair: u32,
        /// Amount as a canonical decimal string.
        amount: String,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `SpotMarginWithdraw(string metafluxChain,uint32 pair,string amount,uint64 nonce)`
    SpotMarginWithdraw {
        /// Chain tag.
        metaflux_chain: String,
        /// Spot margin pair id.
        pair: u32,
        /// Amount as a canonical decimal string.
        amount: String,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `SpotMarginOpen(string metafluxChain,uint32 pair,uint64 size,uint64 limitPx,string borrow,uint64 nonce)`
    SpotMarginOpen {
        /// Chain tag.
        metaflux_chain: String,
        /// Spot margin pair id.
        pair: u32,
        /// Order size on the 1e8 plane.
        size: u64,
        /// Limit price on the 1e8 plane.
        limit_px: u64,
        /// Borrow amount as a canonical decimal string.
        borrow: String,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `EarnDeposit(string metafluxChain,uint32 asset,string amount,uint64 nonce)`
    EarnDeposit {
        /// Chain tag.
        metaflux_chain: String,
        /// Asset id.
        asset: u32,
        /// Deposit amount as a canonical decimal string.
        amount: String,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `EarnWithdraw(string metafluxChain,uint32 asset,string shares,uint64 nonce)`
    EarnWithdraw {
        /// Chain tag.
        metaflux_chain: String,
        /// Asset id.
        asset: u32,
        /// Share count as a canonical decimal string.
        shares: String,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `AgentSetAbstraction(string metafluxChain,address user,uint8 kind,string value,uint64 nonce)`
    AgentSetAbstraction {
        /// Chain tag.
        metaflux_chain: String,
        /// User address the abstraction applies to.
        user: Address,
        /// Abstraction kind discriminant.
        kind: u8,
        /// Abstraction value, hashed verbatim as an EIP-712 string.
        value: String,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `MbWithdraw(string metafluxChain,uint8 chain,uint32 asset,uint64 amount,string dstAddr,uint64 nonce)`
    ///
    /// The signed `chain` is the mapped `uint8` (`1` = Base, `2` = Arbitrum);
    /// the POST `params.chain` carries the string name.
    MbWithdraw {
        /// Chain tag.
        metaflux_chain: String,
        /// Destination chain discriminant (`1` = Base, `2` = Arbitrum).
        chain: u8,
        /// Asset id.
        asset: u32,
        /// Integer amount (not a decimal string).
        amount: u64,
        /// Destination address string for the target chain.
        dst_addr: String,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `CoreEvmTransfer(string metafluxChain,string amount,bool toEvm,address destination,uint32 asset,uint64 nonce)`
    CoreEvmTransfer {
        /// Chain tag.
        metaflux_chain: String,
        /// Amount as a canonical decimal string (whole-token plane).
        amount: String,
        /// Direction: `true` = Core → MetaFluxEVM.
        to_evm: bool,
        /// MetaFluxEVM-side recipient address.
        destination: Address,
        /// MTF asset id to move (0 = USDC). Signed so a relay cannot redirect the
        /// transfer to a different spot token.
        asset: u32,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `CoreEvmTransferV2(string metafluxChain,string amount,bool toEvm,address destination,uint32 asset,uint32 destinationChainId,bytes data,uint64 nonce)`
    ///
    /// The payload-carrying form. Build this ONLY when the envelope carries
    /// `data` or `destination_chain_id` — presence is the selector, so an empty
    /// payload and a chain id of `0` both belong here. An envelope with neither
    /// key uses [`TypedAction::CoreEvmTransfer`] and digests byte-identically to
    /// one built before those fields existed.
    CoreEvmTransferV2 {
        /// Chain tag.
        metaflux_chain: String,
        /// Amount as a canonical decimal string (whole-token plane).
        amount: String,
        /// Direction: `true` = Core → MetaFluxEVM.
        to_evm: bool,
        /// MetaFluxEVM-side recipient, and the target of `data`.
        destination: Address,
        /// MTF asset id to move (0 = USDC).
        asset: u32,
        /// Delivery chain. `0` or the local EVM chain id; anything else is
        /// rejected on arrival.
        destination_chain_id: u32,
        /// EVM calldata run against `destination` after the credit.
        data: Vec<u8>,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `SendToEvmWithData(string metafluxChain,uint32 token,string amount,uint32 sourceDex,address destinationRecipient,bool toPerp,uint32 destinationChainId,bytes data,uint64 transferNonce,uint64 nonce)`
    ///
    /// Moves a spot token to MetaFluxEVM and runs a payload against the
    /// recipient. Every field is signed, including the three the chain refuses to
    /// honour with any value but one — see
    /// [`crate::types::core_evm::SendToEvmWithData`] for the rule on each.
    SendToEvmWithData {
        /// Chain tag.
        metaflux_chain: String,
        /// Spot token id to move.
        token: u32,
        /// Amount as a canonical decimal string (whole-token plane).
        amount: String,
        /// Source book. Signed, and accepted only as `0`.
        source_dex: u32,
        /// MetaFluxEVM-side recipient, and the target of `data`.
        destination_recipient: Address,
        /// Credit a perp account. Signed, and accepted only as `false`.
        to_perp: bool,
        /// Delivery chain. Signed, and accepted only as `0` or the local EVM
        /// chain id.
        destination_chain_id: u32,
        /// EVM payload run against the recipient after the credit.
        data: Vec<u8>,
        /// Per-transfer nonce — the params-level `nonce`, signed as
        /// `transferNonce`. Distinct from the envelope nonce below.
        transfer_nonce: u64,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `CreateSubAccount(string metafluxChain,string name,bool hasExplicitIndex,uint32 explicitIndex,bool sharedStpGroup,uint64 nonce)`
    ///
    /// The optional explicit index flattens to a presence `bool` + value (`0`
    /// when absent).
    CreateSubAccount {
        /// Chain tag.
        metaflux_chain: String,
        /// Human-readable sub-account name.
        name: String,
        /// Explicit-index presence flag.
        has_explicit_index: bool,
        /// Explicit sub-account index (`0` when absent).
        explicit_index: u32,
        /// Share the parent's STP group.
        shared_stp_group: bool,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `SubAccountTransfer(string metafluxChain,uint32 subIndex,bool deposit,string amount,uint64 nonce)`
    SubAccountTransfer {
        /// Chain tag.
        metaflux_chain: String,
        /// Sub-account index (relative to the sender).
        sub_index: u32,
        /// Direction (`true` = parent → sub).
        deposit: bool,
        /// Amount as a canonical decimal string.
        amount: String,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `SubAccountSpotTransfer(string metafluxChain,uint32 subIndex,uint32 token,bool deposit,string amount,uint64 nonce)`
    SubAccountSpotTransfer {
        /// Chain tag.
        metaflux_chain: String,
        /// Sub-account index.
        sub_index: u32,
        /// Token (spot asset) id.
        token: u32,
        /// Direction (`true` = parent → sub).
        deposit: bool,
        /// Amount as a canonical decimal string.
        amount: String,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `CDeposit(string metafluxChain,string amount,uint64 nonce)` — spot MTF → free staking pool.
    CDeposit {
        /// Chain tag.
        metaflux_chain: String,
        /// Amount of MTF to move, as a canonical decimal string.
        amount: String,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `CWithdraw(string metafluxChain,string amount,uint64 nonce)` — free staking pool → spot MTF.
    CWithdraw {
        /// Chain tag.
        metaflux_chain: String,
        /// Amount of MTF to move, as a canonical decimal string.
        amount: String,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `UserSetAbstraction(string metafluxChain,uint8 kind,string value,uint64 nonce)`
    UserSetAbstraction {
        /// Chain tag.
        metaflux_chain: String,
        /// Sub-type tag.
        kind: u8,
        /// Setting value, hashed verbatim as a canonical decimal string.
        value: String,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `PriorityBid(string metafluxChain,uint32 asset,uint16 bidBps,uint64 nonce)`
    PriorityBid {
        /// Chain tag.
        metaflux_chain: String,
        /// Asset this bid is bound to.
        asset: u32,
        /// Bid in basis points.
        bid_bps: u16,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `CancelAllOrders(string metafluxChain,bool hasAsset,uint32 asset,uint64 nonce)`,
    /// or its `*_WITH_OWNER` shape (`address owner` right after `metafluxChain`)
    /// when an agent-resolved `owner` is bound.
    ///
    /// The optional asset filter flattens to a presence `bool` + value (`0` when
    /// "all assets").
    CancelAllOrders {
        /// Chain tag.
        metaflux_chain: String,
        /// Agent-resolved params-level `owner` for operator / vault trading.
        /// `None` signs the owner-less digest (byte-identical to today); `Some`
        /// binds the `owner` right after `metafluxChain`, selecting the
        /// `*_WITH_OWNER` type string.
        owner: Option<Address>,
        /// Asset-filter presence flag.
        has_asset: bool,
        /// Asset filter (`0` when "all assets").
        asset: u32,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `SubmitEncryptedOrder(string metafluxChain,bytes ciphertext,bytes32 commitment,uint8 threshold,uint64 targetBlock,uint64 revealDeadlineMs,uint64 nonce)`
    ///
    /// `ciphertext` hashes as EIP-712 `bytes` (`keccak256(raw)`); `commitment`
    /// is a `bytes32` carried verbatim into one word.
    SubmitEncryptedOrder {
        /// Chain tag.
        metaflux_chain: String,
        /// Encrypted order ciphertext (hashed as `bytes`).
        ciphertext: Vec<u8>,
        /// `keccak(plaintext‖salt)` commitment (`bytes32`).
        commitment: [u8; 32],
        /// Threshold shares to reveal.
        threshold: u8,
        /// Block height at/after which decryption may proceed.
        target_block: u64,
        /// Consensus-time (ms) reveal deadline.
        reveal_deadline_ms: u64,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `RfqRequest(string metafluxChain,uint32 market,uint8 side,uint64 size,bool hasLimitPx,uint64 limitPx,uint64 expiryMs,bool hasStpGroup,uint64 stpGroup,uint64 nonce)`
    ///
    /// RFQ taker request. `side` is a `uint8` (`0` = bid, `1` = ask); numeric
    /// fields are the raw `uint64` wire form (fixed-point lots / price, NOT
    /// decimal-scaled). The optional `limit_px` / `stp_group` each flatten to a
    /// presence `bool` + value (`0` when absent).
    ///
    /// The node also accepts an agent-resolved `owner` here, with its own
    /// `*_WITH_OWNER` type string. This variant signs the owner-less form, so
    /// the signer is the taker.
    RfqRequest {
        /// Chain tag.
        metaflux_chain: String,
        /// Market to request a quote on.
        market: u32,
        /// Taker side (`0` = bid, `1` = ask).
        side: u8,
        /// Requested size (the `u64` wire form).
        size: u64,
        /// Whether a taker limit price is present.
        has_limit_px: bool,
        /// Taker limit price (`0` when absent; the `u64` wire form).
        limit_px: u64,
        /// Server-clock expiry (ms; `0` = handler default window).
        expiry_ms: u64,
        /// Whether an STP group is present.
        has_stp_group: bool,
        /// STP group id (`0` when absent).
        stp_group: u64,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `RfqAccept(string metafluxChain,uint64 rfqId,uint32 quoteIdx,uint64 size,uint64 nonce)`
    ///
    /// Accept of a specific resting RFQ quote. Like [`Self::RfqRequest`] the
    /// node offers an owner-bound form; this variant signs the owner-less one.
    RfqAccept {
        /// Chain tag.
        metaflux_chain: String,
        /// Parent RFQ session id.
        rfq_id: u64,
        /// Index of the accepted quote in the session's quote vector.
        quote_idx: u32,
        /// Accepted size (the `u64` wire form).
        size: u64,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `RfqQuote(string metafluxChain,uint64 rfqId,uint64 price,uint64 maxSize,uint64 validUntilMs,bool hasStpGroup,uint64 stpGroup,uint64 nonce)`
    /// (owner-less) or the `*_WITH_OWNER` shape when an approved agent quotes AS a
    /// vault — the owner binds the `entry.maker` identity, so it IS signed.
    ///
    /// Maker quote onto an open RFQ session. `price` / `max_size` are the raw
    /// `uint64` wire form (the order path's convention, NOT decimal-scaled); the
    /// optional `stp_group` flattens to a presence `bool` + value (`0` when absent).
    RfqQuote {
        /// Chain tag.
        metaflux_chain: String,
        /// Params-level owner the agent quotes for. `None` = self / legacy →
        /// owner-less digest. `Some` binds the maker identity into the digest.
        owner: Option<Address>,
        /// Parent RFQ session id.
        rfq_id: u64,
        /// Maker's quoted price (the `u64` 1e8-plane wire form).
        price: u64,
        /// Maximum size the maker will fill (the `u64` wire form).
        max_size: u64,
        /// Quote's own expiry (ms; `<= request.expiry_ms`).
        valid_until_ms: u64,
        /// Whether an STP group is present.
        has_stp_group: bool,
        /// STP group id (`0` when absent).
        stp_group: u64,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `FbaSubmit(string metafluxChain,uint32 market,uint8 side,uint64 size,uint64 price,bool hasStpGroup,uint64 stpGroup,uint64 nonce)`
    ///
    /// Submit into a market's frequent-batch-auction pool. `side` is a `uint8`;
    /// `size` / `price` are the raw `uint64` wire form; the optional `stp_group`
    /// flattens to a presence `bool` + value.
    ///
    /// The node accepts an agent-resolved `owner` on the wire. That owner routes
    /// admission only; there is one frozen type string, so the digest stays
    /// owner-less.
    FbaSubmit {
        /// Chain tag.
        metaflux_chain: String,
        /// Target market.
        market: u32,
        /// Side (`0` = bid, `1` = ask).
        side: u8,
        /// Submitted size (the `u64` wire form).
        size: u64,
        /// Limit / worst-acceptable price (the `u64` wire form).
        price: u64,
        /// Whether an STP group is present.
        has_stp_group: bool,
        /// STP group id (`0` when absent).
        stp_group: u64,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `Noop(string metafluxChain,uint64 nonce)`
    ///
    /// A deliberate no-op. The handler touches no state, so the only effect is
    /// burning the envelope nonce. Use it as a keepalive, or to close a nonce
    /// gap: a committed `noop` at nonce `N` invalidates any other in-flight
    /// action signed with nonce `N`.
    ///
    /// Sender-authorized, and effectively master only: the chain does not
    /// permit an agent wallet to sign it. The wire action carries no `params`.
    Noop {
        /// Chain tag.
        metaflux_chain: String,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `BorrowLend(string metafluxChain,uint8 kind,string amount,uint64 nonce)`
    ///
    /// Lend / un-lend / borrow / repay against the BOLE pool. `kind` is the
    /// signed `uint8` discriminant; the POST `params.kind` carries the
    /// PascalCase name instead. Build it with
    /// [`Exchange::borrow_lend`](crate::rest::exchange::Exchange::borrow_lend)
    /// so the two forms cannot drift.
    BorrowLend {
        /// Chain tag.
        metaflux_chain: String,
        /// Direction: `0` lend, `1` un-lend, `2` borrow, `3` repay.
        kind: u8,
        /// Amount as a canonical decimal string.
        amount: String,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `RegisterMetaliquidityOperator(string metafluxChain,uint64 vaultId,address operator,bool allowed,uint64 expiresAtMs,uint64 nonce)`
    ///
    /// A vault leader grants or revokes an operator on its own vault.
    RegisterMetaliquidityOperator {
        /// Chain tag.
        metaflux_chain: String,
        /// Vault id the operator acts for.
        vault_id: u64,
        /// Operator address.
        operator: Address,
        /// `true` grants, `false` revokes.
        allowed: bool,
        /// Grant expiry (ms since epoch). `0` = never expires.
        expires_at_ms: u64,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `SpotRegisterToken(string metafluxChain,string symbol,uint8 szDecimals,uint8 weiDecimals,string maxDeployFee,uint64 nonce)`
    SpotRegisterToken {
        /// Chain tag.
        metaflux_chain: String,
        /// Token symbol.
        symbol: String,
        /// Display / size precision.
        sz_decimals: u8,
        /// Native token decimals.
        wei_decimals: u8,
        /// Highest Dutch accept price taken, as a canonical decimal string in
        /// whole USDC.
        max_deploy_fee: String,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `SpotRegisterPair(string metafluxChain,uint32 base,uint32 quote,string name,string maxDeployFee,uint64 nonce)`
    SpotRegisterPair {
        /// Chain tag.
        metaflux_chain: String,
        /// Base token id.
        base: u32,
        /// Quote token id.
        quote: u32,
        /// Pair name.
        name: String,
        /// Highest Dutch accept price taken, as a canonical decimal string in
        /// whole USDC.
        max_deploy_fee: String,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `SpotSetPairParams(string metafluxChain,uint32 pair,uint32 takerFeeDbps,uint32 makerFeeDbps,uint64 minNotionalCents,uint64 nonce)`
    SpotSetPairParams {
        /// Chain tag.
        metaflux_chain: String,
        /// Spot pair id.
        pair: u32,
        /// Taker fee in DECI-bps.
        taker_fee_dbps: u32,
        /// Maker fee in DECI-bps.
        maker_fee_dbps: u32,
        /// Min order notional in USDC cents.
        min_notional_cents: u64,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `SpotSetPairActive(string metafluxChain,uint32 pair,bool active,uint64 nonce)`
    SpotSetPairActive {
        /// Chain tag.
        metaflux_chain: String,
        /// Spot pair id.
        pair: u32,
        /// `true` opens the pair, `false` closes it.
        active: bool,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `SpotSeedHolders(string metafluxChain,uint32 asset,address[] holders,string[] amounts,uint64 nonce)`
    ///
    /// Both arrays are IN the digest, so no relay can re-target, re-size or
    /// re-order a staged row under a replayed signature.
    SpotSeedHolders {
        /// Chain tag.
        metaflux_chain: String,
        /// The spot token being staged.
        asset: u32,
        /// Holder addresses, parallel with `amounts`.
        holders: Vec<Address>,
        /// WHOLE-unit amounts as canonical decimal strings, parallel with
        /// `holders`.
        amounts: Vec<String>,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `SpotFinalizeSupply(string metafluxChain,uint32 asset,string maxSupply,uint64 nonce)`
    SpotFinalizeSupply {
        /// Chain tag.
        metaflux_chain: String,
        /// The spot token being sealed.
        asset: u32,
        /// Checksum over every staged row, as a canonical decimal string.
        max_supply: String,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `PerpRegisterAsset(string metafluxChain,string symbol,uint8 decimals,uint64 nonce)`
    PerpRegisterAsset {
        /// Chain tag.
        metaflux_chain: String,
        /// Market symbol.
        symbol: String,
        /// Token decimals. `0` is not "zero decimals" — the node reads it as its
        /// default of 8.
        decimals: u8,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `PerpSetOracle(string metafluxChain,uint32 asset,uint16 oracleSourceMask,uint64 nonce)`
    PerpSetOracle {
        /// Chain tag.
        metaflux_chain: String,
        /// Target market asset id.
        asset: u32,
        /// Bitmask of enabled oracle sources.
        oracle_source_mask: u16,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `PerpSetLeverage(string metafluxChain,uint32 asset,uint8 maxLeverage,uint64 nonce)`
    PerpSetLeverage {
        /// Chain tag.
        metaflux_chain: String,
        /// Target market asset id.
        asset: u32,
        /// Max leverage.
        max_leverage: u8,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `PerpSetFeeTier(string metafluxChain,uint32 asset,uint32 takerFeeDbps,uint32 makerFeeDbps,uint32 deployerFeeBps,uint64 nonce)`
    ///
    /// The three legs are signed SEPARATELY. The node packs them into the one
    /// value its handler decodes, so the signer signs the legs it means.
    PerpSetFeeTier {
        /// Chain tag.
        metaflux_chain: String,
        /// Target market asset id.
        asset: u32,
        /// Taker fee in DECI-bps.
        taker_fee_dbps: u32,
        /// Maker fee in DECI-bps.
        maker_fee_dbps: u32,
        /// Deployer cut in WHOLE bps.
        deployer_fee_bps: u32,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `PerpSetMakerRebate(string metafluxChain,uint32 asset,uint16 rebateBps,uint64 nonce)`
    PerpSetMakerRebate {
        /// Chain tag.
        metaflux_chain: String,
        /// Target market asset id.
        asset: u32,
        /// Maker rebate in whole bps.
        rebate_bps: u16,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `PerpSetMinSize(string metafluxChain,uint32 asset,uint64 minOrderSize,uint64 nonce)`
    PerpSetMinSize {
        /// Chain tag.
        metaflux_chain: String,
        /// Target market asset id.
        asset: u32,
        /// Min order size in the market's size plane.
        min_order_size: u64,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `PerpActivateMarket(string metafluxChain,uint32 asset,uint64 nonce)`
    PerpActivateMarket {
        /// Chain tag.
        metaflux_chain: String,
        /// Target market asset id.
        asset: u32,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `PerpDeactivateMarket(string metafluxChain,uint32 asset,uint64 nonce)`
    PerpDeactivateMarket {
        /// Chain tag.
        metaflux_chain: String,
        /// Target market asset id.
        asset: u32,
        /// Envelope nonce.
        nonce: u64,
    },
    /// `PerpSetSubDeployers(string metafluxChain,uint32 asset,address subDeployer,bool add,uint64 nonce)`
    ///
    /// `sub_deployer` and `add` are both IN the digest, so no relay can re-target
    /// the delegate or flip a removal into a grant.
    PerpSetSubDeployers {
        /// Chain tag.
        metaflux_chain: String,
        /// Target market asset id.
        asset: u32,
        /// The delegate address.
        sub_deployer: Address,
        /// `true` adds the delegate, `false` removes it.
        add: bool,
        /// Envelope nonce.
        nonce: u64,
    },
}

impl TypedAction {
    /// The frozen `encodeType` string for this variant.
    fn type_string(&self) -> &'static [u8] {
        match self {
            TypedAction::SendAsset { .. } => SEND_ASSET_TYPE,
            TypedAction::UsdClassTransfer { .. } => USD_CLASS_TRANSFER_TYPE,
            TypedAction::Withdraw { .. } => WITHDRAW_TYPE,
            TypedAction::ApproveAgent { .. } => APPROVE_AGENT_TYPE,
            TypedAction::SetReferrer { .. } => SET_REFERRER_TYPE,
            TypedAction::ApproveBuilderFee { .. } => APPROVE_BUILDER_FEE_TYPE,
            TypedAction::SetDisplayName { .. } => SET_DISPLAY_NAME_TYPE,
            TypedAction::SetPositionMode { .. } => SET_POSITION_MODE_TYPE,
            TypedAction::UserPortfolioMargin { .. } => USER_PORTFOLIO_MARGIN_TYPE,
            TypedAction::ConvertToMultiSigUser { .. } => CONVERT_TO_MULTI_SIG_USER_TYPE,
            TypedAction::MultiSig { .. } => MULTI_SIG_TYPE,
            TypedAction::UpdateLeverage { .. } => UPDATE_LEVERAGE_TYPE,
            TypedAction::ClaimRewards { .. } => CLAIM_REWARDS_TYPE,
            TypedAction::LinkStakingUser { .. } => LINK_STAKING_USER_TYPE,
            TypedAction::CreateVault { .. } => CREATE_VAULT_TYPE,
            TypedAction::VaultModify { .. } => VAULT_MODIFY_TYPE,
            TypedAction::SpotMarginClose { .. } => SPOT_MARGIN_CLOSE_TYPE,
            TypedAction::UpdateIsolatedMargin { .. } => UPDATE_ISOLATED_MARGIN_TYPE,
            TypedAction::TopUpIsolatedOnlyMargin { .. } => TOP_UP_ISOLATED_ONLY_MARGIN_TYPE,
            TypedAction::TokenDelegate { .. } => TOKEN_DELEGATE_TYPE,
            TypedAction::VaultTransfer { .. } => VAULT_TRANSFER_TYPE,
            TypedAction::VaultWithdraw { .. } => VAULT_WITHDRAW_TYPE,
            TypedAction::SpotMarginDeposit { .. } => SPOT_MARGIN_DEPOSIT_TYPE,
            TypedAction::SpotMarginWithdraw { .. } => SPOT_MARGIN_WITHDRAW_TYPE,
            TypedAction::SpotMarginOpen { .. } => SPOT_MARGIN_OPEN_TYPE,
            TypedAction::EarnDeposit { .. } => EARN_DEPOSIT_TYPE,
            TypedAction::EarnWithdraw { .. } => EARN_WITHDRAW_TYPE,
            TypedAction::AgentSetAbstraction { .. } => AGENT_SET_ABSTRACTION_TYPE,
            TypedAction::MbWithdraw { .. } => MB_WITHDRAW_TYPE,
            TypedAction::CoreEvmTransfer { .. } => account::CORE_EVM_TRANSFER_TYPE,
            TypedAction::CoreEvmTransferV2 { .. } => account::CORE_EVM_TRANSFER_V2_TYPE,
            TypedAction::SendToEvmWithData { .. } => account::SEND_TO_EVM_WITH_DATA_TYPE,
            TypedAction::CreateSubAccount { .. } => account::CREATE_SUB_ACCOUNT_TYPE,
            TypedAction::SubAccountTransfer { .. } => account::SUB_ACCOUNT_TRANSFER_TYPE,
            TypedAction::SubAccountSpotTransfer { .. } => account::SUB_ACCOUNT_SPOT_TRANSFER_TYPE,
            TypedAction::CDeposit { .. } => account::C_DEPOSIT_TYPE,
            TypedAction::CWithdraw { .. } => account::C_WITHDRAW_TYPE,
            TypedAction::UserSetAbstraction { .. } => account::USER_SET_ABSTRACTION_TYPE,
            TypedAction::PriorityBid { .. } => account::PRIORITY_BID_TYPE,
            TypedAction::CancelAllOrders { owner, .. } => {
                if owner.is_some() {
                    account::CANCEL_ALL_ORDERS_WITH_OWNER_TYPE
                } else {
                    account::CANCEL_ALL_ORDERS_TYPE
                }
            }
            TypedAction::SubmitEncryptedOrder { .. } => account::SUBMIT_ENCRYPTED_ORDER_TYPE,
            TypedAction::RfqRequest { .. } => account::RFQ_REQUEST_TYPE,
            TypedAction::RfqAccept { .. } => account::RFQ_ACCEPT_TYPE,
            TypedAction::FbaSubmit { .. } => account::FBA_SUBMIT_TYPE,
            TypedAction::Noop { .. } => account::NOOP_TYPE,
            TypedAction::VaultDistribute { .. } => VAULT_DISTRIBUTE_TYPE,
            TypedAction::ClaimBuilderRewards { .. } => CLAIM_BUILDER_REWARDS_TYPE,
            TypedAction::ClaimReferralRewards { .. } => CLAIM_REFERRAL_REWARDS_TYPE,
            TypedAction::RfqQuote { owner: None, .. } => account::RFQ_QUOTE_TYPE,
            TypedAction::RfqQuote { owner: Some(_), .. } => account::RFQ_QUOTE_WITH_OWNER_TYPE,
            TypedAction::BorrowLend { .. } => BORROW_LEND_TYPE,
            TypedAction::RegisterMetaliquidityOperator { .. } => {
                REGISTER_METALIQUIDITY_OPERATOR_TYPE
            }
            TypedAction::SpotRegisterToken { .. } => SPOT_REGISTER_TOKEN_TYPE,
            TypedAction::SpotRegisterPair { .. } => SPOT_REGISTER_PAIR_TYPE,
            TypedAction::SpotSetPairParams { .. } => SPOT_SET_PAIR_PARAMS_TYPE,
            TypedAction::SpotSetPairActive { .. } => SPOT_SET_PAIR_ACTIVE_TYPE,
            TypedAction::SpotSeedHolders { .. } => SPOT_SEED_HOLDERS_TYPE,
            TypedAction::SpotFinalizeSupply { .. } => SPOT_FINALIZE_SUPPLY_TYPE,
            TypedAction::PerpRegisterAsset { .. } => PERP_REGISTER_ASSET_TYPE,
            TypedAction::PerpSetOracle { .. } => PERP_SET_ORACLE_TYPE,
            TypedAction::PerpSetLeverage { .. } => PERP_SET_LEVERAGE_TYPE,
            TypedAction::PerpSetFeeTier { .. } => PERP_SET_FEE_TIER_TYPE,
            TypedAction::PerpSetMakerRebate { .. } => PERP_SET_MAKER_REBATE_TYPE,
            TypedAction::PerpSetMinSize { .. } => PERP_SET_MIN_SIZE_TYPE,
            TypedAction::PerpActivateMarket { .. } => PERP_ACTIVATE_MARKET_TYPE,
            TypedAction::PerpDeactivateMarket { .. } => PERP_DEACTIVATE_MARKET_TYPE,
            TypedAction::PerpSetSubDeployers { .. } => PERP_SET_SUB_DEPLOYERS_TYPE,
        }
    }

    /// `typeHash = keccak256(encodeType)` for this variant.
    #[must_use]
    pub fn type_hash(&self) -> [u8; 32] {
        keccak(self.type_string())
    }

    /// `encodeData(s)` — the 32-byte words for each field, in declared order.
    fn encode_data(&self) -> Vec<[u8; 32]> {
        match self {
            TypedAction::SendAsset {
                metaflux_chain,
                source_dex,
                destination_dex,
                asset,
                destination,
                amount,
                to_perp,
                nonce,
            } => vec![
                enc_string(metaflux_chain),
                enc_u32(*source_dex),
                enc_u32(*destination_dex),
                enc_u32(*asset),
                enc_addr(destination),
                enc_string(amount),
                enc_bool(*to_perp),
                enc_u64(*nonce),
            ],
            TypedAction::UsdClassTransfer {
                metaflux_chain,
                ntl,
                to_perp,
                nonce,
            } => vec![
                enc_string(metaflux_chain),
                enc_string(ntl),
                enc_bool(*to_perp),
                enc_u64(*nonce),
            ],
            TypedAction::Withdraw {
                metaflux_chain,
                asset,
                amount,
                destination_chain_id,
                use_cctp,
                nonce,
            } => vec![
                enc_string(metaflux_chain),
                enc_u32(*asset),
                enc_string(amount),
                enc_u32(*destination_chain_id),
                enc_bool(*use_cctp),
                enc_u64(*nonce),
            ],
            TypedAction::ApproveAgent {
                metaflux_chain,
                agent_address,
                agent_name,
                expires_at_ms,
                nonce,
            } => vec![
                enc_string(metaflux_chain),
                enc_addr(agent_address),
                enc_string(agent_name),
                enc_u64(*expires_at_ms),
                enc_u64(*nonce),
            ],
            TypedAction::SetReferrer {
                metaflux_chain,
                referrer,
                nonce,
            } => vec![
                enc_string(metaflux_chain),
                enc_addr(referrer),
                enc_u64(*nonce),
            ],
            TypedAction::ApproveBuilderFee {
                metaflux_chain,
                builder,
                max_fee_bps,
                nonce,
            } => vec![
                enc_string(metaflux_chain),
                enc_addr(builder),
                enc_u16(*max_fee_bps),
                enc_u64(*nonce),
            ],
            TypedAction::SetDisplayName {
                metaflux_chain,
                display_name,
                nonce,
            } => vec![
                enc_string(metaflux_chain),
                enc_string(display_name),
                enc_u64(*nonce),
            ],
            TypedAction::SetPositionMode {
                metaflux_chain,
                hedge,
                nonce,
            } => vec![
                enc_string(metaflux_chain),
                enc_bool(*hedge),
                enc_u64(*nonce),
            ],
            TypedAction::UserPortfolioMargin {
                metaflux_chain,
                enroll,
                nonce,
            } => vec![
                enc_string(metaflux_chain),
                enc_bool(*enroll),
                enc_u64(*nonce),
            ],
            TypedAction::ConvertToMultiSigUser {
                metaflux_chain,
                signers,
                threshold,
                nonce,
            } => vec![
                enc_string(metaflux_chain),
                enc_addr_array(signers),
                enc_u32(*threshold),
                enc_u64(*nonce),
            ],
            TypedAction::MultiSig {
                metaflux_chain,
                user,
                inner_action_blob,
                signatures,
                nonce,
            } => vec![
                enc_string(metaflux_chain),
                enc_addr(user),
                enc_bytes(inner_action_blob),
                enc_bytes_array(signatures),
                enc_u64(*nonce),
            ],
            TypedAction::UpdateLeverage {
                metaflux_chain,
                asset,
                leverage,
                is_isolated,
                nonce,
            } => vec![
                enc_string(metaflux_chain),
                enc_u32(*asset),
                enc_u32(*leverage),
                enc_bool(*is_isolated),
                enc_u64(*nonce),
            ],
            TypedAction::ClaimRewards {
                metaflux_chain,
                validator,
                nonce,
            } => vec![
                enc_string(metaflux_chain),
                enc_addr(validator),
                enc_u64(*nonce),
            ],
            TypedAction::LinkStakingUser {
                metaflux_chain,
                target,
                nonce,
            } => vec![
                enc_string(metaflux_chain),
                enc_addr(target),
                enc_u64(*nonce),
            ],
            TypedAction::CreateVault {
                metaflux_chain,
                name,
                lock_period_secs,
                kind,
                nonce,
            } => vec![
                enc_string(metaflux_chain),
                enc_string(name),
                enc_u64(*lock_period_secs),
                enc_u8(*kind),
                enc_u64(*nonce),
            ],
            TypedAction::VaultModify {
                metaflux_chain,
                vault_id,
                new_name,
                nonce,
            } => vec![
                enc_string(metaflux_chain),
                enc_u64(*vault_id),
                enc_string(new_name),
                enc_u64(*nonce),
            ],
            TypedAction::SpotMarginClose {
                metaflux_chain,
                pair,
                limit_px,
                nonce,
            } => vec![
                enc_string(metaflux_chain),
                enc_u32(*pair),
                enc_u64(*limit_px),
                enc_u64(*nonce),
            ],
            TypedAction::UpdateIsolatedMargin {
                metaflux_chain,
                asset,
                delta,
                nonce,
            } => vec![
                enc_string(metaflux_chain),
                enc_u32(*asset),
                enc_string(delta),
                enc_u64(*nonce),
            ],
            TypedAction::TopUpIsolatedOnlyMargin {
                metaflux_chain,
                asset,
                amount,
                nonce,
            } => vec![
                enc_string(metaflux_chain),
                enc_u32(*asset),
                enc_string(amount),
                enc_u64(*nonce),
            ],
            TypedAction::TokenDelegate {
                metaflux_chain,
                validator,
                amount,
                is_undelegate,
                lock_months,
                nonce,
            } => vec![
                enc_string(metaflux_chain),
                enc_addr(validator),
                enc_string(amount),
                enc_bool(*is_undelegate),
                enc_u8(*lock_months),
                enc_u64(*nonce),
            ],
            TypedAction::VaultTransfer {
                metaflux_chain,
                vault_id,
                deposit,
                amount,
                nonce,
            } => vec![
                enc_string(metaflux_chain),
                enc_u64(*vault_id),
                enc_bool(*deposit),
                enc_string(amount),
                enc_u64(*nonce),
            ],
            TypedAction::VaultWithdraw {
                metaflux_chain,
                vault_id,
                shares,
                nonce,
            } => vec![
                enc_string(metaflux_chain),
                enc_u64(*vault_id),
                enc_string(shares),
                enc_u64(*nonce),
            ],
            TypedAction::SpotMarginDeposit {
                metaflux_chain,
                pair,
                amount,
                nonce,
            } => vec![
                enc_string(metaflux_chain),
                enc_u32(*pair),
                enc_string(amount),
                enc_u64(*nonce),
            ],
            TypedAction::SpotMarginWithdraw {
                metaflux_chain,
                pair,
                amount,
                nonce,
            } => vec![
                enc_string(metaflux_chain),
                enc_u32(*pair),
                enc_string(amount),
                enc_u64(*nonce),
            ],
            TypedAction::SpotMarginOpen {
                metaflux_chain,
                pair,
                size,
                limit_px,
                borrow,
                nonce,
            } => vec![
                enc_string(metaflux_chain),
                enc_u32(*pair),
                enc_u64(*size),
                enc_u64(*limit_px),
                enc_string(borrow),
                enc_u64(*nonce),
            ],
            TypedAction::EarnDeposit {
                metaflux_chain,
                asset,
                amount,
                nonce,
            } => vec![
                enc_string(metaflux_chain),
                enc_u32(*asset),
                enc_string(amount),
                enc_u64(*nonce),
            ],
            TypedAction::EarnWithdraw {
                metaflux_chain,
                asset,
                shares,
                nonce,
            } => vec![
                enc_string(metaflux_chain),
                enc_u32(*asset),
                enc_string(shares),
                enc_u64(*nonce),
            ],
            TypedAction::AgentSetAbstraction {
                metaflux_chain,
                user,
                kind,
                value,
                nonce,
            } => vec![
                enc_string(metaflux_chain),
                enc_addr(user),
                enc_u8(*kind),
                enc_string(value),
                enc_u64(*nonce),
            ],
            TypedAction::MbWithdraw {
                metaflux_chain,
                chain,
                asset,
                amount,
                dst_addr,
                nonce,
            } => vec![
                enc_string(metaflux_chain),
                enc_u8(*chain),
                enc_u32(*asset),
                enc_u64(*amount),
                enc_string(dst_addr),
                enc_u64(*nonce),
            ],
            TypedAction::CoreEvmTransferV2 {
                metaflux_chain,
                amount,
                to_evm,
                destination,
                asset,
                destination_chain_id,
                data,
                nonce,
            } => account::core_evm_transfer_v2_words(
                metaflux_chain,
                amount,
                *to_evm,
                destination,
                *asset,
                *destination_chain_id,
                data,
                *nonce,
            ),
            TypedAction::CoreEvmTransfer {
                metaflux_chain,
                amount,
                to_evm,
                destination,
                asset,
                nonce,
            } => account::core_evm_transfer_words(
                metaflux_chain,
                amount,
                *to_evm,
                destination,
                *asset,
                *nonce,
            ),
            TypedAction::SendToEvmWithData {
                metaflux_chain,
                token,
                amount,
                source_dex,
                destination_recipient,
                to_perp,
                destination_chain_id,
                data,
                transfer_nonce,
                nonce,
            } => account::send_to_evm_with_data_words(
                metaflux_chain,
                *token,
                amount,
                *source_dex,
                destination_recipient,
                *to_perp,
                *destination_chain_id,
                data,
                *transfer_nonce,
                *nonce,
            ),
            TypedAction::CreateSubAccount {
                metaflux_chain,
                name,
                has_explicit_index,
                explicit_index,
                shared_stp_group,
                nonce,
            } => account::create_sub_account_words(
                metaflux_chain,
                name,
                *has_explicit_index,
                *explicit_index,
                *shared_stp_group,
                *nonce,
            ),
            TypedAction::SubAccountTransfer {
                metaflux_chain,
                sub_index,
                deposit,
                amount,
                nonce,
            } => account::sub_account_transfer_words(
                metaflux_chain,
                *sub_index,
                *deposit,
                amount,
                *nonce,
            ),
            TypedAction::SubAccountSpotTransfer {
                metaflux_chain,
                sub_index,
                token,
                deposit,
                amount,
                nonce,
            } => account::sub_account_spot_transfer_words(
                metaflux_chain,
                *sub_index,
                *token,
                *deposit,
                amount,
                *nonce,
            ),
            TypedAction::CDeposit {
                metaflux_chain,
                amount,
                nonce,
            } => account::staking_move_words(metaflux_chain, amount, *nonce),
            TypedAction::CWithdraw {
                metaflux_chain,
                amount,
                nonce,
            } => account::staking_move_words(metaflux_chain, amount, *nonce),
            TypedAction::UserSetAbstraction {
                metaflux_chain,
                kind,
                value,
                nonce,
            } => account::user_set_abstraction_words(metaflux_chain, *kind, value, *nonce),
            TypedAction::PriorityBid {
                metaflux_chain,
                asset,
                bid_bps,
                nonce,
            } => account::priority_bid_words(metaflux_chain, *asset, *bid_bps, *nonce),
            TypedAction::CancelAllOrders {
                metaflux_chain,
                owner,
                has_asset,
                asset,
                nonce,
            } => match owner {
                Some(o) => account::cancel_all_orders_words_with_owner(
                    metaflux_chain,
                    o,
                    *has_asset,
                    *asset,
                    *nonce,
                ),
                None => {
                    account::cancel_all_orders_words(metaflux_chain, *has_asset, *asset, *nonce)
                }
            },
            TypedAction::SubmitEncryptedOrder {
                metaflux_chain,
                ciphertext,
                commitment,
                threshold,
                target_block,
                reveal_deadline_ms,
                nonce,
            } => account::submit_encrypted_order_words(
                metaflux_chain,
                ciphertext,
                commitment,
                *threshold,
                *target_block,
                *reveal_deadline_ms,
                *nonce,
            ),
            TypedAction::RfqRequest {
                metaflux_chain,
                market,
                side,
                size,
                has_limit_px,
                limit_px,
                expiry_ms,
                has_stp_group,
                stp_group,
                nonce,
            } => account::rfq_request_words(
                metaflux_chain,
                *market,
                *side,
                *size,
                *has_limit_px,
                *limit_px,
                *expiry_ms,
                *has_stp_group,
                *stp_group,
                *nonce,
            ),
            TypedAction::RfqAccept {
                metaflux_chain,
                rfq_id,
                quote_idx,
                size,
                nonce,
            } => account::rfq_accept_words(metaflux_chain, *rfq_id, *quote_idx, *size, *nonce),
            TypedAction::FbaSubmit {
                metaflux_chain,
                market,
                side,
                size,
                price,
                has_stp_group,
                stp_group,
                nonce,
            } => account::fba_submit_words(
                metaflux_chain,
                *market,
                *side,
                *size,
                *price,
                *has_stp_group,
                *stp_group,
                *nonce,
            ),
            TypedAction::Noop {
                metaflux_chain,
                nonce,
            } => account::noop_words(metaflux_chain, *nonce),
            TypedAction::VaultDistribute {
                metaflux_chain,
                vault_id,
                pnl,
                nonce,
            } => vec![
                enc_string(metaflux_chain),
                enc_u64(*vault_id),
                enc_string(pnl),
                enc_u64(*nonce),
            ],
            TypedAction::ClaimBuilderRewards {
                metaflux_chain,
                nonce,
            } => vec![enc_string(metaflux_chain), enc_u64(*nonce)],
            TypedAction::ClaimReferralRewards {
                metaflux_chain,
                nonce,
            } => vec![enc_string(metaflux_chain), enc_u64(*nonce)],
            TypedAction::RfqQuote {
                metaflux_chain,
                owner,
                rfq_id,
                price,
                max_size,
                valid_until_ms,
                has_stp_group,
                stp_group,
                nonce,
            } => match owner {
                Some(o) => account::rfq_quote_words_with_owner(
                    metaflux_chain,
                    o,
                    *rfq_id,
                    *price,
                    *max_size,
                    *valid_until_ms,
                    *has_stp_group,
                    *stp_group,
                    *nonce,
                ),
                None => account::rfq_quote_words(
                    metaflux_chain,
                    *rfq_id,
                    *price,
                    *max_size,
                    *valid_until_ms,
                    *has_stp_group,
                    *stp_group,
                    *nonce,
                ),
            },
            TypedAction::BorrowLend {
                metaflux_chain,
                kind,
                amount,
                nonce,
            } => vec![
                enc_string(metaflux_chain),
                enc_u8(*kind),
                enc_string(amount),
                enc_u64(*nonce),
            ],
            TypedAction::RegisterMetaliquidityOperator {
                metaflux_chain,
                vault_id,
                operator,
                allowed,
                expires_at_ms,
                nonce,
            } => vec![
                enc_string(metaflux_chain),
                enc_u64(*vault_id),
                enc_addr(operator),
                enc_bool(*allowed),
                enc_u64(*expires_at_ms),
                enc_u64(*nonce),
            ],
            TypedAction::SpotRegisterToken {
                metaflux_chain,
                symbol,
                sz_decimals,
                wei_decimals,
                max_deploy_fee,
                nonce,
            } => vec![
                enc_string(metaflux_chain),
                enc_string(symbol),
                enc_u8(*sz_decimals),
                enc_u8(*wei_decimals),
                enc_string(max_deploy_fee),
                enc_u64(*nonce),
            ],
            TypedAction::SpotRegisterPair {
                metaflux_chain,
                base,
                quote,
                name,
                max_deploy_fee,
                nonce,
            } => vec![
                enc_string(metaflux_chain),
                enc_u32(*base),
                enc_u32(*quote),
                enc_string(name),
                enc_string(max_deploy_fee),
                enc_u64(*nonce),
            ],
            TypedAction::SpotSetPairParams {
                metaflux_chain,
                pair,
                taker_fee_dbps,
                maker_fee_dbps,
                min_notional_cents,
                nonce,
            } => vec![
                enc_string(metaflux_chain),
                enc_u32(*pair),
                enc_u32(*taker_fee_dbps),
                enc_u32(*maker_fee_dbps),
                enc_u64(*min_notional_cents),
                enc_u64(*nonce),
            ],
            TypedAction::SpotSetPairActive {
                metaflux_chain,
                pair,
                active,
                nonce,
            } => vec![
                enc_string(metaflux_chain),
                enc_u32(*pair),
                enc_bool(*active),
                enc_u64(*nonce),
            ],
            TypedAction::SpotSeedHolders {
                metaflux_chain,
                asset,
                holders,
                amounts,
                nonce,
            } => vec![
                enc_string(metaflux_chain),
                enc_u32(*asset),
                enc_addr_array(holders),
                enc_string_array(amounts),
                enc_u64(*nonce),
            ],
            TypedAction::SpotFinalizeSupply {
                metaflux_chain,
                asset,
                max_supply,
                nonce,
            } => vec![
                enc_string(metaflux_chain),
                enc_u32(*asset),
                enc_string(max_supply),
                enc_u64(*nonce),
            ],
            TypedAction::PerpRegisterAsset {
                metaflux_chain,
                symbol,
                decimals,
                nonce,
            } => vec![
                enc_string(metaflux_chain),
                enc_string(symbol),
                enc_u8(*decimals),
                enc_u64(*nonce),
            ],
            TypedAction::PerpSetOracle {
                metaflux_chain,
                asset,
                oracle_source_mask,
                nonce,
            } => vec![
                enc_string(metaflux_chain),
                enc_u32(*asset),
                enc_u16(*oracle_source_mask),
                enc_u64(*nonce),
            ],
            TypedAction::PerpSetLeverage {
                metaflux_chain,
                asset,
                max_leverage,
                nonce,
            } => vec![
                enc_string(metaflux_chain),
                enc_u32(*asset),
                enc_u8(*max_leverage),
                enc_u64(*nonce),
            ],
            TypedAction::PerpSetFeeTier {
                metaflux_chain,
                asset,
                taker_fee_dbps,
                maker_fee_dbps,
                deployer_fee_bps,
                nonce,
            } => vec![
                enc_string(metaflux_chain),
                enc_u32(*asset),
                enc_u32(*taker_fee_dbps),
                enc_u32(*maker_fee_dbps),
                enc_u32(*deployer_fee_bps),
                enc_u64(*nonce),
            ],
            TypedAction::PerpSetMakerRebate {
                metaflux_chain,
                asset,
                rebate_bps,
                nonce,
            } => vec![
                enc_string(metaflux_chain),
                enc_u32(*asset),
                enc_u16(*rebate_bps),
                enc_u64(*nonce),
            ],
            TypedAction::PerpSetMinSize {
                metaflux_chain,
                asset,
                min_order_size,
                nonce,
            } => vec![
                enc_string(metaflux_chain),
                enc_u32(*asset),
                enc_u64(*min_order_size),
                enc_u64(*nonce),
            ],
            TypedAction::PerpActivateMarket {
                metaflux_chain,
                asset,
                nonce,
            } => vec![enc_string(metaflux_chain), enc_u32(*asset), enc_u64(*nonce)],
            TypedAction::PerpDeactivateMarket {
                metaflux_chain,
                asset,
                nonce,
            } => vec![enc_string(metaflux_chain), enc_u32(*asset), enc_u64(*nonce)],
            TypedAction::PerpSetSubDeployers {
                metaflux_chain,
                asset,
                sub_deployer,
                add,
                nonce,
            } => vec![
                enc_string(metaflux_chain),
                enc_u32(*asset),
                enc_addr(sub_deployer),
                enc_bool(*add),
                enc_u64(*nonce),
            ],
        }
    }

    /// `typeHash` with the OPTIONAL top-level `expiresAfter` field folded in.
    ///
    /// `expires_after == 0` (the never-expires case) returns EXACTLY
    /// [`type_hash`](Self::type_hash) — byte-identical to every frozen signature.
    /// When non-zero, the shared envelope-suffix fold turns the frozen type
    /// string's trailing `...,uint64 nonce)` into
    /// `...,uint64 nonce,uint64 expiresAfter)` before hashing. Mirrors the node's
    /// `folded_type_hash` (applies uniformly to every variant, `*_WITH_OWNER`
    /// included).
    fn folded_type_hash(&self, expires_after: u64) -> [u8; 32] {
        if expires_after == 0 {
            return self.type_hash();
        }
        let base = self.type_string();
        debug_assert_eq!(base.last(), Some(&b')'), "type string must end in ')'");
        let suffix = b",uint64 expiresAfter)";
        let mut folded = Vec::with_capacity(base.len() - 1 + suffix.len());
        folded.extend_from_slice(&base[..base.len() - 1]);
        folded.extend_from_slice(suffix);
        keccak(&folded)
    }

    /// `hashStruct(s) = keccak256(typeHash ‖ encodeData(s))`.
    #[must_use]
    pub fn hash_struct(&self) -> [u8; 32] {
        self.hash_struct_with_expiry(0)
    }

    /// `hashStruct(s)` with the OPTIONAL top-level `expiresAfter` folded in.
    ///
    /// `expires_after == 0` reproduces [`hash_struct`](Self::hash_struct)
    /// BYTE-FOR-BYTE (frozen type hash + the exact `encode_data` words, no extra
    /// word). When non-zero it uses the folded type hash and appends ONE trailing
    /// `uint256(expires_after)` word AFTER the existing nonce word.
    #[must_use]
    pub fn hash_struct_with_expiry(&self, expires_after: u64) -> [u8; 32] {
        let mut k = Keccak::v256();
        k.update(&self.folded_type_hash(expires_after));
        for word in self.encode_data() {
            k.update(&word);
        }
        if expires_after != 0 {
            k.update(&enc_u64(expires_after));
        }
        let mut out = [0u8; 32];
        k.finalize(&mut out);
        out
    }
}

/// EIP-712 wrapper binding a [`TypedAction`] to a domain chain id, so it can be
/// signed through [`crate::wallet::Wallet::sign_eip712`].
///
/// The 32-byte digest is `keccak256(0x19 0x01 ‖ domainSeparator ‖ hashStruct)`,
/// where the domain separator is the shared MetaFlux V1 5-field domain for the
/// given chain id.
#[derive(Clone, Debug)]
pub struct TypedActionDigest<'a> {
    action: &'a TypedAction,
    chain_id: u64,
    expires_after: u64,
}

impl<'a> TypedActionDigest<'a> {
    /// Bind `action` to `chain_id` for signing (no expiry — the digest is
    /// byte-identical to every pre-`expiresAfter` signature).
    #[must_use]
    pub fn new(action: &'a TypedAction, chain_id: u64) -> Self {
        Self {
            action,
            chain_id,
            expires_after: 0,
        }
    }

    /// Bind `action` to `chain_id` with an OPTIONAL top-level `expiresAfter`
    /// (consensus time in ms; `0` = never expires). `expires_after == 0`
    /// reproduces [`new`](Self::new) BYTE-FOR-BYTE; non-zero folds the expiry
    /// into the signed digest so a relay can neither strip nor alter it.
    ///
    /// A non-zero expiry is only admitted once the network activates the field —
    /// until then, sign with `0` / [`new`](Self::new).
    #[must_use]
    pub fn new_with_expiry(action: &'a TypedAction, chain_id: u64, expires_after: u64) -> Self {
        Self {
            action,
            chain_id,
            expires_after,
        }
    }
}

impl Eip712 for TypedActionDigest<'_> {
    fn domain_separator(&self) -> [u8; 32] {
        metaflux_domain_separator(self.chain_id)
    }

    fn struct_hash(&self) -> [u8; 32] {
        self.action.hash_struct_with_expiry(self.expires_after)
    }
}

/// The MetaFlux V1 EIP-712 domain separator for `chain_id`.
///
/// `keccak256(typeHash ‖ keccak256(name) ‖ keccak256(version) ‖ chainId ‖ verifyingContract)`
/// with `name = "MetaFlux"`, `version = "1"`, `verifyingContract = 0x0`.
#[must_use]
pub fn metaflux_domain_separator(chain_id: u64) -> [u8; 32] {
    let type_hash = keccak(
        b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    );
    let name_hash = keccak(b"MetaFlux");
    let version_hash = keccak(b"1");
    let mut chain_be = [0u8; 32];
    chain_be[24..].copy_from_slice(&chain_id.to_be_bytes());
    let verifying_padded = [0u8; 32]; // Address::ZERO, left-padded.

    let mut k = Keccak::v256();
    k.update(&type_hash);
    k.update(&name_hash);
    k.update(&version_hash);
    k.update(&chain_be);
    k.update(&verifying_padded);
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::sign::Eip712;

    fn addr(byte: u8) -> Address {
        Address::from_bytes([byte; 20])
    }

    /// Pin the three fully specified KAT vectors from the signing contract
    /// (chain id 114514 / `"Testnet"`) byte-for-byte.
    #[test]
    fn kat_vectors_chain_114514() {
        let approve_agent = TypedAction::ApproveAgent {
            metaflux_chain: "Testnet".into(),
            agent_address: addr(0xA1),
            agent_name: "trading-bot".into(),
            expires_at_ms: 1_700_000_000_000,
            nonce: 1,
        };
        assert_eq!(
            hex::encode(TypedActionDigest::new(&approve_agent, 114514).to_digest()),
            "569bb62f0cd468264550e8bdc4c37abcf273bdd48569bed37b985c5d6e94693e"
        );

        let send_asset = TypedAction::SendAsset {
            metaflux_chain: "Testnet".into(),
            source_dex: 0,
            destination_dex: 1,
            asset: 2,
            destination: addr(0x3C),
            amount: "750.25".into(),
            to_perp: true,
            nonce: 28,
        };
        assert_eq!(
            hex::encode(TypedActionDigest::new(&send_asset, 114514).to_digest()),
            "88aa17af1dc0d6d35934ada321549a4b8b6a4d964f9c5263e1200b4f696cac4d"
        );

        let multi_sig = TypedAction::ConvertToMultiSigUser {
            metaflux_chain: "Testnet".into(),
            signers: vec![addr(0x11), addr(0x22), addr(0x33)],
            threshold: 2,
            nonce: 7,
        };
        assert_eq!(
            hex::encode(TypedActionDigest::new(&multi_sig, 114514).to_digest()),
            "981a2b3adb1d0c03a7af30076f3c6497ffeabe79e380b01be4f1f14eb1252e84"
        );
    }

    /// Pin the twelve formerly-deferred typed actions (chain id 114514 /
    /// `"Testnet"`) byte-for-byte against the frozen contract digests.
    #[test]
    fn kat_vectors_extended_chain_114514() {
        let cases: Vec<(TypedAction, &str)> = vec![
            (
                TypedAction::UpdateIsolatedMargin {
                    metaflux_chain: "Testnet".into(),
                    asset: 1,
                    delta: "-100.5".into(),
                    nonce: 9,
                },
                "f3ca20d10ce710d31de3d321d61d60b53550adbb4dfd09fca9b7a8c8dbc08162",
            ),
            (
                TypedAction::TopUpIsolatedOnlyMargin {
                    metaflux_chain: "Testnet".into(),
                    asset: 1,
                    amount: "50".into(),
                    nonce: 10,
                },
                "47647d208358a681eb657867da2ce00dfeb010a7f2023ecb69e195642da24c8a",
            ),
            (
                TypedAction::TokenDelegate {
                    metaflux_chain: "Testnet".into(),
                    validator: addr(0xD4),
                    amount: "1000".into(),
                    is_undelegate: false,
                    lock_months: 0,
                    nonce: 11,
                },
                "cc3d9e5ed170fc39028ebe587af079e42968a1c5e324da20bc584ddc28711a98",
            ),
            (
                TypedAction::VaultTransfer {
                    metaflux_chain: "Testnet".into(),
                    vault_id: 42,
                    deposit: true,
                    amount: "250.75".into(),
                    nonce: 16,
                },
                "d5da325a4e1331ebd6a158d7192795a3eeaf2a39c86b90d44cd5506c98ececc9",
            ),
            (
                TypedAction::VaultWithdraw {
                    metaflux_chain: "Testnet".into(),
                    vault_id: 42,
                    shares: "10.5".into(),
                    nonce: 18,
                },
                "ca6c76e49c7cedd99df8d27ee85d14175b954d25bdac53f9525e6b8c71f6b5a7",
            ),
            (
                TypedAction::SpotMarginDeposit {
                    metaflux_chain: "Testnet".into(),
                    pair: 5,
                    amount: "100".into(),
                    nonce: 20,
                },
                "3d2f440131e3059d8ac4329864f258ae8c799f82323785a36420182ed3e304fd",
            ),
            (
                TypedAction::SpotMarginWithdraw {
                    metaflux_chain: "Testnet".into(),
                    pair: 5,
                    amount: "50".into(),
                    nonce: 21,
                },
                "44540925574b90c68c0cb4c5773d2d51e14d3c3ddd6c9fe5b97e81aba67e768c",
            ),
            (
                TypedAction::SpotMarginOpen {
                    metaflux_chain: "Testnet".into(),
                    pair: 5,
                    size: 1_000,
                    limit_px: 5_000_000_000,
                    borrow: "200".into(),
                    nonce: 22,
                },
                "d56110f1e4adb4fbd07a72b870678425bd5440d2119e3d9d9f205469c6dbd4c1",
            ),
            (
                TypedAction::EarnDeposit {
                    metaflux_chain: "Testnet".into(),
                    asset: 0,
                    amount: "500".into(),
                    nonce: 24,
                },
                "947530d85221850f892412799ef45baef7f5a75663272bc565e81c519879664e",
            ),
            (
                TypedAction::EarnWithdraw {
                    metaflux_chain: "Testnet".into(),
                    asset: 0,
                    shares: "25.5".into(),
                    nonce: 25,
                },
                "5244365c226ab1b7ec786129f134d104a2923a57b9cc2588d6b215aef5b55018",
            ),
            (
                TypedAction::AgentSetAbstraction {
                    metaflux_chain: "Testnet".into(),
                    user: addr(0xF6),
                    kind: 3,
                    value: "abstraction-value".into(),
                    nonce: 14,
                },
                "0dd8a92857e2f4aafd97dd0131704bab22969345844389d2b214d55f2a7de71e",
            ),
            (
                TypedAction::MbWithdraw {
                    metaflux_chain: "Testnet".into(),
                    chain: 2,
                    asset: 1,
                    amount: 1_000_000,
                    dst_addr: "0xdeadbeef".into(),
                    nonce: 19,
                },
                "423f327abdec7b3469b6dc5d4993ac4a11f0a09487cec564b85d8162abdee2e8",
            ),
        ];
        for (action, want) in cases {
            assert_eq!(
                hex::encode(TypedActionDigest::new(&action, 114514).to_digest()),
                want,
                "digest drift for {action:?}"
            );
        }
    }

    /// `cancel_all_orders` with an agent-resolved `owner` (operator / vault):
    /// (1) the selected encodeType bytes equal the node's
    /// `CANCEL_ALL_ORDERS_WITH_OWNER_TYPE` (literal copied from the node's
    /// account typed-signing contract); (2) the owner-present digest matches the
    /// pinned vector; (3) it DIFFERS from the owner-less digest; and (4) the
    /// owner-less digest is byte-identical to the pre-owner KAT
    /// (`9088140f…`, the value pinned in `tests/typed_signing_kat.rs`).
    #[test]
    fn cancel_all_orders_with_owner_kat() {
        let with_owner = TypedAction::CancelAllOrders {
            metaflux_chain: "Testnet".into(),
            owner: Some(addr(0xbb)),
            has_asset: true,
            asset: 4,
            nonce: 62,
        };
        let without_owner = TypedAction::CancelAllOrders {
            metaflux_chain: "Testnet".into(),
            owner: None,
            has_asset: true,
            asset: 4,
            nonce: 62,
        };
        // (1) encodeType bytes == node CANCEL_ALL_ORDERS_WITH_OWNER_TYPE (verbatim).
        assert_eq!(
            with_owner.type_string(),
            b"MetaFluxTransaction:CancelAllOrders(string metafluxChain,address owner,bool hasAsset,uint32 asset,uint64 nonce)" as &[u8]
        );
        assert_eq!(without_owner.type_string(), account::CANCEL_ALL_ORDERS_TYPE);
        // (2) pinned owner-present digest.
        let d_owner = hex::encode(TypedActionDigest::new(&with_owner, 114514).to_digest());
        let d_plain = hex::encode(TypedActionDigest::new(&without_owner, 114514).to_digest());
        assert_eq!(
            d_owner,
            "c1d74d89c9b07b884ccde57768b17de760c6efb22fd59066c9595ad0cd8c45ba"
        );
        // (3) owner-present differs from owner-less; (4) owner-less == pre-owner KAT.
        assert_ne!(d_owner, d_plain);
        assert_eq!(
            d_plain,
            "9088140fe0311f99071e2c45e5eff506052fa787e6eb44e0d110a198fb5a3bf7"
        );
    }

    #[test]
    fn chain_tag_mapping() {
        assert_eq!(metaflux_chain_tag(8964), "Mainnet");
        assert_eq!(metaflux_chain_tag(114514), "Testnet");
        assert_eq!(metaflux_chain_tag(31337), "Devnet");
        assert_eq!(metaflux_chain_tag(7), "Devnet");
    }
}
