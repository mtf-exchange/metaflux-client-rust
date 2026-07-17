//! EIP-712 typed-action signing for the TRADING set (orders / cancels / TWAP /
//! batches) — the structured typed-action path for the formerly-opaque
//! actions. The node migrated the 12 trading actions to the typed scheme; the
//! opaque `MetaFluxAction` envelope is no longer admitted for them.
//!
//! Mirrors the TS SDK's `native/typed_orders.ts` field-for-field. Orders nest a
//! builder carve + a trigger block (both flattened into the signed struct),
//! sub-enums (side / kind / tif / stp / position_side / tpsl / grouping) are
//! EIP-712 `string`s carried VERBATIM in their snake_case (camelCase grouping)
//! wire form, the cloid is a `0x`-hex string (`""` when absent), and the batch
//! actions hash their item list as a `bytes32` (`keccak256(concat(item words))`).
//!
//! Atomic encoding (CONSENSUS-FROZEN — identical to the account set):
//! - `hashStruct(s) = keccak256(typeHash ‖ encodeData(s))`, `typeHash = keccak256(encodeType)`
//! - each field → one 32-byte word, declared order: uintN big-endian zero-padded;
//!   bool → uint8 0/1; address → 20 bytes right-aligned; string → keccak256(utf8);
//!   bytes32 (batch items) → keccak256(concat(element words))
//! - `digest = keccak256(0x19 0x01 ‖ domainSeparator ‖ hashStruct)`
//!
//! Optional fields flatten to sentinels (matching the server's wire→typed map):
//! cloid absent → `""`; no builder → fee 0 + zero address; one-way → position_side
//! `""`; no trigger → px 0, is_market false, tpsl `""`.

use tiny_keccak::{Hasher, Keccak};

use crate::error::ClientError;
use crate::types::order::{
    BatchCancel, BatchModify, BatchOrder, CancelByCloid, CancelOrder, Modify, Order, OrderGrouping,
    OrderKind, PositionSide, ScheduleCancel, Side, StpMode, TimeInForce, TpSl,
};
use crate::types::spot::{SpotCancel, SpotOrder};
use crate::types::twap::{TwapCancel, TwapOrder};
use crate::wallet::key::Address;
use crate::wallet::sign::Eip712;
use crate::wallet::typed::{metaflux_chain_tag, metaflux_domain_separator};

// ===== Encoder toolkit (restated locally so the module is self-contained) =====

fn keccak(input: &[u8]) -> [u8; 32] {
    let mut h = Keccak::v256();
    h.update(input);
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    out
}

/// `uint256(u64)` → big-endian, zero-left-padded to 32 bytes.
fn enc_u64(v: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&v.to_be_bytes());
    out
}

/// `uint256(u32)` → big-endian, zero-left-padded to 32 bytes.
fn enc_u32(v: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[28..].copy_from_slice(&v.to_be_bytes());
    out
}

/// `uint256(u16)` → big-endian, zero-left-padded to 32 bytes.
fn enc_u16(v: u16) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[30..].copy_from_slice(&v.to_be_bytes());
    out
}

/// `bool` → `uint8` `0`/`1`, zero-left-padded to 32 bytes.
fn enc_bool(v: bool) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[31] = u8::from(v);
    out
}

/// `string` → `keccak256(utf8)`.
fn enc_string(s: &str) -> [u8; 32] {
    keccak(s.as_bytes())
}

/// `bytes32[]`/`T[]` aggregate → `keccak256(concat of element 32-byte words))`.
fn hash_items(items: &[[u8; 32]]) -> [u8; 32] {
    let mut k = Keccak::v256();
    for w in items {
        k.update(w);
    }
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out
}

// ===== Sub-enum → canonical wire string =====

fn side_str(s: Side) -> &'static str {
    match s {
        Side::Bid => "bid",
        Side::Ask => "ask",
    }
}
fn kind_str(k: OrderKind) -> &'static str {
    match k {
        OrderKind::Limit => "limit",
        OrderKind::Market => "market",
        OrderKind::StopLoss => "stop_loss",
        OrderKind::TakeProfit => "take_profit",
    }
}
fn tif_str(t: TimeInForce) -> &'static str {
    match t {
        TimeInForce::Gtc => "gtc",
        TimeInForce::Ioc => "ioc",
        TimeInForce::Aon => "aon",
        TimeInForce::Alo => "alo",
    }
}
fn stp_str(s: StpMode) -> &'static str {
    match s {
        StpMode::CancelOldest => "cancel_oldest",
        StpMode::CancelNewest => "cancel_newest",
        StpMode::CancelBoth => "cancel_both",
        StpMode::Reject => "reject",
    }
}
fn position_side_str(p: PositionSide) -> &'static str {
    match p {
        PositionSide::Long => "long",
        PositionSide::Short => "short",
    }
}
fn tpsl_str(t: TpSl) -> &'static str {
    match t {
        TpSl::Tp => "tp",
        TpSl::Sl => "sl",
    }
}
fn grouping_str(g: OrderGrouping) -> &'static str {
    match g {
        OrderGrouping::Na => "na",
        OrderGrouping::NormalTpsl => "normalTpsl",
        OrderGrouping::PositionTpsl => "positionTpsl",
    }
}

/// `0x`-hex string for a cloid (matching the wire / TS form), `""` when absent.
fn cloid_str(c: Option<crate::types::Cloid>) -> String {
    c.map_or_else(String::new, |c| format!("0x{}", hex::encode(c.0)))
}

// ===== encodeType strings (CONSENSUS-FROZEN; byte-identical to node + TS) =====

const TY_SUBMIT_ORDER: &[u8] = b"MetaFluxTransaction:SubmitOrder(string metafluxChain,uint32 market,string side,string kind,uint64 size,uint64 limitPx,string tif,string stpMode,bool reduceOnly,string cloid,uint16 builderFee,address builderUser,string positionSide,uint64 triggerPx,bool triggerIsMarket,string triggerTpsl,uint64 nonce)";
const TY_CANCEL_ORDER: &[u8] =
    b"MetaFluxTransaction:CancelOrder(string metafluxChain,uint32 market,uint64 oid,uint64 nonce)";
const TY_SPOT_ORDER: &[u8] = b"MetaFluxTransaction:SpotOrder(string metafluxChain,uint32 pair,string side,uint64 size,uint64 limitPx,string tif,string stpMode,string cloid,uint64 nonce)";
const TY_SPOT_CANCEL: &[u8] =
    b"MetaFluxTransaction:SpotCancel(string metafluxChain,uint32 pair,uint64 oid,uint64 nonce)";
const TY_CANCEL_BY_CLOID: &[u8] = b"MetaFluxTransaction:CancelByCloid(string metafluxChain,uint32 asset,string cloid,uint64 nonce)";
const TY_MODIFY: &[u8] = b"MetaFluxTransaction:Modify(string metafluxChain,uint32 market,uint64 oid,bool hasNewPx,uint64 newPx,bool hasNewSize,uint64 newSize,string cloid,bool alwaysPlace,uint64 nonce)";
const TY_BATCH_MODIFY: &[u8] =
    b"MetaFluxTransaction:BatchModify(string metafluxChain,bytes32 modifications,uint64 nonce)";
const TY_SCHEDULE_CANCEL: &[u8] =
    b"MetaFluxTransaction:ScheduleCancel(string metafluxChain,uint64 cancelAtBlock,uint64 nonce)";
const TY_TWAP_ORDER: &[u8] = b"MetaFluxTransaction:TwapOrder(string metafluxChain,uint32 market,string side,uint64 totalSize,uint32 sliceCount,uint64 delayMs,bool reduceOnly,uint64 nonce)";
const TY_TWAP_CANCEL: &[u8] =
    b"MetaFluxTransaction:TwapCancel(string metafluxChain,uint64 twapId,uint64 nonce)";
const TY_BATCH_ORDER: &[u8] = b"MetaFluxTransaction:BatchOrder(string metafluxChain,address owner,bytes32 orders,string grouping,uint64 nonce)";
const TY_BATCH_CANCEL: &[u8] =
    b"MetaFluxTransaction:BatchCancel(string metafluxChain,bytes32 cancels,uint64 nonce)";

// ===== `*_WITH_OWNER` encodeType strings (agent-resolved owner; operator / vault
// trading) — CONSENSUS-FROZEN, byte-identical to the node's `*_WITH_OWNER_TYPE`.
//
// Used ONLY when the wire action carries an `owner`; the `owner` sits right after
// `metafluxChain`, before the action's own fields. Owner-ABSENT signs the base
// string above (byte-identical to the pre-owner digest).

const TY_SPOT_ORDER_WITH_OWNER: &[u8] = b"MetaFluxTransaction:SpotOrder(string metafluxChain,address owner,uint32 pair,string side,uint64 size,uint64 limitPx,string tif,string stpMode,string cloid,uint64 nonce)";
const TY_SPOT_CANCEL_WITH_OWNER: &[u8] = b"MetaFluxTransaction:SpotCancel(string metafluxChain,address owner,uint32 pair,uint64 oid,uint64 nonce)";
const TY_CANCEL_BY_CLOID_WITH_OWNER: &[u8] = b"MetaFluxTransaction:CancelByCloid(string metafluxChain,address owner,uint32 asset,string cloid,uint64 nonce)";
const TY_MODIFY_WITH_OWNER: &[u8] = b"MetaFluxTransaction:Modify(string metafluxChain,address owner,uint32 market,uint64 oid,bool hasNewPx,uint64 newPx,bool hasNewSize,uint64 newSize,string cloid,bool alwaysPlace,uint64 nonce)";
const TY_BATCH_MODIFY_WITH_OWNER: &[u8] =
    b"MetaFluxTransaction:BatchModify(string metafluxChain,address owner,bytes32 modifications,uint64 nonce)";
const TY_TWAP_CANCEL_WITH_OWNER: &[u8] =
    b"MetaFluxTransaction:TwapCancel(string metafluxChain,address owner,uint64 twapId,uint64 nonce)";
const TY_BATCH_CANCEL_WITH_OWNER: &[u8] =
    b"MetaFluxTransaction:BatchCancel(string metafluxChain,address owner,bytes32 cancels,uint64 nonce)";

// ===== Per-item word layouts =====

/// Flatten one perp order into its 15 signed struct-hash words. `owner` is NOT
/// part of the typed digest (the node's typed map omits it).
fn order_words(o: &Order) -> Vec<[u8; 32]> {
    let (builder_fee, builder_user) = o
        .builder
        .map_or((0u16, [0u8; 32]), |b| (b.fee, enc_addr_word(&b.user)));
    let (trigger_px, trigger_is_market, trigger_tpsl) = o.trigger.map_or((0u64, false, ""), |t| {
        (t.trigger_px, t.is_market, tpsl_str(t.tpsl))
    });
    let position_side = o.position_side.map_or("", position_side_str);
    vec![
        enc_u32(o.market.0),
        enc_string(side_str(o.side)),
        enc_string(kind_str(o.kind)),
        enc_u64(o.size),
        enc_u64(o.limit_px),
        enc_string(tif_str(o.tif)),
        enc_string(stp_str(o.stp_mode)),
        enc_bool(o.reduce_only),
        enc_string(&cloid_str(o.cloid)),
        enc_u16(builder_fee),
        builder_user,
        enc_string(position_side),
        enc_u64(trigger_px),
        enc_bool(trigger_is_market),
        enc_string(trigger_tpsl),
    ]
}

/// `address` → 20 bytes right-aligned in a 32-byte word.
fn enc_addr_word(a: &crate::wallet::key::Address) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(a.as_bytes());
    out
}

/// Flatten one modify into its 8 words. The SDK `Modify` addresses by oid, so
/// `cloid`/`always_place` take the server sentinels (`""` / false).
fn modify_words(m: &Modify) -> Vec<[u8; 32]> {
    let has_new_px = m.new_px.is_some();
    let has_new_size = m.new_size.is_some();
    vec![
        enc_u32(m.market.0),
        enc_u64(m.oid.0),
        enc_bool(has_new_px),
        enc_u64(m.new_px.unwrap_or(0)),
        enc_bool(has_new_size),
        enc_u64(m.new_size.unwrap_or(0)),
        enc_string(""),
        enc_bool(false),
    ]
}

/// Flatten one cancel into its 2 `(market, oid)` words. A cloid-only cancel has
/// no typed form (the digest binds `oid`).
fn cancel_words(c: &CancelOrder) -> Result<Vec<[u8; 32]>, ClientError> {
    let oid = c.oid.ok_or_else(|| {
        ClientError::Validation("a cloid-only cancel has no typed form (binds oid)".into())
    })?;
    Ok(vec![enc_u32(c.market.0), enc_u64(oid.0)])
}

// ===== The typed trading action =====

/// A trading action signable under the typed scheme. Borrows its payload.
#[derive(Clone, Copy, Debug)]
pub enum TypedTradingAction<'a> {
    /// `submit_order`.
    SubmitOrder(&'a Order),
    /// `cancel_order`.
    CancelOrder(&'a CancelOrder),
    /// `spot_order`.
    SpotOrder(&'a SpotOrder),
    /// `spot_cancel`.
    SpotCancel(&'a SpotCancel),
    /// `cancel_by_cloid`.
    CancelByCloid(&'a CancelByCloid),
    /// `modify`.
    Modify(&'a Modify),
    /// `batch_modify`.
    BatchModify(&'a BatchModify),
    /// `schedule_cancel`.
    ScheduleCancel(&'a ScheduleCancel),
    /// `twap_order`.
    TwapOrder(&'a TwapOrder),
    /// `twap_cancel`.
    TwapCancel(&'a TwapCancel),
    /// `batch_order`.
    BatchOrder(&'a BatchOrder),
    /// `batch_cancel`.
    BatchCancel(&'a BatchCancel),
}

impl TypedTradingAction<'_> {
    /// The frozen `encodeType` string for this action.
    #[must_use]
    pub fn type_string(&self) -> &'static [u8] {
        match self {
            Self::SubmitOrder(_) => TY_SUBMIT_ORDER,
            Self::CancelOrder(_) => TY_CANCEL_ORDER,
            Self::SpotOrder(_) => TY_SPOT_ORDER,
            Self::SpotCancel(_) => TY_SPOT_CANCEL,
            Self::CancelByCloid(_) => TY_CANCEL_BY_CLOID,
            Self::Modify(_) => TY_MODIFY,
            Self::BatchModify(_) => TY_BATCH_MODIFY,
            Self::ScheduleCancel(_) => TY_SCHEDULE_CANCEL,
            Self::TwapOrder(_) => TY_TWAP_ORDER,
            Self::TwapCancel(_) => TY_TWAP_CANCEL,
            Self::BatchOrder(_) => TY_BATCH_ORDER,
            Self::BatchCancel(_) => TY_BATCH_CANCEL,
        }
    }

    /// Whether this action has an owner-carrying (`*_WITH_OWNER`) typed form,
    /// used for operator / vault trading where the agent-resolved params-level
    /// `owner` differs from the signer. `submit_order` / `cancel_order` /
    /// `schedule_cancel` / `twap_order` have no owner form; `batch_order` carries
    /// its owner inside its own struct, not via the digest-level owner.
    const fn supports_owner(&self) -> bool {
        matches!(
            self,
            Self::SpotOrder(_)
                | Self::SpotCancel(_)
                | Self::CancelByCloid(_)
                | Self::Modify(_)
                | Self::BatchModify(_)
                | Self::TwapCancel(_)
                | Self::BatchCancel(_)
        )
    }

    /// The `encodeType` string for this action, selecting the `*_WITH_OWNER`
    /// shape when an agent-resolved `owner` is bound. Owner-absent (or an action
    /// with no owner form) returns the base [`Self::type_string`], byte-identical
    /// to the pre-owner digest.
    fn type_string_for(&self, owner: Option<&Address>) -> &'static [u8] {
        match (owner, self) {
            (Some(_), Self::SpotOrder(_)) => TY_SPOT_ORDER_WITH_OWNER,
            (Some(_), Self::SpotCancel(_)) => TY_SPOT_CANCEL_WITH_OWNER,
            (Some(_), Self::CancelByCloid(_)) => TY_CANCEL_BY_CLOID_WITH_OWNER,
            (Some(_), Self::Modify(_)) => TY_MODIFY_WITH_OWNER,
            (Some(_), Self::BatchModify(_)) => TY_BATCH_MODIFY_WITH_OWNER,
            (Some(_), Self::TwapCancel(_)) => TY_TWAP_CANCEL_WITH_OWNER,
            (Some(_), Self::BatchCancel(_)) => TY_BATCH_CANCEL_WITH_OWNER,
            _ => self.type_string(),
        }
    }

    /// The full ordered word list: chain tag first, then the agent-resolved
    /// `owner` (only for the owner-carrying actions), the action fields, and the
    /// nonce last. With `owner = None` the words are byte-identical to today.
    fn encode_data(
        &self,
        chain_tag: &str,
        nonce: u64,
        owner: Option<&Address>,
    ) -> Result<Vec<[u8; 32]>, ClientError> {
        let nonce_word = enc_u64(nonce);
        let mut words = vec![enc_string(chain_tag)];
        // The params-level `owner` sits right after `metafluxChain`, before the
        // action's own fields — mirroring the node's `*_WITH_OWNER` encoders.
        if let (Some(o), true) = (owner, self.supports_owner()) {
            words.push(enc_addr_word(o));
        }
        match self {
            Self::SubmitOrder(o) => words.extend(order_words(o)),
            Self::CancelOrder(c) => words.extend(cancel_words(c)?),
            Self::SpotOrder(o) => {
                words.push(enc_u32(o.pair));
                words.push(enc_string(side_str(o.side)));
                words.push(enc_u64(o.size));
                words.push(enc_u64(o.limit_px));
                words.push(enc_string(tif_str(o.tif)));
                words.push(enc_string(stp_str(o.stp_mode)));
                words.push(enc_string(&cloid_str(o.cloid)));
            }
            Self::SpotCancel(c) => {
                words.push(enc_u32(c.pair));
                words.push(enc_u64(c.oid));
            }
            Self::CancelByCloid(p) => {
                words.push(enc_u32(p.asset.0));
                words.push(enc_string(&cloid_str(Some(p.cloid))));
            }
            Self::Modify(m) => words.extend(modify_words(m)),
            Self::BatchModify(p) => {
                let items: Vec<[u8; 32]> = p.modifications.iter().flat_map(modify_words).collect();
                words.push(hash_items(&items));
            }
            Self::ScheduleCancel(p) => words.push(enc_u64(p.cancel_at_block)),
            Self::TwapOrder(p) => {
                words.push(enc_u32(p.market.0));
                words.push(enc_string(side_str(p.side)));
                words.push(enc_u64(p.total_size));
                words.push(enc_u32(p.slice_count));
                words.push(enc_u64(p.delay_ms));
                words.push(enc_bool(p.reduce_only));
            }
            Self::TwapCancel(p) => words.push(enc_u64(p.twap_id)),
            Self::BatchOrder(p) => {
                words.push(enc_addr_word(&p.owner)); // params-level owner (vault for operator trading)
                let items: Vec<[u8; 32]> = p.orders.iter().flat_map(order_words).collect();
                words.push(hash_items(&items));
                words.push(enc_string(grouping_str(p.grouping)));
            }
            Self::BatchCancel(p) => {
                let mut items: Vec<[u8; 32]> = Vec::new();
                for c in &p.cancels {
                    items.extend(cancel_words(c)?);
                }
                words.push(hash_items(&items));
            }
        }
        words.push(nonce_word);
        Ok(words)
    }

    /// `typeHash` for the selected (base or `*_WITH_OWNER`) type string, with the
    /// OPTIONAL top-level `expiresAfter` field folded in when non-zero. Mirrors
    /// the node's `folded_type_hash`: trailing `...,uint64 nonce)` becomes
    /// `...,uint64 nonce,uint64 expiresAfter)`. `expires_after == 0` returns the
    /// frozen type hash byte-for-byte.
    fn folded_type_hash(&self, owner: Option<&Address>, expires_after: u64) -> [u8; 32] {
        let base = self.type_string_for(owner);
        if expires_after == 0 {
            return keccak(base);
        }
        let suffix = b",uint64 expiresAfter)";
        let mut folded = Vec::with_capacity(base.len() - 1 + suffix.len());
        folded.extend_from_slice(&base[..base.len() - 1]);
        folded.extend_from_slice(suffix);
        keccak(&folded)
    }

    /// `hashStruct(s) = keccak256(typeHash ‖ encodeData(s))`, selecting the
    /// owner-carrying `typeHash` + words when `owner` is bound, and folding the
    /// OPTIONAL top-level `expiresAfter` when non-zero (extra trailing
    /// `uint256(expires_after)` word AFTER the nonce word). `expires_after == 0`
    /// is byte-identical to the pre-`expiresAfter` digest.
    fn hash_struct(
        &self,
        chain_tag: &str,
        nonce: u64,
        owner: Option<&Address>,
        expires_after: u64,
    ) -> Result<[u8; 32], ClientError> {
        let mut k = Keccak::v256();
        k.update(&self.folded_type_hash(owner, expires_after));
        for w in self.encode_data(chain_tag, nonce, owner)? {
            k.update(&w);
        }
        if expires_after != 0 {
            k.update(&enc_u64(expires_after));
        }
        let mut out = [0u8; 32];
        k.finalize(&mut out);
        Ok(out)
    }
}

/// EIP-712 wrapper binding a [`TypedTradingAction`] to a chain id + nonce.
///
/// The digest is `keccak256(0x19 0x01 ‖ domainSeparator ‖ hashStruct)`. Use
/// [`TypedTradingDigest::to_digest`] (panic-free encoding requires a valid
/// action — build via [`TypedTradingDigest::digest`] for the fallible form).
#[derive(Clone, Copy, Debug)]
pub struct TypedTradingDigest<'a> {
    action: TypedTradingAction<'a>,
    owner: Option<Address>,
    chain_id: u64,
    nonce: u64,
    expires_after: u64,
}

impl<'a> TypedTradingDigest<'a> {
    /// Bind `action` to `chain_id` + `nonce` (no agent-resolved owner). The
    /// digest is byte-identical to the pre-owner form.
    #[must_use]
    pub fn new(action: TypedTradingAction<'a>, chain_id: u64, nonce: u64) -> Self {
        Self {
            action,
            owner: None,
            chain_id,
            nonce,
            expires_after: 0,
        }
    }

    /// Attach an OPTIONAL top-level `expiresAfter` (consensus time in ms; `0` =
    /// never expires) to the signed digest. `0` reproduces the pre-`expiresAfter`
    /// digest BYTE-FOR-BYTE; non-zero folds the expiry in so a relay can neither
    /// strip nor alter it. Only admitted once the network activates the field.
    #[must_use]
    pub const fn with_expires_after(mut self, expires_after: u64) -> Self {
        self.expires_after = expires_after;
        self
    }

    /// Bind `action` to `chain_id` + `nonce` with an agent-resolved `owner`
    /// (operator / vault trading: the signer is an approved agent of `owner`).
    ///
    /// The `owner` enters the digest right after `metafluxChain` for the
    /// owner-carrying actions (`modify` / `batch_modify` / `batch_cancel` /
    /// `cancel_by_cloid` / `twap_cancel` / `spot_order` / `spot_cancel`),
    /// selecting the node's `*_WITH_OWNER` type string. For actions with no owner
    /// form the `owner` is ignored, so the digest stays byte-identical to
    /// [`TypedTradingDigest::new`].
    #[must_use]
    pub fn new_with_owner(
        action: TypedTradingAction<'a>,
        owner: Address,
        chain_id: u64,
        nonce: u64,
    ) -> Self {
        Self {
            action,
            owner: Some(owner),
            chain_id,
            nonce,
            expires_after: 0,
        }
    }

    /// Fallible 32-byte digest — errors if the action has no typed form (e.g. a
    /// cloid-only cancel). The infallible [`Eip712::to_digest`] returns a
    /// zero-oid digest in that case, so prefer this for cancels.
    pub fn digest(&self) -> Result<[u8; 32], ClientError> {
        let domain = metaflux_domain_separator(self.chain_id);
        let strukt = self.action.hash_struct(
            metaflux_chain_tag(self.chain_id),
            self.nonce,
            self.owner.as_ref(),
            self.expires_after,
        )?;
        let mut h = Keccak::v256();
        h.update(&[0x19, 0x01]);
        h.update(&domain);
        h.update(&strukt);
        let mut out = [0u8; 32];
        h.finalize(&mut out);
        Ok(out)
    }
}

impl Eip712 for TypedTradingDigest<'_> {
    fn domain_separator(&self) -> [u8; 32] {
        metaflux_domain_separator(self.chain_id)
    }

    fn struct_hash(&self) -> [u8; 32] {
        self.action
            .hash_struct(
                metaflux_chain_tag(self.chain_id),
                self.nonce,
                self.owner.as_ref(),
                self.expires_after,
            )
            .unwrap_or([0u8; 32])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::order::{Builder, Trigger};
    use crate::types::{Cloid, MarketId, OrderId};
    use crate::wallet::key::Address;

    const CHAIN: u64 = 114514;
    const NONCE: u64 = 1;

    fn hexd(action: TypedTradingAction) -> String {
        hex::encode(
            TypedTradingDigest::new(action, CHAIN, NONCE)
                .digest()
                .unwrap(),
        )
    }
    fn owner() -> Address {
        Address([0x11; 20])
    }
    fn cloid() -> Cloid {
        Cloid([0xAB; 16])
    }
    fn rich_order() -> Order {
        Order {
            owner: owner(),
            market: MarketId(7),
            side: Side::Ask,
            kind: OrderKind::TakeProfit,
            size: 500,
            limit_px: 0,
            tif: TimeInForce::Alo,
            stp_mode: StpMode::CancelOldest,
            reduce_only: true,
            cloid: Some(cloid()),
            builder: Some(Builder {
                fee: 25,
                user: Address([0x22; 20]),
            }),
            position_side: Some(PositionSide::Short),
            trigger: Some(Trigger {
                trigger_px: 4200,
                is_market: true,
                tpsl: TpSl::Tp,
            }),
        }
    }
    fn plain_order() -> Order {
        Order {
            owner: owner(),
            market: MarketId(1),
            side: Side::Bid,
            kind: OrderKind::Limit,
            size: 100,
            limit_px: 6_800_000_000_000,
            tif: TimeInForce::Gtc,
            stp_mode: StpMode::CancelNewest,
            reduce_only: false,
            cloid: None,
            builder: None,
            position_side: None,
            trigger: None,
        }
    }
    fn cancel(market: u32, oid: u64) -> CancelOrder {
        CancelOrder {
            owner: owner(),
            market: MarketId(market),
            oid: Some(OrderId(oid)),
            cloid: None,
        }
    }
    fn modify() -> Modify {
        Modify {
            market: MarketId(1),
            oid: OrderId(1234),
            new_px: Some(6_900_000_000_000),
            new_size: Some(200),
        }
    }

    // KAT vectors generated from @metaflux-dex/client (TS SDK, lockstep-verified
    // against the node) at chain 114514, nonce 1. Any drift = a consensus break.
    #[test]
    fn submit_order_kat() {
        assert_eq!(
            hexd(TypedTradingAction::SubmitOrder(&rich_order())),
            "a34651fda7e834d830ca185d30280b861e0ee811786b6ff14cb7ff2b8379fa9f"
        );
    }
    #[test]
    fn cancel_order_kat() {
        assert_eq!(
            hexd(TypedTradingAction::CancelOrder(&cancel(1, 1234))),
            "0e36f387b37eda4890fdae26770596e7995bb92b6407ece7095e50813431639a"
        );
    }
    #[test]
    fn spot_order_kat() {
        let o = SpotOrder {
            pair: 3,
            side: Side::Bid,
            size: 50,
            limit_px: 100_000_000,
            tif: TimeInForce::Ioc,
            stp_mode: StpMode::CancelOldest,
            cloid: Some(cloid()),
        };
        assert_eq!(
            hexd(TypedTradingAction::SpotOrder(&o)),
            "981902cfbf00fc9c9bb26acdebfe356cd0e2b8da69199ed9b8ae2a316cf1cb34"
        );
    }
    #[test]
    fn spot_cancel_kat() {
        let c = SpotCancel { pair: 3, oid: 99 };
        assert_eq!(
            hexd(TypedTradingAction::SpotCancel(&c)),
            "5f794c0c7a2c1b473efd5e86a4386385ce4696ad2cdc8d849eb9b30745c5f7fc"
        );
    }
    #[test]
    fn cancel_by_cloid_kat() {
        let p = CancelByCloid {
            asset: MarketId(1),
            cloid: cloid(),
        };
        assert_eq!(
            hexd(TypedTradingAction::CancelByCloid(&p)),
            "575fdab951085e30a1f260cae0a8fc2dfdc416247a3e4f5707a0b09d25a2fc24"
        );
    }
    #[test]
    fn modify_kat() {
        assert_eq!(
            hexd(TypedTradingAction::Modify(&modify())),
            "2ef6437095dd5d2a71265b78abe9ef5ef5db97d385d27e768225f326eff98d19"
        );
    }
    #[test]
    fn batch_modify_kat() {
        let p = BatchModify {
            modifications: vec![
                modify(),
                Modify {
                    market: MarketId(2),
                    oid: OrderId(5678),
                    new_px: None,
                    new_size: None,
                },
            ],
        };
        assert_eq!(
            hexd(TypedTradingAction::BatchModify(&p)),
            "c0914a0623f6032bdc85adb0b572fab74d8c5f775bef10455bcebd5454e3dd14"
        );
    }
    #[test]
    fn schedule_cancel_kat() {
        let p = ScheduleCancel {
            cancel_at_block: 1_000_000,
        };
        assert_eq!(
            hexd(TypedTradingAction::ScheduleCancel(&p)),
            "22938a65d68e2e4eceddd04ba345db0602822a901d7f3f6e8666f8fb20816a1d"
        );
    }
    #[test]
    fn twap_order_kat() {
        let p = TwapOrder {
            market: MarketId(1),
            side: Side::Bid,
            total_size: 10_000,
            slice_count: 5,
            delay_ms: 30_000,
            reduce_only: false,
        };
        assert_eq!(
            hexd(TypedTradingAction::TwapOrder(&p)),
            "3614120f4a58c58df65f36065ceb891646444e1e91ef26a78f4584a31e187638"
        );
    }
    #[test]
    fn twap_cancel_kat() {
        let p = TwapCancel { twap_id: 42 };
        assert_eq!(
            hexd(TypedTradingAction::TwapCancel(&p)),
            "08ebfec844ed708f1085d0251450503f309e0f44c450943227c4cf7e0b3a589f"
        );
    }
    #[test]
    fn batch_order_kat() {
        let p = BatchOrder {
            owner: owner(),
            orders: vec![plain_order(), rich_order()],
            grouping: OrderGrouping::NormalTpsl,
        };
        assert_eq!(
            hexd(TypedTradingAction::BatchOrder(&p)),
            // includes the params-level `owner` (added for operator/vault trading)
            "ef21c04ccb568652ab2d8950dffd1bd289acaafde846199f74a8ba72e0f5dad8"
        );
    }
    #[test]
    fn batch_cancel_kat() {
        let p = BatchCancel {
            cancels: vec![cancel(1, 1234), cancel(2, 5678)],
        };
        assert_eq!(
            hexd(TypedTradingAction::BatchCancel(&p)),
            "46d484036118744ef5996146ec9d35e1a54f550913238564831d5cc33d3af449"
        );
    }

    // ── agent-resolved `owner` (operator / vault trading) ──
    //
    // For each owner-carrying action: (1) the SDK's selected encodeType bytes
    // equal the node's `*_WITH_OWNER_TYPE` (literals copied verbatim from the
    // node's typed-order signing contract); (2) the owner-present digest matches the
    // pinned vector; (3) the owner-present digest DIFFERS from the owner-less one
    // (the owner is cryptographically bound); and (4) the owner-LESS digest is
    // byte-identical to the pre-owner KAT (backward compat). Owner = 0xbb..bb,
    // chain 114514, nonce 1 — same fixtures as the owner-less KATs above.

    /// The agent-resolved owner used by the `*_WITH_OWNER` vectors (`0xbb..bb`).
    fn owner_bind() -> Address {
        Address([0xbb; 20])
    }
    /// Owner-bound digest hex for `action`.
    fn hexd_owner(action: TypedTradingAction) -> String {
        hex::encode(
            TypedTradingDigest::new_with_owner(action, owner_bind(), CHAIN, NONCE)
                .digest()
                .unwrap(),
        )
    }

    #[test]
    fn modify_with_owner_kat() {
        let o = owner_bind();
        let a = TypedTradingAction::Modify(&modify());
        // (1) encodeType bytes == node MODIFY_WITH_OWNER_TYPE (verbatim).
        assert_eq!(
            a.type_string_for(Some(&o)),
            b"MetaFluxTransaction:Modify(string metafluxChain,address owner,uint32 market,uint64 oid,bool hasNewPx,uint64 newPx,bool hasNewSize,uint64 newSize,string cloid,bool alwaysPlace,uint64 nonce)" as &[u8]
        );
        // (2) pinned owner-present digest.
        assert_eq!(
            hexd_owner(a),
            "6c9f289d2785cd12fdad8f5933623cfcde275ba17f83d196dc667930577607a0"
        );
        // (3) differs from owner-less; (4) owner-less == pre-owner KAT.
        assert_ne!(hexd_owner(a), hexd(a));
        assert_eq!(
            hexd(a),
            "2ef6437095dd5d2a71265b78abe9ef5ef5db97d385d27e768225f326eff98d19"
        );
    }

    #[test]
    fn cancel_by_cloid_with_owner_kat() {
        let o = owner_bind();
        let p = CancelByCloid {
            asset: MarketId(1),
            cloid: cloid(),
        };
        let a = TypedTradingAction::CancelByCloid(&p);
        assert_eq!(
            a.type_string_for(Some(&o)),
            b"MetaFluxTransaction:CancelByCloid(string metafluxChain,address owner,uint32 asset,string cloid,uint64 nonce)" as &[u8]
        );
        assert_eq!(
            hexd_owner(a),
            "607915958cc50aa3688744ce281f477a2a13ed74f7b49dd3b24492c2ebd10d40"
        );
        assert_ne!(hexd_owner(a), hexd(a));
        assert_eq!(
            hexd(a),
            "575fdab951085e30a1f260cae0a8fc2dfdc416247a3e4f5707a0b09d25a2fc24"
        );
    }

    #[test]
    fn spot_order_with_owner_kat() {
        let o = owner_bind();
        let order = SpotOrder {
            pair: 3,
            side: Side::Bid,
            size: 50,
            limit_px: 100_000_000,
            tif: TimeInForce::Ioc,
            stp_mode: StpMode::CancelOldest,
            cloid: Some(cloid()),
        };
        let a = TypedTradingAction::SpotOrder(&order);
        assert_eq!(
            a.type_string_for(Some(&o)),
            b"MetaFluxTransaction:SpotOrder(string metafluxChain,address owner,uint32 pair,string side,uint64 size,uint64 limitPx,string tif,string stpMode,string cloid,uint64 nonce)" as &[u8]
        );
        assert_eq!(
            hexd_owner(a),
            "974960f541953bf10ad3677c41ebfa9d8cbeb90868f74ccdf44590327e7163fc"
        );
        assert_ne!(hexd_owner(a), hexd(a));
        assert_eq!(
            hexd(a),
            "981902cfbf00fc9c9bb26acdebfe356cd0e2b8da69199ed9b8ae2a316cf1cb34"
        );
    }

    #[test]
    fn spot_cancel_with_owner_kat() {
        let o = owner_bind();
        let c = SpotCancel { pair: 3, oid: 99 };
        let a = TypedTradingAction::SpotCancel(&c);
        assert_eq!(
            a.type_string_for(Some(&o)),
            b"MetaFluxTransaction:SpotCancel(string metafluxChain,address owner,uint32 pair,uint64 oid,uint64 nonce)" as &[u8]
        );
        assert_eq!(
            hexd_owner(a),
            "378a4b73e59a10e121c05f47c82f599147f66faf9ff6510d489d7baedfabb8f5"
        );
        assert_ne!(hexd_owner(a), hexd(a));
        assert_eq!(
            hexd(a),
            "5f794c0c7a2c1b473efd5e86a4386385ce4696ad2cdc8d849eb9b30745c5f7fc"
        );
    }

    #[test]
    fn batch_modify_with_owner_kat() {
        let o = owner_bind();
        let p = BatchModify {
            modifications: vec![
                modify(),
                Modify {
                    market: MarketId(2),
                    oid: OrderId(5678),
                    new_px: None,
                    new_size: None,
                },
            ],
        };
        let a = TypedTradingAction::BatchModify(&p);
        assert_eq!(
            a.type_string_for(Some(&o)),
            b"MetaFluxTransaction:BatchModify(string metafluxChain,address owner,bytes32 modifications,uint64 nonce)" as &[u8]
        );
        assert_eq!(
            hexd_owner(a),
            "a38064007bd676e1c7f524138bfd74853861a7e7ca8d971429bf16110ead06da"
        );
        assert_ne!(hexd_owner(a), hexd(a));
        assert_eq!(
            hexd(a),
            "c0914a0623f6032bdc85adb0b572fab74d8c5f775bef10455bcebd5454e3dd14"
        );
    }

    #[test]
    fn batch_cancel_with_owner_kat() {
        let o = owner_bind();
        let p = BatchCancel {
            cancels: vec![cancel(1, 1234), cancel(2, 5678)],
        };
        let a = TypedTradingAction::BatchCancel(&p);
        assert_eq!(
            a.type_string_for(Some(&o)),
            b"MetaFluxTransaction:BatchCancel(string metafluxChain,address owner,bytes32 cancels,uint64 nonce)" as &[u8]
        );
        assert_eq!(
            hexd_owner(a),
            "331396c719d6bbf49572ec3366a430b78eb5193d73c5475ccd204c8a6d681aef"
        );
        assert_ne!(hexd_owner(a), hexd(a));
        assert_eq!(
            hexd(a),
            "46d484036118744ef5996146ec9d35e1a54f550913238564831d5cc33d3af449"
        );
    }

    #[test]
    fn twap_cancel_with_owner_kat() {
        let o = owner_bind();
        let p = TwapCancel { twap_id: 42 };
        let a = TypedTradingAction::TwapCancel(&p);
        assert_eq!(
            a.type_string_for(Some(&o)),
            b"MetaFluxTransaction:TwapCancel(string metafluxChain,address owner,uint64 twapId,uint64 nonce)" as &[u8]
        );
        assert_eq!(
            hexd_owner(a),
            "2fe790c3e954f69cdd91734c4608c5568bf698a9ef19aa65f40356c3c0b9e3ce"
        );
        assert_ne!(hexd_owner(a), hexd(a));
        assert_eq!(
            hexd(a),
            "08ebfec844ed708f1085d0251450503f309e0f44c450943227c4cf7e0b3a589f"
        );
    }

    /// Actions with NO owner form (`submit_order` here) ignore a bound owner —
    /// the digest is byte-identical to the owner-less form (no `*_WITH_OWNER`).
    #[test]
    fn owner_ignored_for_actions_without_owner_form() {
        let order = rich_order();
        let a = TypedTradingAction::SubmitOrder(&order);
        assert_eq!(a.type_string_for(Some(&owner_bind())), a.type_string());
        assert_eq!(hexd_owner(a), hexd(a));
    }
}
