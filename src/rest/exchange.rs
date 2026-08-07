//! `/exchange` — signed write actions.
//!
//! Every write action here builds a node-accepted structured [`TypedAction`]
//! EIP-712 digest and posts the typed envelope `{ action, nonce, signature }`
//! to the typed-only `/exchange`. The node REJECTS the old opaque
//! `MetaFluxAction(string action,uint64 nonce)` scheme, so this module carries
//! NO opaque digest path: the plain convenience methods delegate to their typed
//! twins in the sibling [`crate::rest::exchange_typed`] module, which own the
//! structured digest + wire shape.
//!
//! ## EIP-712 domain
//!
//! Every typed action shares the MTF-native V1 domain (`name = "MetaFlux"`,
//! `version = "1"`, `chainId = <chain id>`, `verifyingContract = 0x0`); see
//! [`crate::wallet::metaflux_domain_separator`].
//!
//! [`TypedAction`]: crate::wallet::TypedAction
//!
//! ## One remaining legacy lane
//!
//! [`Exchange::submit_deploy_action`] still signs the legacy opaque
//! `MetaFluxAction(string action,uint64 nonce)` digest. It is retained ONLY for
//! the MIP-3 deploy actions (`submit_gas_auction_bid` / `perp_deploy` /
//! `spot_deploy`), which have NO typed-scheme variant yet. Every STANDARD
//! trading / account action signs the structured [`TypedAction`] digest.

use serde::Serialize;
use serde_json::{Value, json};
use tiny_keccak::{Hasher, Keccak};

use crate::error::ClientError;
use crate::rest::RestClient;
use crate::types::{
    account::{
        AgentSetAbstraction, ApproveAgent, ApproveBrokerFee, ApproveBuilderFee,
        ConvertToMultiSigUser, PriorityBid, SetDisplayName, SetReferrer, TopUpIsolatedOnlyMargin,
        UpdateIsolatedMargin, UpdateLeverage, UserPortfolioMargin, UserSetAbstraction,
    },
    chase::{CancelChaseParams, ChaseParams},
    encrypted::SubmitEncryptedOrder,
    fba::FbaSubmit,
    meta_bridge::MbWithdraw,
    order::{
        BatchCancel, BatchModify, BatchOrder, CancelAllOrders, CancelByCloid, CancelOrder, Modify,
        Order, OrderResponse, ScheduleCancel, TimeInForce,
    },
    rfq::{RfqAccept, RfqRequest},
    scale::{CancelScaleParams, ScaleDist, ScaleParams},
    spot::{
        EarnDeposit, EarnWithdraw, SpotCancel, SpotMarginClose, SpotMarginDeposit, SpotMarginOpen,
        SpotMarginWithdraw, SpotOrder,
    },
    staking::{ClaimRewards, LinkStakingUser, TokenDelegate},
    twap::{TwapCancel, TwapOrder},
    vault::{CreateVault, VaultDistribute, VaultKind, VaultModify, VaultTransfer, VaultWithdraw},
};
use crate::wallet::{Address, Eip712, Signature, TypedTradingAction, Wallet};

/// MetaFlux EIP-712 domain chain ids.
///
/// - **mainnet** `8964` (`0x2304`)
/// - **testnet** `114514` (`0x1bf52`) — the live devnet/testnet runs this,
///   so it is the SDK's default signing target today.
///
/// The chain id rides in the EIP-712 domain separator; the node enforces
/// the same value, so a mismatch makes every `POST /exchange` return 401.
pub const MTF_MAINNET_CHAIN_ID: u64 = 8964;

/// MTF testnet/devnet EIP-712 domain chain id. See [`MTF_MAINNET_CHAIN_ID`].
pub const MTF_TESTNET_CHAIN_ID: u64 = 114514;

/// Default MTF EIP-712 domain chain id. Aliases the testnet id, since the
/// live devnet/testnet is what the SDK signs against today.
pub const MTF_CHAIN_ID: u64 = MTF_TESTNET_CHAIN_ID;

/// `/exchange` namespace handle. Constructed via [`RestClient::exchange`].
///
/// Uses the global [`MTF_CHAIN_ID`] constant (= testnet [`MTF_TESTNET_CHAIN_ID`])
/// for EIP-712 domain construction. A builder field for selecting
/// [`MTF_MAINNET_CHAIN_ID`] will arrive when mainnet goes live.
#[derive(Debug)]
pub struct Exchange<'a> {
    pub(crate) client: &'a RestClient,
    /// OPTIONAL top-level action expiry (consensus time in ms) folded into every
    /// TYPED-scheme signed action this handle produces. `0` (the default) signs
    /// the pre-`expiresAfter` digest BYTE-FOR-BYTE; a non-zero value binds the
    /// expiry into the signature. Set via [`Exchange::with_expires_after`].
    ///
    /// A non-zero expiry is only admitted once the network activates the field.
    /// The legacy deploy lane ([`Exchange::submit_deploy_action`]) ignores this
    /// knob.
    pub(crate) expires_after_ms: u64,
}

impl<'a> Exchange<'a> {
    /// Return a copy of this handle that folds `expires_after_ms` (consensus time
    /// in ms; `0` = never expires) into every TYPED-scheme action it signs.
    ///
    /// One knob for all typed actions — no per-action argument. `0` reproduces the
    /// pre-`expiresAfter` digest byte-for-byte; a non-zero value is only accepted
    /// once the network activates the field, so leave it `0` until then.
    #[must_use]
    pub fn with_expires_after(mut self, expires_after_ms: u64) -> Self {
        self.expires_after_ms = expires_after_ms;
        self
    }
}

/// Envelope for the legacy opaque MIP-3 deploy lane
/// ([`Exchange::submit_deploy_action`]). The typed path builds its own envelope
/// in [`crate::rest::exchange_typed`].
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
        // A TP/SL-LIMIT trigger leg (`is_market = false`) fires a reduce-only GTC
        // at the order's `limit_px`; reject a zero price / non-GTC tif loud, not
        // as a silent market stop. No wire/digest change — both fields were always
        // signed.
        check_trigger_limit(order)?;
        // Coerce a Market order's tif to IOC before building the action JSON +
        // typed digest: the node lowers a Market kind to a limit, and a
        // Market+Gtc/Alo would silently REST on the book. See
        // `Order::coerce_market_tif`. Both the wire JSON and the signed digest
        // read this same coerced order, so the signed payload carries IOC.
        let order = order.market_tif_coerced();
        let action = json!({ "type": "submit_order", "order": &order });
        self.post_typed_trade(wallet, action, TypedTradingAction::SubmitOrder(&order))
            .await
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
        self.post_typed_trade(wallet, action, TypedTradingAction::CancelOrder(cancel))
            .await
    }

    /// Toggle the signing account's position mode (hedge / two-way vs one-way).
    ///
    /// `hedge = true` switches to two-way mode (independent long + short legs
    /// per market); `hedge = false` reverts to one-way. The node only accepts
    /// the switch while the account is **flat on every market** — otherwise it
    /// rejects the action. The signer authorizes the change: this call sends no
    /// `owner`, so the recovered signer is the target account.
    ///
    /// Once in hedge mode, every perp order MUST set
    /// [`crate::types::order::Order::position_side`].
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn set_position_mode(
        &self,
        wallet: &Wallet,
        hedge: bool,
    ) -> Result<Value, ClientError> {
        self.set_position_mode_typed(wallet, hedge).await
    }

    /// Submit a spot CLOB order.
    ///
    /// Ownership follows [`SpotOrder::owner`]. With `owner` present the signing
    /// `wallet` must be an approved AGENT of that address, and the node places
    /// the order AS the owner: the digest binds `owner` right after
    /// `metafluxChain` (the `SpotOrder` `*_WITH_OWNER` type string) and the wire
    /// body carries the same address. Absent, the signer trades for itself and
    /// both the digest and the posted bytes are unchanged.
    ///
    /// `tif` accepts `ioc` / `gtc` / `alo`; a `gtc` / `alo` residual rests on the
    /// book against escrowed funds. `limit_px` must be `> 0`.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn spot_order(
        &self,
        wallet: &Wallet,
        order: &SpotOrder,
    ) -> Result<OrderResponse, ClientError> {
        let action = json!({ "type": "spot_order", "order": order });
        self.post_typed_trade_bound(
            wallet,
            order.owner,
            action,
            TypedTradingAction::SpotOrder(order),
        )
        .await
    }

    /// Cancel a resting spot order by `oid`.
    ///
    /// Ownership follows [`SpotCancel::owner`], exactly as in
    /// [`Self::spot_order`]: present = an approved agent cancels AS that owner;
    /// absent = the signer cancels its own order.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn spot_cancel(
        &self,
        wallet: &Wallet,
        cancel: &SpotCancel,
    ) -> Result<Value, ClientError> {
        let action = json!({ "type": "spot_cancel", "cancel": cancel });
        self.post_typed_trade_bound(
            wallet,
            cancel.owner,
            action,
            TypedTradingAction::SpotCancel(cancel),
        )
        .await
    }

    /// **DEPRECATED — the node REJECTS this action.** Post quote collateral
    /// into an isolated spot-margin account.
    ///
    /// Dead surface. Spot margin is CROSS-collateralized against the one
    /// unified USDC account, so there is no per-pair collateral bucket to post
    /// into. The node rejects the action whenever the cross-margin model is
    /// active, which on the live chain is from genesis: `spot-margin is
    /// cross-collateralized against your USDC account; no separate deposit`.
    ///
    /// Use the account-wide flow instead: fund the unified USDC account, then
    /// open with [`Self::spot_margin_open`] and close with
    /// [`Self::spot_margin_close`]. Both draw against unified USDC directly.
    ///
    /// The action stays on the wire so old signatures stay verifiable. The
    /// [`SpotMarginDeposit`] type and its EIP-712 type string are kept for the
    /// same reason.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    #[deprecated(
        note = "the node rejects this action under cross-margin (live from genesis); fund the unified USDC account and use spot_margin_open / spot_margin_close"
    )]
    #[allow(deprecated)]
    pub async fn spot_margin_deposit(
        &self,
        wallet: &Wallet,
        params: &SpotMarginDeposit,
    ) -> Result<Value, ClientError> {
        self.spot_margin_deposit_typed(wallet, params.pair, params.amount.clone())
            .await
    }

    /// **DEPRECATED — the node REJECTS this action.** Withdraw free collateral
    /// from an isolated spot-margin account.
    ///
    /// Dead surface, the twin of [`Self::spot_margin_deposit`]. There is no
    /// per-pair collateral bucket to withdraw from under cross-margin. The node
    /// rejects the action whenever the cross-margin model is active, which on
    /// the live chain is from genesis: `spot-margin is cross-collateralized;
    /// withdraw USDC from your account directly`.
    ///
    /// Use the account-wide flow instead: close the position with
    /// [`Self::spot_margin_close`], then withdraw from the unified USDC account
    /// through the normal account lane ([`Self::mb_withdraw`]).
    ///
    /// The action stays on the wire so old signatures stay verifiable. The
    /// [`SpotMarginWithdraw`] type and its EIP-712 type string are kept for the
    /// same reason.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    #[deprecated(
        note = "the node rejects this action under cross-margin (live from genesis); close with spot_margin_close and withdraw from the unified USDC account"
    )]
    #[allow(deprecated)]
    pub async fn spot_margin_withdraw(
        &self,
        wallet: &Wallet,
        params: &SpotMarginWithdraw,
    ) -> Result<Value, ClientError> {
        self.spot_margin_withdraw_typed(wallet, params.pair, params.amount.clone())
            .await
    }

    /// Open a leveraged spot position: borrow quote from the pair's Earn pool
    /// and IOC-buy base on leverage.
    ///
    /// Sender-authorized. The borrow funds the buy 100%; the bought base is held
    /// segregated. Gated by the initial-margin requirement on the worst-case
    /// cost (`limit_px × size`). Returns the `202 Accepted` admission envelope.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn spot_margin_open(
        &self,
        wallet: &Wallet,
        params: &SpotMarginOpen,
    ) -> Result<Value, ClientError> {
        self.spot_margin_open_typed(
            wallet,
            params.pair,
            params.size,
            params.limit_px,
            params.borrow.clone(),
        )
        .await
    }

    /// Close a leveraged spot position: IOC-sell the held base, repay principal
    /// + interest to the Earn pool, return the remainder.
    ///
    /// Sender-authorized. A partial fill keeps the account open.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn spot_margin_close(
        &self,
        wallet: &Wallet,
        params: &SpotMarginClose,
    ) -> Result<Value, ClientError> {
        self.spot_margin_close_typed(wallet, params.pair, params.limit_px)
            .await
    }

    /// Supply quote into an Earn lending pool for pool shares.
    ///
    /// Sender-authorized. 1:1 on a fresh pool, else priced off pool NAV; the
    /// pool auto-creates on the first deposit. Returns the `202 Accepted`
    /// admission envelope — confirm via `/info` `earn_state`.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn earn_deposit(
        &self,
        wallet: &Wallet,
        params: &EarnDeposit,
    ) -> Result<Value, ClientError> {
        self.earn_deposit_typed(wallet, params.asset, params.amount.clone())
            .await
    }

    /// Redeem Earn pool shares back to quote.
    ///
    /// Sender-authorized. The payout is clamped to the pool's idle liquidity
    /// (`supplied − borrowed`); a redemption larger than idle pays exactly idle
    /// and burns proportionally fewer shares.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn earn_withdraw(
        &self,
        wallet: &Wallet,
        params: &EarnWithdraw,
    ) -> Result<Value, ClientError> {
        self.earn_withdraw_typed(wallet, params.asset, params.shares.clone())
            .await
    }

    // ---- order management ----

    /// Cancel a resting order by its client order id.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn cancel_by_cloid(
        &self,
        wallet: &Wallet,
        params: &CancelByCloid,
    ) -> Result<Value, ClientError> {
        let action = json!({ "type": "cancel_by_cloid", "params": params });
        self.post_typed_trade(wallet, action, TypedTradingAction::CancelByCloid(params))
            .await
    }

    /// As an approved agent, cancel a resting order of `owner` by its client
    /// order id — the operator / vault counterpart of [`Self::cancel_by_cloid`].
    ///
    /// The signing `wallet` is a registered agent of `owner`; the action cancels
    /// `owner`'s order (operator / vault trading), not the signer's. The signed
    /// digest binds `owner` right after `metafluxChain` (selecting the
    /// `CancelByCloid` `*_WITH_OWNER` type string), and the POST carries a
    /// params-level `owner` (`0x`-hex) so the node's `NativeCancelByCloid.owner`
    /// is set.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn cancel_by_cloid_as(
        &self,
        wallet: &Wallet,
        owner: Address,
        params: &CancelByCloid,
    ) -> Result<Value, ClientError> {
        let action = json!({ "type": "cancel_by_cloid", "params": params });
        self.post_typed_trade_as(
            wallet,
            owner,
            action,
            TypedTradingAction::CancelByCloid(params),
        )
        .await
    }

    /// Amend a resting order's price and/or size in place.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn modify(&self, wallet: &Wallet, params: &Modify) -> Result<Value, ClientError> {
        let action = json!({ "type": "modify", "params": params });
        self.post_typed_trade(wallet, action, TypedTradingAction::Modify(params))
            .await
    }

    /// As an approved agent, amend a resting order of `owner` in place — the
    /// operator / vault counterpart of [`Self::modify`].
    ///
    /// The signing `wallet` is a registered agent of `owner`; the action amends
    /// `owner`'s order (operator / vault trading), not the signer's. The signed
    /// digest binds `owner` right after `metafluxChain` (selecting the `Modify`
    /// `*_WITH_OWNER` type string), and the POST carries a params-level `owner`
    /// (`0x`-hex) so the node's `NativeModify.owner` is set.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn modify_as(
        &self,
        wallet: &Wallet,
        owner: Address,
        params: &Modify,
    ) -> Result<Value, ClientError> {
        let action = json!({ "type": "modify", "params": params });
        self.post_typed_trade_as(wallet, owner, action, TypedTradingAction::Modify(params))
            .await
    }

    /// Apply N modifications under one signature.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn batch_modify(
        &self,
        wallet: &Wallet,
        params: &BatchModify,
    ) -> Result<Value, ClientError> {
        let action = json!({ "type": "batch_modify", "params": params });
        self.post_typed_trade(wallet, action, TypedTradingAction::BatchModify(params))
            .await
    }

    /// As an approved agent, apply N modifications to `owner`'s resting orders
    /// under one signature — the operator / vault counterpart of
    /// [`Self::batch_modify`].
    ///
    /// The signing `wallet` is a registered agent of `owner`; the action amends
    /// `owner`'s orders (operator / vault trading), not the signer's. The signed
    /// digest binds `owner` right after `metafluxChain` (selecting the
    /// `BatchModify` `*_WITH_OWNER` type string), and the POST carries a
    /// params-level `owner` (`0x`-hex) so the node's `NativeBatchModify.owner`
    /// is set.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn batch_modify_as(
        &self,
        wallet: &Wallet,
        owner: Address,
        params: &BatchModify,
    ) -> Result<Value, ClientError> {
        let action = json!({ "type": "batch_modify", "params": params });
        self.post_typed_trade_as(
            wallet,
            owner,
            action,
            TypedTradingAction::BatchModify(params),
        )
        .await
    }

    /// Place N orders under one signature.
    ///
    /// Ownership is the params-level [`BatchOrder::owner`] (the gateway ignores
    /// per-order `owner`). For self-trading set `batch.owner = wallet.address()`.
    /// For operator-driven vault trading set `batch.owner` to the VAULT address;
    /// it may differ from the signer — the node authorizes the registered
    /// operator, so the SDK does NOT enforce owner == signer here.
    ///
    /// A committed batch returns SYNCHRONOUS per-leg statuses, like
    /// [`Exchange::submit_order`]: the node's order path covers `batch_order`
    /// and emits one `statuses` entry per PLACED leg, each echoing its own
    /// `cloid`. The return stays a raw [`Value`] for compatibility; for typed
    /// per-leg statuses use [`Exchange::place_order`]. A batch that has not
    /// committed inside the node's wait window returns one `pending` handle
    /// instead — track it via `/info` / WS.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn batch_order(
        &self,
        wallet: &Wallet,
        batch: &BatchOrder,
    ) -> Result<Value, ClientError> {
        // Reject any TP/SL-LIMIT leg with a zero price / non-GTC tif before signing
        // (same guard as `submit_order`).
        for o in &batch.orders {
            check_trigger_limit(o)?;
        }
        // Coerce every Market leg's tif to IOC before signing (a Market+Gtc/Alo
        // would rest on the book); see `BatchOrder::market_tifs_coerced`.
        let batch = batch.market_tifs_coerced();
        let action = json!({ "type": "batch_order", "params": &batch });
        self.post_typed_trade(wallet, action, TypedTradingAction::BatchOrder(&batch))
            .await
    }

    /// Apply N cancels under one signature. Each cancel's `owner` MUST equal the
    /// wallet address.
    ///
    /// # Errors
    /// - [`ClientError::Validation`] if any cancel's `owner != wallet.address()`.
    /// - HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn batch_cancel(
        &self,
        wallet: &Wallet,
        batch: &BatchCancel,
    ) -> Result<Value, ClientError> {
        for (i, c) in batch.cancels.iter().enumerate() {
            if c.owner != wallet.address() {
                return Err(ClientError::Validation(format!(
                    "batch cancel[{i}].owner {} != wallet address {}",
                    c.owner,
                    wallet.address()
                )));
            }
        }
        let action = json!({ "type": "batch_cancel", "params": batch });
        self.post_typed_trade(wallet, action, TypedTradingAction::BatchCancel(batch))
            .await
    }

    /// As an approved agent, apply N cancels to `owner`'s resting orders under
    /// one signature — the operator / vault counterpart of [`Self::batch_cancel`].
    ///
    /// The signing `wallet` is a registered agent of `owner`; the action cancels
    /// `owner`'s orders (operator / vault trading), not the signer's. Unlike
    /// [`Self::batch_cancel`], there is NO owner == signer guard — the node
    /// authorizes the registered operator, so each cancel's `owner` may differ
    /// from the signer. The signed digest binds `owner` right after
    /// `metafluxChain` (selecting the `BatchCancel` `*_WITH_OWNER` type string),
    /// and the POST carries a params-level `owner` (`0x`-hex) so the node's
    /// `NativeBatchCancel.owner` is set.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn batch_cancel_as(
        &self,
        wallet: &Wallet,
        owner: Address,
        batch: &BatchCancel,
    ) -> Result<Value, ClientError> {
        let action = json!({ "type": "batch_cancel", "params": batch });
        self.post_typed_trade_as(
            wallet,
            owner,
            action,
            TypedTradingAction::BatchCancel(batch),
        )
        .await
    }

    /// Schedule a cancel-all of the sender's open orders at a future block.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn schedule_cancel(
        &self,
        wallet: &Wallet,
        params: &ScheduleCancel,
    ) -> Result<Value, ClientError> {
        let action = json!({ "type": "schedule_cancel", "params": params });
        self.post_typed_trade(wallet, action, TypedTradingAction::ScheduleCancel(params))
            .await
    }

    /// Cancel all of the sender's open orders (optionally for a single asset).
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn cancel_all_orders(
        &self,
        wallet: &Wallet,
        params: &CancelAllOrders,
    ) -> Result<Value, ClientError> {
        self.cancel_all_orders_typed(wallet, params.asset.map(|m| m.0))
            .await
    }

    // ---- SCALE ladder (node-native; fork-gated `scale_order` feature) ----

    /// Place a SCALE ladder: one signed compact ladder the node expands
    /// DETERMINISTICALLY into `n` resting limit legs between `px_low` and
    /// `px_high` that all share the one `cloid`.
    ///
    /// Self-trading: the signing wallet owns the ladder (leave `params.owner`
    /// `None`). For operator / vault trading use [`Self::scale_order_as`].
    ///
    /// The wire `weights` array is emitted ONLY for `dist = custom` (empty for
    /// every derived distribution — the node rejects a non-empty one). A custom
    /// ladder MUST carry `weights.len() == n`.
    ///
    /// # Errors
    /// - [`ClientError::Validation`] if a custom ladder's `weights.len() != n`.
    /// - HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn scale_order(
        &self,
        wallet: &Wallet,
        params: &ScaleParams,
    ) -> Result<Value, ClientError> {
        let action = scale_order_action(params)?;
        self.post_typed_trade(wallet, action, TypedTradingAction::ScaleOrder(params))
            .await
    }

    /// As an approved agent, place a SCALE ladder OWNED by `owner` — the operator
    /// / vault counterpart of [`Self::scale_order`].
    ///
    /// The signing `wallet` is a registered agent of `owner`. This method sets
    /// `owner` on a copy of `params`, so the POSTed `params.owner` (`0x`-hex)
    /// and the signed digest come from the SAME value: the digest binds `owner`
    /// right after `metafluxChain` and selects the `ScaleOrder` `*_WITH_OWNER`
    /// type string. Equivalent to [`Self::scale_order`] with `params.owner` set.
    ///
    /// # Errors
    /// See [`Self::scale_order`].
    pub async fn scale_order_as(
        &self,
        wallet: &Wallet,
        owner: Address,
        params: &ScaleParams,
    ) -> Result<Value, ClientError> {
        let owned = ScaleParams {
            owner: Some(owner),
            ..params.clone()
        };
        let action = scale_order_action(&owned)?;
        self.post_typed_trade(wallet, action, TypedTradingAction::ScaleOrder(&owned))
            .await
    }

    /// Cancel every resting leg on `params.market` owned by the sender that
    /// carries `params.cloid` (cancel-all-by-cloid — the SCALE group cancel).
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn cancel_scale(
        &self,
        wallet: &Wallet,
        params: &CancelScaleParams,
    ) -> Result<Value, ClientError> {
        let action = json!({ "type": "cancel_scale", "params": params });
        self.post_typed_trade(wallet, action, TypedTradingAction::CancelScale(params))
            .await
    }

    /// As an approved agent, cancel `owner`'s SCALE ladder by cloid — the
    /// operator / vault counterpart of [`Self::cancel_scale`]. The owner rides
    /// on the params, exactly as in [`Self::scale_order_as`].
    ///
    /// # Errors
    /// See [`Self::cancel_scale`].
    pub async fn cancel_scale_as(
        &self,
        wallet: &Wallet,
        owner: Address,
        params: &CancelScaleParams,
    ) -> Result<Value, ClientError> {
        let owned = CancelScaleParams {
            owner: Some(owner),
            ..*params
        };
        let action = json!({ "type": "cancel_scale", "params": owned });
        self.post_typed_trade(wallet, action, TypedTradingAction::CancelScale(&owned))
            .await
    }

    // ---- CHASE re-pricer (node-native `chase_order` feature) ----

    /// Place a CHASE order: one signed intent the node keeps re-pricing to the
    /// top of book until it fills, expires (`ttl_ms`), or reaches `max_reprices`.
    ///
    /// Chase places a single post-only leg. Each reprice cancels the old leg and
    /// places a new leg under the SAME re-stamped `cloid` (only the leg oid
    /// changes). Correlate leg placements and fills by `cloid` on the existing
    /// `order_updates` / `open_orders` / `fills` feeds — there is no chase WS
    /// channel. The synchronous ack carries the `chase_oid` handle for
    /// [`Self::cancel_chase`].
    ///
    /// Self-trading: the signing wallet owns the chase (leave `params.owner`
    /// `None`). For operator / vault trading use [`Self::chase_order_as`]. Chase
    /// is perp markets only in v1.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn chase_order(
        &self,
        wallet: &Wallet,
        params: &ChaseParams,
    ) -> Result<Value, ClientError> {
        let action = json!({ "type": "chase_order", "params": params });
        self.post_typed_trade(wallet, action, TypedTradingAction::ChaseOrder(params))
            .await
    }

    /// As an approved agent, place a CHASE order OWNED by `owner` — the operator
    /// / vault counterpart of [`Self::chase_order`].
    ///
    /// The signing `wallet` is a registered agent of `owner`. This method sets
    /// `owner` on a copy of `params`, so the POSTed `params.owner` (`0x`-hex)
    /// and the signed digest come from the SAME value: the digest binds `owner`
    /// right after `metafluxChain` and selects the `ChaseOrder` `*_WITH_OWNER`
    /// type string. Equivalent to [`Self::chase_order`] with `params.owner` set.
    ///
    /// # Errors
    /// See [`Self::chase_order`].
    pub async fn chase_order_as(
        &self,
        wallet: &Wallet,
        owner: Address,
        params: &ChaseParams,
    ) -> Result<Value, ClientError> {
        let owned = ChaseParams {
            owner: Some(owner),
            ..params.clone()
        };
        let action = json!({ "type": "chase_order", "params": owned });
        self.post_typed_trade(wallet, action, TypedTradingAction::ChaseOrder(&owned))
            .await
    }

    /// Cancel a running CHASE by its registry handle (`params.chase_oid`, the
    /// handle from the placement ack — NOT the leg oid).
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn cancel_chase(
        &self,
        wallet: &Wallet,
        params: &CancelChaseParams,
    ) -> Result<Value, ClientError> {
        let action = json!({ "type": "cancel_chase", "params": params });
        self.post_typed_trade(wallet, action, TypedTradingAction::CancelChase(params))
            .await
    }

    /// As an approved agent, cancel `owner`'s CHASE by its handle — the operator
    /// / vault counterpart of [`Self::cancel_chase`]. The owner rides on the
    /// params, exactly as in [`Self::chase_order_as`].
    ///
    /// # Errors
    /// See [`Self::cancel_chase`].
    pub async fn cancel_chase_as(
        &self,
        wallet: &Wallet,
        owner: Address,
        params: &CancelChaseParams,
    ) -> Result<Value, ClientError> {
        let owned = CancelChaseParams {
            owner: Some(owner),
            ..*params
        };
        let action = json!({ "type": "cancel_chase", "params": owned });
        self.post_typed_trade(wallet, action, TypedTradingAction::CancelChase(&owned))
            .await
    }

    // ---- TWAP ----

    /// Submit a sliced (TWAP) order.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn twap_order(
        &self,
        wallet: &Wallet,
        params: &TwapOrder,
    ) -> Result<Value, ClientError> {
        let action = json!({ "type": "twap_order", "params": params });
        self.post_typed_trade(wallet, action, TypedTradingAction::TwapOrder(params))
            .await
    }

    /// Cancel a running TWAP parent by id.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn twap_cancel(
        &self,
        wallet: &Wallet,
        params: &TwapCancel,
    ) -> Result<Value, ClientError> {
        let action = json!({ "type": "twap_cancel", "params": params });
        self.post_typed_trade(wallet, action, TypedTradingAction::TwapCancel(params))
            .await
    }

    // ---- leverage & margin ----

    /// Set the per-asset leverage (and optionally flip to isolated margin).
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn update_leverage(
        &self,
        wallet: &Wallet,
        params: &UpdateLeverage,
    ) -> Result<Value, ClientError> {
        self.update_leverage_typed(wallet, params.asset.0, params.leverage, params.is_isolated)
            .await
    }

    /// Add or remove isolated margin on an open position.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn update_isolated_margin(
        &self,
        wallet: &Wallet,
        params: &UpdateIsolatedMargin,
    ) -> Result<Value, ClientError> {
        self.update_isolated_margin_typed(wallet, params.asset.0, params.delta.clone())
            .await
    }

    /// Top up the margin of a strict-isolated-only position.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn top_up_isolated_only_margin(
        &self,
        wallet: &Wallet,
        params: &TopUpIsolatedOnlyMargin,
    ) -> Result<Value, ClientError> {
        self.top_up_isolated_only_margin_typed(wallet, params.asset.0, params.amount.clone())
            .await
    }

    /// Enroll into or out of portfolio margin.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn user_portfolio_margin(
        &self,
        wallet: &Wallet,
        params: &UserPortfolioMargin,
    ) -> Result<Value, ClientError> {
        self.user_portfolio_margin_typed(wallet, params.enroll)
            .await
    }

    /// Enroll the signing account into portfolio margin.
    ///
    /// Convenience wrapper over [`Exchange::user_portfolio_margin`] with
    /// `enroll = true`. The node's `pm_enroll` action tag is an unmapped stub;
    /// this deliberately emits the bridged `user_portfolio_margin` action.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn pm_enroll(&self, wallet: &Wallet) -> Result<Value, ClientError> {
        self.user_portfolio_margin(wallet, &UserPortfolioMargin { enroll: true })
            .await
    }

    /// Unenroll the signing account from portfolio margin.
    ///
    /// Convenience wrapper over [`Exchange::user_portfolio_margin`] with
    /// `enroll = false`. The node's `pm_unenroll` action tag is an unmapped
    /// stub; this deliberately emits the bridged `user_portfolio_margin` action.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn pm_unenroll(&self, wallet: &Wallet) -> Result<Value, ClientError> {
        self.user_portfolio_margin(wallet, &UserPortfolioMargin { enroll: false })
            .await
    }

    // ---- account & agent settings ----

    /// Set the account display name (handle).
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn set_display_name(
        &self,
        wallet: &Wallet,
        params: &SetDisplayName,
    ) -> Result<Value, ClientError> {
        self.set_display_name_typed(wallet, params.display_name.clone())
            .await
    }

    /// Set the account referrer (one-time, immutable once set).
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn set_referrer(
        &self,
        wallet: &Wallet,
        params: &SetReferrer,
    ) -> Result<Value, ClientError> {
        self.set_referrer_typed(wallet, params.referrer).await
    }

    /// Approve an agent wallet to sign on behalf of this account.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn approve_agent(
        &self,
        wallet: &Wallet,
        params: &ApproveAgent,
    ) -> Result<Value, ClientError> {
        self.approve_agent_typed(
            wallet,
            params.agent,
            params.name.clone().unwrap_or_default(),
            params.expires_at_ms.unwrap_or(0),
        )
        .await
    }

    /// Approve a broker to charge a fee (up to `max_bps`) on this account's
    /// orders. `max_bps = 0` revokes.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn approve_broker_fee(
        &self,
        wallet: &Wallet,
        params: &ApproveBrokerFee,
    ) -> Result<Value, ClientError> {
        self.approve_broker_fee_typed(wallet, params.builder, params.max_bps)
            .await
    }

    /// Old name for [`Self::approve_broker_fee`].
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn approve_builder_fee(
        &self,
        wallet: &Wallet,
        params: &ApproveBuilderFee,
    ) -> Result<Value, ClientError> {
        self.approve_broker_fee(wallet, params).await
    }

    /// Convert the account to an M-of-N multisig.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn convert_to_multi_sig_user(
        &self,
        wallet: &Wallet,
        params: &ConvertToMultiSigUser,
    ) -> Result<Value, ClientError> {
        self.convert_to_multi_sig_user_typed(wallet, params.signers.clone(), params.threshold)
            .await
    }

    /// Set a self-scoped abstraction config value.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn user_set_abstraction(
        &self,
        wallet: &Wallet,
        params: &UserSetAbstraction,
    ) -> Result<Value, ClientError> {
        self.user_set_abstraction_typed(wallet, params.kind, params.value.clone())
            .await
    }

    /// As an approved agent, set an abstraction config value for `params.user`.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn agent_set_abstraction(
        &self,
        wallet: &Wallet,
        params: &AgentSetAbstraction,
    ) -> Result<Value, ClientError> {
        self.agent_set_abstraction_typed(wallet, params.user, params.kind, params.value.clone())
            .await
    }

    /// Pay a priority fee (bps) for block-front placement on an asset.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn priority_bid(
        &self,
        wallet: &Wallet,
        params: &PriorityBid,
    ) -> Result<Value, ClientError> {
        self.priority_bid_typed(wallet, params.asset.0, params.bid_bps)
            .await
    }

    // ---- staking ----

    /// Delegate stake to a validator, or queue an undelegation.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn token_delegate(
        &self,
        wallet: &Wallet,
        params: &TokenDelegate,
    ) -> Result<Value, ClientError> {
        self.token_delegate_typed(
            wallet,
            params.validator,
            params.amount.clone(),
            params.is_undelegate,
            params.lock_months,
        )
        .await
    }

    /// Claim accrued staking rewards.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn claim_rewards(
        &self,
        wallet: &Wallet,
        params: &ClaimRewards,
    ) -> Result<Value, ClientError> {
        self.claim_rewards_typed(wallet, params.validator.unwrap_or(Address::ZERO))
            .await
    }

    /// Alias another account as this account's staking target.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn link_staking_user(
        &self,
        wallet: &Wallet,
        params: &LinkStakingUser,
    ) -> Result<Value, ClientError> {
        self.link_staking_user_typed(wallet, params.target).await
    }

    // ---- encrypted orders ----

    /// Submit a threshold-encrypted order ciphertext.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn submit_encrypted_order(
        &self,
        wallet: &Wallet,
        params: &SubmitEncryptedOrder,
    ) -> Result<Value, ClientError> {
        self.submit_encrypted_order_typed(
            wallet,
            params.ciphertext.clone(),
            params.commitment,
            params.threshold,
            params.target_block,
            params.reveal_deadline_ms,
        )
        .await
    }

    // ---- vaults ----

    /// Create a new vault. The signing wallet becomes the leader.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn create_vault(
        &self,
        wallet: &Wallet,
        params: &CreateVault,
    ) -> Result<Value, ClientError> {
        // The typed `CreateVault` digest is TOP-LEVEL only: `params.parent` is
        // not part of the frozen type string and is dropped here.
        let kind = match params.kind {
            VaultKind::Metaliquidity => 1u8,
            VaultKind::User => 0u8,
        };
        self.create_vault_typed(wallet, params.name.clone(), params.lock_period_secs, kind)
            .await
    }

    /// Leader moves capital into or out of a vault.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn vault_transfer(
        &self,
        wallet: &Wallet,
        params: &VaultTransfer,
    ) -> Result<Value, ClientError> {
        self.vault_transfer_typed(
            wallet,
            params.vault_id.0,
            params.deposit,
            params.amount.clone(),
        )
        .await
    }

    /// Leader updates vault configuration.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn vault_modify(
        &self,
        wallet: &Wallet,
        params: &VaultModify,
    ) -> Result<Value, ClientError> {
        // The typed `VaultModify` digest binds only `newName`; the node's frozen
        // type string carries no lock-period / fee / paused fields, so those are
        // dropped here.
        self.vault_modify_typed(
            wallet,
            params.vault_id.0,
            params.new_name.clone().unwrap_or_default(),
        )
        .await
    }

    /// Follower redeems shares from a vault (subject to the per-vault lock).
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn vault_withdraw(
        &self,
        wallet: &Wallet,
        params: &VaultWithdraw,
    ) -> Result<Value, ClientError> {
        self.vault_withdraw_typed(wallet, params.vault_id.0, params.shares.clone())
            .await
    }

    /// Follower-deposit USD into a vault, minting shares at the current NAV
    /// (`vault_distribute`).
    ///
    /// The amount rides the `pnl` field (a legacy name on the node) as a
    /// positive decimal string, hashed verbatim.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn vault_distribute(
        &self,
        wallet: &Wallet,
        params: &VaultDistribute,
    ) -> Result<Value, ClientError> {
        self.vault_distribute_typed(wallet, params.vault_id.0, params.pnl.clone())
            .await
    }

    // ---- MetaBridge ----

    /// Withdraw cross-collateral to a destination chain.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn mb_withdraw(
        &self,
        wallet: &Wallet,
        params: &MbWithdraw,
    ) -> Result<Value, ClientError> {
        self.mb_withdraw_typed(
            wallet,
            params.chain,
            params.asset,
            params.amount,
            params.dst_addr.clone(),
        )
        .await
    }

    // ---- RFQ / FBA / encrypted ----
    //
    // These delegate to their typed twins, which own the node-accepted
    // `TypedAction` digest and the `{type, params}` wire shape. The node reads
    // the RFQ / FBA numeric fields as `u64`, so the wider `u128` / `i128` param
    // structs are range-checked on the way down.

    /// Open an RFQ session as a taker (`rfq_request`) under the typed scheme.
    ///
    /// # Errors
    /// - [`ClientError::Validation`] if `size` / `limit_px` exceed `u64`.
    /// - HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn rfq_request(
        &self,
        wallet: &Wallet,
        params: &RfqRequest,
    ) -> Result<Value, ClientError> {
        let size = u64::try_from(params.size)
            .map_err(|_| ClientError::Validation("rfq size overflows u64".into()))?;
        let limit_px = params
            .limit_px
            .map(u64::try_from)
            .transpose()
            .map_err(|_| ClientError::Validation("rfq limit_px out of u64 range".into()))?;
        self.rfq_request_typed(
            wallet,
            params.market.0,
            params.side,
            size,
            limit_px,
            params.expiry_ms,
            params.stp_group,
        )
        .await
    }

    /// Cross against a specific resting RFQ quote (`rfq_accept`) under the typed
    /// scheme.
    ///
    /// # Errors
    /// - [`ClientError::Validation`] if `size` exceeds `u64`.
    /// - HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn rfq_accept(
        &self,
        wallet: &Wallet,
        params: &RfqAccept,
    ) -> Result<Value, ClientError> {
        let size = u64::try_from(params.size)
            .map_err(|_| ClientError::Validation("rfq accept size overflows u64".into()))?;
        self.rfq_accept_typed(wallet, params.rfq_id.0, params.quote_idx, size)
            .await
    }

    /// Submit an order into a market's frequent-batch-auction pool
    /// (`fba_submit`) under the typed scheme.
    ///
    /// # Errors
    /// - [`ClientError::Validation`] if `size` / `price` exceed `u64`.
    /// - HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn fba_submit(
        &self,
        wallet: &Wallet,
        params: &FbaSubmit,
    ) -> Result<Value, ClientError> {
        let size = u64::try_from(params.size)
            .map_err(|_| ClientError::Validation("fba size overflows u64".into()))?;
        let price = u64::try_from(params.price)
            .map_err(|_| ClientError::Validation("fba price out of u64 range".into()))?;
        self.fba_submit_typed(
            wallet,
            params.market.0,
            params.side,
            size,
            price,
            params.stp_group,
        )
        .await
    }

    // --- Legacy opaque MIP-3 deploy lane ---

    /// Sign + POST a MIP-3 deploy-lane action under the LEGACY opaque
    /// `MetaFluxAction(string action,uint64 nonce)` digest.
    ///
    /// This is the ONE remaining opaque path. It exists ONLY for the MIP-3
    /// deploy actions (`submit_gas_auction_bid` / `perp_deploy` / `spot_deploy`),
    /// which have no typed-scheme variant. Do NOT use it for standard trading /
    /// account actions — those sign the structured [`crate::wallet::TypedAction`]
    /// digest through the dedicated methods in this module.
    ///
    /// # Errors
    /// - [`ClientError::Signature`] on signing failure.
    /// - HTTP / decode / protocol errors per [`crate::ClientError`].
    #[deprecated(
        note = "operator-injected lane; the node rejects this opaque digest at serde (400). Kept for reference only."
    )]
    pub async fn submit_deploy_action<R: serde::de::DeserializeOwned>(
        &self,
        wallet: &Wallet,
        action: Value,
    ) -> Result<R, ClientError> {
        let nonce = next_nonce();
        let digest = ActionSignedDigest {
            action: &action,
            nonce,
        };
        let signature = wallet.sign_eip712(&digest)?.to_hex();
        let envelope = SignedEnvelope {
            action: &action,
            nonce,
            signature,
        };
        self.client.post_json("/exchange", &envelope).await
    }
}

/// Legacy opaque EIP-712 digest for an `(action, nonce)` pair
/// (`MetaFluxAction(string action,uint64 nonce)` over the canonical-JSON action
/// body). Used ONLY by [`Exchange::submit_deploy_action`]; the typed path lives
/// in [`crate::wallet::TypedActionDigest`].
struct ActionSignedDigest<'a> {
    action: &'a Value,
    nonce: u64,
}

impl Eip712 for ActionSignedDigest<'_> {
    fn domain_separator(&self) -> [u8; 32] {
        let type_hash = keccak(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                .as_bytes(),
        );
        let name_hash = keccak("MetaFlux".as_bytes());
        let version_hash = keccak("1".as_bytes());
        let mut buf = Vec::with_capacity(32 * 5);
        buf.extend_from_slice(&type_hash);
        buf.extend_from_slice(&name_hash);
        buf.extend_from_slice(&version_hash);
        let mut chain_be = [0u8; 32];
        chain_be[24..].copy_from_slice(&MTF_CHAIN_ID.to_be_bytes());
        buf.extend_from_slice(&chain_be);
        buf.extend_from_slice(&[0u8; 32]); // verifyingContract = 0x0, left-padded.
        keccak(&buf)
    }

    fn struct_hash(&self) -> [u8; 32] {
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

/// TP/SL-LIMIT client guard: a trigger leg with `is_market = false` fires a
/// reduce-only GTC limit at the order's own `limit_px`. Reject a zero price or a
/// non-GTC tif LOUD — a zero price would refire-reject forever, and a non-GTC tif
/// (e.g. `alo`) would dead-loop at fire. A market trigger (`is_market = true`) or
/// a plain order (no trigger) passes unchanged. No wire / digest change — both
/// `is_market` and `limit_px` were always in the signed order.
fn check_trigger_limit(o: &Order) -> Result<(), ClientError> {
    if let Some(t) = o.trigger {
        if !t.is_market {
            if o.limit_px == 0 {
                return Err(ClientError::Validation(
                    "TP/SL-LIMIT trigger needs limit_px > 0 (the fired resting price)".into(),
                ));
            }
            if o.tif != TimeInForce::Gtc {
                return Err(ClientError::Validation(
                    "TP/SL-LIMIT trigger needs tif = gtc".into(),
                ));
            }
        }
    }
    Ok(())
}

/// Build the `scale_order` wire action JSON, enforcing the custom-weights rule
/// and emitting the `weights` array ONLY for `dist = custom`. Every derived
/// distribution carries an EMPTY array — the node's F1 shared-lowering guard
/// rejects a non-custom order that carries non-empty weights.
fn scale_order_action(params: &ScaleParams) -> Result<Value, ClientError> {
    let mut v = serde_json::to_value(params)
        .map_err(|e| ClientError::Validation(format!("scale params serialize: {e}")))?;
    if matches!(params.dist, ScaleDist::Custom) {
        if params.weights.len() as u64 != u64::from(params.n) {
            return Err(ClientError::Validation(format!(
                "custom scale ladder needs weights.len() == n (got {} weights, n = {})",
                params.weights.len(),
                params.n
            )));
        }
    } else {
        v["weights"] = json!([]);
    }
    Ok(json!({ "type": "scale_order", "params": v }))
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
pub(crate) fn next_nonce() -> u64 {
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

/// Test-only escape hatch: the LEGACY opaque digest for the MIP-3 deploy lane
/// ([`Exchange::submit_deploy_action`]). Used by the deploy-lane tests under
/// `tests/`. Not part of the stable public API — standard actions sign the
/// typed digest (see [`crate::rest::exchange_typed::_typed_digest_for_test`]).
#[doc(hidden)]
pub fn _action_digest_for_test(action: &Value, nonce: u64) -> [u8; 32] {
    ActionSignedDigest { action, nonce }.to_digest()
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
