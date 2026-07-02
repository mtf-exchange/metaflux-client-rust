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
//! schema (matches the gateway's signed-action decoder).

use serde::Serialize;
use serde_json::{Value, json};
use tiny_keccak::{Hasher, Keccak};

use crate::error::ClientError;
use crate::rest::RestClient;
use crate::types::{
    account::{
        AgentSetAbstraction, ApproveAgent, ApproveBuilderFee, ConvertToMultiSigUser, PriorityBid,
        SetDisplayName, SetReferrer, TopUpIsolatedOnlyMargin, UpdateIsolatedMargin, UpdateLeverage,
        UserDexAbstraction, UserPortfolioMargin, UserSetAbstraction,
    },
    cross_chain::CrossChainSend,
    encrypted::{EncryptedOrderSubmit, SubmitEncryptedOrder},
    fba::FbaSubmit,
    governance::{REDACTED, SetMetaliquidityWhitelist},
    meta_bridge::MbWithdraw,
    order::{
        BatchCancel, BatchModify, BatchOrder, CancelAllOrders, CancelByCloid, CancelOrder, Modify,
        Order, OrderResponse, ScheduleCancel,
    },
    rfq::{RfqAccept, RfqRequest},
    spot::{
        EarnDeposit, EarnWithdraw, SpotCancel, SpotMarginClose, SpotMarginDeposit, SpotMarginOpen,
        SpotMarginWithdraw, SpotOrder,
    },
    staking::{ClaimRewards, LinkStakingUser, TokenDelegate},
    twap::{TwapCancel, TwapOrder},
    vault::{CreateVault, VaultDistribute, VaultModify, VaultTransfer, VaultWithdraw},
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
    /// rejects the action. The signer authorizes the change; the params carry
    /// no address (the recovered signer is the target account).
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
        let action = json!({ "type": "set_position_mode", "params": { "hedge": hedge } });
        self.post_signed(wallet, action).await
    }

    /// Submit a spot CLOB order.
    ///
    /// The signing account is the order owner — the spot order body carries no
    /// owner field; the node binds the order to the recovered signer. v0 is IOC
    /// limit only (`tif = ioc`, `limit_px > 0`); see [`SpotOrder::ioc_limit`].
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn spot_order(
        &self,
        wallet: &Wallet,
        order: &SpotOrder,
    ) -> Result<OrderResponse, ClientError> {
        let action = json!({ "type": "spot_order", "order": order });
        self.post_typed_trade(wallet, action, TypedTradingAction::SpotOrder(order))
            .await
    }

    /// Cancel a resting spot order by `oid`.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn spot_cancel(
        &self,
        wallet: &Wallet,
        cancel: &SpotCancel,
    ) -> Result<Value, ClientError> {
        let action = json!({ "type": "spot_cancel", "cancel": cancel });
        self.post_typed_trade(wallet, action, TypedTradingAction::SpotCancel(cancel))
            .await
    }

    /// Post quote collateral into a spot-margin account (spot margin / Earn,
    /// devnet preview).
    ///
    /// Sender-authorized: the recovered signer is the actor (no owner field).
    /// Margin must be enabled for the pair, else the node rejects. Returns the
    /// `202 Accepted` admission envelope — confirm via `/info` `spot_margin_state`.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn spot_margin_deposit(
        &self,
        wallet: &Wallet,
        params: &SpotMarginDeposit,
    ) -> Result<Value, ClientError> {
        let action = json!({ "type": "spot_margin_deposit", "params": params });
        self.post_signed(wallet, action).await
    }

    /// Withdraw free collateral from a spot-margin account.
    ///
    /// Sender-authorized. Full collateral is withdrawable while flat; an open
    /// position gates the withdraw at the initial-margin requirement.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn spot_margin_withdraw(
        &self,
        wallet: &Wallet,
        params: &SpotMarginWithdraw,
    ) -> Result<Value, ClientError> {
        let action = json!({ "type": "spot_margin_withdraw", "params": params });
        self.post_signed(wallet, action).await
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
        let action = json!({ "type": "spot_margin_open", "params": params });
        self.post_signed(wallet, action).await
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
        let action = json!({ "type": "spot_margin_close", "params": params });
        self.post_signed(wallet, action).await
    }

    /// Supply quote into an Earn lending pool for pool shares (devnet preview).
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
        let action = json!({ "type": "earn_deposit", "params": params });
        self.post_signed(wallet, action).await
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
        let action = json!({ "type": "earn_withdraw", "params": params });
        self.post_signed(wallet, action).await
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
    /// operator, so the SDK does NOT enforce owner == signer here. Unlike
    /// [`Exchange::submit_order`], a batch returns the admission envelope (not a
    /// synchronous per-order status); observe fills via `/info` / WS.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn batch_order(
        &self,
        wallet: &Wallet,
        batch: &BatchOrder,
    ) -> Result<Value, ClientError> {
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
        let action = json!({ "type": "cancel_all_orders", "params": params });
        self.post_signed(wallet, action).await
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
        let action = json!({ "type": "update_leverage", "params": params });
        self.post_signed(wallet, action).await
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
        let action = json!({ "type": "update_isolated_margin", "params": params });
        self.post_signed(wallet, action).await
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
        let action = json!({ "type": "top_up_isolated_only_margin", "params": params });
        self.post_signed(wallet, action).await
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
        let action = json!({ "type": "user_portfolio_margin", "params": params });
        self.post_signed(wallet, action).await
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
        let action = json!({ "type": "set_display_name", "params": params });
        self.post_signed(wallet, action).await
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
        let action = json!({ "type": "set_referrer", "params": params });
        self.post_signed(wallet, action).await
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
        let action = json!({ "type": "approve_agent", "params": params });
        self.post_signed(wallet, action).await
    }

    /// Approve a builder to charge a fee (up to `max_bps`) on this account's
    /// orders. `max_bps = 0` revokes.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn approve_builder_fee(
        &self,
        wallet: &Wallet,
        params: &ApproveBuilderFee,
    ) -> Result<Value, ClientError> {
        let action = json!({ "type": "approve_builder_fee", "params": params });
        self.post_signed(wallet, action).await
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
        let action = json!({ "type": "convert_to_multi_sig_user", "params": params });
        self.post_signed(wallet, action).await
    }

    /// Toggle the account's DEX-abstraction opt-in flag.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn user_dex_abstraction(
        &self,
        wallet: &Wallet,
        params: &UserDexAbstraction,
    ) -> Result<Value, ClientError> {
        let action = json!({ "type": "user_dex_abstraction", "params": params });
        self.post_signed(wallet, action).await
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
        let action = json!({ "type": "user_set_abstraction", "params": params });
        self.post_signed(wallet, action).await
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
        let action = json!({ "type": "agent_set_abstraction", "params": params });
        self.post_signed(wallet, action).await
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
        let action = json!({ "type": "priority_bid", "params": params });
        self.post_signed(wallet, action).await
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
        let action = json!({ "type": "token_delegate", "params": params });
        self.post_signed(wallet, action).await
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
        let action = json!({ "type": "claim_rewards", "params": params });
        self.post_signed(wallet, action).await
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
        let action = json!({ "type": "link_staking_user", "params": params });
        self.post_signed(wallet, action).await
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
        let action = json!({ "type": "submit_encrypted_order", "params": params });
        self.post_signed(wallet, action).await
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
        let action = json!({ "type": "create_vault", "params": params });
        self.post_signed(wallet, action).await
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
        let action = json!({ "type": "vault_transfer", "params": params });
        self.post_signed(wallet, action).await
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
        let action = json!({ "type": "vault_modify", "params": params });
        self.post_signed(wallet, action).await
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
        let action = json!({ "type": "vault_withdraw", "params": params });
        self.post_signed(wallet, action).await
    }

    /// Follower-deposit USD into a vault, minting shares at the current NAV
    /// (`vault_distribute`).
    ///
    /// The amount rides the `pnl` field (a legacy name on the node) as a
    /// positive decimal string. **Forward-compat:** the node currently returns
    /// `UnsupportedAction` for this tag on `/exchange` until it bridges the
    /// `vault_distribute` handler; the SDK emits the byte-correct wire shape.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn vault_distribute(
        &self,
        wallet: &Wallet,
        params: &VaultDistribute,
    ) -> Result<Value, ClientError> {
        let action = json!({ "type": "vault_distribute", "params": params });
        self.post_signed(wallet, action).await
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
        let action = json!({ "type": "mb_withdraw", "params": params });
        self.post_signed(wallet, action).await
    }

    // ---- governance / operator ----

    /// Set a metaliquidity-provider whitelist membership (validator-authorized).
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn REDACTED(
        &self,
        wallet: &Wallet,
        params: &SetMetaliquidityWhitelist,
    ) -> Result<Value, ClientError> {
        let action = json!({ "type": "REDACTED", "params": params });
        self.post_signed(wallet, action).await
    }

    /// Register or revoke an external strategy operator for a vault
    /// (vault-leader-authorized).
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn REDACTED(
        &self,
        wallet: &Wallet,
        params: &REDACTED,
    ) -> Result<Value, ClientError> {
        let action = json!({ "type": "REDACTED", "params": params });
        self.post_signed(wallet, action).await
    }

    // ---- RFQ / FBA / cross-chain / encrypted (forward-compat) ----
    //
    // The node recognizes these action tags but currently lowers them to
    // `UnsupportedAction` on the public `/exchange` path (the real handlers run
    // on the EVM core-writer path). The SDK emits the byte-correct wire shape
    // each core param struct expects, so these become live the moment the node
    // bridges them — no SDK change required. Note the per-action wrapper keys
    // differ (`rfq` / `accept` / `submit` / `msg` / `encrypted`).

    /// Open an RFQ session as a taker (`rfq_request`). Wrapper key is `rfq`.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn rfq_request(
        &self,
        wallet: &Wallet,
        params: &RfqRequest,
    ) -> Result<Value, ClientError> {
        let action = json!({ "type": "rfq_request", "rfq": params });
        self.post_signed(wallet, action).await
    }

    /// Cross against a specific resting RFQ quote (`rfq_accept`). Wrapper key is
    /// `accept`.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn rfq_accept(
        &self,
        wallet: &Wallet,
        params: &RfqAccept,
    ) -> Result<Value, ClientError> {
        let action = json!({ "type": "rfq_accept", "accept": params });
        self.post_signed(wallet, action).await
    }

    /// Submit an order into a market's frequent-batch-auction pool
    /// (`fba_submit`). Wrapper key is `submit`.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn fba_submit(
        &self,
        wallet: &Wallet,
        params: &FbaSubmit,
    ) -> Result<Value, ClientError> {
        let action = json!({ "type": "fba_submit", "submit": params });
        self.post_signed(wallet, action).await
    }

    /// Initiate a chain-agnostic cross-chain transfer (`cross_chain_send`).
    /// Wrapper key is `msg`.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn cross_chain_send(
        &self,
        wallet: &Wallet,
        params: &CrossChainSend,
    ) -> Result<Value, ClientError> {
        let action = json!({ "type": "cross_chain_send", "msg": params });
        self.post_signed(wallet, action).await
    }

    /// Submit a threshold-encrypted order via the `encrypted_order_submit` tag.
    /// Wrapper key is `encrypted`.
    ///
    /// Distinct from [`Exchange::submit_encrypted_order`], which targets a
    /// different (bridged) core handler with a 5-field payload.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn encrypted_order_submit(
        &self,
        wallet: &Wallet,
        params: &EncryptedOrderSubmit,
    ) -> Result<Value, ClientError> {
        let action = json!({ "type": "encrypted_order_submit", "encrypted": params });
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
        let (nonce, signature) = sign_action(wallet, &action)?;
        let envelope = SignedEnvelope {
            action: &action,
            nonce,
            signature,
        };
        // `/exchange` is the node's MTF-native signed-action front door. The
        // `{action, nonce, signature}` envelope + EIP-712-over-canonical-JSON
        // digest match the server's handler byte-for-byte (cross-impl KAT in
        // this module pins it).
        self.client.post_json("/exchange", &envelope).await
    }
}

/// Sign an action with a fresh monotonic nonce, returning `(nonce, 0x-hex
/// signature)`.
///
/// This is the one signing primitive shared by the REST `POST /exchange` path
/// ([`Exchange::post_signed`]) and the WebSocket `post` action path
/// ([`crate::ws::WsClient::post_action`]). Both recover the signer over the
/// **compact `serde_json` serialization of the action object**, so a single
/// helper guarantees the two transports sign byte-identical digests.
pub(crate) fn sign_action(wallet: &Wallet, action: &Value) -> Result<(u64, String), ClientError> {
    let nonce = next_nonce();
    let digest = ActionSignedDigest { action, nonce };
    let sig = wallet.sign_eip712(&digest)?;
    Ok((nonce, sig.to_hex()))
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
        // byte-for-byte mirroring the server's domain separator.
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
    /// 5-field) + digest FORMULA against the server's committed native-action
    /// KAT value.
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

        // Server's committed native-action KAT value, recomputed for the MTF
        // testnet chain id 114514 (MTF_CHAIN_ID):
        // f7aa1087f79b30fb3f13a190636d32b32720d5984191992d707e2afbca716e0d
        let expected: [u8; 32] = [
            0xf7, 0xaa, 0x10, 0x87, 0xf7, 0x9b, 0x30, 0xfb, 0x3f, 0x13, 0xa1, 0x90, 0x63, 0x6d,
            0x32, 0xb3, 0x27, 0x20, 0xd5, 0x98, 0x41, 0x91, 0x99, 0x2d, 0x70, 0x7e, 0x2a, 0xfb,
            0xca, 0x71, 0x6e, 0x0d,
        ];
        assert_eq!(
            digest, expected,
            "SDK digest must equal server KAT f7aa10..6e0d; got {digest:02x?}"
        );
    }
}
