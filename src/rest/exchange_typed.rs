//! Structured (typed-scheme) `/exchange` signed actions.
//!
//! These extend [`Exchange`] with the structured EIP-712 signing path: each
//! action is signed as a named [`TypedAction`] struct (so wallets render its
//! fields), and the POST posts to the typed-only `/exchange`. Decimal magnitudes are
//! signed AND posted as the identical canonical string, since the server hashes
//! the received string before parsing it.
//!
//! Everything not in this typed set keeps the opaque legacy scheme on
//! [`Exchange`] in the sibling module.

use serde::Serialize;
use serde_json::{Value, json};

use crate::error::ClientError;
use crate::rest::exchange::{Exchange, MTF_CHAIN_ID, next_nonce};
use crate::types::defi::BorrowLendKind;
use crate::wallet::{
    Eip712, TypedAction, TypedActionDigest, TypedTradingAction, TypedTradingDigest, Wallet,
    metaflux_chain_tag,
};

/// A typed-scheme signed action ready to POST to `/exchange`.
///
/// Posts to the typed-only `/exchange`; the structured EIP-712 path is the
/// server, alongside the `{ type, params }` action object whose decimal fields
/// are the exact canonical strings that were hashed.
#[derive(Clone, Debug, Serialize)]
struct TypedSignedEnvelope<'a> {
    action: &'a Value,
    nonce: u64,
    signature: String,
    /// OPTIONAL top-level action expiry (consensus time in ms). Omitted from the
    /// wire when `0`/absent so the bytes are byte-identical to the
    /// pre-`expiresAfter` envelope; present (and folded into the signed digest)
    /// only when non-zero.
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_after: Option<u64>,
}

/// Map a [`crate::types::meta_bridge::BridgeChain`] to the `uint8` the typed `BridgeWithdraw` digest
/// signs (`Base = 1`, `Arbitrum = 2`). This is independent of the
/// wire string name, which is still PascalCase in the POST params.
fn mb_chain_to_u8(chain: crate::types::meta_bridge::BridgeChain) -> u8 {
    match chain {
        crate::types::meta_bridge::BridgeChain::Base => 1,
        crate::types::meta_bridge::BridgeChain::Arbitrum => 2,
    }
}

/// The PascalCase wire name for a [`crate::types::meta_bridge::BridgeChain`] (the value the POST
/// `params.chain` carries).
fn mb_chain_name(chain: crate::types::meta_bridge::BridgeChain) -> &'static str {
    match chain {
        crate::types::meta_bridge::BridgeChain::Base => "Base",
        crate::types::meta_bridge::BridgeChain::Arbitrum => "Arbitrum",
    }
}

/// The `uint8` the typed `RfqRequest` / `FbaSubmit` digests sign for a side
/// (`Bid = 0`, `Ask = 1`). Independent of the PascalCase `"Bid"` / `"Ask"` the
/// POST `params.side` carries.
fn core_side_to_u8(side: crate::types::rfq::CoreSide) -> u8 {
    match side {
        crate::types::rfq::CoreSide::Bid => 0,
        crate::types::rfq::CoreSide::Ask => 1,
    }
}

impl<'a> Exchange<'a> {
    // ---- typed-scheme signed actions (structured EIP-712) ----
    //
    // These mirror the structured signing path: rather than hashing the opaque
    // canonical-JSON action body, each action is a named EIP-712 struct so a
    // wallet can render its fields. The server selects this path via
    // the typed-only `/exchange`. Decimal magnitudes are signed AND posted as the
    // identical canonical string (the server hashes the received string, then
    // parses it), so pick one canonical decimal form per amount.

    /// Transfer an asset between accounts / sides under the typed scheme.
    ///
    /// `amount` is a canonical decimal string (e.g. `"750.25"`).
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    #[allow(clippy::too_many_arguments)]
    pub async fn send_asset_typed(
        &self,
        wallet: &Wallet,
        source_dex: u32,
        destination_dex: u32,
        asset: u32,
        destination: crate::wallet::Address,
        amount: impl Into<String>,
        to_perp: bool,
    ) -> Result<Value, ClientError> {
        let amount = amount.into();
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::SendAsset {
                metaflux_chain: chain,
                source_dex,
                destination_dex,
                asset,
                destination,
                amount: amount.clone(),
                to_perp,
                nonce,
            };
            let params = json!({
                "source_dex": source_dex,
                "destination_dex": destination_dex,
                "asset": asset,
                "destination": destination,
                "amount": amount,
                "to_perp": to_perp,
            });
            (action, "send_asset", params)
        })
        .await
    }

    /// Move USD between the spot and perp class under the typed scheme.
    ///
    /// `ntl` is a canonical decimal string.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn usd_class_transfer_typed(
        &self,
        wallet: &Wallet,
        ntl: impl Into<String>,
        to_perp: bool,
    ) -> Result<Value, ClientError> {
        let ntl = ntl.into();
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::UsdClassTransfer {
                metaflux_chain: chain,
                ntl: ntl.clone(),
                to_perp,
                nonce,
            };
            let params = json!({ "ntl": ntl, "to_perp": to_perp });
            (action, "usd_class_transfer", params)
        })
        .await
    }

    /// Withdraw an asset to a destination chain under the typed scheme.
    ///
    /// `amount` is a canonical decimal string.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn withdraw_typed(
        &self,
        wallet: &Wallet,
        asset: u32,
        amount: impl Into<String>,
        destination_chain_id: u32,
        use_cctp: bool,
    ) -> Result<Value, ClientError> {
        let amount = amount.into();
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::Withdraw {
                metaflux_chain: chain,
                asset,
                amount: amount.clone(),
                destination_chain_id,
                use_cctp,
                nonce,
            };
            let params = json!({
                "asset": asset,
                "amount": amount,
                "destination_chain_id": destination_chain_id,
                "use_cctp": use_cctp,
            });
            (action, "withdraw", params)
        })
        .await
    }

    /// Approve an agent wallet under the typed scheme.
    ///
    /// The typed digest does not cover an expiry — the typed approval never
    /// expires. Use [`Exchange::approve_agent`] (legacy) if you need an expiry.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn approve_agent_typed(
        &self,
        wallet: &Wallet,
        agent_address: crate::wallet::Address,
        agent_name: impl Into<String>,
        expires_at_ms: u64,
    ) -> Result<Value, ClientError> {
        let agent_name = agent_name.into();
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::ApproveAgent {
                metaflux_chain: chain,
                agent_address,
                agent_name: agent_name.clone(),
                expires_at_ms,
                nonce,
            };
            let mut params = json!({ "agent": agent_address, "name": agent_name });
            // `0` = never expires (omit from the wire); a real expiry rides verbatim.
            if expires_at_ms != 0 {
                params["expires_at_ms"] = json!(expires_at_ms);
            }
            (action, "approve_agent", params)
        })
        .await
    }

    /// Set the account referrer under the typed scheme.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn set_referrer_typed(
        &self,
        wallet: &Wallet,
        referrer: crate::wallet::Address,
    ) -> Result<Value, ClientError> {
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::SetReferrer {
                metaflux_chain: chain,
                referrer,
                nonce,
            };
            (action, "set_referrer", json!({ "referrer": referrer }))
        })
        .await
    }

    /// Approve a broker fee under the typed scheme.
    ///
    /// The POSTed action tag is `approve_broker_fee`. The EIP-712 type string
    /// stays `ApproveBuilderFee`: it is consensus-frozen, so the two names
    /// differ on purpose.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn approve_broker_fee_typed(
        &self,
        wallet: &Wallet,
        broker: crate::wallet::Address,
        max_fee_bps: u16,
    ) -> Result<Value, ClientError> {
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::ApproveBuilderFee {
                metaflux_chain: chain,
                builder: broker,
                max_fee_bps,
                nonce,
            };
            let params = json!({ "builder": broker, "max_bps": max_fee_bps });
            (action, "approve_broker_fee", params)
        })
        .await
    }

    /// Old name for [`Self::approve_broker_fee_typed`].
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn approve_builder_fee_typed(
        &self,
        wallet: &Wallet,
        builder: crate::wallet::Address,
        max_fee_bps: u16,
    ) -> Result<Value, ClientError> {
        self.approve_broker_fee_typed(wallet, builder, max_fee_bps)
            .await
    }

    /// Set the account display name under the typed scheme.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn set_display_name_typed(
        &self,
        wallet: &Wallet,
        display_name: impl Into<String>,
    ) -> Result<Value, ClientError> {
        let display_name = display_name.into();
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::SetDisplayName {
                metaflux_chain: chain,
                display_name: display_name.clone(),
                nonce,
            };
            let params = json!({ "display_name": display_name });
            (action, "set_display_name", params)
        })
        .await
    }

    /// Toggle position mode (hedge / one-way) under the typed scheme.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn set_position_mode_typed(
        &self,
        wallet: &Wallet,
        hedge: bool,
    ) -> Result<Value, ClientError> {
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::SetPositionMode {
                metaflux_chain: chain,
                hedge,
                nonce,
            };
            (action, "set_position_mode", json!({ "hedge": hedge }))
        })
        .await
    }

    /// Enroll into / out of portfolio margin under the typed scheme.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn user_portfolio_margin_typed(
        &self,
        wallet: &Wallet,
        enroll: bool,
    ) -> Result<Value, ClientError> {
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::UserPortfolioMargin {
                metaflux_chain: chain,
                enroll,
                nonce,
            };
            (action, "user_portfolio_margin", json!({ "enroll": enroll }))
        })
        .await
    }

    /// Convert the account to an M-of-N multisig under the typed scheme.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn convert_to_multi_sig_user_typed(
        &self,
        wallet: &Wallet,
        signers: Vec<crate::wallet::Address>,
        threshold: u32,
    ) -> Result<Value, ClientError> {
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::ConvertToMultiSigUser {
                metaflux_chain: chain,
                signers: signers.clone(),
                threshold,
                nonce,
            };
            let params = json!({ "signers": signers, "threshold": threshold });
            (action, "convert_to_multi_sig_user", params)
        })
        .await
    }

    /// Set per-asset leverage (and optionally isolated margin) under the typed
    /// scheme.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn update_leverage_typed(
        &self,
        wallet: &Wallet,
        asset: u32,
        leverage: u32,
        is_isolated: bool,
    ) -> Result<Value, ClientError> {
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::UpdateLeverage {
                metaflux_chain: chain,
                asset,
                leverage,
                is_isolated,
                nonce,
            };
            let params =
                json!({ "asset": asset, "leverage": leverage, "is_isolated": is_isolated });
            (action, "update_leverage", params)
        })
        .await
    }

    /// Claim staking rewards under the typed scheme.
    ///
    /// Pass [`crate::wallet::Address::ZERO`] for the validator to claim across
    /// all delegations.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn claim_rewards_typed(
        &self,
        wallet: &Wallet,
        validator: crate::wallet::Address,
    ) -> Result<Value, ClientError> {
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::ClaimRewards {
                metaflux_chain: chain,
                validator,
                nonce,
            };
            // The zero validator means "claim all"; the legacy wire omits the
            // field in that case, matching the node's optional decode.
            let params = if validator == crate::wallet::Address::ZERO {
                json!({})
            } else {
                json!({ "validator": validator })
            };
            (action, "claim_rewards", params)
        })
        .await
    }

    /// Link another account as this account's staking target under the typed
    /// scheme.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn link_staking_user_typed(
        &self,
        wallet: &Wallet,
        target: crate::wallet::Address,
    ) -> Result<Value, ClientError> {
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::LinkStakingUser {
                metaflux_chain: chain,
                target,
                nonce,
            };
            (action, "link_staking_user", json!({ "target": target }))
        })
        .await
    }

    /// Create a vault under the typed scheme.
    ///
    /// The typed digest does not cover a parent vault — the typed creation is
    /// top-level. Use [`Exchange::create_vault`] (legacy) for a parented vault.
    /// `kind` is `0` = user, `1` = metaliquidity.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn create_vault_typed(
        &self,
        wallet: &Wallet,
        name: impl Into<String>,
        lock_period_secs: u64,
        kind: u8,
    ) -> Result<Value, ClientError> {
        let name = name.into();
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::CreateVault {
                metaflux_chain: chain,
                name: name.clone(),
                lock_period_secs,
                kind,
                nonce,
            };
            let kind_tag = if kind == 1 { "Metaliquidity" } else { "User" };
            let params = json!({
                "name": name,
                "lock_period_secs": lock_period_secs,
                "kind": kind_tag,
            });
            (action, "create_vault", params)
        })
        .await
    }

    /// Modify a vault's name under the typed scheme.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn vault_modify_typed(
        &self,
        wallet: &Wallet,
        vault_id: u64,
        new_name: impl Into<String>,
    ) -> Result<Value, ClientError> {
        let new_name = new_name.into();
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::VaultModify {
                metaflux_chain: chain,
                vault_id,
                new_name: new_name.clone(),
                nonce,
            };
            let params = json!({ "vault_id": vault_id, "new_name": new_name });
            (action, "vault_modify", params)
        })
        .await
    }

    /// Close a leveraged spot position under the typed scheme.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn spot_margin_close_typed(
        &self,
        wallet: &Wallet,
        pair: u32,
        limit_px: u64,
    ) -> Result<Value, ClientError> {
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::SpotMarginClose {
                metaflux_chain: chain,
                pair,
                limit_px,
                nonce,
            };
            let params = json!({ "pair": pair, "limit_px": limit_px });
            (action, "spot_margin_close", params)
        })
        .await
    }

    /// Add or remove isolated margin on an open position under the typed scheme.
    ///
    /// `delta` is a signed canonical decimal string (`+` adds, `-` withdraws).
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn update_isolated_margin_typed(
        &self,
        wallet: &Wallet,
        asset: u32,
        delta: impl Into<String>,
    ) -> Result<Value, ClientError> {
        let delta = delta.into();
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::UpdateIsolatedMargin {
                metaflux_chain: chain,
                asset,
                delta: delta.clone(),
                nonce,
            };
            let params = json!({ "asset": asset, "delta": delta });
            (action, "update_isolated_margin", params)
        })
        .await
    }

    /// Top up the margin of a strict-isolated-only position under the typed
    /// scheme.
    ///
    /// `amount` is a positive canonical decimal string.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn top_up_isolated_only_margin_typed(
        &self,
        wallet: &Wallet,
        asset: u32,
        amount: impl Into<String>,
    ) -> Result<Value, ClientError> {
        let amount = amount.into();
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::TopUpIsolatedOnlyMargin {
                metaflux_chain: chain,
                asset,
                amount: amount.clone(),
                nonce,
            };
            let params = json!({ "asset": asset, "amount": amount });
            (action, "top_up_isolated_only_margin", params)
        })
        .await
    }

    /// Delegate stake to a validator (or queue an undelegation) under the typed
    /// scheme.
    ///
    /// `amount` is a canonical decimal string. `lock_months` picks the lock tier
    /// (`0` = flexible, else `1` / `6` / `24`); it is ignored on undelegate but
    /// still hashed into the digest, so pass the same value the wire carries.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn token_delegate_typed(
        &self,
        wallet: &Wallet,
        validator: crate::wallet::Address,
        amount: impl Into<String>,
        is_undelegate: bool,
        lock_months: u8,
    ) -> Result<Value, ClientError> {
        let amount = amount.into();
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::TokenDelegate {
                metaflux_chain: chain,
                validator,
                amount: amount.clone(),
                is_undelegate,
                lock_months,
                nonce,
            };
            let params = json!({
                "validator": validator,
                "amount": amount,
                "is_undelegate": is_undelegate,
                "lock_months": lock_months,
            });
            (action, "token_delegate", params)
        })
        .await
    }

    /// Move capital into or out of a vault under the typed scheme.
    ///
    /// `amount` is a canonical decimal string.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn vault_transfer_typed(
        &self,
        wallet: &Wallet,
        vault_id: u64,
        deposit: bool,
        amount: impl Into<String>,
    ) -> Result<Value, ClientError> {
        let amount = amount.into();
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::VaultTransfer {
                metaflux_chain: chain,
                vault_id,
                deposit,
                amount: amount.clone(),
                nonce,
            };
            let params = json!({
                "vault_id": vault_id,
                "deposit": deposit,
                "amount": amount,
            });
            (action, "vault_transfer", params)
        })
        .await
    }

    /// Redeem shares from a vault under the typed scheme.
    ///
    /// `shares` is a canonical decimal string.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn vault_withdraw_typed(
        &self,
        wallet: &Wallet,
        vault_id: u64,
        shares: impl Into<String>,
    ) -> Result<Value, ClientError> {
        let shares = shares.into();
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::VaultWithdraw {
                metaflux_chain: chain,
                vault_id,
                shares: shares.clone(),
                nonce,
            };
            let params = json!({ "vault_id": vault_id, "shares": shares });
            (action, "vault_withdraw", params)
        })
        .await
    }

    /// **DEPRECATED — the node REJECTS this action.** Post quote collateral to
    /// a spot-margin account under the typed scheme.
    ///
    /// Dead surface. Spot margin is cross-collateralized against the one
    /// unified USDC account, so there is no per-pair bucket to post into. The
    /// node rejects the action whenever the cross-margin model is active, which
    /// on the live chain is from genesis. Fund the unified USDC account and use
    /// [`Self::spot_margin_open_typed`] / [`Self::spot_margin_close_typed`].
    ///
    /// Kept so old signatures stay verifiable. `amount` is a canonical decimal
    /// string.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    #[deprecated(
        note = "the node rejects this action under cross-margin (live from genesis); fund the unified USDC account and use spot_margin_open / spot_margin_close"
    )]
    pub async fn spot_margin_deposit_typed(
        &self,
        wallet: &Wallet,
        pair: u32,
        amount: impl Into<String>,
    ) -> Result<Value, ClientError> {
        let amount = amount.into();
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::SpotMarginDeposit {
                metaflux_chain: chain,
                pair,
                amount: amount.clone(),
                nonce,
            };
            let params = json!({ "pair": pair, "amount": amount });
            (action, "spot_margin_deposit", params)
        })
        .await
    }

    /// **DEPRECATED — the node REJECTS this action.** Withdraw free collateral
    /// from a spot-margin account under the typed scheme.
    ///
    /// Dead surface, the twin of [`Self::spot_margin_deposit_typed`]. There is
    /// no per-pair bucket to withdraw from under cross-margin. The node rejects
    /// the action whenever the cross-margin model is active, which on the live
    /// chain is from genesis. Close with [`Self::spot_margin_close_typed`],
    /// then withdraw from the unified USDC account through the normal account
    /// lane.
    ///
    /// Kept so old signatures stay verifiable. `amount` is a canonical decimal
    /// string.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    #[deprecated(
        note = "the node rejects this action under cross-margin (live from genesis); close with spot_margin_close and withdraw from the unified USDC account"
    )]
    pub async fn spot_margin_withdraw_typed(
        &self,
        wallet: &Wallet,
        pair: u32,
        amount: impl Into<String>,
    ) -> Result<Value, ClientError> {
        let amount = amount.into();
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::SpotMarginWithdraw {
                metaflux_chain: chain,
                pair,
                amount: amount.clone(),
                nonce,
            };
            let params = json!({ "pair": pair, "amount": amount });
            (action, "spot_margin_withdraw", params)
        })
        .await
    }

    /// Open a leveraged spot position under the typed scheme.
    ///
    /// `size` and `limit_px` are 1e8-plane integers; `borrow` is a canonical
    /// decimal string.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn spot_margin_open_typed(
        &self,
        wallet: &Wallet,
        pair: u32,
        size: u64,
        limit_px: u64,
        borrow: impl Into<String>,
    ) -> Result<Value, ClientError> {
        let borrow = borrow.into();
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::SpotMarginOpen {
                metaflux_chain: chain,
                pair,
                size,
                limit_px,
                borrow: borrow.clone(),
                nonce,
            };
            let params = json!({
                "pair": pair,
                "size": size,
                "limit_px": limit_px,
                "borrow": borrow,
            });
            (action, "spot_margin_open", params)
        })
        .await
    }

    /// Supply quote into an Earn lending pool under the typed scheme.
    ///
    /// `amount` is a canonical decimal string.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn earn_deposit_typed(
        &self,
        wallet: &Wallet,
        asset: u32,
        amount: impl Into<String>,
    ) -> Result<Value, ClientError> {
        let amount = amount.into();
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::EarnDeposit {
                metaflux_chain: chain,
                asset,
                amount: amount.clone(),
                nonce,
            };
            let params = json!({ "asset": asset, "amount": amount });
            (action, "earn_deposit", params)
        })
        .await
    }

    /// Redeem Earn pool shares under the typed scheme.
    ///
    /// `shares` is a canonical decimal string.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn earn_withdraw_typed(
        &self,
        wallet: &Wallet,
        asset: u32,
        shares: impl Into<String>,
    ) -> Result<Value, ClientError> {
        let shares = shares.into();
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::EarnWithdraw {
                metaflux_chain: chain,
                asset,
                shares: shares.clone(),
                nonce,
            };
            let params = json!({ "asset": asset, "shares": shares });
            (action, "earn_withdraw", params)
        })
        .await
    }

    /// As an approved agent, set an abstraction config value for `user` under
    /// the typed scheme.
    ///
    /// `value` is hashed verbatim as an EIP-712 string.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn agent_set_abstraction_typed(
        &self,
        wallet: &Wallet,
        user: crate::wallet::Address,
        kind: u8,
        value: impl Into<String>,
    ) -> Result<Value, ClientError> {
        let value = value.into();
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::AgentSetAbstraction {
                metaflux_chain: chain,
                user,
                kind,
                value: value.clone(),
                nonce,
            };
            let params = json!({ "user": user, "kind": kind, "value": value });
            (action, "agent_set_abstraction", params)
        })
        .await
    }

    /// Withdraw cross-collateral to a destination chain under the typed scheme.
    ///
    /// The signed `chain` field is the mapped `uint8` (`Base = 1`,
    /// `Arbitrum = 2`), but the POST `params.chain` carries the
    /// PascalCase string name the wire expects. `amount` is an integer in base
    /// units (not a decimal string); `dst_addr` is a `0x`-hex destination
    /// address for the target chain.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn mb_withdraw_typed(
        &self,
        wallet: &Wallet,
        chain: crate::types::meta_bridge::BridgeChain,
        asset: u32,
        amount: u64,
        dst_addr: impl Into<String>,
    ) -> Result<Value, ClientError> {
        let dst_addr = dst_addr.into();
        let chain_u8 = mb_chain_to_u8(chain);
        let chain_name = mb_chain_name(chain);
        self.post_signed_typed(wallet, |meta_chain, nonce| {
            let action = TypedAction::BridgeWithdraw {
                metaflux_chain: meta_chain,
                chain: chain_u8,
                asset,
                amount,
                dst_addr: dst_addr.clone(),
                nonce,
            };
            let params = json!({
                "chain": chain_name,
                "asset": asset,
                "amount": amount,
                "dst_addr": dst_addr,
            });
            (action, "bridge_withdraw", params)
        })
        .await
    }

    /// Transfer USDC between Core and MetaFluxEVM under the typed scheme.
    ///
    /// `amount` is a canonical decimal string (whole-USDC plane); `to_evm = true`
    /// moves Core → MetaFluxEVM, and `false` is refused (the return leg must
    /// originate as a MetaFluxEVM transaction). `destination` is the
    /// MetaFluxEVM-side recipient.
    ///
    /// **A fee may be charged on top of `amount`, in MTF, with a USDC fallback.**
    /// The chain refuses the whole transfer when neither balance covers the fee,
    /// and also when the MTF reference price is unusable — so this call can fail
    /// for a reason unrelated to `asset` or your balance of it. The fee is ZERO
    /// today, so nothing is charged. See
    /// [the fee rules](crate::types::core_evm#the-core-to-evm-fee).
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn core_evm_transfer_typed(
        &self,
        wallet: &Wallet,
        amount: impl Into<String>,
        to_evm: bool,
        destination: crate::wallet::Address,
        asset: u32,
    ) -> Result<Value, ClientError> {
        let amount = amount.into();
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::CoreEvmTransfer {
                metaflux_chain: chain,
                amount: amount.clone(),
                to_evm,
                destination,
                asset,
                nonce,
            };
            let params = json!({
                "amount": amount,
                "to_evm": to_evm,
                "destination": destination,
                "asset": asset,
            });
            (action, "core_evm_transfer", params)
        })
        .await
    }

    /// Move a spot token to MetaFluxEVM and run `data` against the recipient,
    /// under the typed scheme.
    ///
    /// The chain debits the signer's spot balance of `token`, credits
    /// `destination_recipient` on MetaFluxEVM, and then runs `data` against that
    /// address. `amount` is a canonical decimal string on the whole-token plane;
    /// it is signed and posted as the identical text.
    ///
    /// `transfer_nonce` labels the transfer. It is NOT the envelope nonce, which
    /// this method takes from the account's nonce source; the two may differ.
    ///
    /// **Pass `source_dex = 0`, `to_perp = false`, and `destination_chain_id = 0`
    /// unless you know otherwise.** The chain refuses any other value for the
    /// first two, and refuses a `destination_chain_id` that is neither `0` nor
    /// the local EVM chain id. An older node accepted those fields and then
    /// ignored them, so a payload copied from that era carries `source_dex = 1`
    /// and now fails. `data` holds 4096 bytes at most, and an amount under one EVM
    /// quantum is refused rather than debited for a zero credit. A zero
    /// `destination_recipient` is refused too. See
    /// [`crate::types::core_evm::SendToEvmWithData`] for the rule on every field.
    ///
    /// **The SAME fee [`Exchange::core_evm_transfer_typed`] pays applies here**, in
    /// MTF with a USDC fallback, on top of `amount`. Neither call is the cheaper
    /// lane. The chain refuses the whole transfer when neither balance covers the
    /// fee, and also when the MTF reference price is unusable. The fee is ZERO
    /// today, so nothing is charged. See
    /// [the fee rules](crate::types::core_evm#the-core-to-evm-fee).
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    #[allow(clippy::too_many_arguments)]
    pub async fn send_to_evm_with_data_typed(
        &self,
        wallet: &Wallet,
        token: u32,
        amount: impl Into<String>,
        source_dex: u32,
        destination_recipient: crate::wallet::Address,
        to_perp: bool,
        destination_chain_id: u32,
        data: Vec<u8>,
        transfer_nonce: u64,
    ) -> Result<Value, ClientError> {
        let amount = amount.into();
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::SendToEvmWithData {
                metaflux_chain: chain,
                token,
                amount: amount.clone(),
                source_dex,
                destination_recipient,
                to_perp,
                destination_chain_id,
                data: data.clone(),
                transfer_nonce,
                nonce,
            };
            let params = json!({
                "token": token,
                "amount": amount,
                "source_dex": source_dex,
                "destination_recipient": destination_recipient,
                "to_perp": to_perp,
                "destination_chain_id": destination_chain_id,
                "data": data,
                "nonce": transfer_nonce,
            });
            (action, "send_to_evm_with_data", params)
        })
        .await
    }

    /// Create a sub-account under the signing (parent) account, under the typed
    /// scheme.
    ///
    /// `explicit_index` is optional: `None` lets the node assign the next free
    /// index and omits the field from the wire (the signed digest flattens the
    /// optional to a presence `bool` + value `0`).
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn create_sub_account_typed(
        &self,
        wallet: &Wallet,
        name: impl Into<String>,
        explicit_index: Option<u32>,
        shared_stp_group: bool,
    ) -> Result<Value, ClientError> {
        let name = name.into();
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::CreateSubAccount {
                metaflux_chain: chain,
                name: name.clone(),
                has_explicit_index: explicit_index.is_some(),
                explicit_index: explicit_index.unwrap_or(0),
                shared_stp_group,
                nonce,
            };
            let mut params = json!({ "name": name, "shared_stp_group": shared_stp_group });
            // Absent index is omitted from the wire; the signed digest still
            // covers the flattened (false, 0) pair.
            if let Some(idx) = explicit_index {
                params["explicit_index"] = json!(idx);
            }
            (action, "create_sub_account", params)
        })
        .await
    }

    /// Move quote collateral between the parent and a sub-account under the typed
    /// scheme.
    ///
    /// `amount` is a canonical decimal string; `deposit = true` moves
    /// parent → sub.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn sub_account_transfer_typed(
        &self,
        wallet: &Wallet,
        sub_index: u32,
        deposit: bool,
        amount: impl Into<String>,
    ) -> Result<Value, ClientError> {
        let amount = amount.into();
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::SubAccountTransfer {
                metaflux_chain: chain,
                sub_index,
                deposit,
                amount: amount.clone(),
                nonce,
            };
            let params = json!({
                "sub_index": sub_index,
                "deposit": deposit,
                "amount": amount,
            });
            (action, "sub_account_transfer", params)
        })
        .await
    }

    /// Move a spot token between the parent and a sub-account under the typed
    /// scheme.
    ///
    /// `amount` is a canonical decimal string; `deposit = true` moves
    /// parent → sub.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn sub_account_spot_transfer_typed(
        &self,
        wallet: &Wallet,
        sub_index: u32,
        token: u32,
        deposit: bool,
        amount: impl Into<String>,
    ) -> Result<Value, ClientError> {
        let amount = amount.into();
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::SubAccountSpotTransfer {
                metaflux_chain: chain,
                sub_index,
                token,
                deposit,
                amount: amount.clone(),
                nonce,
            };
            let params = json!({
                "sub_index": sub_index,
                "token": token,
                "deposit": deposit,
                "amount": amount,
            });
            (action, "sub_account_spot_transfer", params)
        })
        .await
    }

    /// Move spot MTF into the free staking pool (`c_deposit`) under the typed
    /// scheme.
    ///
    /// `amount` is a canonical decimal string.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn c_deposit_typed(
        &self,
        wallet: &Wallet,
        amount: impl Into<String>,
    ) -> Result<Value, ClientError> {
        let amount = amount.into();
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::CDeposit {
                metaflux_chain: chain,
                amount: amount.clone(),
                nonce,
            };
            (action, "c_deposit", json!({ "amount": amount }))
        })
        .await
    }

    /// Move MTF from the free staking pool back to spot (`c_withdraw`) under the
    /// typed scheme.
    ///
    /// `amount` is a canonical decimal string.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn c_withdraw_typed(
        &self,
        wallet: &Wallet,
        amount: impl Into<String>,
    ) -> Result<Value, ClientError> {
        let amount = amount.into();
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::CWithdraw {
                metaflux_chain: chain,
                amount: amount.clone(),
                nonce,
            };
            (action, "c_withdraw", json!({ "amount": amount }))
        })
        .await
    }

    /// Set a self-scoped abstraction config value under the typed scheme.
    ///
    /// `value` is hashed verbatim as a canonical decimal string.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn user_set_abstraction_typed(
        &self,
        wallet: &Wallet,
        kind: u8,
        value: impl Into<String>,
    ) -> Result<Value, ClientError> {
        let value = value.into();
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::UserSetAbstraction {
                metaflux_chain: chain,
                kind,
                value: value.clone(),
                nonce,
            };
            let params = json!({ "kind": kind, "value": value });
            (action, "user_set_abstraction", params)
        })
        .await
    }

    /// Pay a priority fee (bps) for block-front placement on an asset under the
    /// typed scheme.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn priority_bid_typed(
        &self,
        wallet: &Wallet,
        asset: u32,
        bid_bps: u16,
    ) -> Result<Value, ClientError> {
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::PriorityBid {
                metaflux_chain: chain,
                asset,
                bid_bps,
                nonce,
            };
            let params = json!({ "asset": asset, "bid_bps": bid_bps });
            (action, "priority_bid", params)
        })
        .await
    }

    /// Cancel all of the sender's open orders (optionally for one asset) under
    /// the typed scheme.
    ///
    /// `asset` is optional: `None` cancels across all assets and omits the field
    /// from the wire (the signed digest flattens the optional to a presence
    /// `bool` + value `0`).
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn cancel_all_orders_typed(
        &self,
        wallet: &Wallet,
        asset: Option<u32>,
    ) -> Result<Value, ClientError> {
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::CancelAllOrders {
                metaflux_chain: chain,
                owner: None,
                has_asset: asset.is_some(),
                asset: asset.unwrap_or(0),
                nonce,
            };
            let params = match asset {
                Some(a) => json!({ "asset": a }),
                None => json!({}),
            };
            (action, "cancel_all_orders", params)
        })
        .await
    }

    /// As an approved agent, cancel all of `owner`'s open orders (optionally for
    /// one asset) under the typed scheme — the agent-resolved counterpart of
    /// [`Self::cancel_all_orders_typed`].
    ///
    /// The signing `wallet` is a registered agent of `owner`; the action cancels
    /// `owner`'s orders (operator / vault trading), not the signer's. The signed
    /// digest binds `owner` right after `metafluxChain` (selecting the
    /// `*_WITH_OWNER` type string), and the POST carries a params-level `owner`
    /// (`0x`-hex) so the node's `NativeCancelAllOrders.owner` is set. `asset` is
    /// optional exactly as in the owner-less form (`None` = all assets, omitted
    /// from the wire).
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn cancel_all_orders_as(
        &self,
        wallet: &Wallet,
        owner: crate::wallet::Address,
        asset: Option<u32>,
    ) -> Result<Value, ClientError> {
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::CancelAllOrders {
                metaflux_chain: chain,
                owner: Some(owner),
                has_asset: asset.is_some(),
                asset: asset.unwrap_or(0),
                nonce,
            };
            let mut params = match asset {
                Some(a) => json!({ "asset": a }),
                None => json!({}),
            };
            // The agent-resolved owner rides as a params-level `0x`-hex field;
            // the node reads `NativeCancelAllOrders.owner` from it.
            params["owner"] = json!(owner);
            (action, "cancel_all_orders", params)
        })
        .await
    }

    /// Submit a threshold-encrypted order under the typed scheme.
    ///
    /// `ciphertext` is signed as EIP-712 `bytes` (`keccak256(raw)`) and posted as
    /// a JSON byte array; `commitment` is a 32-byte `bytes32` carried verbatim.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn submit_encrypted_order_typed(
        &self,
        wallet: &Wallet,
        ciphertext: Vec<u8>,
        commitment: [u8; 32],
        threshold: u8,
        target_block: u64,
        reveal_deadline_ms: u64,
    ) -> Result<Value, ClientError> {
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::SubmitEncryptedOrder {
                metaflux_chain: chain,
                ciphertext: ciphertext.clone(),
                commitment,
                threshold,
                target_block,
                reveal_deadline_ms,
                nonce,
            };
            let params = json!({
                "ciphertext": ciphertext,
                "commitment": commitment.to_vec(),
                "threshold": threshold,
                "target_block": target_block,
                "reveal_deadline_ms": reveal_deadline_ms,
            });
            (action, "submit_encrypted_order", params)
        })
        .await
    }

    /// Unenroll the sender from portfolio margin via the `pm_unenroll` tag under
    /// the typed scheme.
    ///
    /// An ALIAS of [`Self::user_portfolio_margin_typed`]` (enroll = false)`: it
    /// signs the IDENTICAL `UserPortfolioMargin` digest with `enroll = false`, but
    /// posts the no-params `{ "type": "pm_unenroll" }` wire form.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn pm_unenroll_typed(&self, wallet: &Wallet) -> Result<Value, ClientError> {
        self.post_signed_typed_raw(wallet, |chain, nonce| {
            let action = TypedAction::UserPortfolioMargin {
                metaflux_chain: chain,
                enroll: false,
                nonce,
            };
            (action, json!({ "type": "pm_unenroll" }))
        })
        .await
    }

    /// Burn one envelope nonce with the `noop` tag under the typed scheme.
    ///
    /// The handler touches no state. Use it as a keepalive, or to close a nonce
    /// gap: once a `noop` commits at nonce `N`, any other in-flight action
    /// signed with nonce `N` can no longer commit.
    ///
    /// Sender-authorized, and effectively master only: the chain does not permit
    /// an agent wallet to sign it. The POST carries no `params` key.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn noop_typed(&self, wallet: &Wallet) -> Result<Value, ClientError> {
        self.post_signed_typed_raw(wallet, |chain, nonce| {
            let action = TypedAction::Noop {
                metaflux_chain: chain,
                nonce,
            };
            (action, json!({ "type": "noop" }))
        })
        .await
    }

    /// Open an RFQ session as a taker via the `rfq_request` tag under the typed
    /// scheme.
    ///
    /// `side` is PascalCase on the wire (`"Bid"` / `"Ask"`) but a `uint8`
    /// (`0` / `1`) in the digest. `size` / `limit_px` are the raw `u64` wire form
    /// (fixed-point lots / price). `limit_px` / `stp_group` are optional; absent →
    /// presence `false` + `0` in the digest, `null` on the wire. For an approved
    /// agent opening the RFQ AS a vault, use [`Self::rfq_request_as`].
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    #[allow(clippy::too_many_arguments)]
    pub async fn rfq_request_typed(
        &self,
        wallet: &Wallet,
        market: u32,
        side: crate::types::rfq::CoreSide,
        size: u64,
        limit_px: Option<u64>,
        expiry_ms: u64,
        stp_group: Option<u64>,
    ) -> Result<Value, ClientError> {
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::RfqRequest {
                metaflux_chain: chain,
                owner: None,
                market,
                side: core_side_to_u8(side),
                size,
                has_limit_px: limit_px.is_some(),
                limit_px: limit_px.unwrap_or(0),
                expiry_ms,
                has_stp_group: stp_group.is_some(),
                stp_group: stp_group.unwrap_or(0),
                nonce,
            };
            let params = json!({
                "market": market,
                "side": side,
                "size": size,
                "limit_px": limit_px,
                "expiry_ms": expiry_ms,
                "stp_group": stp_group,
            });
            (action, "rfq_request", params)
        })
        .await
    }

    /// Cross against a specific resting RFQ quote via the `rfq_accept` tag under
    /// the typed scheme.
    ///
    /// The node gates the accept on `requester == sender`, so an RFQ opened with
    /// [`Self::rfq_request_as`] can only be accepted with [`Self::rfq_accept_as`]
    /// for the same owner.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn rfq_accept_typed(
        &self,
        wallet: &Wallet,
        rfq_id: u64,
        quote_idx: u32,
        size: u64,
    ) -> Result<Value, ClientError> {
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::RfqAccept {
                metaflux_chain: chain,
                owner: None,
                rfq_id,
                quote_idx,
                size,
                nonce,
            };
            let params = json!({
                "rfq_id": rfq_id,
                "quote_idx": quote_idx,
                "size": size,
            });
            (action, "rfq_accept", params)
        })
        .await
    }

    /// As an approved agent, open an RFQ AS `owner` (a vault) under the typed
    /// scheme — the owner-bound counterpart of [`Self::rfq_request_typed`].
    ///
    /// The signed digest binds `owner` right after `metafluxChain` (selecting the
    /// `RfqRequest` `*_WITH_OWNER` type string). Signing the owner-LESS string
    /// instead is not a rejection: the node admits the action and opens the RFQ
    /// on the agent's OWN account, so the option escrow and the resulting
    /// position land on the operator wallet, not the vault.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    #[allow(clippy::too_many_arguments)]
    pub async fn rfq_request_as(
        &self,
        wallet: &Wallet,
        owner: crate::wallet::Address,
        market: u32,
        side: crate::types::rfq::CoreSide,
        size: u64,
        limit_px: Option<u64>,
        expiry_ms: u64,
        stp_group: Option<u64>,
    ) -> Result<Value, ClientError> {
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::RfqRequest {
                metaflux_chain: chain,
                owner: Some(owner),
                market,
                side: core_side_to_u8(side),
                size,
                has_limit_px: limit_px.is_some(),
                limit_px: limit_px.unwrap_or(0),
                expiry_ms,
                has_stp_group: stp_group.is_some(),
                stp_group: stp_group.unwrap_or(0),
                nonce,
            };
            let params = json!({
                "owner": owner,
                "market": market,
                "side": side,
                "size": size,
                "limit_px": limit_px,
                "expiry_ms": expiry_ms,
                "stp_group": stp_group,
            });
            (action, "rfq_request", params)
        })
        .await
    }

    /// As an approved agent, accept a resting RFQ quote AS `owner` (a vault)
    /// under the typed scheme — the owner-bound counterpart of
    /// [`Self::rfq_accept_typed`].
    ///
    /// `owner` MUST be the same account [`Self::rfq_request_as`] opened the RFQ
    /// for: the node gates the accept on `requester == sender`.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn rfq_accept_as(
        &self,
        wallet: &Wallet,
        owner: crate::wallet::Address,
        rfq_id: u64,
        quote_idx: u32,
        size: u64,
    ) -> Result<Value, ClientError> {
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::RfqAccept {
                metaflux_chain: chain,
                owner: Some(owner),
                rfq_id,
                quote_idx,
                size,
                nonce,
            };
            let params = json!({
                "owner": owner,
                "rfq_id": rfq_id,
                "quote_idx": quote_idx,
                "size": size,
            });
            (action, "rfq_accept", params)
        })
        .await
    }

    /// Submit an order into a market's frequent-batch-auction pool via the
    /// `fba_submit` tag under the typed scheme.
    ///
    /// `side` is PascalCase on the wire but a `uint8` in the digest. `size` /
    /// `price` are the raw `u64` wire form. The price field is named `price`
    /// (NOT `limit_px`). `stp_group` is optional (absent → presence `false` + `0`).
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn fba_submit_typed(
        &self,
        wallet: &Wallet,
        market: u32,
        side: crate::types::rfq::CoreSide,
        size: u64,
        price: u64,
        stp_group: Option<u64>,
    ) -> Result<Value, ClientError> {
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::FbaSubmit {
                metaflux_chain: chain,
                market,
                side: core_side_to_u8(side),
                size,
                price,
                has_stp_group: stp_group.is_some(),
                stp_group: stp_group.unwrap_or(0),
                nonce,
            };
            let params = json!({
                "market": market,
                "side": side,
                "size": size,
                "price": price,
                "stp_group": stp_group,
            });
            (action, "fba_submit", params)
        })
        .await
    }

    /// Follower-deposit USD into a vault under the typed scheme
    /// (`vault_distribute`).
    ///
    /// The deposit amount rides the node's legacy `pnl` field as a positive
    /// canonical decimal string, hashed verbatim; the posted string MUST equal
    /// the signed string.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn vault_distribute_typed(
        &self,
        wallet: &Wallet,
        vault_id: u64,
        pnl: impl Into<String>,
    ) -> Result<Value, ClientError> {
        let pnl = pnl.into();
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::VaultDistribute {
                metaflux_chain: chain,
                vault_id,
                pnl: pnl.clone(),
                nonce,
            };
            let params = json!({ "vault_id": vault_id, "pnl": pnl });
            (action, "vault_distribute", params)
        })
        .await
    }

    /// Post a maker quote onto an open RFQ session under the typed scheme
    /// (`rfq_quote`).
    ///
    /// `price` / `max_size` are the raw `u64` wire form (the order path's
    /// convention, NOT decimal-scaled). `stp_group` is optional (absent →
    /// presence `false` + `0` in the digest, `null` on the wire). For an
    /// approved agent quoting AS a vault, use [`Self::rfq_quote_as`].
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    #[allow(clippy::too_many_arguments)]
    pub async fn rfq_quote_typed(
        &self,
        wallet: &Wallet,
        rfq_id: u64,
        price: u64,
        max_size: u64,
        valid_until_ms: u64,
        stp_group: Option<u64>,
    ) -> Result<Value, ClientError> {
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::RfqQuote {
                metaflux_chain: chain,
                owner: None,
                rfq_id,
                price,
                max_size,
                valid_until_ms,
                has_stp_group: stp_group.is_some(),
                stp_group: stp_group.unwrap_or(0),
                nonce,
            };
            let params = json!({
                "rfq_id": rfq_id,
                "price": price,
                "max_size": max_size,
                "valid_until_ms": valid_until_ms,
                "stp_group": stp_group,
            });
            (action, "rfq_quote", params)
        })
        .await
    }

    /// As an approved agent, post a maker RFQ quote AS `owner` (a vault) under
    /// the typed scheme — the owner-bound counterpart of [`Self::rfq_quote_typed`].
    ///
    /// The signed digest binds `owner` right after `metafluxChain` (selecting the
    /// `RfqQuote` `*_WITH_OWNER` type string) — the handler captures
    /// `entry.maker`, so which account the quote is made as IS signed. The POST
    /// carries a params-level `owner` (`0x`-hex).
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    #[allow(clippy::too_many_arguments)]
    pub async fn rfq_quote_as(
        &self,
        wallet: &Wallet,
        owner: crate::wallet::Address,
        rfq_id: u64,
        price: u64,
        max_size: u64,
        valid_until_ms: u64,
        stp_group: Option<u64>,
    ) -> Result<Value, ClientError> {
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::RfqQuote {
                metaflux_chain: chain,
                owner: Some(owner),
                rfq_id,
                price,
                max_size,
                valid_until_ms,
                has_stp_group: stp_group.is_some(),
                stp_group: stp_group.unwrap_or(0),
                nonce,
            };
            let mut params = json!({
                "rfq_id": rfq_id,
                "price": price,
                "max_size": max_size,
                "valid_until_ms": valid_until_ms,
                "stp_group": stp_group,
            });
            // The agent-resolved owner rides as a params-level `0x`-hex field.
            params["owner"] = json!(owner);
            (action, "rfq_quote", params)
        })
        .await
    }

    /// Drain the sender's accrued builder-code fee credit under the typed scheme
    /// (`claim_builder_rewards`). No params.
    ///
    /// The node variant carries a required (empty) `params` struct, so the wire
    /// body is `{"type":"claim_builder_rewards","params":{}}`.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn claim_builder_rewards_typed(&self, wallet: &Wallet) -> Result<Value, ClientError> {
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::ClaimBuilderRewards {
                metaflux_chain: chain,
                nonce,
            };
            (action, "claim_builder_rewards", json!({}))
        })
        .await
    }

    /// Drain the sender's accrued referrer fee credit under the typed scheme
    /// (`claim_referral_rewards`). No params.
    ///
    /// The node variant carries a required (empty) `params` struct, so the wire
    /// body is `{"type":"claim_referral_rewards","params":{}}`.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn claim_referral_rewards_typed(
        &self,
        wallet: &Wallet,
    ) -> Result<Value, ClientError> {
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::ClaimReferralRewards {
                metaflux_chain: chain,
                nonce,
            };
            (action, "claim_referral_rewards", json!({}))
        })
        .await
    }

    /// Lend / un-lend / borrow / repay against the BOLE pool under the typed
    /// scheme.
    ///
    /// `amount` is a canonical decimal string. The POST carries `kind` as its
    /// PascalCase name; the digest signs the same direction as a `uint8`.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn borrow_lend_typed(
        &self,
        wallet: &Wallet,
        kind: BorrowLendKind,
        amount: impl Into<String>,
    ) -> Result<Value, ClientError> {
        let amount = amount.into();
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::BorrowLend {
                metaflux_chain: chain,
                kind: kind.as_u8(),
                amount: amount.clone(),
                nonce,
            };
            let params = json!({ "kind": kind.wire_name(), "amount": amount });
            (action, "borrow_lend", params)
        })
        .await
    }

    /// Grant or revoke a vault operator under the typed scheme.
    ///
    /// The signer must lead `vault_id`. `expires_at_ms` is a timestamp in ms
    /// since epoch; `0` never expires.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn register_metaliquidity_operator_typed(
        &self,
        wallet: &Wallet,
        vault_id: u64,
        operator: crate::wallet::Address,
        allowed: bool,
        expires_at_ms: u64,
    ) -> Result<Value, ClientError> {
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::RegisterMetaliquidityOperator {
                metaflux_chain: chain,
                vault_id,
                operator,
                allowed,
                expires_at_ms,
                nonce,
            };
            let mut params = json!({
                "vault_id": vault_id,
                "operator": operator,
                "allowed": allowed,
            });
            // The node refuses an explicit `expires_at_ms: 0` because absent and
            // zero flatten to one digest. Omit the key, as `approve_agent` does.
            if expires_at_ms != 0 {
                params["expires_at_ms"] = json!(expires_at_ms);
            }
            (action, "register_metaliquidity_operator", params)
        })
        .await
    }

    // ---- permissionless spot deployer lane ----
    //
    // `max_deploy_fee` / `max_supply` / every seeded amount are hashed VERBATIM
    // and re-sent unchanged, so each method holds ONE `String` and feeds it to
    // both the digest and the POST.

    /// Register a fresh spot token under the typed scheme.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn spot_register_token_typed(
        &self,
        wallet: &Wallet,
        symbol: impl Into<String>,
        sz_decimals: u8,
        wei_decimals: u8,
        max_deploy_fee: impl Into<String>,
    ) -> Result<Value, ClientError> {
        let symbol = symbol.into();
        let max_deploy_fee = max_deploy_fee.into();
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::SpotRegisterToken {
                metaflux_chain: chain,
                symbol: symbol.clone(),
                sz_decimals,
                wei_decimals,
                max_deploy_fee: max_deploy_fee.clone(),
                nonce,
            };
            let params = json!({
                "symbol": symbol,
                "sz_decimals": sz_decimals,
                "wei_decimals": wei_decimals,
                "max_deploy_fee": max_deploy_fee,
            });
            (action, "spot_register_token", params)
        })
        .await
    }

    /// Register a `(base, quote)` spot pair under the typed scheme.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn spot_register_pair_typed(
        &self,
        wallet: &Wallet,
        base: u32,
        quote: u32,
        name: impl Into<String>,
        max_deploy_fee: impl Into<String>,
    ) -> Result<Value, ClientError> {
        let name = name.into();
        let max_deploy_fee = max_deploy_fee.into();
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::SpotRegisterPair {
                metaflux_chain: chain,
                base,
                quote,
                name: name.clone(),
                max_deploy_fee: max_deploy_fee.clone(),
                nonce,
            };
            let params = json!({
                "base": base,
                "quote": quote,
                "name": name,
                "max_deploy_fee": max_deploy_fee,
            });
            (action, "spot_register_pair", params)
        })
        .await
    }

    /// Set a spot pair's fee tier and min notional under the typed scheme.
    ///
    /// Both fees are DECI-bps, not bps.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn spot_set_pair_params_typed(
        &self,
        wallet: &Wallet,
        pair: u32,
        taker_fee_dbps: u32,
        maker_fee_dbps: u32,
        min_notional_cents: u64,
    ) -> Result<Value, ClientError> {
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::SpotSetPairParams {
                metaflux_chain: chain,
                pair,
                taker_fee_dbps,
                maker_fee_dbps,
                min_notional_cents,
                nonce,
            };
            let params = json!({
                "pair": pair,
                "taker_fee_dbps": taker_fee_dbps,
                "maker_fee_dbps": maker_fee_dbps,
                "min_notional_cents": min_notional_cents,
            });
            (action, "spot_set_pair_params", params)
        })
        .await
    }

    /// Open or close a spot pair under the typed scheme.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn spot_set_pair_active_typed(
        &self,
        wallet: &Wallet,
        pair: u32,
        active: bool,
    ) -> Result<Value, ClientError> {
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::SpotSetPairActive {
                metaflux_chain: chain,
                pair,
                active,
                nonce,
            };
            let params = json!({ "pair": pair, "active": active });
            (action, "spot_set_pair_active", params)
        })
        .await
    }

    /// Stage genesis holder rows for a spot token under the typed scheme.
    ///
    /// The rows are inside the signed digest, so the two arrays must stay
    /// parallel and keep their order.
    ///
    /// # Errors
    /// - [`ClientError::Validation`] if the arrays differ in length or are empty.
    /// - HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn spot_seed_holders_typed(
        &self,
        wallet: &Wallet,
        asset: u32,
        holders: Vec<crate::wallet::Address>,
        amounts: Vec<String>,
    ) -> Result<Value, ClientError> {
        if holders.is_empty() {
            return Err(ClientError::Validation(
                "spot_seed_holders needs at least one row".into(),
            ));
        }
        if holders.len() != amounts.len() {
            return Err(ClientError::Validation(
                "spot_seed_holders holders and amounts differ in length".into(),
            ));
        }
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::SpotSeedHolders {
                metaflux_chain: chain,
                asset,
                holders: holders.clone(),
                amounts: amounts.clone(),
                nonce,
            };
            let params = json!({
                "asset": asset,
                "holders": holders,
                "amounts": amounts,
            });
            (action, "spot_seed_holders", params)
        })
        .await
    }

    /// Check the staged sum, then mint the supply once, under the typed scheme.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn spot_finalize_supply_typed(
        &self,
        wallet: &Wallet,
        asset: u32,
        max_supply: impl Into<String>,
    ) -> Result<Value, ClientError> {
        let max_supply = max_supply.into();
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::SpotFinalizeSupply {
                metaflux_chain: chain,
                asset,
                max_supply: max_supply.clone(),
                nonce,
            };
            let params = json!({ "asset": asset, "max_supply": max_supply });
            (action, "spot_finalize_supply", params)
        })
        .await
    }

    // ---- MIP-3 perp deployer lane ----
    //
    // Nine sub-actions, nine tags, nine frozen signing strings. Each method
    // posts only the fields ITS sub-handler reads. No method carries a bid: the
    // gas-auction lane is dead and the node rejects a non-zero one.

    /// Allocate a fresh perp market under the typed scheme.
    ///
    /// `decimals` of `0` selects the node default of 8, not zero decimals.
    ///
    /// `name` is the perp dex the market joins: 1 to 16 ASCII alphanumeric
    /// bytes, unique across dexes ignoring case, and WRITE-ONCE. Send it on
    /// every registration — the first one creates the dex, and a later one must
    /// repeat the stored name. `symbol` must read `<name>:<suffix>` with a
    /// non-empty suffix; the node compares the prefix byte-exact.
    ///
    /// Availability is per network. On the primary networks the node knows
    /// these tags; an unknown action is what gets `unknown variant`. Probe one
    /// call against your target network. See [`crate::types::perp`].
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn perp_register_asset_typed(
        &self,
        wallet: &Wallet,
        symbol: impl Into<String>,
        decimals: u8,
        name: impl Into<String>,
    ) -> Result<Value, ClientError> {
        let symbol = symbol.into();
        let name = name.into();
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::PerpRegisterAsset {
                metaflux_chain: chain,
                symbol: symbol.clone(),
                decimals,
                name: name.clone(),
                nonce,
            };
            let params = json!({ "symbol": symbol, "decimals": decimals, "name": name });
            (action, "perp_register_asset", params)
        })
        .await
    }

    /// Bind a market's enabled oracle-source subset under the typed scheme.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn perp_set_oracle_typed(
        &self,
        wallet: &Wallet,
        asset: u32,
        oracle_source_mask: u16,
    ) -> Result<Value, ClientError> {
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::PerpSetOracle {
                metaflux_chain: chain,
                asset,
                oracle_source_mask,
                nonce,
            };
            let params = json!({ "asset": asset, "oracle_source_mask": oracle_source_mask });
            (action, "perp_set_oracle", params)
        })
        .await
    }

    /// Set a market's max leverage under the typed scheme.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn perp_set_leverage_typed(
        &self,
        wallet: &Wallet,
        asset: u32,
        max_leverage: u8,
    ) -> Result<Value, ClientError> {
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::PerpSetLeverage {
                metaflux_chain: chain,
                asset,
                max_leverage,
                nonce,
            };
            let params = json!({ "asset": asset, "max_leverage": max_leverage });
            (action, "perp_set_leverage", params)
        })
        .await
    }

    /// Set a market's three fee legs under the typed scheme.
    ///
    /// The taker and maker legs are DECI-bps; the deployer leg is WHOLE bps.
    /// The signer signs the three legs, not the node's packing of them.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn perp_set_fee_tier_typed(
        &self,
        wallet: &Wallet,
        asset: u32,
        taker_fee_dbps: u32,
        maker_fee_dbps: u32,
        deployer_fee_bps: u32,
    ) -> Result<Value, ClientError> {
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::PerpSetFeeTier {
                metaflux_chain: chain,
                asset,
                taker_fee_dbps,
                maker_fee_dbps,
                deployer_fee_bps,
                nonce,
            };
            let params = json!({
                "asset": asset,
                "taker_fee_dbps": taker_fee_dbps,
                "maker_fee_dbps": maker_fee_dbps,
                "deployer_fee_bps": deployer_fee_bps,
            });
            (action, "perp_set_fee_tier", params)
        })
        .await
    }

    /// Set a market's maker rebate under the typed scheme.
    ///
    /// `rebate_bps` is WHOLE bps, unlike the fee-tier legs.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn perp_set_maker_rebate_typed(
        &self,
        wallet: &Wallet,
        asset: u32,
        rebate_bps: u16,
    ) -> Result<Value, ClientError> {
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::PerpSetMakerRebate {
                metaflux_chain: chain,
                asset,
                rebate_bps,
                nonce,
            };
            let params = json!({ "asset": asset, "rebate_bps": rebate_bps });
            (action, "perp_set_maker_rebate", params)
        })
        .await
    }

    /// Set a market's minimum order size under the typed scheme.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn perp_set_min_size_typed(
        &self,
        wallet: &Wallet,
        asset: u32,
        min_order_size: u64,
    ) -> Result<Value, ClientError> {
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::PerpSetMinSize {
                metaflux_chain: chain,
                asset,
                min_order_size,
                nonce,
            };
            let params = json!({ "asset": asset, "min_order_size": min_order_size });
            (action, "perp_set_min_size", params)
        })
        .await
    }

    /// Open a market to trading under the typed scheme.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn perp_activate_market_typed(
        &self,
        wallet: &Wallet,
        asset: u32,
    ) -> Result<Value, ClientError> {
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::PerpActivateMarket {
                metaflux_chain: chain,
                asset,
                nonce,
            };
            (action, "perp_activate_market", json!({ "asset": asset }))
        })
        .await
    }

    /// Close a market to new orders under the typed scheme.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn perp_deactivate_market_typed(
        &self,
        wallet: &Wallet,
        asset: u32,
    ) -> Result<Value, ClientError> {
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::PerpDeactivateMarket {
                metaflux_chain: chain,
                asset,
                nonce,
            };
            (action, "perp_deactivate_market", json!({ "asset": asset }))
        })
        .await
    }

    /// Add or remove one delegated deployer under the typed scheme.
    ///
    /// The delegate and the direction are both signed, so neither can be
    /// re-targeted nor flipped under a replayed signature.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn perp_set_sub_deployers_typed(
        &self,
        wallet: &Wallet,
        asset: u32,
        sub_deployer: crate::wallet::Address,
        add: bool,
    ) -> Result<Value, ClientError> {
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::PerpSetSubDeployers {
                metaflux_chain: chain,
                asset,
                sub_deployer,
                add,
                nonce,
            };
            let params = json!({
                "asset": asset,
                "sub_deployer": sub_deployer,
                "add": add,
            });
            (action, "perp_set_sub_deployers", params)
        })
        .await
    }

    /// Push a MIP-3 market's index px under the typed scheme.
    ///
    /// `px` is a WHOLE-USDC decimal string, not the 1e8 book plane. The exact
    /// bytes given here are hashed AND posted, so the node verifies the same
    /// spelling the wallet signed.
    ///
    /// Gated by the `mip3_deployer_oracle` fork feature, which is ACTIVE FROM
    /// GENESIS on a fresh chain. A legacy or unknown network answers
    /// `mip3_deployer_oracle feature not active` until a stake vote arms it. See
    /// [`crate::types::perp::Mip3SetOraclePx`].
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn mip3_set_oracle_px_typed(
        &self,
        wallet: &Wallet,
        asset: u32,
        px: impl Into<String>,
    ) -> Result<Value, ClientError> {
        let px = px.into();
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::Mip3SetOraclePx {
                metaflux_chain: chain,
                asset,
                px: px.clone(),
                nonce,
            };
            let params = json!({ "asset": asset, "px": px.clone() });
            (action, "mip3_set_oracle_px", params)
        })
        .await
    }

    /// Sign + POST a structured (typed-scheme) action.
    ///
    /// The closure is handed the chain tag and a fresh nonce; it returns the
    /// [`TypedAction`] to sign (which embeds the same nonce) plus the
    /// `(type, params)` for the wire `action`. The decimal strings inside the
    /// `TypedAction` and the `params` MUST be identical — the server hashes the
    /// received string before parsing it.
    async fn post_signed_typed<F, R>(&self, wallet: &Wallet, build: F) -> Result<R, ClientError>
    where
        F: FnOnce(String, u64) -> (TypedAction, &'static str, Value),
        R: serde::de::DeserializeOwned,
    {
        self.post_signed_typed_raw(wallet, |chain, nonce| {
            let (typed, ty, params) = build(chain, nonce);
            (typed, json!({ "type": ty, "params": params }))
        })
        .await
    }

    /// Submit a multisig-acting bundle under the typed scheme.
    ///
    /// This wraps the roster-signed inner action in the outer
    /// [`TypedAction::MultiSig`] envelope and POSTs it. Collect the inner
    /// `signatures` first with [`crate::wallet::sign_multisig_inner`] (each roster
    /// member signs the SAME `inner_action_blob` bytes + `inner_nonce` under the
    /// acting account `user`).
    ///
    /// - `wallet` signs only the OUTER envelope — it may be ANY account (the
    ///   acting authority is the recovered inner signer set), so a relay / bot can
    ///   submit on the roster's behalf.
    /// - `inner_action_blob` is the EXACT canonical `Action` JSON bytes the roster
    ///   signed; it rides as `0x`-hex and is hashed raw by the node.
    /// - The envelope `nonce` is PINNED to `inner_nonce` (NOT a fresh nonce): it
    ///   must equal the nonce the roster signed and advances against `user`'s
    ///   window.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn multi_sig_typed(
        &self,
        wallet: &Wallet,
        user: crate::wallet::Address,
        inner_action_blob: Vec<u8>,
        signatures: Vec<Vec<u8>>,
        inner_nonce: u64,
    ) -> Result<Value, ClientError> {
        let blob_hex = format!("0x{}", hex::encode(&inner_action_blob));
        let sigs_hex: Vec<String> = signatures
            .iter()
            .map(|s| format!("0x{}", hex::encode(s)))
            .collect();
        self.post_signed_typed_at_nonce(wallet, inner_nonce, |chain, nonce| {
            let action = TypedAction::MultiSig {
                metaflux_chain: chain,
                user,
                inner_action_blob: inner_action_blob.clone(),
                signatures: signatures.clone(),
                nonce,
            };
            let params = json!({
                "user": user,
                "inner_action_blob": blob_hex,
                "signatures": sigs_hex,
                "nonce": nonce,
            });
            (action, json!({ "type": "multi_sig", "params": params }))
        })
        .await
    }

    /// Sign + POST a typed-scheme action at an EXPLICIT `nonce` (rather than a
    /// fresh monotonic one). Used by [`Self::multi_sig_typed`], whose envelope
    /// nonce must equal the inner nonce the roster signed.
    async fn post_signed_typed_at_nonce<F, R>(
        &self,
        wallet: &Wallet,
        nonce: u64,
        build: F,
    ) -> Result<R, ClientError>
    where
        F: FnOnce(String, u64) -> (TypedAction, Value),
        R: serde::de::DeserializeOwned,
    {
        let chain = metaflux_chain_tag(MTF_CHAIN_ID).to_string();
        let (typed, action) = build(chain, nonce);
        let expires_after = self.expires_after_ms;
        let digest =
            TypedActionDigest::new_with_expiry(&typed, MTF_CHAIN_ID, expires_after).to_digest();
        let signature = wallet.sign_digest(&digest)?.to_hex();
        let envelope = TypedSignedEnvelope {
            action: &action,
            nonce,
            signature,
            expires_after: expires_after_wire(expires_after),
        };
        self.client.post_json("/exchange", &envelope).await
    }

    /// Sign + POST a structured (typed-scheme) action with a CALLER-BUILT wire
    /// `action` JSON.
    ///
    /// Same digest contract as [`Self::post_signed_typed`] — the closure binds the
    /// [`TypedAction`] and the wire `action` to the SAME nonce — but the caller
    /// shapes the full `{ type, … }` envelope. Used for actions whose wire form
    /// is not the `{ type, params }` default: e.g. a no-params tag like
    /// `pm_unenroll` (`{ "type": "pm_unenroll" }`, no `params` key).
    async fn post_signed_typed_raw<F, R>(&self, wallet: &Wallet, build: F) -> Result<R, ClientError>
    where
        F: FnOnce(String, u64) -> (TypedAction, Value),
        R: serde::de::DeserializeOwned,
    {
        let nonce = next_nonce();
        let chain = metaflux_chain_tag(MTF_CHAIN_ID).to_string();
        let (typed, action) = build(chain, nonce);
        let expires_after = self.expires_after_ms;
        let digest =
            TypedActionDigest::new_with_expiry(&typed, MTF_CHAIN_ID, expires_after).to_digest();
        let signature = wallet.sign_digest(&digest)?.to_hex();
        let envelope = TypedSignedEnvelope {
            action: &action,
            nonce,
            signature,
            expires_after: expires_after_wire(expires_after),
        };
        self.client.post_json("/exchange", &envelope).await
    }

    /// Sign a TRADING action (order / cancel / TWAP / batch) under the typed
    /// scheme and POST it. The 12 trading actions migrated to the typed scheme
    /// in node lockstep — the opaque `MetaFluxAction` envelope is no longer
    /// admitted for them. `action` is the canonical `{ type, … }` wire JSON;
    /// `typed` is its structured form, bound to the same nonce for the digest.
    pub(crate) async fn post_typed_trade<R: serde::de::DeserializeOwned>(
        &self,
        wallet: &Wallet,
        action: Value,
        typed: TypedTradingAction<'_>,
    ) -> Result<R, ClientError> {
        self.post_typed_trade_bound(wallet, None, action, typed)
            .await
    }

    /// Sign + POST an agent-resolved (owner-bound) TRADING action — the
    /// operator / vault counterpart of [`Self::post_typed_trade`].
    ///
    /// Identical to [`Self::post_typed_trade`] except (1) the digest binds
    /// `owner` via [`TypedTradingDigest::new_with_owner`], which selects the
    /// action's `*_WITH_OWNER` type string and inserts the owner word right after
    /// `metafluxChain`; and (2) the POSTed `action` gains a params-level `owner`
    /// (`0x`-hex) so the node's `Native*.owner` is set. The signing `wallet` is a
    /// registered agent of `owner`; the recovered signer is the AGENT, not the
    /// owner. For an owner-less action the owner-less [`Self::post_typed_trade`]
    /// signs a byte-identical digest.
    pub(crate) async fn post_typed_trade_as<R: serde::de::DeserializeOwned>(
        &self,
        wallet: &Wallet,
        owner: crate::wallet::Address,
        mut action: Value,
        typed: TypedTradingAction<'_>,
    ) -> Result<R, ClientError> {
        // The agent-resolved owner rides as a params-level `0x`-hex field; the
        // node reads `Native*.owner` from it (mirrors `cancel_all_orders_as`).
        action["params"]["owner"] = json!(owner);
        self.post_typed_trade_bound(wallet, Some(owner), action, typed)
            .await
    }

    /// Sign + POST a TRADING action whose wire body ALREADY carries its own
    /// `owner` field — the spot lane, where `owner` lives inside the action's
    /// `order` / `cancel` object rather than a `params` object.
    ///
    /// `owner = Some` binds the `*_WITH_OWNER` digest, so the recovered signer is
    /// the approved AGENT and the node routes the action to the owner. `None`
    /// signs the owner-less digest and posts byte-identical bytes to
    /// [`Self::post_typed_trade`]. This method never edits `action`; the caller's
    /// serialized type is the single source of the wire `owner`.
    pub(crate) async fn post_typed_trade_bound<R: serde::de::DeserializeOwned>(
        &self,
        wallet: &Wallet,
        owner: Option<crate::wallet::Address>,
        action: Value,
        typed: TypedTradingAction<'_>,
    ) -> Result<R, ClientError> {
        let nonce = next_nonce();
        let expires_after = self.expires_after_ms;
        let digest = match owner {
            Some(o) => TypedTradingDigest::new_with_owner(typed, o, MTF_CHAIN_ID, nonce),
            None => TypedTradingDigest::new(typed, MTF_CHAIN_ID, nonce),
        }
        .with_expires_after(expires_after)
        .digest()?;
        let signature = wallet.sign_digest(&digest)?.to_hex();
        let envelope = TypedSignedEnvelope {
            action: &action,
            nonce,
            signature,
            expires_after: expires_after_wire(expires_after),
        };
        self.client.post_json("/exchange", &envelope).await
    }
}

/// Map an `expires_after_ms` knob to the wire field: `None` (omit) at `0`, else
/// `Some(ms)`. Keeps a `0` envelope byte-identical to the pre-`expiresAfter`
/// form.
const fn expires_after_wire(expires_after_ms: u64) -> Option<u64> {
    if expires_after_ms == 0 {
        None
    } else {
        Some(expires_after_ms)
    }
}

/// Test-only escape hatch: compute the typed-scheme EIP-712 digest the SDK
/// would sign for the given [`TypedAction`] against the default
/// [`MTF_CHAIN_ID`]. Used by the integration tests under `tests/`. Not part of
/// the stable public API.
#[doc(hidden)]
pub fn _typed_digest_for_test(action: &TypedAction) -> [u8; 32] {
    TypedActionDigest::new(action, MTF_CHAIN_ID).to_digest()
}

/// Test-only escape hatch: the typed-scheme digest with an OPTIONAL top-level
/// `expires_after` (ms) folded in, against the default [`MTF_CHAIN_ID`]. `0`
/// reproduces [`_typed_digest_for_test`] byte-for-byte. Used by the integration
/// tests under `tests/`. Not part of the stable public API.
#[doc(hidden)]
pub fn _typed_digest_for_test_with_expiry(action: &TypedAction, expires_after: u64) -> [u8; 32] {
    TypedActionDigest::new_with_expiry(action, MTF_CHAIN_ID, expires_after).to_digest()
}

/// Test-only escape hatch: the typed-scheme EIP-712 digest for a TRADING action
/// (order / cancel / …) against the default [`MTF_CHAIN_ID`] + given nonce.
#[doc(hidden)]
pub fn _typed_trade_digest_for_test(action: TypedTradingAction<'_>, nonce: u64) -> [u8; 32] {
    TypedTradingDigest::new(action, MTF_CHAIN_ID, nonce)
        .digest()
        .expect("typed trade digest")
}

/// Test-only escape hatch: the agent-resolved (`*_WITH_OWNER`) typed-scheme
/// digest for a TRADING action against the default [`MTF_CHAIN_ID`] + nonce.
#[doc(hidden)]
pub fn _typed_trade_digest_for_test_as(
    action: TypedTradingAction<'_>,
    owner: crate::wallet::Address,
    nonce: u64,
) -> [u8; 32] {
    TypedTradingDigest::new_with_owner(action, owner, MTF_CHAIN_ID, nonce)
        .digest()
        .expect("typed trade digest")
}
