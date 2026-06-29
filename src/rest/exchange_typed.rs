//! Structured (typed-scheme) `/exchange` signed actions.
//!
//! These extend [`Exchange`] with the structured EIP-712 signing path: each
//! action is signed as a named [`TypedAction`] struct (so wallets render its
//! fields), and the POST carries `sig_scheme: "typed"`. Decimal magnitudes are
//! signed AND posted as the identical canonical string, since the server hashes
//! the received string before parsing it.
//!
//! Everything not in this typed set keeps the opaque legacy scheme on
//! [`Exchange`] in the sibling module.

use serde::Serialize;
use serde_json::{Value, json};

use crate::error::ClientError;
use crate::rest::exchange::{Exchange, MTF_CHAIN_ID, next_nonce};
use crate::wallet::{
    Eip712, TypedAction, TypedActionDigest, TypedTradingAction, TypedTradingDigest, Wallet,
    metaflux_chain_tag,
};

/// A typed-scheme signed action ready to POST to `/exchange`.
///
/// Carries `sig_scheme: "typed"` to select the structured EIP-712 path on the
/// server, alongside the `{ type, params }` action object whose decimal fields
/// are the exact canonical strings that were hashed.
#[derive(Clone, Debug, Serialize)]
struct TypedSignedEnvelope<'a> {
    action: &'a Value,
    nonce: u64,
    signature: String,
    sig_scheme: &'static str,
}

/// Map a [`crate::types::meta_bridge::MbChain`] to the `uint8` the typed `MbWithdraw` digest
/// signs (`Solana = 0`, `Base = 1`, `Arbitrum = 2`). This is independent of the
/// wire string name, which is still PascalCase in the POST params.
fn mb_chain_to_u8(chain: crate::types::meta_bridge::MbChain) -> u8 {
    match chain {
        crate::types::meta_bridge::MbChain::Solana => 0,
        crate::types::meta_bridge::MbChain::Base => 1,
        crate::types::meta_bridge::MbChain::Arbitrum => 2,
    }
}

/// The PascalCase wire name for a [`crate::types::meta_bridge::MbChain`] (the value the POST
/// `params.chain` carries).
fn mb_chain_name(chain: crate::types::meta_bridge::MbChain) -> &'static str {
    match chain {
        crate::types::meta_bridge::MbChain::Solana => "Solana",
        crate::types::meta_bridge::MbChain::Base => "Base",
        crate::types::meta_bridge::MbChain::Arbitrum => "Arbitrum",
    }
}

impl<'a> Exchange<'a> {
    // ---- typed-scheme signed actions (structured EIP-712) ----
    //
    // These mirror the structured signing path: rather than hashing the opaque
    // canonical-JSON action body, each action is a named EIP-712 struct so a
    // wallet can render its fields. The server selects this path via
    // `sig_scheme: "typed"`. Decimal magnitudes are signed AND posted as the
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

    /// Approve a builder fee under the typed scheme.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn approve_builder_fee_typed(
        &self,
        wallet: &Wallet,
        builder: crate::wallet::Address,
        max_fee_bps: u16,
    ) -> Result<Value, ClientError> {
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::ApproveBuilderFee {
                metaflux_chain: chain,
                builder,
                max_fee_bps,
                nonce,
            };
            let params = json!({ "builder": builder, "max_bps": max_fee_bps });
            (action, "approve_builder_fee", params)
        })
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

    /// Set metaliquidity whitelist membership under the typed scheme.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn REDACTED_typed(
        &self,
        wallet: &Wallet,
        account: crate::wallet::Address,
        allowed: bool,
    ) -> Result<Value, ClientError> {
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::REDACTED {
                metaflux_chain: chain,
                account,
                allowed,
                nonce,
            };
            let params = json!({ "address": account, "allowed": allowed });
            (action, "REDACTED", params)
        })
        .await
    }

    /// Register / revoke a metaliquidity operator under the typed scheme.
    ///
    /// `expires_at_ms = 0` never expires.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn REDACTED_typed(
        &self,
        wallet: &Wallet,
        vault_id: u64,
        operator: crate::wallet::Address,
        allowed: bool,
        expires_at_ms: u64,
    ) -> Result<Value, ClientError> {
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::REDACTED {
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
            if expires_at_ms != 0 {
                params["expires_at_ms"] = json!(expires_at_ms);
            }
            (action, "REDACTED", params)
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
    /// `amount` is a canonical decimal string.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn token_delegate_typed(
        &self,
        wallet: &Wallet,
        validator: crate::wallet::Address,
        amount: impl Into<String>,
        is_undelegate: bool,
    ) -> Result<Value, ClientError> {
        let amount = amount.into();
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::TokenDelegate {
                metaflux_chain: chain,
                validator,
                amount: amount.clone(),
                is_undelegate,
                nonce,
            };
            let params = json!({
                "validator": validator,
                "amount": amount,
                "is_undelegate": is_undelegate,
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

    /// Post quote collateral to a spot-margin account under the typed scheme.
    ///
    /// `amount` is a canonical decimal string.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
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

    /// Withdraw free collateral from a spot-margin account under the typed
    /// scheme.
    ///
    /// `amount` is a canonical decimal string.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
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
    /// The signed `chain` field is the mapped `uint8` (`Solana = 0`,
    /// `Base = 1`, `Arbitrum = 2`), but the POST `params.chain` carries the
    /// PascalCase string name the wire expects. `amount` is an integer in base
    /// units (not a decimal string); `dst_addr` is a `0x`-hex destination
    /// address for the target chain.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn mb_withdraw_typed(
        &self,
        wallet: &Wallet,
        chain: crate::types::meta_bridge::MbChain,
        asset: u32,
        amount: u64,
        dst_addr: impl Into<String>,
    ) -> Result<Value, ClientError> {
        let dst_addr = dst_addr.into();
        let chain_u8 = mb_chain_to_u8(chain);
        let chain_name = mb_chain_name(chain);
        self.post_signed_typed(wallet, |meta_chain, nonce| {
            let action = TypedAction::MbWithdraw {
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
            (action, "mb_withdraw", params)
        })
        .await
    }

    /// Transfer USDC between Core and MetaFluxEVM under the typed scheme.
    ///
    /// `amount` is a canonical decimal string (whole-USDC plane); `to_evm = true`
    /// moves Core → MetaFluxEVM, `false` the reverse. `destination` is the
    /// MetaFluxEVM-side recipient.
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

    /// Toggle the account's DEX-abstraction opt-in flag under the typed scheme.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn user_dex_abstraction_typed(
        &self,
        wallet: &Wallet,
        enabled: bool,
    ) -> Result<Value, ClientError> {
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::UserDexAbstraction {
                metaflux_chain: chain,
                enabled,
                nonce,
            };
            (
                action,
                "user_dex_abstraction",
                json!({ "enabled": enabled }),
            )
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
        let nonce = next_nonce();
        let chain = metaflux_chain_tag(MTF_CHAIN_ID).to_string();
        let (typed, ty, params) = build(chain, nonce);
        let digest = TypedActionDigest::new(&typed, MTF_CHAIN_ID).to_digest();
        let signature = wallet.sign_digest(&digest)?.to_hex();
        let action = json!({ "type": ty, "params": params });
        let envelope = TypedSignedEnvelope {
            action: &action,
            nonce,
            signature,
            sig_scheme: "typed",
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
        let nonce = next_nonce();
        let digest = TypedTradingDigest::new(typed, MTF_CHAIN_ID, nonce).digest()?;
        let signature = wallet.sign_digest(&digest)?.to_hex();
        let envelope = TypedSignedEnvelope {
            action: &action,
            nonce,
            signature,
            sig_scheme: "typed",
        };
        self.client.post_json("/exchange", &envelope).await
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

/// Test-only escape hatch: the typed-scheme EIP-712 digest for a TRADING action
/// (order / cancel / …) against the default [`MTF_CHAIN_ID`] + given nonce.
#[doc(hidden)]
pub fn _typed_trade_digest_for_test(action: TypedTradingAction<'_>, nonce: u64) -> [u8; 32] {
    TypedTradingDigest::new(action, MTF_CHAIN_ID, nonce)
        .digest()
        .expect("typed trade digest")
}
