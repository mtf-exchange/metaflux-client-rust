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
use crate::rest::exchange::{Exchange, next_nonce, MTF_CHAIN_ID};
use crate::wallet::{Eip712, TypedAction, TypedActionDigest, Wallet, metaflux_chain_tag};

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
    ) -> Result<Value, ClientError> {
        let agent_name = agent_name.into();
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::ApproveAgent {
                metaflux_chain: chain,
                agent_address,
                agent_name: agent_name.clone(),
                nonce,
            };
            let params = json!({ "agent": agent_address, "name": agent_name });
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
    pub async fn set_metaliquidity_set_typed(
        &self,
        wallet: &Wallet,
        account: crate::wallet::Address,
        allowed: bool,
    ) -> Result<Value, ClientError> {
        self.post_signed_typed(wallet, |chain, nonce| {
            let action = TypedAction::SetMetaliquiditySet {
                metaflux_chain: chain,
                account,
                allowed,
                nonce,
            };
            let params = json!({ "address": account, "allowed": allowed });
            (action, "set_metaliquidity_set", params)
        })
        .await
    }

    /// Register / revoke a metaliquidity operator under the typed scheme.
    ///
    /// `expires_at_ms = 0` never expires.
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
            if expires_at_ms != 0 {
                params["expires_at_ms"] = json!(expires_at_ms);
            }
            (action, "register_metaliquidity_operator", params)
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
}

/// Test-only escape hatch: compute the typed-scheme EIP-712 digest the SDK
/// would sign for the given [`TypedAction`] against the default
/// [`MTF_CHAIN_ID`]. Used by the integration tests under `tests/`. Not part of
/// the stable public API.
#[doc(hidden)]
pub fn _typed_digest_for_test(action: &TypedAction) -> [u8; 32] {
    TypedActionDigest::new(action, MTF_CHAIN_ID).to_digest()
}
