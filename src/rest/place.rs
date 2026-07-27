//! `place_order` — one entry point over the three wire order actions.
//!
//! The input and result types live in [`crate::types::place`]. This module
//! holds only the routing.

use serde_json::Value;

use crate::error::ClientError;
use crate::rest::exchange::Exchange;
use crate::types::order::BatchOrder;
use crate::types::place::{
    BatchPlacement, LegStatus, PlaceRequest, Placement, SpotActionOutcome, SpotPlacements,
};
use crate::wallet::Wallet;

impl Exchange<'_> {
    /// Place one order or many through a single entry point.
    ///
    /// This is a CONVENIENCE over the wire, not a replacement for it. It signs
    /// and posts the same actions the per-action methods do, so a reader can
    /// still reason about what hits the chain:
    ///
    /// | request | wire action | actions sent |
    /// |---|---|---|
    /// | [`PlaceRequest::Perp`], any count | `batch_order` | 1 |
    /// | [`PlaceRequest::Spot`], N orders | `spot_order` | N |
    /// | mixed perp and spot | none — refused | 0 |
    ///
    /// **Perp route.** Every perp request — including a single order — goes
    /// through [`Exchange::batch_order`], so it gets per-leg statuses, the
    /// `grouping` field, and the params-level `owner` that routes an agent's
    /// signature to a vault. It does NOT use the `order` action; call
    /// [`Exchange::submit_order`] directly if you need that exact action.
    ///
    /// **Spot route.** The wire cannot batch spot orders, so each order becomes
    /// its OWN `spot_order` action, with its own signature, nonce and commit.
    /// The result is [`Placement::SeparateSpotActions`] — NOT an atomic
    /// submission. The SDK stops at the first action that fails to send and
    /// reports the remaining orders in `not_sent`. Each order carries its own
    /// [`SpotOrder::owner`], so an approved agent places spot orders here too;
    /// build the request with [`PlaceRequest::spot_as`].
    ///
    /// [`SpotOrder::owner`]: crate::types::spot::SpotOrder::owner
    ///
    /// **Mixed request.** Refused. A caller who passes both venues expects one
    /// atomic submission, and two independent ones would be a surprise that
    /// costs money. Build the request with [`PlaceRequest::from_legs`] to get
    /// that refusal at construction time.
    ///
    /// Number planes are untouched: `size` and `limit_px` stay on the 1e8 book
    /// plane, exactly as passed.
    ///
    /// # Errors
    /// - [`ClientError::Validation`] if the request carries no orders, or (perp
    ///   route) a TP/SL-LIMIT leg has no price / a non-GTC tif.
    /// - [`ClientError::Http`] / [`ClientError::ProtocolError`] on transport.
    ///   On the spot route a transport failure is reported PER ACTION inside
    ///   [`SpotActionOutcome::result`], because earlier actions may already be
    ///   live.
    pub async fn place_order(
        &self,
        wallet: &Wallet,
        req: &PlaceRequest,
    ) -> Result<Placement, ClientError> {
        if req.is_empty() {
            return Err(ClientError::Validation(
                "place request carries no orders".into(),
            ));
        }
        match req {
            PlaceRequest::Perp {
                owner,
                orders,
                grouping,
            } => {
                let batch = BatchOrder {
                    owner: *owner,
                    orders: orders.clone(),
                    grouping: *grouping,
                };
                let response: Value = self.batch_order(wallet, &batch).await?;
                Ok(Placement::BatchAction(BatchPlacement::from_response(
                    response,
                )))
            }
            PlaceRequest::Spot { orders } => {
                let mut sent = Vec::with_capacity(orders.len());
                let mut failed_at = None;
                for (index, order) in orders.iter().enumerate() {
                    let result = self
                        .spot_order(wallet, order)
                        .await
                        .map(|r| r.statuses.into_iter().map(LegStatus::Known).collect());
                    let failed = result.is_err();
                    sent.push(SpotActionOutcome {
                        index,
                        pair: order.pair,
                        result,
                    });
                    if failed {
                        failed_at = Some(index);
                        break;
                    }
                }
                // A failed send may still have been admitted. Stop, so the caller
                // decides; sending on would place orders against an unknown state.
                let not_sent = failed_at
                    .map(|i| ((i + 1)..orders.len()).collect())
                    .unwrap_or_default();
                Ok(Placement::SeparateSpotActions(SpotPlacements {
                    sent,
                    not_sent,
                }))
            }
        }
    }
}
