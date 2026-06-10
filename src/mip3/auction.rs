//! MIP-3 gas auction helpers (client-side polling + submission).
//!
//! The L1 implements a Dutch-style gas auction: each round
//! emits a "credit window" during which the highest unique bidder receives
//! a `pending_deploy_credit` that lets them submit the deploy sequence.
//!
//! This module wraps the auction's three client-facing primitives:
//!
//! - **Submit bid** → posts a signed `submit_gas_auction_bid` action.
//! - **Check credit** → polls `info: { type: "deploy_credit", address }`
//!   for the per-address credit count.
//! - **Await credit** → polls with backoff until credit appears or `max_wait`
//!   elapses.
//!
//! The bid kind matches the auction class — token register / perp deploy /
//! spot pair deploy each runs as a separate auction with its own minimum.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::time::{Instant, sleep};

use crate::Client;
use crate::error::ClientError;
use crate::wallet::{Address, Wallet};

/// The class of auction the bid targets.
///
/// Each class has its own current price + round duration. Per-class
/// economics: defaults are pinned but governance-tunable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionKind {
    /// Token register auction — purchases an `asset_id` slot.
    TokenRegister,
    /// Perp market deploy auction — yields a `pending_deploy_credit` for
    /// running the 8-step `perpDeploy` sequence.
    PerpDeploy,
    /// Spot pair deploy auction — yields a `pending_deploy_credit` for the
    /// 4-step `spotDeploy` sequence.
    SpotPairDeploy,
}

impl AuctionKind {
    /// Wire discriminator (matches L1 handler).
    #[must_use]
    pub fn type_id(&self) -> &'static str {
        match self {
            Self::TokenRegister => "token_register",
            Self::PerpDeploy => "perp_deploy",
            Self::SpotPairDeploy => "spot_pair_deploy",
        }
    }
}

/// A bid into the gas auction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AuctionBid {
    /// Which auction class to bid into.
    pub kind: AuctionKind,
    /// Bid amount in USDC cents (smallest unit). Must exceed the current
    /// auction price for the round to accept.
    pub bid_amount_usdc_cents: u128,
}

/// Server response to a bid submission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct BidReceipt {
    /// Identifier of the auction round this bid was assigned to.
    pub round_id: u64,
    /// Echo of the bidder's address.
    pub bidder: Address,
    /// Bid amount accepted (server may quote-clip).
    pub accepted_amount_usdc_cents: u128,
    /// Outcome string. `"accepted"`, `"replaced"`, `"underbid"`, etc.
    pub status: String,
}

impl Client {
    /// Submit a bid for the current gas auction round.
    ///
    /// The wallet signs an EIP-712 `submit_gas_auction_bid` action; the
    /// gateway verifies the signer matches the bidder field (set internally
    /// by the SDK to `wallet.address()`).
    ///
    /// # Errors
    /// - [`ClientError::Http`] / [`ClientError::ProtocolError`] on transport.
    /// - [`ClientError::Signature`] on signing failure.
    pub async fn submit_gas_auction_bid(
        &self,
        wallet: &Wallet,
        bid: AuctionBid,
    ) -> Result<BidReceipt, ClientError> {
        let action = json!({
            "type": "submit_gas_auction_bid",
            "bidder": wallet.address(),
            "kind": bid.kind,
            "bid_amount_usdc_cents": bid.bid_amount_usdc_cents,
        });
        self.rest().exchange().post_signed(wallet, action).await
    }

    /// Query the L1 for `address`'s outstanding deploy credits.
    ///
    /// Returns the count of pending credits — `0` means "no credit yet
    /// awarded", non-zero means "you may run a deploy sequence".
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`ClientError`].
    pub async fn check_deploy_credit(&self, address: Address) -> Result<u32, ClientError> {
        // Returns a small wrapper struct so we don't depend on a free-form Value.
        #[derive(Deserialize)]
        struct CreditResp {
            credit_count: u32,
        }
        let body = json!({
            "type": "deploy_credit",
            "address": address,
        });
        let resp: CreditResp = self.rest().info().raw(body).await.and_then(|v: Value| {
            serde_json::from_value::<CreditResp>(v).map_err(ClientError::from)
        })?;
        Ok(resp.credit_count)
    }

    /// Block (async-sleep) until `wallet`'s address has at least one pending
    /// deploy credit, or `max_wait` elapses.
    ///
    /// Uses exponential backoff capped at 5 seconds. `max_wait` must be
    /// `Some(d)` — there is intentionally no infinite-wait variant; long-
    /// running auctions are caller's job to compose.
    ///
    /// # Errors
    /// - [`ClientError::Validation`] if `max_wait` ≤ `Duration::ZERO` or if
    ///   the wait elapses without seeing a credit.
    /// - Bubbles up [`Client::check_deploy_credit`] errors.
    pub async fn await_deploy_credit(
        &self,
        wallet: &Wallet,
        max_wait: Duration,
    ) -> Result<(), ClientError> {
        if max_wait.is_zero() {
            return Err(ClientError::Validation(
                "await_deploy_credit: max_wait must be > 0".into(),
            ));
        }
        let deadline = Instant::now() + max_wait;
        let mut delay = Duration::from_millis(500);
        let cap = Duration::from_secs(5);

        loop {
            let credits = self.check_deploy_credit(wallet.address()).await?;
            if credits > 0 {
                return Ok(());
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(ClientError::Validation(format!(
                    "await_deploy_credit: timed out after {:?} without seeing credit",
                    max_wait
                )));
            }
            let remaining = deadline - now;
            let sleep_for = delay.min(remaining);
            sleep(sleep_for).await;
            delay = (delay * 2).min(cap);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auction_kind_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&AuctionKind::TokenRegister).unwrap(),
            "\"token_register\""
        );
        assert_eq!(
            serde_json::to_string(&AuctionKind::PerpDeploy).unwrap(),
            "\"perp_deploy\""
        );
        assert_eq!(
            serde_json::to_string(&AuctionKind::SpotPairDeploy).unwrap(),
            "\"spot_pair_deploy\""
        );
    }

    #[test]
    fn auction_bid_round_trips() {
        let b = AuctionBid {
            kind: AuctionKind::PerpDeploy,
            bid_amount_usdc_cents: 150_000_000, // $1.5M in cents
        };
        let j = serde_json::to_string(&b).unwrap();
        let dec: AuctionBid = serde_json::from_str(&j).unwrap();
        assert_eq!(b, dec);
    }

    #[test]
    fn bid_receipt_round_trips() {
        let r = BidReceipt {
            round_id: 42,
            bidder: Address::ZERO,
            accepted_amount_usdc_cents: 100_000_000, // $1.0M in cents
            status: "accepted".into(),
        };
        let j = serde_json::to_string(&r).unwrap();
        let dec: BidReceipt = serde_json::from_str(&j).unwrap();
        assert_eq!(r, dec);
    }

    #[tokio::test]
    async fn await_deploy_credit_rejects_zero_wait() {
        let c = Client::new("https://devnet-gateway.mtf.exchange").unwrap();
        let w = Wallet::random_for_testing();
        let err = c.await_deploy_credit(&w, Duration::ZERO).await.unwrap_err();
        assert!(matches!(err, ClientError::Validation(_)));
    }
}
