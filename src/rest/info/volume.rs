//! `/info` — daily traded volume for one account.
//!
//! **NOT LIVE YET.** The archive serves this and the gateway routes it, but
//! neither is released — a live gateway answers `400 UNKNOWN_TYPE` until the
//! next indexer and gateway swap. The type ships ahead so a caller can build
//! against the shape; a rejection before that release is not a client bug.
//!
//! ONE query: [`Info::user_volume_history`], the read behind a "Your Volume
//! History" panel. It is served by the historical archive, not by a validator.
//!
//! ## It is NOT the fee tier
//!
//! The chain's fee ladder reads a **30-day** window, counts each product
//! separately, and rolls only volume that PAID a protocol fee — a zero-fee pair
//! adds nothing to it. This read counts every fill over whatever window is
//! asked for. Read the tier, and the volume the tier saw, from `fee_schedule`
//! with an address.
//!
//! ## The volumes are on the RAW node plane
//!
//! `px` is scaled by `1e8` and `sz` by `10^sz_decimals`, so `px * sz` carries a
//! per-market factor. A figure is a true USDC notional only within ONE market,
//! and a total across markets is not a dollar amount. The archive holds no
//! market registry to normalize with.

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::error::ClientError;
use crate::rest::info::{Info, insert_time_window};
use crate::wallet::Address;

/// One UTC day inside a [`UserVolumeHistory`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct VolumeDay {
    /// The UTC day, `YYYY-MM-DD`.
    pub date: String,
    /// EVERY account's traded notional that day, each print counted once.
    pub exchange_volume: String,
    /// This account's notional as the RESTING side.
    pub maker_volume: String,
    /// This account's notional as the AGGRESSOR.
    pub taker_volume: String,
}

/// `user_volume_history` response — one row per UTC day, newest first.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct UserVolumeHistory {
    /// Echo of the requested account, `0x` hex.
    #[serde(default)]
    pub address: String,
    /// One row per UTC day, newest first. A quiet day has NO ROW; a day the
    /// EXCHANGE traded but this account did not IS present, with the account's
    /// two figures at `"0"`.
    #[serde(default)]
    pub days: Vec<VolumeDay>,
    /// `maker_volume / exchange_volume` over the trailing 14 FULL days. A
    /// fraction, not a percent: `"0.0002"` is 0.02%. `"0"` when the exchange
    /// traded nothing. It does NOT follow the requested window — every page of
    /// [`Self::days`] carries the same share.
    #[serde(default)]
    pub maker_volume_share_14d: String,
    /// The scope and plane caveats, in prose.
    #[serde(default)]
    pub flag: String,
}

impl Info<'_> {
    /// `user_volume_history` — per UTC day, the exchange's traded volume beside
    /// this account's own maker and taker volume, newest day first, plus the
    /// account's trailing 14-day maker share.
    ///
    /// THE CURRENT UTC DAY IS NEVER RETURNED. A partial day reads as a collapse
    /// in volume and makes a fee tier look like it moved, so `end_time` cannot
    /// open it. Both bounds snap to a UTC day.
    ///
    /// The volumes are RAW-plane and the share is a ratio of two RAW-plane
    /// totals — see the module docs. This read is NOT the fee tier.
    ///
    /// # Errors
    /// HTTP / decode / protocol errors per [`crate::ClientError`].
    pub async fn user_volume_history(
        &self,
        address: Address,
        start_time: Option<u64>,
        end_time: Option<u64>,
        limit: Option<u32>,
    ) -> Result<UserVolumeHistory, ClientError> {
        let mut body = json!({ "type": "user_volume_history", "address": address });
        insert_time_window(&mut body, start_time, end_time);
        if let Some(l) = limit {
            let obj = body.as_object_mut().expect("json! produced an object");
            obj.insert("limit".into(), json!(l));
        }
        self.client.post_json("/info", &body).await
    }
}
