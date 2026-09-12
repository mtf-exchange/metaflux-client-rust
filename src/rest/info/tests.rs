//! Unit tests for the `/info` response shapes.
//!
//! Split out of `info.rs`, which was past the 4096-line cap.

use super::*;

/// Vault shares ride ONE plane on both the read and the write, so a
/// redemption sends back the exact string the read gave.
///
/// The pairs are the node's own: the raw share counts its share-rendering
/// test sweeps, converted at the 10^18 share scale. The largest is the
/// 96-bit decimal-mantissa ceiling, 2^96-1, where the conversion is still
/// exact.
#[test]
fn vault_shares_read_then_withdraw_that_exact_string() {
    const GOLDENS: &[(u128, &str)] = &[
        (0, "0"),
        (1, "0.000000000000000001"),
        (1_000_000_000_000_000_000, "1"),
        (12_345_000_000_000_000_000_000, "12345"),
        (
            79_228_162_514_264_337_593_543_950_335,
            "79228162514.264337593543950335",
        ),
    ];

    for (raw, whole) in GOLDENS {
        let served = serde_json::json!({
            "vault_id": 7u64,
            "vault_address": "0x000000000000000000000000000000000000dead",
            "shares": whole,
            "equity": "5000000000",
        });
        let eq: VaultEquity = serde_json::from_value(served).unwrap();
        assert_eq!(eq.shares, *whole, "the read plane is whole shares");

        // The withdraw carries the read string unchanged.
        let shares = crate::types::WholeShares::from(eq.shares.as_str());
        assert_eq!(shares.to_string(), *whole);
        assert_eq!(
            serde_json::to_value(&shares).unwrap(),
            serde_json::json!(whole),
            "the newtype is transparent on the wire"
        );

        // A caller that believed the old "18-dec" claim would send this.
        if *raw != 0 {
            assert_ne!(
                shares.to_string(),
                raw.to_string(),
                "raw={raw} must never ride the wire rescaled by 10^18"
            );
        }
    }
}

/// `undelegated_pool_balance` is absent on an older node. Absent must decode
/// as unknown, never as a zero balance.
#[test]
fn staking_snapshot_absent_free_pool_is_none_not_zero() {
    let without = serde_json::json!({ "total_staked": "1000" });
    let s: StakingSnapshot = serde_json::from_value(without).unwrap();
    assert_eq!(s.undelegated_pool_balance, None);

    let with = serde_json::json!({
        "total_staked": "1000",
        "undelegated_pool_balance": "250",
    });
    let s: StakingSnapshot = serde_json::from_value(with).unwrap();
    assert_eq!(s.undelegated_pool_balance.as_deref(), Some("250"));
}

/// A weight of `"0"` beside a large `amount` is the whole point of the field:
/// the row earns nothing at its tier. An older node sends neither field, and
/// absent must stay unknown so it cannot read as that zero.
#[test]
fn delegation_row_carries_lock_tier_and_weight() {
    let served = serde_json::json!({
        "validator": "0x0000000000000000000000000000000000000009",
        "amount": "1000",
        "since_ts": 1_700_000_000_000u64,
        "pending_rewards": "0",
        "lock_months": 0,
        "reward_weight": "0",
    });
    let d: Delegation = serde_json::from_value(served).unwrap();
    assert_eq!(d.lock_months, Some(0));
    assert_eq!(d.reward_weight.as_deref(), Some("0"));

    let legacy = serde_json::json!({
        "validator": "0x0000000000000000000000000000000000000009",
        "amount": "1000",
        "since_ts": 1_700_000_000_000u64,
        "pending_rewards": "0",
    });
    let d: Delegation = serde_json::from_value(legacy).unwrap();
    assert_eq!(d.lock_months, None);
    assert_eq!(d.reward_weight, None);
}

/// Stamp the committed as-of block onto an overview-shape fixture.
fn with_as_of(mut body: serde_json::Value) -> serde_json::Value {
    body["height"] = serde_json::json!(562u64);
    body["time"] = serde_json::json!(1_700_000_000_555u64);
    body
}

/// Decode the DEPLOYED gateway `markets.data` shape: an object
/// `{ "perp": [...], "spot": {...} }`, not a flat array. `markets` must
/// return the perp records (pre-fix: `invalid type: map, expected sequence`).
#[test]
fn markets_meta_decodes_perp_spot_object() {
    #[derive(serde::Deserialize)]
    struct MarketsResp {
        #[serde(default)]
        perp: Vec<MarketMeta>,
    }
    let data = serde_json::json!({
        "perp": [{
            "coin": "BTC", "signing_id": 0, "kind": "perp", "sz_decimals": 5,
            "mark_px": "64000", "oracle_px": "64000", "mid_px": "64000",
            "mark_source": "oracle_median", "fba_enabled": false,
            "change_24h": "0", "day_ntl_vlm": "0", "premium": "0", "prev_day_px": "64000",
            "tick_size": "1000000", "step_size": "1", "min_order": "1",
            "max_leverage": 50, "init_margin_ratio": "200", "maint_margin_ratio": "300",
            "margin_tiers": [
                { "max_open_interest": "100000", "max_leverage": 50, "maint_margin_ratio": "100" },
                { "max_open_interest": null, "max_leverage": 5, "maint_margin_ratio": "1000" }
            ],
            "open_interest": "0", "funding": {
                "rate_per_hr": "0", "cap_per_hr": "400", "interval_ms": 3600000,
                "next_payment_ts": 0 },
            "token": {
                "id": 0, "wei_decimals": 8,
                "token_id": "0x00000000000000000000000000000000000000000000000000000000000000aa",
                "system_address": "0x0000000000000000000000000000000000000200",
                "evm_contract": { "address": "0x0000000000000000000000000000000000012345",
                                  "evm_extra_wei_decimals": 0 },
                "is_canonical": true, "circulating_supply": "21000000"
            }
        }, {
            // A perp with NO registered underlying token omits `token` -> None.
            "coin": "ETH", "signing_id": 1, "kind": "perp", "sz_decimals": 4,
            "mark_source": "oracle_median", "fba_enabled": false,
            "tick_size": "100000", "step_size": "1", "min_order": "1",
            "max_leverage": 25, "init_margin_ratio": "400", "maint_margin_ratio": "500"
        }],
        "spot": { "pairs": [], "tokens": [] }
    });
    let resp: MarketsResp = serde_json::from_value(data).unwrap();
    assert_eq!(resp.perp.len(), 2);
    assert_eq!(resp.perp[0].coin, "BTC");
    assert_eq!(resp.perp[0].margin_tiers.len(), 2);
    // Perp underlying-token block: EVM binding + circulating_supply.
    let tok = resp.perp[0].token.as_ref().unwrap();
    assert_eq!(tok.id, 0);
    assert_eq!(tok.circulating_supply, "21000000");
    assert_eq!(
        tok.evm_contract.as_ref().unwrap().address,
        "0x0000000000000000000000000000000000012345"
    );
    assert!(tok.is_canonical);
    // The second perp omits `token` entirely -> None.
    assert!(resp.perp[1].token.is_none());
}

/// The DYNAMIC `markets` row, byte-for-byte from chain 114514 on 2026-08-08.
///
/// It carries no `sz_decimals` / `tick_size` / `step_size` / `min_order` /
/// `max_leverage` / margin ratios / `mark_source` / `fba_enabled`, so
/// [`MarketMeta`] cannot decode it. The old hand-written fixture above did
/// carry them, which is why the mismatch went unseen — pin the real reply.
#[test]
fn markets_dynamic_row_decodes_live_reply() {
    let row = serde_json::json!({
        "change_24h": "0.01186283",
        "coin": "BTC",
        "day_ntl_vlm": "0",
        "funding": { "cap_per_hr": "400", "interval_ms": 3_600_000u64,
                     "next_payment_ts": 1_786_165_200_000u64, "rate_per_hr": "-3" },
        "halted": false,
        "impact_pxs": ["64998", "65030.7"],
        "kind": "perp",
        "mark_px": "65013.3",
        "mid_px": "65014.4",
        "open_interest": "0.7895",
        "oracle_px": "65033.7",
        "premium": "-0.00029993",
        "prev_day_px": "64251.1"
    });
    assert!(
        serde_json::from_value::<MarketMeta>(row.clone()).is_err(),
        "the static type must not silently accept a dynamic row"
    );

    let m: MarketDynamic = serde_json::from_value(row).unwrap();
    assert_eq!(m.coin, "BTC");
    assert_eq!(m.mark_px, "65013.3");
    assert_eq!(m.mid_px.as_deref(), Some("65014.4"));
    assert_eq!(m.impact_pxs.unwrap(), vec!["64998", "65030.7"]);
    assert_eq!(m.funding.cap_per_hr, "400");
    assert!(!m.halted);
    // A healthy market omits both markers; neither may read as a value.
    assert!(m.px_stale.is_none());
    assert!(m.day_ntl_vlm_lower_bound_from.is_none());
}

/// `user_position_history`: the envelope is address + rows, and a degraded
/// row keeps its numbers null rather than plausible.
#[test]
fn user_position_history_decodes_degraded_row() {
    let data = serde_json::json!({
        "address": "0x0c4ec1cba7310669b08145f17a29b1048d9196ab",
        "positions": [{
            "avg_close_px": "74.75000000", "avg_entry_px": null,
            "close_block": 6_831_775u64, "close_complete": false,
            "closed_at": 1_786_162_051_867u64, "closed_pnl": "0.8960000000",
            "closed_sz": "0.80", "coin": "SOL", "entry_complete": false,
            "fee_paid": "0.001794", "funding_complete": false, "funding_paid": "0",
            "max_sz": null, "net_pnl": "0.8942060000", "open_block": 6_831_775u64,
            "opened_at": 1_786_162_051_867u64, "realized_pnl": "0.8942060000",
            "side": "long"
        }]
    });
    let h: UserPositionHistory = serde_json::from_value(data).unwrap();
    let p = &h.positions[0];
    assert_eq!(p.coin, "SOL");
    assert_eq!(p.side, "long");
    assert_eq!(p.closed_sz, "0.80");
    assert!(!p.entry_complete);
    assert!(p.avg_entry_px.is_none());
    assert!(p.max_sz.is_none());
    // funding_paid reads "0" while funding_complete is false: UNKNOWN, not zero.
    assert_eq!(p.funding_paid, "0");
    assert!(!p.funding_complete);
}

/// TODAY'S live reply must decode, not just tomorrow's. Chain 114514 on
/// 2026-08-08 still serves `closed_qty` AND the `coverage` envelope that the
/// batch deletes. The gateway carries both size keys across the deploy
/// window, so the client reads either into the one approved name, and the
/// retired envelope must pass through as an ignored key rather than a
/// decode error.
#[test]
fn position_history_accepts_the_old_size_key() {
    let data = serde_json::json!({
        "address": "0x0c4ec1cba7310669b08145f17a29b1048d9196ab",
        "coverage": { "fills_gaps": [{ "from": 336_421u64, "to": 336_421u64 }],
                      "truncated": false, "complete": false },
        "positions": [{
            "coin": "SOL", "side": "long", "max_sz": "1", "closed_qty": "0.80",
            "avg_entry_px": "70", "avg_close_px": "74.75", "closed_pnl": "3.8",
            "fee_paid": "0.001794", "realized_pnl": "3.798206",
            "funding_paid": "0", "net_pnl": "3.798206",
            "opened_at": 1u64, "closed_at": 2u64, "open_block": 1u64,
            "close_block": 2u64, "entry_complete": true, "close_complete": true,
            "funding_complete": true
        }]
    });
    let h: UserPositionHistory = serde_json::from_value(data).unwrap();
    assert_eq!(h.positions[0].closed_sz, "0.80");
}

/// `account_state.balances`: a row with no recorded basis says `null`, and
/// a bought row carries the whole-row cost.
#[test]
fn token_balance_carries_optional_avg_entry_px() {
    let rows = serde_json::json!([
        { "name": "USDC", "signing_id": 100, "total": "390548", "hold": "390548" },
        { "name": "MTF", "signing_id": 104, "total": "10000039.5196599",
          "hold": "3000000", "avg_entry_px": "412.5" }
    ]);
    let b: Vec<TokenBalance> = serde_json::from_value(rows).unwrap();
    // Deposited / pre-basis holdings carry no entry — never a zero.
    assert!(b[0].avg_entry_px.is_none());
    assert_eq!(b[1].avg_entry_px.as_deref(), Some("412.5"));
}

/// Decode the exact `l2_book.data` payload from the `/info` contract.
#[test]
fn l2_book_decodes_doc_fixture() {
    let data = serde_json::json!({
        "bids": [{ "px": "100.49", "sz": "1", "n_orders": 5 }],
        "asks": [{ "px": "100.51", "sz": "2", "n_orders": 3 }]
    });
    // The retired `size` level key must NOT decode.
    assert!(
        serde_json::from_value::<L2Level>(
            serde_json::json!({ "px": "100.49", "size": "1", "n_orders": 5 })
        )
        .is_err()
    );
    let b: L2Book = serde_json::from_value(data).unwrap();
    assert_eq!(b.bids.len(), 1);
    assert_eq!(b.bids[0].px, "100.49");
    assert_eq!(b.bids[0].sz, "1");
    assert_eq!(b.bids[0].n_orders, 5);
    assert_eq!(b.asks[0].n_orders, 3);
    // px/sz serialize as strings.
    let j = serde_json::to_value(&b).unwrap();
    assert!(j["bids"][0]["px"].is_string());
    assert!(j["bids"][0]["sz"].is_string());
    assert!(j["bids"][0]["n_orders"].is_number());
}

/// Decode a body CAPTURED FROM THE LIVE CHAIN, not hand-written.
///
/// The previous fixture was authored beside the type and carried `id` with a
/// non-null `mark_px`. It stayed green while the real call failed on every
/// request, because a fixture that shares the type's assumption cannot fail
/// on drift. Re-capture this body when the wire moves.
#[test]
fn spot_meta_decodes_a_captured_live_body() {
    let data = serde_json::json!({
        "pairs": [{
            "active": false,
            "base": 101,
            "circulating_supply": "0",
            "day_ntl_vlm": "0",
            "deployer": "0x17c5185167401ed00cf5f5b2fc97d9bbfdb7d025",
            "mark_px": null,
            "mid_px": null,
            "min_notional": "1",
            "name": "BTC/USDC",
            "prev_day_px": null,
            "quote": 100,
            "registered_at": 0,
            "signing_id": 110,
            "sz_decimals": 5,
            "taker_fee_bps": "5"
        }],
        "tokens": [{
            "evm_contract": null,
            "id": 100,
            "is_canonical": true,
            "name": "USDC",
            "system_address": "0x80abd3bd8c42d2a279e4fa00f20bb30637734371",
            "sz_decimals": 2,
            "token_id": "0xf23ea17597e324c04f842e6d8bfffe75636f0af88e7c7ab93ea755d9056396bc",
            "total_supply": "0",
            "wei_decimals": 6
        }]
    });
    let m: SpotMeta = serde_json::from_value(data).unwrap();
    assert_eq!(m.pairs[0].signing_id, 110);
    assert_eq!(m.pairs[0].name, "BTC/USDC");
    assert_eq!(m.pairs[0].base, 101);
    assert_eq!(m.pairs[0].quote, 100);
    assert_eq!(m.pairs[0].sz_decimals, 5);
    assert_eq!(m.pairs[0].taker_fee_bps.as_deref(), Some("5"));
    assert!(!m.pairs[0].active);
    // An inactive pair prices as an explicit null, which `serde(default)`
    // does NOT cover. This assertion is the one that was failing live.
    assert_eq!(m.pairs[0].mark_px, None);
    assert_eq!(m.pairs[0].mid_px, None);
    assert_eq!(m.tokens[0].name, "USDC");
    assert_eq!(m.tokens[0].wei_decimals, 6);
    assert!(m.tokens[0].evm_contract.is_none());
    assert!(m.tokens[0].is_canonical);
}

/// The `spot_meta()` wrapper decodes the `markets_meta` kind=spot envelope:
/// the `spot` sub-object is RETAINED even when kind-filtered.
#[test]
fn markets_meta_kind_spot_wrapper_decodes() {
    #[derive(serde::Deserialize)]
    struct Resp {
        #[serde(default)]
        spot: SpotMeta,
    }
    let data = serde_json::json!({
        "spot": {
            "pairs": [{
                "signing_id": 110, "name": "BTC/USDC", "base": 101, "quote": 100,
                "taker_fee_bps": null, "min_notional": "1", "active": false,
                "mark_px": null
            }],
            "tokens": [
                { "id": 0, "name": "BTC", "sz_decimals": 5, "wei_decimals": 8 }
            ]
        }
    });
    let resp: Resp = serde_json::from_value(data).unwrap();
    assert_eq!(resp.spot.pairs.len(), 1);
    assert_eq!(resp.spot.pairs[0].name, "BTC/USDC");
    // No deployer override — the common case. A non-optional type failed
    // the whole response here, not just this field.
    assert_eq!(resp.spot.pairs[0].taker_fee_bps, None);
    // Older/minimal token rows (no evm block) still decode via defaults.
    assert_eq!(resp.spot.tokens[0].name, "BTC");
    assert!(resp.spot.tokens[0].evm_contract.is_none());
    assert_eq!(resp.spot.tokens[0].total_supply, "");
}

/// `L2BookParams` serializes with snake_case keys and OMITS `None` fields,
/// so a params-less request carries no aggregation keys.
#[test]
fn l2_book_params_serialize_omits_none() {
    let empty = L2BookParams::default();
    let j = serde_json::to_value(empty).unwrap();
    assert!(j.get("n_sig_figs").is_none());
    assert!(j.get("mantissa").is_none());
    assert!(j.get("n_levels").is_none());

    let p = L2BookParams {
        n_sig_figs: Some(5),
        mantissa: Some(2),
        n_levels: Some(20),
    };
    let j = serde_json::to_value(p).unwrap();
    assert_eq!(j["n_sig_figs"], 5);
    assert_eq!(j["mantissa"], 2);
    assert_eq!(j["n_levels"], 20);
}

/// A spot pair l2_book renders real depth and may echo `coin`.
#[test]
fn l2_book_decodes_spot_pair_with_coin_echo() {
    let data = serde_json::json!({
        "coin": "BTC/USDC",
        "bids": [{ "px": "61550", "sz": "1.5", "n_orders": 2 }],
        "asks": [{ "px": "61551", "sz": "0.8", "n_orders": 1 }]
    });
    let b: L2Book = serde_json::from_value(data).unwrap();
    assert_eq!(b.coin, "BTC/USDC");
    assert_eq!(b.bids.len(), 1);
    assert_eq!(b.asks[0].px, "61551");
}

/// Decode the deployed gateway `fee_schedule.data`: string bps + tiers[].
#[test]
fn fee_schedule_decodes_gateway_fixture() {
    let data = serde_json::json!({
        "maker_bps": "1.0",
        "taker_bps": "5.0",
        "referrer_share_bps": "5.0",
        "burn_ratio": "0.8",
        "tiers": [{ "maker_bps": "1.0", "taker_bps": "5.0", "volume_30d": "0" }]
    });
    let f: FeeSchedule = serde_json::from_value(data).unwrap();
    assert_eq!(f.maker_bps.as_deref(), Some("1.0"));
    assert_eq!(f.referrer_share_bps, "5.0");
    assert_eq!(f.burn_ratio, "0.8");
    assert_eq!(f.tiers.len(), 1);
    assert_eq!(f.tiers[0].taker_bps, "5.0");
    assert_eq!(f.tiers[0].volume_30d, "0");
    let dec: FeeSchedule = serde_json::from_str(&serde_json::to_string(&f).unwrap()).unwrap();
    assert_eq!(f, dec);

    // A source-built node may omit the top-level maker/taker pair.
    let data2 = serde_json::json!({
        "referrer_share_bps": "5.0",
        "burn_ratio": "0.8",
        "tiers": [{ "maker_bps": "1.0", "taker_bps": "5.0", "volume_30d": "0" }]
    });
    let f2: FeeSchedule = serde_json::from_value(data2).unwrap();
    assert!(f2.maker_bps.is_none() && f2.taker_bps.is_none());
}

/// The address form carries a `user` block with per-product rows.
#[test]
fn fee_schedule_decodes_the_per_product_user_block() {
    let data = serde_json::json!({
        "type": "fee_schedule",
        "tiers": [],
        "burn_ratio": "0.30",
        "referrer_share_bps": "1.0",
        "user": {
            "address": "0x00000000000000000000000000000000000000aa",
            "taker_volume_30d": "12500000",
            "maker_volume_30d": "3100000",
            "taker_bps": "4.5",
            "maker_bps": "1.5",
            "effective_taker_bps": "4.05",
            "effective_maker_bps": "1.2",
            "staking_discount_permille": 100,
            "maker_rebate_bps": "0.3",
            "products": [
                { "product": "perp", "taker_bps": "4.05", "maker_bps": "1.2",
                  "taker_volume_30d": "12500000", "maker_volume_30d": "3100000" },
                { "product": "spot_margin", "taker_bps": "9.0", "taker_volume_30d": "0" },
                { "product": "option", "option_taker_bps": "0.5",
                  "option_premium_cap_ppm": 150000 }
            ]
        }
    });
    let f: FeeSchedule = serde_json::from_value(data).unwrap();
    let u = f.user.expect("the address form carries a user block");
    assert_eq!(u.staking_discount_permille, 100);
    assert_eq!(u.products.len(), 3);
    // A maker rate CAN be negative — that is a credit, not a malformed rate.
    assert_eq!(u.products[0].maker_bps.as_deref(), Some("1.2"));
    assert_eq!(u.products[0].taker_bps.as_deref(), Some("4.05"));
    // A product with no maker leg OMITS both maker keys. `None` here is
    // "no maker leg", which is NOT the same fact as a maker rate of zero.
    assert_eq!(u.products[1].product, "spot_margin");
    assert_eq!(u.products[1].maker_bps, None);
    assert_eq!(u.products[1].maker_volume_30d, None);
    // The option row is a DIFFERENT shape: no ladder tier, no volume, and
    // the two rates that actually decide its fee.
    assert_eq!(u.products[2].product, "option");
    assert_eq!(u.products[2].taker_bps, None, "no ladder tier on an option");
    assert_eq!(u.products[2].taker_volume_30d, None);
    assert_eq!(u.products[2].option_taker_bps.as_deref(), Some("0.5"));
    assert_eq!(u.products[2].option_premium_cap_ppm, Some(150_000));
}

/// The ladder-only read carries no `user` key, and an older server carries
/// no `products`. Neither may fail the decode.
#[test]
fn fee_schedule_tolerates_an_absent_user_and_absent_products() {
    let bare: FeeSchedule = serde_json::from_value(serde_json::json!({
        "type": "fee_schedule", "tiers": [],
        "burn_ratio": "0.30", "referrer_share_bps": "1.0"
    }))
    .unwrap();
    assert!(bare.user.is_none());

    let old: FeeSchedule = serde_json::from_value(serde_json::json!({
        "type": "fee_schedule", "tiers": [],
        "burn_ratio": "0.30", "referrer_share_bps": "1.0",
        "user": {
            "address": "0x00000000000000000000000000000000000000aa",
            "taker_volume_30d": "0", "maker_volume_30d": "0",
            "taker_bps": "4.5", "maker_bps": "1.5",
            "effective_taker_bps": "4.5", "effective_maker_bps": "1.5",
            "staking_discount_permille": 0, "maker_rebate_bps": "0"
        }
    }))
    .unwrap();
    assert!(old.user.expect("user present").products.is_empty());
}

/// The CURRENT node `fee_schedule` body, key for key. It carries no broker
/// rebate at all — the field was removed server-side, and the node's own
/// tests now assert its absence — so the SDK must not offer one to read.
#[test]
fn fee_schedule_decodes_the_current_node_body() {
    let data = serde_json::json!({
        "tiers": [
            { "volume_30d": "0", "maker_bps": "1.0", "taker_bps": "5.0" },
            { "volume_30d": "5000000", "maker_bps": "0.8", "taker_bps": "4.0" }
        ],
        "pooled_volume_sunset_day": 20_500,
        "pooled_volume_sunset_ms": "1771200000000",
        "pooled_volume_counts": true,
        "burn_ratio": "0.7",
        "referrer_share_bps": "1000"
    });
    let f: FeeSchedule = serde_json::from_value(data).unwrap();
    assert_eq!(f.tiers.len(), 2);
    assert_eq!(f.tiers[1].taker_bps, "4.0");
    assert_eq!(f.pooled_volume_sunset_day, Some(20_500));
    assert_eq!(f.pooled_volume_counts, Some(true));
    assert_eq!(f.referrer_share_bps, "1000");
    assert!(f.maker_bps.is_none() && f.taker_bps.is_none());
    assert!(f.user.is_none());

    let round_trip: FeeSchedule =
        serde_json::from_str(&serde_json::to_string(&f).unwrap()).unwrap();
    assert_eq!(f, round_trip);
}

/// Decode the node `open_orders.data`. One canonical row serves the REST
/// read, the WS snapshot, and the inner `order` of a WS `order_updates`
/// record; parked triggers ride in the same set.
#[test]
fn open_orders_decodes_node_wire() {
    let data = serde_json::json!({
        "address": "0x000000000000000000000000000000000000beef",
        "orders": [
            { "oid": 4242, "coin": "BTC", "side": "B", "px": "25000", "sz": "60",
              "orig_sz": null, "tif": "gtc", "reduce_only": false, "trigger": null,
              "cloid": "0x0000000000000000000000000000abcd",
              "inserted_at": 1_700_000_000_000u64 },
            { "oid": 4243, "coin": "BTC/USDC", "side": "A", "px": "35000", "sz": "10",
              "orig_sz": null, "tif": "alo", "reduce_only": false, "trigger": null,
              "cloid": null, "inserted_at": 1_700_000_000_001u64 },
            { "oid": 4244, "coin": "ETH", "side": "A", "px": "1800", "sz": "3",
              "orig_sz": null, "tif": "trigger", "reduce_only": true,
              "trigger": { "trigger_px": "1800", "trigger_above": false,
                           "is_parked": true, "is_market": false, "limit_px": "1795" },
              "cloid": null, "inserted_at": 1_700_000_000_002u64 }
        ]
    });
    let o: OpenOrders = serde_json::from_value(data).unwrap();
    assert_eq!(o.orders.len(), 3);

    // Perp resting row.
    assert_eq!(o.orders[0].oid, 4242);
    assert_eq!(o.orders[0].coin, "BTC");
    assert_eq!(o.orders[0].side, OrderSide::Bid);
    assert_eq!(o.orders[0].sz, "60");
    assert_eq!(o.orders[0].tif.as_deref(), Some("gtc"));
    assert_eq!(o.orders[0].reduce_only, Some(false));
    assert_eq!(o.orders[0].orig_sz, None);
    assert_eq!(o.orders[0].inserted_at, 1_700_000_000_000);
    assert_eq!(
        o.orders[0].cloid.as_deref(),
        Some("0x0000000000000000000000000000abcd")
    );

    // Spot resting row: `coin` is the pair name; cloid absent -> None.
    assert_eq!(o.orders[1].coin, "BTC/USDC");
    assert_eq!(o.orders[1].side, OrderSide::Ask);
    assert_eq!(o.orders[1].cloid, None);

    // Parked trigger row: the detail the retired `frontend_open_orders` read
    // carried. `tif` is the non-TIF token "trigger", so the field stays a
    // String — a closed TIF enum would reject this row.
    let parked = &o.orders[2];
    assert_eq!(parked.tif.as_deref(), Some("trigger"));
    assert_eq!(parked.reduce_only, Some(true));
    let t = parked.trigger.as_ref().unwrap();
    assert_eq!(t.trigger_px, "1800");
    assert!(!t.trigger_above);
    assert_eq!(t.is_parked, Some(true));
    assert_eq!(t.is_market, Some(false));
    assert_eq!(t.limit_px.as_deref(), Some("1795"));

    let j = serde_json::to_value(&o).unwrap();
    assert_eq!(j["orders"][0]["side"], "B");
    assert_eq!(j["orders"][1]["side"], "A");
    assert!(j["orders"][0]["oid"].is_number());
    // The retired top-level `account_id` is never emitted.
    assert!(j.get("account_id").is_none());
    let dec: OpenOrders = serde_json::from_str(&serde_json::to_string(&o).unwrap()).unwrap();
    assert_eq!(o, dec);
}

/// The retired `"bid"` / `"ask"` side tokens and the retired `size` /
/// `inserted_at_ms` keys must all fail to decode.
#[test]
fn open_order_rejects_the_pre_wire_v2_row() {
    let legacy = serde_json::json!({
        "oid": 1, "coin": "BTC", "side": "bid", "px": "1", "size": "2",
        "inserted_at_ms": 3u64
    });
    assert!(serde_json::from_value::<OpenOrder>(legacy).is_err());
    assert!(serde_json::from_value::<OrderSide>(serde_json::json!("bid")).is_err());
    assert_eq!(
        serde_json::from_value::<OrderSide>(serde_json::json!("B")).unwrap(),
        OrderSide::Bid
    );
}

/// Decode a `candle_snapshot` bar using the compact single-letter wire keys.
/// A price bar folds no trades: `v` and `q` are `"0"` and `n` counts price
/// SAMPLES.
#[test]
fn candle_snapshot_bar_decodes_compact_keys() {
    let data = serde_json::json!({
        "s": "BTC",
        "i": "1m",
        "t": 1_700_000_040_000u64,
        "T": 1_700_000_099_999u64,
        "o": "67000.0",
        "c": "67042.5",
        "h": "67080.0",
        "l": "66990.0",
        "v": "0",
        "q": "0",
        "n": 12
    });
    let bar: Candle = serde_json::from_value(data).unwrap();
    assert_eq!(bar.coin, "BTC");
    assert_eq!(bar.interval, "1m");
    assert_eq!(bar.open_time, 1_700_000_040_000);
    assert_eq!(bar.close_time, 1_700_000_099_999);
    assert_eq!(bar.close, "67042.5");
    assert_eq!(bar.volume, "0");
    assert_eq!(bar.quote_volume, "0");
    assert_eq!(bar.num_samples, 12);
    // Round-trips back to the compact keys.
    let j = serde_json::to_value(&bar).unwrap();
    assert_eq!(j["s"], "BTC");
    assert!(j["o"].is_string());
    assert!(j["t"].is_number());
    assert!(j["n"].is_number());
}

/// A carry-forward bar: no sample in the window, so the previous close is
/// carried and `n` is `0`.
#[test]
fn candle_snapshot_bar_decodes_a_carry_forward_bar() {
    let bar: Candle = serde_json::from_value(serde_json::json!({
        "s": "BTC", "i": "1m",
        "t": 1_700_000_100_000u64, "T": 1_700_000_159_999u64,
        "o": "67042.5", "c": "67042.5", "h": "67042.5", "l": "67042.5",
        "v": "0", "q": "0", "n": 0
    }))
    .unwrap();
    assert_eq!(bar.num_samples, 0);
    assert_eq!(bar.open, bar.close);
    assert_eq!(bar.high, bar.low);
}

/// Decode a public `trades_by_time` / `recent_trades` print: symbol coin,
/// A/B side, 0x action hash, big-integer `tid`.
#[test]
fn trade_decodes_symbol_coin_and_hash() {
    let data = serde_json::json!({
        "coin": "BTC",
        "px": "61643.70000000",
        "sz": "0.00024",
        "side": "A",
        "tid": 18232248797686447553u64,
        "block": 37697,
        "hash": "0xd3c94e061264a4e9fd3090f0a65da636377737bc7b8e6e5b0ee839ed3e5d07d7",
        "time": 1783000783768u64
    });
    let t: Trade = serde_json::from_value(data).unwrap();
    assert_eq!(t.coin, "BTC");
    assert_eq!(t.side, "A");
    assert_eq!(t.tid, 18_232_248_797_686_447_553);
    assert_eq!(t.block, 37697);
    assert!(t.hash.as_deref().is_some_and(|h| h.starts_with("0x")));
    // The node sends `""` for a systemic print: recorded, and there was no
    // signed taker action.
    let systemic = serde_json::json!({
        "coin": "BTC", "px": "1", "sz": "1", "side": "B",
        "tid": 1u64, "block": 1, "time": 1u64, "hash": ""
    });
    let s: Trade = serde_json::from_value(systemic).unwrap();
    assert_eq!(s.hash.as_deref(), Some(""), "recorded, and there was none");
    // An archive-served print OMITS the key: the table stores no hash, so
    // the fact is unknown, not empty.
    let archived = serde_json::json!({
        "coin": "BTC", "px": "1", "sz": "1", "side": "B",
        "tid": 2u64, "block": 1, "time": 1u64
    });
    let a: Trade = serde_json::from_value(archived).unwrap();
    assert_eq!(a.hash, None, "not recorded is not the same as empty");
}

// ── P2 wave-1: typed /info read decodes (fixtures pinned to the node
// serializer shapes) ──

/// `order_status` filled branch = EVERY matching leg plus the summed size.
/// An order that filled in two prints must not report one of them.
#[test]
fn order_status_filled_decodes_all_legs() {
    let leg = |sz: &str, tid: &str, block: Option<u64>| {
        let mut v = serde_json::json!({
            "coin": "MTF", "side": "B", "px": "0.12126000", "sz": sz,
            "time": 1_784_820_001_998u64, "oid": "42", "tid": tid,
            "fee": "0.000952", "fee_token": "USDC", "closed_pnl": "0",
            "dir": "Open Long", "start_position": "-357795.12", "hash": ""
        });
        if let Some(b) = block {
            v["block"] = serde_json::json!(b);
        }
        v
    };
    let data = serde_json::json!({
        "status": "filled",
        // `tid` past 2^53 — the reason the wire serves ids as strings.
        "fills": [leg("0.62", "16613428288414605024", None), leg("0.87", "7", Some(8_416_000))],
        "total_filled_sz": "1.49"
    });
    let st: OrderStatus = serde_json::from_value(data).unwrap();
    let OrderStatus::Filled {
        fills,
        total_filled_sz,
    } = &st
    else {
        panic!("expected Filled, got {st:?}");
    };
    assert_eq!(fills.len(), 2);
    assert_eq!(total_filled_sz, "1.49");
    assert_eq!(fills[0].tid, 16_613_428_288_414_605_024);
    assert_eq!(fills[0].oid, 42);
    assert_eq!(fills[0].fee_token.as_deref(), Some("USDC"));
    assert_eq!(fills[0].block, None); // archive-normalized leg carries no block
    assert_eq!(fills[1].block, Some(8_416_000));
}

/// The id family decodes from a STRING and from a NUMBER alike, and a
/// request still serializes it as a number.
#[test]
fn ids_decode_from_string_or_number_and_serialize_numeric() {
    let row = |tid: serde_json::Value| {
        serde_json::json!({
            "coin": "BTC", "px": "67000", "sz": "0.1", "side": "A",
            "tid": tid, "block": 1u64, "time": 1u64
        })
    };
    let a: Trade = serde_json::from_value(row(serde_json::json!("16613428288414605024"))).unwrap();
    let b: Trade =
        serde_json::from_value(row(serde_json::json!(16_613_428_288_414_605_024u64))).unwrap();
    assert_eq!(a.tid, b.tid);
    assert_eq!(a.tid, 16_613_428_288_414_605_024);

    // A cancel is a REQUEST: it accepts either shape but always sends a number.
    let c: crate::types::spot::SpotCancel =
        serde_json::from_str(r#"{"pair":3,"oid":"12345"}"#).unwrap();
    assert_eq!(c.oid, 12345);
    assert_eq!(
        serde_json::to_value(c).unwrap()["oid"],
        serde_json::json!(12345)
    );
}

/// A terminal outcome is its own status, and `unknown` no longer has to
/// stand in for a cancel. The shape is the node's: a `status` beside an
/// `outcome` of exactly `oid` / `coin` / `side` / `time` / `reason`.
#[test]
fn order_status_terminal_states_decode() {
    // A successful cancel names the order only: no side, no reason.
    let data = serde_json::json!({
        "status": "canceled",
        "outcome": {
            "oid": "32535358", "coin": "BTC", "side": null,
            "time": 1_784_820_001_998u64, "reason": null
        }
    });
    let OrderStatus::Canceled { outcome } = serde_json::from_value(data).unwrap() else {
        panic!("expected Canceled");
    };
    assert_eq!(outcome.oid, Some(32_535_358));
    assert_eq!(outcome.coin, "BTC");
    assert_eq!(outcome.side, None);
    assert_eq!(outcome.reason, None);

    // `cancel_rejected` is a status of its own. A caller that branches on
    // `reason` instead of the variant reads this as a cancel.
    let data = serde_json::json!({
        "status": "cancel_rejected",
        "outcome": {
            "oid": "77", "coin": "ETH", "side": null, "time": 5u64,
            "reason": "order not found"
        }
    });
    let OrderStatus::CancelRejected { outcome } = serde_json::from_value(data).unwrap() else {
        panic!("expected CancelRejected");
    };
    assert_eq!(outcome.oid, Some(77));
    assert_eq!(outcome.reason.as_deref(), Some("order not found"));

    // Rejected by cloid: the order never got an oid.
    let data = serde_json::json!({
        "status": "rejected",
        "outcome": {
            "oid": null, "coin": "BTC", "side": "A", "time": 9u64,
            "reason": "insufficient margin"
        }
    });
    let OrderStatus::Rejected { outcome } = serde_json::from_value(data).unwrap() else {
        panic!("expected Rejected");
    };
    assert_eq!(outcome.oid, None);
    assert_eq!(outcome.side, Some(OrderSide::Ask));
}

/// `order_status` resting branch: tick-snapped `px`, `"B"` / `"A"` side, cloid.
#[test]
fn order_status_resting_decodes() {
    let data = serde_json::json!({
        "status": "resting",
        "order": {
            "oid": 7u64, "coin": "BTC", "side": "A", "px": "62500.12",
            "sz": "1.5", "inserted_at": 1u64,
            "cloid": "0x0000000000000000000000000000abcd"
        }
    });
    let OrderStatus::Resting { order } = serde_json::from_value(data).unwrap() else {
        panic!("expected Resting");
    };
    assert_eq!(order.oid, 7);
    assert_eq!(order.side, OrderSide::Ask);
    assert_eq!(order.px, "62500.12");
    assert_eq!(order.sz, "1.5");
    assert_eq!(order.inserted_at, 1);
    assert_eq!(
        order.cloid.as_deref(),
        Some("0x0000000000000000000000000000abcd")
    );
    // cloid absent -> None.
    let no_cloid = serde_json::json!({
        "status": "resting",
        "order": { "oid": 8u64, "coin": "BTC", "side": "B", "px": "1",
                   "sz": "1", "inserted_at": 2u64, "cloid": null }
    });
    let OrderStatus::Resting { order } = serde_json::from_value(no_cloid).unwrap() else {
        panic!("expected Resting");
    };
    assert_eq!(order.side, OrderSide::Bid);
    assert_eq!(order.cloid, None);
}

/// `order_status` triggered branch: market vs limit trigger (`is_market` +
/// `limit_px`).
#[test]
fn order_status_triggered_decodes() {
    let data = serde_json::json!({
        "status": "triggered",
        "trigger": {
            "oid": 9u64, "coin": "BTC", "side": "A", "trigger_px": "60000",
            "trigger_above": false, "sz": "1", "registered_at": 3u64,
            "fired": false, "is_market": false, "limit_px": "59900",
            "cloid": null
        }
    });
    let OrderStatus::Triggered { trigger } = serde_json::from_value(data).unwrap() else {
        panic!("expected Triggered");
    };
    assert!(!trigger.is_market);
    assert_eq!(trigger.limit_px.as_deref(), Some("59900"));
    assert!(!trigger.fired);
    // The node writes the key on every parked leg; a leg with no handle sends
    // `null`.
    assert_eq!(trigger.cloid, None);
    // Market trigger: is_market true, limit_px null.
    let mkt = serde_json::json!({
        "status": "triggered",
        "trigger": { "oid": 9u64, "coin": "BTC", "side": "B",
                     "trigger_px": "60000", "trigger_above": true, "sz": "1",
                     "registered_at": 3u64, "fired": true,
                     "is_market": true, "limit_px": null }
    });
    let OrderStatus::Triggered { trigger } = serde_json::from_value(mkt).unwrap() else {
        panic!("expected Triggered");
    };
    assert!(trigger.is_market);
    assert_eq!(trigger.limit_px, None);
    // Neither key is written on an ordinary trigger, so both stay None.
    assert_eq!(trigger.group, None);
    assert_eq!(trigger.trail_px, None);

    // A ladder leg carries `group`; a trailing leg carries `trail_px`.
    let ladder = serde_json::json!({
        "status": "triggered",
        "trigger": { "oid": 11u64, "coin": "BTC", "side": "A",
                     "trigger_px": "59000", "trigger_above": false, "sz": "1",
                     "registered_at": 3u64, "fired": false,
                     "is_market": true, "limit_px": null,
                     "group": 9u64, "trail_px": "250.5",
                     "cloid": "0x000102030405060708090a0b0c0d0e0f" }
    });
    let OrderStatus::Triggered { trigger } = serde_json::from_value(ladder).unwrap() else {
        panic!("expected Triggered");
    };
    assert_eq!(trigger.group, Some(9));
    assert_eq!(trigger.trail_px.as_deref(), Some("250.5"));
    // `cancel_by_cloid` reaches the parked leg by this handle.
    assert_eq!(
        trigger.cloid.as_deref(),
        Some("0x000102030405060708090a0b0c0d0e0f")
    );
}

/// `order_status` unknown branch.
#[test]
fn order_status_unknown_decodes() {
    let st: OrderStatus =
        serde_json::from_value(serde_json::json!({ "status": "unknown" })).unwrap();
    assert!(matches!(st, OrderStatus::Unknown));
}

/// `historical_orders`: an archive superset row (from `order_canonical`) and a
/// node-fold-only row (Always fields + `block`, no superset).
#[test]
fn historical_orders_decodes_superset_and_fold_rows() {
    let data = serde_json::json!({
        "address": "0x4242424242424242424242424242424242424242",
        "orders": [
            {
                "oid": 9u64, "coin": "MTF", "side": "A", "status": "filled",
                "time": 1_784_820_001_000u64, "px": "194.78000000",
                "filled_sz": "112.2", "hash": "", "limit_px": "194.78000000",
                "avg_px": "194.78000000", "sz": "112.2", "orig_sz": "112.2",
                "total_sz": "112.2", "tif": "Gtc", "reduce_only": false
            },
            {
                "oid": 8u64, "coin": "MTF", "side": "B", "status": "filled",
                "px": "101", "filled_sz": "1.2", "time": 20u64,
                "block": 2u64, "hash": ""
            }
        ]
    });
    let h: HistoricalOrders = serde_json::from_value(data).unwrap();
    assert_eq!(h.orders.len(), 2);
    // Archive superset row.
    let a = &h.orders[0];
    assert_eq!(a.oid, 9);
    assert_eq!(a.px.as_deref(), Some("194.78000000"));
    assert_eq!(a.filled_sz, "112.2");
    assert_eq!(a.avg_px.as_deref(), Some("194.78000000"));
    assert_eq!(a.tif.as_deref(), Some("Gtc"));
    assert_eq!(a.reduce_only, Some(false));
    assert_eq!(a.block, None);
    // Node-fold-only row: superset fields absent -> None; block present.
    let b = &h.orders[1];
    assert_eq!(b.filled_sz, "1.2");
    assert_eq!(b.block, Some(2));
    assert_eq!(b.avg_px, None);
    assert_eq!(b.tif, None);
    assert_eq!(b.reduce_only, None);
}

/// A `historical_orders` row can carry NO price: an order with neither an
/// average fill price nor a limit price sends no `px` key, and a row that
/// reports the price sources sends them as JSON `null`. Both shapes decode to
/// `None`, and neither fails the response.
#[test]
fn historical_orders_decodes_rows_with_no_price() {
    let data = serde_json::json!({
        "address": "0x4242424242424242424242424242424242424242",
        "orders": [
            {
                "oid": 11u64, "coin": "MTF", "side": "B", "status": "error",
                "time": 30u64, "filled_sz": "0", "hash": ""
            },
            {
                "oid": 12u64, "coin": "MTF", "side": "B", "status": "resting",
                "time": 31u64, "filled_sz": "0", "hash": "", "px": null,
                "limit_px": null, "avg_px": null, "total_sz": null
            }
        ]
    });
    let h: HistoricalOrders = serde_json::from_value(data).unwrap();
    assert_eq!(h.orders.len(), 2);
    // Key absent.
    assert_eq!(h.orders[0].px, None);
    assert_eq!(h.orders[0].oid, 11);
    assert_eq!(h.orders[0].filled_sz, "0");
    // Key present, value null.
    assert_eq!(h.orders[1].px, None);
    assert_eq!(h.orders[1].limit_px, None);
    assert_eq!(h.orders[1].avg_px, None);
    assert_eq!(h.orders[1].total_sz, None);
}

/// `user_funding`: the 28-significant-digit `usdc` survives verbatim as a
/// String (values from `funding_canonical`); the `payment` alias also decodes.
#[test]
fn user_funding_28_digit_usdc_survives_and_payment_aliases() {
    let data = serde_json::json!({
        "address": "0x4242424242424242424242424242424242424242",
        "start_time": null,
        "end_time": null,
        "fundings": [
            { "coin": "MTF", "time": 1_784_800_000_000u64,
              "usdc": "0.0189543210987654321098765432",
              "szi": "17415", "funding_rate": "-0.0005" }
        ]
    });
    let f: UserFunding = serde_json::from_value(data).unwrap();
    assert_eq!(f.start_time, None);
    assert_eq!(f.end_time, None);
    assert_eq!(f.fundings.len(), 1);
    // 28-digit value survives byte-for-byte.
    assert_eq!(f.fundings[0].usdc, "0.0189543210987654321098765432");
    assert_eq!(f.fundings[0].coin, "MTF");
    // The future `payment` field name decodes via the alias.
    let aliased = serde_json::json!({
        "coin": "MTF", "time": 1u64, "payment": "1.25",
        "szi": "1", "funding_rate": "0"
    });
    let rec: FundingRecord = serde_json::from_value(aliased).unwrap();
    assert_eq!(rec.usdc, "1.25");
}

/// `user_funding` unknown-address empty shape (node account-history contract).
#[test]
fn user_funding_empty_shape_decodes() {
    let data = serde_json::json!({
        "address": "0x4242424242424242424242424242424242424242",
        "start_time": null, "end_time": null, "fundings": []
    });
    let f: UserFunding = serde_json::from_value(data).unwrap();
    assert!(f.fundings.is_empty());
    assert_eq!(f.start_time, None);
}

/// `user_non_funding_ledger_updates`: the union under the snake_case
/// `ledger_updates` key, and the camelCase key it replaced.
#[test]
fn user_non_funding_ledger_union_decodes_snake_key() {
    let data = serde_json::json!({
        "ledger_updates": [
            { "coin": "USDC", "time": 1_784_800_000_001u64, "kind": "deposit",
              "delta": "100", "counterparty": "0xabc", "chain": "base" },
            { "coin": "USDC", "time": 1_784_800_000_002u64,
              "kind": "liquidation", "delta": "-12.5", "market": 7u32,
              "mark_px": "104.5" },
            { "coin": "MTF", "time": 1_784_800_000_003u64,
              "kind": "staking_reward", "delta": "3" },
            { "coin": "MTF", "time": 1_784_800_000_004u64, "kind": "trade",
              "tid": 77u64, "realized_pnl": "1.5", "fee": "0.02",
              "fee_token": "USDC" }
        ]
    });
    let l: UserNonFundingLedgerUpdates = serde_json::from_value(data).unwrap();
    assert_eq!(l.ledger_updates.len(), 4);
    // Money-movement row, with the bridge chain a deposit carries.
    assert_eq!(l.ledger_updates[0].coin, "USDC");
    assert_eq!(l.ledger_updates[0].kind.as_deref(), Some("deposit"));
    assert_eq!(l.ledger_updates[0].counterparty.as_deref(), Some("0xabc"));
    assert_eq!(l.ledger_updates[0].chain.as_deref(), Some("base"));
    assert_eq!(l.ledger_updates[0].tid, None);
    // Forced-close row: `market` is an ID, `mark_px` the price it used.
    assert_eq!(l.ledger_updates[1].market, Some(7));
    assert_eq!(l.ledger_updates[1].mark_px.as_deref(), Some("104.5"));
    assert_eq!(l.ledger_updates[1].delta.as_deref(), Some("-12.5"));
    // A kind this build predates still decodes.
    assert_eq!(l.ledger_updates[2].kind.as_deref(), Some("staking_reward"));
    // Trade row.
    assert_eq!(l.ledger_updates[3].tid, Some(77));
    assert_eq!(l.ledger_updates[3].realized_pnl.as_deref(), Some("1.5"));
    assert_eq!(l.ledger_updates[3].fee_token.as_deref(), Some("USDC"));
    // Serializes back to snake_case, never to the retired camelCase key.
    let j = serde_json::to_value(&l).unwrap();
    assert!(j.get("ledger_updates").is_some());
    assert!(j.get("ledgerUpdates").is_none());
}

/// The retired camelCase key is NOT accepted. This is the positive control
/// for the test above: it fails the same way if the field simply vanished.
#[test]
fn user_non_funding_ledger_rejects_retired_camel_key() {
    let data = serde_json::json!({
        "ledgerUpdates": [
            { "coin": "USDC", "time": 1u64, "kind": "deposit", "delta": "1" }
        ]
    });
    let l: UserNonFundingLedgerUpdates = serde_json::from_value(data).unwrap();
    assert!(l.ledger_updates.is_empty());
}

/// `user_ledger_updates` (node kind): envelope decodes, records stay raw JSON.
#[test]
fn user_ledger_updates_envelope_decodes_raw_records() {
    let data = serde_json::json!({
        "address": "0x4242424242424242424242424242424242424242",
        "start_time": 5u64, "end_time": 9u64, "updates": []
    });
    let u: UserLedgerUpdates = serde_json::from_value(data).unwrap();
    assert_eq!(u.start_time, Some(5));
    assert_eq!(u.end_time, Some(9));
    assert!(u.updates.is_empty());
}

/// `spot_margin_state`: SYMBOLIZED pair name, `params` present and null.
#[test]
fn spot_margin_state_decodes() {
    let data = serde_json::json!({
        "user": "0x4242424242424242424242424242424242424242",
        "accounts": [
            { "pair": "BTC/USDC", "collateral": "1000", "borrowed": "250.5",
              "borrow_index_snapshot": "1.02", "base_held": "3.14",
              "current_debt": "255.51",
              "params": { "init_bps": "1000", "maint_bps": "500" } },
            { "pair": "ETH/USDC", "collateral": "0", "borrowed": "0",
              "borrow_index_snapshot": "1", "base_held": "0",
              "current_debt": "0", "params": null }
        ]
    });
    let s: SpotMarginState = serde_json::from_value(data).unwrap();
    assert_eq!(s.accounts.len(), 2);
    assert_eq!(s.accounts[0].pair, "BTC/USDC");
    assert_eq!(s.accounts[1].pair, "ETH/USDC");
    assert_eq!(s.accounts[0].current_debt, "255.51");
    // A raw numeric pair id is the pre-wire-v2 shape and must not decode.
    assert!(
        serde_json::from_value::<SpotMarginAccount>(serde_json::json!({
            "pair": 200u32, "collateral": "0", "borrowed": "0",
            "borrow_index_snapshot": "1", "base_held": "0", "current_debt": "0",
            "params": null
        }))
        .is_err()
    );
    let p = s.accounts[0].params.as_ref().unwrap();
    assert_eq!(p.init_bps, "1000");
    assert_eq!(p.maint_bps, "500");
    // Margin-disabled pair: params null.
    assert!(s.accounts[1].params.is_none());
}

/// `user_interest`: the two indices ride the row so a caller can re-derive
/// `accrued`; a pair with no pool carries a null `pool_index`; `earned` is
/// always null.
#[test]
fn user_interest_decodes() {
    let v: UserInterest = serde_json::from_value(json!({
        "user": "0x0000000000000000000000000000000000000001",
        "owed": "2",
        "borrows": [
            {
                "lane": "spot_margin",
                "pair": "MTF/USDC",
                "principal": "20",
                "accrued": "22",
                "interest": "2",
                "index_snapshot": "1",
                "pool_index": "1.1"
            },
            {
                "lane": "spot_margin",
                "pair": "200",
                "principal": "7",
                "accrued": "7",
                "interest": "0",
                "index_snapshot": "1",
                "pool_index": null
            }
        ],
        "earned": null
    }))
    .expect("user_interest decodes");
    assert_eq!(v.owed, "2");
    assert_eq!(v.borrows.len(), 2);
    assert_eq!(v.borrows[0].pool_index.as_deref(), Some("1.1"));
    assert_eq!(v.borrows[1].pool_index, None);
    assert_eq!(v.earned, None);
}

/// `earn_state`: pools with and without the per-user stake fields.
#[test]
fn earn_state_decodes_with_and_without_user() {
    let data = serde_json::json!({
        "pools": [
            { "name": "USDC", "signing_id": 0u32, "total_supplied": "10000", "total_borrowed": "4000",
              "idle": "6000", "shares_total": "9500", "share_value": "1.0526",
              "borrow_index": "1.03", "reserve_factor_bps": "1000",
              "borrow_rate_bps_annual": "550", "reserve_accrued": "12.5",
              "user_shares": "100", "user_value": "105.26" }
        ]
    });
    let e: EarnState = serde_json::from_value(data).unwrap();
    assert_eq!(e.pools.len(), 1);
    assert_eq!(e.pools[0].idle, "6000");
    // The pool token symbol rides beside the numeric asset id.
    assert_eq!(e.pools[0].name, "USDC");
    assert_eq!(e.pools[0].user_shares.as_deref(), Some("100"));
    assert_eq!(e.pools[0].user_value.as_deref(), Some("105.26"));
    // No user: the per-user fields are absent -> None.
    let no_user = serde_json::json!({
        "pools": [
            { "name": "USDC", "signing_id": 0u32, "total_supplied": "1", "total_borrowed": "0",
              "idle": "1", "shares_total": "1", "share_value": "1",
              "borrow_index": "1", "reserve_factor_bps": "0",
              "borrow_rate_bps_annual": "0", "reserve_accrued": "0" }
        ]
    });
    let e2: EarnState = serde_json::from_value(no_user).unwrap();
    assert_eq!(e2.pools[0].user_shares, None);
    assert_eq!(e2.pools[0].user_value, None);
}

/// `user_fills`: a node-ring perp fill WITH `block` + `0x` hash, and a spot
/// fill (raw-plane integer `sz`) WITHOUT `block` (archive-normalized). The
/// canonical perp values mirror `order_status_filled_decodes_canonical_fill`.
#[test]
fn user_fills_decodes_canonical_fills() {
    let data = serde_json::json!({
        "address": "0x4242424242424242424242424242424242424242",
        "fills": [
            {
                "coin": "MTF", "side": "B", "px": "0.12126000", "sz": "112.22",
                "time": 1_784_820_001_998u64, "oid": 42u64, "tid": 7u64,
                "fee": "0.000952", "closed_pnl": "0", "dir": "Open Long",
                "start_position": "-357795.12", "block": 8_416_000u64,
                "hash": "0xabcdef"
            },
            {
                "coin": "MTF/USDC", "side": "A", "px": "0.12130000", "sz": "112",
                "time": 1_784_820_002_000u64, "oid": 43u64, "tid": 8u64,
                "fee": "0.0001", "closed_pnl": "0", "dir": "Sell",
                "start_position": "500", "hash": ""
            }
        ]
    });
    let uf: UserFills = serde_json::from_value(data).unwrap();
    assert_eq!(uf.fills.len(), 2);
    // Node-ring perp fill: block present, 0x hash.
    let perp = &uf.fills[0];
    assert_eq!(perp.coin, "MTF");
    assert_eq!(perp.px, "0.12126000");
    assert_eq!(perp.sz, "112.22");
    assert_eq!(perp.start_position, "-357795.12");
    assert_eq!(perp.block, Some(8_416_000));
    assert_eq!(perp.hash, "0xabcdef");
    // Spot fill: raw-plane integer sz, no block, empty hash.
    let spot = &uf.fills[1];
    assert_eq!(spot.coin, "MTF/USDC");
    assert_eq!(spot.side, "A");
    assert_eq!(spot.sz, "112");
    assert_eq!(spot.block, None);
    assert!(spot.hash.is_empty());
    // Round-trips: address echo preserved.
    let j = serde_json::to_value(&uf).unwrap();
    assert_eq!(
        j.get("address").and_then(Value::as_str),
        Some("0x4242424242424242424242424242424242424242")
    );
}

/// `funding_history`: one unclamped sample (`premium == funding_rate`) and
/// one clamped (`premium` beyond the cap → capped `funding_rate`).
#[test]
fn funding_history_decodes_samples() {
    let data = serde_json::json!({
        "coin": "MTF",
        "samples": [
            { "ts": 1_784_800_000_000u64, "premium": "0.01",
              "funding_rate": "0.01" },
            { "ts": 1_784_800_003_600u64, "premium": "0.05",
              "funding_rate": "0.04" }
        ]
    });
    let fh: FundingHistory = serde_json::from_value(data).unwrap();
    assert_eq!(fh.coin, "MTF");
    assert_eq!(fh.samples.len(), 2);
    assert_eq!(fh.samples[0].ts, 1_784_800_000_000);
    // Unclamped: premium and realized rate agree.
    assert_eq!(fh.samples[0].premium, "0.01");
    assert_eq!(fh.samples[0].funding_rate, "0.01");
    // Clamped: realized rate is the capped value below the premium.
    assert_eq!(fh.samples[1].premium, "0.05");
    assert_eq!(fh.samples[1].funding_rate, "0.04");
}

/// The trigger detail the retired `frontend_open_orders` read carried now
/// rides the enriched `open_orders` row: a two-key block on a resting book
/// order, and the full parked block on an off-book TP / SL row.
#[test]
fn open_orders_carries_the_folded_trigger_detail() {
    let data = serde_json::json!({
        "address": "0x4242424242424242424242424242424242424242",
        "orders": [
            { "oid": 1u64, "coin": "BTC", "side": "B", "px": "62500.12",
              "sz": "1.5", "orig_sz": null, "tif": "gtc", "reduce_only": false,
              "cloid": null, "trigger": null, "inserted_at": 10u64 },
            { "oid": 2u64, "coin": "BTC", "side": "A", "px": "63000",
              "sz": "0.5", "orig_sz": null, "tif": "alo", "reduce_only": false,
              "cloid": "0x0000000000000000000000000000abcd",
              "trigger": { "trigger_px": "62000", "trigger_above": false },
              "inserted_at": 11u64 },
            { "oid": 3u64, "coin": "BTC", "side": "A", "px": "61000",
              "sz": "0.25", "orig_sz": null, "tif": "trigger", "reduce_only": true,
              "cloid": null,
              "trigger": { "trigger_px": "61000", "trigger_above": false,
                           "is_parked": true, "is_market": false,
                           "limit_px": "60950" },
              "inserted_at": 12u64 }
        ]
    });
    let f: OpenOrders = serde_json::from_value(data).unwrap();
    assert_eq!(f.orders.len(), 3);
    // Plain resting order: no trigger, no cloid.
    let plain = &f.orders[0];
    assert_eq!(plain.side, OrderSide::Bid);
    assert_eq!(plain.tif.as_deref(), Some("gtc"));
    assert!(plain.cloid.is_none());
    assert!(plain.trigger.is_none());
    // Resting order with a two-key trigger block: parked keys are None.
    let resting_trig = f.orders[1].trigger.as_ref().unwrap();
    assert_eq!(resting_trig.trigger_px, "62000");
    assert!(!resting_trig.trigger_above);
    assert_eq!(resting_trig.is_parked, None);
    assert_eq!(resting_trig.is_market, None);
    assert_eq!(resting_trig.limit_px, None);
    assert_eq!(
        f.orders[1].cloid.as_deref(),
        Some("0x0000000000000000000000000000abcd")
    );
    // Parked TP/SL-LIMIT row: full trigger block. It is neither a ladder
    // leg nor a trailing leg, so both of those keys stay absent.
    assert_eq!(f.orders[2].tif.as_deref(), Some("trigger"));
    let parked = f.orders[2].trigger.as_ref().unwrap();
    assert_eq!(parked.is_parked, Some(true));
    assert_eq!(parked.is_market, Some(false));
    assert_eq!(parked.limit_px.as_deref(), Some("60950"));
    assert_eq!(parked.group, None);
    assert_eq!(parked.trail_px, None);
}

/// A scaled TP/SL LADDER: three or more `positionTpsl` legs share one
/// `group`, and a trailing leg adds `trail_px`. Both keys are absent on
/// every other row, so the older shapes must keep decoding unchanged.
#[test]
fn open_orders_reads_the_ladder_handle_and_the_trailing_callback() {
    let leg = |oid: u64, group: serde_json::Value, trail: serde_json::Value| {
        let mut t = serde_json::json!({
            "trigger_px": "61000", "trigger_above": false,
            "is_parked": true, "is_market": true, "limit_px": null
        });
        let o = t.as_object_mut().unwrap();
        if !group.is_null() {
            o.insert("group".into(), group);
        }
        if !trail.is_null() {
            o.insert("trail_px".into(), trail);
        }
        serde_json::json!({
            "oid": oid, "coin": "BTC", "side": "A", "px": "61000", "sz": "0.25",
            "orig_sz": null, "tif": "trigger", "reduce_only": true,
            "cloid": null, "trigger": t, "inserted_at": oid
        })
    };
    let data = serde_json::json!({
        "address": "0x4242424242424242424242424242424242424242",
        "orders": [
            leg(7, serde_json::json!(7u64), serde_json::Value::Null),
            leg(8, serde_json::json!(7u64), serde_json::Value::Null),
            leg(9, serde_json::json!(7u64), serde_json::json!("120.25")),
        ]
    });
    let f: OpenOrders = serde_json::from_value(data).unwrap();
    let groups: Vec<Option<u64>> = f
        .orders
        .iter()
        .map(|o| o.trigger.as_ref().unwrap().group)
        .collect();
    // Every leg of one ladder shares the handle of its first leg.
    assert_eq!(groups, vec![Some(7), Some(7), Some(7)]);
    assert_eq!(f.orders[0].trigger.as_ref().unwrap().trail_px, None);
    assert_eq!(
        f.orders[2].trigger.as_ref().unwrap().trail_px.as_deref(),
        Some("120.25")
    );
}

/// `active_asset_data`: `[buy, sell]` pairs as `[String; 2]`, margin_mode,
/// has_position.
#[test]
fn active_asset_data_decodes() {
    let data = serde_json::json!({
        "address": "0x4242424242424242424242424242424242424242",
        "coin": "BTC", "leverage": 20u32, "margin_mode": "cross",
        "mark_px": "62500", "available_to_trade": ["100000", "150000"],
        "max_trade_szs": ["1.6", "2.4"], "max_trade_size": "500",
        "has_position": true
    });
    let a: ActiveAssetData = serde_json::from_value(data).unwrap();
    assert_eq!(a.coin, "BTC");
    assert_eq!(a.leverage, 20);
    assert_eq!(a.margin_mode, "cross");
    assert_eq!(
        a.available_to_trade,
        ["100000".to_string(), "150000".to_string()]
    );
    assert_eq!(a.max_trade_szs, ["1.6".to_string(), "2.4".to_string()]);
    assert_eq!(a.max_trade_size.as_deref(), Some("500"));
    assert!(a.has_position);
}

/// `agents`: one never-expiring / unnamed entry (`name` + `expires_at`
/// both `null`) and one with both set.
#[test]
fn agents_decodes_null_and_set_expiry() {
    let data = serde_json::json!({
        "address": "0x4242424242424242424242424242424242424242",
        "agents": [
            { "agent": "0x1111111111111111111111111111111111111111",
              "name": null, "expires_at": null },
            { "agent": "0x2222222222222222222222222222222222222222",
              "name": "bot-1", "expires_at": 1_800_000_000_000u64 }
        ]
    });
    let a: AccountOverview = serde_json::from_value(with_as_of(data)).unwrap();
    assert_eq!(a.agents.len(), 2);
    // Never-expiring, unnamed.
    assert_eq!(a.agents[0].name, None);
    assert_eq!(a.agents[0].expires_at, None);
    // Named with an expiry.
    assert_eq!(a.agents[1].name.as_deref(), Some("bot-1"));
    assert_eq!(a.agents[1].expires_at, Some(1_800_000_000_000));
}

/// `sub_accounts`: index, address, and the `equity` field the node always
/// emits.
#[test]
fn sub_accounts_decodes_equity() {
    let data = serde_json::json!({
        "address": "0x4242424242424242424242424242424242424242",
        "sub_accounts": [
            { "index": 1u32,
              "address": "0x3333333333333333333333333333333333333333",
              "equity": "1234.5" },
            { "index": 2u32,
              "address": "0x4444444444444444444444444444444444444444",
              "equity": "0" }
        ]
    });
    let s: AccountOverview = serde_json::from_value(with_as_of(data)).unwrap();
    assert_eq!(s.sub_accounts.len(), 2);
    assert_eq!(s.sub_accounts[0].index, 1);
    assert_eq!(s.sub_accounts[0].equity, "1234.5");
    assert_eq!(s.sub_accounts[1].equity, "0");
}
