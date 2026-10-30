//! Known-answer test: the owner-bound digests EQUAL the node's.
//!
//! Eleven type strings gained an `address owner` word right after
//! `metafluxChain`. The node accepts the owner-less string only as the owner's
//! own signature; an agent must sign the bound form, so its signature cannot be
//! re-posted under another owner. Every digest below is pasted from the node's
//! own KAT emitter (chain 114514 / `"Testnet"`, owner `0x1111…1111`).

use metaflux_client::rest::exchange_typed::_typed_digest_for_test;
use metaflux_client::types::order::{
    CancelOrder, Order, OrderKind, PositionSide, ScheduleCancel, Side, StpMode, TimeInForce, TpSl,
    Trigger,
};
use metaflux_client::types::twap::TwapOrder;
use metaflux_client::types::{MarketId, OrderId};
use metaflux_client::wallet::{
    Address, TypedAction, TypedTradingAction, TypedTradingDigest, metaflux_chain_tag,
    metaflux_domain_separator,
};
use tiny_keccak::{Hasher, Keccak};

const CHAIN: u64 = 114_514;
const NONCE: u64 = 7;

fn owner() -> Address {
    Address([0x11; 20])
}

fn trade_digest(action: TypedTradingAction, nonce: u64) -> String {
    hex::encode(
        TypedTradingDigest::new(action, CHAIN, nonce)
            .digest()
            .expect("digest"),
    )
}

fn account_digest(action: &TypedAction) -> String {
    hex::encode(_typed_digest_for_test(action))
}

fn order(trail: Option<u64>) -> Order {
    Order {
        owner: owner(),
        market: MarketId(1),
        side: Side::Bid,
        kind: OrderKind::Limit,
        size: 1000,
        limit_px: 5_000_000_000_000,
        tif: TimeInForce::Gtc,
        stp_mode: StpMode::CancelOldest,
        reduce_only: false,
        cloid: None,
        builder: None,
        position_side: None,
        trigger: trail.map(|trail_px| Trigger {
            trigger_px: 0,
            is_market: false,
            tpsl: TpSl::Tp,
            trail_px: Some(trail_px),
        }),
    }
}

fn twap(position_side: Option<PositionSide>, randomize: bool) -> TwapOrder {
    TwapOrder {
        market: MarketId(4),
        side: Side::Ask,
        total_size: 1000,
        slice_count: 10,
        delay_ms: 500,
        reduce_only: true,
        position_side,
        randomize,
        owner: Some(owner()),
    }
}

#[test]
fn submit_order_binds_the_owner() {
    assert_eq!(
        trade_digest(TypedTradingAction::SubmitOrder(&order(None)), NONCE),
        "e8bd3a1ac347a666d1cb380be7162fda93c878bc34d9172bbacdd2521aac155b"
    );
}

/// The node's trail vector hashes an EMPTY `triggerTpsl` next to `trailPx = 7`.
/// `Trigger::tpsl` is a mandatory enum, so the SDK cannot post that leg; the
/// vector is pinned through a word-level encoder, and the SDK's own digest for
/// the same leg with `"tp"` must equal that encoder's output.
#[test]
fn submit_order_trail_binds_the_owner() {
    assert_eq!(
        trail_digest_by_hand(""),
        "640607ceda3c78990eb3c95768c69a42f7df84305ccb584aa7a077e79fc13f57"
    );
    assert_eq!(
        trade_digest(TypedTradingAction::SubmitOrder(&order(Some(7))), NONCE),
        trail_digest_by_hand("tp")
    );
}

fn keccak(input: &[u8]) -> [u8; 32] {
    let mut h = Keccak::v256();
    h.update(input);
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    out
}

fn word_u64(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}

fn word_addr(a: &Address) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(&a.0);
    w
}

fn trail_digest_by_hand(tpsl: &str) -> String {
    const TY: &[u8] = b"MetaFluxTransaction:SubmitOrder(string metafluxChain,address owner,uint32 market,string side,string kind,uint64 size,uint64 limitPx,string tif,string stpMode,bool reduceOnly,string cloid,uint16 builderFee,address builderUser,string positionSide,uint64 triggerPx,bool triggerIsMarket,string triggerTpsl,uint64 trailPx,uint64 nonce)";
    let words = [
        keccak(metaflux_chain_tag(CHAIN).as_bytes()),
        word_addr(&owner()),
        word_u64(1),
        keccak(b"bid"),
        keccak(b"limit"),
        word_u64(1000),
        word_u64(5_000_000_000_000),
        keccak(b"gtc"),
        keccak(b"cancel_oldest"),
        word_u64(0),
        keccak(b""),
        word_u64(0),
        word_addr(&Address::ZERO),
        keccak(b""),
        word_u64(0),
        word_u64(0),
        keccak(tpsl.as_bytes()),
        word_u64(7),
        word_u64(NONCE),
    ];
    let mut h = Keccak::v256();
    h.update(&keccak(TY));
    for w in &words {
        h.update(w);
    }
    let mut strukt = [0u8; 32];
    h.finalize(&mut strukt);
    let mut h = Keccak::v256();
    h.update(&[0x19, 0x01]);
    h.update(&metaflux_domain_separator(CHAIN));
    h.update(&strukt);
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    hex::encode(out)
}

#[test]
fn cancel_order_binds_the_owner() {
    let cancel = CancelOrder {
        owner: owner(),
        market: MarketId(1),
        oid: Some(OrderId(42)),
        cloid: None,
    };
    assert_eq!(
        trade_digest(TypedTradingAction::CancelOrder(&cancel), NONCE),
        "58960111f53e7a47f006d040f2bc007ba988d2dbcb3b0806bbf6906bd8fe0548"
    );
}

#[test]
fn schedule_cancel_binds_the_owner() {
    let p = ScheduleCancel {
        cancel_at_block: 9000,
        owner: Some(owner()),
    };
    assert_eq!(
        trade_digest(TypedTradingAction::ScheduleCancel(&p), NONCE),
        "c7256bff6f4ff5a3400a370d424bfe2924c22e3a06a9de4db3fdc1038bb812dd"
    );
}

#[test]
fn twap_order_binds_the_owner_on_all_three_strings() {
    assert_eq!(
        trade_digest(TypedTradingAction::TwapOrder(&twap(None, false)), 48),
        "f5c885724ae108a608a83119e71a84bbac1d9348b59cfe789d7bc90fa7c9855a",
        "v1"
    );
    assert_eq!(
        trade_digest(
            TypedTradingAction::TwapOrder(&twap(Some(PositionSide::Long), false)),
            48
        ),
        "d97d4ad88b28ce4aa47bdce1e9244e18a0f88f45011160fae932119faea1b18e",
        "v2"
    );
    assert_eq!(
        trade_digest(
            TypedTradingAction::TwapOrder(&twap(Some(PositionSide::Short), true)),
            48
        ),
        "914d04d6544236461894a5fdb8df985717983a5380a0c17e64fa3c00cd51e8bc",
        "v3"
    );
}

#[test]
fn account_actions_bind_the_owner() {
    assert_eq!(
        account_digest(&TypedAction::UpdateLeverage {
            metaflux_chain: "Testnet".into(),
            owner: Some(owner()),
            asset: 1,
            leverage: 20,
            is_isolated: false,
            nonce: NONCE,
        }),
        "51a1e33faff20e5f504d1abb72f9fc208f9f3e5d8c8e8c73c4b8e44ed7f4f396",
        "update_leverage"
    );
    assert_eq!(
        account_digest(&TypedAction::UpdateIsolatedMargin {
            metaflux_chain: "Testnet".into(),
            owner: Some(owner()),
            asset: 1,
            delta: "-5".into(),
            nonce: NONCE,
        }),
        "dd62d7c0d8256374abeecc45f15e31bc28cb96bc0f7f097a4aa2bb7191714959",
        "update_isolated_margin"
    );
    assert_eq!(
        account_digest(&TypedAction::TopUpIsolatedOnlyMargin {
            metaflux_chain: "Testnet".into(),
            owner: Some(owner()),
            asset: 1,
            amount: "5".into(),
            nonce: NONCE,
        }),
        "9f178c1b814f5fe81bce49ca7852435cfb821ad4cef8d3d44d8671824b185d5c",
        "top_up_isolated_only_margin"
    );
    assert_eq!(
        account_digest(&TypedAction::SetPositionMode {
            metaflux_chain: "Testnet".into(),
            owner: Some(owner()),
            hedge: true,
            nonce: NONCE,
        }),
        "8261799554b2f20ceacb9d523757fc025f92bc8620b92a2ac583432c207d3642",
        "set_position_mode"
    );
}

/// The owner-less string stays reachable as the owner's own signature.
#[test]
fn the_self_form_stays_distinct() {
    let o = order(None);
    let bound = trade_digest(TypedTradingAction::SubmitOrder(&o), NONCE);
    let self_form = hex::encode(
        TypedTradingDigest::new(TypedTradingAction::SubmitOrder(&o), CHAIN, NONCE)
            .self_signed()
            .digest()
            .expect("digest"),
    );
    assert_ne!(bound, self_form);
}
