//! Known-answer test: the SDK's trailing-stop digests EQUAL the node's.
//!
//! `trail_px` moves WHERE a position closes, so it is a control field and it is
//! bound by the EIP-712 type string. PRESENCE selects the string — a leg with no
//! trail keeps the frozen digest byte-for-byte, and `Some(0)` is a different
//! digest from `None`.
//!
//! Every digest below is pasted from the NODE's own KAT emitter
//! (`core_state::tests::trail_px_signing::emit_trail_kat_vectors`, chain 114514
//! / `"Testnet"`, nonce 1). Pinning this SDK against its own output would prove
//! nothing.

use metaflux_client::types::order::{
    BatchOrder, Builder, Order, OrderGrouping, OrderKind, PositionSide, Side, StpMode, TimeInForce,
    TpSl, Trigger,
};
use metaflux_client::types::{Cloid, MarketId};
use metaflux_client::wallet::{Address, TypedTradingAction, TypedTradingDigest};

const CHAIN: u64 = 114_514;
const NONCE: u64 = 1;
/// The KAT trailing callback, in 1e8-plane tick units.
const TRAIL: u64 = 50_000_000;
/// The KAT expiry (consensus ms), for the composition vector.
const EXPIRY: u64 = 1_900_000_000_000;

fn owner() -> Address {
    Address([0x11; 20])
}

fn digest(action: TypedTradingAction, expires_after: u64) -> String {
    let d = TypedTradingDigest::new(action, CHAIN, NONCE).with_expires_after(expires_after);
    format!("0x{}", hex::encode(d.digest().expect("digest")))
}

/// The rich take-profit leg of the node's vectors.
fn rich(trail: Option<u64>) -> Order {
    Order {
        owner: owner(),
        market: MarketId(7),
        side: Side::Ask,
        kind: OrderKind::TakeProfit,
        size: 500,
        limit_px: 0,
        tif: TimeInForce::Alo,
        stp_mode: StpMode::CancelOldest,
        reduce_only: true,
        cloid: Some(Cloid([0xAB; 16])),
        builder: Some(Builder {
            fee: 25,
            user: Address([0x22; 20]),
        }),
        position_side: Some(PositionSide::Short),
        trigger: Some(Trigger {
            trigger_px: 4200,
            is_market: true,
            tpsl: TpSl::Tp,
            trail_px: trail,
        }),
    }
}

/// The plain GTC leg of the node's vectors.
fn plain() -> Order {
    Order {
        owner: owner(),
        market: MarketId(1),
        side: Side::Bid,
        kind: OrderKind::Limit,
        size: 100,
        limit_px: 6_800_000_000_000,
        tif: TimeInForce::Gtc,
        stp_mode: StpMode::CancelNewest,
        reduce_only: false,
        cloid: None,
        builder: None,
        position_side: None,
        trigger: None,
    }
}

fn batch(orders: Vec<Order>) -> BatchOrder {
    BatchOrder {
        owner: owner(),
        orders,
        grouping: OrderGrouping::NormalTpsl,
    }
}

/// The four node vectors, digest for digest.
#[test]
fn trail_digests_match_the_node_kats() {
    assert_eq!(
        digest(TypedTradingAction::SubmitOrder(&rich(Some(TRAIL))), 0),
        "0xf78212e9ab8ad38ad455552cd9343a7a6637a8d331f23528fe7ae84713a20b64",
        "trailing_single"
    );
    let mixed = batch(vec![plain(), rich(Some(TRAIL))]);
    assert_eq!(
        digest(TypedTradingAction::BatchOrder(&mixed), 0),
        "0xdf6da2a4e1c3cabd1852bfa1aa05495a839d3787f1a01e2df18c199b53453b88",
        "mixed_batch_with_owner"
    );
    let control = batch(vec![plain(), rich(None)]);
    assert_eq!(
        digest(TypedTradingAction::BatchOrder(&control), 0),
        "0xef21c04ccb568652ab2d8950dffd1bd289acaafde846199f74a8ba72e0f5dad8",
        "no_trail_control — this is also the pre-trail SDK KAT"
    );
    assert_eq!(
        digest(TypedTradingAction::SubmitOrder(&rich(Some(TRAIL))), EXPIRY),
        "0x3f4d7fd0d3fb293e604fe6e5c4fc52e7b76830eaa39f8dc5d4d26b34372d5d92",
        "trailing_single_with_expiry"
    );
}

/// The type strings the node prints for those vectors, verbatim.
#[test]
fn the_trailing_type_strings_match_the_node() {
    assert_eq!(
        TypedTradingAction::SubmitOrder(&rich(Some(TRAIL))).type_string(),
        b"MetaFluxTransaction:SubmitOrder(string metafluxChain,uint32 market,string side,string kind,uint64 size,uint64 limitPx,string tif,string stpMode,bool reduceOnly,string cloid,uint16 builderFee,address builderUser,string positionSide,uint64 triggerPx,bool triggerIsMarket,string triggerTpsl,uint64 trailPx,uint64 nonce)"
    );
    let mixed = batch(vec![plain(), rich(Some(TRAIL))]);
    assert_eq!(
        TypedTradingAction::BatchOrder(&mixed).type_string(),
        b"MetaFluxTransaction:BatchOrder(string metafluxChain,address owner,bytes32 orders,string grouping,bytes32 trailPxs,uint64 nonce)"
    );
    // No leg trails → the frozen string, and with it the frozen digest.
    let control = batch(vec![plain(), rich(None)]);
    assert_eq!(
        TypedTradingAction::BatchOrder(&control).type_string(),
        b"MetaFluxTransaction:BatchOrder(string metafluxChain,address owner,bytes32 orders,string grouping,uint64 nonce)"
    );
    assert_eq!(
        TypedTradingAction::SubmitOrder(&rich(None)).type_string(),
        b"MetaFluxTransaction:SubmitOrder(string metafluxChain,uint32 market,string side,string kind,uint64 size,uint64 limitPx,string tif,string stpMode,bool reduceOnly,string cloid,uint16 builderFee,address builderUser,string positionSide,uint64 triggerPx,bool triggerIsMarket,string triggerTpsl,uint64 nonce)"
    );
}

/// PRESENCE, not value: an explicit zero callback must not share the absent
/// digest, on the single leg and per batch leg alike.
#[test]
fn an_explicit_zero_trail_is_not_the_absent_digest() {
    assert_ne!(
        digest(TypedTradingAction::SubmitOrder(&rich(Some(0))), 0),
        digest(TypedTradingAction::SubmitOrder(&rich(None)), 0)
    );
    let zero = batch(vec![plain(), rich(Some(0))]);
    let absent = batch(vec![plain(), rich(None)]);
    assert_ne!(
        digest(TypedTradingAction::BatchOrder(&zero), 0),
        digest(TypedTradingAction::BatchOrder(&absent), 0)
    );
}

/// WHICH leg trails is bound. The two legs are IDENTICAL apart from the
/// callback, so moving the trail from leg 0 to leg 1 changes nothing except
/// which leg trails — and that must still move the digest, or a relay can
/// re-point the stop at the other leg.
#[test]
fn permuting_which_batch_leg_trails_changes_the_digest() {
    let leg = |trail: Option<u64>| {
        let mut o = plain();
        o.trigger = Some(Trigger {
            trigger_px: 3000,
            is_market: true,
            tpsl: TpSl::Sl,
            trail_px: trail,
        });
        o
    };
    let first = batch(vec![leg(Some(TRAIL)), leg(None)]);
    let second = batch(vec![leg(None), leg(Some(TRAIL))]);
    assert_eq!(
        TypedTradingAction::BatchOrder(&first).type_string(),
        TypedTradingAction::BatchOrder(&second).type_string(),
        "both shapes select the same type string, so only the words can differ"
    );
    assert_ne!(
        digest(TypedTradingAction::BatchOrder(&first), 0),
        digest(TypedTradingAction::BatchOrder(&second), 0),
        "which leg carries the trail must be bound"
    );
}

/// One tick of callback must move the digest, or the word is not in the hash.
#[test]
fn a_one_unit_trail_change_moves_the_digest() {
    assert_ne!(
        digest(TypedTradingAction::SubmitOrder(&rich(Some(TRAIL))), 0),
        digest(TypedTradingAction::SubmitOrder(&rich(Some(TRAIL + 1))), 0)
    );
    assert_ne!(
        digest(TypedTradingAction::SubmitOrder(&rich(Some(TRAIL))), EXPIRY),
        digest(
            TypedTradingAction::SubmitOrder(&rich(Some(TRAIL + 1))),
            EXPIRY
        ),
        "the trail must stay bound under a non-zero expiry"
    );
}

/// An absent trail keeps the wire byte-identical: no `trail_px` key at all.
#[test]
fn an_absent_trail_adds_no_wire_key() {
    let json = serde_json::to_string(&rich(None)).expect("serialize");
    assert!(!json.contains("trail_px"), "{json}");
    let with = serde_json::to_string(&rich(Some(TRAIL))).expect("serialize");
    assert!(with.contains("\"trail_px\":50000000"), "{with}");
}
