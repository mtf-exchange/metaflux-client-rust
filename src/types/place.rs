//! Unified order placement — one input shape for perp and spot orders.
//!
//! The wire carries three distinct order actions:
//!
//! - `order` — one perp order.
//! - `batch_order` — N perp orders under one signature, with a params-level
//!   `owner` and a `grouping`.
//! - `spot_order` — ONE spot order. Spot keys on `pair`, on an id space of its
//!   own, and the wire cannot batch spot orders.
//!
//! [`PlaceRequest`] is the SDK-side input that covers all three, and
//! [`Placement`] reports what the chosen route did. See
//! [`Exchange::place_order`] for the routing table.
//!
//! The venue split lives in the TYPE. A perp leg and a spot leg are different
//! structs, so a caller cannot build a leg that names both a `market` and a
//! `pair`. A request that mixes the two venues is refused at construction
//! ([`PlaceRequest::from_legs`]), never split into two submissions.
//!
//! Number planes are unchanged. `size` and `limit_px` stay on the 1e8 book
//! plane, as plain integers. This module converts nothing.
//!
//! [`Exchange::place_order`]: crate::rest::exchange::Exchange::place_order

use serde_json::Value;

use crate::error::ClientError;
use crate::types::OrderId;
use crate::types::order::{Order, OrderGrouping, OrderStatus};
use crate::types::spot::SpotOrder;
use crate::wallet::Address;

/// One leg of a [`PlaceRequest`].
///
/// A perp leg keys on `market` and carries `reduce_only`, `builder`,
/// `position_side` and `trigger`. A spot leg keys on `pair` and carries none
/// of them. Use this enum when the venue is only known at run time; otherwise
/// build the request directly with [`PlaceRequest::perp`] or
/// [`PlaceRequest::spot`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OrderLeg {
    /// A perp CLOB order.
    Perp(Order),
    /// A spot CLOB order.
    Spot(SpotOrder),
}

impl OrderLeg {
    /// `true` for a perp leg.
    #[must_use]
    pub const fn is_perp(&self) -> bool {
        matches!(self, OrderLeg::Perp(_))
    }

    /// `true` for a spot leg.
    #[must_use]
    pub const fn is_spot(&self) -> bool {
        matches!(self, OrderLeg::Spot(_))
    }
}

impl From<Order> for OrderLeg {
    fn from(o: Order) -> Self {
        OrderLeg::Perp(o)
    }
}

impl From<SpotOrder> for OrderLeg {
    fn from(o: SpotOrder) -> Self {
        OrderLeg::Spot(o)
    }
}

/// A venue-pure place request: perp orders OR spot orders, never both.
///
/// Each variant maps to one wire route:
///
/// | variant | wire action | actions sent |
/// |---|---|---|
/// | [`PlaceRequest::Perp`] | `batch_order` | 1 |
/// | [`PlaceRequest::Spot`] | `spot_order` | 1 per order |
///
/// A mixed set of legs cannot reach either route: [`PlaceRequest::from_legs`]
/// refuses it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlaceRequest {
    /// Perp orders. Routes to ONE `batch_order` action.
    Perp {
        /// Account that OWNS the orders — the params-level `batch_order.owner`.
        /// Set it to the signing wallet for self-trading, or to a VAULT address
        /// for operator-driven vault trading. The node authorizes a registered
        /// operator, so it MAY differ from the signer.
        owner: Address,
        /// Orders to place, in priority order.
        orders: Vec<Order>,
        /// Grouping semantics for the batch.
        grouping: OrderGrouping,
    },
    /// Spot orders. Routes to ONE `spot_order` action PER order, because the
    /// wire cannot batch spot orders. The signing wallet owns every order — a
    /// spot order body carries no owner field.
    Spot {
        /// Orders to place, in request order.
        orders: Vec<SpotOrder>,
    },
}

impl PlaceRequest {
    /// Build a perp request. `owner` is the params-level `batch_order.owner`;
    /// `grouping` defaults to [`OrderGrouping::Na`] — set it with
    /// [`PlaceRequest::with_grouping`].
    pub fn perp(owner: Address, orders: impl IntoIterator<Item = Order>) -> Self {
        PlaceRequest::Perp {
            owner,
            orders: orders.into_iter().collect(),
            grouping: OrderGrouping::Na,
        }
    }

    /// Build a spot request.
    pub fn spot(orders: impl IntoIterator<Item = SpotOrder>) -> Self {
        PlaceRequest::Spot {
            orders: orders.into_iter().collect(),
        }
    }

    /// Set the batch grouping. A spot request is returned unchanged — the
    /// `spot_order` wire action has no grouping field.
    #[must_use]
    pub fn with_grouping(mut self, g: OrderGrouping) -> Self {
        if let PlaceRequest::Perp { grouping, .. } = &mut self {
            *grouping = g;
        }
        self
    }

    /// Build a request from legs whose venue is only known at run time.
    ///
    /// The perp owner is read from the legs: every perp leg must carry the same
    /// [`Order::owner`], and that address becomes the params-level
    /// `batch_order.owner`.
    ///
    /// # Errors
    /// [`ClientError::Validation`] if the legs are empty, if they mix perp and
    /// spot, or if the perp legs disagree on the owner.
    pub fn from_legs(legs: impl IntoIterator<Item = OrderLeg>) -> Result<Self, ClientError> {
        let mut perp: Vec<Order> = Vec::new();
        let mut spot: Vec<SpotOrder> = Vec::new();
        for leg in legs {
            match leg {
                OrderLeg::Perp(o) => perp.push(o),
                OrderLeg::Spot(o) => spot.push(o),
            }
        }
        match (perp.is_empty(), spot.is_empty()) {
            (true, true) => Err(ClientError::Validation(
                "place request carries no orders".into(),
            )),
            (false, false) => Err(ClientError::Validation(format!(
                "mixed venues: {} perp and {} spot order(s) in one request. \
                 The wire cannot batch the two. Perp orders go through one \
                 `batch_order` action; each spot order goes through its own \
                 `spot_order` action. Send one venue per request.",
                perp.len(),
                spot.len()
            ))),
            (true, false) => Ok(PlaceRequest::Spot { orders: spot }),
            (false, true) => {
                let owner = perp[0].owner;
                if let Some((i, bad)) = perp
                    .iter()
                    .enumerate()
                    .find(|(_, o)| o.owner != owner)
                    .map(|(i, o)| (i, o.owner))
                {
                    return Err(ClientError::Validation(format!(
                        "perp legs disagree on the owner: leg 0 is {owner}, leg {i} is {bad}. \
                         A `batch_order` carries ONE params-level owner. \
                         Use PlaceRequest::perp to set it."
                    )));
                }
                Ok(PlaceRequest::perp(owner, perp))
            }
        }
    }

    /// Number of orders in the request.
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            PlaceRequest::Perp { orders, .. } => orders.len(),
            PlaceRequest::Spot { orders } => orders.len(),
        }
    }

    /// `true` when the request carries no orders. `place_order` refuses one.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// `true` for a perp request (the `batch_order` route).
    #[must_use]
    pub const fn is_perp(&self) -> bool {
        matches!(self, PlaceRequest::Perp { .. })
    }
}

/// One status entry returned by an order action.
///
/// The node's status union grows over time (`pending`, `chase`, …), so an
/// entry this SDK does not type is kept verbatim instead of failing the decode.
#[derive(Clone, Debug, PartialEq)]
pub enum LegStatus {
    /// A typed status: `resting`, `filled` or `error`.
    Known(OrderStatus),
    /// Any other entry, verbatim. A `pending` handle lands here: the node
    /// admitted the action but it had not committed when the node answered.
    Other(Value),
}

impl LegStatus {
    /// Decode one status entry. An entry outside the typed union is kept as
    /// [`LegStatus::Other`].
    #[must_use]
    pub fn from_value(v: Value) -> Self {
        match serde_json::from_value::<OrderStatus>(v.clone()) {
            Ok(s) => LegStatus::Known(s),
            Err(_) => LegStatus::Other(v),
        }
    }

    /// The typed status, if this entry is one.
    #[must_use]
    pub const fn known(&self) -> Option<&OrderStatus> {
        match self {
            LegStatus::Known(s) => Some(s),
            LegStatus::Other(_) => None,
        }
    }

    /// The node-assigned `oid`, if this entry carries one.
    #[must_use]
    pub fn oid(&self) -> Option<OrderId> {
        self.known().and_then(OrderStatus::oid)
    }

    /// `true` if the node rejected this entry.
    #[must_use]
    pub fn is_error(&self) -> bool {
        self.known().is_some_and(OrderStatus::is_error)
    }
}

/// Outcome of ONE `batch_order` action.
#[derive(Clone, Debug, PartialEq)]
pub struct BatchPlacement {
    /// Per-leg statuses, in submission order — one entry per PLACED leg.
    /// Empty when the node answered with an admission envelope instead of a
    /// status array; read [`BatchPlacement::response`] then.
    pub statuses: Vec<LegStatus>,
    /// The `/exchange` response body, verbatim.
    pub response: Value,
}

impl BatchPlacement {
    /// Split a `/exchange` body into typed statuses plus the verbatim body.
    #[must_use]
    pub fn from_response(response: Value) -> Self {
        let statuses = response
            .get("statuses")
            .and_then(Value::as_array)
            .map(|a| a.iter().cloned().map(LegStatus::from_value).collect())
            .unwrap_or_default();
        Self { statuses, response }
    }
}

/// Outcome of one `spot_order` action.
#[derive(Debug)]
pub struct SpotActionOutcome {
    /// Index of the order in the request.
    pub index: usize,
    /// Spot pair the action targeted.
    pub pair: u32,
    /// The node's per-order statuses, or the error that ended the send.
    pub result: Result<Vec<LegStatus>, ClientError>,
}

/// Outcome of the spot route: N SEPARATE `spot_order` actions.
///
/// The actions are NOT atomic. Each one carries its own signature, nonce and
/// commit, so some can succeed while others fail. Read [`SpotPlacements::sent`]
/// to see exactly which orders reached the node.
#[derive(Debug)]
pub struct SpotPlacements {
    /// One entry per action the SDK SENT, in request order.
    pub sent: Vec<SpotActionOutcome>,
    /// Request indexes the SDK did NOT send, because an earlier action failed.
    pub not_sent: Vec<usize>,
}

/// What a [`Exchange::place_order`] call did.
///
/// The variant names the ACTION COUNT, because that is where the two routes
/// differ: a perp request is one action, a spot request is one action per
/// order. A [`Placement::SeparateSpotActions`] is never an atomic result.
///
/// [`Exchange::place_order`]: crate::rest::exchange::Exchange::place_order
#[derive(Debug)]
pub enum Placement {
    /// ONE `batch_order` action carried every perp order.
    BatchAction(BatchPlacement),
    /// N SEPARATE `spot_order` actions, one per spot order. NOT atomic.
    SeparateSpotActions(SpotPlacements),
}

impl Placement {
    /// Number of wire actions the call sent: `1` for the perp route, one per
    /// SENT order for the spot route. Above `1` the orders committed
    /// independently.
    #[must_use]
    pub fn action_count(&self) -> usize {
        match self {
            Placement::BatchAction(_) => 1,
            Placement::SeparateSpotActions(p) => p.sent.len(),
        }
    }

    /// `true` when an action failed to send, an order was left unsent, or the
    /// node returned an `error` status.
    #[must_use]
    pub fn has_failure(&self) -> bool {
        match self {
            Placement::BatchAction(b) => b.statuses.iter().any(LegStatus::is_error),
            Placement::SeparateSpotActions(p) => {
                !p.not_sent.is_empty()
                    || p.sent.iter().any(|a| match &a.result {
                        Ok(st) => st.iter().any(LegStatus::is_error),
                        Err(_) => true,
                    })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::order::{OrderKind, RestingStatus, Side, StpMode, TimeInForce};
    use crate::types::{Cloid, MarketId};

    fn perp(owner: Address) -> Order {
        Order {
            owner,
            market: MarketId(1),
            side: Side::Bid,
            kind: OrderKind::Limit,
            size: 1_000,
            limit_px: 5_000_000_000_000,
            tif: TimeInForce::Gtc,
            stp_mode: StpMode::CancelOldest,
            reduce_only: false,
            cloid: None,
            builder: None,
            position_side: None,
            trigger: None,
        }
    }

    fn spot() -> SpotOrder {
        SpotOrder::ioc_limit(3, Side::Bid, 1_000, 5_000_000_000)
    }

    fn addr(b: u8) -> Address {
        Address([b; 20])
    }

    #[test]
    fn from_legs_all_perp_reads_the_shared_owner() {
        let owner = addr(0x11);
        let req =
            PlaceRequest::from_legs([OrderLeg::Perp(perp(owner)), OrderLeg::Perp(perp(owner))])
                .unwrap();
        match req {
            PlaceRequest::Perp {
                owner: o,
                orders,
                grouping,
            } => {
                assert_eq!(o, owner);
                assert_eq!(orders.len(), 2);
                assert_eq!(grouping, OrderGrouping::Na);
            }
            other => panic!("expected Perp, got {other:?}"),
        }
    }

    #[test]
    fn from_legs_all_spot_builds_a_spot_request() {
        let req =
            PlaceRequest::from_legs([OrderLeg::Spot(spot()), OrderLeg::Spot(spot())]).unwrap();
        assert!(!req.is_perp());
        assert_eq!(req.len(), 2);
    }

    #[test]
    fn from_legs_refuses_mixed_venues() {
        let err = PlaceRequest::from_legs([OrderLeg::Perp(perp(addr(1))), OrderLeg::Spot(spot())])
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("mixed venues"),
            "message names the reason: {msg}"
        );
        assert!(msg.contains("batch_order") && msg.contains("spot_order"));
    }

    #[test]
    fn from_legs_refuses_empty() {
        assert!(
            PlaceRequest::from_legs([])
                .unwrap_err()
                .to_string()
                .contains("no orders")
        );
    }

    #[test]
    fn from_legs_refuses_perp_legs_with_different_owners() {
        let err =
            PlaceRequest::from_legs([OrderLeg::Perp(perp(addr(1))), OrderLeg::Perp(perp(addr(2)))])
                .unwrap_err();
        assert!(err.to_string().contains("disagree on the owner"));
    }

    #[test]
    fn with_grouping_only_touches_a_perp_request() {
        let p =
            PlaceRequest::perp(addr(1), [perp(addr(1))]).with_grouping(OrderGrouping::NormalTpsl);
        match p {
            PlaceRequest::Perp { grouping, .. } => assert_eq!(grouping, OrderGrouping::NormalTpsl),
            other => panic!("expected Perp, got {other:?}"),
        }
        let s = PlaceRequest::spot([spot()]).with_grouping(OrderGrouping::NormalTpsl);
        assert_eq!(s, PlaceRequest::spot([spot()]));
    }

    #[test]
    fn leg_status_types_a_known_entry() {
        let v = serde_json::json!({ "resting": { "oid": 7 } });
        let s = LegStatus::from_value(v);
        assert_eq!(s.oid(), Some(OrderId(7)));
        assert!(!s.is_error());
        assert!(matches!(
            s.known(),
            Some(OrderStatus::Resting(RestingStatus {
                oid: OrderId(7),
                ..
            }))
        ));
    }

    #[test]
    fn leg_status_keeps_an_unknown_entry_verbatim() {
        // A `pending` handle must not fail the decode.
        let v = serde_json::json!({ "pending": { "action_hash": "0xab", "nonce": 5 } });
        let s = LegStatus::from_value(v.clone());
        assert_eq!(s, LegStatus::Other(v));
        assert!(s.known().is_none());
        assert_eq!(s.oid(), None);
        assert!(!s.is_error());
    }

    #[test]
    fn batch_placement_decodes_statuses_and_keeps_the_body() {
        let body = serde_json::json!({ "statuses": [
            { "resting": { "oid": 1, "cloid": "0x000102030405060708090a0b0c0d0e0f" } },
            { "error": "size below market minimum" }
        ]});
        let p = BatchPlacement::from_response(body.clone());
        assert_eq!(p.statuses.len(), 2);
        assert_eq!(p.statuses[0].oid(), Some(OrderId(1)));
        assert!(p.statuses[1].is_error());
        assert_eq!(p.response, body);
    }

    #[test]
    fn batch_placement_on_an_admission_envelope_has_no_statuses() {
        let body = serde_json::json!({ "accepted": true, "nonce": 9 });
        let p = BatchPlacement::from_response(body.clone());
        assert!(p.statuses.is_empty());
        assert_eq!(p.response, body);
    }

    #[test]
    fn placement_reports_the_action_count() {
        let batch = Placement::BatchAction(BatchPlacement::from_response(
            serde_json::json!({ "statuses": [{ "resting": { "oid": 1 } }] }),
        ));
        assert_eq!(batch.action_count(), 1);
        assert!(!batch.has_failure());

        let spot = Placement::SeparateSpotActions(SpotPlacements {
            sent: vec![
                SpotActionOutcome {
                    index: 0,
                    pair: 3,
                    result: Ok(vec![LegStatus::from_value(
                        serde_json::json!({ "resting": { "oid": 4 } }),
                    )]),
                },
                SpotActionOutcome {
                    index: 1,
                    pair: 3,
                    result: Err(ClientError::Validation("boom".into())),
                },
            ],
            not_sent: vec![2],
        });
        assert_eq!(spot.action_count(), 2);
        assert!(spot.has_failure());
    }

    #[test]
    fn order_leg_from_conversions_pick_the_venue() {
        let owner = addr(1);
        assert!(OrderLeg::from(perp(owner)).is_perp());
        assert!(OrderLeg::from(spot()).is_spot());
    }

    #[test]
    fn cloid_survives_into_the_request_unchanged() {
        let mut o = spot();
        o.cloid = Some(Cloid([0xAB; 16]));
        let req = PlaceRequest::spot([o.clone()]);
        match req {
            PlaceRequest::Spot { orders } => assert_eq!(orders[0], o),
            other => panic!("expected Spot, got {other:?}"),
        }
    }
}
