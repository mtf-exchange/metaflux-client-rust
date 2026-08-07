//! The candle series selector.
//!
//! Three series are served on both the REST `candle_snapshot` read and the
//! `candles` WS channel: the mark price, the oracle index price, and executed
//! trades. `mark` is the default.
//!
//! An unknown token is never served as another series. A chart drawn from the
//! wrong price is a trading hazard, so the request fails instead.
//!
//! A PRICE series and the TRADE series differ in more than price. A price series
//! has a bar in every window its samples cover. The trade series is SPARSE: a
//! window with no fill has NO bar, never a carried-forward one. Volume and count
//! also differ — a price bar reports zero volume and a SAMPLE count, a trade bar
//! reports real volume and a real trade count.

use serde::{Deserialize, Serialize};

/// The price series a candle folds.
///
/// Pass it to [`Info::candle_snapshot`] and
/// [`WsClient::subscribe_candles`]. The wire field is `candle_type`.
///
/// [`Info::candle_snapshot`]: crate::rest::info::Info::candle_snapshot
/// [`WsClient::subscribe_candles`]: crate::ws::WsClient::subscribe_candles
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CandleType {
    /// Mark price — the price positions mark at, and the node's DEFAULT series.
    /// Serves perp and spot markets.
    #[default]
    Mark,
    /// Oracle index price. Perp markets ONLY — a spot pair has no oracle price,
    /// so it answers empty.
    Oracle,
    /// Executed-trade OHLCV, folded from prints. Perp and spot markets.
    ///
    /// SPARSE: a window with no fill produces no bar at all.
    Trade,
}

impl CandleType {
    /// Every series, in wire order.
    pub const ALL: [CandleType; 3] = [Self::Mark, Self::Oracle, Self::Trade];

    /// The wire token.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Mark => "mark",
            Self::Oracle => "oracle",
            Self::Trade => "trade",
        }
    }

    /// Parse a wire token. `None` for anything that is not one of the three.
    #[must_use]
    pub fn from_token(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|c| c.token() == s)
    }
}

impl std::fmt::Display for CandleType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.token())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_round_trip() {
        for c in CandleType::ALL {
            assert_eq!(CandleType::from_token(c.token()), Some(c));
        }
        assert_eq!(
            CandleType::ALL.map(CandleType::token),
            ["mark", "oracle", "trade"]
        );
    }

    #[test]
    fn mark_is_the_default() {
        assert_eq!(CandleType::default(), CandleType::Mark);
    }

    /// An unknown token must not parse, and must never resolve to another
    /// series. Case matters: the wire tokens are lowercase.
    #[test]
    fn unknown_tokens_do_not_parse() {
        for bad in ["TRADE", "Mark", "", "index", "last"] {
            assert!(
                CandleType::from_token(bad).is_none(),
                "{bad} must not parse"
            );
        }
    }

    #[test]
    fn serializes_as_the_wire_token() {
        assert_eq!(
            serde_json::to_string(&CandleType::Mark).unwrap(),
            "\"mark\""
        );
        assert_eq!(
            serde_json::to_string(&CandleType::Oracle).unwrap(),
            "\"oracle\""
        );
        assert_eq!(
            serde_json::from_str::<CandleType>("\"oracle\"").unwrap(),
            CandleType::Oracle
        );
        assert_eq!(
            serde_json::from_str::<CandleType>("\"trade\"").unwrap(),
            CandleType::Trade
        );
        assert!(serde_json::from_str::<CandleType>("\"last\"").is_err());
    }

    #[test]
    fn displays_as_the_wire_token() {
        assert_eq!(CandleType::Oracle.to_string(), "oracle");
    }
}
