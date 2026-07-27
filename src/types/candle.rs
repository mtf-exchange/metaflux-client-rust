//! The candle price-series selector.
//!
//! A candle bar folds a PRICE series, never executions. The node serves two
//! series — the mark price and the oracle index price — and `mark` is the
//! default. The executed-trade candle is RETIRED: `trade` is not a valid
//! `candle_type` and the node rejects it like any other unknown token, on both
//! the REST `candle_snapshot` read and the `candles` WS channel.
//!
//! An unknown token is never served as the other series. A chart drawn from the
//! wrong price is a trading hazard, so the node fails the request instead.

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
}

impl CandleType {
    /// Every series, in wire order.
    pub const ALL: [CandleType; 2] = [Self::Mark, Self::Oracle];

    /// The wire token.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Mark => "mark",
            Self::Oracle => "oracle",
        }
    }

    /// Parse a wire token. `None` for any other value, including the retired
    /// `trade`.
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
        assert_eq!(CandleType::ALL.map(CandleType::token), ["mark", "oracle"]);
    }

    #[test]
    fn mark_is_the_default() {
        assert_eq!(CandleType::default(), CandleType::Mark);
    }

    /// The trade candle is RETIRED. It must not parse, and it must not resolve
    /// to the other series.
    #[test]
    fn retired_and_unknown_tokens_do_not_parse() {
        for bad in ["trade", "TRADE", "Mark", "", "index"] {
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
        assert!(serde_json::from_str::<CandleType>("\"trade\"").is_err());
    }

    #[test]
    fn displays_as_the_wire_token() {
        assert_eq!(CandleType::Oracle.to_string(), "oracle");
    }
}
