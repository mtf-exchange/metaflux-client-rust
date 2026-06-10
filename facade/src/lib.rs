//! `metaflux` — a short alias for the `metaflux-client` SDK.
//!
//! This crate re-exports the entire public API of `metaflux-client`. Depend on
//! `metaflux` and use it exactly as you would `metaflux_client`:
//!
//! ```
//! use metaflux::types::MarketId;
//! assert_eq!(MarketId(1).0, 1);
//! ```
//!
//! See the `metaflux-client` crate for full documentation.

#![forbid(unsafe_code)]

#[doc(inline)]
pub use metaflux_client::*;
