# Changelog

All notable changes to `metaflux-client` are documented in this file. The
format adheres to [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once we cut `v1.0`. Pre-1.0 minor bumps may break.

## [Unreleased]

### Added

- `Exchange::place_order` — one entry point for perp and spot orders. It routes,
  it does not reshape: a perp request (any count) becomes ONE `batch_order`
  action; a spot request becomes ONE `spot_order` action PER order, because the
  wire cannot batch spot. The posted `action` bytes are byte-identical to the
  per-action methods, which a mock-server test asserts.
- `PlaceRequest` / `OrderLeg` / `Placement` in `types::place`. The venue split
  lives in the type: a perp leg and a spot leg are different structs.
  `PlaceRequest::from_legs` REFUSES a mixed perp + spot request rather than
  splitting it — two independent submissions would look like one atomic one.
  `Placement::SeparateSpotActions` names its own non-atomicity and reports each
  action separately.
- `LegStatus` keeps an untyped status entry (for example a `pending` handle)
  verbatim, so a new node status cannot fail the decode.

### Changed

- `spot_margin_deposit` / `spot_margin_withdraw` (and their `_typed` twins) are
  documented as DEAD. The node rejects both whenever the cross-margin model is
  active, which on the live chain is from genesis: collateral is the one unified
  USDC account. Fund that account, then use `spot_margin_open` /
  `spot_margin_close`. The actions, the types and the EIP-712 type strings stay
  so old signatures remain verifiable. The old deprecation note pointed at a
  future activation height, which was wrong for the live chain.
- `batch_order` documentation corrected: a committed batch DOES return
  synchronous per-leg statuses. The node's order path covers `batch_order` and
  emits one entry per placed leg, each echoing its own `cloid`. Behaviour and
  return type are unchanged.

## [0.15.0]

Aligns the whole typed `/info` read layer and the WS channel set to the node's
**wire-v2** read surface. Wire-v2 reshaped `account_state`, enriched
`open_orders`, added the `web_data` read + channel, added the
`spot_margin_state` channel, removed the `spot_state` channel, dropped the `_ms`
suffix from every `/info` timestamp, made `B`/`A` + `sz` the canonical order
dialect, and symbolized coins. Every rename below was verified against the node
serializer that emits the field.

### Changed

- **BREAKING** `AccountState` drops `#[serde(default)]` from
  `clearinghouse_state`, `balances`, `abstraction` and `position_mode`. The node
  always emits all four, so a default let a server-side rename decode into an
  account that holds nothing — a silent zero on the money path. A dropped or
  renamed field now fails the decode.
- `order_updates` documentation corrected: `order.sz` is the REMAINING size, not
  the filled size. The executed size and its average price ride the record's own
  `filled_sz` and `avg_px` fields.
- WS `coin` documentation corrected: the node canonicalizes a market SYMBOL
  (`"BTC"`) or a spot pair name (`"BTC/USDC"`) through the committed universe. A
  numeric asset-id string still works, but is no longer required.
- **BREAKING** `AccountState` is reshaped. The flat `positions` array is now
  `clearinghouse_state`, a map of dex key to `{positions:[…]}`; the core dex key
  is the empty string `""` and is always present, and a MIP-3 deployer dex keys
  on the deployer's lowercase `0x`-hex address. Use `AccountState::core_positions()`
  for the common case. `balances` is now an ARRAY of `{asset, name, total, hold}`
  token rows (USDC first); an all-zero token row is skipped. Top-level
  `maint_margin` is gone — read it from `margin_summary`. `mode`
  (`MarginMode`) and `pm_enabled` are gone: the margin class now rides
  `abstraction` (`"unified"` / `"portfolio"`), typed as the new `Abstraction`
  enum. `AccountPosition` keys on the symbol `coin` (was the numeric `asset`) and
  gained `liq`, `roe`, `funding`, `margin`, `maint_margin`, `notional`, plus an
  optional hedge-leg `side` (`"long"` / `"short"`, typed as `PositionSide` — NOT
  the order-book side). `AccountState` also gained `position_mode`,
  `pm_maint_margin`, `pm_net_value`, `pm_concentration_penalty` (whole-USDC
  strings, always present) and the flat `height` / `time` stamp.
- **BREAKING** `OrderSide` now serializes as `"B"` / `"A"` (was `"bid"` /
  `"ask"`). This is the canonical order dialect on `open_orders`, `order_status`
  and `rfq_open`. It is NOT the position leg label.
- **BREAKING** the size key is `sz` (was `size`) on `L2Level`, `OpenOrder`,
  `RestingOrderStatus` and `TriggerOrderStatus`. The `account_state` POSITION
  size key stays `size` and stays SIGNED — the two planes are deliberately not
  unified.
- **BREAKING** every `/info` timestamp dropped its `_ms` suffix:
  `OpenOrder.inserted_at_ms` -> `inserted_at`, `RestingOrderStatus.inserted_at_ms`
  -> `inserted_at`, `TriggerOrderStatus.registered_at_ms` -> `registered_at`,
  `PmSummary.enrolled_at_ms` -> `enrolled_at`, `AgentEntry.expires_at_ms` ->
  `expires_at`, `FundingSample.ts_ms` -> `ts`, `PredictedFunding.next_funding_time`
  -> `next_funding_ts`. DURATIONS keep `ms` — `lock_period_ms`, `interval_ms`,
  `period_ms` and `delay_ms` are unchanged.
- **BREAKING** `OpenOrder` is the ONE canonical order row the node renders for
  the REST read, the WS `open_orders` snapshot, and the inner `order` of a WS
  `order_updates` record. It gained `orig_sz`, `tif`, `reduce_only` and a folded
  `trigger` block, and the row set now includes parked TP / SL / stop triggers
  (`tif: "trigger"`). `tif` stays a `String` because `"trigger"` is not a TIF.
- **BREAKING** `OpenOrders.account_id` is dropped — the node never emitted it.
- **BREAKING** `VaultState` is a full rewrite:
  `{vault, name, tvl, share_price, depositor_count, high_water_mark,
  performance_fee_bps, lock_period_ms, strategy}`. The old
  `vault_id` / `leader` / `nav_usd_cents` shape matched nothing the node emits.
  `Info::vault_state` now takes the vault ADDRESS and posts the `vault` key (it
  posted `vault_id`). `tvl` and `high_water_mark` are whole USDC, NOT cents, and
  `share_price` is whole USDC per WHOLE share at full precision — a client that
  scales it by the share scale reads 1e18x high.
- **BREAKING** `SpotBalance` now carries `total` + `hold` (was a single
  `balance` the node never emitted), and `SpotClearinghouseState` gained the
  `height` / `time` stamp.
- **BREAKING** `SpotMarginAccount.pair` is a symbolized pair NAME `String`
  (e.g. `"BTC/USDC"`), was a raw `u32` pair id. `params.init_bps` /
  `maint_bps` stay JSON strings — do not normalize them to numbers.
- **BREAKING** `StakingState` now nests its body in the new `StakingSnapshot`
  (`state` field). The `web_data` read reuses the same type for its
  `staking.state` facet.
- **BREAKING** `WsClient::messages()` yields `WsFrame` (was `WsMessage`).
  `WsFrame` pairs the typed `message` with the envelope's `is_snapshot` flag; an
  absent flag reads `false`, so a delta is never mistaken for a snapshot.
- **BREAKING** `Info::rfq_state(rfq_id)` is replaced by `Info::rfq_open()` and
  `Info::rfq_user(address)`. The node `rfq_open` takes no parameters and answers
  `{rfqs:[…]}`; the old `RfqState` DTO could never decode it.

### Added

- `Info::web_data(address)` — the consolidated account snapshot (vault equities
  + followed / led vault states, staking state + delegator summary,
  sub-accounts, the multisig signer set, agent wallets) plus a flat `height` /
  `time` stamp. One round trip replaces five facet reads. New `WebData`,
  `WebDataVault`, `VaultEquity`, `WebDataStaking`, `StakingSnapshot`,
  `DelegatorSummary` and `MultiSigSigners` types.
- `Subscription::WebData` + `WsClient::subscribe_web_data(user)` — the same body
  on a WS channel.
- `Subscription::SpotMarginState` + `WsClient::subscribe_spot_margin_state(user)`
  — per-commit spot-margin positions, body identical to the REST read.
- `EarnPool.name` — the token symbol beside the numeric `asset`.
- `OrderTrigger` (the repurposed `FrontendTrigger`), `Abstraction`,
  `PositionSide`, `DexPositions`, `TokenBalance`, `RfqOpen`, `RfqUser`,
  `RfqSession` and `RfqQuote`.
- `WsMessage::as_account_state()`, `WsMessage::as_open_orders()` and
  `WsMessage::as_order_updates()` — typed decoders for the account WS channels.
  The raw `serde_json::Value` payload stays on every variant, so this is
  additive. `WsMessage::channel()` returns the frame's wire channel name.
- `OrderUpdate` and `WsOrderRow` — the `order_updates` record and its inner
  order row. The row keeps every field optional: a `canceled` /
  `cancel_rejected` / `rejected` record carries `null` for the fields the book
  no longer holds, which `OpenOrder` rejects.
- `AccountState.health_deferred` — `true` when the risk engine cannot price a
  leg the account holds. `tier` and `health` are then not solvency statements.
  The node emits the key only when true, so absent reads `false`.

### Removed

- **BREAKING** `Info::frontend_open_orders()` and the `FrontendOpenOrders` /
  `FrontendOpenOrder` / `FrontendTrigger` types. The node removed the
  `frontend_open_orders` kind (an unknown kind answers 400); its parked TP / SL
  detail is folded into the enriched `open_orders` row.
- **BREAKING** `Subscription::SpotState`, `WsMessage::SpotState` and
  `WsClient::subscribe_spot_state()`. The node removed the WS `spot_state`
  channel; a subscribe now answers an error envelope. The REST
  `spot_clearinghouse_state` read STAYS. Migration note: `account_state`
  `balances` skips all-zero token rows that `spot_state` used to emit.
- **BREAKING** `Info::user_state()` and the `types::position` module
  (`UserState` / `Position`). The method posted `account_state` into a
  cents-plane DTO that could never decode the response.
- **BREAKING** `types::rfq::RfqState`, `MmQuote` and `RfqStatus` — read types
  that matched no node response. The write actions (`RfqRequest`, `RfqAccept`,
  `CoreSide`, `RfqId`) are unchanged.

### Added — chase orders

- Chase order support: the `chase_order` / `cancel_chase` `Exchange` methods
  (plus the operator / vault `chase_order_as` / `cancel_chase_as`), the
  `ChaseParams` / `CancelChaseParams` request types, and the `ChaseOrder` /
  `CancelChase` typed EIP-712 actions. A chase places one post-only leg that the
  node re-prices to the top of book until it fills, reaches `ttl_ms`, or hits
  `max_reprices`. Every re-price shares the same re-stamped `cloid`; correlate
  legs and fills by `cloid` on the existing `order_updates` / `open_orders` /
  `fills` feeds. Perp markets only.
- Digest known-answer vectors and mock-server wire / sign-recover tests that pin
  the consensus-frozen `ChaseOrder` / `CancelChase` type strings, the field word
  order, and the `*_WITH_OWNER` owner binding.

## [0.14.0]

### Changed

- `Info::spot_meta()` is now a convenience wrapper over `markets_meta`
  (`kind=spot`): the standalone `spot_meta` `/info` type was removed server-side
  (it returns 400 `unknown info type`). The method posts
  `{"type":"markets_meta","kind":"spot"}` and unwraps the retained `spot` key,
  returning the identical `SpotMeta` shape — no caller change required.
- **BREAKING** `SpotPair::taker_fee_bps` is now a `String` (was `u16`): the live
  wire emits it as a decimal string (`"5"`). A `u16` field hard-fails decode
  against node 0.7.26.
- **BREAKING** `Info::l2_book` signature is now
  `l2_book(coin, params: Option<&L2BookParams>)` (was `l2_book(coin, depth: u32)`).
  `depth` is dropped in favour of the aggregation params; pass `None` for the
  full ungrouped book.

### Added

- `l2_book` (REST + WS) deterministic away-from-spread aggregation via the new
  `L2BookParams { n_sig_figs, mantissa, n_levels }`. The WS `Subscription::L2Book`
  carries the same three optional snake_case params (omitted when unset); the
  `WsClient` enforces the server's one-view-per-coin l2_book semantics (a
  re-subscribe on the same coin replaces the view; unsubscribe is param-blind).
  New `WsClient::subscribe_l2_book_coin(coin, params)` for spot-pair / aggregated
  subscribes by raw coin.
- Spot L2 depth: `l2_book` now renders real bids/asks for a spot pair coin
  (name `"BTC/USDC"` or pair id); `L2Book` gained a `coin` echo field.
- `SpotPair` price/volume context: `mark_px`, `mid_px`, `prev_day_px`,
  `day_ntl_vlm`, `circulating_supply`.
- `SpotToken` registry enrichment: `token_id`, `system_address`,
  `evm_contract` (now an OBJECT `{address, evm_extra_wei_decimals}`, via the new
  `TokenEvmContract`), `is_canonical`, `total_supply`.
- `MarketInfo::token`: an optional `PerpUnderlyingToken` block (EVM binding +
  `circulating_supply`), present on `markets_meta` / `market_info` perp rows when
  the perp has a registered underlying token, omitted otherwise.
- `open_orders` now includes spot resting orders (a spot row's `coin` is the
  pair name `"BTC/USDC"`).

## [0.6.0]

### Added

- Typed EIP-712 signing + `Exchange` methods for `core_evm_transfer` and the
  ten previously-unsigned account / sub-account / staking / abstraction /
  priority / encrypted actions: `create_sub_account`, `sub_account_transfer`,
  `sub_account_spot_transfer`, `c_deposit`, `c_withdraw`,
  `user_dex_abstraction`, `user_set_abstraction`, `priority_bid`,
  `cancel_all_orders`, `submit_encrypted_order`. These reach the typed-only
  `/exchange` path (`sig_scheme: "typed"`); previously they had no structured
  signing form and were un-submittable.
- Field-encoding rules matched byte-for-byte to the server + TypeScript SDK:
  server-flattened `Option<T>` → `(has_x bool, x uintN)` presence/value pairs
  for `create_sub_account.explicit_index` and `cancel_all_orders.asset` (the
  presence flag and an absent value are signed but omitted from the POST
  `params`), `submit_encrypted_order.ciphertext` as EIP-712 `bytes`
  (`keccak256(raw)`) and `commitment` as `bytes32` (raw 32-byte word), and
  decimal magnitudes carried verbatim.
- Known-answer-test vectors pinning the eleven new digests (chain id 114514)
  to the same server-verified values the TypeScript SDK pins, including the
  optional-absent variants (`create_sub_account` with no index,
  `cancel_all_orders` with no asset).

## [0.11.0]

### Added

- Owner-bound (operator / vault) `Exchange` methods for the order-lifecycle
  cancel / modify actions: `batch_cancel_as`, `batch_modify_as`, `modify_as`,
  and `cancel_by_cloid_as`. Each mirrors its owner-less sibling but signs the
  action's `*_WITH_OWNER` typed digest (owner bound right after `metafluxChain`,
  via `TypedTradingDigest::new_with_owner`) and injects a params-level `owner`
  (`0x`-hex) into the POSTed `action` so the node's `Native*.owner` is set. This
  lets a registered agent cancel/modify a VAULT's resting orders on its behalf;
  `batch_cancel_as` carries NO owner == signer guard (unlike `batch_cancel`).
  Completes the `*_as` operator surface begun with `cancel_all_orders_as` in
  0.10.0 (`place` already routed the owner via `BatchOrder.owner`).
- Internal `Exchange::post_typed_trade_as` helper: the owner-bound counterpart
  of `post_typed_trade` (owner-less digests stay byte-identical).
- Mock-server tests pinning each `*_as` method's wire shape (params-level
  `0x`-hex `owner`) and proving the signature recovers to the AGENT over the
  owner-form typed digest.

## [0.10.0]

### Added

- EIP-712 owner-routing for order-lifecycle actions: an operator/agent can sign
  `/exchange` actions on behalf of another owner (`*_as` variants), including
  `cancel_all_orders_as` — an agent-signed `cancelAllOrders` for another owner.
- Signing for the five W1 microstructure actions on the typed-only `/exchange`
  path.
- API-precision policy: a round-to-grid helper plus canonical response types.

### Changed

- Market orders now force `tif = Ioc` (O8) — a market order is never silently
  rested as a resting order.
- Dropped the vestigial `sig_scheme: "typed"` field from `/exchange` requests.

## [0.7.17]

### Changed

- `FeeSchedule` and `FeeTier` fee fields (`maker_bps`, `taker_bps`, and related)
  are now transmitted as decimal basis-point strings (e.g., `"5.0"`, `"0.5"`),
  supporting sub-basis-point precision. The SDK already parses these as strings,
  so no code changes are needed for existing clients — decimal parsing happens
  automatically.

### Note

- The server now enforces EVM transaction signature verification (standard
  Ethereum signed raw-tx format); existing clients using standard EVM tooling
  are unaffected.

## [Unreleased]

### Added

- Consolidated `/info` market reads: `recent_trades(coin)`,
  `trades_by_time(coin, start, end)` (bounded recent window), `predicted_fundings()`
  (clamped rate + next per-asset settlement boundary), and `candle_snapshot(coin,
  interval, start, end)` — the single archive-first candle query (compact
  single-letter wire keys). `MarketInfo` now carries `coin` (the market symbol)
  and the inline `margin_tiers` ladder (`[{ max_open_interest: Option<String>,
  max_leverage: u8, maint_margin_ratio: String }]`, upper-bound bands; `None` =
  unbounded top tier).
- WS `explorer_block` / `explorer_txs` channels plus `subscribe_spot_state`,
  `subscribe_user_fundings`, `subscribe_explorer_block` and
  `subscribe_explorer_txs` helpers. Doc notes for the non-empty `trades`
  on-subscribe snapshot, the `user_fundings` record shape
  (`{ coin, payment, szi, fundingRate, time }`), the `order_updates` `sz`
  (filled) / `orig_sz` (original) fields, and the `explorer_txs` row `hash`.
- Typed request types + `Exchange` methods for the node's full signed-action
  surface: `modify` / `batch_modify` / `batch_order` / `batch_cancel` /
  `cancel_by_cloid` / `schedule_cancel` / `cancel_all_orders`, `twap_order` /
  `twap_cancel`, `update_leverage` / `update_isolated_margin` /
  `top_up_isolated_only_margin` / `user_portfolio_margin`, `set_display_name` /
  `set_referrer` / `approve_agent` / `approve_builder_fee` /
  `convert_to_multi_sig_user` / `user_dex_abstraction` / `user_set_abstraction` /
  `agent_set_abstraction` / `priority_bid`, `token_delegate` / `claim_rewards` /
  `link_staking_user`, `submit_encrypted_order`, `create_vault` /
  `vault_transfer` / `vault_modify` / `vault_withdraw`, `mb_withdraw`.

### Changed

- **Breaking:** `/info` reads are keyed by `coin` (the market symbol) and
  `address` (0x hex): `l2_book(coin, depth)`, `market_info(coin)` (folds in the
  former `market_info_by_coin`), `staking_state(address)` and
  `delegations(address)` replace the numeric `market_id` / `asset_id` /
  `account_id` variants. Responses render coin symbols everywhere (e.g.
  `Trade.coin = "BTC"`). Signed `/exchange` actions are UNCHANGED — `asset`
  stays a numeric `u32` in the typed digests (consensus-frozen).
- **Breaking:** removed signed actions the node does not accept — `rfq_request` /
  `rfq_accept`, `fba_submit`, `pm_enroll` / `pm_unenroll` / `pm_rebalance`,
  `cross_chain_send`, `encrypted_order_submit` (replaced by
  `submit_encrypted_order`), `vault_create` (replaced by `create_vault`),
  `vault_distribute`. Read types for these domains (e.g. `RfqState`, `PmState`,
  `VaultState`) are retained.
- **Breaking:** `vault_withdraw` now takes `{ vault_id, shares }` with `shares`
  as a decimal string.

### Removed

- **Breaking:** the `candle` info read (replaced by `candle_snapshot`), the
  `web_data2` read and WS channel, the standalone `margin_table` read (the ladder
  now rides inline on markets / `market_info` as `margin_tiers`), and the
  `MarketInfo.name` field (use `coin`).
- The optional `grpc` feature and the `tonic` / `prost` dependencies.
