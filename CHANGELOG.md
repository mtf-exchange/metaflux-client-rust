# Changelog

All notable changes to `metaflux-client` are documented in this file. The
format adheres to [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once we cut `v1.0`. Pre-1.0 minor bumps may break.

## [Unreleased]

### Removed

- **Breaking: `Info::encode_action` is deleted.** The node no longer serves the
  read, because the `multi_sig` inner blob now accepts the ordinary
  `{type, params}` wire action. Build the blob by UTF-8 encoding the action you
  would post to `/exchange`, and have every member sign those bytes. Build it
  ONCE and distribute it: two members who each serialize their own copy are
  trusting two JSON writers to agree on key order.

  The node still accepts the core `Action` JSON, which is what older bundles
  carry. Do not build that form by hand — its variant names live in the node and
  move when actions move.

- **Breaking: five `/info` reads are deleted.** The official surface gives each
  question exactly ONE read, so a read that duplicated or narrowed another is
  gone. There is no deprecation window.

  - `pm_summary` / `Info::pm_summary` / `PmSummary` — read `account_state`. It
    serves `pm_maint_margin`, `pm_net_value` and `pm_concentration_penalty` on
    the same plane. The figures are meaningful when `abstraction ==
    "portfolio"`.
  - `bridge_chain_configs` / `Info::bridge_chain_configs` / `BridgeChainConfigs`
    — read `Info::bridge_user_outbox`. `BridgeUserOutbox` now carries
    `withdrawals_halted` and `configs`. The rows DEFINE the `message_id` the
    entries carry, so one read serves both. An address with no withdrawal gets
    the rows and an empty `entries`.
  - `account_overview` — `Info::account_overview` keeps its name and its
    `AccountOverview` shape, but now posts `account_state` with
    `detail: "overview"`.
  - `evm_contract_bindings` — the SDK never typed it. Its `variant` tag folds
    into `TokenEvmContract` on the `markets_meta` token rows.
  - `oracle_sources` — the SDK never typed it. The `OracleSource` MIP-3
    write-side enum is untouched.

- **Breaking: the WS `web_data` channel is retired.** `Subscription::WebData`,
  `WsMessage::WebData` and `WsClient::subscribe_web_data` are gone. The node
  refuses a `web_data` subscribe at the next release.

  **The REST `web_data` read is unchanged.** Keep using
  `client.rest().info().web_data(addr)`; it returns the same `WebData` body the
  channel pushed. Poll it in place of the push. Every facet also has its own
  focused read: `user_vault_equities`, `staking_state`, `delegator_summary`,
  `sub_accounts`, `user_to_multi_sig_signers` and `agents`.

### Changed

- **RFQ is live as the option trade path.** The `types::rfq` doc comments said
  every market was refused because no option series existed. Series exist now,
  so the three actions clear them. A market that is not a LIVE series is still
  refused with `rfq is options-only: market <n> is not an option series`. **No
  signing type changed** — the RFQ EIP-712 type strings are untouched.

  The session reads `rfq_open` and `rfq_user` are PUBLIC, which is what makes an
  accept completable: a taker finds its own `rfq_id` there and a maker finds a
  request to answer. This SDK does not type them yet — read them raw. No WS
  channel carries an RFQ event, so both are polled.

- **Breaking: `AccountState` renames its two account-level margin scalars.**
  `init_margin` is now `total_margin_used`, and `maint_margin` is now
  `cross_maintenance_margin_used`. The names now say the SCOPE: the maintenance
  figure covers the CROSS book only. An isolated position is margined and
  liquidated on its own bucket, so size it off the row's own `maint_margin`.

  The PER-POSITION `maint_margin` and `margin` fields on a
  `clearinghouse_state` row are UNCHANGED, as are `maint_margin_ratio` /
  `init_margin_ratio` on the market surfaces and the `pm_maint_margin` account
  field.

- **Breaking: two read fields change type.** The node serializes every `*_bps`
  field on the public wire as a JSON string, so `VaultState.performance_fee_bps`
  and `BridgeChainConfig.validator_quorum_threshold_bps` are now `String`. The
  value is unchanged; only the type moves. This lands with the node release that
  makes the change, not before it.

- **Breaking: `Trade.hash` is now `Option<String>`.** An ABSENT hash and an
  EMPTY hash are different facts and the old `String` collapsed them. `None`
  means NOT RECORDED — an archive-served print, whose table stores no trace
  hash. `Some("")` means recorded, and there was no signed taker action.

### Added

- **`Info::option_series`, and the `OptionSeriesRegistry` / `OptionSeries` /
  `OptionKind` types.** The read serves every live option series: the
  `signing_id` an RFQ action signs against, the underlying, the kind, the
  strike, the cap, the expiry, the size precision, and the escrow a writer
  locks.

  `signing_id` is a `MarketId` and it goes straight into `RfqRequest.market`.
  The registry serves it WHOLE. There is no formula, no base and no arithmetic
  that derives it — the encoding behind the number is internal to the node and
  may move.

  `escrow_per_unit` is what a WRITER locks per whole unit. On a `CappedCall` it
  is `cap − strike`, not `strike`: a $100,000 strike capped at $130,000 locks
  $30,000 per unit. Reading `strike` as the lock overstates it by the whole
  strike.

  `cap` is `None` on a put — the node omits the key. An empty registry is a
  `200` with an empty `series`, not an error.

  The read carries no option price and no implied volatility, because the chain
  computes neither. There is still NO public read for an option position: the
  visible effect of a fill is the USDC balance change on `account_state`.

- **`OrderTrigger.group` / `TriggerOrderStatus.group`** — the scaled-TP/SL
  LADDER handle, `Option<u64>`. A `positionTpsl` batch of three or more
  protective legs parks a ladder; its legs share this handle and are NOT OCO — a
  fill of one leg does not cancel the others. One or two legs keep the older
  shapes and read `None`.

- **`OrderTrigger.trail_px` / `TriggerOrderStatus.trail_px`** — the TRAILING
  callback as a decimal string, `Option<String>`. When it is present,
  `trigger_px` is the RATCHETED level, not the level the owner sent.

  READ ONLY. `types::order::Trigger` deliberately has no `trail_px`: the frozen
  `SubmitOrder` / `BatchOrder` EIP-712 type strings do not bind the field, so
  `/exchange` refuses any order that carries it. The write side arrives when a
  versioned type string binds it.

- **`AccountDetail::Adl` and `AccountPosition.adl_lamps`** — the ADL queue
  indicator, `0..=4` lamps, served only at the new depth. More lamps = sooner in
  the auto-deleveraging queue. It is a RANKING against the other seats on the
  same side, not a probability. `Some(0)` is a real answer: the position is not
  in the queue, which includes a hedge account whose only opposing leg is its
  own.

- **`AccountState.total_raw_usd`** — settled cash equity as a decimal string.
  It EXCLUDES unrealised PnL, so it differs from `account_value` by exactly the
  open PnL. Served at both `detail` depths.

- **`AccountState.total_ntl_pos`** — mark notional of the account's CROSS legs
  as a decimal string. Isolated legs are NOT counted, so it is not the whole
  exposure. `Option<String>`: served at the FULL depth only, because
  `detail: "margin"` skips the position walk.

- `WsMessage::as_ledger_updates` and the `WsLedgerUpdate` record. The
  `ledger_updates` channel was reachable only as a raw `Value`, so every caller
  wrote its own decoder for a shape the SDK already knew.

  `kind` is a `String`, not an enum, and every field except `kind` and `time` is
  optional. Two kinds arrive in a later node release — `deposit` for a bridge
  inbound credit and `liquidation` for a forced-close settlement — and this
  decoder accepts both today, along with any kind a newer node adds.

## [0.21.0] — 2026-08-21

### Added

- `Client::mip3_set_oracle_px` and the `Mip3SetOraclePx` params type. A MIP-3
  market deployer can push their market's index price from their own source. The
  chain has carried the action since its EIP-712 type was frozen, but no client
  could sign it, so the capability was unreachable from Rust.

  `px` is a decimal STRING and is signed VERBATIM: the exact bytes passed are the
  bytes hashed and the bytes posted, so a relay can neither reprice a push nor
  re-target it at another market. Only the market's deployer or a registered
  sub-deployer may sign one.

  The KAT digest is derived FROM THE NODE. Pinning this SDK against its own
  output would prove nothing.

- `Info::gossip_root_ips` and the `GossipRootIps` / `AdvertisedPeer` types. The
  read returns the nodes a deployment advertises for peer discovery: id, the
  three public endpoints, and the peer's public key. The fields map one-to-one
  onto a joining node's own peer config, so a row is copied and dialed.

  A node that advertises nothing is ABSENT from the rows. There is no fallback
  to a node's internal dial list, so an empty `peers` is the honest answer for a
  deployment that advertises nothing.

  The read was previously reachable only through the raw `Value` escape hatch.

  Against an older node the decode fails on the missing `peers` field. That is
  deliberate: a silent empty roster is indistinguishable from a deployment that
  advertises nothing.

### Changed

- **Availability claims corrected — they were false.** The deployer actions do
  NOT answer `unknown variant` on the primary networks; the node knows every
  tag. And `mip3_deployer_oracle` is ACTIVE FROM GENESIS on a chain that started
  fresh, so no stake vote will ever arm it there. Only a legacy or unknown
  network keeps it dormant. Availability is per network: probe one call and read
  the error.

- The executed-trade candle is NOT retired. `CandleType::ALL` has carried three
  values for some time while the docs still told callers otherwise. The candle
  frame doc also described the node's old shape; every frame carries
  `{snapshot, candles}`, and the frame-level `is_snapshot` stays `false`.

## [0.20.0] — 2026-08-18

**0.19.0 was tagged on 2026-08-09 and never published.** Its release run failed because
the facade crate depended on `metaflux-client = "^0.18.0"`, which cannot resolve 0.19.0 —
on a 0.x version the caret pins the minor. The dependency now tracks the crate version,
and this release takes a fresh number rather than reusing a tag that is already pushed.

First release since 0.18.1. Carries the staged work plus the
`send_to_evm_with_data` action and the Core to EVM fee rules.

### Removed

- **BREAKING** The `explorer` REST namespace is gone: `RestClient::explorer`,
  `Explorer`, `Explorer::block_by_height`, `Explorer::tx_by_hash`, and the
  `Block` and `Transaction` types. **The server never served these endpoints.**
  They were not deprecated and they did not stop working — no MetaFlux server
  ever answered them, so every call returned a not-found error. You lose no
  working capability by upgrading.
- There is no replacement, because the capability does not exist server-side. No
  MetaFlux endpoint looks up a block by height or a transaction by hash. To
  follow committed blocks and transactions, subscribe to the WebSocket
  `explorer_block` and `explorer_txs` streams — those ARE served, and they stay.
  They deliver each block and transaction as it commits; they do not answer a
  query about a past one.

### Changed

- The `/exchange` action tag is now `approve_broker_fee`, not
  `approve_builder_fee`. The node accepts BOTH names, so an old client keeps
  working; this SDK emits the new one. `Exchange::approve_broker_fee` and
  `Exchange::approve_broker_fee_typed` are the canonical methods.
  `approve_builder_fee` and `approve_builder_fee_typed` stay as old names and
  now emit the new tag. `ApproveBrokerFee` is an alias of `ApproveBuilderFee`.
  **The node must run a binary that knows the new tag before you upgrade.**
  The EIP-712 type string stays
  `MetaFluxTransaction:ApproveBuilderFee(...)`. It is consensus-frozen: one
  changed byte breaks verification of every historical signature. The wire tag
  and the signing string therefore differ on purpose.
- **BREAKING** `FeeSchedule::builder_rebate_bps` is now `Option<String>` and
  defaults to absent. A current server sends no `builder_rebate_bps` in
  `fee_schedule`. The previous required field failed the WHOLE response with a
  missing-field error, so every caller of the read broke. This version decodes
  both shapes. `None` means "the server sent no value". The SDK does NOT
  substitute `"0"`, because a fabricated zero is indistinguishable from a real
  rebate. Read the field with `as_deref()` and handle `None`.
- **BREAKING** `HistoricalOrder::px` is now `Option<String>` and defaults to
  absent. A `historical_orders` row carries no `px` when the order has neither an
  average fill price nor a limit price — a market order that never rested. The
  previous required field failed the WHOLE response with a missing-field error,
  so one such order in an account's history broke the read. Ordinary user data
  triggers this. This version decodes an absent `px` and a `null` `px` to `None`.
  The SDK does NOT substitute `"0"`, because a fabricated zero reads as a real
  price. Read the field with `as_deref()` and handle `None`.
- The `HistoricalOrder` documentation no longer claims `status` is always
  `"filled"`. A deep-history read also returns non-executed rows, which is the
  same case that carries no `px`.

### Added

- **A Core → MetaFluxEVM move can charge a fee**, and both actions charge the same
  one: `core_evm_transfer` and `send_to_evm_with_data`. Neither is the cheaper
  lane. Documented on both types and both client methods, with the full rule in the
  `types::core_evm` module docs.
- The fee is a quantity of **MTF**, debited ON TOP of the amount, as a second
  debit. It has nothing to do with the asset you move: a transfer of BTC debits BTC
  for the amount and MTF for the fee. It is not a wire field — the chain resolves
  it, and a caller can neither set it nor choose its currency.
- Resolution order, and the chain never splits the fee: spot **MTF** first; then
  **USDC** at the MTF reference price, out of withdrawable collateral; then a
  refusal of the whole transfer, `insufficient MTF or USDC for the core->evm fee`.
  A transfer OF MTF needs `amount + fee`, because both debits hit one balance.
- **The transfer is also refused when the MTF reference price is unusable**:
  `MTF price unavailable; the core->evm fee cannot be quoted in USDC`. MTF is
  priced from its own book, and the chain refuses rather than quote a guess. **This
  is the row callers get wrong: a transfer can fail for a reason unrelated to the
  asset moved, or to your balance of it.** Only a sender short of MTF meets it.
- **The fee is ZERO today, so nothing is charged and none of those refusals can
  happen.** Validator governance sets the amount and no endpoint serves the current
  value, so a caller can neither read it nor predict a change. Hold a small spot
  MTF balance to stay payable, and handle the two refusals.
- A refused transfer pays nothing: the fee is charged only after the amount leg is
  accepted.
- `core_evm_transfer` with `to_evm = false` is refused. The return leg must
  originate as a MetaFluxEVM transaction, not as a signed action. The field
  documentation claimed the direction worked.
- `send_to_evm_with_data` — `Exchange::send_to_evm_with_data_typed`,
  `types::core_evm::SendToEvmWithData`, and `TypedAction::SendToEvmWithData`.
  The action moves a spot token to MetaFluxEVM and runs a payload against the
  recipient. **The node serves it and no client could express it**, so the
  capability was unreachable from this SDK. The signing string is
  `MetaFluxTransaction:SendToEvmWithData(string metafluxChain,uint32 token,string
  amount,uint32 sourceDex,address destinationRecipient,bool toPerp,uint32
  destinationChainId,bytes data,uint64 transferNonce,uint64 nonce)`, and the
  digest is pinned against the node's own fixture.
- The action takes TWO nonces. `transfer_nonce` is the params-level `nonce` that
  labels the transfer and signs as `transferNonce`; the envelope nonce orders the
  account's actions. Both are signed, and they may differ.
- **Send `source_dex = 0`.** The node refuses any other value: the action debits
  the spot ledger and no other. **This is the row an older caller hits** — a
  payload built for the earlier node carries `source_dex: 1`, which was signed
  and then ignored. It now fails.
- `to_perp` must be `false` (the MetaFluxEVM side has no perp account) and
  `destination_chain_id` must be `0` or the local EVM chain id (delivery to a
  remote chain is not built). Both were signed and ignored before. A caller who
  named a remote chain had the value delivered LOCALLY in silence; that silence
  is what the rejection replaces.
- `data` holds 4096 bytes at most. A reverting payload never unwinds the credit:
  the debit is done and the credit landed, so read the receipt.
- The node truncates `amount` to one EVM quantum — first to 8 decimal places,
  then to the token's EVM decimals — and debits exactly what it credits. An
  amount under one quantum is REFUSED, rather than debited for a zero credit.
- A zero `destination_recipient` IS refused on this action, the same as on
  `core_evm_transfer`. (An earlier draft of this entry said the opposite. The
  credit is a mint to the named address and no owner check follows it, so a zero
  recipient would burn the debit.)
- **BREAKING** `TwapOrder` carries two new fields, `position_side:
  Option<PositionSide>` and `randomize: bool`. Every struct literal must add
  them; `TwapOrder { position_side: None, randomize: false, ..}` reproduces the
  old behaviour and the old signed bytes exactly. **Without them a hedge account
  could not place a TWAP at all**: the node REQUIRES the leg on a hedge account
  and refuses it on a one-way one, and the field is bound in the signature, so a
  client that cannot express it cannot sign a valid parent.
- `TwapOrder` now selects one of the three consensus-frozen TWAP signing
  strings, matching the node: `randomize: true` selects the V3 string WHATEVER
  the leg — a randomized one-way parent signs an EMPTY `positionSide` — else a
  present `position_side` selects V2, else the base string. Both new fields are
  omitted from the wire at their defaults, so a one-way, non-randomized payload
  is byte-identical to the one an older SDK sent. The four digests are pinned by
  the node's own cross-language vectors.

### Fixed

- `facade/Cargo.toml` pinned `metaflux-client` at `version = "0.18.0"` while both
  packages are `0.19.0`, so cargo could not resolve the workspace and NO build,
  test or lint ran. The pin now tracks the package version.

## [0.16.0]

Lands the unified `place_order` entry point, the agent-resolved spot `owner`, an
owner-aware low-level digest, and the `candle_type` price series.

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
- **BREAKING** `SpotOrder` and `SpotCancel` gain an optional `owner`
  (`Option<Address>`), mirroring the node's `NativeSpotOrder.owner` /
  `NativeSpotCancel.owner`. With `owner` present an approved AGENT places or
  cancels the order AS that owner; absent, the signer trades for itself. The
  node has supported this since the agent-resolved owner routing landed
  (`NativeAction::claimed_owner` returns it), but no client could reach it. The
  field is breaking only for struct-literal construction — build with
  `SpotOrder::ioc_limit` / `SpotCancel::new`, then `with_owner`.
- `PlaceRequest::spot_as` — a spot request through `place_order` placed AS an
  owner. It stamps `owner` on every leg; `PlaceRequest::spot` stays owner-less.
- `SpotCancel::new` — a constructor, so adding a field does not break callers
  again.
- `TypedTradingAction::payload_owner` — the agent-resolved `owner` an action's
  own payload carries. `TypedTradingDigest::new` binds it, so the low-level
  digest API can no longer sign an owner-less digest for an owner-carrying body.
- `CandleType` (`mark` / `oracle`), the candle price-series selector. `mark` is
  the node default and serves perp and spot; `oracle` serves perp only.

### Changed

- **BREAKING** `TypedTradingDigest::new` reads the action's payload `owner`.
  Six actions carry it — `spot_order`, `spot_cancel`, `scale_order`,
  `cancel_scale`, `chase_order`, `cancel_chase`. Before this the low-level API
  ignored the field, so a caller signed the owner-LESS digest while the posted
  body carried the owner; a present `owner` selects a DIFFERENT frozen EIP-712
  type string, so the node rejected the signature. `TypedTradingDigest::digest`
  now also FAILS when an explicitly bound owner contradicts the payload's own,
  rather than emitting a digest that cannot verify. An owner-less payload signs
  the same bytes as before. The public `Exchange` path was already correct.
- **BREAKING** `Info::candle_snapshot` takes a `candle_type: CandleType`
  argument and sends it inside `req`. The node serves TWO series, `mark`
  (default) and `oracle`; the executed-trade candle is RETIRED and `trade` is a
  400. The request field is named `candle_type`, not `price_type`.
- **BREAKING** `Subscription::Candles` gains `candle_type`, and
  `WsClient::subscribe_candles` takes it. The routing key is
  `(coin, interval, candle_type)`, so two series at one interval are two
  subscriptions.
- **BREAKING** `Candle::num_trades` is renamed `num_samples`. A bar folds a
  PRICE series, so `n` counts price samples and is `0` on a carry-forward bar.
  `volume` and `quote_volume` are documented as always `"0"` for the same
  reason. The old names described the retired trade candle.
- Corrected the "sender-authorized" doc claims that contradict the node's
  `claimed_owner` arms: `Modify`, the three margin actions in `types::account`,
  `RfqRequest`, `RfqAccept`, `FbaSubmit`, and both TWAP actions all accept an
  agent-resolved `owner` on the wire. Each note now says whether that owner
  enters the EIP-712 digest or only routes admission. The stale sentence came
  from the node source and cost real capability in both SDKs.

- `Exchange::spot_order` / `Exchange::spot_cancel` read the new `owner`. Present
  selects the node's `SpotOrder` / `SpotCancel` `*_WITH_OWNER` EIP-712 type
  string and binds the owner word right after `metafluxChain`; absent signs the
  pre-owner digest and posts pre-owner bytes BYTE-FOR-BYTE. Two byte pins and a
  digest pin hold that.
- Spot documentation corrected on two counts. (1) A spot order is NOT
  sender-authorized-only: the wire carries an optional `owner` and an approved
  agent may trade as it. (2) `tif` is not IOC-only — the node accepts `ioc`,
  `gtc` and `alo`, and rests a `gtc` / `alo` residual against escrow. Both notes
  described a node that no longer exists.

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

## [Unreleased — STALE DUPLICATE, historical]

This second `Unreleased` heading predates 0.19.0 and its content was shipped
long ago. The version it belonged to is not recoverable from this file, so it is
labelled rather than guessed. See the note at the top of 0.19.0.

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
