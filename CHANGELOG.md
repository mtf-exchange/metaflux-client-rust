# Changelog

All notable changes to `metaflux-client` are documented in this file. The
format adheres to [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once we cut `v1.0`. Pre-1.0 minor bumps may break.

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
  `vault_transfer` / `vault_modify` / `vault_withdraw`, `mb_withdraw`,
  `REDACTED` / `REDACTED`.

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
