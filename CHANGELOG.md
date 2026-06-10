# Changelog

All notable changes to `metaflux-client` are documented in this file. The
format adheres to [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once we cut `v1.0`. Pre-1.0 minor bumps may break.

## [Unreleased]

### Added

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
  `set_metaliquidity_whitelist` / `register_metaliquidity_operator`.

### Changed

- **Breaking:** removed signed actions the node does not accept — `rfq_request` /
  `rfq_accept`, `fba_submit`, `pm_enroll` / `pm_unenroll` / `pm_rebalance`,
  `cross_chain_send`, `encrypted_order_submit` (replaced by
  `submit_encrypted_order`), `vault_create` (replaced by `create_vault`),
  `vault_distribute`. Read types for these domains (e.g. `RfqState`, `PmState`,
  `VaultState`) are retained.
- **Breaking:** `vault_withdraw` now takes `{ vault_id, shares }` with `shares`
  as a decimal string.

### Removed

- The optional `grpc` feature and the `tonic` / `prost` dependencies.
