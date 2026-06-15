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
  `REDACTED` / `REDACTED`.

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
