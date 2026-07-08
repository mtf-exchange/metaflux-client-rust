# Contributing

Thanks for your interest in `metaflux-client`.

## Development

```bash
cargo build --all-features
cargo test --all-features
cargo test --no-default-features
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all
```

CI enforces `fmt`, `clippy -D warnings`, the test matrix, and
`cargo doc -D warnings` — run them locally before pushing.

### Git hooks

The repo ships a `pre-commit` hook that mirrors the CI `cargo fmt` gate.
Enable it once per clone:

```bash
git config core.hooksPath .githooks
```

`core.hooksPath` is local config, so every clone must run this once.

## Workspace layout

- `metaflux-client` (repo root) — the SDK.
- `facade/` — the `metaflux` alias crate that re-exports `metaflux-client`.

## Changes

- Open an issue to discuss anything non-trivial first.
- Keep commits focused; match the surrounding code style and comment density.
- Add tests for new behaviour.
- External contributions: fork and open a pull request against `main`.

By contributing, you agree your contributions are licensed under the MIT
license.
