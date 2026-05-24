# chime Local 1.0.0 Evidence

Date: 2026-05-25

Status: local package-readiness evidence. No crates.io publish, GitHub
release, release tag, or remote artifact publication was created.

## Version Freeze

- `chime` package version: `1.0.0`
- Local SDK dependency: `contrix = 1.0.0` via
  `../contrix-rust-sdk/crates/sdk`

## Local Gates

```powershell
cargo fmt --all -- --check
cargo check --no-default-features
cargo check --no-default-features --features http
cargo check --no-default-features --features notify
cargo check --no-default-features --features http,notify
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo deny check
cargo package --list --allow-dirty
git diff --check
```

`cargo package --list --allow-dirty` is used for local-only evidence because a
full registry package verification attempts to resolve the sibling `contrix`
crate from crates.io. This repository intentionally does not publish that
sibling crate in the local readiness workflow.

## Interop Notes

- `tests/live_floria_integration.rs` exercises the live floria bridge when
  `FLORIA_BIN` is available.
- yougen owns platform push receivers and OS token acquisition. The chime
  crate stays platform-neutral and exposes the validation/registration/lifecycle
  contract used by that host integration.
