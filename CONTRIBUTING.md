# Contributing to chime

Thanks for taking the time to contribute. `chime` is a small, focused
Rust SDK that ships Contrix push gateway types, registration helpers,
and an optional HTTP client. The project value is in being _boring and
correct_ — we trade bells and whistles for stable wire shapes and
strict privacy validators.

## Development environment

- Rust toolchain: stable channel.
- Minimum supported Rust version (MSRV): **1.89** — keep CI green on
  this toolchain even if you develop on a newer one.
- Editor: any. The repo enforces formatting via `rustfmt`.

```bash
git clone https://github.com/contrix-dev/chime
cd chime
cargo build
```

## Common commands

| Task | Command |
| ---- | ------- |
| Build (default features) | `cargo build` |
| Build (all features) | `cargo build --all-features` |
| Run tests (default) | `cargo test` |
| Run tests across feature matrix | see [feature matrix](#feature-matrix) |
| Format | `cargo fmt --all` |
| Lint | `cargo clippy --all-features -- -D warnings` |
| Build docs | `RUSTDOCFLAGs=-Dwarnings cargo doc --all-features --no-deps` |
| Check spelling | `typos` (install `cargo install typos-cli` first) |

### Feature matrix

CI runs `check`, `test`, and `clippy` against four feature
combinations. Reproduce locally before pushing:

```bash
for f in "" "http" "notify" "http,notify"; do
  cargo check --no-default-features --features "$f"
  cargo test  --no-default-features --features "$f"
  cargo clippy --no-default-features --features "$f" -- -D warnings
done
```

### Required gates before opening a PR

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --all-features -- -D warnings`
- [ ] `cargo test --all-features`
- [ ] `cargo test` across the four feature combinations above
- [ ] `cargo doc --all-features --no-deps` builds without warnings
- [ ] `cargo package --no-verify --allow-dirty` succeeds (CI runs this
      as the `package` job)

## Commit messages

Use the prefix `chime: ` followed by an imperative summary of the
change, mirroring existing history:

```
chime: PushNotifyPolicyContext closes the C1 release gate
chime: bridge capability accessors (B2) + drift gate fixture test (F4)
```

Reference TODO IDs (e.g. `A2`, `C3`, `F4`, `G5`) when the change
addresses an item from `_todos.md`.

## Pull request guidelines

- Keep PRs focused on a single TODO ID or single concern. Cross-cutting
  refactors should land separately so reviewers can reason about wire
  changes without bundle churn.
- Document wire-shape changes in `CHANGELOG.md` under the
  `[Unreleased]` section. Pre-1.0 we do not pretend that response or
  request shape is unconditionally stable, but we do call out
  additions vs. renames vs. removals.
- Run the full feature matrix before pushing. CI reproduces it but
  catches regressions much earlier locally.

## Privacy boundary discipline

Two rules are enforced in code; do not weaken them.

1. `push_key` and any FCM/APNs/WebPush token fragment is **redacted**
   in `Debug` impls and tracing fields. New types that carry token
   material must implement a custom `Debug` that uses
   `redact_push_key` (or an equivalent helper).
2. `validate_blind_wakeup`, `validate_plaintext_visible_service`, and
   `PushNotifyPolicyContext::mode_for` are the only legal entry points
   that decide whether identifying metadata may leave the SDK. New
   conditional fields belong inside that gate, not above it.

Tests for changes that touch the privacy boundary should add a row to
`shared_push_notify_privacy_vectors()` so floria and other downstream
gateways inherit the same fixture.

## Security reports

Do not file security-sensitive issues in the public tracker. Follow the
process in [SECURITY.md](SECURITY.md).

## Releasing (maintainers)

1. Bump `version` in `Cargo.toml`.
2. Move entries in `CHANGELOG.md` from `[Unreleased]` to a new
   `[X.Y.Z] - YYYY-MM-DD` section.
3. Open a release PR. Once merged on `main`:
4. Tag: `git tag vX.Y.Z && git push origin vX.Y.Z`. CI's `release.yml`
   verifies the tag matches `Cargo.toml`, runs `cargo publish
   --dry-run`, and prepares a draft GitHub release.
5. To actually publish to crates.io, dispatch the `release` workflow
   with `dry_run = false` (requires the `CRATES_IO_TOKEN` secret on the
   `crates-io` environment).
