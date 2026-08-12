# Contributing to chime

Thanks for taking the time to contribute. `chime` is a small, focused
Rust SDK that ships Arkret push gateway types, registration helpers,
and an optional HTTP client. The project value is in being _boring and
correct_ — we trade bells and whistles for stable wire shapes and
strict privacy validators.

## Pre-commit hook setup

After cloning, enable the project's pre-commit hooks:

```sh
git config core.hooksPath .githooks
```

The hook runs `cargo fmt --all -- --check` plus `cargo clippy --no-deps
-- -D warnings` on staged Rust changes. If `.githooks/pre-commit` is
missing, copy it from
[`arkret-rust-sdk`](https://github.com/arkret-org/arkret-rust-sdk)
and adapt to your local toolchain.

## Development environment

- Rust toolchain: stable channel.
- Minimum supported Rust version (MSRV): **1.97** — keep CI green on
  this toolchain even if you develop on a newer one.
- Editor: any. The repo enforces formatting via `rustfmt`.

```bash
git clone https://github.com/arkret-org/chime
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
combinations. Reproduce them locally before handing off changes:

```bash
for f in "" "http" "notify" "http,notify"; do
  cargo check --no-default-features --features "$f"
  cargo test  --no-default-features --features "$f"
  cargo clippy --no-default-features --features "$f" -- -D warnings
done
```

### Required gates before handing off changes

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --all-features -- -D warnings`
- [ ] `cargo test --all-features`
- [ ] `cargo test` across the four feature combinations above
- [ ] `cargo doc --all-features --no-deps` builds without warnings
- [ ] `cargo package --list --allow-dirty` succeeds (CI runs this as
      the local package file-set job)

## Commit messages

Use the prefix `chime: ` followed by an imperative summary of the
change, mirroring existing history:

```
chime: PushNotifyPolicyContext closes the C1 release gate
chime: bridge capability accessors (B2) + notify agent privacy tests (F4)
```

Reference TODO IDs (e.g. `A2`, `C3`, `F4`, `G5`) when the change
addresses an item from `_todos.md`.

## Change review guidelines

- Keep changes focused on a single TODO ID or single concern. Cross-cutting
  refactors should land separately so reviewers can reason about wire
  changes without bundle churn.
- Document wire-shape changes in `CHANGELOG.md` under the
  `[Unreleased]` section. For the local `1.0.0` line, call out
  additions separately from renames or removals so downstream consumers
  can judge SemVer impact.
- Run the full feature matrix before handing off the branch. CI
  reproduces it, but the local gates catch regressions earlier.

## Privacy boundary discipline

Two rules are enforced in code; do not weaken them.

1. `push_key` and any FCM/APNs/WebPush token fragment is **redacted**
   in `Debug` impls and tracing fields. New types that carry token
   material must implement a custom `Debug` that uses
   `redact_push_key` (or an equivalent helper).
2. Gateway-side blind-wakeup validation lives in the SDK
   (`arkret_push_policy::blind_payload_sanitizer`), not in chime. Do not
   reintroduce server-side notify wire types or their validators here —
   chime is a client SDK.

## Security reports

Do not file security-sensitive issues in the public tracker. Follow the
process in [SECURITY.md](SECURITY.md).

## Local Release Readiness

1. Bump `version` in `Cargo.toml`.
2. Move entries in `CHANGELOG.md` from `[Unreleased]` to a new
   `[X.Y.Z] - YYYY-MM-DD` section.
3. Run the local verification matrix from
   [docs/production-checklist.md](docs/production-checklist.md).
4. Verify the local package file set with `cargo package --list
   --allow-dirty` and record the evidence in the local milestone notes.

Do not tag, push, create a GitHub release, or publish to crates.io from
this repo's local readiness workflow.
