# chime — Release-Readiness Tasks

> Parent plan: [`../_todos_all.md`](../_todos_all.md)
> Project role: client SDK for receiving floria push notifications.
> Phase: **3 (track 3c)**.

## State at start (2026-05-24)

- ~8.1 k LoC across 21 modules; abstract wire+request-builder SDK (no platform receivers).
- Features: `http`, `notify`.
- 0 active `realm-rework` TODO sites; deactivation hooks are wired through
  host-supplied sinks.
- 6 README examples + 6 integration tests (incl. live floria spawn).
- CI: 4-feature matrix, MSRV 1.89, fmt/clippy/doc/typos/audit/package/release.

## Phase 3 tasks

### Integration TODOs
- [x] §1 `src/lifecycle.rs:48` — provide a default `AccountDeactivationSink` impl (or document required host-app hooks more explicitly) for round23-T07.
- [x] §2 `src/lifecycle.rs:102` — wire concrete queue-flush logic once yougen ships its message queue API.
- [x] §3 `src/notify.rs:603` — switch local forbidden-key sweep to SDK's `is_forbidden_payload_key` once §1-§7 of contrix-rust-sdk lands the export.
- [x] §4 `src/notify.rs:1095` — drop chime's locally-maintained legacy-key handling when SDK takes over.

### Compatibility-alias cleanup (paired with SDK realm-rework removal)
- [x] §5 Remove the `serde(alias = "space_id")` on `PushNotification.realm_id` once SDK 0.8.0 alias removal lands. Bump chime to 0.2.0 (wire-breaking).
- [x] §6 Remove the `realm-rework` TODO comments in `src/notify.rs` and `src/push_route.rs`.

### Tests
- [ ] §7 Add an end-to-end smoke test that integrates with yougen (after yougen lands real OS push tokens) — driven from `tests/`.
- [x] §8 Add a fuzz test on `validate_blind_wakeup` (cargo-fuzz or `proptest::test_runner`).

### Engineering hygiene
- [x] §9 Add `cargo deny` (currently absent — only audit).
- [x] §10 Add local coverage badge (tarpaulin already available — wire it without remote upload).
- [x] §11 Pin reqwest/serde minor versions for 1.0 reproducibility.

### Docs
- [x] §12 Add a "production deployment with chime" guide (`docs/production-checklist.md`) — currently the README has a checklist that should be extracted.
- [x] §13 Add API examples for `notify` feature (currently doctest examples cover http but not notify validators).

## Phase 5

- [ ] §14 Build local `v1.0.0` package artifacts and record the evidence. Do not tag, push, or publish to crates.io.

## Exit gate (phase 3)

All of:
1. §1-§6 closed.
2. CI matrix green (4 feature combos).
3. Live-floria integration test green.
4. Record a local `v0.2.0-rc1` milestone without creating a git tag or publishing artifacts.

## Notes

- chime has NO platform-specific code; that's intentional. Platform receivers live in yougen.
- The `live_floria_integration.rs` skips silently when `FLORIA_BIN` is unset — that's fine for OSS contributors; CI should set the env var.
