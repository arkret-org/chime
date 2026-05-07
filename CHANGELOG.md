# Changelog

All notable changes to `chime` are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this
project follows [SemVer](https://semver.org/) once it reaches `1.0`.

## [Unreleased]

### Added

- `plan_multi_gateway_repair` + `PushMultiGatewayRepairPlan` extend the
  registration state-machine to multi-gateway preferences. Each binding
  in `PushPreferences::effective_gateways()` gets its own
  `PushRegistrationRepairPlan` planned against the subset of states
  whose `push_gateway` matches that binding; states left over from a
  removed gateway are surfaced as `orphan_states` with pre-built
  unregister requests. Same-token registrations across distinct
  gateways no longer cross-pollinate as token-moves.
- Multi-gateway registration. `GatewayBinding { gateway_type,
  push_gateway, push_key, app_id }` plus
  `PushPreferences::gateways: Vec<GatewayBinding>` (default empty,
  fully backward-compatible). `PushPreferences::effective_gateways()`
  returns either the explicit list or a synthesized single binding
  from the legacy `push_gateway` / `gateway_type` fields.
  `ContrixPushClient::register_device_all` exercises every binding
  independently and returns one `Result` per binding so partial
  failures stay visible.
- `PushRetryPolicy::with_disabled_kinds(&[PushErrorKind::…])` and
  `retries_disabled_for(kind)` so callers can carve a hole in the
  retry loop for specific error kinds. Implemented as a `u32` bitmask
  indexed by `PushErrorKind::ordinal()`, which is hand-numbered so
  `#[non_exhaustive]` additions cannot reorder existing masks.
- `tests/property.rs` proptest suite (5 properties) covering register
  request totality, unregister never-echoes-token, deterministic
  opaque `hash_push_key`, blind-wakeup rejection of sensitive keys,
  and `PushTargetId` serde round-trip.
- README rust code blocks compile as doc-tests via
  `#[cfg(doctest)] #[doc = include_str!("../README.md")]` — quick-start
  examples can no longer drift away from the API.
- Spec-aligned `PushTargetId` newtype and `WakeupKind` enum on
  `PushNotification`. Validates the per-(principal, device, push_route)
  pairwise pseudonym shape (`cx:pseudonym:push:<base64url>` or raw
  base64url, ≥ 22 chars, rejects DIDs / device-id / token material).
  `PushNotifyRequest::validate_blind_wakeup_strict` enforces both fields
  per `contrix-spec` §5.1.
- `PushRoute` typed wrapper (`route`, `push_target_id`,
  `push_gateway_did`, `encryption_key`, `capabilities`, `revoked`,
  `metadata`) with active/revoked state machine and `PushRouteId` /
  `PushRouteCapability` newtypes. Models the `cx.device.push_route`
  actor-private state event without owning private keys.
- `tests/pseudonym_unlinkability.rs` integration tests locking that the
  SDK never accepts a DID / device id / push token / contrix typed-id
  prefix as a `PushTargetId`, and that distinct routes keep distinct
  pseudonyms across serde round-trips.
- `ContrixPushClient::rotate_token(existing, config, prefs, strategy)`:
  high-level wrapper around `plan_token_rotation_with_strategy` +
  register/unregister.
- `PushPreferencesStore` trait (load / save / clear) so host apps can
  plug their own keychain / encrypted storage backend without rolling
  the file IO themselves.
- Pre-1.0 stability banner in `README.md` / `README_zh.md` and
  `push/wire.rs` module docs.
- `package` and `audit` jobs in CI (`cargo publish --dry-run` plus
  `rustsec/audit-check` against advisory database).
- Release workflow (`.github/workflows/release.yml`) that verifies the
  pushed tag matches `Cargo.toml` version, runs a dry-run publish, and
  drafts a GitHub release with notes from this changelog.
- `CONTRIBUTING.md`, `SECURITY.md`, and `CHANGELOG.md` for repo
  hygiene.
- Crates.io metadata in `Cargo.toml` (`keywords`, `categories`,
  `homepage`, `documentation`, `readme`, `exclude`, and a
  `[package.metadata.docs.rs]` section that builds with all features).
- Stability annotations on public types: `PushGatewayType`,
  `PushPreferences`, `PushPlatform`, `PushDeviceConfig`,
  `PushErrorKind` (now also `#[non_exhaustive]`), and
  `PushRegistrationState`.

### Changed

- `PushNotification.validate_wire_model` now accepts either a non-empty
  legacy `type` field or a set `wakeup_kind`; previously `type` was
  unconditionally required. This is backward-compatible for callers
  that still set `type`.
- `typos.toml` cleaned up — removed copy-pasted entries unrelated to
  this crate; added Contrix project vocabulary.
- README quick-start no longer references the non-existent
  `chime::try_from_json` helper; only `from_json` is the strict parser.

### Fixed

- Two pre-existing `cargo doc -Dwarnings` errors in
  `src/push/client.rs` and `src/notify.rs`.

## [0.1.0] - Unreleased (target)

Initial public release once the items in `_todos.md` Phase G are
merged.

### Wire types and validators

- `RegisterDeviceRequest` / `RegisterDeviceResponse` / `Unregister...`
  with `#[non_exhaustive]` response shapes for additive evolution.
- `cx.push.notify` wire DTOs (`PushNotifyRequest` / `PushNotification`
  / `PushNotificationDevice`) gated behind the `notify` feature.
- `PushHint` newtype enforcing opaque wakeup-token shape (≤64 chars,
  `[A-Za-z0-9_\-:.]`, no DID / call setup / preview material).
- `PushNotifyPolicyContext` privacy gate: blind wakeup is the default;
  plaintext is only allowed for explicitly listed destination service
  DIDs.
- `EncryptedEnvelope` typed wrapper for DID-bound payloads (chime does
  not encrypt or decrypt — only locks the wire shape).
- `validate_blind_wakeup`, `validate_plaintext_visible_service`,
  `assert_payload_safe` — the three legal exit points for sensitive
  metadata.

### HTTP client (`http` feature)

- `ContrixPushClient` with `register_device`, `unregister_device`,
  `bridge_describe`, `integration_describe`, `integration_view`.
- Default fail-closed on missing `X-Contrix-Session-Grant` header
  (toggle with `with_required_session_grant(false)` for dev sandboxes).
- Auto-generated idempotency keys for register/unregister so retries
  are always safe.
- `PushRetryPolicy` with `Retry-After` honoring, exponential backoff,
  and bounded jitter.
- `PushErrorKind::from_failure_code` mapping Contrix
  `bridge/describe.failure_codes` strings.

### Local state

- `PushRegistrationState` with `schema_version`, principal/device/app
  binding, hashed token, redacted preview, expiry/refresh hint, last
  success/error summary.
- `PushRegistrationStore` trait with multi-registration default
  implementations.
- `merge_registration_state` + `plan_registration_repair` +
  `plan_token_rotation_with_strategy`.
- `BridgeContractCache` for advisory drift detection.

### Discovery / capability

- `bridge/describe` typed accessors (`supports_dedup`, `dedup_window`,
  `rate_limit_window`, `rate_limits_by`, `max_request_size`).
- `IntegrationView` aggregating manifest + bridge with
  `requires(service, purpose)` / `contract_digest()` helpers.

### CI

- Feature matrix (`""`, `"http"`, `"notify"`, `"http,notify"`) checked,
  tested, clippied.
- `rustfmt`, `cargo doc -Dwarnings`, MSRV (1.89), `crate-ci/typos`,
  `cargo publish --dry-run`, and `rustsec/audit-check` jobs.

[Unreleased]: https://github.com/contrix-dev/chime/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/contrix-dev/chime/releases/tag/v0.1.0
