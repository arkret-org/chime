# Changelog

All notable changes to `chime` are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this
project follows [SemVer](https://semver.org/) once it reaches `1.0`.

## R3.4 — Spec sync 2026-05-31 (cokret-spec @ c2848a4)

- Synced protocol-facing names and fixtures to `c2848a4`: event envelope schema naming, `_ids` grant constraints, accountability principal vocabulary, `ck:rtc_participant:` media participants, agent session start fields, and key-backup signature algorithm naming where applicable.

> No version tag, no crates.io / Docker Hub / npm publish — git commit only.

## R3.3 — Spec sync 2026-05-28 (cokret-spec @ cced4b8)

- R3.3 spec sync — pin to cokret-spec @ cced4b8 (CXP-0011 shareable object addressing / `cx.directory.resolve_target`: N/A for this service; object-address resolution belongs to the Directory Service).

> No version tag, no crates.io / Docker Hub / npm publish — git commit only.
## R3.2 — Spec sync 2026-05-28 (cokret-spec @ b56cab1)

- Audited for mention-reference decode types: none present (push SDK uses DID actor routing lists + push-rule booleans). No wire change required for the §3.8 mention shape v2; `drift_gate` green.
- Synced to cokret-spec @ b56cab1.

> No version tag, no crates.io / Docker Hub / npm publish — git commit only.
## R3 — Spec sync 2026-05-27 (cokret-spec @ b47ff6ec)

- CALL-1: `push::media_token` wraps the SDK `call_media_token_exchange` request builder and exposes `structurally_validate_media_token_response` + `MediaTokenStructuralValidationContext` for the anchor / TTL / participant-binding tuple check. The successful return type is `StructurallyValidatedMediaTokenResponse`, explicitly not cryptographic verification; host applications must verify `service_signature` and `participant_binding.sig` before SFrame keying until SDK signature verification lands.
- CALL-2: token responses are rejected with typed `MediaTokenError` variants for `unknown_focus_type`, `token_issuer_unauthorised`, `participant_binding_invalid`, `focus_mismatch`, `legacy_single_endpoint_media_service`; classified by `PushErrorKind::is_media_token_rejection`.
- ERR-1: 20 new R3 error codes mirrored from cokret-rust-sdk into `PushErrorKind` (media-binding + agent-lifecycle + recovery + handle homograph); `from_failure_code` matches via `cokret::error::ERROR_CODE_*` constants.
- Telemetry / UI helpers added: `is_media_token_rejection`, `is_media_binding_code`, `is_agent_lifecycle_code` for branching error UX.

> No version tag, no crates.io / Docker Hub / npm publish — git commit only.

## [Unreleased]

### Added — CXP-0007 (Circle primitive) client-side surface

- **`chime::bugle::BugleAppIdResolver`** provides the minimal
  domestic-Android app-id resolution path: Android prefers
  `domestic_app_id`, other platforms use the normal `app_id`.
- **Chinese documentation** under `zh/` covers integration, error
  codes, and production checks for yougen-facing SDK consumers.
- **`PushNotification.circle_id` and `PushNotification.effective_scope`**
  expose the typed `ck:circle:` / `ck:realm:` security boundary that an
  event was authored against. `validate_wire_model` rejects untyped
  values and `validate_blind_wakeup` enforces the Circle metadata
  privacy invariant (no `did:` literal smuggled in `circle_id`, no
  `circle_name` / `circle_members` / `circle_member_dids` in `extra`).
  `PushNotification` becomes `#[non_exhaustive]`; new constructor
  `PushNotification::new_blind_wakeup(push_target_id, wakeup_kind)`
  for external consumers that previously used struct literals.
- **`PushPreferences.muted_circle_ids` and `muted_realm_ids`**
  (`BTreeSet<String>`) so a device can opt out of UI surfacing for a
  specific Circle or Realm while floria continues to account for
  wire-level delivery. Empty sets are omitted from the persisted JSON.
- **`AccountDeactivationReceipt.circle_bindings_cleared` and
  `realm_bindings_cleared`** snapshot the muted Circle / Realm ids
  observed in the prefs store before `on_account_deactivate` wipes
  them, so host-side telemetry can report which bindings were live at
  the moment of deactivation. `AccountDeactivationReceipt` is no
  longer `Copy` (now contains `Vec<String>`).
- **wasm32 CI coverage** (`.github/workflows/ci.yml`): a new job runs
  `cargo check --target wasm32-unknown-unknown --features http` and
  `cargo doc --target wasm32-unknown-unknown --no-deps --features http`
  with `RUSTDOCFLAGS=-Dwarnings` so wasm-only regressions are visible.
- **Doc-test for the blind-wakeup error path**: the
  `validate a blind push wakeup` README example now branches on a
  plaintext-`title` payload and asserts the validator surfaces the
  offending field name.

### Changed

- **Breaking security rename:** removed the misleading
  `verify_media_token_response` / `MediaTokenVerifyContext` surface.
  Consumers must use `structurally_validate_media_token_response` with
  `MediaTokenStructuralValidationContext`; the success marker is
  `StructurallyValidatedMediaTokenResponse`, not a signature-verification
  proof.
- **`MediaTokenError::FocusMismatch` fields are explicit**: errors now
  carry `requested_focus_id`, `binding_focus_id`, and optional
  `committed_focus_id` so logs no longer conflate a requested-vs-binding
  mismatch with a committed-session-focus mismatch.
- **`tests/live_floria_integration.rs` is fail-fast in CI.** A new
  `tests/_helpers/floria_spawn.rs::require_floria_or_skip` helper
  panics when the floria binary is unavailable AND
  `CHIME_INTEGRATION_REQUIRED=1` is set (CI sets this); without the
  env var it still prints a clearly-labelled `[warn]` skip so local
  developers without a sibling floria checkout keep getting a green
  run. A new `live-integration` CI job checks out
  `cokret/floria`, builds the binary, and exercises the tests
  with `CHIME_INTEGRATION_REQUIRED=1`.

### Security

- Media-token exchange validation is now named as structure-only:
  `structurally_validate_media_token_response` returns
  `StructurallyValidatedMediaTokenResponse`, so yougen cannot confuse
  tuple/anchor/TTL checks with Ed25519 verification before SFrame
  keying.
- `PushNotification` documentation now calls out the `#[serde(flatten)]`
  `extra` map explicitly: deserialization must be followed by
  `assert_payload_safe`, `validate_blind_wakeup`, or
  `validate_wire_model`.
- `NonceTracker` documentation now treats persistent replay storage as
  mandatory for server-side relays and multi-process hosts.
- Circle metadata privacy: `circle_members` / `circle_member_dids` /
  `circle_member_actor_ids` are now classified as never-allowed
  payload keys; they cannot appear on any push wakeup wire even for
  whitelisted plaintext-visible destination service DIDs.

### Notes

- Version stays at `1.0.0`; no release artifact, no crates.io publish,
  no git tag in this round (per `_todos_all.md` §0 hard rules).

## [1.0.0] - 2026-05-25

### Added

- `NoopAccountDeactivationSink` and `ClosureAccountDeactivationSink` so host
  applications can wire deactivation queue/cache/session cleanup without a
  bespoke adapter type.
- Local `cargo deny` configuration and CI check.
- Notify-feature README example and `docs/production-checklist.md`.
- Proptest coverage for safe opaque `validate_blind_wakeup` extension keys.

### Changed

- The package version is now `1.0.0` for the realm-only wire break.
- chime routes forbidden blind-payload key checks through the SDK's
  `is_forbidden_payload_key`.
- Local package verification no longer contains publish, tag, or GitHub release
  actions.

### Round R4 — protocol review closures (2026-05-20, cokret-spec `2a4d39b..a77b995`)

Client-side push SDK alignment with the round-4 wire shapes. See
[`_chime_todos.md`](./_chime_todos.md) for the workstream context.

- **Added** recognition of the `mention_redirect_target_actor_ids` payload
  field on message / system-message push routing — chime now exposes the
  field through its typed push-payload types so consumers (yougen et al.)
  can decide whether the active device is an authorised redirect target.
- **Added** typed surface for the three new floria-passthrough error
  reason codes (`delivery_binding_stale` / `delivery_binding_handed_over` /
  `historical_only`); `historical_only` is annotated as diagnostic and
  suppresses local user-visible notification.
- **Added** DID method-name regex sweep tightened to
  `^did:[a-z0-9]+:[^\s]+$` across chime's DID validators and test fixtures.

### Round R2/R3 (2026-05-20, spec rounds 2+3 close-out, 17 P0/P1 tasks)

#### Added

- **T07 account deactivation cleanup hook.** New `lifecycle` module
  exposing `on_account_deactivate(sink, prefs_store, source)` as the
  single integrator entrypoint. Drives the four-step fanout from
  `account-lifecycle.md` §7.1: drain local push queue → clear
  keypackage cache → invalidate device session → clear persisted
  `PushPreferences`. Sub-step bodies live host-side via
  `AccountDeactivationSink`, `NoopAccountDeactivationSink`, or
  `ClosureAccountDeactivationSink` so chime stays out of the queue / MLS
  / keychain layer; the call order and `DeviceSessionInvalidationReason`
  / `DeactivationSource` discriminants are pinned by chime so every
  consumer (yougen / starid / sodmin) winds down the same way. Receipt
  type (`AccountDeactivationReceipt`) reports which sub-steps ran when
  one fails mid-flight.
- **`assert_no_sensitive_fields(payload)` defense-in-depth helper**
  (notify feature). Panics in `debug_assertions` and returns
  `Err(field_path)` in release when any Round R2/R3 governance field
  (`appeal_id`, `attestation_evidence`, `trust_domain`,
  `policy_frontier_digest`, `reset_event_id`, …) appears anywhere in a
  blind push payload tree. Backed by the new public
  `ROUND_R2_R3_SENSITIVE_FIELDS: &[&str]` so chime / floria / yougen can
  iterate the same negative-vector list. Mirrors the floria T07/T10/T06
  forbidden-field surface.

#### Notes

- **Ephemeral kinds — confirmed not consumed.** A repo-wide search
  for `cx.presence` / `cx.typing` / `cx.receipt.read` /
  `cx.call.signal` and `ephemeral` returned zero hits in `src/` and
  `tests/`. chime never parsed these as push payload kinds (they ride
  ephemeral channels, not the floria push path) so no removal was
  needed; recording the audit here so the round 2+3 close-out doesn't
  reopen the question.

### Changed

- Realm/Space terminology inversion (wire-breaking): old `Space` (security
  boundary) → **Realm**, old `Place` (container) → **Space**. Push routes
  and notify payloads now carry the new `realm_id` field. Legacy aliases are
  removed from the chime wire model.

### Notes

- CH-3 (2026-05-18): evaluated extracting `state::repair` and
  `state::rotation` to `cokret-sdk` for reuse by starid/teabay.
  Skipped: every plan function is parameterised over push-specific
  types (`PushRegistrationState`, `PushDeviceConfig`,
  `PushPreferences`, `RegisterDeviceRequest`,
  `UnregisterDeviceRequest`, `GatewayBinding`) and the pure policy
  logic is a few dozen lines that would only become a trait skeleton
  with full generification. starid/teabay currently have no
  client-side device registration lifecycle. Skip notes left inline
  in `src/state/repair.rs` and `src/state/rotation.rs`.

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
  opt-in). `PushPreferences::effective_gateways()`
  returns either the explicit list or a synthesized single binding
  from the singular `push_gateway` / `gateway_type` fields.
  `CokretPushClient::register_device_all` exercises every binding
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
  pairwise pseudonym shape (`ck:pseudonym:push:<base64url>` or raw
  base64url, ≥ 22 chars, rejects DIDs / device-id / token material).
  `PushNotifyRequest::validate_blind_wakeup_strict` enforces both fields
  per `cokret-spec` §5.1.
- `PushRoute` typed wrapper (`route`, `push_target_id`,
  `push_gateway_did`, `encryption_key`, `capabilities`, `revoked`,
  `metadata`) with active/revoked state machine and `PushRouteId` /
  `PushRouteCapability` newtypes. Models the `cx.device.push_route`
  actor-private state event without owning private keys.
- `tests/pseudonym_unlinkability.rs` integration tests locking that the
  SDK never accepts a DID / device id / push token / cokret typed-id
  prefix as a `PushTargetId`, and that distinct routes keep distinct
  pseudonyms across serde round-trips.
- `CokretPushClient::rotate_token(existing, config, prefs, strategy)`:
  high-level wrapper around `plan_token_rotation_with_strategy` +
  register/unregister.
- `PushPreferencesStore` trait (load / save / clear) so host apps can
  plug their own keychain / encrypted storage backend without rolling
  the file IO themselves.
- Local `1.0.0` stability banner in `README.md` / `README_zh.md` and
  `push/wire.rs` module docs.
- `package` and `audit` jobs in CI (`cargo package --list` plus
  `rustsec/audit-check` against advisory database).
- Local release-readiness workflow (`.github/workflows/release.yml`) that
  builds package artifacts without tags, pushes, GitHub releases, or
  crates.io publishing.
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

- **Breaking:** `PushPreferences` no longer carries the singular
  `gateway_type` / `push_gateway` pair. The multi-gateway
  `gateways: Vec<GatewayBinding>` is now the only source of gateway
  data, `effective_gateways()` and `apply_gateway_type_defaults()` are
  gone, and `from_json` rejects the removed singular keys.
  `build_register_device_request`,
  `build_unregister_device_request`,
  `plan_registration_repair`, `plan_token_rotation` /
  `plan_token_rotation_with_strategy`, and
  `CokretPushClient::register_device` /
  `unregister_device` / `rotate_token` now take an explicit
  `&GatewayBinding`. `plan_multi_gateway_repair` iterates
  `prefs.gateways` directly and surfaces every persisted state as an
  orphan when `gateways` is empty.
  `build_registration_state` drops its `config` argument along with
  `with_registration_id_fallback`: state's `registration_id` now comes
  straight from the server response (or is `None`).
- `PushNotification.validate_wire_model` now requires `wakeup_kind` on
  the current notify wire model.
- `typos.toml` cleaned up — removed copy-pasted entries unrelated to
  this crate; added Cokret project vocabulary.
- README quick-start no longer references the non-existent
  `chime::try_from_json` helper; only `from_json` is the strict parser.

### Fixed

- Two pre-existing `cargo doc -Dwarnings` errors in
  `src/push/client.rs` and `src/notify.rs`.

## Pre-1.0 planning snapshot

Historical planning notes retained from the pre-1.0 task list.

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

- `CokretPushClient` with `register_device`, `unregister_device`,
  `bridge_describe`, `integration_describe`, `integration_view`.
- Default fail-closed on missing `X-Cokret-Session-Grant` header
  (toggle with `with_required_session_grant(false)` for dev sandboxes).
- Auto-generated idempotency keys for register/unregister so retries
  are always safe.
- `PushRetryPolicy` with `Retry-After` honoring, exponential backoff,
  and bounded jitter.
- `PushErrorKind::from_failure_code` mapping Cokret
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
  local package, and `rustsec/audit-check` jobs.
