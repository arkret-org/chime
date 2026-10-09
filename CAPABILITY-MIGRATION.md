# Authority-Commit Capability Migration

chime is a client-side library: push preferences, gateway binding, device
register/unregister request building, an optional Station-only HTTP client, and
the notification rule / DND evaluator. It authors no Realm Event and never
holds a `RealmCommit`.

This file records, for every product entry point that existed before the
authority-commit clean break, where the capability lives now and which test
covers it. Empty implementations are named as empty.

## Protocol invariants every row is measured against

Only the invariants that can be violated from inside this repository are listed.
The rest of the protocol has no surface here.

- [x] chime never produces a Realm Event, so no type it builds carries a
  predecessor, ordering, basis, frontier, Seal or Cell field. `grep` for
  `RealmCommit`, `CommittedEventRef`, `CommitStreamRef`, `EventCommitSubmission`,
  `previous_commit_ref` and `stream_position` across `src/`, `tests/` and
  `examples/` returns zero hits.
- [x] Device registration is a Station-side operation
  (`ak.edge.push.command.register_device.v1` /
  `ak.edge.push.command.unregister_device.v1`), not a Gateway self-service one.
  `ArkretPushClient` sends the registration calls only to its Station base URL
  and requires an Arkret session grant header by default. Gateway discovery and
  direct Gateway HTTP are absent.
- [x] A registration identifies its owner by the complete `AccountId`
  (`principal_id` + `station_id`). A bare principal id is not an identity: two
  Stations may host the same principal, and the local state must keep them
  distinct.
- [x] Push notification consent is explicit registration state, never inferred
  from the presence of a token.
- [x] No Seal / Cell / frontier / control-proposal vocabulary survives in the
  public API, the wire DTOs or the docs.

## Product capabilities preserved

| Capability | Implementation (`file:symbol`) | Tests |
|---|---|---|
| Push preferences document: enable flag, loopback allowance, WebPush endpoint allowlist, JSON load/save | `src/lib.rs:PushPreferences` | `tests::default_preferences`, `tests::json_roundtrip`, `tests::from_json_partial_uses_field_defaults`, `tests::from_json_rejects_invalid_payload` |
| Gateway selection (Standard / Bugle / Custom) and Android-OEM app-id resolution | `src/lib.rs:PushGatewayType::resolve_app_id` | `tests::gateways_round_trip_through_json`, `tests::resolve_app_id_standard`, `tests::resolve_app_id_bugle_android`, `tests::resolve_app_id_bugle_ios_uses_base` |
| Per-account gateway binding with per-binding overrides and push-key redaction | `src/gateway_binding.rs:GatewayBinding` | `gateway_binding::tests` (6): `binding_round_trips_through_json_with_defaults_omitted`, `binding_with_overrides_serializes_overrides`, `binding_rejects_unknown_fields`, `binding_debug_redacts_push_key_override`, `resolve_app_id_prefers_binding_override`, `resolve_app_id_falls_back_to_gateway_resolution` |
| Register-device request building, including required `device_id`, gateway, push key, explicit consent and WebPush allowlist enforcement | `src/push/registration.rs:build_register_device_request` | `push::registration::tests::register_request_matches_arkret_schema`, `::requires_device_id`, `::requires_register_push_gateway`, `::requires_register_push_key`, `::validates_webpush_endpoint_allowlist`, `::visible_notification_opt_in_is_explicit_registration_state`, `::redacts_push_tokens_from_debug_output`; doctest `src/push/registration.rs` line 21 |
| Unregister-device request building, by registration id or by device | `src/push/registration.rs:build_unregister_device_request` | `push::registration::tests::unregister_request_supports_registration_id`; doctest `src/push/registration.rs` line 99; `tests/property.rs:unregister_request_never_echoes_random_into_push_key` |
| Frozen wire DTOs and platform enum for the two registration operations | `src/push/wire.rs:ChimePushRegisterDeviceRequest`, `:ChimePushUnregisterDeviceRequest`, `:PushDeviceConfig`, `:PushPlatform` | `push::wire::tests::response_models_cover_frozen_wire_metadata`, `::supports_web_and_desktop_platforms`, `::rejects_unknown_platform` |
| Gateway URL validation (HTTPS, loopback exception, no query secrets), Station API-root normalisation, push-key and URL redaction | `src/push/urls.rs:validate_push_gateway_url`, `:validate_webpush_endpoint_allowlist`, `:redact_push_key`, `:redact_url`, `:try_station_api_url` | `push::urls::tests` (5): `url_builder_accepts_origin_or_api_root`, `rejects_non_loopback_http_push_gateway_url`, `allows_loopback_http_push_gateway_when_enabled`, `rejects_query_secret_in_push_gateway_url`, `rejects_insecure_webpush_endpoint_when_url_is_present`; `push::urls::redaction_tests::only_registered_push_key_schemes_are_exposed`, `::wildcard_host_pattern_excludes_the_bare_domain` |
| Typed error classification over the RFC 9457 problem envelope and the wire reason codes | `src/push/errors.rs:PushErrorKind`, `:PushRegistrationError`, `:classify_http_error`, `:PushErrorKind::from_failure_reason_code` | `push::errors::tests` (6): `classifies_error_codes`, `from_failure_reason_code_covers_contract`, `historical_only_code_classifies`, `historical_only_maps_200`, `maps_410_gone_status`, `ordinals_are_unique_and_fit_retry_mask` |
| Station-only async register / unregister client, session-grant header policy, idempotency key generation, response-size cap | `src/push/client/core.rs:ArkretPushClient`, `src/push/client/transport.rs:ArkretHttpOutcome` | `push::client::tests`, notably `default_register_rejects_without_session_grant`, `default_register_allows_with_session_grant_header`, `default_unregister_rejects_without_session_grant`, `register_success_exposes_response_context_and_headers`, `unregister_success`, `unregister_not_found_is_not_a_station_success`, `register_no_content_is_not_a_station_typed_success`, `rejects_oversized_response_before_json_decode`, `invalid_success_schema_is_invalid_response` |
| Retry curve, `Retry-After` honouring, per-error-kind retry suppression | `src/push/client/retry.rs:PushRetryPolicy` (curve delegated to `arkret_retry::RetryPolicy`) | `push::client::tests::retries_429_and_honors_retry_after`, `::retries_503`, `::does_not_retry_duplicate_conflict`, `::disabled_kinds_skip_otherwise_retryable_error` |
| Credential hygiene: zeroize-on-drop bearer material, redacted `Debug` for errors and problem extensions | `src/push/client/secret.rs:SecretString` | `push::client::tests::bearer_token_is_redacted_in_debug_output`, `::error_debug_redacts_problem_detail_and_extensions`, `::exposes_non_json_error_body_without_debug_leak` |
| Local persisted registration state keyed by the complete `AccountId`, with an opaque push-key hash instead of the token | `src/state/model.rs:PushRegistrationState`, `:build_registration_state`, `:hash_push_key` | `state::model::tests::builds_registration_state_from_success`, `::hashes_push_key_without_exposing_value`, `::same_principal_station_registrations_remain_distinct_and_private`; doctest `src/state/model.rs` line 40; `tests/property.rs:hash_push_key_is_deterministic_and_opaque` |
| Client-side notification rule chain: first-match evaluation, kind priority, unsupported-feature rejection, blind-wakeup requirement for unresolved E2EE rules | `src/rules.rs:evaluate_notification`, `:parse_push_rules` | `rules::tests::first_matching_rule_wins`, `::rule_kind_priority_precedes_document_order`, `::server_locus_user_rule_is_rejected_as_unsupported_feature`, `::malformed_rules_are_not_reported_as_unsupported_feature`, `::rejected_rules_do_not_borrow_authority_from_the_coarse_watch_gate`, `::unresolved_e2ee_client_rule_requires_blind_wakeup` |
| DND document parsing: canonical closed document, current tzdb pin, half-open and cross-midnight periods, all-day exclusivity | `src/rules.rs:parse_dnd_settings`, `:DND_TZDB_VERSION` | `rules::tests::dnd_requires_closed_canonical_document_and_current_tzdb`, `::dnd_periods_use_half_open_and_cross_midnight_semantics`, `::dnd_all_day_is_explicit_and_cannot_mix_with_periods`, `::dnd_rejects_ambiguous_or_noncanonical_period_sets` |
| Downstream-shape smoke against the inkson client flow | `tests/inkson_integration_smoke.rs` | `chime_client_requires_session_grant_before_inkson_can_register`, `inkson_style_fcm_and_apns_tokens_build_chime_register_requests` |
| README quick-start examples compiled as doc-tests | `src/lib.rs:readme_doctest` | `src/lib.rs` readme doctests at lines 144, 176, 218 |

No capability in this repository is a no-op, an empty body, or a signature
without logic. Every public function listed above has at least one test that
asserts on its result rather than on the fact that it returned.

## Removed as complete old-protocol units

Verified against `git log`/`git show` for this repository's migration round
(`76688d6` .. `c12929b`, 2026-08-30 .. 2026-09-16).

- `PushErrorKind::DeliveryBindingStale` and
  `PushErrorKind::DeliveryBindingHandedOver`, their `ErrorCode` mappings
  (`DELIVERY_BINDING_STALE`, `DELIVERY_BINDING_HANDED_OVER`), their retry-mask
  ordinals 19 and 20, the `delivery_binding_and_historical_only_codes_classify`
  test and the README bullet that documented them (`f8d65b6`). Both codes meant
  "the federation sender used an obsolete member delivery-binding **frontier**",
  and the stale variant's documented response payload was
  `new_recipient_id` + `handover_frontier`. A frontier is not an object in the
  authority-commit protocol, so there is nothing for a consumer to resolve and
  retry against; the whole error category, not just its name, is gone. The
  ordinal comment now explicitly preserves `HistoricalOnly` at 21 so the retry
  bitmask does not silently renumber.
- The "Principal Server" role name in the crate docs, the README and the
  architecture diagram (`76688d6`). The role is `Station`; keeping the old
  name would leave the library describing a service that the protocol no longer
  defines.
- The local error envelope and its hand-rolled decoding (`33d3057`). Error
  responses are the RFC 9457 `Problem` from `arkret_wire`; a second envelope in
  chime was a second source of truth for the same wire object.

## Migrated mixed areas, with the evidence

- `src/push/errors.rs`: the classification surface stayed whole — HTTP status
  mapping, the retry bitmask, the redacted `Debug` and every non-delivery-binding
  kind. Only the two delivery-binding kinds were cut, and the ordinal table kept
  its numbering so no other kind moved. `ordinals_are_unique_and_fit_retry_mask`
  is the guard.
- `src/state/model.rs` and `src/push/wire.rs`: local registration metadata kept
  its shape but `principal_id: String` became `account_id: Option<AccountId>`
  (`7bc9678`). The reason is a protocol invariant, not tidiness: a principal is
  only identified together with its Station, so a state file keyed on the
  principal alone merged two different registrations. `state::model::tests::
  same_principal_station_registrations_remain_distinct_and_private` is the
  regression that fails if that is undone.
- `src/push/registration.rs` and `src/push/wire.rs`: the register request kept
  every field it had and gained an explicit `visible_notification_opt_in`
  (`4b82c95`). Consent is registration state the Station must be told, not a
  default the Gateway may assume; `visible_notification_opt_in_is_explicit_
  registration_state` pins it.
- `src/push/client/retry.rs`: the retry capability stayed; the curve moved to
  `arkret_retry::RetryPolicy` so chime no longer owns a second backoff ladder.
- `src/rules.rs`: the rule engine and DND evaluator were untouched by this
  round. They are client-side, operate on the decrypted document, and have no
  protocol coupling.

## Verification gates

Every result below was produced on this machine during this task. Commands were
run from `D:\Works\arkret-org\chime`.

| Command | Result |
|---|---|
| `cargo test --all-features --no-fail-fast` | **80 passed, 0 failed, 0 ignored.** Breakdown: 69 unit tests (`src/`), 2 in `tests/inkson_integration_smoke.rs`, 3 in `tests/property.rs`, 6 doc-tests. |
| module reachability self-check | 1 crate, 4 crate roots (`src/lib.rs`, `examples/desktop-tauri.rs`, `tests/inkson_integration_smoke.rs`, `tests/property.rs`); **20 `.rs` files on disk under `src/`, `tests/`, `examples/`; 20 reachable by walking `mod` from those roots; 0 orphans.** The walk resolves `#[path]` attributes and nested inline `mod` blocks, and treats every integration-test file as a crate root (so `tests/common`-style helpers are not falsely reported). No file in this repository is excluded from compilation. |
| residue scan (`git grep -i` for `Seal`, `Cell`, `CBS`, `ControlProposal`, `frontier`, `lattice`, `RHRK`, `history_secret`, `policy_root`, `state_root`, `actor_seq`, `encryption_floor`, `governance_profile`, `security_frontier`, `ordinary_authoring`, `Legacy`, `Deprecated`) | **Zero hits for every term.** The only match in the whole scan is the ordinary English word "retired" in three places — `README.md:313` and `src/push/errors.rs:32` describe HTTP 410, where the *push token* has been retired by the provider, and `src/push/errors.rs:73` is the comment that keeps `HistoricalOnly` at ordinal 21. None is protocol vocabulary. |
| `cargo fmt` | Not run. `--all` reaches into the sibling `arkret-rust-sdk` path-dependency checkout, which other agents are editing concurrently; a formatting write there was out of scope for this task. |

`cargo test` above compiles `arkret-canonical`, `arkret-identifiers`,
`arkret-wire`, `arkret-models-crypto`, `arkret-models-identity`,
`arkret-models-discovery`, `arkret-models-integration`, `arkret-push-policy` and
`arkret-retry` from the sibling SDK checkout, so the green run is also a check
that chime's SDK surface usage is current.

## External blockers

None outstanding for chime itself.

One environmental note, recorded because it affects reproducibility rather than
correctness: the sibling `arkret-rust-sdk` checkout is being edited by other
agents in parallel, and a first attempt at the test run above was stopped by
three errors in `crates/models-identity/src/signer_key_operations.rs`
(`validate_for_selector` missing on `ResolvedSignerKey`, and
`SignerKeyQueryOutcome::selector` used as a field at lines 278 and 308). That is
SDK-internal and was fixed upstream without any change here; the retry produced
the 80/0 above. The SDK tree went red twice more later in the session
(`crates/signatures/src/detached_object.rs`, then
`crates/http-client/src/endpoints/events.rs`), but neither crate is in chime's
dependency graph. Nothing in chime, and nothing in the SDK, was modified to
obtain this result.
