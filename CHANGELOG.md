# Changelog

## [Unreleased]

### Removed

- Remove client-side Gateway `ServiceDescribe` fetching. Register/unregister
  clients are Station-only; Gateway URLs remain request fields.
- Drop the request-signing surface (`PushRequestSigningContext`,
  `PushRequestSigningOptions`, `content_digest_sha256`, `NonceTracker`,
  the signing-context builders, and the signed-header constants): the
  register/unregister face is bearer + session grant per the spec
  security scheme, and notify-direction signing lives in soland/floria.
- Drop the unconsumed `PushRoute` model, the storage trait surface
  (`PushPreferencesStore`, `PushRegistrationStore`,
  `MemoizingPushPreferencesStore`), token-rotation and repair planning,
  the platform app-id resolver traits, the `WatchLevel` rule-core
  re-export shim, the AKP-0010 mirror variants on `PushErrorKind`, and
  the unused `ArkretPushClient` methods (`server_describe`,
  `floria_integration_*`, config-driven register/unregister,
  `register_device_all`, `rotate_token`, path/default-header setters).
- Drop the unconsumed `ArkretPushClient::floria_bridge_describe_with_context`
  metadata variant (`floria_bridge_describe()` remains) and the unused
  `PushRegistrationError::status()` accessor (`kind()` plus
  `request_id()` / `retry_after()` cover the same surface).
- Drop the unused `PushRetryPolicy::conservative()` preset, the
  `ArkretPushClient::with_retry_policy` builder, and
  `PushRegistrationError::error_envelope()`.
- Drop the never-written `PushRegistrationState.refresh_hint` /
  `last_error` fields together with the `PushRegistrationLastError`
  struct.
- Drop the dead `base64`, `arkret-signatures`, and
  `arkret-models-discovery` dependencies.
- Drop the `sha2` dependency; idempotency-key derivation now goes through
  `arkret_canonical::sha256_hex_from_slices` like every other digest in
  the crate.

### Changed

- Reject unregister `404` instead of manufacturing local success, and require
  register success to decode the Station's typed outcome (`204` is not enough).
- Align the active protocol target to `arkret-spec @ 5d66aeb`.
- Push discovery is host-owned; floria's product-local
  `floria_bridge_describe()` remains the bridge-contract adapter.

### Fixed

- Keep CI, documentation, and examples aligned with MSRV 1.97.
