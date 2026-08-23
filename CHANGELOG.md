# Changelog

## [Unreleased]

### Removed

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
  `error_envelope()` / `request_id()` / `retry_after()` cover the same
  surface).
- Drop the dead `base64`, `arkret-signatures`, and
  `arkret-models-discovery` dependencies.
- Drop the `sha2` dependency; idempotency-key derivation now goes through
  `arkret_canonical::sha256_hex_from_slices` like every other digest in
  the crate.

### Changed

- Align the active protocol target to `arkret-spec @ 5d66aeb`.
- Push discovery is host-owned; floria's product-local
  `floria_bridge_describe()` remains the bridge-contract adapter.

### Fixed

- Keep CI, documentation, and examples aligned with MSRV 1.97.
