# yougen ↔ chime integration

This document maps the surface yougen needs from chime so the two crates
can be wired without re-deriving the contract every release. It is
deliberately implementation-focused: the goal is "what does yougen pass
into chime, and what does it get back".

## Push-token shape mapping

yougen receives raw push tokens from the host platform's push subsystem
(or its UnifiedPush distributor on platforms without a vendor push) and
forwards them to chime as a `push_key` string plus a `PushPlatform`
enum value. The string carries its own scheme prefix so the gateway
side never has to guess.

| yougen `Platform`                       | Vendor / transport            | `push_key` prefix       | `chime::PushPlatform` |
| --------------------------------------- | ----------------------------- | ----------------------- | --------------------- |
| `Platform::Android`                     | Firebase Cloud Messaging      | `fcm:<opaque-token>`    | `PushPlatform::Android` |
| `Platform::Android` (degooglified)      | UnifiedPush distributor       | `unifiedpush:<endpoint>`| `PushPlatform::Android` |
| `Platform::Ios`                         | Apple Push Notification svc   | `apns:<hex-token>`      | `PushPlatform::Ios`     |
| `Platform::Macos`                       | UnifiedPush bridge / desktop  | `unifiedpush:<endpoint>`| `PushPlatform::Desktop` |
| `Platform::Linux`                       | UnifiedPush distributor       | `unifiedpush:<endpoint>`| `PushPlatform::Desktop` |
| `Platform::Windows`                     | UnifiedPush bridge            | `unifiedpush:<endpoint>`| `PushPlatform::Desktop` |
| `Platform::Web`                         | Web Push (RFC 8030)           | `unifiedpush:<endpoint>`| `PushPlatform::Web`     |

Notes:

- The `fcm:` / `apns:` / `unifiedpush:` prefix is the gateway's primary
  routing signal. chime's `PushRouteId` validators (see
  `chime/src/push_route.rs`) enforce that the scheme matches an
  expected transport — yougen MUST NOT strip it.
- The `PushPlatform` enum currently has four variants: `Android`,
  `Ios`, `Web`, `Desktop`. `Linux` / `macOS` / `Windows` all collapse
  into `Desktop`. yougen keeps the finer-grained `Platform` for its own
  telemetry but downgrades when calling chime.
- Web Push endpoints SHOULD be wrapped in `unifiedpush:` rather than a
  bare HTTPS URL so the gateway router treats them as the same
  transport family as desktop UnifiedPush.

## `spec_version` alignment

chime exposes the compiled-in protocol version as
`chime::EXPECTED_SPEC_VERSION` (current value pinned in
`chime/src/push/bridge_describe.rs`). The push bridge's
`PushBridgeDescribeOutcome::spec_version` field carries whatever the
deployed gateway advertises; the SDK provides
`warn_on_spec_version_mismatch()` so drift surfaces in logs without
crashing existing devices.

yougen's smoke-test harness MUST:

1. Call `bridge_describe()` against the target gateway.
2. Compare the returned `spec_version` to
   `chime::EXPECTED_SPEC_VERSION`.
3. Fail the smoke test if the two differ — gateway drift is the most
   common cause of "registrations succeed but notifications never
   arrive" bugs and is cheap to catch up-front.

The crate-level audited spec target is `cokret-spec @ cced4b8`; older
SHAs in changelog history are retained only as round-by-round audit
records.

## chime APIs yougen calls

These are the only public chime entry points the yougen integration
needs. Anything else is implementation-detail and may move between
releases.

- `chime::build_register_device_request(&device_config, &binding, &prefs)`
  — assembles the canonical `RegisterDeviceRequest` from the
  yougen-side device descriptor, the gateway binding (account/route
  binding cached locally), and the user's notification preferences.
  Returns a request struct the caller serialises via the chime HTTP
  client (or hands off to whatever transport yougen prefers).
- `chime::build_unregister_device_request(...)` — symmetric tear-down call
  for device deregistration / sign-out flows.
- `chime::PushNotificationDedup::from_descriptor(&notify_descriptor)`
  — constructs the dedup key used to suppress duplicate notification
  deliveries. yougen's local-notification scheduler MUST run every
  inbound push through this helper before raising a system
  notification; otherwise re-delivered pushes (common on flaky
  cellular) appear twice in the user's tray.
- `chime::call_media_token_exchange(...)` plus
  `chime::structurally_validate_media_token_response(&response, &ctx)`
  — builds and structure-checks a `ck.self.call.media.token_exchange`
  response. The validation context type is
  `MediaTokenStructuralValidationContext`, and success returns
  `StructurallyValidatedMediaTokenOutcome`. This marker means only
  issuer-anchor, tuple, and TTL checks passed; yougen MUST verify
  `service_signature` and `participant_binding.sig` with the realm
  media-service Ed25519 key before SFrame keying.

## `BackgroundFetchDriver` integration

chime's lifecycle module exposes a `BackgroundFetchDriver` trait
(`chime/src/lifecycle.rs`) that the host app implements to plumb
background fetches into the platform's background-task scheduler. The
trait surface:

- `dispatch_background_fetch(&self, hint)` — invoked by chime when an
  inbound push carries a `BackgroundFetchHint`. The host returns a
  `BackgroundFetchOutcome` (success / deferred / failed) so chime can
  decide whether to ack the push.
- `NoopBackgroundFetchDriver` — the stock no-op implementation. yougen
  ships this by default on platforms where there is no
  background-fetch scheduler (current Linux desktop builds), and swaps
  it out per-platform as the integrations land:
  - iOS: `BGTaskScheduler` bridge.
  - Android: `WorkManager` bridge.
  - Desktop UnifiedPush: best-effort foreground fetch (still a noop
    today; tracked in the platform stub roadmap).

The driver is stashed in an `Arc<dyn BackgroundFetchDriver<Error = _>>`
on the chime lifecycle, so yougen can hand chime a single shared
instance at boot and let chime route hints to it from any thread.
