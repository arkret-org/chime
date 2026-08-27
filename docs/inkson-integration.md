# inkson ↔ chime integration

This document maps the surface inkson needs from chime so the two crates
can be wired without re-deriving the contract every release. It is
deliberately implementation-focused: the goal is "what does inkson pass
into chime, and what does it get back".

## Push-token shape mapping

inkson receives raw push tokens from the host platform's push subsystem
(or its UnifiedPush distributor on platforms without a vendor push) and
forwards them to chime as a `push_key` string plus a `PushPlatform`
enum value. The string carries its own scheme prefix so the gateway
side never has to guess.

| inkson `Platform`                       | Vendor / transport            | `push_key` prefix       | `chime::PushPlatform` |
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
  routing signal — inkson MUST NOT strip it.
- The `PushPlatform` enum currently has four variants: `Android`,
  `Ios`, `Web`, `Desktop`. `Linux` / `macOS` / `Windows` all collapse
  into `Desktop`. inkson keeps the finer-grained `Platform` for its own
  telemetry but downgrades when calling chime.
- Web Push endpoints SHOULD be wrapped in `unifiedpush:` rather than a
  bare HTTPS URL so the gateway router treats them as the same
  transport family as desktop UnifiedPush.

## Push gateway discovery

The deployed gateway publishes canonical `ServiceDescribe`; fetch it via
`service_describe()` at `/_arkret/describe`.

inkson's smoke-test harness MUST call `service_describe()` and fail when
validation fails, the role is not `push_gateway`, or the canonical notify
operation bundle is absent. SDK/artifact digests belong in generated CI evidence,
not in this hand-maintained guide.

## chime APIs inkson calls

These are the only public chime entry points the inkson integration
needs. Anything else is implementation-detail and may move between
releases.

- `chime::build_register_device_request(&device_config, &binding, &prefs)`
  — assembles the canonical `RegisterDeviceRequest` from the
  inkson-side device descriptor, the gateway binding (account/route
  binding cached locally), and the user's notification preferences.
  Returns a request struct the caller serialises via the chime HTTP
  client (or hands off to whatever transport inkson prefers).
- `chime::build_unregister_device_request(...)` — symmetric tear-down call
  for device deregistration / sign-out strands.
