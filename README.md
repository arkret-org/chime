# chime

[![coverage](https://img.shields.io/badge/coverage-local%20tarpaulin-informational)](docs/production-checklist.md#local-verification)

> **Stability:** v1 development phase. The public API and persisted formats
> may change aggressively without backward compatibility. Canonical outcome
> and error wire types are consumed directly from `arkret-models-integration`
> and `arkret-wire`.

Arkret push notification gateway types, preferences, and device registration helpers.

**chime** provides shared data types and request-building logic for Arkret clients that need to register push-capable devices with a Station, Sync Service, or delegated Push Gateway.

## Realm vs Space

`chime` aligns push routes with the current Realm / Space vocabulary:

- **Realm:** security boundary — membership, capability, E2EE, and federation are governed at this level. Push permission and per-realm mute apply here.
- **Space:** navigation container — board, list, section, or calendar bucket. Lives inside a Realm and inherits its security context.

## Client-SDK shape changes

Two client-SDK shape changes. See
[`CHANGELOG.md`](CHANGELOG.md) `[Unreleased]` for the chime-facing
wire-breaking list; the normative source remains `../arkret-spec/spec/v1/`.

- **`mention_redirect_target_route_tokens` recognition** — typed
  push-payload structs expose the field; consumers decide whether the
  active device route token is an authorised
  redirect target.
- **New floria-passthrough error reason codes** —
  `delivery_binding_stale` / `delivery_binding_handed_over` /
  `historical_only` join the typed reason-code surface;
  `historical_only` is annotated as diagnostic and suppresses
  user-visible notification.

## Ephemeral kinds

Ephemeral kinds (`ak.presence`, `ak.typing`, `ak.receipt.read`,
`ak.call.signal`) are confirmed not consumed by chime. See
[`CHANGELOG.md`](CHANGELOG.md) `[Unreleased]`; the normative source
remains `../arkret-spec/spec/v1/`.

## Chinese docs

简体中文接入文档见 [`zh/README.md`](zh/README.md)，包括
[`zh/integration-guide.md`](zh/integration-guide.md)、
[`zh/error-codes.md`](zh/error-codes.md) 和
[`zh/production-checklist.md`](zh/production-checklist.md)。

## Gateway Support

| Gateway | Description |
| --- | --- |
| **Standard** | Arkret Push Gateway using platform adapters such as FCM, APNs, Web Push, or desktop notification bridges. |
| **Bugle** | Arkret Push Gateway with domestic Chinese Android OEM provider support through JPush, Huawei, Xiaomi, OPPO, vivo, HONOR, and HarmonyOS routes. |
| **Custom** | User-provided gateway URL for self-hosted or third-party gateways. |

Bugle host integrations still own provider SDK setup and token
acquisition. For app-id resolution, `GatewayBinding::resolve_app_id`
and `PushGatewayType::Bugle` prefer `domestic_app_id` for Android.

## Features

| Feature | Description |
| --- | --- |
| _(default)_ | Core types, JSON serialization helpers, and Arkret register/unregister request builders. No network dependencies. |
| `http` | Adds `ArkretPushClient`, a small `reqwest` helper for `POST /_arkret/edge/push/register-device` and `POST /_arkret/edge/push/unregister-device`. |

> **Server-side `ak.edge.push.command.notify.v1` wire types are not part of
> this crate.** chime is a client SDK: it builds register/unregister
> requests and evaluates client-side push rules. Gateway implementations
> that need to validate outbound blind-wakeup payloads use the SDK's
> `arkret_push_policy::blind_payload_sanitizer` directly.

## AKP-0007 Circle subscriptions

[AKP-0007 Circle primitive](../arkret-spec/spec/v1/zh/models/circle.md)
introduces an encrypted sub-boundary inside a Realm. The security scope
of an Event lives in its producer-signed `scope_ref`; object read
projections may materialize an equal `effective_scope`. Neither name
reaches the push wire:

- **Receiving a Circle-scoped wakeup.** The push wakeup wire carries no
  Circle identifier and no scope field. Raw Realm ids, Circle ids and
  `effective_scope` MUST NOT enter `/_arkret/edge/push/notify`
  (`push-notifications.md` §5.1); the wakeup only carries opaque
  `route_tokens.scope_route_token` / `devices[].target_route_token`.
  The client resolves the security boundary from the durable Event it
  fetches after the wakeup, never from the wakeup itself. The closed SDK
  wire type rejects `circle_name` / `circle_display_name` and the
  `circle_members` / `circle_member_dids` / `circle_member_actor_ids`
  membership surfaces during deserialization.
- **Muting a Circle on this device.** Per-scope mute state lives in the
  host application, matched host-side against the scope the client
  resolved for the fetched Event — the wakeup itself cannot be matched,
  because it carries no scope. A muted scope MUST NOT raise a UI
  surface; wire-level delivery is unchanged so floria can still account
  for the receipt.

## Quick Start

`chime` is not published to a registry; consumers depend on a sibling checkout
by path. Add to your `Cargo.toml`:

```toml
[dependencies]
chime = { path = "../chime" }
# or with the Arkret HTTP registration client:
# chime = { path = "../chime", features = ["http"] }
```

### Core types

```rust
use chime::{GatewayBinding, PushGatewayType, PushPreferences};

let prefs = PushPreferences {
    enabled: true,
    gateways: vec![
        GatewayBinding::new(
            PushGatewayType::Bugle,
            "https://push.palpo.im/_arkret/edge/push/notify",
        )
        .with_app_id("app.example.android.cn"),
    ],
    ..Default::default()
};

let binding = &prefs.gateways[0];
let app_id = binding.resolve_app_id(
    Some(chime::PushPlatform::Android),
    Some("app.example.android"),
    Some("app.example.android.cn"),
);
assert_eq!(app_id, Some("app.example.android.cn"));

// `PushPreferences` is plain `serde`; persist it with whatever encoder
// the host already uses.
let json = serde_json::to_string_pretty(&prefs).unwrap();
let loaded: PushPreferences = serde_json::from_str(&json).unwrap();
assert_eq!(loaded.gateways[0].gateway_type, PushGatewayType::Bugle);
```

### Build a Arkret registration body

```rust
use chime::{
    GatewayBinding, PushDeviceConfig, PushGatewayType, PushPreferences,
    build_register_device_request,
};

let config = PushDeviceConfig {
    principal_id: Some(
        arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
    ),
    device_id: "ak:device:01904100-0000-7000-8000-000000000004",
    push_key: Some("fcm-or-apns-device-token"),
    platform: Some("android"),
    app_id: Some("app.example.android"),
    domestic_app_id: Some("app.example.android.cn"),
    registration_id: None,
    display_name: Some("Alice Phone"),
    idempotency_key: Some("device-phone-register-v1"),
    request_id: Some("ak:request:01904100-0000-7000-8000-000000000001"),
    proof: None,
};

let binding = GatewayBinding::new(
    PushGatewayType::Standard,
    "https://push.example.com/_arkret/edge/push/notify",
);
let prefs = PushPreferences {
    enabled: true,
    ..Default::default()
};

let request = build_register_device_request(&config, &binding, &prefs).unwrap();
assert_eq!(
    request.device_id,
    "ak:device:01904100-0000-7000-8000-000000000004"
);
```

### Register through HTTP

```rust,no_run
# #[cfg(feature = "http")]
# async fn doc_run() -> Result<(), chime::PushRegistrationError> {
# use chime::{GatewayBinding, PushDeviceConfig, PushGatewayType, PushPreferences};
# let config = PushDeviceConfig {
#     principal_id: None,
#     device_id: "ak:device:01904100-0000-7000-8000-000000000004",
#     push_key: Some("fcm-or-apns-device-token"),
#     platform: None,
#     app_id: None,
#     domestic_app_id: None,
#     registration_id: None,
#     display_name: None,
#     idempotency_key: None,
#     request_id: None,
#     proof: None,
# };
# let binding = GatewayBinding::new(
#     PushGatewayType::Standard,
#     "https://push.example.com/_arkret/edge/push/notify",
# );
# let prefs = PushPreferences {
#     enabled: true,
#     ..Default::default()
# };
use chime::{ArkretPushClient, build_register_device_request};

let client = ArkretPushClient::new("https://principal.example")
    .with_bearer_token("session-token")
    .with_timeout(std::time::Duration::from_secs(10))
    .with_session_grant("externally-issued-coauth-or-soland-grant")?;

let request = build_register_device_request(&config, &binding, &prefs)?;
let response = client
    .register_device_with_request(&request, None, None)
    .await?;
let _push_target_id = response.body.push_target_id;
# Ok(())
# }
```

Production notes:

- Authentication material is only sent through headers. Do not put session tokens, API keys, signatures, or bearer tokens in a binding's `push_gateway` URL query string.
- Each binding's `push_gateway` must be HTTPS unless `allow_insecure_loopback_push_gateway` is enabled for localhost development.
- WebPush registrations can set `webpush_endpoint_allowlist` to restrict accepted endpoint origins or host patterns before a browser endpoint is sent to the service.
- `push_key` is redacted in debug output and logs; callers should still store it as a secret.
- `ArkretPushClient` retries only safe idempotent requests: register calls need an idempotency key, while unregister is treated as idempotent. `Retry-After` is honored before exponential backoff plus bounded jitter.

### Local registration state

`PushRegistrationState` stores non-secret local state: principal ID, device id, platform/app id, gateway, token hash/preview, registration id, expiry, and last success timestamp. Build it from a successful register response with `build_registration_state()`.

Persistence is host-owned: store the state through an OS keychain, encrypted app storage, or another locally protected store. The state includes `schema_version` so applications can migrate persisted records without exposing raw platform tokens.

## Configuration & Operations

`chime` is a library, not a service — it has no daemon, no config file
of its own, and no environment variables it reads. Operational concerns
live entirely in the host application that wires `ArkretPushClient`
into a Arkret Station / Sync Service deployment.

### Build profile

| Knob | Value | Note |
| ---- | ----- | ---- |
| MSRV | `1.98` | Enforced by CI; bump only with a minor release. |
| TLS backend | `rustls-tls` (via reqwest) | No system OpenSSL dependency. |
| Tokio runtime | optional via `http` feature | Multi-thread or current-thread, host's choice. |
| Logging | `tracing` events on the `chime` target | No allocator on the hot path; subscribe at info-level for register/unregister breadcrumbs. |

### Production checklist

- **HTTPS only.** `validate_push_gateway_url` rejects non-HTTPS gateway
  URLs unless the host opts in by setting
  `PushPreferences::allow_insecure_loopback_push_gateway = true` for a
  loopback dev URL.
- **WebPush origins.** Set
  `PushPreferences::webpush_endpoint_allowlist` to the list of FCM /
  Apple / Mozilla origins or host patterns you accept; `*.push.services.mozilla.com`
  and `https://fcm.googleapis.com` are typical entries.
- **Auth in headers, not URLs.** Session tokens, bearer tokens, API
  keys, and HTTP message signatures must travel in headers. Putting
  them in a binding's `push_gateway` query string is rejected.
- **Session grant fail-closed.** `ArkretPushClient::new(...)` defaults
  to `with_required_session_grant(true)`. Always attach
  `X-Arkret-Session-Grant` via `with_session_grant("...")` (or
  `with_header(...)`) before calling register/unregister. Dev sandboxes
  that need to skip this can flip the flag.
- **Idempotency.** If you do not provide an idempotency key, the
  client generates one and reuses it across retries. Persist your own
  key for server-side dedup if you care about cross-process
  deduplication.
- **Retries.** The client does not retry (`PushRetryPolicy::disabled()`
  is the fixed policy); hosts that need retries wrap calls in their own
  retry loop built on `arkret_retry::RetryPolicy`, honoring `Retry-After`
  via `PushRegistrationError::retry_after_duration()`.
- **Token storage.** Persist `PushRegistrationState` in an OS
  keychain, encrypted app storage, or another locally protected store.
  Never log raw `push_key`; the crate redacts it in `Debug` impls and
  tracing fields, and you should mirror that in your own code.
- **Privacy gate.** Gateway-side payload validation is not chime's
  surface. Validate every outbound wakeup through the SDK's
  `arkret_push_policy::blind_payload_sanitizer` before it leaves the
  gateway; treating every notification as a blind wakeup is the safest
  default.

### Observability

`chime` emits `tracing` events with the target prefix `chime`:

```text
INFO  chime::push::client  Arkret push device registered (prebuilt body)  platform=android operation_id=ak.edge.push.command.register_device.v1 request_id=ak:request:01904100-0000-7000-8000-000000000001
```

Subscribe with any `tracing-subscriber` layer; Sentry / OpenTelemetry
exporters work without further glue.

### Troubleshooting

| Symptom | Likely cause |
| ------- | ------------ |
| `MissingField("session_grant")` returned before any HTTP request | `with_required_session_grant(true)` is on but no `X-Arkret-Session-Grant` header is attached. |
| `InvalidPushGatewayUrl { reason: "scheme must be https" }` | HTTP push gateway URL in production. Allow loopback only if you're testing locally. |
| `WebPushEndpointNotAllowed` | The browser-issued endpoint origin is not in `webpush_endpoint_allowlist`. Add the origin or host pattern. |
| `Gone` (HTTP 410) | The push token was retired. Drop the local registration and let the device generate a new token before re-registering. |
| `Unauthenticated` after token refresh | The bearer token rotated mid-request. Refresh `with_bearer_token(...)` and retry. |

## Protocol Mapping

The crate maps to the Arkret v1 push HTTP binding:

| Operation ID | HTTP Binding | Request builder |
| --- | --- | --- |
| `ak.edge.push.command.register_device.v1` | `POST /_arkret/edge/push/register-device` | `build_register_device_request()` |
| `ak.edge.push.command.unregister_device.v1` | `POST /_arkret/edge/push/unregister-device` | `build_unregister_device_request()` |
| `ak.edge.push.command.notify.v1` | `POST /_arkret/edge/push/notify` | Gateway/server-side operation, not a client registration call. |

Register/unregister builders carry the canonical operation id, optional `principal_id`, `device_id`, app id, gateway URL, idempotency key, request id, and caller-supplied proof. Register responses expose only the spec response body fields (`ok`, `registration_id`, and `expires_at`); response headers carry transport metadata such as request id.

Push notifications are derived wakeups, not canonical truth. For E2EE Realms, push gateways should receive only minimized metadata such as `push_target_id`, `wakeup_kind`, counts, priority/TTL/collapse hints, and optional body-free `push_hint`.

The SDK-owned notify wire model enforces that boundary on the gateway side. Entity facets and view-renderer output are routing or context hints only when the application has explicitly authorized that use; do not serialize facet-derived title, body, display name, or space name into provider payloads. The closed SDK model rejects unknown aliases and provider wrappers during deserialization.

## Architecture

```text
Arkret Client
        |
        v
   +---------+     PushPreferences { gateways: Vec<GatewayBinding> }
   |  chime  | --> GatewayBinding { gateway_type, push_gateway, push_key, app_id }
   +----+----+     build_register_device_request(config, binding, prefs)
        |          ArkretPushClient (optional)
        v
Station / Sync Service
        |
        v
Arkret Push Gateway
        |
        +-- FCM / APNs / Web Push / Desktop
        +-- Bugle domestic providers:
            +-- JPush
            +-- Huawei / HarmonyOS
            +-- Xiaomi
            +-- OPPO / OnePlus
            +-- vivo
            +-- HONOR
```

## License

Licensed under Apache 2.0. See [LICENSE](LICENSE).
