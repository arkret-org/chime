# chime

> **Stability:** `0.x`. Within a `0.x` minor release, the public surface evolves
> additively — new optional fields, new enum variants, new helper methods. Renames
> and removals require bumping the minor (`0.x → 0.x+1`). Response wire types
> (`RegisterDeviceResponse`, `UnregisterDeviceResponse`, `ContrixErrorEnvelope`)
> carry `#[non_exhaustive]` so server-driven field additions do not break
> downstream consumers.

Contrix push notification gateway types, preferences, and device registration helpers.

**chime** provides shared data types and request-building logic for Contrix clients that need to register push-capable devices with a Principal Server, Sync Service, or delegated Push Gateway.

## Gateway Support

| Gateway | Description |
| --- | --- |
| **Standard** | Contrix Push Gateway using platform adapters such as FCM, APNs, Web Push, or desktop notification bridges. |
| **Bugle** | Contrix Push Gateway with domestic Chinese Android OEM provider support through JPush, Huawei, Xiaomi, OPPO, vivo, HONOR, and HarmonyOS routes. |
| **Custom** | User-provided gateway URL for self-hosted or third-party gateways. |

## Features

| Feature | Description |
| --- | --- |
| _(default)_ | Core types, JSON serialization helpers, and Contrix register/unregister request builders. No network dependencies. |
| `http` | Adds `ContrixPushClient`, a small `reqwest` helper for `POST /api/v1/push/register-device` and `POST /api/v1/push/unregister-device`. |
| `notify` | Adds server/gateway-side `cx.push.notify` wire types and blind-wakeup privacy validation. |

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
chime = "0.1"
# or with Contrix HTTP registration and gateway notify wire types:
# chime = { version = "0.1", features = ["http"] }
# chime = { version = "0.1", features = ["http", "notify"] }
```

In-tree workspace consumers can also pull a path dependency:

```toml
chime = { path = "../chime", features = ["http"] }
```

### Core types

```rust
use chime::{PushGatewayType, PushPreferences};

let mut prefs = PushPreferences {
    enabled: true,
    gateway_type: PushGatewayType::Bugle,
    ..Default::default()
};
prefs.apply_gateway_type_defaults();

let app_id = prefs.app_id(
    Some(chime::PushPlatform::Android),
    Some("app.example.android"),
    Some("app.example.android.cn"),
);
assert_eq!(app_id, Some("app.example.android.cn"));

let json = chime::to_json(&prefs).unwrap();
let loaded = chime::from_json(&json).unwrap();
assert_eq!(loaded.gateway_type, PushGatewayType::Bugle);
```

### Build a Contrix registration body

```rust
use chime::{PushDeviceConfig, PushPreferences, build_register_device_request};

let config = PushDeviceConfig {
    principal_did: Some("did:web:alice.example"),
    device_id: "did:web:alice.example#device-phone",
    push_key: Some("fcm-or-apns-device-token"),
    platform: Some("android"),
    app_id: Some("app.example.android"),
    domestic_app_id: Some("app.example.android.cn"),
    registration_id: None,
    display_name: Some("Alice Phone"),
    idempotency_key: Some("device-phone-register-v1"),
    request_id: Some("cx:req:01JS0KE000000000000000000"),
    proof: None,
};

let prefs = PushPreferences {
    enabled: true,
    push_gateway: "https://push.example.com/api/v1/push/notify".to_owned(),
    ..Default::default()
};

let request = build_register_device_request(&config, &prefs).unwrap();
assert_eq!(request.device_id, "did:web:alice.example#device-phone");
```

### Register through HTTP

```rust,ignore
use chime::{ContrixPushClient, PushDeviceConfig, PushPreferences};

let client = ContrixPushClient::new("https://principal.example")
    .with_bearer_token("session-token")
    .with_timeout(std::time::Duration::from_secs(10))
    .with_retry_policy(chime::PushRetryPolicy::conservative())
    .with_default_request_id("cx:req:01JS0KE000000000000000000");

let response = client.register_device_with_context(&config, &prefs).await?;
assert!(response.body.ok);
```

Production notes:

- Authentication material is only sent through headers. Do not put session tokens, API keys, signatures, or bearer tokens in `push_gateway` query strings.
- `push_gateway` must be HTTPS unless `allow_insecure_loopback_push_gateway` is enabled for localhost development.
- WebPush registrations can set `webpush_endpoint_allowlist` to restrict accepted endpoint origins or host patterns before a browser endpoint is sent to the service.
- `push_key` is redacted in debug output and logs; callers should still store it as a secret.
- `ContrixPushClient` retries only safe idempotent requests: register calls need an idempotency key, while unregister is treated as idempotent. `Retry-After` is honored before exponential backoff plus bounded jitter.
- `allow_push_hint` only permits body-free wakeup hints. It does not permit plaintext message bodies for E2EE Spaces.

### Request signing helpers

`chime` does not own authentication secrets or private keys. Callers can build a canonical proof body or HTTP Message Signature headers from the request they are about to send:

```rust,ignore
use chime::{
    PushRequestSigningOptions, build_register_device_request,
    build_register_signing_context_with_options,
};

let request = build_register_device_request(&config, &prefs)?;
let context = build_register_signing_context_with_options(
    "https://principal.example",
    &request,
    PushRequestSigningOptions::new("2026-04-29T00:00:00Z", "https://principal.example")
        .with_actor_did("did:web:alice.example")
        .with_expires_at("2026-04-29T00:05:00Z")
        .with_origin("https://app.example")
        .with_origin_service_did("did:web:sync.example.com")
        .with_destination_service_did("did:web:principal.example")
        .with_nonce("device-phone-register-v1")
        .with_idempotency_key("device-phone-register-v1")
        .with_session_grant("externally-issued-coauth-or-soland-grant"),
)?;

let proof_body = context.canonical_proof_body()?;
let signature = signer.sign_http_message(&context)?;
let headers = context.http_message_signature_headers("sig1", &signature)?;
```

`proof_body` is caller-signed and passed back through `PushDeviceConfig::proof`. The returned HTTP signature headers include `Content-Digest`, Contrix device/audience/actor/expiry/origin/destination metadata, nonce/idempotency context, `Signature-Input`, and `Signature`; attach them with your HTTP stack or `ContrixPushClient::with_header`. `chime` can carry an externally supplied coauth/soland grant, but it never owns private keys or mints grants.

### Local registration state

`PushRegistrationState` stores non-secret local state: principal DID, device id, platform/app id, gateway, token hash/preview, registration id, expiry/refresh hint, and last success/error summary. The `PushRegistrationStore` trait keeps the legacy single-registration methods and adds multi-registration defaults (`load_push_registrations`, `save_push_registrations`, and `delete_push_registration`) for apps that store several accounts, apps, or devices.

Store implementations should use OS keychain, encrypted app storage, or another locally protected store. The state includes `schema_version` so applications can migrate persisted records without exposing raw platform tokens.

After a successful register, `merge_registration_state()` drops stale logical duplicates and same-token records that were left behind on another device entry. When a client needs to recover from partial failures or stale local storage, `plan_registration_repair()` produces the unregister/register work needed to reconcile old token state with the current device token.

### Token rotation

```rust,ignore
use chime::{plan_token_rotation_with_strategy, PushRegistrationState, PushTokenRotationStrategy};

let existing: Option<PushRegistrationState> = store.load_push_registration()?;
let plan = plan_token_rotation_with_strategy(
    existing.as_ref(),
    &config,
    &prefs,
    PushTokenRotationStrategy::RegisterNewFirst,
)?;

if let Some(register_new) = plan.register_new {
    // Send with ContrixPushClient or your own HTTP stack, then persist success.
}
if let Some(unregister_old) = plan.unregister_old {
    // For RegisterNewFirst, send this after the replacement succeeds.
}
```

## Configuration & Operations

`chime` is a library, not a service — it has no daemon, no config file
of its own, and no environment variables it reads. Operational concerns
live entirely in the host application that wires `ContrixPushClient`
into a Contrix Principal Server / Sync Service deployment.

### Build profile

| Knob | Value | Note |
| ---- | ----- | ---- |
| MSRV | `1.89` | Enforced by CI; bump only with a minor release. |
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
  them in `push_gateway` query strings is rejected.
- **Session grant fail-closed.** `ContrixPushClient::new(...)` defaults
  to `with_required_session_grant(true)`. Always attach
  `X-Contrix-Session-Grant` via `with_session_grant("...")` (or
  `with_header(...)`) before calling register/unregister. Dev sandboxes
  that need to skip this can flip the flag.
- **Idempotency.** If you do not provide an idempotency key, the
  client generates one and reuses it across retries. Persist your own
  key for server-side dedup if you care about cross-process
  deduplication.
- **Retries.** Default `PushRetryPolicy::disabled()`. Use
  `PushRetryPolicy::conservative()` for `429`/`503`/network-timeout
  retries with `Retry-After` honoring and bounded jitter.
- **Token storage.** Implement `PushRegistrationStore` over an OS
  keychain, encrypted app storage, or another locally protected store.
  Never log raw `push_key`; the crate redacts it in `Debug` impls and
  tracing fields, and you should mirror that in your own code.
- **Privacy gate.** When you build the `notify` feature into a
  gateway, validate every outbound payload through
  `PushNotifyRequest::assert_payload_safe(&policy)`. Empty
  `PushNotifyPolicyContext` means every notification is treated as
  blind wakeup, which is the safest default.

### Observability

`chime` emits `tracing` events with the target prefix `chime`:

```text
INFO  chime::push::client  Contrix push device registered  platform=android gateway="Contrix Standard" operation_id=cx.push.register_device request_id=cx:req:01JS0KE000000000000000000
```

Subscribe with any `tracing-subscriber` layer; Sentry / OpenTelemetry
exporters work without further glue.

### Troubleshooting

| Symptom | Likely cause |
| ------- | ------------ |
| `MissingField("session_grant")` returned before any HTTP request | `with_required_session_grant(true)` is on but no `X-Contrix-Session-Grant` header is attached. |
| `InvalidPushGatewayUrl { reason: "scheme must be https" }` | HTTP push gateway URL in production. Allow loopback only if you're testing locally. |
| `WebPushEndpointNotAllowed` | The browser-issued endpoint origin is not in `webpush_endpoint_allowlist`. Add the origin or host pattern. |
| `Gone` (HTTP 410) | The push token was retired. Drop the local registration and let the device generate a new token before re-registering. |
| `Unauthenticated` after token refresh | The bearer token rotated mid-request. Refresh `with_bearer_token(...)` and retry. |

## Migration from legacy Matrix pusher terms

| Legacy term | Contrix term |
| --- | --- |
| `matrix` feature | `http` feature |
| `PusherConfig` | `PushDeviceConfig` |
| `register_pusher` | `ContrixPushClient::register_device` or `build_register_device_request` |
| `unregister_pusher` | `ContrixPushClient::unregister_device` or `build_unregister_device_request` |
| `gateway_url` | `push_gateway` |
| `show_message_preview` | `allow_push_hint` |

Use these direct renames when migrating persisted config or API payloads. Strict parsers and validators no longer accept legacy alias fields.

## Protocol Mapping

The crate maps to the Contrix v1 push HTTP binding:

| Operation ID | HTTP Binding | Request builder |
| --- | --- | --- |
| `cx.push.register_device` | `POST /api/v1/push/register-device` | `build_register_device_request()` |
| `cx.push.unregister_device` | `POST /api/v1/push/unregister-device` | `build_unregister_device_request()` |
| `cx.push.notify` | `POST /api/v1/push/notify` | Gateway/server-side operation, not a client registration call. |

Register/unregister bodies carry the canonical operation id, optional `principal_did`, `device_id`, app id, gateway URL, idempotency key, request id, and caller-supplied proof. Responses expose the accepted gateway, token hash/preview, expiry or refresh hints, warnings, and request id when the service returns them.

Push notifications are derived wakeups, not canonical truth. For E2EE Spaces, push gateways should receive only minimized metadata such as `space_id`, event type, counts, target device references, priority/TTL/collapse hints, and optional body-free `push_hint`.

With the `notify` feature, `PushNotifyRequest::validate_wire_model()` and `PushNotifyRequest::validate_blind_wakeup()` enforce that boundary. Entity facets and view-renderer output are routing or context hints only when the application has explicitly authorized that use; do not serialize facet-derived title, body, display name, or space name into provider payloads. The validator rejects removed legacy `room` / `card` / `subject` references, `schema_id` / `kind` aliases, `sender_service_did`, provider payload wrappers, title/body/preview fields, and facet/view-renderer extension keys before gateway delivery.

`shared_push_notify_privacy_vectors()` exposes the E2EE invalid cases, including legacy-reference rejections, and the explicit plaintext-visible service allow case so gateway implementations such as `floria` can run the same vectors.

## Architecture

```text
Contrix Client
        |
        v
   +---------+     PushPreferences
   |  chime  | --> PushGatewayType { Standard, Bugle, Custom }
   +----+----+     build_register_device_request()
        |          ContrixPushClient (optional)
        v
Principal Server / Sync Service
        |
        v
Contrix Push Gateway
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
