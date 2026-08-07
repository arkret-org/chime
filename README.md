# chime

> **Spec target**: [arkret-spec @ 074aefee](../arkret-spec) (sync 2026-06-23)

[![coverage](https://img.shields.io/badge/coverage-local%20tarpaulin-informational)](docs/production-checklist.md#local-verification)

> **Stability:** local `1.0.0` freeze candidate. Breaking public API changes
> now require a major-version bump. Outcome wire types
> (`PushRegisterDeviceOutcome`, `PushUnregisterDeviceOutcome`, `ArkretErrorEnvelope`)
> carry `#[non_exhaustive]` so server-driven field additions do not break
> downstream consumers.

Arkret push notification gateway types, preferences, and device registration helpers.

**chime** provides shared data types and request-building logic for Arkret clients that need to register push-capable devices with a Principal Server, Sync Service, or delegated Push Gateway.

## Realm vs Space

`chime` aligns push routes with the current Realm / Space vocabulary:

- **Realm:** security boundary — membership, capability, E2EE, and federation are governed at this level. Push permission and per-realm mute apply here.
- **Space:** navigation container — board, list, section, or calendar bucket. Lives inside a Realm and inherits its security context.

## Round R4 (protocol review closures)

Spec round 4 adds two client-SDK shape changes. See
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

## Round R2/R3 notes

Spec rounds 2+3 (2026-05-20) added the `lifecycle::on_account_deactivate`
host integration hook (T07 — 4-step local push cleanup) and the
`ROUND_R2_R3_SENSITIVE_FIELDS` defense-in-depth list that mirrors floria's
blind-wakeup forbidden-field surface. Ephemeral kinds (`ak.presence`,
`ak.typing`, `ak.receipt.read`, `ak.call.signal`) are confirmed not
consumed by chime. See [`CHANGELOG.md`](CHANGELOG.md) `[Unreleased]`;
the normative source remains `../arkret-spec/spec/v1/`.

## Protocol Baseline

The current audited protocol pin for this crate is
`arkret-spec @ 5d66aeb`; older SHAs in `CHANGELOG.md` are historical
round entries, not the active completion gate.

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
and `PushGatewayType::Bugle` prefer `domestic_app_id` for Android;
hosts that need the standalone resolver trait can use
`chime::bugle::BugleAppIdResolver` or provide their own
`PlatformAppIdResolver`.

## Features

| Feature | Description |
| --- | --- |
| _(default)_ | Core types, JSON serialization helpers, and Arkret register/unregister request builders. No network dependencies. |
| `http` | Adds `ArkretPushClient`, a small `reqwest` helper for `POST /_arkret/edge/push/register-device` and `POST /_arkret/edge/push/unregister-device`. |
| `notify` | Re-exports the SDK-owned `ak.edge.push.command.notify` wire types and adds blind-wakeup privacy validation. |

> **Production deployments MUST enable the `notify` feature.** Without it,
> the blind-wakeup / plaintext-visible privacy validators
> (`PushNotifyEnvelopeExt::assert_payload_safe`,
> `PushNotificationExt::validate_blind_wakeup`) and the Circle / governance
> metadata leak checks (`assert_no_sensitive_fields`,
> `ROUND_R2_R3_SENSITIVE_FIELDS`) are not compiled in — a wakeup that
> would otherwise be rejected by the validator will pass straight through
> to the device. Local-only smoke tests can leave it off, but any
> integration that touches real floria / inkson / soland traffic must
> compile with `--features http,notify`.
>
> The SDK-owned `PushNotifyRequestBody` and `PushNotificationEnvelope` are
> closed wire shapes, so unknown fields fail during deserialization. Hosts
> must still call `assert_payload_safe`, `validate_blind_wakeup`, or
> `validate_wire_model` before reading fields or showing UI because semantic
> privacy constraints are stricter than serde shape validation.

## AKP-0007 Circle subscriptions

[AKP-0007 Circle primitive](../arkret-spec/spec/v1/zh/models/circle.md)
introduces an encrypted sub-boundary inside a Realm. The security scope
of an Event lives in its producer-signed `scope_ref`; object read
projections may materialize an equal `effective_scope`. Neither name
reaches the push wire:

- **Receiving a Circle-scoped wakeup.** `PushNotificationEnvelope` carries no
  Circle identifier and no scope field. Raw Realm ids, Circle ids and
  `effective_scope` MUST NOT enter `/_arkret/edge/push/notify`
  (`push-notifications.md` §5.1); the wakeup only carries opaque
  `route_tokens.scope_route_token` / `devices[].target_route_token`.
  The client resolves the security boundary from the durable Event it
  fetches after the wakeup, never from the wakeup itself. The Circle
  metadata privacy validator in `validate_blind_wakeup` rejects
  `circle_name` / `circle_display_name` and the `circle_members` /
  `circle_member_dids` / `circle_member_actor_ids` membership surfaces;
  the closed SDK wire type rejects those fields during deserialization.
- **Muting a Circle on this device.** `PushPreferences` carries
  `muted_circle_ids: BTreeSet<String>` and `muted_realm_ids:
  BTreeSet<String>`. These are matched host-side against the scope the
  client resolved for the fetched Event — the wakeup itself cannot be
  matched, because it carries no scope. A muted scope MUST NOT raise a
  UI surface; wire-level delivery is unchanged so floria can still
  account for the receipt.
- **Deactivation cleanup.** `on_account_deactivate` snapshots
  `muted_circle_ids` / `muted_realm_ids` onto the returned
  `AccountDeactivationReceipt` (fields `circle_bindings_cleared` and
  `realm_bindings_cleared`) before wiping the persisted prefs, so
  host-side telemetry can observe which Circle / Realm bindings were
  live at the moment of deactivation.

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
chime = "1.0.0"
# or with Arkret HTTP registration and gateway notify wire types:
# chime = { version = "1.0.0", features = ["http"] }
# chime = { version = "1.0.0", features = ["http", "notify"] }
```

In-tree workspace consumers can also pull a path dependency:

```toml
chime = { path = "../chime", features = ["http"] }
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

let json = chime::to_json(&prefs).unwrap();
let loaded = chime::from_json(&json).unwrap();
assert_eq!(loaded.gateways[0].gateway_type, PushGatewayType::Bugle);
```

### Build a Arkret registration body

```rust
use chime::{
    GatewayBinding, PushDeviceConfig, PushGatewayType, PushPreferences,
    build_register_device_request,
};

let config = PushDeviceConfig {
    principal_id: Some("did:web:alice.example"),
    device_id: "ak:device:01904100-0000-7000-8000-000000000004",
    push_key: Some("fcm-or-apns-device-token"),
    platform: Some("android"),
    app_id: Some("app.example.android"),
    domestic_app_id: Some("app.example.android.cn"),
    registration_id: None,
    display_name: Some("Alice Phone"),
    idempotency_key: Some("device-phone-register-v1"),
    request_id: Some("ak:request:01JS0KE000000000000000000"),
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

### Validate a blind push wakeup

Enable the `notify` feature when implementing a gateway or a host-side push
receiver. The validator accepts only opaque routing metadata by default.

```rust
# #[cfg(feature = "notify")]
use chime::{
    PushNotifyEnvelopeExt, PushNotifyPolicyContext, PushNotifyRequestBody,
};

# #[cfg(feature = "notify")]
# fn main() -> Result<(), Box<dyn std::error::Error>> {
let request: PushNotifyRequestBody = serde_json::from_value(serde_json::json!({
    "notification": {
        "push_target_id": "ak:pseudonym:push:01HYZ8Z000000000000000",
        "wakeup_kind": "message",
        "timing_profile_hint": "default",
        "devices": [{
            "device_id": "ak:device:01904100-0000-7000-8000-000000000010",
            "push_key": "fcm:opaque-token",
            "app_id": "app.example"
        }]
    }
}))?;

request.assert_payload_safe(&PushNotifyPolicyContext::blind_wakeup_only(), None)?;

// The SDK model is closed: a plaintext label cannot hide in an `extra` map.
let err = serde_json::from_value::<PushNotifyRequestBody>(serde_json::json!({
    "notification": {
        "push_target_id": "ak:pseudonym:push:01HYZ8Z000000000000001",
        "wakeup_kind": "message",
        "timing_profile_hint": "default",
        "title": "Secret",
        "devices": [{
            "device_id": "ak:device:01904100-0000-7000-8000-000000000011"
        }]
    }
}))
    .expect_err("unknown plaintext metadata must be rejected");
let msg = err.to_string();
assert!(msg.contains("unknown field `title`"));
# Ok(())
# }
# #[cfg(not(feature = "notify"))]
# fn main() {}
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
use chime::ArkretPushClient;

let client = ArkretPushClient::new("https://principal.example")
    .with_bearer_token("session-token")
    .with_timeout(std::time::Duration::from_secs(10))
    .with_retry_policy(chime::PushRetryPolicy::conservative())
    .with_default_request_id("ak:request:01JS0KE000000000000000000");

let response = client
    .register_device_with_context(&config, &binding, &prefs)
    .await?;
assert!(response.body.ok);
# Ok(())
# }
```

> Live coverage of this strand lives in `tests/live_floria_integration.rs`,
> which spawns a real `floria` push gateway on a loopback port and exercises
> the discovery + notify side of the same `ArkretPushClient`.

Production notes:

- Authentication material is only sent through headers. Do not put session tokens, API keys, signatures, or bearer tokens in a binding's `push_gateway` URL query string.
- Media-token exchange uses `verify_media_token_outcome`, which delegates
  to the SDK media verifier. The caller supplies the original
  `CallMediaTokenExchangeRequestBody` and current `MediaServiceAnchors`,
  so chime checks issuer anchoring, participant tuple, TTL,
  `service_signature`, and `participant_binding.sig` before returning a
  verified token marker.
- Each binding's `push_gateway` must be HTTPS unless `allow_insecure_loopback_push_gateway` is enabled for localhost development.
- WebPush registrations can set `webpush_endpoint_allowlist` to restrict accepted endpoint origins or host patterns before a browser endpoint is sent to the service.
- `push_key` is redacted in debug output and logs; callers should still store it as a secret.
- `ArkretPushClient` retries only safe idempotent requests: register calls need an idempotency key, while unregister is treated as idempotent. `Retry-After` is honored before exponential backoff plus bounded jitter.
- `allow_push_hint` only permits body-free wakeup hints. It does not permit plaintext message bodies for E2EE Spaces.

### Request signing helpers

`chime` does not own authentication secrets or private keys. Callers can build a canonical proof body or HTTP Message Signature headers from the request they are about to send:

```rust,no_run
# fn doc_run() -> Result<(), chime::PushRegistrationError> {
# use chime::{GatewayBinding, PushDeviceConfig, PushGatewayType, PushPreferences};
# let config = PushDeviceConfig {
#     principal_id: None,
#     device_id: "ak:device:01904100-0000-7000-8000-000000000004",
#     push_key: Some("fcm-or-apns-device-token"),
#     platform: None, app_id: None, domestic_app_id: None,
#     registration_id: None, display_name: None,
#     idempotency_key: None, request_id: None, proof: None,
# };
# let binding = GatewayBinding::new(
#     PushGatewayType::Standard,
#     "https://push.example.com/_arkret/edge/push/notify",
# );
# let prefs = PushPreferences {
#     enabled: true,
#     ..Default::default()
# };
# struct DummySigner;
# impl DummySigner {
#     fn sign_http_message(&self, _ctx: &chime::PushRequestSigningContext)
#         -> Result<String, chime::PushRegistrationError> { Ok(String::new()) }
# }
# let signer = DummySigner;
use chime::{
    PushRequestSigningOptions, build_register_device_request,
    build_register_signing_context_with_options,
};

let request = build_register_device_request(&config, &binding, &prefs)?;
let context = build_register_signing_context_with_options(
    "https://principal.example",
    &request,
    PushRequestSigningOptions::new("2026-04-29T00:00:00.000Z", "https://principal.example")
        .with_actor_id("did:web:alice.example")
        .with_expires_at("2026-04-29T00:05:00.000Z")
        .with_origin("https://app.example")
        .with_origin_service_id("did:web:sync.example.com")
        .with_destination_service_id("did:web:principal.example")
        .with_nonce("device-phone-register-v1")
        .with_idempotency_key("device-phone-register-v1")
        .with_session_grant("externally-issued-coauth-or-soland-grant"),
)?;

let proof_body = context.canonical_proof_body()?;
let signature = signer.sign_http_message(&context)?;
let headers = context.http_message_signature_headers("sig1", &signature)?;
# let _ = (proof_body, headers);
# Ok(())
# }
```

`proof_body` is caller-signed and passed back through `PushDeviceConfig::proof`. The returned HTTP signature headers include `Content-Digest`, Arkret device/audience/actor/expiry/origin/destination metadata, nonce/idempotency context, `Signature-Input`, and `Signature`; attach them with your HTTP stack or `ArkretPushClient::with_header`. `chime` can carry an externally supplied coauth/soland grant, but it never owns private keys or mints grants.

### Local registration state

`PushRegistrationState` stores non-secret local state: principal ID, device id, platform/app id, gateway, token hash/preview, registration id, expiry/refresh hint, and last success/error summary. The `PushRegistrationStore` trait exposes single-registration methods plus multi-registration helpers (`load_push_registrations`, `save_push_registrations`, and `delete_push_registration`) for apps that store several accounts, apps, or devices.

Store implementations should use OS keychain, encrypted app storage, or another locally protected store. The state includes `schema_version` so applications can migrate persisted records without exposing raw platform tokens.

After a successful register, `merge_registration_state()` drops stale logical duplicates and same-token records that were left behind on another device entry. When a client needs to recover from partial failures or stale local storage, `plan_registration_repair()` produces the unregister/register work needed to reconcile old token state with the current device token.

### Token rotation

```rust,no_run
# fn doc_run() -> Result<(), chime::PushRegistrationError> {
# use chime::{GatewayBinding, PushDeviceConfig, PushGatewayType, PushPreferences};
# let config = PushDeviceConfig {
#     principal_id: None,
#     device_id: "ak:device:01904100-0000-7000-8000-000000000004",
#     push_key: Some("fcm-or-apns-device-token"),
#     platform: None, app_id: None, domestic_app_id: None,
#     registration_id: None, display_name: None,
#     idempotency_key: None, request_id: None, proof: None,
# };
# let binding = GatewayBinding::new(
#     PushGatewayType::Standard,
#     "https://push.example.com/_arkret/edge/push/notify",
# );
# let prefs = PushPreferences {
#     enabled: true,
#     ..Default::default()
# };
use chime::{plan_token_rotation_with_strategy, PushRegistrationState, PushTokenRotationStrategy};

// Replace this with your `PushRegistrationStore::load_push_registration()` call.
let existing: Option<PushRegistrationState> = None;
let plan = plan_token_rotation_with_strategy(
    existing.as_ref(),
    &config,
    &binding,
    &prefs,
    PushTokenRotationStrategy::RegisterNewFirst,
)?;

if let Some(register_new) = plan.register_new {
    // Send with ArkretPushClient or your own HTTP stack, then persist success.
    let _ = register_new;
}
if let Some(unregister_old) = plan.unregister_old {
    // For RegisterNewFirst, send this after the replacement succeeds.
    let _ = unregister_old;
}
# Ok(())
# }
```

## Configuration & Operations

`chime` is a library, not a service — it has no daemon, no config file
of its own, and no environment variables it reads. Operational concerns
live entirely in the host application that wires `ArkretPushClient`
into a Arkret Principal Server / Sync Service deployment.

### Build profile

| Knob | Value | Note |
| ---- | ----- | ---- |
| MSRV | `1.97` | Enforced by CI; bump only with a minor release. |
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
- **Nonce replay storage.** `NonceTracker` is in-memory and
  per-instance. Server-side relays and multi-process hosts must back it
  with a shared persistent store, such as Redis or an encrypted local
  key-value database, before accepting inbound frames after restart or
  across workers.
- **Retries.** Default `PushRetryPolicy::disabled()`. Use
  `PushRetryPolicy::conservative()` for `429`/`503`/network-timeout
  retries with `Retry-After` honoring and bounded jitter.
- **Token storage.** Implement `PushRegistrationStore` over an OS
  keychain, encrypted app storage, or another locally protected store.
  Never log raw `push_key`; the crate redacts it in `Debug` impls and
  tracing fields, and you should mirror that in your own code.
- **Privacy gate.** When you build the `notify` feature into a
  gateway, validate every outbound payload through
  `PushNotifyEnvelopeExt::assert_payload_safe(&policy, None)`. Empty
  `PushNotifyPolicyContext` means every notification is treated as
  blind wakeup, which is the safest default.

### Observability

`chime` emits `tracing` events with the target prefix `chime`:

```text
INFO  chime::push::client  Arkret push device registered  platform=android gateway="Arkret Standard" operation_id=ak.edge.push.command.register_device request_id=ak:request:01JS0KE000000000000000000
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
| `ak.edge.push.command.register_device` | `POST /_arkret/edge/push/register-device` | `build_register_device_request()` |
| `ak.edge.push.command.unregister_device` | `POST /_arkret/edge/push/unregister-device` | `build_unregister_device_request()` |
| `ak.edge.push.command.notify` | `POST /_arkret/edge/push/notify` | Gateway/server-side operation, not a client registration call. |

Register/unregister builders carry the canonical operation id, optional `principal_id`, `device_id`, app id, gateway URL, idempotency key, request id, and caller-supplied proof. Register responses expose only the spec response body fields (`ok`, `registration_id`, and `expires_at`); response headers carry transport metadata such as request id.

Push notifications are derived wakeups, not canonical truth. For E2EE Realms, push gateways should receive only minimized metadata such as `push_target_id`, `wakeup_kind`, counts, priority/TTL/collapse hints, and optional body-free `push_hint`.

With the `notify` feature, the `PushNotifyEnvelopeExt` methods on the SDK-owned `PushNotifyRequestBody` enforce that boundary. Entity facets and view-renderer output are routing or context hints only when the application has explicitly authorized that use; do not serialize facet-derived title, body, display name, or space name into provider payloads. The closed SDK model rejects unknown aliases and provider wrappers during deserialization; the Chime validator then rejects typed identifying metadata that is not allowed in blind-wakeup mode.

`shared_push_notify_privacy_vectors()` exposes the E2EE invalid cases and the explicit plaintext-visible service allow case so gateway implementations such as `floria` can run the same vectors.

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
Principal Server / Sync Service
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
