# chime

> **Spec target**: [contrix-spec @ cced4b8](../contrix-spec) (R3.3 sync 2026-05-28)

[![coverage](https://img.shields.io/badge/coverage-local%20tarpaulin-informational)](docs/production-checklist.md#local-verification)

> **Stability:** local `1.0.0` freeze candidate. Breaking public API changes
> now require a major-version bump. Response wire types
> (`RegisterDeviceResponse`, `UnregisterDeviceResponse`, `ContrixErrorEnvelope`)
> carry `#[non_exhaustive]` so server-driven field additions do not break
> downstream consumers.

Contrix push notification gateway types, preferences, and device registration helpers.

**chime** provides shared data types and request-building logic for Contrix clients that need to register push-capable devices with a Principal Server, Sync Service, or delegated Push Gateway.

## Realm vs Space

Following the Phase 1–4 terminology inversion, `chime` aligns push routes with the new vocabulary:

- **Realm:** security boundary — membership, capability, E2EE, and federation are governed at this level. Push permission and per-realm mute apply here.
- **Space:** navigation container — board, list, section, or calendar bucket. Lives inside a Realm and inherits its security context.

## Round R4 (protocol review closures)

Spec round 4 (`contrix-spec` range `2a4d39b..a77b995`, 8 commits) adds
two client-SDK shape changes. See [`CHANGELOG.md`](CHANGELOG.md)
`[Unreleased]` and [`../_todos.md`](../_todos.md) for the canonical
wire-breaking list.

- **`mention_redirect_target_actor_ids` recognition** — typed
  push-payload structs expose the field; consumers (yougen et al.)
  decide whether the active device's actor is an authorised
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
blind-wakeup forbidden-field surface. Ephemeral kinds (`cx.presence`,
`cx.typing`, `cx.receipt.read`, `cx.call.signal`) are confirmed not
consumed by chime. See [`CHANGELOG.md`](CHANGELOG.md) `[Unreleased]` and
[`../contrix-spec/CHANGELOG.md`](../contrix-spec/CHANGELOG.md) for the
normative source.

## Cross-project task tracking

Per-project task lists are consolidated upstream — see
[`../_todos.md`](../_todos.md) for the active cross-project task plan.

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

> **Production deployments MUST enable the `notify` feature.** Without it,
> the blind-wakeup / plaintext-visible privacy validators
> (`PushNotifyReqBody::assert_payload_safe`,
> `PushNotification::validate_blind_wakeup`) and the Circle / governance
> metadata leak checks (`assert_no_sensitive_fields`,
> `ROUND_R2_R3_SENSITIVE_FIELDS`) are not compiled in — a wakeup that
> would otherwise be rejected by the validator will pass straight through
> to the device. Local-only smoke tests can leave it off, but any
> integration that touches real floria / yougen / soland traffic must
> compile with `--features http,notify`.

## CXP-0007 Circle subscriptions

[CXP-0007 Circle primitive](../contrix-spec/specs/protocol/circle.md)
introduces an encrypted sub-boundary inside a Realm. chime exposes the
client-side surface so a wakeup can carry the Circle context end-to-end:

- **Receiving a Circle-scoped wakeup.** `PushNotification.circle_id`
  carries the typed `cx:circle:` reference of the Circle the wakeup
  was authored against (when applicable). `PushNotification.effective_scope`
  mirrors the event envelope's `effective_scope` field
  (`cx:circle:...` or `cx:realm:...`) so the client can correlate the
  wakeup with the security boundary without an extra round-trip.
  Both fields are validated by `validate_wire_model`; the Circle
  metadata privacy validator in `validate_blind_wakeup` additionally
  rejects `circle_name` / `circle_members` / `circle_member_dids` in
  the `extra` map and any `circle_id` value that smuggles a `did:`
  literal in its tail.
- **Muting a Circle on this device.** `PushPreferences` carries
  `muted_circle_ids: BTreeSet<String>` and `muted_realm_ids:
  BTreeSet<String>`. Wakeups whose `circle_id` (or `realm_id`) is in
  the matching set MUST NOT raise a UI surface; wire-level delivery
  is unchanged so floria can still account for the receipt.
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
# or with Contrix HTTP registration and gateway notify wire types:
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
            "https://push.palpo.im/api/v1/push/notify",
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

### Build a Contrix registration body

```rust
use chime::{
    GatewayBinding, PushDeviceConfig, PushGatewayType, PushPreferences,
    build_register_device_request,
};

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
    request_id: Some("cx:request:01JS0KE000000000000000000"),
    proof: None,
};

let binding = GatewayBinding::new(
    PushGatewayType::Standard,
    "https://push.example.com/api/v1/push/notify",
);
let prefs = PushPreferences {
    enabled: true,
    ..Default::default()
};

let request = build_register_device_request(&config, &binding, &prefs).unwrap();
assert_eq!(request.device_id, "did:web:alice.example#device-phone");
```

### Validate a blind push wakeup

Enable the `notify` feature when implementing a gateway or a host-side push
receiver. The validator accepts only opaque routing metadata by default.

```rust
# #[cfg(feature = "notify")]
use chime::{
    PushNotification, PushNotificationDevice, PushNotifyPolicyContext, PushNotifyReqBody,
    PushTargetId, WakeupKind,
};

# #[cfg(feature = "notify")]
# fn main() -> Result<(), Box<dyn std::error::Error>> {
// `PushNotification` is `#[non_exhaustive]` so additive Circle / R2-R3
// fields cannot break downstream constructors. Build through
// `new_blind_wakeup` plus field-update from the returned value.
let mut notification = PushNotification::new_blind_wakeup(
    PushTargetId::new("cx:pseudonym:push:01HYZ8Z000000000000000")?,
    WakeupKind::Message,
);
notification.devices = vec![PushNotificationDevice {
    push_key: "fcm:opaque-token".to_owned(),
    app_id: Some("app.example".to_owned()),
    registration_id: None,
    push_key_hash: None,
    platform: None,
}];
let request = PushNotifyReqBody {
    notification,
    ..Default::default()
};

request.assert_payload_safe(&PushNotifyPolicyContext::blind_wakeup_only())?;

// P2D.5 — error-path doc-test: a plaintext label in `extra` is
// rejected by the blind-wakeup validator even when the wire shape
// otherwise looks innocent. This is the exact path that protects
// against an integrator accidentally bypassing the SDK sanitizer.
let mut leaky = PushNotification::new_blind_wakeup(
    PushTargetId::new("cx:pseudonym:push:01HYZ8Z000000000000001")?,
    WakeupKind::Message,
);
leaky.devices = vec![PushNotificationDevice {
    push_key: "fcm:opaque-token".to_owned(),
    app_id: Some("app.example".to_owned()),
    registration_id: None,
    push_key_hash: None,
    platform: None,
}];
leaky.extra.insert(
    "title".to_owned(),
    serde_json::Value::String("Secret".to_owned()),
);
let leaky_request = PushNotifyReqBody {
    notification: leaky,
    ..Default::default()
};
let err = leaky_request
    .assert_payload_safe(&PushNotifyPolicyContext::blind_wakeup_only())
    .expect_err("plaintext metadata must be rejected");
let msg = err.to_string();
assert!(msg.contains("title"), "error should name the leaking field: {msg}");
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
#     principal_did: None,
#     device_id: "did:web:alice.example#device-phone",
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
#     "https://push.example.com/api/v1/push/notify",
# );
# let prefs = PushPreferences {
#     enabled: true,
#     ..Default::default()
# };
use chime::ContrixPushClient;

let client = ContrixPushClient::new("https://principal.example")
    .with_bearer_token("session-token")
    .with_timeout(std::time::Duration::from_secs(10))
    .with_retry_policy(chime::PushRetryPolicy::conservative())
    .with_default_request_id("cx:request:01JS0KE000000000000000000");

let response = client
    .register_device_with_context(&config, &binding, &prefs)
    .await?;
assert!(response.body.ok);
# Ok(())
# }
```

> Live coverage of this flow lives in `tests/live_floria_integration.rs`,
> which spawns a real `floria` push gateway on a loopback port and exercises
> the discovery + notify side of the same `ContrixPushClient`.

Production notes:

- Authentication material is only sent through headers. Do not put session tokens, API keys, signatures, or bearer tokens in a binding's `push_gateway` URL query string.
- Each binding's `push_gateway` must be HTTPS unless `allow_insecure_loopback_push_gateway` is enabled for localhost development.
- WebPush registrations can set `webpush_endpoint_allowlist` to restrict accepted endpoint origins or host patterns before a browser endpoint is sent to the service.
- `push_key` is redacted in debug output and logs; callers should still store it as a secret.
- `ContrixPushClient` retries only safe idempotent requests: register calls need an idempotency key, while unregister is treated as idempotent. `Retry-After` is honored before exponential backoff plus bounded jitter.
- `allow_push_hint` only permits body-free wakeup hints. It does not permit plaintext message bodies for E2EE Spaces.

### Request signing helpers

`chime` does not own authentication secrets or private keys. Callers can build a canonical proof body or HTTP Message Signature headers from the request they are about to send:

```rust,no_run
# fn doc_run() -> Result<(), chime::PushRegistrationError> {
# use chime::{GatewayBinding, PushDeviceConfig, PushGatewayType, PushPreferences};
# let config = PushDeviceConfig {
#     principal_did: None,
#     device_id: "did:web:alice.example#device-phone",
#     push_key: Some("fcm-or-apns-device-token"),
#     platform: None, app_id: None, domestic_app_id: None,
#     registration_id: None, display_name: None,
#     idempotency_key: None, request_id: None, proof: None,
# };
# let binding = GatewayBinding::new(
#     PushGatewayType::Standard,
#     "https://push.example.com/api/v1/push/notify",
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
# let _ = (proof_body, headers);
# Ok(())
# }
```

`proof_body` is caller-signed and passed back through `PushDeviceConfig::proof`. The returned HTTP signature headers include `Content-Digest`, Contrix device/audience/actor/expiry/origin/destination metadata, nonce/idempotency context, `Signature-Input`, and `Signature`; attach them with your HTTP stack or `ContrixPushClient::with_header`. `chime` can carry an externally supplied coauth/soland grant, but it never owns private keys or mints grants.

### Local registration state

`PushRegistrationState` stores non-secret local state: principal DID, device id, platform/app id, gateway, token hash/preview, registration id, expiry/refresh hint, and last success/error summary. The `PushRegistrationStore` trait exposes single-registration methods plus multi-registration helpers (`load_push_registrations`, `save_push_registrations`, and `delete_push_registration`) for apps that store several accounts, apps, or devices.

Store implementations should use OS keychain, encrypted app storage, or another locally protected store. The state includes `schema_version` so applications can migrate persisted records without exposing raw platform tokens.

After a successful register, `merge_registration_state()` drops stale logical duplicates and same-token records that were left behind on another device entry. When a client needs to recover from partial failures or stale local storage, `plan_registration_repair()` produces the unregister/register work needed to reconcile old token state with the current device token.

### Token rotation

```rust,no_run
# fn doc_run() -> Result<(), chime::PushRegistrationError> {
# use chime::{GatewayBinding, PushDeviceConfig, PushGatewayType, PushPreferences};
# let config = PushDeviceConfig {
#     principal_did: None,
#     device_id: "did:web:alice.example#device-phone",
#     push_key: Some("fcm-or-apns-device-token"),
#     platform: None, app_id: None, domestic_app_id: None,
#     registration_id: None, display_name: None,
#     idempotency_key: None, request_id: None, proof: None,
# };
# let binding = GatewayBinding::new(
#     PushGatewayType::Standard,
#     "https://push.example.com/api/v1/push/notify",
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
    // Send with ContrixPushClient or your own HTTP stack, then persist success.
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
  them in a binding's `push_gateway` query string is rejected.
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
INFO  chime::push::client  Contrix push device registered  platform=android gateway="Contrix Standard" operation_id=cx.push.register_device request_id=cx:request:01JS0KE000000000000000000
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

## Protocol Mapping

The crate maps to the Contrix v1 push HTTP binding:

| Operation ID | HTTP Binding | Request builder |
| --- | --- | --- |
| `cx.push.register_device` | `POST /api/v1/push/register-device` | `build_register_device_request()` |
| `cx.push.unregister_device` | `POST /api/v1/push/unregister-device` | `build_unregister_device_request()` |
| `cx.push.notify` | `POST /api/v1/push/notify` | Gateway/server-side operation, not a client registration call. |

Register/unregister bodies carry the canonical operation id, optional `principal_did`, `device_id`, app id, gateway URL, idempotency key, request id, and caller-supplied proof. Responses expose the accepted gateway, token hash/preview, expiry or refresh hints, warnings, and request id when the service returns them.

Push notifications are derived wakeups, not canonical truth. For E2EE Realms, push gateways should receive only minimized metadata such as `push_target_id`, `wakeup_kind`, counts, priority/TTL/collapse hints, and optional body-free `push_hint`.

With the `notify` feature, `PushNotifyRequest::validate_wire_model()` and `PushNotifyRequest::validate_blind_wakeup()` enforce that boundary. Entity facets and view-renderer output are routing or context hints only when the application has explicitly authorized that use; do not serialize facet-derived title, body, display name, or space name into provider payloads. The validator rejects removed aliases such as `schema_id` and `kind`, provider payload wrappers, title/body/preview fields, and facet/view-renderer extension keys before gateway delivery.

`shared_push_notify_privacy_vectors()` exposes the E2EE invalid cases and the explicit plaintext-visible service allow case so gateway implementations such as `floria` can run the same vectors.

## Architecture

```text
Contrix Client
        |
        v
   +---------+     PushPreferences { gateways: Vec<GatewayBinding> }
   |  chime  | --> GatewayBinding { gateway_type, push_gateway, push_key, app_id }
   +----+----+     build_register_device_request(config, binding, prefs)
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

---

<!-- circle-rollout milestone pointer -->
> **Active milestone tracking** (local-only, gitignored): see
> `_chime_todos.md` in the parent `contrix-dev/` directory for the
> circle-rollout (CXP-0007) work item list and per-stage checkpoints.
