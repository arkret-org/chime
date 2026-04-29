# chime

> **Warning:** This project is in a very early stage and APIs may change without notice.

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
chime = { path = "../chime" }
# or with Contrix HTTP registration and gateway notify wire types:
# chime = { path = "../chime", features = ["http"] }
# chime = { path = "../chime", features = ["http", "notify"] }
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
let loaded = chime::from_json(&json);
assert_eq!(loaded.gateway_type, PushGatewayType::Bugle);
```

### Build a Contrix registration body

```rust
use chime::{PushDeviceConfig, PushPreferences, build_register_device_request};

let config = PushDeviceConfig {
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
    .with_retry_policy(chime::PushRetryPolicy::conservative());

let response = client.register_device_with_context(&config, &prefs).await?;
assert!(response.body.ok);
```

Production notes:

- Authentication material is only sent through headers. Do not put session tokens, API keys, signatures, or bearer tokens in `push_gateway` query strings.
- `push_gateway` must be HTTPS unless `allow_insecure_loopback_push_gateway` is enabled for localhost development.
- `push_key` is redacted in debug output and logs; callers should still store it as a secret.
- `allow_push_hint` only permits body-free wakeup hints. It does not permit plaintext message bodies for E2EE Spaces.

### Token rotation

```rust,ignore
use chime::{plan_token_rotation, PushRegistrationState};

let existing: Option<PushRegistrationState> = store.load_push_registration()?;
let plan = plan_token_rotation(existing.as_ref(), &config, &prefs)?;

if let Some(unregister_old) = plan.unregister_old {
    // Send with ContrixPushClient or your own HTTP stack.
}
if let Some(register_new) = plan.register_new {
    // Send with ContrixPushClient or your own HTTP stack, then persist success.
}
```

## Migration from legacy Matrix pusher terms

| Legacy term | Contrix term |
| --- | --- |
| `matrix` feature | `http` feature |
| `PusherConfig` | `PushDeviceConfig` |
| `register_pusher` | `ContrixPushClient::register_device` or `build_register_device_request` |
| `unregister_pusher` | `ContrixPushClient::unregister_device` or `build_unregister_device_request` |
| `gateway_url` | `push_gateway` |
| `show_message_preview` | `allow_push_hint` |

## Protocol Mapping

The crate maps to the Contrix v1 push HTTP binding:

| Operation ID | HTTP Binding | Request builder |
| --- | --- | --- |
| `cx.push.register_device` | `POST /api/v1/push/register-device` | `build_register_device_request()` |
| `cx.push.unregister_device` | `POST /api/v1/push/unregister-device` | `build_unregister_device_request()` |
| `cx.push.notify` | `POST /api/v1/push/notify` | Gateway/server-side operation, not a client registration call. |

Push notifications are derived wakeups, not canonical truth. For E2EE Spaces, push gateways should receive only minimized metadata such as `space_id`, event type, counts, and optional body-free `push_hint`.

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
