# chime

> **Warning:** This project is in a very early stage and is not functional yet. APIs will change without notice.

Matrix push notification gateway types, preferences, and pusher registration library.

**chime** provides the shared data types and logic used by Matrix chat clients to configure and register push notification gateways with a Matrix homeserver. It is designed for use by multiple front-end projects (e.g. [Synpad](https://github.com/nickkuk/synpad), [Robrix](https://github.com/nickkuk/robrix)) that need a common push notification layer.

## Gateway Support

| Gateway    | Description |
|------------|-------------|
| **Sygnal** | Standard Matrix push gateway using FCM (Android) and APNs (iOS). Works globally. |
| **Bugle**  | Push gateway with domestic Chinese Android OEM provider support. Routes through JPush `third_party_channel` to Huawei Push Kit, Xiaomi Mi Push, OPPO Push, vivo Push, HONOR Push, and HarmonyOS. Ideal for mainland China where Google FCM is unavailable. |
| **Custom** | User-provided gateway URL for self-hosted or third-party gateways. |

## Features

| Feature  | Description |
|----------|-------------|
| _(default)_ | Core types (`PushGatewayType`, `PushPreferences`) and JSON serialization helpers. No network dependencies. |
| `matrix` | Adds `register_pusher()` and `unregister_pusher()` functions that use `matrix_sdk::Client` to register/unregister HTTP pushers with a Matrix homeserver. Invalid platforms are rejected explicitly, and disabled preferences trigger unregister instead of re-registering. |

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
chime = { path = "../chime" }
# or with pusher registration:
# chime = { path = "../chime", features = ["matrix"] }
```

### Core types (no network)

```rust
use chime::{PushGatewayType, PushPreferences};

// Create preferences with Bugle gateway for China users
let mut prefs = PushPreferences {
    enabled: true,
    gateway_type: PushGatewayType::Bugle,
    ..Default::default()
};
prefs.apply_gateway_type_defaults();

// Resolve the correct app ID for the gateway
let app_id = prefs.android_app_id("app.example.android", "app.example.android.cn");
assert_eq!(app_id, "app.example.android.cn");

// Serialize to JSON for persistence
let json = chime::to_json(&prefs).unwrap();
let loaded = chime::from_json(&json);
assert_eq!(loaded.gateway_type, PushGatewayType::Bugle);
```

### Pusher registration (requires `matrix` feature)

```rust,ignore
use chime::{PushPreferences, PusherConfig, register_pusher};

let config = PusherConfig {
    token: "fcm-or-apns-device-token",
    platform: "android",
    android_app_id: "app.example.android",
    domestic_android_app_id: "app.example.android.cn",
    ios_app_id: "app.example.ios",
    app_display_name: "MyApp",
    device_display_name: "MyApp Mobile",
};

let prefs = PushPreferences::default();
register_pusher(&matrix_client, &config, &prefs).await?;
```

## Architecture

```
Matrix Client (Synpad / Robrix / ...)
        |
        v
   ┌─────────┐     PushPreferences
   │  chime  │───> PushGatewayType { Sygnal, Bugle, Custom }
   └────┬─────┘     register_pusher() / unregister_pusher()
        |
        v
  Matrix Homeserver
        |
        v
  Push Gateway (Sygnal or Bugle)
        |
        ├── FCM ──> Android (global)
        ├── APNs ─> iOS
        └── Bugle domestic providers:
            ├── JPush (aggregation layer)
            ├── Huawei Push Kit / HarmonyOS
            ├── Xiaomi Mi Push
            ├── OPPO / OnePlus Push
            ├── vivo Push
            └── HONOR Push
```

## License

Licensed under Apache 2.0. See [LICENSE](LICENSE).
