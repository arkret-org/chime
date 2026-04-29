# chime

> **警告：** 本项目处于非常早期阶段，API 可能随时变更，恕不另行通知。

Contrix 推送通知网关类型、偏好设置和设备注册辅助库。

**chime** 提供 Contrix 客户端共享的数据类型和请求构建逻辑，用于把可接收推送的设备注册到 Principal Server、Sync Service 或被委托的 Push Gateway。

## 网关支持

| 网关 | 说明 |
| --- | --- |
| **Standard** | 标准 Contrix Push Gateway，可连接 FCM、APNs、Web Push 或桌面通知桥接。 |
| **Bugle** | 支持中国大陆安卓 OEM 厂商通道的 Contrix Push Gateway，可通过极光推送、华为、小米、OPPO、vivo、荣耀和鸿蒙路线投递。 |
| **Custom** | 用户自定义网关 URL，用于自托管或第三方网关。 |

## 功能特性

| Feature | 说明 |
| --- | --- |
| _(默认)_ | 核心类型、JSON 序列化辅助函数，以及 Contrix 注册/注销请求构建器。无网络依赖。 |
| `http` | 添加 `ContrixPushClient`，使用 `reqwest` 调用 `POST /api/v1/push/register-device` 和 `POST /api/v1/push/unregister-device`。 |
| `notify` | 添加服务端/网关侧 `cx.push.notify` wire 类型和 blind-wakeup 隐私校验。 |

## 快速开始

添加到你的 `Cargo.toml`：

```toml
[dependencies]
chime = { path = "../chime" }
# 如需 Contrix HTTP 注册功能和网关 notify wire 类型：
# chime = { path = "../chime", features = ["http"] }
# chime = { path = "../chime", features = ["http", "notify"] }
```

### 核心类型

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

### 构建 Contrix 注册请求体

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

### 通过 HTTP 注册

```rust,ignore
use chime::{ContrixPushClient, PushDeviceConfig, PushPreferences};

let client = ContrixPushClient::new("https://principal.example")
    .with_bearer_token("session-token")
    .with_timeout(std::time::Duration::from_secs(10))
    .with_retry_policy(chime::PushRetryPolicy::conservative());

let response = client.register_device_with_context(&config, &prefs).await?;
assert!(response.body.ok);
```

生产接入注意事项：

- 认证材料只通过 header 发送。不要把 session token、API key、签名或 bearer token 放进 `push_gateway` query string。
- `push_gateway` 必须使用 HTTPS；只有 localhost 开发场景可以显式打开 `allow_insecure_loopback_push_gateway`。
- `push_key` 在 debug output 和日志中会脱敏；调用方仍应按 secret 存储。
- `allow_push_hint` 只允许不含正文的唤醒提示，不允许 E2EE Space 的明文消息正文。

### Token rotation

```rust,ignore
use chime::{plan_token_rotation, PushRegistrationState};

let existing: Option<PushRegistrationState> = store.load_push_registration()?;
let plan = plan_token_rotation(existing.as_ref(), &config, &prefs)?;

if let Some(unregister_old) = plan.unregister_old {
    // 使用 ContrixPushClient 或你自己的 HTTP stack 发送。
}
if let Some(register_new) = plan.register_new {
    // 发送新注册请求，成功后持久化新的 registration state。
}
```

## 从旧 Matrix pusher 术语迁移

| 旧术语 | Contrix 术语 |
| --- | --- |
| `matrix` feature | `http` feature |
| `PusherConfig` | `PushDeviceConfig` |
| `register_pusher` | `ContrixPushClient::register_device` 或 `build_register_device_request` |
| `unregister_pusher` | `ContrixPushClient::unregister_device` 或 `build_unregister_device_request` |
| `gateway_url` | `push_gateway` |
| `show_message_preview` | `allow_push_hint` |

## 协议映射

本 crate 映射到 Contrix v1 推送 HTTP binding：

| Operation ID | HTTP Binding | 请求构建器 |
| --- | --- | --- |
| `cx.push.register_device` | `POST /api/v1/push/register-device` | `build_register_device_request()` |
| `cx.push.unregister_device` | `POST /api/v1/push/unregister-device` | `build_unregister_device_request()` |
| `cx.push.notify` | `POST /api/v1/push/notify` | 网关/服务端操作，不是客户端设备注册调用。 |

推送通知是派生唤醒，不是 canonical truth。E2EE Space 下，推送网关只应收到最小化元数据，例如 `space_id`、事件类型、计数，以及可选的不含正文的 `push_hint`。

## 架构

```text
Contrix Client
        |
        v
   +---------+     PushPreferences
   |  chime  | --> PushGatewayType { Standard, Bugle, Custom }
   +----+----+     build_register_device_request()
        |          ContrixPushClient (可选)
        v
Principal Server / Sync Service
        |
        v
Contrix Push Gateway
        |
        +-- FCM / APNs / Web Push / Desktop
        +-- Bugle 国内厂商推送：
            +-- 极光推送 JPush
            +-- 华为 / 鸿蒙
            +-- 小米
            +-- OPPO / 一加
            +-- vivo
            +-- 荣耀
```

## 许可证

Apache 2.0 许可。详见 [LICENSE](LICENSE)。
