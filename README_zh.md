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

let strict = chime::try_from_json(&json).unwrap();
assert_eq!(strict.gateway_type, PushGatewayType::Bugle);
```

### 构建 Contrix 注册请求体

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

### 通过 HTTP 注册

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

生产接入注意事项：

- 认证材料只通过 header 发送。不要把 session token、API key、签名或 bearer token 放进 `push_gateway` query string。
- `push_gateway` 必须使用 HTTPS；只有 localhost 开发场景可以显式打开 `allow_insecure_loopback_push_gateway`。
- WebPush 注册可以设置 `webpush_endpoint_allowlist`，在浏览器 endpoint 发送给服务端前限制允许的 origin 或 host pattern。
- `push_key` 在 debug output 和日志中会脱敏；调用方仍应按 secret 存储。
- `ContrixPushClient` 只重试安全的幂等请求：register 需要 idempotency key，unregister 按幂等处理。客户端会优先遵守 `Retry-After`，再使用 exponential backoff 和有界 jitter。
- `allow_push_hint` 只允许不含正文的唤醒提示，不允许 E2EE Space 的明文消息正文。

### 请求签名辅助

`chime` 不托管认证 secret 或私钥。调用方可以基于即将发送的请求构建 canonical proof body 或 HTTP Message Signature header：

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

`proof_body` 由调用方签名，再通过 `PushDeviceConfig::proof` 带回请求体。HTTP signature headers 会包含 `Content-Digest`、Contrix device/audience/actor/expiry/origin/destination metadata、nonce/idempotency context、`Signature-Input` 和 `Signature`；调用方可用自己的 HTTP stack 发送，也可通过 `ContrixPushClient::with_header` 注入。`chime` 可以携带外部提供的 coauth/soland grant，但不会托管私钥，也不会自己签发 grant。

### 本地注册状态

`PushRegistrationState` 存储非 secret 的本地状态：principal DID、device id、platform/app id、gateway、token hash/preview、registration id、expiry/refresh hint，以及 last success/error 摘要。`PushRegistrationStore` 保留旧的单条注册方法，并添加 multi-registration 默认方法（`load_push_registrations`、`save_push_registrations`、`delete_push_registration`），方便应用同时保存多个账号、app 或设备。

存储实现应使用系统 keychain、加密应用存储或其它本地受保护存储。state 中包含 `schema_version`，便于应用迁移持久化记录，同时不暴露原始平台 token。

注册成功后，`merge_registration_state()` 会清理同一逻辑注册和同一 token 遗留的 stale 记录。需要处理部分失败或本地状态陈旧时，`plan_registration_repair()` 会生成需要执行的 unregister/register 修复计划。

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
    // 发送新注册请求，成功后持久化新的 registration state。
}
if let Some(unregister_old) = plan.unregister_old {
    // RegisterNewFirst 策略下，在新注册成功后再发送旧 token 注销请求。
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

迁移时请直接改成新字段名。严格解析和校验路径已经不再接受 legacy alias 字段。

## 协议映射

本 crate 映射到 Contrix v1 推送 HTTP binding：

| Operation ID | HTTP Binding | 请求构建器 |
| --- | --- | --- |
| `cx.push.register_device` | `POST /api/v1/push/register-device` | `build_register_device_request()` |
| `cx.push.unregister_device` | `POST /api/v1/push/unregister-device` | `build_unregister_device_request()` |
| `cx.push.notify` | `POST /api/v1/push/notify` | 网关/服务端操作，不是客户端设备注册调用。 |

Register/unregister 请求体会携带 canonical operation id、可选 `principal_did`、`device_id`、app id、gateway URL、idempotency key、request id 和调用方提供的 proof。响应会在服务端返回时暴露 accepted gateway、token hash/preview、过期或 refresh hint、warnings 与 request id。

推送通知是派生唤醒，不是 canonical truth。E2EE Space 下，推送网关只应收到最小化元数据，例如 `space_id`、事件类型、计数、目标设备引用、priority/TTL/collapse hint，以及可选的不含正文的 `push_hint`。

启用 `notify` feature 后，`PushNotifyRequest::validate_wire_model()` 和 `PushNotifyRequest::validate_blind_wakeup()` 会强制执行这条边界。Entity facets 和 view renderer 输出只有在应用明确授权时才可作为路由或上下文提示；不要把 facet 派生出的 title、body、display name 或 space name 序列化进 provider payload。校验器会在网关投递前拒绝已移除的 `room` / `card` / `subject` 引用、`schema_id` / `kind` 别名、`sender_service_did`、provider payload 包装、title/body/preview 字段，以及 facet/view-renderer 扩展键。

`shared_push_notify_privacy_vectors()` 会导出 E2EE invalid cases（包含 legacy 引用拒绝样例）和显式 plaintext-visible service allow case，方便 `floria` 等网关实现复用同一组向量。

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
