# chime

> **警告：** 本项目处于非常早期的阶段，当前尚不可用。API 可能随时变更，恕不另行通知。

Matrix 推送通知网关类型、偏好设置及推送器注册库。

**chime** 提供了 Matrix 聊天客户端用来配置和向 Matrix 主服务器注册推送通知网关的共享数据类型和逻辑。它设计为多个前端项目（如 [Synpad](https://github.com/nickkuk/synpad)、[Robrix](https://github.com/nickkuk/robrix)）共用的推送通知层。

## 网关支持

| 网关       | 说明 |
|------------|------|
| **Sygnal** | 标准 Matrix 推送网关，使用 FCM（Android）和 APNs（iOS）。全球可用。 |
| **Bugle**  | 支持中国大陆安卓 OEM 厂商的推送网关。通过极光推送（JPush）`third_party_channel` 路由到华为推送、小米推送、OPPO 推送、vivo 推送、荣耀推送和鸿蒙推送。适用于中国大陆 Google FCM 不可用的场景。 |
| **Custom** | 用户自定义网关 URL，用于自托管或第三方网关。 |

## 功能特性

| Feature    | 说明 |
|------------|------|
| _(默认)_   | 核心类型（`PushGatewayType`、`PushPreferences`）和 JSON 序列化辅助函数。无网络依赖。 |
| `matrix`   | 添加 `register_pusher()` 和 `unregister_pusher()` 函数，使用 `matrix_sdk::Client` 向 Matrix 主服务器注册/注销 HTTP 推送器。会显式拒绝非法平台值，并在推送被禁用时优先执行注销而不是继续注册。 |

## 快速开始

添加到你的 `Cargo.toml`：

```toml
[dependencies]
chime = { path = "../chime" }
# 如需推送器注册功能：
# chime = { path = "../chime", features = ["matrix"] }
```

### 核心类型（无网络依赖）

```rust
use chime::{PushGatewayType, PushPreferences};

// 为中国用户创建 Bugle 网关偏好设置
let mut prefs = PushPreferences {
    enabled: true,
    gateway_type: PushGatewayType::Bugle,
    ..Default::default()
};
prefs.apply_gateway_type_defaults();

// 根据网关类型解析正确的 app ID
let app_id = prefs.android_app_id("app.example.android", "app.example.android.cn");
assert_eq!(app_id, "app.example.android.cn");

// 序列化为 JSON 用于持久化存储
let json = chime::to_json(&prefs).unwrap();
let loaded = chime::from_json(&json);
assert_eq!(loaded.gateway_type, PushGatewayType::Bugle);
```

### 推送器注册（需要 `matrix` 特性）

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

## 架构

```
Matrix 客户端（Synpad / Robrix / ...）
        |
        v
   ┌─────────┐     PushPreferences
   │  chime  │───> PushGatewayType { Sygnal, Bugle, Custom }
   └────┬─────┘     register_pusher() / unregister_pusher()
        |
        v
  Matrix 主服务器
        |
        v
  推送网关（Sygnal 或 Bugle）
        |
        ├── FCM ──> Android（全球）
        ├── APNs ─> iOS
        └── Bugle 国内厂商推送：
            ├── 极光推送 JPush（聚合层）
            ├── 华为推送 / 鸿蒙推送
            ├── 小米推送
            ├── OPPO / 一加推送
            ├── vivo 推送
            └── 荣耀推送
```

## 支持的中国厂商推送通道

Bugle 推送网关通过极光推送（JPush）的 `third_party_channel` 机制，将推送消息路由到以下国内安卓厂商的推送服务：

| 厂商   | 推送服务           | 说明 |
|--------|-------------------|------|
| 华为   | 华为推送（Push Kit） | 支持华为手机及鸿蒙系统设备 |
| 小米   | 小米推送（Mi Push）  | 支持小米/红米/POCO 手机 |
| OPPO   | OPPO 推送（OPlus Push） | 支持 OPPO/Realme 手机 |
| 一加   | 一加推送           | 复用 OPPO/OPlus 推送接口 |
| vivo   | vivo 推送          | 支持 vivo/iQOO 手机 |
| 荣耀   | 荣耀推送（Push Kit） | 支持荣耀手机 |
| 鸿蒙   | HarmonyOS 推送     | 通过 JPush 或华为推送支持 |

每个厂商通道均支持通过 Bugle 网关配置文件独立启用或禁用，也可以统一通过 JPush 聚合路由。

## 许可证

Apache 2.0 许可。详见 [LICENSE](LICENSE)。
