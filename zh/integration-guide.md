# inkson 集成指南

## 注册 push 设备

1. 从平台 SDK 取得 push token，保留传输前缀，例如
   `fcm:<token>`、`apns:<token>`、`unifiedpush:<endpoint>`。
2. 构造 `PushDeviceConfig`，其中 `device_id`、`push_key`、`platform`、
   `app_id` 来自 host。Android 国内 OEM 路由可同时提供
   `domestic_app_id`。
3. 为每个网关构造 `GatewayBinding`，再调用
   `build_register_device_request(&config, &binding, &prefs)`。
4. 通过 `ArkretPushClient` 或 host 自己的 HTTP 栈，只向已登录账户自己的
   Station 发送请求。Gateway URL 只进入注册字段，不是客户端 HTTP 目标。

Bugle 说明：host 仍负责华为/小米/OPPO/vivo/HONOR/HarmonyOS/JPush SDK
接入和 token 获取。chime 只负责 wire shape。app id 解析走
`GatewayBinding::resolve_app_id`；Android Bugle 路由优先 `domestic_app_id`。

客户端不得直连 Gateway 读取 `ServiceDescribe`、VAPID 或 provider endpoint，
也不得把 bearer/session grant 转发给 Gateway。Gateway capability 与 durable
receipt 由 Station 侧 handoff 编排验证。
