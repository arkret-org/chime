# inkson 集成指南

## 注册 push 设备

1. 从平台 SDK 取得 push token，保留传输前缀，例如
   `fcm:<token>`、`apns:<token>`、`unifiedpush:<endpoint>`。
2. 构造 `PushDeviceConfig`，其中 `device_id`、`push_key`、`platform`、
   `app_id` 来自 host。Android 国内 OEM 路由可同时提供
   `domestic_app_id`。
3. 为每个网关构造 `GatewayBinding`，再调用
   `build_register_device_request(&config, &binding, &prefs)`。
4. 通过 `ArkretPushClient` 或 host 自己的 HTTP 栈发送请求。

Bugle 说明：host 仍负责华为/小米/OPPO/vivo/HONOR/HarmonyOS/JPush SDK
接入和 token 获取。chime 只负责 wire shape。app id 解析走
`GatewayBinding::resolve_app_id`；Android Bugle 路由优先 `domestic_app_id`。

## drift 检查

push gateway 通过 `service_describe()` 发现 canonical role capability。smoke test
应在 `ServiceDescribe` 无效、service kind 错误或缺少 push notify operation bundle 时失败，
而不是继续注册设备。
