# yougen 集成指南

## 注册 push 设备

1. 从平台 SDK 取得 push token，保留传输前缀，例如
   `fcm:<token>`、`apns:<token>`、`unifiedpush:<endpoint>`。
2. 构造 `PushDeviceConfig`，其中 `device_id`、`push_key`、`platform`、
   `app_id` 来自 host。Android 国内 OEM 路由可同时提供
   `domestic_app_id`。
3. 为每个网关构造 `GatewayBinding`，再调用
   `build_register_device_request(&config, &binding, &prefs)`。
4. 通过 `CokretPushClient` 或 host 自己的 HTTP 栈发送请求。

Bugle 说明：host 仍负责华为/小米/OPPO/vivo/HONOR/HarmonyOS/JPush SDK
接入和 token 获取。chime 只负责 wire shape。需要单独解析 app id 时可用
`chime::bugle::BugleAppIdResolver`；Android 优先 `domestic_app_id`。

## 接收 push wakeup

`PushNotification.extra` 使用 `#[serde(flatten)]`，serde 会把未知字段放进
`extra`，不会在反序列化时拒绝。因此：

1. 反序列化 `PushNotifyReqBody`。
2. 立即调用 `assert_payload_safe(&PushNotifyPolicyContext::blind_wakeup_only())`
   或更具体的 `validate_blind_wakeup` / `validate_wire_model`。
3. 只有 validator 通过后，才可以读字段、入队、唤醒 UI 或调度后台同步。

## media token / SFrame

调用流程：

1. `call_media_token_exchange(...)` 构造 token exchange 请求。
2. 收到 `MediaTokenResponse` 后调用
   `structurally_validate_media_token_response(&response, &ctx)`。
3. 成功返回的是 `StructurallyValidatedMediaTokenResponse`，只表示
   issuer anchor、participant tuple、TTL 已通过结构校验。
4. yougen/host 必须用 realm media-service Ed25519 公钥验证
   `service_signature` 和 `participant_binding.sig`。
5. 只有签名验证通过后，才允许进入 SFrame keying。

## drift 检查

`bridge_describe()` 返回的 `spec_version` 应与
`chime::EXPECTED_SPEC_VERSION` 一致。smoke test 应在不一致时失败，而不是
继续注册设备。
