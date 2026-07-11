# 生产检查清单

## 编译与协议

- 生产构建启用 `--features http,notify`。
- 协议发现走 `server_describe()`；floria 适配层的
  `floria_bridge_describe().spec_version` 必须匹配 `chime::EXPECTED_SPEC_VERSION`。
- 当前 chime 审计目标是 `arkret-spec @ 5d66aeb`；升级协议头前需要重新跑
  drift gate 和集成 smoke test。

## push payload 安全

- 任意 `PushNotifyRequestBody` / `PushNotification` 反序列化后，必须立即调用
  `assert_payload_safe`、`validate_blind_wakeup` 或 `validate_wire_model`。
- 默认使用 `PushNotifyPolicyContext::blind_wakeup_only()`。
- 不要把 title、body、sender display name、space/realm display name 或
  Circle 成员列表放进 blind wakeup。
- `PushNotification.extra` 是未信任扩展字段；validator 通过前不要读取。

## media token

- SFrame keying 前必须调用 `verify_media_token_outcome`。
- `MediaTokenVerificationContext` 必须包含原始 token exchange 请求和当前
  `MediaServiceAnchors`，以验证 `service_signature` 和 `participant_binding.sig`。
- `FocusMismatch` 日志应记录 requested、binding、committed 三个 focus 字段。

## replay / nonce

- `NonceTracker` 是内存、单实例 tracker。
- 服务端 relay、集群 worker、重启后仍接收 inbound frame 的 host 必须把
  `(origin_service_id, nonce)` 或 `(device_id, nonce)` 写入共享持久化存储，
  保存时间至少覆盖 replay window。
- 时钟回拨按 duplicate 等价处理，应该 fail-closed 并报警。

## Bugle / 国内 OEM

- host 负责 OEM provider SDK 接入和 token 获取。
- Android Bugle 路由优先使用 `domestic_app_id`；可用
  `chime::bugle::BugleAppIdResolver` 或 host 自定义 resolver。
- 每个 gateway binding 独立注册、独立重试、独立保存 registration state。
