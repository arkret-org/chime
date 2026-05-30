# 错误码处理

chime 将网关/协议失败归一到 `PushErrorKind`。调用方应优先按 kind 分支，
保留原始 HTTP body 供排障。

## 注册与网关

| Kind | 处理建议 |
| --- | --- |
| `MissingField` / `InvalidPlatform` / `InvalidPushGatewayUrl` | 本地配置错误，直接 fail-fast，提示开发或配置修复。 |
| `WebPushEndpointNotAllowed` | WebPush endpoint origin 未在 allowlist 中，更新配置后重试。 |
| `Unauthenticated` | 刷新 bearer/session grant 后重试。 |
| `CapabilityDenied` | 当前 principal 或 device 没有权限，不要自动重试。 |
| `RateLimited` / `TemporarilyUnavailable` | 按 `Retry-After` 和 `PushRetryPolicy` 退避重试。 |
| `DuplicateConflict` | 幂等冲突；确认 idempotency key 后再决定是否重发。 |
| `Gone` | push token 或 registration 已失效，丢弃本地状态并重新注册。 |

## media token / CXP-0010

`is_media_token_rejection()` 覆盖 yougen call UI 最常见的五类失败：

| Kind | 含义 |
| --- | --- |
| `FocusMismatch` | 请求 focus、binding focus 或 committed session focus 不一致。错误字段包含 `requested_focus_id`、`binding_focus_id`、可选 `committed_focus_id`。 |
| `UnknownFocusType` | SDK 不认识该 media backend，必须 fail-closed。 |
| `TokenIssuerUnauthorised` | `participant_binding.issuer_kid` 未锚定到当前 realm media service。 |
| `ParticipantBindingInvalid` | participant tuple 或 TTL 不合法。当前 chime 不在这里完成 Ed25519 验签。 |
| `LegacySingleEndpointMediaService` | realm 仍是旧单端点 media service，不能执行多 focus token exchange。 |

其它 media-binding kind 可用 `is_media_binding_code()` 归类到同一遥测桶。

## Round 4 delivery binding

- `DeliveryBindingStale` / `DeliveryBindingHandedOver`：停止向旧 recipient
  发送，重新解析当前 binding。
- `HistoricalOnly`：只作为诊断响应，不要触发新的 reducer 副作用、push
  fanout 或重试。

## agent lifecycle

`is_agent_lifecycle_code()` 覆盖 agent pause/deactivate、proof invalid、approval
consumed 等终态或策略失败。通常不应自动重试，应把原因交给账号/agent UI。
