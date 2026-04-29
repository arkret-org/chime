# chime Active TODO

> 更新日期: 2026-04-29
> 范围: Contrix 客户端侧 push device registration SDK。`chime` 负责类型、builder、HTTP helper、本地持久化接口和可选 wire model；`cx.push.notify` 的真实网关投递属于 `floria`。

## 0. 当前边界

- [x] 已提供 Contrix push preferences、register/unregister request builder、可选 `http` feature 和 `ContrixPushClient`。
- [x] 已提供可选 `notify` feature 的 `cx.push.notify` wire model 和 blind-wakeup 校验。
- [x] 已提供本地 registration state、storage trait、push token hash/preview、token rotation plan。
- [ ] 当前实现仍处于 0.1 API shaping 阶段，未完成真实 Principal Server / Push Gateway 端到端联调。
- [ ] 不在本 crate 中实现 APNs/FCM/OEM 投递逻辑；服务端/网关 notify 类型只作为可选 wire model 提供。

## P0: Register / Unregister 协议契约

目标: 与 `contrix-spec/discovery/push-notifications.md` 和 `soland` wire contract 完全一致。

- [x] `cx.push.register_device` 请求字段冻结:
  - [x] `device_id`。
  - [x] `push_gateway`。
  - [x] `push_key`。
  - [x] `platform`。
  - [x] `app_id`。
  - [x] `display_name`。
  - [x] `idempotency_key`。
  - [x] `proof` caller-supplied hook。
- [x] `push_gateway` 语义:
  - [x] 表示 Principal Server 应使用的下游 Push Gateway endpoint。
  - [x] 必须是 HTTPS URL，loopback/dev profile 例外。
  - [x] 不得包含 access token、session token 或长期 secret query。
- [x] `push_key` 语义:
  - [x] 平台 token 原值由调用方传入。
  - [x] 支持 `fcm:`、`apns:`、`webpush:` 等前缀，但不强制破坏平台原 token。
  - [x] `Debug` / client debug / notify device debug 中脱敏。
- [ ] register response:
  - [x] 类型支持 `registration_id` 可选持久化。
  - [x] 类型支持 `expires_at` 可选语义。
  - [ ] duplicate same payload 幂等成功需要服务端 contract/E2E 验证。
  - [x] duplicate different payload 返回 `duplicate_conflict` 并分类为不可自动重试。
- [ ] `cx.push.unregister_device`:
  - [x] 支持按 `registration_id` 注销。
  - [x] 支持按 `device_id + app_id + push_key` 注销。
  - [ ] 未找到时仍可按幂等成功处理需要服务端 contract/E2E 验证。
  - [ ] 设备撤销后上层应主动调用 unregister 或接受服务端自动清理，需要下游集成确认。

并行性: request/response model、URL validation、HTTP behavior tests 已完成；字段仍需和 `soland` contract 最终对齐。

## P0: Authentication and Request Signing Hooks

目标: `chime` 不托管认证秘密，但提供安全注入点。

- [x] Bearer token helper:
  - [x] 仅使用 `Authorization` header。
  - [x] 禁止 query token。
  - [x] token 不进入 `ContrixPushClient` debug output。
  - [x] README 明确 audience/issuer/expiry 由调用方处理。
- [ ] DID proof hook:
  - [x] 调用方可注入 canonical proof body。
  - [x] proof transcript 包含 method、path、body digest、device_id、created_at、audience。
- [ ] HTTP Message Signature hook:
  - [x] 调用方可注入签名 header。
  - [x] method、target URI、content digest、device id、created/audience 的签名 transcript helper。
  - [ ] actor DID、expires 和最终 header 格式仍需上层 signer/contract 定稿。
- [x] Request metadata:
  - [x] `X-Contrix-Request-Id`。
  - [x] `Idempotency-Key`。
  - [x] User-Agent。
  - [x] SDK version。

## P0: HTTP Client Production Behavior

- [x] Client configuration:
  - [x] timeout。
  - [x] retry policy。
  - [x] custom reqwest client injection。
  - [x] base URL normalization。
  - [x] loopback HTTP dev override for `push_gateway`。
- [x] Error taxonomy:
  - [x] unauthenticated。
  - [x] capability_denied。
  - [x] rate_limited。
  - [x] temporarily_unavailable。
  - [x] duplicate_conflict。
  - [x] schema_violation。
  - [x] network_timeout。
  - [x] invalid_response。
- [ ] Retry behavior:
  - [x] 429 honors `Retry-After`。
  - [x] 503 honors `Retry-After`。
  - [x] timeout uses exponential backoff when enabled。
  - [x] duplicate_conflict is not auto-retried。
  - [x] unregister treats service `not_found` as idempotent success。
- [x] Response context:
  - [x] expose request id。
  - [x] expose retry-after。
  - [x] preserve raw Contrix error envelope for diagnostics。

## P1: Local State and Token Rotation

- [x] Provide storage trait for push registration state:
  - [x] `registration_id`。
  - [x] `device_id`。
  - [x] `app_id`。
  - [x] push gateway URL。
  - [x] push token hash / redacted preview。
  - [x] registered_at / expires_at。
- [x] Token rotation helper:
  - [x] detect changed platform token。
  - [x] unregister old token when available。
  - [x] register new token with idempotency key。
  - [x] keep old token redacted in debug/errors。
- [ ] Multi-device behavior:
  - [ ] same account multiple devices requires downstream app integration tests。
  - [ ] same device multiple apps/platforms requires downstream app integration tests。
  - [ ] reinstall flow requires downstream app integration tests。
  - [ ] device rename flow requires downstream app integration tests。

## P1: Optional Gateway Wire Models

目标: 只提供类型，不实现 provider 投递。

- [x] `cx.push.notify` request/response model behind optional `notify` feature。
- [x] `PushNotification` with body-free `push_hint`。
- [x] `PushNotificationDevice` with redacted debug。
- [x] `RejectedPushToken` / rejection reason。
- [x] Privacy validator:
  - [x] rejects message body。
  - [x] rejects encrypted payload bytes。
  - [x] rejects SDP / ICE / TURN credential。

## P1: Tests

- [x] Unit tests:
  - [x] Android + Bugle app id selection。
  - [x] iOS APNs app id selection。
  - [x] web / desktop platform。
  - [x] unknown platform error。
  - [x] empty `device_id` / `push_key` / `push_gateway`。
  - [x] legacy JSON alias migration。
  - [x] token redaction。
  - [x] URL query secret rejection。
  - [x] token rotation planning。
  - [x] notify blind-wakeup privacy validation。
- [x] HTTP mock tests:
  - [x] register success。
  - [x] unregister success。
  - [x] 400 schema violation。
  - [x] 401 unauthenticated。
  - [x] 403 capability_denied。
  - [x] 409 duplicate_conflict。
  - [x] 429 + `Retry-After`。
  - [x] 503 + `Retry-After`。
  - [x] non-JSON error body。
- [ ] End-to-end tests:
  - [ ] with `soland` register/unregister。
  - [ ] with `floria` provider mock through `cotest`。
  - [ ] token rotation。
  - [ ] multi-device registration。
  - [ ] E2EE blind wakeup payload。

## P1: Documentation and Release

- [x] README / README_zh:
  - [x] production setup example。
  - [x] auth injection example。
  - [x] retry/error handling example。
  - [x] token rotation example。
  - [x] E2EE blind wakeup warning。
  - [x] migration from legacy Matrix pusher terms。
- [x] rustdoc examples for public builders and client methods。
- [x] Crate metadata checked before tag。
- [x] Release gate:
  - [x] `cargo fmt -- --check`。
  - [x] `cargo test`。
  - [x] `cargo test --all-features`。
  - [x] `cargo clippy --all-features -- -D warnings`。
  - [x] `cargo doc --all-features --no-deps`。

## Definition of Done

- [ ] Register/unregister payloads pass Principal Server contract tests。
- [x] Tokens and bearer credentials are never printed in full by SDK debug output。
- [x] Retry and error behavior is deterministic and partially documented。
- [ ] Real `chask -> chime -> soland -> floria` flow is covered by `cotest` or equivalent E2E。
