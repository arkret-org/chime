# chime — Contrix Push SDK TODO

> 审计日期：2026-05-05
> 协议参考：`contrix-spec/zh/discovery/push-notifications.md` + `crypto-media/encryption-and-audit.md`（push privacy boundary）。
> 项目栈：Rust SDK，`feature = ["http", "notify"]`；提供给 yougen 等客户端消费。

## 标记说明

- 🅿 parallel-safe：单文件 / 单 type / 单 helper
- 🔒 sequential：动 lib.rs 顶层 re-export / DTO shape / state machine
- ⚠ high-risk：privacy boundary（DID 泄漏到 token / payload）
- 状态：`[ ]` 未做 · `[~]` 部分完成 · `[x]` 已完成

## 当前状态摘要

- **Crates / Features**：`chime`（默认） + `http`（`ContrixPushClient`，调用 soland `register-device` / `unregister-device`） + `notify`（gateway 侧 `cx.push.notify` wire 类型 + blind-wakeup 校验）。
- **核心模块**（拆分后）：`lib.rs`（389） + `notify.rs`（1190） + `push/{mod,wire,bridge_describe,errors,signing,urls,registration,client}.rs`（共 3.3K，最大 client.rs 1010 行含 mock server tests） + `state/{mod,model,rotation,repair,test_fixtures}.rs`（共 950 行）。
- **现有能力**：`PushGatewayType` / `PushPreferences`、register/unregister 请求构建器、`http` feature 下的 `ContrixPushClient`（含自动生成 idempotency-key 回退）、`notify` feature 下的 wire DTO、blind-wakeup legacy reject（`room_id` / `card_id` / `subject_id` + active-field + sender legacy typed-id），`bridge/describe` 消费 + `IntegrationView` 聚合 + `PushErrorKind::from_failure_code` 失败码映射（含 410 Gone）。
- **测试**：73 unit + 4 doctest 全绿；4 档 feature 矩阵（no-default / http / notify / all）全部 build 通过。
- **README 警示**：项目处于早期，API 可能变更（response 类型已加 `#[non_exhaustive]`，扩字段不破 SemVer）。

---

# 执行阶段（按依赖排序）

## Phase 0 · 架构性重构（阻塞所有 P1+）

> push.rs 3072 行 / state.rs 888 行单文件膨胀；F1/F2 拆完后 P1 的 wire / errors / state subtask 才有具体落点。

| # | 任务 | 状态 | 涉及文件 |
|---|---|---|---|
| F1 🔒 | **push.rs 拆分**：`src/push.rs`（3072 行）按职能拆 `push/{wire,bridge_describe,errors,signing,urls,registration,client}.rs`，每个文件 < 700 行；`push/mod.rs` 仅做 path/header 常量与 re-export。`lib.rs` 公开签名保持不变。 | `[x]` | `src/push.rs` → `src/push/*.rs` |
| F2 🔒 | **state.rs 拆分**：`src/state.rs`（888 行）拆 `state/{model,rotation,repair}.rs`；`state/mod.rs` 做 re-export；`state/test_fixtures.rs` 共享 `cfg(test)` fixture。 | `[x]` | `src/state.rs` → `src/state/*.rs` |

## Phase 1 · 契约/边界稳定化（依赖 Phase 0）

> 拆完后再冻结 wire shape、补齐 error / privacy gate；这一组直接关系到下游 yougen 消费的 stable 边界。

### Phase 1a · Wire / Error 收敛

| # | 任务 | 状态 | 文件 |
|---|---|---|---|
| A1 🔒 | **register/unregister model 冻结**：response 类型加 `#[non_exhaustive]`（前向兼容字段添加）；request 类型保持 struct-literal 可构造但加 0.x-stable doc 注；wire.rs 顶部 module-doc 写明 stability 契约。 | `[x]` | `push/wire.rs` |
| A4 🅿 | **register failure classification**：`PushErrorKind` 覆盖 401/403/404/409/410/422/429/503；新增 `PushErrorKind::Gone` 变体处理 token 撤销语义。 | `[x]` | `push/errors.rs` |
| B3 🅿 | **failure_codes 映射**：`PushErrorKind::from_failure_code(&str) -> Option<PushErrorKind>`；`classify_http_error` 改用此函数；映射涵盖 unauthenticated / capability_denied / rate_limited / temporarily_unavailable / duplicate_conflict / not_found / gone / registration_gone / push_token_gone / schema_violation 系列。 | `[x]` | `push/errors.rs` |
| F3 🅿 | **API 稳定性 banner 转正**：README + README_zh 替换为 `0.x` SemVer 承诺，明示 response 类型 `#[non_exhaustive]` + 加法演进；wire.rs module-doc 也写明 stability 契约。每个 public type 的稳定级别 `#[doc]` 注解延后到 Q2 文档轮一起做。 | `[x]` | `README.md`、`README_zh.md`、`push/wire.rs` |

### Phase 1b · Privacy / Blind-Wakeup（C1/C3 是 release gate）

| # | 任务 | 状态 | 文件 |
|---|---|---|---|
| C1 ⚠ | **DID 不进 payload / token**：扩展 `assert_payload_safe(&Notification, &PolicyContext)`，在 SDK 层强制；调用方传入 `plaintext_visible_services` 集合；失败 → `PushNotifyPrivacyError::DidLeaked`。 | `[ ]` | `notify.rs` |
| C2 🅿 | **active-field legacy typed-id reject**：原已覆盖 `flow_id = cx:card:*` / `event_id` / `space_id` 前缀强制；本轮扩展 `sender` 字段：若值为 `cx:room:*` / `cx:card:*` / `cx:subject:*` → `LegacyField`。 | `[x]` | `notify.rs` |
| C3 🅿 | **`push_hint` body-free 强制**：`validate_hint` 已拒绝 title/body/space_name/sender_display_name 与 SDP/ICE/TURN 标记；新增 `PushHint` 强类型 builder 会破坏 `push_hint: "New message"` 这类已用例和共享 privacy vector，需要先和 floria 协调，**本轮不做**。 | `[ ]` | `notify.rs` |

## Phase 2 · 可靠性 / 客户端体验（依赖 Phase 0；与 Phase 1 并行安全）

| # | 任务 | 状态 | 文件 |
|---|---|---|---|
| E1 🅿 | **HTTP retry policy**：`PushRetryPolicy` 已有骨架；429 走 `Retry-After`、5xx 指数退避、上限保护、jitter — 本仓已实现；进一步可补 429 jitter 上限策略 / 关闭重试细粒度控制。 | `[~]` | `push/client.rs` |
| E2 🅿 | **idempotency-key 注入**：caller 不提供且无 default 时，`post_json` 自动生成 `cx-sdk-<sha256-hex>` 形式 key；同一逻辑请求所有 retry 共用同一 key（`generate_idempotency_key()` 在 retry 循环外调用一次）；retry safety check 简化为 "总是安全"，因为现在永远有 idempotency key。 | `[x]` | `push/client.rs` |
| A2 🅿 | **token rotation**：当前一次性注册；扩展 `rotate_token(old, new)`，调用 soland `register-device` 时携带 `previous_token_hash`（与 soland Stream F-9 联动）。 | `[ ]` | `push/registration.rs` |
| A5 🅿 | **session-grant binding**：register 请求强制带 soland session-grant + audience；bridge mismatch fail closed。 | `[ ]` | `push/registration.rs` |
| E3 🅿 | **本地状态持久化抽象**：`PushRegistrationStore` trait 已存在（`state/model.rs`），提供 load / save / clear / list 默认实现，调用方可基于 keychain / sqlite 实现；in-memory fallback 通过 trait default impls 已就位。`PushPreferences` 的对应 trait 后续按需补。 | `[~]` | `state/model.rs` |

## Phase 3 · Bridge Discovery / 多 gateway（依赖 Phase 0、可并 Phase 1/2）

| # | 任务 | 状态 | 文件 |
|---|---|---|---|
| B1 🅿 | **`integration_describe()` SDK helper**：新增 `IntegrationView { manifest, bridge }` 类型 + `IntegrationView::requires(service, purpose)` / `contract_digest()` 便利方法；`ContrixPushClient::integration_view()` async 方法顺序拉取并合并；任一失败短路。 | `[x]` | `push/bridge_describe.rs`、`push/client.rs` |
| B2 🅿 | **多 gateway 自动 capability negotiation**：根据 `bridge/describe` 的 `provider_capabilities` 决定是否启用 batch / TTL / collapse_key / topic-fanout。 | `[ ]` | `push/client.rs` |
| B4 🅿 | **contract digest cache**：本地缓存 `bridge/describe` 的 `contract_digest`，drift 时 emit warning（不强制阻断，由调用方决定）。 | `[ ]` | `state/bridge_cache.rs` |
| A3 🅿 | **multi-gateway 注册**：客户端可同时注册到多个 gateway（standard + bugle + custom）；`PushPreferences` 的 `gateways: Vec<GatewayBinding>`。 | `[ ]` | `lib.rs`、`state/registration.rs` |
| C4 🅿 | **encrypted envelope handoff**：`notify` feature 下的 wire 类型与 `contrix-rust-sdk` 的 `EncryptedEnvelope` 对齐；DID-bound payload 进 envelope，绝不裸传。 | `[ ]` | `notify.rs` |

## Phase 4 · 新模块面（D 系列；独立 feature 拆分）

> 与现有 push 路径无耦合，可单独 feature gate 推进。

| # | 任务 | 状态 | 文件 |
|---|---|---|---|
| D1 🅿 | **`device_messages` SDK surface**：补 `cx.schema.device_message.v1` 的 typed wrapper + `send/receive` helper；对应 soland `/api/v1/device_messages/*`。 | `[ ]` | 新 `src/device_messages.rs` |
| D2 🅿 | **`cx.key.verification.*` SDK helper**：SAS / QR ceremony 一次性消费 + replay 阻挡。 | `[ ]` | 新 `src/key_verification.rs` |
| D3 🅿 | **`key_backup` SDK surface**：`cx.schema.key_backup.v1` typed wrapper + restore-ticket SDK 客户端。 | `[ ]` | 新 `src/key_backup.rs` |

## Phase 5 · 集成 / CI / 测试覆盖

| # | 任务 | 状态 | 文件 |
|---|---|---|---|
| F4 🅿 | **drift gate**：`bridge/describe` DTO 与 `floria` 真实 schema 在 CI 做对齐测试；任何字段漂移 fail closed。 | `[ ]` | `tests/*`、`.github/workflows/*` |
| Q1 🅿 | feature 矩阵 CI：`check` + `test` + `clippy` 三个 job 各跑 `""` / `"http"` / `"notify"` / `"http,notify"` 四档；MSRV bump 到 1.89（`Cargo.toml` 一致）。 | `[x]` | `.github/workflows/ci.yml` |
| Q2 🅿 | 文档：每个 public type 加 `#[doc]` 稳定级别注解；deeper API doc。F3 已完成 README banner，本项剩 per-type `#[doc]` 标注。 | `[~]` | `lib.rs`、`push/wire.rs`、`state/model.rs` |
| Q3 🅿 | property test：register/unregister roundtrip + bridge describe parse roundtrip + notify privacy gate。 | `[ ]` | `tests/*` |
| Q4 🅿 | `typos.toml` 已存在 + CI 加上 `crate-ci/typos@master` job。 | `[x]` | `.github/workflows/ci.yml` |
| S1 🔒 | 与 yougen 集成：把 yougen 当前手写的 push register 路径替换成 `chime::ContrixPushClient`。 | `[ ]` | 跨仓 |
| S2 🅿 | 与 cotest 联调：cotest 的 push 黑盒向量复用 chime 的 typed reject helper。 | `[ ]` | 跨仓 |
| S3 🅿 | 文档 round-trip：README 中所有 example code block 都跑 `cargo doc-test`。 | `[ ]` | `README*.md`、CI |

---

## 依赖关系图

```
Phase 0 (F1, F2)
   ├─→ Phase 1a (A1, A4, B3, F3)
   ├─→ Phase 1b (C1, C2, C3)         ← release gate
   ├─→ Phase 2  (E1, E2, A2, A5, E3)
   ├─→ Phase 3  (B1, B2, B4, A3, C4)
   └─→ Phase 4  (D1, D2, D3)         ← 独立模块面
                  ↓
              Phase 5 (F4, Q1..Q4, S1..S3)
```

**关键阻塞点**：
- F1/F2 拆分先于 P1 sub-task（不然 push/wire.rs / push/errors.rs 没有真实落点）
- A1（register model 冻结）→ A2..A5 全依赖
- C1（DID payload privacy gate）→ release gate
- D1..D3 必须等 contrix-rust-sdk 高层 DTO scaffold 稳定（已基本完成）

## 不在本轮范围

- 桌面通知桥接的具体平台实现（macOS NSUserNotification / Windows Toast / Linux libnotify）— 由 yougen 各端组合做
- HarmonyOS / iOS native push 客户端绑定 — 跨仓 native 组件
- 端到端 E2EE 媒体下载（属于客户端 / soland blob 边界）
