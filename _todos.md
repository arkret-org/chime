# chime — Contrix Push SDK TODO

> 审计日期：2026-05-06
> 协议参考：`contrix-spec/zh/discovery/push-notifications.md` + `crypto-media/device-lifecycle.md` §5a Privacy-Preserving Push。
> 项目栈：Rust SDK，`feature = ["http", "notify"]`；提供给 yougen 等客户端消费。

## 标记说明

- 🅿 parallel-safe：单文件 / 单 type / 单 helper
- 🔒 sequential：动 lib.rs 顶层 re-export / DTO shape / state machine
- ⚠ high-risk：privacy boundary（DID 泄漏到 token / payload）/ wire-shape 破坏性变更
- 状态：`[ ]` 未做 · `[~]` 部分完成 · `[x]` 已完成

## 当前状态摘要

- **Crates / Features**：`chime`（默认） + `http`（`ContrixPushClient` / `register-device` / `unregister-device` / `bridge-describe` / `integration-describe` / `rotate_token`） + `notify`（gateway 侧 `cx.push.notify` wire 类型 + blind-wakeup 校验 + spec-strict `push_target_id`/`wakeup_kind` 校验）。
- **测试**：125 unit + 3 drift_gate + 5 property + 6 pseudonym_unlinkability + 6 README doctest 全绿；4 档 feature 矩阵（no-default / http / notify / all）全绿。
- **CI**：check / test / clippy / fmt / doc(-Dwarnings) / msrv(1.89) / typos / package(cargo publish --dry-run) / audit(rustsec) 已就位。
- **发布**：`Cargo.toml` 已含 keywords / categories / readme / homepage / documentation / exclude；docs.rs all-features；`.github/workflows/release.yml` 在 tag `v*.*.*` 时校验 + 发布 + 草稿 GitHub Release；`CHANGELOG.md` / `CONTRIBUTING.md` / `SECURITY.md` / `dependabot.yml` 全部就位。
- **协议补齐**：`PushTargetId` newtype（≥ 22-char base64url，拒 DID / 设备标识）+ `WakeupKind` enum（`message` / `incoming_call` / `mention` / `member` / `presence` / `Custom`）+ `validate_blind_wakeup_strict`；`PushRoute` typed wrapper（`route` / `push_target_id` / `push_gateway_did` / `encryption_key` / `capabilities` / `revoked`）+ active/revoked 状态机 + 不可关联性 integration test。

---

# 阶段 G · GitHub / Publish / Release（本轮新增，优先级最高）

| # | 任务 | 状态 | 涉及文件 |
|---|---|---|---|
| G1 🅿 | **README typo 修复**：删除 `chime::try_from_json` 引用，仅留 `from_json`。 | `[x]` | `README.md`、`README_zh.md` |
| G2 🅿 | **Cargo.toml 发布元信息**：补 `keywords` / `categories` / `readme` / `homepage` / `documentation` / `exclude` + `[package.metadata.docs.rs]` all-features。 | `[x]` | `Cargo.toml` |
| G3 🅿 | **typos.toml 清理**：移除复制粘贴噪声（`AttributeIDSupressMenu`、`Hashi`），改为 Contrix 项目专用词汇 + `target/`+`Cargo.lock` exclude。 | `[x]` | `typos.toml` |
| G4 🅿 | **Release 工作流**：`.github/workflows/release.yml` push tag `v*` 触发，`verify` 校验 tag 与 Cargo.toml 版本一致 + `cargo publish --dry-run`，`publish` 在 `crates-io` environment 下走真发布，`github_release` 拉 CHANGELOG 段做 draft release。 | `[x]` | `.github/workflows/release.yml` |
| G5 🅿 | **`cargo package` CI job**：`ci.yml` 增 `package` job，跑 `cargo package --no-verify --allow-dirty` + `cargo publish --dry-run --allow-dirty --all-features`。 | `[x]` | `.github/workflows/ci.yml` |
| G6 🅿 | **`cargo audit` CI job**：增 `audit` job，使用 `rustsec/audit-check@v2.0.0`。 | `[x]` | `.github/workflows/ci.yml` |
| G7 🅿 | **`SECURITY.md`**：私下漏洞披露通道（GitHub Security Advisory + 邮件）、supported versions、隐私边界报告范围。 | `[x]` | `SECURITY.md` |
| G8 🅿 | **`CONTRIBUTING.md`**：本地命令、feature 矩阵跑法、commit prefix `chime: ...` 约定、PR 检查项、隐私边界规则、release 流程。 | `[x]` | `CONTRIBUTING.md` |
| G9 🅿 | **`CHANGELOG.md`**：Keep-a-Changelog；`Unreleased` 段记录本轮 G 项；`0.1.0` 段汇总当前落地能力。 | `[x]` | `CHANGELOG.md` |
| G10 🅿 | **README 部署 / 配置 / 启动小节**：`Configuration & Operations` 覆盖 HTTPS / loopback / WebPush allowlist / session-grant fail-closed / idempotency / 重试策略 / 令牌存储 / 隐私门控 / tracing target / 故障排查表。中英双语都补。 | `[x]` | `README.md`、`README_zh.md` |
| G11 🅿 | **Dependabot**：`.github/dependabot.yml` 启用 cargo + github-actions 周更新。 | `[x]` | `.github/dependabot.yml` |
| G12 🅿 | **修复 `cargo doc -Dwarnings`**：`push/client.rs` 的 `MissingField("session_grant")` 链接形态不合法、`notify.rs` 引用了不存在的 `validate_hint` 锚点。改为合法的 intra-doc link，CI `doc` job 现在跑 `-Dwarnings` 不会爆。 | `[x]` | `src/push/client.rs`、`src/notify.rs` |

# 阶段 P · Protocol Spec 对齐（破坏性，优先级 P0 但 SemVer 风险）

| # | 任务 | 状态 | 涉及文件 |
|---|---|---|---|
| P1 ⚠ | **`push_target_id` + `wakeup_kind` 补齐（additive）**：`PushTargetId` newtype（`cx:pseudonym:push:` 或 raw base64url，22..128 chars，拒 DID / 设备标识 / 其他 typed-id 前缀）+ `WakeupKind` enum；`PushNotification` 加 Optional 字段；`validate_blind_wakeup_strict` 要求两者；`validate_wire_model` 接受 `type` 或 `wakeup_kind` 任一；drift_gate fixture 不变（仍用 `type` 路径）。**未做**：drift_gate fixture 升级到 spec 形态、`type` 字段标 deprecated（留给 0.2 minor）。 | `[x]` | `src/notify.rs` |
| P2 ⚠ | **`cx.device.push_route` typed wrapper**：`PushRoute { route, push_target_id, push_gateway_did, encryption_key, capabilities, revoked, metadata }` + active/revoked 状态机 + `PushRouteId` 强类型 + `PushRouteCapability` enum。default-feature 与 notify-feature 都能编译（payload 字段在 notify 下走 `PushTargetId`，否则降级为 `String`）。 | `[x]` | `src/push_route.rs` |
| P3 🅿 | **`push_target_id` 不可关联性 integration test**：`tests/pseudonym_unlinkability.rs` 6 个 case 锁 SDK 拒绝 DID / device_id / push_key / 邮箱 / 电话进伪名；同 device 两条 route 持不同 pseudonym；serde round-trip 字节级保留。 | `[x]` | `tests/pseudonym_unlinkability.rs` |

# 阶段 1 · Phase 1 残留

| # | 任务 | 状态 | 涉及文件 |
|---|---|---|---|
| Q2 🅿 | **per-type `#[doc]` 稳定级别注解**：`PushGatewayType` / `PushPreferences` / `PushPlatform` / `PushDeviceConfig` / `PushErrorKind`（顺手 `#[non_exhaustive]`）/ `PushRegistrationState` 都补了 `Stability: 0.x-stable` 注。 | `[x]` | `src/lib.rs`、`src/push/wire.rs`、`src/push/errors.rs`、`src/state/model.rs` |
| Q3 🅿 | **property test**：5 个 proptest（register roundtrip 不 panic / unregister 不回写 push_key / hash_push_key 确定性 + 不暴露 token / blind-wakeup 拒 sensitive keys / push_target_id serde 字节级 round-trip）。`proptest` 入 dev-dep。 | `[x]` | `tests/property.rs` |

# 阶段 2 · Phase 2 残留

| # | 任务 | 状态 | 涉及文件 |
|---|---|---|---|
| E1 🅿 | **HTTP retry policy 微调**：`PushRetryPolicy::with_disabled_kinds(&[PushErrorKind::TemporarilyUnavailable])` 与 `retries_disabled_for(kind)` 落地；用 `disabled_kinds_mask: u32` bitmask + `PushErrorKind::ordinal()` 手工编号让 `#[non_exhaustive]` 添加变体不破 mask 语义。 | `[x]` | `src/push/client.rs`、`src/push/errors.rs` |
| A2 🅿 | **顶层 `rotate_token(old, new)` 客户端方法**：`ContrixPushClient::rotate_token(existing, config, prefs, strategy)` —— 调用 `plan_token_rotation_with_strategy` 决定是否要换，再按 `UnregisterOldFirst` / `RegisterNewFirst` 顺序 wrap register/unregister。Token 未变返回 `Ok(None)`。 | `[x]` | `src/push/client.rs` |
| E3 🅿 | **`PushPreferencesStore` trait**：`load_push_preferences` / `save_push_preferences` / `clear_push_preferences`（默认 impl 写回 default 值）；in-memory tests 锁 trait 形态。 | `[x]` | `src/state/model.rs` |

# 阶段 3 · Phase 3 残留

| # | 任务 | 状态 | 涉及文件 |
|---|---|---|---|
| B2 🅿 | **`provider_capabilities` 字段扩展**：当前 `PushBridgeDescribeNotifyDescriptor` 已暴露 `supports_dedup` / `dedup_window` / `rate_limit_window` / `rate_limits_by` / `max_request_size`；server-side `provider_capabilities`（细粒度 per-provider FCM/APNs/Bugle 能力）尚未在 floria 出现。**阻塞外部**：等 floria 仓库的 bridge/describe wire shape 落地相应字段后再扩展。 | `[~]` | `src/push/bridge_describe.rs` |
| A3 🅿 | **multi-gateway 注册（additive）**：新增 `GatewayBinding { gateway_type, push_gateway, push_key, app_id }` + `PushPreferences::gateways: Vec<GatewayBinding>` 字段（默认空，向后兼容）+ `effective_gateways()` helper（空表 fallback 到单 gateway 旧路径）+ `ContrixPushClient::register_device_all` 并行尝试每个 binding，返回 `Vec<Result<...>>` 让 partial-failure 可见。每条 binding 独立 token / app_id 覆盖。**未做**：state/registration.rs 的多路状态合并需要更细的 plan_registration_repair 适配，留给 0.2。 | `[x]` | `src/gateway_binding.rs`、`src/lib.rs`、`src/push/client.rs` |

# 阶段 4 · 新模块面（独立 feature；本 crate 范围外）

> chime 的 crate description 是 *Contrix push notification gateway types and device registration helpers*。
> D1/D2/D3 都是 **非 push** 协议面（`cx.schema.device_message.v1` / `cx.key.verification.*` / `cx.schema.key_backup.v1`），把它们塞进 chime 会拉低 crate 内聚度并且 docs.rs 列表会让"我只想用 push helper"的下游消费方困惑。
> **结论**：这三项不在 chime 的范围内，应作为独立 crate（如 `chime-keys`）或并入 `contrix-rust-sdk`。本 todo 列表保留只是为了日后跨仓追踪。

| # | 任务 | 状态 | 文件 |
|---|---|---|---|
| D1 🅿 | **`device_messages` SDK surface**：`cx.schema.device_message.v1` 的 typed wrapper + `send/receive` helper（对应 soland `/api/v1/device_messages/*`）。 | `[ ]` (out-of-scope) | 单独 crate / contrix-rust-sdk |
| D2 🅿 | **`cx.key.verification.*` SDK helper**：SAS / QR ceremony 一次性消费 + replay 阻挡。 | `[ ]` (out-of-scope) | 单独 crate / contrix-rust-sdk |
| D3 🅿 | **`key_backup` SDK surface**：`cx.schema.key_backup.v1` typed wrapper + restore-ticket SDK 客户端。 | `[ ]` (out-of-scope) | 单独 crate / contrix-rust-sdk |

# 阶段 5 · 集成 / 跨仓

| # | 任务 | 状态 | 文件 |
|---|---|---|---|
| S1 🔒 | 与 yougen 集成：把 yougen 当前手写的 push register 路径替换成 `chime::ContrixPushClient`。 | `[ ]` (cross-repo) | yougen 仓 |
| S2 🅿 | 与 cotest 联调：cotest 的 push 黑盒向量复用 chime 的 typed reject helper（`shared_push_notify_privacy_vectors()`）。 | `[ ]` (cross-repo) | cotest 仓 |
| S3 🅿 | 文档 round-trip：`#[doc = include_str!("../README.md")]` 挂在 `cfg(doctest)` 上；README 的 4 个 `,ignore` 块按需跳过，2 个无标记块（Core types / Build registration body）每次 `cargo test --doc` 编译并执行。 | `[x]` | `src/lib.rs` |

---

## 依赖关系图

```
G1..G12 ✅                ← GitHub 基础设施 / Publish ready

P1 ⚠ → P2 → P3            ← 协议层 follow-up（破坏性变更）

Q2/Q3                     ← 测试与文档收敛（小风险）

E1 / A2 / E3              ← 易用性 polish

B2                        ← 等 floria 侧 spec 落地后再动（外部阻塞）

D1..D3                    ← 不在 chime 范围内（独立 crate / contrix-rust-sdk）
S1, S2                    ← 跨仓，依赖 yougen / cotest 仓库窗口
```

## 不在本轮范围

- 桌面通知桥接的具体平台实现（macOS NSUserNotification / Windows Toast / Linux libnotify）— 由 yougen 各端组合做
- HarmonyOS / iOS native push 客户端绑定 — 跨仓 native 组件
- 端到端 E2EE 媒体下载（属于客户端 / soland blob 边界）
