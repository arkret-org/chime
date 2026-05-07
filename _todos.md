# chime TODO

> 整理日期: 2026-05-07
> 范围: Contrix Push SDK。非 push 的 device-message / key-backup / verification helper 归 `contrix-rust-sdk` 或独立 crate。

## 当前状态摘要

- Push SDK 的注册、注销、token rotation、blind wakeup privacy validation、push route wrapper、multi-gateway register + state repair、cotest 隐私向量、feature matrix、docs/release 基础设施已经完成。
- 本仓当前没有 P0 编译或发布阻塞。
- 剩余任务全部依赖外部仓：C1（floria capabilities 字段冻结）以及 P2 的 yougen/cotest/floria 集成窗口。

## 标记说明

- `[ ]` 未完成
- `[~]` 部分完成 / 外部阻塞
- `🅿` parallel-safe
- `🔒` sequential
- `⚠` privacy / wire contract 高风险

## P0 · 本仓阻塞项

当前无本仓 P0 阻塞。

## P1 · Push 协议与 SDK surface

| # | 状态 | 任务 | 文件 | 说明 |
|---|---|---|---|---|
| C1 🅿 | `[~]` | 消费 `provider_capabilities` 细粒度矩阵 | `src/push/bridge_describe.rs` | 现在已有 coarse fields；等 `floria` E1 冻结 per-provider batch / TTL / collapse / badge/default payload 等字段后扩展。**外部阻塞 floria。** |
| C2 🅿 | `[x]` | multi-gateway registration state repair | `src/state/repair.rs`、`src/state/mod.rs`、`src/lib.rs` | 新增 `plan_multi_gateway_repair` + `PushMultiGatewayRepairPlan`：每个 binding 拿到自己的 `PushRegistrationRepairPlan`（按 `push_gateway` 过滤 owned states），被移除的 gateway 残留 state 暴露成 `orphan_states` + 预先构造好的 `unregister_orphans`。 |
| C3 🅿 | `[x]` | 导出 cotest 可复用 privacy vector helper | `src/notify.rs`、`src/lib.rs` | `shared_push_notify_privacy_vectors()` 已经在 `feature = "notify"` 下导出（含 7 条 typed reject case），README / CONTRIBUTING 标注 cotest / floria 复用方式；内部 `shared_privacy_vectors_match_validator_outcomes` 测试锁住向量与 validator 输出一致。 |

## P2 · 跨项目集成责任

| # | 状态 | 任务 | 本仓责任 | 根任务 |
|---|---|---|---|---|
| I1 🔒 | `[ ]` | `yougen` 替换手写 push register 为 `ContrixPushClient` | client API 已覆盖 register/unregister/rotate/bridge describe/multi-gateway；等 yougen 仓接入窗口。 | C4 |
| I2 🅿 | `[ ]` | `cotest` 复用 chime privacy vectors | helper 已经在 `notify` feature 下稳定导出；等 cotest 仓接入窗口。 | C4 / C8 |
| I3 🅿 | `[ ]` | 与 `floria` bridge/describe 版本协商 | provider capabilities 字段冻结后更新 typed descriptor 和 serde round-trip。 | C4 |

## 不在本仓范围

| 任务 | 归属 |
|---|---|
| `cx.schema.device_message.v1` send/receive helper | `contrix-rust-sdk` 或独立 device crate |
| `cx.key.verification.*` SAS/QR ceremony helper | `contrix-rust-sdk` |
| `cx.schema.key_backup.v1` restore-ticket SDK client | `contrix-rust-sdk` |

## 已完成（短 changelog）

- `[x]` GitHub / publish / release / docs / security / dependabot 基础设施完成。
- `[x]` `push_target_id`、`wakeup_kind`、`cx.device.push_route`、pseudonym unlinkability tests 完成。
- `[x]` HTTP retry policy、token rotation、`PushPreferencesStore`、README doctest 完成。
- `[x]` Multi-gateway register（`register_device_all`）+ state repair（`plan_multi_gateway_repair`）完成；同 token 跨 gateway 不再误判 token-move。
- `[x]` `shared_push_notify_privacy_vectors()` 在 `notify` feature 下导出，cotest 可直接复用。
