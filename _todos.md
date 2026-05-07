# chime TODO

> 整理日期: 2026-05-07
> 范围: Contrix Push SDK。非 push 的 device-message / key-backup / verification helper 归 `contrix-rust-sdk` 或独立 crate。

## 当前状态摘要

- Push SDK 注册、注销、token rotation、blind wakeup privacy validation、push route wrapper、multi-gateway register + state repair、cotest 隐私向量、feature matrix、docs/release 基础设施已完成。
- floria `provider_capabilities` 细粒度矩阵（v=`2026-05-07`）已经在 `bridge_describe` 中落地（C1/I3）；yougen 已切到 `ContrixPushClient::register_device_with_request` / `unregister_device_with_request` 并支持 bridge-discovered path 注入（I1）。
- 本仓当前没有 P0 编译或发布阻塞，`cargo build` / `cargo test --all-features` / `cargo clippy --all-features` / `cargo doc --all-features` 全绿。
- 唯一剩余条目是 I2：chime 侧 privacy vector helper 已通过 `notify` feature 稳定导出，等 cotest 仓打开接入窗口；本仓没有可继续推进的工作。

## 标记说明

- `[ ]` 未完成
- `[~]` 部分完成 / 外部阻塞
- `🅿` parallel-safe
- `🔒` sequential
- `⚠` privacy / wire contract 高风险

## P1 · Push 协议与 SDK surface

| # | 状态 | 任务 | 文件 | 说明 |
|---|---|---|---|---|
| C1 🅿 | `[x]` | 消费 `provider_capabilities` 细粒度矩阵 | `src/push/bridge_describe.rs` | `ProviderCapabilityDescriptor` + `provider_capabilities_version` / `provider_capabilities` 已加到 `PushBridgeDescribeResponse`，serde 与 floria 冻结 v=`2026-05-07` 对齐。 |

## P2 · 跨项目集成责任

| # | 状态 | 任务 | 本仓责任 | 根任务 |
|---|---|---|---|---|
| I1 🔒 | `[x]` | `yougen` 替换手写 push register 为 `ContrixPushClient` | yougen `register_push_device_with_request*` / `unregister_push_device_with_request` 现走 `ContrixPushClient::register_device_with_request` / `unregister_device_with_request`，新加 `with_register_device_path` / `with_unregister_device_path` 让 bridge-discovered 路径可注入。 | C4 |
| I2 🅿 | `[~]` | `cotest` 复用 chime privacy vectors | helper 已经在 `notify` feature 下稳定导出（`shared_push_notify_privacy_vectors()`）；chime 侧无待办，外部阻塞在 cotest 仓接入窗口。 | C4 / C8 |
| I3 🅿 | `[x]` | 与 `floria` bridge/describe 版本协商 | typed descriptor + serde round-trip 已对齐 floria `PROVIDER_CAPABILITIES_VERSION = "2026-05-07"`。 | C4 |

## 不在本仓范围

| 任务 | 归属 |
|---|---|
| `cx.schema.device_message.v1` send/receive helper | `contrix-rust-sdk` 或独立 device crate |
| `cx.key.verification.*` SAS/QR ceremony helper | `contrix-rust-sdk` |
| `cx.schema.key_backup.v1` restore-ticket SDK client | `contrix-rust-sdk` |

## 已完成（changelog）

- `[x]` GitHub / publish / release / docs / security / dependabot 基础设施。
- `[x]` `push_target_id`、`wakeup_kind`、`cx.device.push_route`、pseudonym unlinkability tests。
- `[x]` HTTP retry policy、token rotation、`PushPreferencesStore`、README doctest。
- `[x]` C2 multi-gateway registration state repair（`plan_multi_gateway_repair`）。
- `[x]` C3 导出 cotest 可复用 privacy vector helper（`shared_push_notify_privacy_vectors()`）。
- `[x]` C1/I3 typed `ProviderCapabilityDescriptor` 消费 floria 冻结的 per-provider batch/TTL/collapse/badge/credential 矩阵（v=`2026-05-07`）。
