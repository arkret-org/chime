# 生产检查清单

## 编译与协议

- 生产构建启用 `--features http`。
- floria 适配层通过 `floria_bridge_describe()` 发现 bridge 契约。
- 当前 chime 审计目标是 `arkret-spec @ 5d66aeb`；升级协议头前需要重新跑
  集成 smoke test。

## Bugle / 国内 OEM

- host 负责 OEM provider SDK 接入和 token 获取。
- Android Bugle 路由优先使用 `domestic_app_id`（经
  `GatewayBinding::resolve_app_id`）。
- 每个 gateway binding 独立注册、独立重试、独立保存 registration state。
