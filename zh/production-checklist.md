# 生产检查清单

## 编译与协议

- 生产构建启用 `--features http`。
- push gateway 通过 `service_describe()` 读取 canonical `/_arkret/describe`。
- 升级 SDK/spec artifact 后重新运行集成 smoke test；不在 README 中维护手写 SHA。

## Bugle / 国内 OEM

- host 负责 OEM provider SDK 接入和 token 获取。
- Android Bugle 路由优先使用 `domestic_app_id`（经
  `GatewayBinding::resolve_app_id`）。
- 每个 gateway binding 独立注册、独立重试、独立保存 registration state。
