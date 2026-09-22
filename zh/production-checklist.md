# 生产检查清单

## 编译与协议

- 生产构建启用 `--features http`。
- register/unregister 的 HTTP 目标只允许当前账户自己的 Station；Gateway URL
  只作为请求字段，客户端不读取其 describe/VAPID/endpoint。
- 升级 SDK/spec artifact 后重新运行集成 smoke test；不在 README 中维护手写 SHA。

## Bugle / 国内 OEM

- host 负责 OEM provider SDK 接入和 token 获取。
- Android Bugle 路由优先使用 `domestic_app_id`（经
  `GatewayBinding::resolve_app_id`）。
- 每个 gateway binding 分别提交给 Station；重试和成功语义只消费 Station 的
  typed outcome，不把 Gateway 204/404 当作客户端成功。
