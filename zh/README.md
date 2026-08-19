# chime 中文文档

当前 chime 审计协议目标：`arkret-spec @ 5d66aeb`。历史
`CHANGELOG.md` 中的旧 SHA 只表示当轮同步记录，不是当前完成门槛。

面向 inkson / host app 的常用文档：

- [集成指南](integration-guide.md)
- [错误码](error-codes.md)
- [生产检查清单](production-checklist.md)

最重要的边界：

- push wakeup 的 blind-wakeup 校验属于 SDK
  `arkret_push_policy::blind_payload_sanitizer` 的职责，不在 chime 内。
- media token 校验走 SDK `arkret_signatures::media`，chime 不再提供包装。
- register/unregister 面走 bearer + session grant；请求签名与 nonce 防重放
  属于 soland fanout signer 与 floria 验证方，chime 不再承载。
