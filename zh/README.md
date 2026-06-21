# chime 中文文档

当前 chime 审计协议目标：`cokret-spec @ 5d66aeb`。历史
`CHANGELOG.md` 中的旧 SHA 只表示当轮同步记录，不是当前完成门槛。

面向 yougen / host app 的常用文档：

- [集成指南](integration-guide.md)
- [错误码](error-codes.md)
- [生产检查清单](production-checklist.md)

最重要的边界：

- push wakeup 反序列化后必须调用
  `PushNotifyRequestBody::assert_payload_safe` 或对应 validator。
- media token 必须通过 `verify_media_token_outcome`，并传入原始请求和
  当前 `MediaServiceAnchors`；该路径会验证 `service_signature` 和
  `participant_binding.sig` 后才允许 SFrame keying。
- `NonceTracker` 仅是内存/单实例防重放；服务端 relay 或多进程部署必须
  接入共享持久化 nonce 存储。
