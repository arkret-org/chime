# chime 中文文档

当前 chime 审计协议目标：`cokret-spec @ c2848a4`。历史
`CHANGELOG.md` 中的旧 SHA 只表示当轮同步记录，不是当前完成门槛。

面向 yougen / host app 的常用文档：

- [集成指南](integration-guide.md)
- [错误码](error-codes.md)
- [生产检查清单](production-checklist.md)

最重要的边界：

- push wakeup 反序列化后必须调用
  `PushNotifyRequestBody::assert_payload_safe` 或对应 validator。
- media token 的
  `structurally_validate_media_token_response` 只做结构校验，不做
  Ed25519 验签；SFrame keying 前必须由 host 验证
  `service_signature` 和 `participant_binding.sig`。
- `NonceTracker` 仅是内存/单实例防重放；服务端 relay 或多进程部署必须
  接入共享持久化 nonce 存储。
