# chime Active TODO

更新时间: 2026-05-03

`chime` 是客户端 / 服务端共享的 Push SDK。它的协议面虽然小，但必须和 `floria`、`soland`、`yougen` 一起完成 `flow` 收口，确保 push 注册和 notify 不再残留 room/card/subject 旧字段。

## 执行顺序

- [x] Block A: 先冻结 register / unregister / notify 的 active wire model。
- [x] Block B: 再完成本地状态、token rotation、HTTP client、错误分类。
- [ ] Block C: 最后联调 `soland`、`floria`、`yougen`、`cotest`。

## 可并行 Lane

- [x] Lane 1: type model / validator。
- [x] Lane 2: HTTP client / retry / auth hooks。
- [x] Lane 3: local state / token rotation。
- [x] Lane 4: shared invalid vectors。
- [ ] Lane 5: cross-project contract tests。

## P0: Active Register and Notify Model

- [x] register / unregister request/response 保持 `cx.profile.push_gateway.v1` 对齐。
- [x] notify request 里的对象引用只允许 active `flow` / `message` / `event` / `notification projection` 语义。
- [x] SDK validator 明确拒绝 legacy `room` / `card` / `subject` typed ID、event kind、schema id、字段别名。
- [x] proof、bearer、HTTP Message Signature helper 的 audience / origin / service DID 绑定继续稳定。

## P0: Runtime and Local State

- [x] HTTP client 的 request id、retry-after、duplicate conflict、retryable classification 与 `soland` / `floria` 的错误模型对齐。
- [x] registration state 持久化继续只存 token hash/preview、gateway、device、app id、refresh hint。
- [x] token rotation、multi-device、partial failure recovery、stale local state repair 补齐真实平台行为。
- [x] debug / error / diagnostics 一律不输出原始 token、proof、WebPush endpoint secret。

## P1: Cross-Project Integration

- [ ] `soland` 的 register/unregister HTTP contract 与 SDK 类型一字不漂移。
- [ ] `floria` 的 notify validator 与 `chime` 使用同一组 invalid vector。
- [ ] `yougen` 通过 `chime` 完成真实注册、注销、轮换、wake-up 处理。
- [ ] `cotest` 覆盖 `yougen/chime -> soland -> floria` 至少一条真实 happy path。

## Definition of Done

- [x] SDK 不再暴露或接受 removed legacy push 引用语义。
- [ ] `soland` / `floria` / `yougen` 三方 contract 对齐。
- [x] token、proof、endpoint secret 在任何错误和日志路径上都不会泄露。
