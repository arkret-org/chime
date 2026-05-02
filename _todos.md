# chime Active TODO

更新时间: 2026-05-02

`chime` 是客户端/服务端共享的 Contrix push SDK。它提供 push preferences、device register/unregister builders、可选 HTTP client、可选 gateway notify wire model 和隐私校验；不实现 APNs/FCM/OEM provider 投递。

## 0. 当前边界

- [x] 已有 `PushPreferences`、`PushDeviceConfig`、register/unregister request builder、optional `http` client。
- [x] 已有 optional `notify` feature、`cx.push.notify` wire model、blind wakeup validator、token hash/preview、rotation plan。
- [x] 已对齐 `cx.profile.push_gateway.v1`、`discovery/push-notifications.md`、`data-structures.md` 的 SDK 边界：push gateway 只做 blind/minimized wakeup；notification/read marker 是派生投影，不是 canonical truth。
- [ ] 仍处于 0.1 API shaping 阶段，未完成与真实 `soland` / `floria` 的端到端 contract test。

## P0: Register / Unregister Contract

- [x] Freeze `cx.push.register_device`:
  - principal DID。
  - device id。
  - platform。
  - app id / domestic app id。
  - push gateway URL。
  - push key/token。
  - preferences。
  - idempotency key。
  - proof。
  - request id。
- [x] Register response:
  - ok。
  - registration id。
  - accepted gateway。
  - token hash/preview。
  - expires/refresh hint。
  - warnings。
  - request id。
- [x] Freeze `cx.push.unregister_device`:
  - device id。
  - registration id or token hash。
  - gateway URL。
  - idempotency key。
  - proof。
  - request id。
- [x] Unregister response:
  - ok。
  - already removed semantics。
  - removed registration id。
  - request id。
- [x] URL/security validation:
  - HTTPS by default。
  - loopback exception behind explicit dev flag。
  - no query string credentials。
  - WebPush endpoint allowlist support。

## P0: Authentication and Signing Hooks

- [x] Bearer helper:
  - header-only。
  - debug redaction。
  - no URL token。
- [x] DID proof helper:
  - canonical proof body。
  - actor DID。
  - device id。
  - audience / service DID。
  - origin。
  - expiry。
  - nonce/idempotency。
- [x] HTTP Message Signature helper:
  - Content-Digest。
  - Signature-Input。
  - Signature。
  - created/expires。
  - origin/destination service DID metadata。
- [x] Session grant integration:
  - accept externally supplied coauth/soland grant。
  - never own private keys。
  - expose signing context only。

## P0: HTTP Client Runtime

- [x] Client config:
  - base URL。
  - timeout。
  - retry policy。
  - default headers。
  - request id。
  - idempotency。
- [x] Error taxonomy:
  - decode Contrix error envelope。
  - preserve request id。
  - classify retryable / non-retryable。
  - expose `Retry-After`。
  - redact token/proof。
- [x] Retry behavior:
  - retry only safe idempotent requests。
  - exponential backoff + jitter。
  - duplicate safe success。
  - duplicate conflict surfaced to caller。
- [x] Contract tests:
  - mocked soland register/unregister。
  - 401/403/409/429/5xx。
  - invalid response schema。
  - token not leaked in debug/error。

## P0: Notify Wire Model and Privacy Validator

- [x] `cx.push.notify` request:
  - idempotency key。
  - origin/destination service DID。
  - app id。
  - target device/token refs。
  - event refs or notification refs。
  - push hint。
  - priority/ttl/collapse key。
- [x] `PushNotification` privacy boundary:
  - notification is projection, not canonical truth。
  - body-free wakeup default。
  - no message body。
  - no encrypted payload bytes。
  - no plaintext attachment filename/preview。
  - no SDP/ICE/TURN credentials。
  - no facet/view-renderer derived title/body unless explicitly authorized。
- [x] Response/rejection:
  - accepted count。
  - rejected token hashes。
  - rejection reason enum。
  - retry-after。
  - provider message id optional。
- [x] Shared vectors:
  - chime validator and floria validator reject the same invalid payloads。
  - E2EE and non-E2EE cases separated。
  - plaintext-visible service allow case explicit。

## P1: Local State and Token Rotation

- [x] Registration state:
  - account/principal DID。
  - device id。
  - gateway。
  - platform/app id。
  - token hash/preview。
  - registration id。
  - last success/error。
  - expiry/refresh hint。
- [x] Storage trait:
  - load/save/delete。
  - multiple registrations per device。
  - encrypted/local storage guidance。
  - migration version。
- [x] Token rotation:
  - unregister old then register new where required。
  - register new first where platform requires overlap。
  - idempotent recovery after partial failure。
  - stale local state repair。
- [x] Multi-device:
  - same principal multiple device ids。
  - same platform token moved to new device。
  - revoked device cleanup。

## P1: Cross-Project Integration

- [ ] `soland`:
  - register/unregister payloads pass Principal Server HTTP tests。
  - session grant / bearer / DID proof hooks work in production mode。
  - response fields match SDK types。
- [ ] `floria`:
  - notify model matches gateway endpoint。
  - rejected token reason round-trips。
  - blind wakeup invalid vectors shared。
- [ ] `yougen`:
  - web/desktop/mobile push registration uses chime builder。
  - local state/token rotation stored through platform storage。
  - UI shows generic E2EE wakeup state only。
- [ ] `cotest`:
  - `yougen/chime -> soland register -> floria notify mock` scenario。

说明：这些项需要修改或运行相邻仓库的真实 contract/E2E 流程，不能仅在 `chime` crate 内闭环完成。

## P1: Documentation and Release

- [x] README:
  - clarify chime is not provider delivery runtime。
  - map to `cx.profile.push_gateway.v1`。
  - document privacy boundary and plaintext-visible service exception。
- [x] Rustdoc:
  - register/unregister examples。
  - signing context examples。
  - token rotation examples。
  - notify validator examples。
- [x] Release gates:
  - `cargo fmt --all -- --check`。
  - `cargo check --all-features`。
  - `cargo test --all-features`。
  - semver audit for 0.1 API。

## Definition of Done

- [ ] Register/unregister payloads pass `soland` contract tests。
- [ ] Notify payloads pass `floria` contract tests。
- [x] Tokens, bearer credentials, proofs and full WebPush endpoints are never printed in debug/errors。
- [x] Retry and error behavior is deterministic and documented。
- [ ] `cotest` covers at least one real push registration + gateway notify flow。
