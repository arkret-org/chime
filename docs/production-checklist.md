# chime Production Checklist

chime is a client-side push contract crate. It does not receive APNs, FCM,
WebPush, or OEM provider callbacks directly; host applications own those
platform receivers and call into chime for validation and wire-shape handling.

## Required Host Wiring

- Route every decoded `cx.push.notify` request through
  `PushNotifyReqBody::assert_payload_safe` before showing UI.
- Use `PushNotifyPolicyContext::blind_wakeup_only` unless the destination
  service DID is explicitly authorized to see plaintext.
- Wire account deactivation into `on_account_deactivate` with either a concrete
  `AccountDeactivationSink` implementation or `ClosureAccountDeactivationSink`.
- Drain local push queues before invalidating the device session.
- Clear keypackage caches and persisted push preferences after deactivation.
- Store push gateway credentials outside logs and crash reports.

## Local Verification

Run these before cutting local artifacts:

```powershell
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo deny check
cargo package --list --allow-dirty
```

`tests/live_floria_integration.rs` remains opt-in and requires `FLORIA_BIN`.
When unset, the test skips without failing local contributor runs.
