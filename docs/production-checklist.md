# chime Production Checklist

chime is a client-side push contract crate. It does not receive APNs, FCM,
WebPush, or OEM provider callbacks directly; host applications own those
platform receivers and call into chime for validation and wire-shape handling.

## Required Host Wiring

- Route every decoded `ak.edge.push.command.notify.v1` request through the
  SDK's `arkret_push_policy::blind_payload_sanitizer` before showing UI.
  Gateway-side notify wire types are not part of chime.
- Drain local push queues before invalidating the device session.
- Clear keypackage caches and persisted push preferences after deactivation.
- Store push gateway credentials outside logs and crash reports.
- Replay protection on inbound frames is host-relay responsibility;
  chime does not track nonces.

## Local Verification

Run these before cutting local artifacts:

```powershell
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo deny check
cargo package --list --allow-dirty
```

## Monitoring metrics (host applications)

Host applications integrating chime SHOULD export the following metrics
so production drift, replay, and privacy regressions show up before they
reach users. Metric names are suggested; the exact instrumentation crate
is left to the host.

| Metric | Type | What it tells you |
|--------|------|-------------------|
| `chime.push.notify.received_total{wakeup_kind,destination_service}` | counter | Inbound `ak.edge.push.command.notify.v1` volume per wakeup kind. A sudden drop is usually an upstream floria / coland routing regression. |
| `chime.push.register_device.latency_seconds{gateway_type,result}` | histogram | End-to-end `register-device` latency. `gateway_type` separates Standard from Bugle so OEM-route degradation is visible. |
| `chime.push.register_device.retries_total{gateway_type,reason}` | counter | Retry attempts emitted by `PushRetryPolicy`. Persistent non-zero traffic on a single `reason` usually means the gateway is rate-limiting or returning a transient envelope. |

All metric labels MUST be low cardinality. Never label by `push_key`,
raw `device_id`, or DID. Hash device ids with a per-deployment salt
before exposing them as a label, and prefer SHA-256 truncation to 8
hex chars so a single attacker can't enumerate the userbase from
metrics scrapes.
