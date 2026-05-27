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

## Drift-gate fixture SLA

`tests/drift_gate.rs` locks down the canonical floria `bridge/describe`
payload plus an embedded `blind_wakeup_request`. The fixture is the
mechanical link between chime's wire expectations and the floria contract
that signs them on the wire.

The SLA for keeping that link tight:

- **Re-snapshot ≤ 7 days after every spec-round release.** A spec round
  is published the moment `contrix-spec` advances its head SHA, even if
  no chime-visible field has obviously moved. Re-snapshotting means:
  1. point `tests/drift_gate.rs::BRIDGE_DESCRIBE_FIXTURE` at the latest
     floria `bridge/describe` output for the new spec head;
  2. re-run `cargo test --features notify drift_gate` and update the
     header comment (date + floria SHA + spec SHA) to match;
  3. add a `CHANGELOG.md` entry under "Drift-gate refreshed" naming the
     spec SHA.
- **14-day hard cap blocks release.** If the drift-gate fixture has not
  been refreshed within 14 days of a spec-round release, chime MUST NOT
  publish a new patch or minor. The drift-gate becoming stale is
  treated as a release-blocking defect, not as a backlog item. The
  guard is enforced by the `tests/drift_gate.rs` snapshot date assertion
  the maintainers update during the refresh.
- **Out-of-band floria changes.** If floria moves `bridge/describe`
  outside of a spec round (rare, e.g. a security fix), refresh the
  fixture in the same PR that pulls floria forward — do not let it
  drift even by a day.

The intent is that any production deployment of chime can answer the
question "is this build aligned with the spec head it claims to be
aligned with?" by reading one git diff, not by tracing through floria's
release history.

## Monitoring metrics (host applications)

Host applications integrating chime SHOULD export the following metrics
so production drift, replay, and privacy regressions show up before they
reach users. Metric names are suggested; the exact instrumentation crate
is left to the host.

| Metric | Type | What it tells you |
|--------|------|-------------------|
| `chime.push.notify.received_total{wakeup_kind,destination_service}` | counter | Inbound `cx.push.notify` volume per wakeup kind. A sudden drop is usually an upstream floria / soland routing regression. |
| `chime.push.notify.rejected_total{reason}` | counter | Wakeups rejected by `assert_payload_safe` / `validate_blind_wakeup`. Bucketed by `PushNotifyPrivacyError` discriminant. Non-zero is always a bug — either floria emitted a forbidden field or chime's validator drifted from the spec. |
| `chime.push.register_device.latency_seconds{gateway_type,result}` | histogram | End-to-end `register-device` latency. `gateway_type` separates Standard from Bugle so OEM-route degradation is visible. |
| `chime.push.register_device.retries_total{gateway_type,reason}` | counter | Retry attempts emitted by `PushRetryPolicy`. Persistent non-zero traffic on a single `reason` usually means the gateway is rate-limiting or returning a transient envelope. |
| `chime.push.nonce.replay_rejected_total{device_id_hash}` | counter | `NonceTracker::observe` rejections. A non-zero rate from a single device hash means either a misbehaving signer or an active replay attempt — page on threshold. |
| `chime.push.bridge.drift_verdict{verdict}` | gauge | Last `BridgeContractCache` verdict per gateway: `match` / `additive_drift` / `breaking_drift`. Pages on `breaking_drift` and on `additive_drift` lingering > 7 days (matches the drift-gate SLA). |
| `chime.push.token_rotation.planned_total{strategy,reason}` | counter | Rotations planned by `plan_token_rotation`. Lets you correlate platform-token churn with backend pressure. |
| `chime.push.account_deactivate.completed_total{source,outcome}` | counter | `on_account_deactivate` completions, bucketed by `DeactivationSource` (user / admin / sync) and `AccountDeactivationReceipt` outcome. A non-zero `outcome=failed` rate is a release blocker — devices that fail to deactivate cleanly are a privacy hazard. |

All metric labels MUST be low cardinality. Never label by `push_key`,
raw `device_id`, or DID. Hash device ids with a per-deployment salt
before exposing them as a label, and prefer SHA-256 truncation to 8
hex chars so a single attacker can't enumerate the userbase from
metrics scrapes.

## Nonce replay window guidance

The `NonceTracker` records every nonce chime has observed within a
configurable window and rejects duplicates. The window value is the
single most important defense against push-payload replay attacks; this
section is the source of truth for picking a value.

The general rule:

> **The nonce window MUST exceed the maximum end-to-end push delivery
> latency you tolerate, plus the maximum clock-skew tolerance you grant
> signers.**

Push delivery from `floria → carrier → device → chime` regularly takes
30–90 seconds in normal operation and can stretch to several minutes
under provider degradation. A window that's too tight produces
false-positive replay rejections during provider blips; a window that's
too wide enlarges the in-memory tracker's footprint and softens the
replay protection.

### Window table by deployment scenario

| Deployment scenario | Recommended window | Maximum acceptable | Rationale |
|---|---|---|---|
| **Consumer mobile, healthy provider** | 5 min | 10 min | Covers typical APNS/FCM latency tails plus a 30s skew budget. The default. |
| **Consumer mobile, OEM-route (Huawei / Xiaomi / OPPO / vivo / JPush)** | 10 min | 15 min | OEM routes have longer 99p latency; 5 min produces false rejects during provider degradation. |
| **Enterprise / regulated, single carrier** | 3 min | 5 min | Tighter posture; signer clocks are NTP-controlled. |
| **Lab / staging** | 1 min | 2 min | Stress-tests the replay defense; never use in prod. |
| **Disaster recovery (provider degraded)** | 20 min | 30 min | Temporary widen during a documented incident; revert within 24h. |
| **High-volume bot / agent integration** | 2 min | 3 min | Signers are server-side (no human clock), so the skew budget collapses. |

When in doubt, **prefer the recommended column over the maximum**. The
maximum is the ceiling above which you should be looking at a different
mitigation (e.g. per-tenant rate limiting) rather than widening the
nonce window.

### Operational expectations

- The tracker's memory footprint scales linearly with `window × inbound
  push rate per device`. At the recommended 5-min window and a typical
  consumer-mobile rate, expect <2 KB per active device.
- Window changes require a tracker flush. Restart the process after a
  config change; do NOT hot-swap the window without a flush, as nonces
  recorded under the prior window may collide with the new window's
  ordering assumptions.
- Page on `chime.push.nonce.replay_rejected_total{device_id_hash}`
  rising above the per-device baseline. A single device hash producing
  >5 rejections/hour is either a misbehaving signer (likely a
  re-issuing client) or an active replay attempt; investigate
  immediately.
