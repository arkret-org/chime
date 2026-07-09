# chime examples

Runnable integration samples that show host applications how to wire
`chime` into the two halves of the Arkret push surface: outbound
device registration and inbound `ck.edge.push.command.notify` handling.

All examples are deliberately dependency-free at runtime — they print
to stdout rather than calling a real gateway, broker, or UI surface —
so `cargo build --examples --features notify` stays fast in CI and the
example code can be reviewed in isolation.

| Example | Audience | Demonstrates |
|---------|----------|--------------|
| [`desktop-tauri.rs`](desktop-tauri.rs) | Desktop client integrators (Tauri / Electron / native Cocoa or Win32 shells). | Building a `RegisterDeviceRequest` from a platform push token and validating an inbound blind-wakeup payload via `assert_payload_safe`. |
| [`server-side-relay.rs`](server-side-relay.rs) | Backend service authors (inkson, on-prem connectors, SRE-owned fan-out proxies). | Decoding inbound `ck.edge.push.command.notify` frames, asserting they are blind-wakeup safe, and rejecting replays with `NonceTracker` before forwarding to an internal queue. |

## Running

Both examples require the `notify` feature:

```powershell
cargo run --example desktop-tauri    --features notify
cargo run --example server-side-relay --features notify
```

## What these examples intentionally do NOT cover

- **Live HTTP I/O.** The desktop example builds the request body and
  hands it back to the caller; the actual `POST` is the host
  application's responsibility (typically via `CokretPushClient` under
  the `http` feature).
- **Inbound signature verification.** chime does not verify push frame
  signatures — see `SECURITY.md` for why and where the host must do it.
- **Platform UI surfacing.** Toast / banner / call-screen integration is
  out of scope; the example logs the validated wakeup kind instead.
- **Broker integration.** The server-side relay's `enqueue_for_fanout`
  stub stands in for the host application's Kafka / NATS / Redis
  client.

Refer to `docs/production-checklist.md` for the full host-wiring
checklist these examples implicitly assume.
