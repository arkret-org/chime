# chime examples

Runnable integration samples that show host applications how to wire
`chime` into the outbound device-registration half of the Arkret push
surface.

All examples are deliberately dependency-free at runtime — they print
to stdout rather than calling a real gateway, broker, or UI surface —
so `cargo build --examples` stays fast in CI and the example code can
be reviewed in isolation.

| Example | Audience | Demonstrates |
|---------|----------|--------------|
| [`desktop-tauri.rs`](desktop-tauri.rs) | Desktop client integrators (Tauri / Electron / native Cocoa or Win32 shells). | Building a `RegisterDeviceRequest` from a platform push token. |

## Running

```powershell
cargo run --example desktop-tauri
```

## What these examples intentionally do NOT cover

- **Live HTTP I/O.** The desktop example builds the request body and
  hands it back to the caller; the actual `POST` is the host
  application's responsibility (typically via `ArkretPushClient` under
  the `http` feature).
- **Inbound signature verification.** chime does not verify push frame
  signatures — see `SECURITY.md` for why and where the host must do it.
- **Platform UI surfacing.** Toast / banner / call-screen integration is
  out of scope.
- **Gateway-side payload validation.** Blind-wakeup validation of
  outbound `ak.edge.push.command.notify.v1` payloads is the SDK's
  `arkret_push_policy::blind_payload_sanitizer` surface, not chime's.

Refer to `docs/production-checklist.md` for the full host-wiring
checklist these examples implicitly assume.
