# Integration Strand: chime ↔ floria ↔ inkson

This document is the end-to-end sequence reference for how a push
notification travels from inkson (the client SDK) through chime (the
contract / privacy validator) and floria (the push gateway) and back.
Companions:

- [`inkson-integration.md`](./inkson-integration.md) — inkson ↔ chime
  contract surface (token shape, register-device payload).
- [`binding-roadmap.md`](./binding-roadmap.md) — long-term contract
  evolution.

## Cast

| Component | Role |
|---|---|
| **inkson** | Client SDK running inside the host app on the device. Owns the platform-native push token, the device identity, and the rendering of incoming notifications. |
| **chime** | In-process contract validator, runs both in the host app (alongside inkson) and on the server (alongside floria). Enforces nonce-replay protection, payload privacy, and the bridge contract. |
| **floria** | Server-side push gateway. Talks to APNS / FCM / OEM providers. Speaks `ak.edge.push.command.notify` to soland on one side and the provider-native push API on the other. |
| **soland** | Upstream event store (not pictured below in the call-path; appears only as the producer of `ak.edge.push.command.notify`). |

## End-to-end sequence: device registration

```text
inkson (device)          chime (device)             floria (server)         chime (server)
     │                        │                          │                       │
     │ (1) get push token     │                          │                       │
     │  from OS push sub      │                          │                       │
     │                        │                          │                       │
     │ (2) build              │                          │                       │
     │  RegisterDevice {      │                          │                       │
     │    push_key,           │                          │                       │
     │    PushPlatform,       │                          │                       │
     │    device_id,          │                          │                       │
     │ accountable_principal_ids │                       │                       │
     │  }                     │                          │                       │
     │───────────────────────►│                          │                       │
     │                        │                          │                       │
     │                        │ (3) validate shape       │                       │
     │                        │  - push_key prefix       │                       │
     │                        │  - device_id well-formed │                       │
     │                        │  - sign w/ device key    │                       │
     │                        │                          │                       │
     │                        │ (4) POST /register-device│                       │
     │                        │─────────────────────────►│                       │
     │                        │                          │                       │
     │                        │                          │ (5) chime validates   │
     │                        │                          │  on server side:      │
     │                        │                          │  - nonce window check │
     │                        │                          │  - signature verify   │
     │                        │                          │──────────────────────►│
     │                        │                          │                       │
     │                        │                          │ (6) record device     │
     │                        │                          │  in floria's gateway  │
     │                        │                          │  routing table        │
     │                        │                          │                       │
     │                        │                          │  (7) provider-side    │
     │                        │                          │  register (APNS topic │
     │                        │                          │  / FCM token mapping) │
     │                        │                          │                       │
     │                        │ (8) DeviceReceipt        │                       │
     │                        │◄─────────────────────────│                       │
     │                        │                          │                       │
     │ (9) DeviceReceipt      │                          │                       │
     │◄───────────────────────│                          │                       │
     │                        │                          │                       │
     │ (10) inkson records    │                          │                       │
     │  the receipt; future   │                          │                       │
     │  pushes are addressable│                          │                       │
```

Notes:

- Steps (3) and (5) run the same `validate_register_device` contract
  code on both sides — the device-side check is for fail-fast UX; the
  server-side check is the security boundary.
- The `accountable_principal_ids` chain in (2) strands through floria unmodified; the
  server-side chime instance checks the chain depth against the realm's
  policy.
- If (5) rejects on `nonce_replay`, the rejection envelope returned to
  inkson carries no provider-specific details — the device retries with
  a fresh nonce.

## End-to-end sequence: incoming notification (visible)

```text
soland                  floria (server)         chime (server)    provider (APNS/FCM)    chime (device)        inkson (device)
   │                        │                       │                    │                       │                    │
   │ (1) emit               │                       │                    │                       │                    │
   │  ak.edge.push.command.notify        │                       │                    │                       │                    │
   │───────────────────────►│                       │                    │                       │                    │
   │                        │                       │                    │                       │                    │
   │                        │ (2) chime validates   │                    │                       │                    │
   │                        │  visible payload:     │                    │                       │                    │
   │                        │  - assert_payload_safe│                    │                       │                    │
   │                        │  - no forbidden fields│                    │                       │                    │
   │                        │  - bridge contract    │                    │                       │                    │
   │                        │──────────────────────►│                    │                       │                    │
   │                        │                       │                    │                       │                    │
   │                        │ (3) compose provider  │                    │                       │                    │
   │                        │  envelope; redact     │                    │                       │                    │
   │                        │  identifiers per      │                    │                       │                    │
   │                        │  redaction map        │                    │                       │                    │
   │                        │                       │                    │                       │                    │
   │                        │ (4) provider push     │                    │                       │                    │
   │                        │──────────────────────────────────────────►│                       │                    │
   │                        │                       │                    │                       │                    │
   │                        │                       │                    │ (5) provider routes   │                    │
   │                        │                       │                    │  to device            │                    │
   │                        │                       │                    │──────────────────────►│                    │
   │                        │                       │                    │                       │                    │
   │                        │                       │                    │                       │ (6) chime device-  │
   │                        │                       │                    │                       │  side validates:   │
   │                        │                       │                    │                       │  - nonce window    │
   │                        │                       │                    │                       │  - sig over payload│
   │                        │                       │                    │                       │  - payload shape   │
   │                        │                       │                    │                       │───────────────────►│
   │                        │                       │                    │                       │                    │
   │                        │                       │                    │                       │                    │ (7) inkson renders
   │                        │                       │                    │                       │                    │  visible notification
   │                        │                       │                    │                       │                    │  via OS facility
```

## End-to-end sequence: incoming notification (blind wakeup)

```text
soland                  floria (server)         chime (server)    provider             chime (device)        inkson (device)
   │                        │                       │                    │                       │                    │
   │ (1) emit               │                       │                    │                       │                    │
   │  ak.edge.push.command.notify        │                       │                    │                       │                    │
   │  wakeup_kind=blind     │                       │                    │                       │                    │
   │───────────────────────►│                       │                    │                       │                    │
   │                        │                       │                    │                       │                    │
   │                        │ (2) chime validates   │                    │                       │                    │
   │                        │  blind wakeup:        │                    │                       │                    │
   │                        │  - payload_size ≤     │                    │                       │                    │
   │                        │    blind_wakeup_max   │                    │                       │                    │
   │                        │  - assert_payload_safe│                    │                       │                    │
   │                        │  - validate_blind_    │                    │                       │                    │
   │                        │    wakeup             │                    │                       │                    │
   │                        │──────────────────────►│                    │                       │                    │
   │                        │                       │                    │                       │                    │
   │                        │ (3) decision tree     │                    │                       │                    │
   │                        │  (see floria runbook):│                    │                       │                    │
   │                        │  - blind feasible? ───┘ no → fallback to visible (step 4)
   │                        │                       │                    │                       │                    │
   │                        │ (4) provider silent   │                    │                       │                    │
   │                        │  push (content-       │                    │                       │                    │
   │                        │  available:1 / data)  │                    │                       │                    │
   │                        │──────────────────────────────────────────►│                       │                    │
   │                        │                       │                    │                       │                    │
   │                        │                       │                    │ (5) device woken,     │                    │
   │                        │                       │                    │  app brought to       │                    │
   │                        │                       │                    │  background           │                    │
   │                        │                       │                    │──────────────────────►│                    │
   │                        │                       │                    │                       │                    │
   │                        │                       │                    │                       │ (6) chime device:  │
   │                        │                       │                    │                       │  - decode wakeup   │
   │                        │                       │                    │                       │  - hand off to     │
   │                        │                       │                    │                       │    inkson          │
   │                        │                       │                    │                       │───────────────────►│
   │                        │                       │                    │                       │                    │
   │                        │                       │                    │                       │                    │ (7) inkson pulls
   │                        │                       │                    │                       │                    │  the real payload
   │                        │                       │                    │                       │                    │  from soland sync
   │                        │                       │                    │                       │                    │  (NO OS notification
   │                        │                       │                    │                       │                    │  rendered)
```

The hand-off in (7) is the canonical reason blind wakeup exists at all:
the OS-side notification stays silent, the app makes its own decision
about what (if anything) to surface to the user based on the actual
payload state, and chime never sees the real payload in plaintext at
the provider hop.

## Failure-mode escalation

Where a failure originates determines which team to page:

| Symptom | Component | Likely origin |
|---|---|---|
| `chime.push.notify.rejected_total{reason="forbidden_field"}` non-zero | floria | floria composed an envelope with a forbidden field; chime caught it server-side. File against floria. |
| `chime.push.nonce.replay_rejected_total{device_id_hash}` spike on one device | inkson or attacker | If hash maps to a known stable device that recently restarted, suspect inkson nonce-store loss. Otherwise treat as replay attempt. |
| Provider 4xx spike (`floria_apns_status_codes{status="403"}` rises) | floria | APNS cert / topic mismatch; see floria runbook. |
| `chime.push.bridge.drift_verdict{verdict="breaking_drift"}` page | chime ↔ floria | A spec / floria release has broken a chime contract. Roll forward chime or roll back floria; do NOT silence the alert. |
| inkson reports notifications "vanishing" silently | chime device side | Device-side chime rejected a payload; check device logs for the rejection reason. Blind-wakeup payloads can fail silently from the user POV; floria should have logged the dispatch. |
