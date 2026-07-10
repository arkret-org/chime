# Security Policy

## Supported Versions

`chime` is in its local `1.0.0` freeze line. Local security fixes should target
the latest `1.0.x` branch. Remote publication is outside this readiness
workflow.

| Version | Supported |
| ------- | --------- |
| 1.0.x   | Yes       |
| < 1.0   | No        |

## Reporting a Vulnerability

Do **not** open a public GitHub issue for security-sensitive bug reports.

Use one of the following private channels:

1. **GitHub Security Advisories** — preferred. Open a draft advisory at
   <https://github.com/arkret/chime/security/advisories/new>. We
   acknowledge new advisories within 5 working days.
2. **Direct contact** — if you cannot use GitHub Security Advisories,
   email the maintainers via the address listed under
   <https://github.com/arkret>.

When you report, please include:

- a description of the issue and its impact in the Arkret push surface
  (`register-device`, `unregister-device`, `bridge/describe`,
  `ak.edge.push.command.notify` validators, or local `PushRegistrationStore` state);
- a minimal reproduction (test fixture, JSON payload, request strand);
- whether the issue is exploitable through the public crate API, requires
  a malicious server response, or requires local code change;
- any disclosure deadline you intend to honor.

## Privacy boundary issues

`chime` enforces a privacy boundary specific to push:

- `push_key` (FCM/APNs/WebPush tokens) MUST NOT appear in logs, debug
  output, or error messages.
- DIDs (`did:*`) MUST NOT appear inside `notification.extra`,
  `push_hint`, or any token-shaped wire field.
- `ak.edge.push.command.notify` payloads default to E2EE blind wakeup; only services
  on the explicit `plaintext_visible_services` allowlist may receive
  identifying metadata.

### AKP-0007 Circle metadata invariants

The Circle primitive introduces an encrypted sub-boundary inside a
Realm. chime's wakeup wire MUST preserve the following invariants on
top of the generic blind-wakeup rules above:

- `PushNotification.circle_id` MAY travel on the blind-wakeup wire as
  an opaque typed-id reference, but its value MUST start with the
  literal `ak:circle:` prefix and MUST NOT contain a `did:` literal
  anywhere in its tail. Untyped or DID-bearing values are rejected by
  `validate_wire_model` / `validate_blind_wakeup`.
- `PushNotification.effective_scope` MUST be either a `ak:circle:` or
  `ak:realm:` typed reference; any other prefix is wire-broken.
- The display label (`circle_name` / `circle_display_name`) and any
  membership listing (`circle_members` / `circle_member_dids` /
  `circle_member_actor_ids`) are never allowed on the wakeup wire,
  including in the plaintext-visible mode that whitelisted destination
  service DIDs see. A wakeup that surfaces them MUST be rejected with
  `PushNotifyPrivacyError::SensitiveField`.

If you believe you have found a way to bypass any of those rules, treat
it as a security report and use the private channels above.

## What is in scope

- The local `chime` package artifact (`http` and `notify` features included).
- Default `ArkretPushClient` HTTPS / TLS / retry / idempotency
  behaviour.
- Default `validate_blind_wakeup` /
  `validate_plaintext_visible_service` / `assert_payload_safe`
  validators and the `PushNotifyPolicyContext` policy gate.

## What is out of scope

- Vulnerabilities in upstream Arkret services (Sync Service, Principal
  Server, soland, floria, …) — please report those to the respective
  service maintainers.
- Vulnerabilities in third-party crates listed in `Cargo.toml`. Report
  those upstream; we will pull a fixed dependency once it is available.
- Misuse by callers that disable the privacy validators or feed an
  attacker-controlled `plaintext_visible_services` allowlist.

## Inbound push frame handling

`chime` ships the wire-shape, privacy, and replay validators for inbound
`ak.edge.push.command.notify` frames, but it deliberately stops short of cryptographic
authentication of the frame itself. The host application owns the
remaining pieces.

### Signature verification is the host's responsibility

`chime` does **NOT** verify the signature on inbound push frames. This
is intentional:

1. The signing key set lives in the host's deployment configuration
   (gateway service DIDs, key rotation cadence, allowlist of accepted
   `kid` values), and chime cannot know that set without becoming a
   service-discovery client.
2. Different host integrations use different transport envelopes — APNs
   provider tokens, FCM bearer tokens, WebPush VAPID, OEM-provider HMAC
   headers — and chime would have to recapitulate each one to verify.
3. Keeping the verifier outside chime keeps the privacy validator
   (`validate_blind_wakeup`) usable as a pure function in tests and
   fuzzers without requiring the test to manage a keystore.

Host applications MUST:

- verify the `Signature` / `Signature-Input` headers (RFC 9421) against
  their configured set of accepted signer DIDs BEFORE handing the
  decoded body to `PushNotifyRequestBody::assert_payload_safe`;
- treat a signature failure as `403` and drop the frame silently — do
  not retry, do not surface to UI, do not log the body;
- include the verifier's accepted `kid` set in their monitoring so
  unexpected `kid` values page on appearance.

### `EncryptedEnvelope` nonce check path

When an inbound frame carries an `EncryptedEnvelope` (E2EE message
body for plaintext-visible destination services), the host MUST:

1. Decode the `nonce` field as base64url and reject the frame if it
   decodes to anything other than the algorithm's required nonce
   width (e.g. 12 bytes for `AES-256-GCM`, 24 bytes for
   `XChaCha20-Poly1305`).
2. Maintain a per-`(recipient, key_id)` nonce-seen set for the
   envelope's key lifetime. A repeated nonce under the same key is a
   protocol break and MUST cause the frame to be dropped with an alert.
3. Refuse envelopes whose `algorithm` field is not in chime's active
   HPKE suite allowlist. Hosts may apply a stricter local capability
   allowlist after that, but unknown or reserved registry rows fail
   closed at the SDK boundary.

`EncryptedEnvelope::nonce` is intentionally `Option<String>` because
some algorithms (e.g. deterministic AEAD variants) omit it; the host
MUST treat the absence as algorithm-dependent rather than as a default
"any nonce is fine" path.

### Stale-timestamp frame handling

Inbound frames carry a `ARKRET_CREATED_AT_HEADER`. The host MUST
enforce a freshness window on that header:

- **Recommended window: 5 minutes** (matches the default
  `NonceTracker` window).
- Frames older than the window MUST be dropped before
  `assert_payload_safe` runs. Old frames may carry signatures that
  were valid at signing time but reference keys that have since
  rotated; treating them as fresh defeats the rotation.
- Clock skew tolerance MUST be symmetric and small (≤ 30 seconds).
  Unbounded future timestamps are a replay vector — drop them.
- Drops MUST be counted in monitoring (`chime.push.notify.rejected_total{reason="stale_timestamp"}`)
  so a misconfigured upstream clock surfaces quickly.

### Replay window: inbound vs outbound

`NonceTracker` is used in both directions, but the windows protect
different invariants and SHOULD NOT share state:

- **Outbound (chime → gateway).** The window protects against the
  host re-signing the same `(device_id, nonce)` after a retry or a
  process restart. The window only needs to cover the maximum end-to-end
  retry budget (~ 60 seconds is enough in practice). A short window
  keeps the tracker's memory footprint trivial on long-running clients.
- **Inbound (gateway → chime relay).** The window protects against an
  attacker (or a buggy upstream) re-injecting an old frame to fan it
  out twice. The window MUST be at least as long as the host's
  `ARKRET_CREATED_AT_HEADER` freshness window plus the host's broker
  retry budget; **5 minutes is the recommended floor**. A short
  inbound window opens a re-fanout vector — when in doubt, lean long.

Mixing the two windows in a single `NonceTracker` is a foot-gun: a
short outbound-style window can silently accept replays of inbound
frames. Maintain separate trackers per direction, and surface their
sizes as `chime.push.nonce.replay_rejected_total` / a complementary
`tracker_size` gauge so unbounded growth shows up before it eats
memory.
