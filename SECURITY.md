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
   <https://github.com/arkret-org/chime/security/advisories/new>. We
   acknowledge new advisories within 5 working days.
2. **Direct contact** — if you cannot use GitHub Security Advisories,
   email the maintainers via the address listed under
   <https://github.com/arkret>.

When you report, please include:

- a description of the issue and its impact in the Arkret push surface
  (`register-device`, `unregister-device`, `bridge/describe`,
  `ak.edge.push.command.notify` validators, or local `PushRegistrationState` state);
- a minimal reproduction (test fixture, JSON payload, request strand);
- whether the issue is exploitable through the public crate API, requires
  a malicious server response, or requires local code change;
- any disclosure deadline you intend to honor.

## Privacy boundary issues

`chime` enforces a privacy boundary specific to push:

- `push_key` (FCM/APNs/WebPush tokens) MUST NOT appear in logs, debug
  output, or error messages.
- DIDs (`did:*`) MUST NOT appear in `push_hint` or any token-shaped wire field.
- `ak.edge.push.command.notify` payloads default to E2EE blind wakeup; only services
  on the explicit `plaintext_visible_services` allowlist may receive
  identifying metadata.

### AKP-0007 Circle metadata invariants

The Circle primitive introduces an encrypted sub-boundary inside a
Realm. chime's wakeup wire MUST preserve the following invariants on
top of the generic blind-wakeup rules above:

- The push wakeup wire MUST NOT carry a Circle identifier, a Realm
  identifier, or a scope field. Per `push-notifications.md` §5.1, raw
  Realm ids, Circle ids and `effective_scope` MUST NOT enter the
  `/_arkret/edge/push/notify` wire under the default
  `ak.profile.push_gateway.blind_wakeup.v1` profile; the only routing
  inputs are `route_tokens` and `devices[].target_route_token`.
- The security scope of an Event is its producer-signed `scope_ref`
  (`models/circle.md` §6.2). A client learns the boundary by fetching
  the durable Event, never from the wakeup.
- The display label (`circle_name` / `circle_display_name`) and any
  membership listing (`circle_members` / `circle_member_dids` /
  `circle_member_actor_ids`) are never allowed on the wakeup wire,
  including in the plaintext-visible mode that whitelisted destination
  service DIDs see. A wakeup that surfaces them MUST be rejected with
  `PushNotifyPrivacyError::SensitiveField`.

If you believe you have found a way to bypass any of those rules, treat
it as a security report and use the private channels above.

## What is in scope

- The local `chime` package artifact (`http` feature included).
- Default `ArkretPushClient` HTTPS / TLS / retry / idempotency
  behaviour.
- The `PushRegistrationState` client-side validators.

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
3. Keeping the verifier outside chime keeps the request builders usable
   as pure functions in tests and fuzzers without requiring the test to
   manage a keystore.

Host applications MUST:

- verify the `Signature` / `Signature-Input` headers (RFC 9421) against
  their configured set of accepted signer DIDs BEFORE handing the
  decoded body to the SDK's blind-wakeup sanitizer;
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

Inbound frames carry a signed creation timestamp header. The host MUST
enforce a freshness window on that header:

- **Recommended window: 5 minutes.**
- Frames older than the window MUST be dropped before
  `assert_payload_safe` runs. Old frames may carry signatures that
  were valid at signing time but reference keys that have since
  rotated; treating them as fresh defeats the rotation.
- Clock skew tolerance MUST be symmetric and small (≤ 30 seconds).
  Unbounded future timestamps are a replay vector — drop them.
- Drops MUST be counted in monitoring (`chime.push.notify.rejected_total{reason="stale_timestamp"}`)
  so a misconfigured upstream clock surfaces quickly.

Replay protection on inbound frames (a per-`(device_id, nonce)` seen
set covering at least the freshness window plus the host's broker
retry budget) is likewise the host relay's responsibility; chime does
not track nonces.
