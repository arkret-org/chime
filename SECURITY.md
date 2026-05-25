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
   <https://github.com/contrix-dev/chime/security/advisories/new>. We
   acknowledge new advisories within 5 working days.
2. **Direct contact** — if you cannot use GitHub Security Advisories,
   email the maintainers via the address listed under
   <https://github.com/contrix-dev>.

When you report, please include:

- a description of the issue and its impact in the Contrix push surface
  (`register-device`, `unregister-device`, `bridge/describe`,
  `cx.push.notify` validators, or local `PushRegistrationStore` state);
- a minimal reproduction (test fixture, JSON payload, request flow);
- whether the issue is exploitable through the public crate API, requires
  a malicious server response, or requires local code change;
- any disclosure deadline you intend to honor.

## Privacy boundary issues

`chime` enforces a privacy boundary specific to push:

- `push_key` (FCM/APNs/WebPush tokens) MUST NOT appear in logs, debug
  output, or error messages.
- DIDs (`did:*`) MUST NOT appear inside `notification.extra`,
  `push_hint`, or any token-shaped wire field.
- `cx.push.notify` payloads default to E2EE blind wakeup; only services
  on the explicit `plaintext_visible_services` allowlist may receive
  identifying metadata.

### CXP-0007 Circle metadata invariants

The Circle primitive introduces an encrypted sub-boundary inside a
Realm. chime's wakeup wire MUST preserve the following invariants on
top of the generic blind-wakeup rules above:

- `PushNotification.circle_id` MAY travel on the blind-wakeup wire as
  an opaque typed-id reference, but its value MUST start with the
  literal `cx:circle:` prefix and MUST NOT contain a `did:` literal
  anywhere in its tail. Untyped or DID-bearing values are rejected by
  `validate_wire_model` / `validate_blind_wakeup`.
- `PushNotification.effective_scope` MUST be either a `cx:circle:` or
  `cx:realm:` typed reference; any other prefix is wire-broken.
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
- Default `ContrixPushClient` HTTPS / TLS / retry / idempotency
  behaviour.
- Default `validate_blind_wakeup` /
  `validate_plaintext_visible_service` / `assert_payload_safe`
  validators and the `PushNotifyPolicyContext` policy gate.

## What is out of scope

- Vulnerabilities in upstream Contrix services (Sync Service, Principal
  Server, soland, floria, …) — please report those to the respective
  service maintainers.
- Vulnerabilities in third-party crates listed in `Cargo.toml`. Report
  those upstream; we will pull a fixed dependency once it is available.
- Misuse by callers that disable the privacy validators or feed an
  attacker-controlled `plaintext_visible_services` allowlist.
