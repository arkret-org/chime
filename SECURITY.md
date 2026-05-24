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
