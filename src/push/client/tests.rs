use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use super::super::errors::PushErrorKind;
use super::super::wire::PushDeviceConfig;
use super::super::{COKRET_REQUEST_ID_HEADER, RETRY_AFTER_HEADER};
use super::core::CokretPushClient;
use super::retry::PushRetryPolicy;
use crate::PushPreferences;

struct MockHttpOutcome {
    status: &'static str,
    headers: Vec<(&'static str, &'static str)>,
    body: &'static str,
}

fn spawn_mock_server(responses: Vec<MockHttpOutcome>) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_thread = Arc::clone(&requests);

    thread::spawn(move || {
        for response in responses {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0_u8; 8192];
            let bytes_read = stream.read(&mut buffer).unwrap();
            requests_for_thread
                .lock()
                .unwrap()
                .push(String::from_utf8_lossy(&buffer[..bytes_read]).to_string());

            let mut raw = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
                response.status,
                response.body.len()
            );
            for (name, value) in response.headers {
                raw.push_str(name);
                raw.push_str(": ");
                raw.push_str(value);
                raw.push_str("\r\n");
            }
            raw.push_str("\r\n");
            raw.push_str(response.body);
            stream.write_all(raw.as_bytes()).unwrap();
        }
    });

    (format!("http://{addr}"), requests)
}

fn config<'a>() -> PushDeviceConfig<'a> {
    PushDeviceConfig {
        principal_id: Some("did:web:alice.example"),
        device_id: "did:web:alice.example#device-phone",
        push_key: Some("fcm:very-secret-token"),
        platform: Some("android"),
        app_id: Some("app.example.android"),
        domestic_app_id: None,
        registration_id: Some("ck:pushreg:01JS0KE000000000000000000"),
        display_name: Some("Alice Phone"),
        idempotency_key: Some("idem-1"),
        request_id: Some("ck:request:test"),
        proof: None,
    }
}

fn prefs() -> PushPreferences {
    PushPreferences {
        enabled: true,
        ..Default::default()
    }
}

fn binding() -> crate::GatewayBinding {
    crate::GatewayBinding::new(
        crate::PushGatewayType::Standard,
        "https://push.example.com/_cokret/edge/push/notify",
    )
}

/// Build a happy-path client with a dummy session grant pre-attached.
///
/// Mirrors production usage where every register/unregister call is
/// expected to carry a soland session grant. Tests that specifically
/// exercise the "missing grant" path use raw `CokretPushClient::new`.
fn client(base_url: impl Into<String>) -> CokretPushClient {
    CokretPushClient::new(base_url)
        .with_session_grant("test-session-grant")
        .expect("test session grant header is valid")
}

#[tokio::test]
async fn register_success_exposes_response_context_and_headers() {
    let (base_url, requests) = spawn_mock_server(vec![MockHttpOutcome {
        status: "200 OK",
        headers: vec![(COKRET_REQUEST_ID_HEADER, "ck:request:server")],
        body: r#"{"ok":true,"registration_id":"reg-1","expires_at":"2026-04-29T00:00:00Z"}"#,
    }]);

    let response = client(base_url)
        .with_bearer_token("session-secret")
        .with_user_agent("test-agent")
        .with_header(
            "Signature-Input",
            r#"sig1=("@method" "@target-uri" "content-digest")"#,
        )
        .unwrap()
        .register_device_with_context(&config(), &binding(), &prefs())
        .await
        .unwrap();

    assert!(response.body.ok);
    assert_eq!(response.body.registration_id.as_deref(), Some("reg-1"));
    assert_eq!(response.request_id.as_deref(), Some("ck:request:server"));

    let request = requests.lock().unwrap().join("\n");
    assert!(request.contains("POST /_cokret/edge/push/register-device HTTP/1.1"));
    assert!(request.contains("authorization: Bearer session-secret"));
    assert!(request.contains("idempotency-key: idem-1"));
    assert!(request.contains("x-cokret-request-id: ck:request:test"));
    assert!(request.contains("user-agent: test-agent"));
    assert!(request.contains("\"idempotency_key\":\"idem-1\""));
}

#[tokio::test]
async fn client_default_headers_fill_request_metadata() {
    let (base_url, requests) = spawn_mock_server(vec![MockHttpOutcome {
        status: "200 OK",
        headers: vec![],
        body: r#"{"ok":true}"#,
    }]);
    let mut config = config();
    config.idempotency_key = None;
    config.request_id = None;

    CokretPushClient::new(base_url)
        .with_default_idempotency_key("client-idem")
        .with_default_request_id("ck:request:client")
        .with_session_grant("coauth-grant-secret")
        .unwrap()
        .register_device(&config, &binding(), &prefs())
        .await
        .unwrap();

    let request = requests.lock().unwrap().join("\n");
    assert!(request.contains("idempotency-key: client-idem"));
    assert!(request.contains("x-cokret-request-id: ck:request:client"));
    assert!(request.contains("x-cokret-session-grant: coauth-grant-secret"));
}

#[tokio::test]
async fn unregister_success() {
    let (base_url, requests) = spawn_mock_server(vec![MockHttpOutcome {
        status: "200 OK",
        headers: vec![],
        body: r#"{"ok":true}"#,
    }]);

    let response = client(base_url)
        .unregister_device(&config(), &binding(), &prefs())
        .await
        .unwrap();

    assert!(response.ok);
    let request = requests.lock().unwrap().join("\n");
    assert!(request.contains("POST /_cokret/edge/push/unregister-device HTTP/1.1"));
    assert!(request.contains("\"registration_id\":\"ck:pushreg:01JS0KE000000000000000000\""));
}

#[tokio::test]
async fn unregister_not_found_is_idempotent_success() {
    let (base_url, _) = spawn_mock_server(vec![MockHttpOutcome {
        status: "404 Not Found",
        headers: vec![(COKRET_REQUEST_ID_HEADER, "ck:request:not-found")],
        body: r#"{"ok":false,"error":{"code":"not_found","message":"missing"}}"#,
    }]);

    let response = client(base_url)
        .unregister_device_with_context(&config(), &binding(), &prefs())
        .await
        .unwrap();

    assert!(response.body.ok);
    assert_eq!(response.request_id.as_deref(), Some("ck:request:not-found"));
}

#[tokio::test]
async fn classifies_json_error_responses() {
    let cases = [
        (
            "400 Bad Request",
            "schema_violation",
            PushErrorKind::SchemaViolation,
        ),
        (
            "401 Unauthorized",
            "unauthenticated",
            PushErrorKind::Unauthenticated,
        ),
        (
            "403 Forbidden",
            "capability_denied",
            PushErrorKind::CapabilityDenied,
        ),
        (
            "409 Conflict",
            "duplicate_conflict",
            PushErrorKind::DuplicateConflict,
        ),
    ];

    for (status, code, expected) in cases {
        let body = format!(
            r#"{{"ok":false,"error":{{"code":"{code}","message":"x"}},"request_id":"ck:request:error"}}"#
        );
        let (base_url, _) = spawn_mock_server(vec![MockHttpOutcome {
            status,
            headers: vec![],
            body: Box::leak(body.into_boxed_str()),
        }]);

        let err = client(base_url)
            .register_device(&config(), &binding(), &prefs())
            .await
            .unwrap_err();

        assert_eq!(err.kind(), expected);
        assert_eq!(err.request_id(), Some("ck:request:error"));
    }
}

#[tokio::test]
async fn exposes_non_json_error_body_without_debug_leak() {
    let (base_url, _) = spawn_mock_server(vec![MockHttpOutcome {
        status: "500 Internal Server Error",
        headers: vec![],
        body: "not json",
    }]);

    let err = client(base_url)
        .register_device(&config(), &binding(), &prefs())
        .await
        .unwrap_err();

    assert_eq!(err.kind(), PushErrorKind::HttpStatus);
    assert!(format!("{err:?}").contains("body_len"));
    assert!(!format!("{err:?}").contains("not json"));
}

#[tokio::test]
async fn invalid_success_schema_is_invalid_response() {
    let (base_url, _) = spawn_mock_server(vec![MockHttpOutcome {
        status: "200 OK",
        headers: vec![],
        body: r#"{"ok":"yes","registration_id":42}"#,
    }]);

    let err = client(base_url)
        .register_device(&config(), &binding(), &prefs())
        .await
        .unwrap_err();

    assert_eq!(err.kind(), PushErrorKind::InvalidResponse);
}

#[tokio::test]
async fn error_debug_redacts_envelope_message_and_details() {
    let (base_url, _) = spawn_mock_server(vec![MockHttpOutcome {
        status: "403 Forbidden",
        headers: vec![],
        body: r#"{"ok":false,"error":{"code":"capability_denied","message":"token fcm:very-secret-token proof super-secret-proof","details":{"proof":"super-secret-proof","push_key":"fcm:very-secret-token"}}}"#,
    }]);

    let err = client(base_url)
        .register_device(&config(), &binding(), &prefs())
        .await
        .unwrap_err();

    let debug = format!("{err:?}");
    assert_eq!(err.kind(), PushErrorKind::CapabilityDenied);
    assert!(!debug.contains("very-secret-token"));
    assert!(!debug.contains("super-secret-proof"));
    assert!(debug.contains("details_present"));
}

#[tokio::test]
async fn retries_429_and_honors_retry_after() {
    let (base_url, requests) = spawn_mock_server(vec![
        MockHttpOutcome {
            status: "429 Too Many Requests",
            headers: vec![(RETRY_AFTER_HEADER, "0")],
            body: r#"{"ok":false,"error":{"code":"rate_limited","message":"slow"}}"#,
        },
        MockHttpOutcome {
            status: "200 OK",
            headers: vec![],
            body: r#"{"ok":true}"#,
        },
    ]);

    let response = client(base_url)
        .with_retry_policy(PushRetryPolicy {
            max_retries: 1,
            initial_backoff: Duration::ZERO,
            max_backoff: Duration::ZERO,
            jitter: Duration::ZERO,
            disabled_kinds_mask: 0,
        })
        .register_device(&config(), &binding(), &prefs())
        .await
        .unwrap();

    assert!(response.ok);
    assert_eq!(requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn default_register_rejects_without_session_grant() {
    // Default `require_session_grant = true` ⇒ no mock server needed:
    // the call fails fast before any request is sent.
    let err = CokretPushClient::new("https://principal.example")
        .register_device(&config(), &binding(), &prefs())
        .await
        .unwrap_err();

    assert_eq!(err.kind(), PushErrorKind::MissingField);
}

#[tokio::test]
async fn default_register_allows_with_session_grant_header() {
    let (base_url, requests) = spawn_mock_server(vec![MockHttpOutcome {
        status: "200 OK",
        headers: vec![],
        body: r#"{"ok":true,"registration_id":"reg-1"}"#,
    }]);

    let response = CokretPushClient::new(base_url)
        .with_session_grant("coauth-grant-secret")
        .unwrap()
        .register_device(&config(), &binding(), &prefs())
        .await
        .unwrap();

    assert!(response.ok);
    let raw = requests.lock().unwrap().join("\n");
    assert!(raw.contains("x-cokret-session-grant: coauth-grant-secret"));
}

#[tokio::test]
async fn default_unregister_rejects_without_session_grant() {
    let err = CokretPushClient::new("https://principal.example")
        .unregister_device(&config(), &binding(), &prefs())
        .await
        .unwrap_err();

    assert_eq!(err.kind(), PushErrorKind::MissingField);
}

#[tokio::test]
async fn opting_out_session_grant_allows_register_without_header() {
    let (base_url, _) = spawn_mock_server(vec![MockHttpOutcome {
        status: "200 OK",
        headers: vec![],
        body: r#"{"ok":true}"#,
    }]);

    let response = CokretPushClient::new(base_url)
        .with_required_session_grant(false)
        .register_device(&config(), &binding(), &prefs())
        .await
        .unwrap();

    assert!(response.ok);
}

#[tokio::test]
async fn register_auto_generates_idempotency_key_when_omitted() {
    let (base_url, requests) = spawn_mock_server(vec![
        MockHttpOutcome {
            status: "503 Service Unavailable",
            headers: vec![(RETRY_AFTER_HEADER, "0")],
            body: r#"{"ok":false,"error":{"code":"temporarily_unavailable","message":"try later"}}"#,
        },
        MockHttpOutcome {
            status: "200 OK",
            headers: vec![],
            body: r#"{"ok":true}"#,
        },
    ]);
    let mut config = config();
    config.idempotency_key = None;

    let response = client(base_url)
        .with_retry_policy(PushRetryPolicy {
            max_retries: 1,
            initial_backoff: Duration::ZERO,
            max_backoff: Duration::ZERO,
            jitter: Duration::ZERO,
            disabled_kinds_mask: 0,
        })
        .register_device(&config, &binding(), &prefs())
        .await
        .unwrap();

    assert!(response.ok);

    let recorded = requests.lock().unwrap();
    assert_eq!(
        recorded.len(),
        2,
        "auto-generated key should make POST retryable"
    );

    let key_of = |raw: &String| -> Option<String> {
        raw.lines()
            .find(|line| line.to_ascii_lowercase().starts_with("idempotency-key:"))
            .and_then(|line| line.split_once(':'))
            .map(|(_, value)| value.trim().to_owned())
    };

    let first = key_of(&recorded[0]).expect("first request carries idempotency key");
    let second = key_of(&recorded[1]).expect("retry carries idempotency key");
    assert_eq!(first, second, "retry must reuse the same key");
    assert!(first.starts_with("ck-sdk-"));
}

#[tokio::test]
async fn does_not_retry_duplicate_conflict() {
    let (base_url, requests) = spawn_mock_server(vec![MockHttpOutcome {
        status: "409 Conflict",
        headers: vec![],
        body: r#"{"ok":false,"error":{"code":"duplicate_conflict","message":"different body"}}"#,
    }]);

    let err = client(base_url)
        .with_retry_policy(PushRetryPolicy {
            max_retries: 2,
            initial_backoff: Duration::ZERO,
            max_backoff: Duration::ZERO,
            jitter: Duration::ZERO,
            disabled_kinds_mask: 0,
        })
        .register_device(&config(), &binding(), &prefs())
        .await
        .unwrap_err();

    assert_eq!(err.kind(), PushErrorKind::DuplicateConflict);
    assert_eq!(requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn retries_503() {
    let (base_url, requests) = spawn_mock_server(vec![
        MockHttpOutcome {
            status: "503 Service Unavailable",
            headers: vec![(RETRY_AFTER_HEADER, "0")],
            body: r#"{"ok":false,"error":{"code":"temporarily_unavailable","message":"try later"}}"#,
        },
        MockHttpOutcome {
            status: "200 OK",
            headers: vec![],
            body: r#"{"ok":true}"#,
        },
    ]);

    let response = client(base_url)
        .with_retry_policy(PushRetryPolicy {
            max_retries: 1,
            initial_backoff: Duration::ZERO,
            max_backoff: Duration::ZERO,
            jitter: Duration::ZERO,
            disabled_kinds_mask: 0,
        })
        .register_device(&config(), &binding(), &prefs())
        .await
        .unwrap();

    assert!(response.ok);
    assert_eq!(requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn disabled_kinds_skip_otherwise_retryable_error() {
    // 503 normally retries, but with TemporarilyUnavailable disabled
    // the very first response should be surfaced immediately.
    let (base_url, requests) = spawn_mock_server(vec![MockHttpOutcome {
        status: "503 Service Unavailable",
        headers: vec![(RETRY_AFTER_HEADER, "0")],
        body: r#"{"ok":false,"error":{"code":"temporarily_unavailable","message":"down"}}"#,
    }]);

    let policy = PushRetryPolicy {
        max_retries: 3,
        initial_backoff: Duration::ZERO,
        max_backoff: Duration::ZERO,
        jitter: Duration::ZERO,
        disabled_kinds_mask: 0,
    }
    .with_disabled_kinds(&[PushErrorKind::TemporarilyUnavailable]);

    assert!(policy.retries_disabled_for(PushErrorKind::TemporarilyUnavailable));
    assert!(!policy.retries_disabled_for(PushErrorKind::RateLimited));

    let err = client(base_url)
        .with_retry_policy(policy)
        .register_device(&config(), &binding(), &prefs())
        .await
        .unwrap_err();

    assert_eq!(err.kind(), PushErrorKind::TemporarilyUnavailable);
    assert_eq!(requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn register_device_all_exercises_each_binding_independently() {
    // Two bindings → two responses. We pre-load the mock server
    // with one response per expected request.
    let (base_url, requests) = spawn_mock_server(vec![
        MockHttpOutcome {
            status: "200 OK",
            headers: vec![],
            body: r#"{"ok":true,"registration_id":"reg-standard"}"#,
        },
        MockHttpOutcome {
            status: "200 OK",
            headers: vec![],
            body: r#"{"ok":true,"registration_id":"reg-bugle"}"#,
        },
    ]);

    let prefs = PushPreferences {
        enabled: true,
        gateways: vec![
            crate::GatewayBinding::new(
                crate::PushGatewayType::Standard,
                "https://push.example.com/_cokret/edge/push/notify",
            ),
            crate::GatewayBinding::new(
                crate::PushGatewayType::Bugle,
                "https://push.palpo.im/_cokret/edge/push/notify",
            )
            .with_push_key("vendor-token-cn-aaaaaaaaaa")
            .with_app_id("app.example.android.cn"),
        ],
        ..Default::default()
    };

    let results = client(base_url)
        .register_device_all(&config(), &prefs)
        .await;

    assert_eq!(results.len(), 2);
    let r0 = results[0].as_ref().unwrap();
    let r1 = results[1].as_ref().unwrap();
    assert_eq!(r0.registration_id.as_deref(), Some("reg-standard"));
    assert_eq!(r1.registration_id.as_deref(), Some("reg-bugle"));

    let raw = requests.lock().unwrap().join("\n");
    // Standard gateway uses caller-supplied token; Bugle uses
    // per-binding override.
    assert!(raw.contains("https://push.example.com"));
    assert!(raw.contains("https://push.palpo.im"));
    assert!(raw.contains("vendor-token-cn-aaaaaaaaaa"));
    // Per-binding app_id override propagates to the Bugle request.
    assert!(raw.contains("app.example.android.cn"));
}

#[tokio::test]
async fn register_device_all_returns_empty_when_no_bindings_configured() {
    // No mock server needed — empty `gateways` means no HTTP work.
    let results = client("http://127.0.0.1:1")
        .register_device_all(&config(), &prefs())
        .await;

    assert!(results.is_empty());
}

/// A.5 #2 — formatting a [`CokretPushClient`] through `{:?}` MUST
/// NOT leak the bearer token. We assert the redaction marker is
/// present and the secret is absent in both the option-empty and
/// option-present arms so a future refactor that drops the
/// `SecretString` wrapper trips this test.
#[test]
fn bearer_token_is_redacted_in_debug_output() {
    let secret = "super-secret-session-bearer-do-not-log";

    let no_token = CokretPushClient::new("https://principal.example");
    let no_token_debug = format!("{no_token:?}");
    assert!(no_token_debug.contains("bearer_token: None"));
    assert!(!no_token_debug.contains(secret));

    let with_token = CokretPushClient::new("https://principal.example").with_bearer_token(secret);
    let debug = format!("{with_token:?}");
    assert!(
        !debug.contains(secret),
        "bearer token leaked through Debug: {debug}"
    );
    assert!(
        debug.contains("<redacted>"),
        "Debug output is missing the redaction marker: {debug}"
    );
}
