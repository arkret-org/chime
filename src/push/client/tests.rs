use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;

use super::super::errors::{PushErrorKind, PushRegistrationError};
use super::super::registration::{build_register_device_request, build_unregister_device_request};
use super::super::wire::{
    ChimePushRegisterDeviceRequest, ChimePushUnregisterDeviceRequest, PushDeviceConfig,
};
use super::super::{ARKRET_REQUEST_ID_HEADER, RETRY_AFTER_HEADER};
use super::core::ArkretPushClient;
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
        device_id: "ak:device:01904100-0000-7000-8000-000000000005",
        push_key: Some("fcm:very-secret-token"),
        platform: Some("android"),
        app_id: Some("app.example.android"),
        domestic_app_id: None,
        registration_id: Some("pushreg-01JS0KE000000000000000000"),
        display_name: Some("Alice Phone"),
        idempotency_key: Some("idem-1"),
        request_id: Some("ak:request:01904100-0000-7000-8000-000000000020"),
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
        "https://push.example.com/_arkret/edge/push/notify",
    )
}

fn register_request() -> ChimePushRegisterDeviceRequest {
    build_register_device_request(&config(), &binding(), &prefs()).unwrap()
}

fn unregister_request() -> ChimePushUnregisterDeviceRequest {
    build_unregister_device_request(&config(), &binding(), &prefs()).unwrap()
}

/// Build a happy-path client with a dummy session grant pre-attached.
///
/// Mirrors production usage where every register/unregister call is
/// expected to carry a soland session grant. Tests that specifically
/// exercise the "missing grant" path use raw `ArkretPushClient::new`.
fn client(base_url: impl Into<String>) -> ArkretPushClient {
    ArkretPushClient::new(base_url)
        .with_session_grant("test-session-grant")
        .expect("test session grant header is valid")
}

#[tokio::test]
async fn register_success_exposes_response_context_and_headers() {
    let (base_url, requests) = spawn_mock_server(vec![MockHttpOutcome {
        status: "200 OK",
        headers: vec![(
            ARKRET_REQUEST_ID_HEADER,
            "ak:request:01904100-0000-7000-8000-000000000021",
        )],
        body: r#"{"ok":true,"push_target_id":"ak:pseudonym:push:ABCDEFGHIJKLMNOPQRSTUV","registration_id":"reg-1","expires_at":"2026-04-29T00:00:00.000Z"}"#,
    }]);

    let request = register_request();
    let response = client(base_url)
        .with_bearer_token("session-secret")
        .register_device_with_request(&request, None, request.request_id.as_deref())
        .await
        .unwrap();

    assert!(response.body.ok);
    assert_eq!(response.body.registration_id.as_deref(), Some("reg-1"));
    assert_eq!(
        response.request_id.as_deref(),
        Some("ak:request:01904100-0000-7000-8000-000000000021")
    );

    let raw = requests.lock().unwrap().join("\n");
    assert!(raw.contains("POST /_arkret/edge/push/register-device HTTP/1.1"));
    assert!(raw.contains("authorization: Bearer session-secret"));
    // CHIME-01: idempotency key, request id, operation id, and proof are
    // header / path concerns — they ride the headers, never the
    // canonical wire body.
    assert!(raw.contains("idempotency-key: idem-1"));
    assert!(raw.contains("x-arkret-request-id: ak:request:01904100-0000-7000-8000-000000000020"));
    assert!(raw.contains("user-agent: chime/"));

    // CHIME-01: the POSTed body is the canonical
    // `PushRegisterDeviceRequestBody` (`additionalProperties:false`), so it
    // MUST NOT carry any of the transport-only fields the local builder
    // tracks. Split off the headers so we only inspect the JSON body.
    let body = raw.rsplit("\r\n\r\n").next().expect("request has a body");
    for forbidden in [
        "\"idempotency_key\"",
        "\"operation_id\"",
        "\"principal_id\"",
        "\"request_id\"",
        "\"proof\"",
    ] {
        assert!(
            !body.contains(forbidden),
            "register wire body must not contain {forbidden}: {body}"
        );
    }
}

#[tokio::test]
async fn unregister_success() {
    let (base_url, requests) = spawn_mock_server(vec![MockHttpOutcome {
        status: "200 OK",
        headers: vec![],
        body: r#"{"ok":true}"#,
    }]);

    let response = client(base_url)
        .unregister_device_with_request(&unregister_request(), None, None)
        .await
        .unwrap();

    assert!(response.body.ok);
    let request = requests.lock().unwrap().join("\n");
    assert!(request.contains("POST /_arkret/edge/push/unregister-device HTTP/1.1"));
    let body = request
        .rsplit("\r\n\r\n")
        .next()
        .expect("request has a body");
    assert!(body.contains("\"device_id\":\"ak:device:01904100-0000-7000-8000-000000000005\""));
    assert!(body.contains("\"push_key\":\"fcm:very-secret-token\""));
    assert!(body.contains("\"app_id\":\"app.example.android\""));
    assert!(
        !body.contains("\"registration_id\""),
        "unregister wire body must not contain registration_id: {body}"
    );
}

#[tokio::test]
async fn unregister_not_found_is_idempotent_success() {
    let (base_url, _) = spawn_mock_server(vec![MockHttpOutcome {
        status: "404 Not Found",
        headers: vec![(
            ARKRET_REQUEST_ID_HEADER,
            "ak:request:01904100-0000-7000-8000-000000000023",
        )],
        body: r#"{"ok":false,"error":{"code":"not_found","message":"missing"}}"#,
    }]);

    let response = client(base_url)
        .unregister_device_with_request(&unregister_request(), None, None)
        .await
        .unwrap();

    assert!(response.body.ok);
    assert_eq!(
        response.request_id.as_deref(),
        Some("ak:request:01904100-0000-7000-8000-000000000023")
    );
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
            r#"{{"ok":false,"error":{{"code":"{code}","message":"x"}},"request_id":"ak:request:01904100-0000-7000-8000-000000000024"}}"#
        );
        let (base_url, _) = spawn_mock_server(vec![MockHttpOutcome {
            status,
            headers: vec![],
            body: Box::leak(body.into_boxed_str()),
        }]);

        let err = client(base_url)
            .register_device_with_request(&register_request(), None, None)
            .await
            .unwrap_err();

        assert_eq!(err.kind(), expected);
        assert_eq!(
            err.request_id(),
            Some("ak:request:01904100-0000-7000-8000-000000000024")
        );
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
        .register_device_with_request(&register_request(), None, None)
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
        .register_device_with_request(&register_request(), None, None)
        .await
        .unwrap_err();

    assert_eq!(err.kind(), PushErrorKind::ResponseInvalid);
}

#[tokio::test]
async fn rejects_oversized_response_before_json_decode() {
    let body = "x".repeat(super::transport::MAX_RESPONSE_BODY_BYTES + 1);
    let (base_url, _) = spawn_mock_server(vec![MockHttpOutcome {
        status: "200 OK",
        headers: vec![],
        body: Box::leak(body.into_boxed_str()),
    }]);

    let error = client(base_url)
        .register_device_with_request(&register_request(), None, None)
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        PushRegistrationError::ResponseTooLarge { .. }
    ));
}

#[tokio::test]
async fn error_debug_redacts_envelope_message_and_details() {
    let (base_url, _) = spawn_mock_server(vec![MockHttpOutcome {
        status: "403 Forbidden",
        headers: vec![],
        body: r#"{"ok":false,"error":{"code":"capability_denied","message":"token fcm:very-secret-token proof super-secret-proof","details":{"proof":"super-secret-proof","push_key":"fcm:very-secret-token"}},"request_id":"ak:request:01904100-0000-7000-8000-000000000025"}"#,
    }]);

    let err = client(base_url)
        .register_device_with_request(&register_request(), None, None)
        .await
        .unwrap_err();

    let debug = format!("{err:?}");
    assert_eq!(err.kind(), PushErrorKind::CapabilityDenied);
    assert!(
        err.error_envelope()
            .is_some_and(|envelope| !envelope.error.details.is_empty())
    );
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
            body: r#"{"ok":true,"push_target_id":"ak:pseudonym:push:ABCDEFGHIJKLMNOPQRSTUV"}"#,
        },
    ]);

    let response = client(base_url)
        .with_retry_policy(PushRetryPolicy {
            retry: arkret_retry::RetryPolicy::none().with_max_retries(1),
            disabled_kinds_mask: 0,
        })
        .register_device_with_request(&register_request(), None, None)
        .await
        .unwrap();

    assert!(response.body.ok);
    assert_eq!(requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn default_register_rejects_without_session_grant() {
    // Default `require_session_grant = true` ⇒ no mock server needed:
    // the call fails fast before any request is sent.
    let err = ArkretPushClient::new("https://principal.example")
        .register_device_with_request(&register_request(), None, None)
        .await
        .unwrap_err();

    assert_eq!(err.kind(), PushErrorKind::MissingField);
}

#[tokio::test]
async fn default_register_allows_with_session_grant_header() {
    let (base_url, requests) = spawn_mock_server(vec![MockHttpOutcome {
        status: "200 OK",
        headers: vec![],
        body: r#"{"ok":true,"push_target_id":"ak:pseudonym:push:ABCDEFGHIJKLMNOPQRSTUV","registration_id":"reg-1"}"#,
    }]);

    let response = ArkretPushClient::new(base_url)
        .with_session_grant("coauth-grant-secret")
        .unwrap()
        .register_device_with_request(&register_request(), None, None)
        .await
        .unwrap();

    assert!(response.body.ok);
    let raw = requests.lock().unwrap().join("\n");
    assert!(raw.contains("x-arkret-session-grant: coauth-grant-secret"));
}

#[tokio::test]
async fn default_unregister_rejects_without_session_grant() {
    let err = ArkretPushClient::new("https://principal.example")
        .unregister_device_with_request(&unregister_request(), None, None)
        .await
        .unwrap_err();

    assert_eq!(err.kind(), PushErrorKind::MissingField);
}

#[tokio::test]
async fn opting_out_session_grant_allows_register_without_header() {
    let (base_url, _) = spawn_mock_server(vec![MockHttpOutcome {
        status: "200 OK",
        headers: vec![],
        body: r#"{"ok":true,"push_target_id":"ak:pseudonym:push:ABCDEFGHIJKLMNOPQRSTUV"}"#,
    }]);

    let response = ArkretPushClient::new(base_url)
        .with_required_session_grant(false)
        .register_device_with_request(&register_request(), None, None)
        .await
        .unwrap();

    assert!(response.body.ok);
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
            body: r#"{"ok":true,"push_target_id":"ak:pseudonym:push:ABCDEFGHIJKLMNOPQRSTUV"}"#,
        },
    ]);
    let mut config = config();
    config.idempotency_key = None;
    let request = build_register_device_request(&config, &binding(), &prefs()).unwrap();

    let response = client(base_url)
        .with_retry_policy(PushRetryPolicy {
            retry: arkret_retry::RetryPolicy::none().with_max_retries(1),
            disabled_kinds_mask: 0,
        })
        .register_device_with_request(&request, None, None)
        .await
        .unwrap();

    assert!(response.body.ok);

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
    assert!(first.starts_with("chime-sdk-"));
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
            retry: arkret_retry::RetryPolicy::none().with_max_retries(2),
            disabled_kinds_mask: 0,
        })
        .register_device_with_request(&register_request(), None, None)
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
            body: r#"{"ok":true,"push_target_id":"ak:pseudonym:push:ABCDEFGHIJKLMNOPQRSTUV"}"#,
        },
    ]);

    let response = client(base_url)
        .with_retry_policy(PushRetryPolicy {
            retry: arkret_retry::RetryPolicy::none().with_max_retries(1),
            disabled_kinds_mask: 0,
        })
        .register_device_with_request(&register_request(), None, None)
        .await
        .unwrap();

    assert!(response.body.ok);
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
        retry: arkret_retry::RetryPolicy::none().with_max_retries(3),
        disabled_kinds_mask: 0,
    }
    .with_disabled_kinds(&[PushErrorKind::TemporarilyUnavailable]);

    assert!(policy.retries_disabled_for(PushErrorKind::TemporarilyUnavailable));
    assert!(!policy.retries_disabled_for(PushErrorKind::RateLimited));

    let err = client(base_url)
        .with_retry_policy(policy)
        .register_device_with_request(&register_request(), None, None)
        .await
        .unwrap_err();

    assert_eq!(err.kind(), PushErrorKind::TemporarilyUnavailable);
    assert_eq!(requests.lock().unwrap().len(), 1);
}

/// A.5 #2 — formatting a [`ArkretPushClient`] through `{:?}` MUST
/// NOT leak the bearer token. We assert the redaction marker is
/// present and the secret is absent in both the option-empty and
/// option-present arms so a future refactor that drops the
/// `SecretString` wrapper trips this test.
#[test]
fn bearer_token_is_redacted_in_debug_output() {
    let secret = "super-secret-session-bearer-do-not-log";

    let no_token = ArkretPushClient::new("https://principal.example");
    let no_token_debug = format!("{no_token:?}");
    assert!(no_token_debug.contains("bearer_token: None"));
    assert!(!no_token_debug.contains(secret));

    let with_token = ArkretPushClient::new("https://principal.example").with_bearer_token(secret);
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
