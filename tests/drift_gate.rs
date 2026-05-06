//! Drift-gate integration test (F4).
//!
//! Locks down the canonical floria `bridge/describe` shape in a single
//! frozen JSON fixture. If floria adds, removes, or renames a field that
//! chime cares about, this test fails in CI and the SDK is forced to
//! re-align before merging.
//!
//! The fixture also contains an embedded `blind_wakeup_request` example
//! that is parsed back through `PushNotifyRequest` + `validate_blind_wakeup`,
//! catching drift in the privacy contract end-to-end.

#![cfg(feature = "notify")]

use chime::{
    BridgeContractCache, BridgeContractDriftVerdict, PushBridgeDescribeResponse,
    PushNotifyPrivacyMode, PushNotifyRequest,
};

/// Canonical floria `bridge/describe` payload (snapshot 2026-05-06).
///
/// Update *deliberately* when floria's bridge contract advances; never
/// silently. The accompanying assertions encode the SDK's expectations.
const BRIDGE_DESCRIBE_FIXTURE: &str = r#"{
    "contract": "cx.push.bridge.v1",
    "version": "1.0.0",
    "api_base_path": "/api/v1",
    "gateway": {
        "service_did": "did:web:gateway.example",
        "supported_profiles": ["fcm", "apns", "webpush"],
        "supported_providers": ["fcm", "apns"],
        "auth_modes": ["http-message-signature", "bearer"]
    },
    "notify": {
        "notify_path": "/api/v1/push/notify",
        "legacy_notify_aliases": [],
        "operation_id": "cx.push.notify",
        "request_id_header": "X-Contrix-Request-Id",
        "idempotency_key_header": "X-Contrix-Idempotency-Key",
        "origin_service_did_header": "X-Contrix-Origin-Service-Did",
        "destination_service_did_header": "X-Contrix-Destination-Service-Did",
        "max_request_size_bytes": 16384,
        "dedup_backend": "redis",
        "dedup_ttl_seconds": 300,
        "rate_limit_window_seconds": 60,
        "rate_limit_scopes": ["per-app", "per-actor"]
    },
    "privacy": {
        "default_mode": "e2ee_blind_wakeup",
        "plaintext_visibility_class": "explicit-opt-in",
        "active_reference_fields": ["flow_id", "message_id", "notification_projection_id"],
        "rejected_legacy_fields": ["room_id", "card_id", "subject_id"]
    },
    "examples": {
        "notify_headers": {
            "X-Contrix-Operation-Id": "cx.push.notify",
            "X-Contrix-Request-Id": "cx:req:01JS0KE000000000000000000"
        },
        "blind_wakeup_request": {
            "operation_id": "cx.push.notify",
            "notification": {
                "event_id": "cx:event:01JS0EV000000000000000000",
                "space_id": "cx:space:01JS0SP000000000000000000",
                "type": "cx.message.create",
                "push_hint": "wakeup-msg-1",
                "counts": { "unread": 1 },
                "devices": [
                    {
                        "push_key": "fcm:opaque-token",
                        "push_key_hash": "sha256:abc",
                        "app_id": "app.example.android"
                    }
                ]
            }
        },
        "plaintext_visible_service_request": null
    },
    "todos": []
}"#;

#[test]
fn bridge_describe_fixture_round_trips_into_chime_dto() {
    let response: PushBridgeDescribeResponse =
        serde_json::from_str(BRIDGE_DESCRIBE_FIXTURE).expect("fixture must parse");

    assert_eq!(response.contract, "cx.push.bridge.v1");
    assert_eq!(response.version, "1.0.0");
    assert!(response.gateway.supports_profile("fcm"));
    assert!(response.notify.supports_dedup());
    assert!(response.notify.rate_limits_by("per-app"));
    assert!(
        response
            .privacy
            .rejected_legacy_fields
            .iter()
            .any(|field| field == "room_id"),
        "spec must keep rejecting legacy room_id"
    );
}

#[test]
fn bridge_describe_fixture_blind_wakeup_example_validates() {
    let response: PushBridgeDescribeResponse =
        serde_json::from_str(BRIDGE_DESCRIBE_FIXTURE).expect("fixture must parse");

    let example = response.examples.blind_wakeup_request.clone();
    assert!(
        !example.is_null(),
        "fixture must carry a blind-wakeup example"
    );

    let request: PushNotifyRequest =
        serde_json::from_value(example).expect("blind-wakeup example must parse as a request");

    request
        .validate_privacy(PushNotifyPrivacyMode::E2eeBlindWakeup)
        .expect("blind-wakeup example must satisfy the privacy gate");
}

#[test]
fn bridge_describe_digest_is_stable_across_serialize_round_trip() {
    let response: PushBridgeDescribeResponse =
        serde_json::from_str(BRIDGE_DESCRIBE_FIXTURE).unwrap();
    let cache = BridgeContractCache::from_response(&response, Some("2026-05-06T00:00:00Z"));

    // Re-deserialize through serde and confirm the digest stays put.
    let json = serde_json::to_string(&response).unwrap();
    let round_trip: PushBridgeDescribeResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(
        cache.evaluate(&round_trip),
        BridgeContractDriftVerdict::Unchanged
    );
}
