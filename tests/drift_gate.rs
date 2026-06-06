//! Drift-gate integration test (F4).
//!
//! Locks down the canonical floria `bridge/describe` shape in a single
//! frozen JSON fixture. If floria adds, removes, or renames a field that
//! chime cares about, this test fails in CI and the SDK is forced to
//! re-align before merging.
//!
//! The fixture also contains an embedded `blind_wakeup_request` example
//! that is parsed back through `PushNotifyRequestBody` + `validate_blind_wakeup`,
//! catching drift in the privacy contract end-to-end.
//!
//! ## Snapshot
//!
//! Re-snapshotted on `2026-05-26` against floria `6496235` and
//! cokret-spec head `37ce729`. The fixture mirrors:
//!
//! - Phase P2 agent-kind routing (`ck.agent.{pause,resume,deactivate}` silent-consume;
//!   `ck.agent.{draft.propose,action_request, action_approve,action_reject}` drop unless
//!   subscribed).
//! - The seven SDK typed-id prefixes (`agent_session`, `agent_key`, `agent_draft`,
//!   `accountability_grant`, `sidecar_circle`, `backup_series`, `recovery_session`).
//!   `agent_principal_id` is a DID-as-id.

#![cfg(feature = "notify")]

use chime::{
    AGENT_ACTOR_PRIVATE_KINDS, AGENT_LIFECYCLE_DURABLE_KINDS, AgentEventRouting,
    BridgeContractCache, BridgeContractDriftVerdict, PHASE_P2_AGENT_TYPED_ID_PREFIXES,
    PushBridgeDescribeResponse, PushNotifyPrivacyMode, PushNotifyRequestBody,
    classify_agent_event_kind, is_phase_p2_agent_typed_id, render_agent_lifecycle_summary,
};

/// Canonical floria `bridge/describe` payload (snapshot 2026-05-26,
/// floria `6496235`, spec `37ce729`).
///
/// Update *deliberately* when floria's bridge contract advances; never
/// silently. The accompanying assertions encode the SDK's expectations.
const BRIDGE_DESCRIBE_FIXTURE: &str = r#"{
    "contract": "ck.push.bridge.v1",
    "version": "1.0.0",
    "api_base_path": "/_cokret/edge/push",
    "spec_version": "cokret-spec@2026-05-26",
    "gateway": {
        "service_did": "did:web:gateway.example",
        "supported_profiles": ["fcm", "apns", "webpush"],
        "supported_providers": ["fcm", "apns"],
        "auth_modes": ["http-message-signature", "bearer"]
    },
    "notify": {
        "notify_path": "/_cokret/edge/push/notify",
        "operation_id": "ck.edge.push.notify",
        "request_id_header": "X-Cokret-Request-Id",
        "idempotency_key_header": "X-Cokret-Idempotency-Key",
        "origin_service_did_header": "X-Cokret-Origin-Service-Did",
        "destination_service_did_header": "X-Cokret-Destination-Service-Did",
        "max_request_size_bytes": 16384,
        "dedup_backend": "redis",
        "dedup_ttl_seconds": 300,
        "rate_limit_window_seconds": 60,
        "rate_limit_scopes": ["per-app", "per-actor"]
    },
    "privacy": {
        "default_mode": "e2ee_blind_wakeup",
        "plaintext_visibility_class": "explicit-opt-in",
        "active_reference_fields": ["notification.push_target_id", "notification.wakeup_kind"]
    },
    "examples": {
        "notify_headers": {
            "X-Cokret-Operation-Id": "ck.edge.push.notify",
            "X-Cokret-Request-Id": "ck:request:01JS0KE000000000000000000"
        },
        "blind_wakeup_request": {
            "operation_id": "ck.edge.push.notify",
            "notification": {
                "push_target_id": "ck:pseudonym:push:01HYZ8Z000000000000000",
                "wakeup_kind": "message",
                "push_hint": "new_message",
                "counts": { "unread": 1 },
                "circle_id": "ck:circle:01HZK9Z000000000000000000",
                "effective_scope": "ck:circle:01HZK9Z000000000000000000",
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

    assert_eq!(response.contract, "ck.push.bridge.v1");
    assert_eq!(response.version, "1.0.0");
    assert_eq!(
        response.spec_version.as_deref(),
        Some("cokret-spec@2026-05-26"),
        "fixture must pin to the current spec head"
    );
    assert!(response.gateway.supports_profile("fcm"));
    assert!(response.notify.supports_dedup());
    assert!(response.notify.rate_limits_by("per-app"));
    assert!(
        response
            .privacy
            .active_reference_fields
            .iter()
            .any(|field| field == "notification.wakeup_kind"),
        "bridge describe must advertise the current wakeup field"
    );
}

#[test]
fn bridge_describe_fixture_blind_wakeup_example_validates() {
    let response: PushBridgeDescribeResponse =
        serde_json::from_str(BRIDGE_DESCRIBE_FIXTURE).expect("fixture must parse");

    let example = response.examples.blind_wakeup_request;
    assert!(
        !example.is_null(),
        "fixture must carry a blind-wakeup example"
    );

    let request: PushNotifyRequestBody =
        serde_json::from_value(example).expect("blind-wakeup example must parse as a request");

    request
        .validate_privacy(PushNotifyPrivacyMode::E2eeBlindWakeup)
        .expect("blind-wakeup example must satisfy the privacy gate");
}

#[test]
fn bridge_describe_digest_is_stable_across_serialize_round_trip() {
    let response: PushBridgeDescribeResponse =
        serde_json::from_str(BRIDGE_DESCRIBE_FIXTURE).unwrap();
    let cache = BridgeContractCache::from_response(&response, Some("2026-05-26T00:00:00Z"))
        .expect("baseline digest must compute");

    // Re-deserialize through serde and confirm the digest stays put.
    let json = serde_json::to_string(&response).unwrap();
    let round_trip: PushBridgeDescribeResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(
        cache
            .evaluate(&round_trip)
            .expect("round-trip digest must compute"),
        BridgeContractDriftVerdict::Unchanged
    );
}

// ── Phase P2 (spec 37ce729) — agent event-kind routing ─────────────────

#[test]
fn agent_lifecycle_kinds_classify_as_durable_lifecycle() {
    // Mirrors floria 6496235's `AGENT_LIFECYCLE_SILENT_KINDS` exactly.
    for kind in AGENT_LIFECYCLE_DURABLE_KINDS {
        assert_eq!(
            classify_agent_event_kind(kind),
            Some(AgentEventRouting::DurableLifecycle),
            "kind `{kind}` must classify as DurableLifecycle"
        );
        let summary = render_agent_lifecycle_summary(kind)
            .expect("durable lifecycle kinds must render a summary");
        // Summary must NOT leak any PII — only the event kind literal +
        // a stable l10n key prefix.
        assert_eq!(summary.event_kind, *kind);
        assert!(
            summary.l10n_key.starts_with("l10n_key:agent.lifecycle."),
            "summary l10n key `{}` must be a stable agent.lifecycle prefix",
            summary.l10n_key
        );
    }
    // The exact set is locked at 3.
    assert_eq!(AGENT_LIFECYCLE_DURABLE_KINDS.len(), 3);
}

#[test]
fn agent_actor_private_kinds_classify_as_actor_private() {
    // Mirrors floria 6496235's `AGENT_ACTOR_PRIVATE_KINDS` exactly.
    for kind in AGENT_ACTOR_PRIVATE_KINDS {
        assert_eq!(
            classify_agent_event_kind(kind),
            Some(AgentEventRouting::ActorPrivate),
            "kind `{kind}` must classify as ActorPrivate"
        );
        // No lifecycle summary for actor-private kinds; the host MUST
        // route them through the blind-wakeup sanitizer.
        assert!(
            render_agent_lifecycle_summary(kind).is_none(),
            "actor-private kind `{kind}` must NOT have a lifecycle summary"
        );
    }
    // The exact set is locked at 4.
    assert_eq!(AGENT_ACTOR_PRIVATE_KINDS.len(), 4);
}

#[test]
fn agent_event_kind_unknown_falls_through() {
    // Anything outside the two locked-down sets returns None — the
    // host's normal notification surface decides how to handle it.
    assert!(classify_agent_event_kind("ck.message.send").is_none());
    assert!(classify_agent_event_kind("cx.agent.unknown").is_none());
    assert!(classify_agent_event_kind("").is_none());
}

// ── Phase P2 — typed-id prefix recognizer ─────────────────────────────

#[test]
fn phase_p2_typed_id_prefixes_match_floria_6496235() {
    // The exact set is locked at 7. If floria 6496235 adds or removes a
    // prefix, this test fires loudly so the chime mirror gets updated
    // in the same change.
    assert_eq!(PHASE_P2_AGENT_TYPED_ID_PREFIXES.len(), 7);
    for prefix in PHASE_P2_AGENT_TYPED_ID_PREFIXES {
        assert!(
            prefix.starts_with("ck:"),
            "prefix `{prefix}` must be a typed-id"
        );
        assert!(prefix.ends_with(':'), "prefix `{prefix}` must end with `:`");
    }
    // Spot-check a known typed-id value passes the recognizer.
    assert!(is_phase_p2_agent_typed_id(
        "ck:agent_session:01HZK9Z000000000000000000"
    ));
    assert!(is_phase_p2_agent_typed_id(
        "ck:accountability_grant:01HZK9Z000000000000000000"
    ));
    assert!(is_phase_p2_agent_typed_id(
        "ck:sidecar_circle:01HZK9Z000000000000000000"
    ));
    // Non-agent typed ids are NOT recognized.
    assert!(!is_phase_p2_agent_typed_id(
        "ck:circle:01HZK9Z000000000000000000"
    ));
    assert!(!is_phase_p2_agent_typed_id(
        "ck:realm:01HZK9Z000000000000000000"
    ));
}

#[test]
fn agent_typed_id_in_event_id_slot_fails_closed() {
    // An agent typed-id (`ck:agent_session:...`) MUST NOT appear in
    // the wakeup's `event_id` slot — that slot is pinned to `ck:event:`.
    // chime's `validate_typed_id` already enforces the prefix, so this
    // exercises the same fail-closed rule from the wire side: the
    // typed-id appears in a slot where its `actor_kind=Agent` cousin
    // would belong on a non-Agent event.
    let frame = serde_json::json!({
        "operation_id": "ck.edge.push.notify",
        "notification": {
            "push_target_id": "ck:pseudonym:push:01HYZ8Z000000000000000",
            "wakeup_kind": "message",
            "event_id": "ck:agent_session:01HZK9Z000000000000000000",
            "devices": [
                { "push_key": "fcm:opaque-token", "app_id": "app.example" }
            ]
        }
    });
    let request: PushNotifyRequestBody =
        serde_json::from_value(frame).expect("request must parse syntactically");
    let err = request.validate_wire_model().unwrap_err();
    let field = match err {
        chime::PushNotifyPrivacyError::InvalidFieldValue { field } => field,
        other => panic!("expected InvalidFieldValue, got {other:?}"),
    };
    assert_eq!(
        field, "event_id",
        "an agent_session typed-id smuggled into the event_id slot must be rejected"
    );
}

#[test]
fn agent_typed_id_in_extra_fails_closed() {
    // Any Phase P2 agent typed-id appearing in `extra` (a non-Agent
    // wire context) is a correlation leak and MUST be rejected.
    let frame = serde_json::json!({
        "operation_id": "ck.edge.push.notify",
        "notification": {
            "push_target_id": "ck:pseudonym:push:01HYZ8Z000000000000000",
            "wakeup_kind": "message",
            "agent_link": "ck:sidecar_circle:01HZK9Z000000000000000000",
            "devices": [
                { "push_key": "fcm:opaque-token", "app_id": "app.example" }
            ]
        }
    });
    let request: PushNotifyRequestBody =
        serde_json::from_value(frame).expect("request must parse syntactically");
    let err = request.validate_wire_model().unwrap_err();
    let field = match err {
        chime::PushNotifyPrivacyError::SensitiveField { field } => field,
        other => panic!("expected SensitiveField, got {other:?}"),
    };
    assert_eq!(field, "agent_link");
}
