//! Notify/agent privacy behavior tests.
//!
//! These tests exercise chime's runtime classifiers and wire validators for
//! agent lifecycle routing and Phase P2 typed-id privacy boundaries.

#![cfg(feature = "notify")]

use chime::{
    AGENT_ACTOR_PRIVATE_KINDS, AGENT_LIFECYCLE_DURABLE_KINDS, AgentEventRouting,
    ChimePushNotifyEnvelope, PHASE_P2_AGENT_TYPED_ID_PREFIXES, classify_agent_event_kind,
    is_phase_p2_agent_typed_id, render_agent_lifecycle_summary,
};

#[test]
fn agent_lifecycle_kinds_classify_as_durable_lifecycle() {
    for kind in AGENT_LIFECYCLE_DURABLE_KINDS {
        assert_eq!(
            classify_agent_event_kind(kind),
            Some(AgentEventRouting::DurableLifecycle),
            "kind `{kind}` must classify as DurableLifecycle"
        );
        let summary = render_agent_lifecycle_summary(kind)
            .expect("durable lifecycle kinds must render a summary");
        assert_eq!(summary.event_kind, *kind);
        assert!(
            summary.l10n_key.starts_with("l10n_key:agent.lifecycle."),
            "summary l10n key `{}` must be a stable agent.lifecycle prefix",
            summary.l10n_key
        );
    }
    assert_eq!(AGENT_LIFECYCLE_DURABLE_KINDS.len(), 3);
}

#[test]
fn agent_actor_private_kinds_classify_as_actor_private() {
    for kind in AGENT_ACTOR_PRIVATE_KINDS {
        assert_eq!(
            classify_agent_event_kind(kind),
            Some(AgentEventRouting::ActorPrivate),
            "kind `{kind}` must classify as ActorPrivate"
        );
        assert!(
            render_agent_lifecycle_summary(kind).is_none(),
            "actor-private kind `{kind}` must NOT have a lifecycle summary"
        );
    }
    assert_eq!(AGENT_ACTOR_PRIVATE_KINDS.len(), 4);
}

#[test]
fn agent_event_kind_unknown_falls_through() {
    assert!(classify_agent_event_kind("ck.message.send").is_none());
    assert!(classify_agent_event_kind("cx.agent.unknown").is_none());
    assert!(classify_agent_event_kind("").is_none());
}

#[test]
fn phase_p2_typed_id_prefixes_are_recognized() {
    assert_eq!(PHASE_P2_AGENT_TYPED_ID_PREFIXES.len(), 4);
    for prefix in PHASE_P2_AGENT_TYPED_ID_PREFIXES {
        assert!(
            prefix.starts_with("ck:"),
            "prefix `{prefix}` must be a typed-id"
        );
        assert!(prefix.ends_with(':'), "prefix `{prefix}` must end with `:`");
    }
    assert!(is_phase_p2_agent_typed_id(
        "ck:agent_interop_session:01HZK9Z000000000000000000"
    ));
    assert!(is_phase_p2_agent_typed_id(
        "ck:grant:01HZK9Z000000000000000000"
    ));
    assert!(!is_phase_p2_agent_typed_id(
        "ck:circle:01HZK9Z000000000000000000"
    ));
    assert!(!is_phase_p2_agent_typed_id(
        "ck:realm:01HZK9Z000000000000000000"
    ));
}

#[test]
fn agent_typed_id_in_event_id_slot_fails_closed() {
    let frame = serde_json::json!({
        "notification": {
            "push_target_id": "ck:pseudonym:push:01HYZ8Z000000000000000",
            "wakeup_kind": "message",
            "event_id": "ck:agent_interop_session:01HZK9Z000000000000000000",
            "devices": [
                {
                    "device_id": "ck:device:01JS0D000000000000000000",
                    "push_key": "fcm:opaque-token",
                    "app_id": "app.example"
                }
            ]
        }
    });
    let request: ChimePushNotifyEnvelope =
        serde_json::from_value(frame).expect("request must parse syntactically");
    let err = request.validate_wire_model().unwrap_err();
    let field = match err {
        chime::PushNotifyPrivacyError::InvalidFieldValue { field } => field,
        other => panic!("expected InvalidFieldValue, got {other:?}"),
    };
    assert_eq!(
        field, "event_id",
        "an agent_interop_session typed-id smuggled into the event_id slot must be rejected"
    );
}

#[test]
fn agent_typed_id_in_extra_fails_closed() {
    let frame = serde_json::json!({
        "notification": {
            "push_target_id": "ck:pseudonym:push:01HYZ8Z000000000000000",
            "wakeup_kind": "message",
            "agent_link": "ck:grant:01HZK9Z000000000000000000",
            "devices": [
                {
                    "device_id": "ck:device:01JS0D000000000000000001",
                    "push_key": "fcm:opaque-token",
                    "app_id": "app.example"
                }
            ]
        }
    });
    let request: ChimePushNotifyEnvelope =
        serde_json::from_value(frame).expect("request must parse syntactically");
    let err = request.validate_wire_model().unwrap_err();
    let field = match err {
        chime::PushNotifyPrivacyError::SensitiveField { field } => field,
        other => panic!("expected SensitiveField, got {other:?}"),
    };
    assert_eq!(field, "agent_link");
}
