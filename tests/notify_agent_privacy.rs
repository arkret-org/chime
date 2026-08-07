//! Notify/agent privacy behavior tests.
//!
//! These tests exercise chime's runtime classifiers and wire validators for
//! agent lifecycle routing and Phase P2 typed-id privacy boundaries.

#![cfg(feature = "notify")]

use chime::{
    AGENT_ACTOR_PRIVATE_KINDS, AGENT_LIFECYCLE_DURABLE_KINDS, AgentEventRouting,
    PHASE_P2_AGENT_TYPED_ID_PREFIXES, PushNotifyRequestBody, classify_agent_event_kind,
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
            Some(AgentEventRouting::ActorPrivateDrop),
            "kind `{kind}` must classify as ActorPrivateDrop"
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
    assert!(classify_agent_event_kind("ak.message.send").is_none());
    assert!(classify_agent_event_kind("ak.agent.unknown").is_none());
    assert!(classify_agent_event_kind("").is_none());
}

#[test]
fn phase_p2_typed_id_prefixes_are_recognized() {
    assert_eq!(PHASE_P2_AGENT_TYPED_ID_PREFIXES.len(), 7);
    for prefix in PHASE_P2_AGENT_TYPED_ID_PREFIXES {
        assert!(
            prefix.starts_with("ak:"),
            "prefix `{prefix}` must be a typed-id"
        );
        assert!(prefix.ends_with(':'), "prefix `{prefix}` must end with `:`");
    }
    assert!(is_phase_p2_agent_typed_id(
        "ak:agent_session:01HZK9Z000000000000000000"
    ));
    assert!(is_phase_p2_agent_typed_id(
        "ak:accountability_grant:01HZK9Z000000000000000000"
    ));
    assert!(!is_phase_p2_agent_typed_id(
        "ak:circle:01HZK9Z000000000000000000"
    ));
    assert!(!is_phase_p2_agent_typed_id(
        "ak:realm:01HZK9Z000000000000000000"
    ));
}

#[test]
fn agent_typed_id_in_event_id_slot_fails_closed() {
    let frame = serde_json::json!({
        "notification": {
            "push_target_id": "ak:pseudonym:push:01HYZ8Z000000000000000",
            "wakeup_kind": "message",
            "timing_profile_hint": "default",
            "event_id": "ak:agent_session:01HZK9Z000000000000000000",
            "devices": [
                {
                    "device_id": "ak:device:01904100-0000-7000-8000-000000000010",
                    "push_key": "fcm:opaque-token",
                    "app_id": "app.example"
                }
            ]
        }
    });
    assert!(serde_json::from_value::<PushNotifyRequestBody>(frame).is_err());
}

#[test]
fn agent_typed_id_in_extra_fails_closed() {
    let frame = serde_json::json!({
        "notification": {
            "push_target_id": "ak:pseudonym:push:01HYZ8Z000000000000000",
            "wakeup_kind": "message",
            "timing_profile_hint": "default",
            "agent_link": "ak:accountability_grant:01HZK9Z000000000000000000",
            "devices": [
                {
                    "device_id": "ak:device:01904100-0000-7000-8000-000000000011",
                    "push_key": "fcm:opaque-token",
                    "app_id": "app.example"
                }
            ]
        }
    });
    assert!(serde_json::from_value::<PushNotifyRequestBody>(frame).is_err());
}
