use cokret::{AuditPolicyAccessPayload, Did, EventId};
use serde_json::Value;

use super::*;
use crate::{PushRuleEventContext, ShouldNotify, WatchLevel, push_rule_reason_code};

const REALM_ROUTE_TOKEN: &str = "realm_route_token_000000001";
const SCOPE_ROUTE_TOKEN: &str = "scope_route_token_000000001";
const ALICE_ROUTE_TOKEN: &str = "alice_route_token_000000001";
const BOB_ROUTE_TOKEN: &str = "bob_route_token_000000001";
const MALLORY_ROUTE_TOKEN: &str = "mallory_route_token_000000001";
const DEVICE_ID: &str = "ck:device:01904100-0000-7000-8000-000000000010";

fn device() -> PushNotificationDevice {
    PushNotificationDevice {
        device_id: DEVICE_ID.to_owned(),
        push_key: Some("fcm:very-secret-token".to_owned()),
        app_id: Some("app.example".to_owned()),
        target_route_token: None,
        platform: Some("android".to_owned()),
    }
}

fn notification() -> PushNotification {
    // `PushNotification` is `#[non_exhaustive]`; build through
    // `Default` and field-update so adding a new optional field
    // does not require touching every test fixture.
    PushNotification {
        push_target_id: Some(
            PushTargetId::new("ck:pseudonym:push:01HYZ8Z000000000000000").unwrap(),
        ),
        wakeup_kind: Some(WakeupKind::Message),
        route_tokens: Some(RouteTokens {
            realm_route_token: Some(REALM_ROUTE_TOKEN.to_owned()),
            ..Default::default()
        }),
        push_hint: Some(PushHint::new("new_message").unwrap()),
        counts: Some(serde_json::json!({ "badge": "2-5" })),
        devices: vec![device()],
        ..Default::default()
    }
}

fn expiry_invalidation_notification() -> PushNotification {
    PushNotification {
        wakeup_kind: Some(WakeupKind::ExpiryInvalidation),
        devices: vec![device()],
        ..Default::default()
    }
}

#[test]
fn local_notification_expiry_invalidation_revokes_visible_preview() {
    let decision = evaluate_local_notification(
        &expiry_invalidation_notification(),
        LocalNotificationState::visible_preview(),
        &LocalNotificationPolicy::default(),
    );

    assert_eq!(decision.action, LocalNotificationAction::RevokeExisting);
    assert_eq!(decision.reason_code, local_reason_code::EXPIRY_INVALIDATION);
    assert_eq!(decision.push_rule_decision, None);
    assert!(decision.action.mutates_existing());
    assert!(!decision.action.visible());
}

#[test]
fn local_notification_expiry_invalidation_can_replace_with_stub() {
    let policy = LocalNotificationPolicy {
        expiry_invalidation_behavior: ExpiryInvalidationBehavior::ReplaceWithExpiredStub,
        ..Default::default()
    };

    let decision = evaluate_local_notification(
        &expiry_invalidation_notification(),
        LocalNotificationState::visible_preview(),
        &policy,
    );

    assert_eq!(
        decision.action,
        LocalNotificationAction::ReplaceWithExpiredStub
    );
    assert_eq!(decision.reason_code, local_reason_code::EXPIRY_INVALIDATION);
    assert_eq!(decision.push_rule_decision, None);
    assert!(decision.action.mutates_existing());
    assert!(decision.action.visible());
}

#[test]
fn local_notification_expiry_invalidation_noops_without_visible_preview() {
    for state in [
        LocalNotificationState {
            visible: false,
            contains_preview: true,
        },
        LocalNotificationState {
            visible: true,
            contains_preview: false,
        },
    ] {
        let decision = evaluate_local_notification(
            &expiry_invalidation_notification(),
            state,
            &LocalNotificationPolicy::default(),
        );

        assert_eq!(decision.action, LocalNotificationAction::Noop);
        assert_eq!(decision.reason_code, local_reason_code::NO_VISIBLE_PREVIEW);
        assert_eq!(decision.push_rule_decision, None);
        assert!(!decision.action.mutates_existing());
        assert!(!decision.action.visible());
    }
}

#[test]
fn local_notification_push_rule_notify_shows_when_unrestricted() {
    let policy = LocalNotificationPolicy {
        watch_level: WatchLevel::All,
        ..Default::default()
    };

    let decision =
        evaluate_local_notification(&notification(), LocalNotificationState::default(), &policy);

    assert_eq!(decision.action, LocalNotificationAction::Show);
    assert_eq!(decision.reason_code, push_rule_reason_code::WATCH_ALLOWS);
    assert_eq!(decision.push_rule_decision, Some(ShouldNotify::Notify));
    assert!(decision.action.visible());
}

#[test]
fn local_notification_dnd_suppresses_visible_notify() {
    let policy = LocalNotificationPolicy {
        watch_level: WatchLevel::All,
        dnd_active: true,
        ..Default::default()
    };

    let decision =
        evaluate_local_notification(&notification(), LocalNotificationState::default(), &policy);

    assert_eq!(decision.action, LocalNotificationAction::Suppress);
    assert_eq!(decision.reason_code, local_reason_code::DND);
    assert_eq!(decision.push_rule_decision, Some(ShouldNotify::Notify));
    assert!(!decision.action.visible());
}

#[test]
fn local_notification_snooze_suppresses_visible_notify() {
    let policy = LocalNotificationPolicy {
        watch_level: WatchLevel::All,
        snoozed: true,
        ..Default::default()
    };

    let decision =
        evaluate_local_notification(&notification(), LocalNotificationState::default(), &policy);

    assert_eq!(decision.action, LocalNotificationAction::Suppress);
    assert_eq!(decision.reason_code, local_reason_code::SNOOZED);
    assert_eq!(decision.push_rule_decision, Some(ShouldNotify::Notify));
    assert!(!decision.action.visible());
}

#[test]
fn local_notification_muted_watch_suppresses_before_local_gates() {
    let policy = LocalNotificationPolicy {
        watch_level: WatchLevel::Muted,
        event_context: PushRuleEventContext {
            mentions_actor: true,
            is_e2ee: true,
            ..Default::default()
        },
        dnd_active: true,
        snoozed: true,
        ..Default::default()
    };

    let decision =
        evaluate_local_notification(&notification(), LocalNotificationState::default(), &policy);

    assert_eq!(decision.action, LocalNotificationAction::Suppress);
    assert_eq!(decision.reason_code, push_rule_reason_code::MUTED);
    assert_eq!(decision.push_rule_decision, Some(ShouldNotify::DontNotify));
}

#[test]
fn local_notification_blind_wakeup_ignores_dnd_and_snooze_until_decrypted() {
    let policy = LocalNotificationPolicy {
        watch_level: WatchLevel::All,
        event_context: PushRuleEventContext {
            is_e2ee: true,
            local_decrypted: false,
            ..Default::default()
        },
        dnd_active: true,
        snoozed: true,
        ..Default::default()
    };

    let decision =
        evaluate_local_notification(&notification(), LocalNotificationState::default(), &policy);

    assert_eq!(decision.action, LocalNotificationAction::BackgroundFetch);
    assert_eq!(
        decision.reason_code,
        push_rule_reason_code::BLIND_WAKEUP_REQUIRED
    );
    assert_eq!(decision.push_rule_decision, Some(ShouldNotify::BlindWakeup));
    assert!(!decision.action.visible());
}

#[test]
fn push_hint_accepts_only_protocol_vocabulary() {
    PushHint::new("new_message").unwrap();
    PushHint::new("incoming_call").unwrap();
    PushHint::new("mention_self").unwrap();
    PushHint::new("l10n_key").unwrap();

    assert!(PushHint::new("New message").is_err());
    assert!(PushHint::new("l10n_key:message.new").is_err());
    assert!(PushHint::new("title:secret").is_err());
}

#[test]
fn wakeup_kind_rejects_unknown_values() {
    let value = "custom_kind";
    let error = serde_json::from_value::<WakeupKind>(Value::String(value.to_owned()))
        .expect_err("unknown wakeup kind must fail closed");
    assert!(
        error.to_string().contains(
            "message, mention, assignment, schedule, reaction, call_invite, reminder, scheduled_send, expiry_invalidation"
        ),
        "unexpected error for {value}: {error}"
    );

    assert_eq!(
        serde_json::from_value::<WakeupKind>(Value::String("assignment".to_owned())).unwrap(),
        WakeupKind::Assignment
    );
    assert_eq!(
        serde_json::from_value::<WakeupKind>(Value::String("schedule".to_owned())).unwrap(),
        WakeupKind::Schedule
    );
    assert_eq!(
        serde_json::from_value::<WakeupKind>(Value::String("call_invite".to_owned())).unwrap(),
        WakeupKind::CallInvite
    );
    assert_eq!(
        serde_json::from_value::<WakeupKind>(Value::String("reminder".to_owned())).unwrap(),
        WakeupKind::Reminder
    );
    assert_eq!(
        serde_json::from_value::<WakeupKind>(Value::String("scheduled_send".to_owned())).unwrap(),
        WakeupKind::ScheduledSend
    );
    assert_eq!(
        serde_json::from_value::<WakeupKind>(Value::String("expiry_invalidation".to_owned()))
            .unwrap(),
        WakeupKind::ExpiryInvalidation
    );
}

#[test]
fn blind_wakeup_rejects_plaintext_metadata() {
    let mut notification = notification();
    notification
        .extra
        .insert("title".to_owned(), Value::String("Secret".to_owned()));

    assert_eq!(
        notification.validate_blind_wakeup().unwrap_err(),
        PushNotifyPrivacyError::SensitiveField {
            field: "title".to_owned()
        }
    );
}

#[test]
fn blind_wakeup_rejects_audience_mention_expansion_metadata() {
    let mut notification = notification();
    notification.extra.insert(
        "audience_mention_routing_hint".to_owned(),
        serde_json::json!({
            "audience": "strand_engaged",
            "recipient_count": 3,
        }),
    );

    assert_eq!(
        notification.validate_blind_wakeup().unwrap_err(),
        PushNotifyPrivacyError::SensitiveField {
            field: "audience_mention_routing_hint".to_owned()
        }
    );
}

#[test]
fn blind_wakeup_rejects_top_level_event_id() {
    let mut notification = notification();
    notification.event_id = Some("ck:event:01JS0EV000000000000000000".to_owned());

    assert_eq!(
        notification.validate_blind_wakeup().unwrap_err(),
        PushNotifyPrivacyError::SensitiveField {
            field: "event_id".to_owned()
        }
    );
}

#[test]
fn blind_wakeup_rejects_top_level_sender() {
    let mut notification = notification();
    notification.sender_actor_id = Some(Did::new("did:web:alice.example").unwrap());

    assert_eq!(
        notification.validate_blind_wakeup().unwrap_err(),
        PushNotifyPrivacyError::SensitiveField {
            field: "sender_actor_id".to_owned()
        }
    );
}

#[test]
fn deserialized_extra_fields_require_runtime_validation() {
    let loaded: PushNotification = serde_json::from_value(serde_json::json!({
        "push_target_id": "ck:pseudonym:push:01HYZ8Z000000000000000",
        "wakeup_kind": "message",
        "kind": "captured-extra-field",
        "devices": [{
            "device_id": DEVICE_ID,
            "push_key": "fcm:very-secret-token",
            "app_id": "app.example"
        }]
    }))
    .unwrap();

    assert!(loaded.extra.contains_key("kind"));
    assert!(matches!(
        loaded.validate_wire_model().unwrap_err(),
        PushNotifyPrivacyError::RemovedField { field } if field == "kind"
    ));
}

#[test]
fn notify_request_validates_fixture_shape() {
    let request = ChimePushNotifyEnvelope {
        notification: notification(),
        ..Default::default()
    };

    request.validate_blind_wakeup().unwrap();
}

/// CHIME-02 — actually consume `shared_push_notify_privacy_vectors()`
/// so the exported fixtures can never silently drift from the wire model
/// again. Every accept-vector payload MUST be a spec-valid notify request
/// body (top level limited to `{notification, event_kind?, reason_code?,
/// audit_envelope?}`, no transport fields like `operation_id`), and its
/// nested `notification` MUST pass the matching privacy mode. Reject
/// vectors MUST fail, surfacing their declared `expected_error_field`.
#[test]
fn shared_privacy_vectors_match_wire_model() {
    // Transport / path-determined fields that the canonical body forbids at
    // the top level (service-http-binding.md:213, :559).
    const FORBIDDEN_BODY_KEYS: &[&str] = &[
        "operation_id",
        "idempotency_key",
        "origin_service_did",
        "destination_service_did",
        "service_did",
    ];

    let vectors = shared_push_notify_privacy_vectors();
    assert!(!vectors.is_empty(), "fixture set must not be empty");

    for vector in vectors {
        let payload = vector
            .payload
            .as_object()
            .unwrap_or_else(|| panic!("vector `{}` payload must be a JSON object", vector.name));

        // The notify request body top level only carries the canonical keys;
        // assert no forbidden transport field leaked in (defends the very
        // regression CHIME-02 fixed).
        for key in payload.keys() {
            assert!(
                !FORBIDDEN_BODY_KEYS.contains(&key.as_str()),
                "vector `{}` leaks forbidden body field `{key}`",
                vector.name
            );
        }

        let notification: PushNotification = serde_json::from_value(
            payload
                .get("notification")
                .unwrap_or_else(|| panic!("vector `{}` missing `notification`", vector.name))
                .clone(),
        )
        .unwrap_or_else(|err| panic!("vector `{}` notification deserialises: {err}", vector.name));

        let envelope = ChimePushNotifyEnvelope {
            notification,
            ..Default::default()
        };

        let result = envelope.validate_privacy(vector.mode);
        if vector.should_accept {
            result.unwrap_or_else(|err| {
                panic!(
                    "vector `{}` should accept but rejected: {err:?}",
                    vector.name
                )
            });
        } else {
            let err = result
                .err()
                .unwrap_or_else(|| panic!("vector `{}` should reject but accepted", vector.name));
            if let Some(field) = vector.expected_error_field.as_deref() {
                assert!(
                    format!("{err:?}").contains(field),
                    "vector `{}` error {err:?} missing expected field `{field}`",
                    vector.name
                );
            }
        }
    }
}

#[test]
fn push_target_id_accepts_typed_and_raw_tokens() {
    PushTargetId::new("ck:pseudonym:push:01HYZ8Z000000000000000").unwrap();
    PushTargetId::new("01HYZ8Z000000000000000").unwrap();

    assert!(PushTargetId::new("ck:device:01HYZ8Z000000000000000").is_err());
    assert!(PushTargetId::new("did:web:alice.example").is_err());
}

#[test]
fn encrypted_envelope_validates_base64_payloads() {
    let envelope = EncryptedEnvelope::new(
        "did:web:alice.example",
        SUPPORTED_ENCRYPTED_ENVELOPE_ALGORITHMS[0],
        "Y2lwaGVydGV4dA==",
    )
    .unwrap()
    .with_nonce("bm9uY2VfYWJj")
    .unwrap()
    .with_key_id("kid-1")
    .with_aad("ck.edge.push.command.notify");

    envelope.validate().unwrap();
    assert!(
        EncryptedEnvelope::new(
            "alice",
            SUPPORTED_ENCRYPTED_ENVELOPE_ALGORITHMS[0],
            "Y2lwaGVydGV4dA=="
        )
        .is_err()
    );
    assert!(
        EncryptedEnvelope::new(
            "did:web:alice",
            SUPPORTED_ENCRYPTED_ENVELOPE_ALGORITHMS[0],
            "not base64!"
        )
        .is_err()
    );
    assert!(matches!(
        EncryptedEnvelope::new("did:web:alice", "x25519", "Y2lwaGVydGV4dA==").unwrap_err(),
        EncryptedEnvelopeError::UnsupportedAlgorithm { .. }
    ));
}

#[test]
fn debug_redacts_push_tokens() {
    let debug = format!("{:?}", device());
    assert!(debug.contains("fcm:<redacted"));
    assert!(!debug.contains("very-secret-token"));

    let rejected = RejectedPushToken {
        push_key: Some("fcm:very-secret-token".to_owned()),
        push_key_hash: Some("pkh_abc".to_owned()),
        app_id: Some("app.example".to_owned()),
        reason: Some("unregistered".to_owned()),
    };
    let debug = format!("{rejected:?}");
    assert!(debug.contains("fcm:<redacted"));
    assert!(!debug.contains("very-secret-token"));
}

#[test]
fn assert_no_sensitive_fields_accepts_clean_payload() {
    let payload = serde_json::json!({
        "push_target_id": "ck:pseudonym:push:01HYZ8Z000000000000000",
        "wakeup_kind": "message",
        "counts": {"unread": 1},
    });
    assert_no_sensitive_fields(&payload).unwrap();
}

#[test]
fn assert_no_sensitive_fields_rejects_round23_governance_fields() {
    for field in ROUND_R2_R3_SENSITIVE_FIELDS {
        let payload = serde_json::json!({
            "push_target_id": "ck:pseudonym:push:01HYZ8Z000000000000000",
            "wakeup_kind": "message",
            *field: "leaked-value",
        });
        // The release-build return value is what we lock in;
        // debug builds will panic in `walk` first, which is also
        // what we want, so we run the function with a catch_unwind
        // so the test verifies both paths.
        let outcome = std::panic::catch_unwind(|| assert_no_sensitive_fields(&payload));
        match outcome {
            Ok(Ok(())) => panic!("field `{field}` slipped through"),
            Ok(Err(path)) => assert!(
                path.contains(field),
                "returned path `{path}` should mention `{field}`"
            ),
            Err(_) => {
                // debug_assert! triggered — also a pass.
            }
        }
    }
}

#[test]
fn assert_no_sensitive_fields_walks_nested_objects() {
    let payload = serde_json::json!({
        "push_target_id": "ck:pseudonym:push:01HYZ8Z000000000000000",
        "metadata": {
            "deep": {
                "appeal_id": "ck:appeal:01ABC"
            }
        }
    });
    let outcome = std::panic::catch_unwind(|| assert_no_sensitive_fields(&payload));
    match outcome {
        Ok(Ok(())) => panic!("nested appeal_id slipped through"),
        Ok(Err(path)) => assert!(path.contains("appeal_id")),
        Err(_) => {} // debug panic path
    }
}

#[test]
fn assert_no_sensitive_fields_walks_arrays() {
    let payload = serde_json::json!({
        "items": [
            {"ok": 1},
            {"trust_domain": "ck:trust_domain:example.net"}
        ]
    });
    let outcome = std::panic::catch_unwind(|| assert_no_sensitive_fields(&payload));
    match outcome {
        Ok(Ok(())) => panic!("array trust_domain slipped through"),
        Ok(Err(path)) => assert!(path.contains("trust_domain")),
        Err(_) => {} // debug panic path
    }
}

// ── Round 4 (B5) — mention_redirect plaintext routing tests ───────

#[test]
fn decrypt_allowed_for_route_token_no_routing_is_open() {
    // No `mention_redirect` field → not a mention-redirect wakeup,
    // gate decision lives elsewhere, return true.
    let notification = notification();
    assert!(notification.decrypt_allowed_for_route_token(ALICE_ROUTE_TOKEN));
    assert!(!notification.has_mention_redirect_routing());
}

#[test]
fn decrypt_allowed_for_route_token_in_list_passes() {
    let mut notification = notification();
    notification
        .route_tokens
        .get_or_insert_with(Default::default)
        .mention_redirect_target_route_tokens =
        vec![ALICE_ROUTE_TOKEN.to_owned(), BOB_ROUTE_TOKEN.to_owned()];
    assert!(notification.has_mention_redirect_routing());
    assert!(notification.decrypt_allowed_for_route_token(ALICE_ROUTE_TOKEN));
    assert!(notification.decrypt_allowed_for_route_token(BOB_ROUTE_TOKEN));
}

#[test]
fn decrypt_allowed_for_route_token_not_in_list_is_fail_closed() {
    let mut notification = notification();
    notification
        .route_tokens
        .get_or_insert_with(Default::default)
        .mention_redirect_target_route_tokens = vec![ALICE_ROUTE_TOKEN.to_owned()];
    // Mallory is not in the list → fail-closed.
    assert!(!notification.decrypt_allowed_for_route_token(MALLORY_ROUTE_TOKEN));
}

#[test]
fn decrypt_allowed_for_route_token_empty_list_is_open() {
    // B5: an empty mention_redirect_target_route_tokens array means this is
    // not a mention-redirect wakeup. Gate decisions live elsewhere.
    let mut notification = notification();
    notification
        .route_tokens
        .get_or_insert_with(Default::default)
        .mention_redirect_target_route_tokens = Vec::new();
    assert!(!notification.has_mention_redirect_routing());
    assert!(notification.decrypt_allowed_for_route_token(ALICE_ROUTE_TOKEN));
}

#[test]
fn mention_redirect_round_trips_through_json() {
    let mut notification = notification();
    notification
        .route_tokens
        .get_or_insert_with(Default::default)
        .mention_redirect_target_route_tokens = vec![ALICE_ROUTE_TOKEN.to_owned()];
    let json = serde_json::to_string(&notification).unwrap();
    // Ensure the field is serialised under the canonical wire name.
    assert!(
        json.contains("mention_redirect_target_route_tokens"),
        "wire name must survive serde: {json}",
    );
    let loaded: PushNotification = serde_json::from_str(&json).unwrap();
    assert!(loaded.decrypt_allowed_for_route_token(ALICE_ROUTE_TOKEN));
}

// ── Round 4 (B5) — e2ee_late_recovery banner surface tests ────────

#[test]
fn late_recovery_event_id_is_some_for_e2ee_late_recovery() {
    // Parse the SDK shape via JSON so chime doesn't need to depend
    // on `chrono` directly to construct timestamps in tests.
    let payload: AuditPolicyAccessPayload = serde_json::from_value(serde_json::json!({
        "realm_id": "ck:realm:01904100-0000-7000-8000-000000000001",
        "actor": "did:web:alice.example",
        "access_kind": "e2ee_late_recovery",
        "late_recovery_original_event_id":
            "ck:event:01904100-0000-7000-8000-000000000002",
        "observed_at": "2026-05-20T00:00:00Z",
    }))
    .unwrap();
    // Sanity-check the SDK validator agrees.
    payload.validate_minimal().unwrap();

    let expected_event_id = EventId::new("ck:event:01904100-0000-7000-8000-000000000002").unwrap();
    let mut notification = notification();
    notification.policy_access = Some(payload);
    assert_eq!(
        notification.late_recovery_event_id(),
        Some(&expected_event_id)
    );
}

#[test]
fn late_recovery_event_id_is_none_for_other_access_kinds() {
    let payload: AuditPolicyAccessPayload = serde_json::from_value(serde_json::json!({
        "realm_id": "ck:realm:01904100-0000-7000-8000-000000000001",
        "actor": "did:web:alice.example",
        "access_kind": "audit",
        "observed_at": "2026-05-20T00:00:00Z",
    }))
    .unwrap();
    let mut notification = notification();
    notification.policy_access = Some(payload);
    assert!(notification.late_recovery_event_id().is_none());
}

#[test]
fn late_recovery_event_id_is_none_when_payload_absent() {
    let notification = notification();
    assert!(notification.late_recovery_event_id().is_none());
}

// ── push route-token model ───────────────────────────────────────────

#[test]
fn route_tokens_round_trip_through_json() {
    let mut n = notification();
    n.route_tokens
        .get_or_insert_with(Default::default)
        .scope_route_token = Some(SCOPE_ROUTE_TOKEN.to_owned());
    n.route_tokens
        .get_or_insert_with(Default::default)
        .delivery_binding_frontier_token = Some("frontier_route_token_000000001".to_owned());
    let json = serde_json::to_string(&n).unwrap();
    assert!(json.contains("route_tokens"));
    assert!(json.contains("scope_route_token"));
    assert!(json.contains("delivery_binding_frontier_token"));
    let loaded: PushNotification = serde_json::from_str(&json).unwrap();
    assert_eq!(loaded.scope_route_token(), n.scope_route_token());
    assert_eq!(
        loaded.delivery_binding_frontier_token(),
        n.delivery_binding_frontier_token()
    );
    loaded.validate_wire_model().unwrap();
    loaded.validate_blind_wakeup().unwrap();
}

#[test]
fn route_token_rejects_short_value() {
    let mut n = notification();
    n.route_tokens
        .get_or_insert_with(Default::default)
        .scope_route_token = Some("short".to_owned());
    assert!(matches!(
        n.validate_wire_model().unwrap_err(),
        PushNotifyPrivacyError::InvalidFieldValue { field }
            if field == "route_tokens.scope_route_token"
    ));
}

#[test]
fn device_id_must_be_sdk_typed_uuidv7() {
    let mut n = notification();
    n.devices[0].device_id = "not-a-device-id".to_owned();
    assert!(matches!(
        n.validate_wire_model().unwrap_err(),
        PushNotifyPrivacyError::InvalidFieldValue { field } if field == "devices[].device_id"
    ));

    let request = ChimePushNotifyEnvelope {
        notification: n,
        ..Default::default()
    };
    assert!(matches!(
        request.validate_wire_model().unwrap_err(),
        PushNotifyPrivacyError::InvalidFieldValue { field } if field == "devices[].device_id"
    ));
}

#[test]
fn blind_wakeup_rejects_plaintext_absolute_unread_count() {
    // §5.1: a plaintext absolute unread count is an activity
    // side-channel and MUST NOT travel in a blind wakeup.
    let mut n = notification();
    n.counts = Some(serde_json::json!({ "unread": 9999 }));
    let err = n.validate_blind_wakeup().unwrap_err();
    assert!(matches!(
        err,
        PushNotifyPrivacyError::SensitiveField { field } if field == "counts.unread"
    ));
}

#[test]
fn blind_wakeup_accepts_increment_bucket_and_badge_counts() {
    // The three §5.1-permitted forms: increment delta, bucketized
    // string, and coarse boolean badge.
    for counts in [
        serde_json::json!({ "unread_increment": 3 }),
        serde_json::json!({ "badge": "2-5" }),
        serde_json::json!({ "badge": true }),
    ] {
        let mut n = notification();
        n.counts = Some(counts.clone());
        n.validate_blind_wakeup()
            .unwrap_or_else(|err| panic!("counts {counts} must pass blind_wakeup: {err}"));
    }
}

#[test]
fn blind_wakeup_rejects_circle_name_in_extra() {
    let mut n = notification();
    n.extra.insert(
        "circle_name".to_owned(),
        Value::String("Bridge Team".to_owned()),
    );
    let err = n.validate_blind_wakeup().unwrap_err();
    assert!(matches!(
        err,
        PushNotifyPrivacyError::SensitiveField { field } if field == "circle_name"
    ));
}

#[test]
fn plaintext_visible_service_rejects_circle_members_array() {
    let mut n = notification();
    n.extra.insert(
        "circle_members".to_owned(),
        serde_json::json!(["did:web:alice.example"]),
    );
    let err = n.validate_plaintext_visible_service().unwrap_err();
    assert!(matches!(
        err,
        PushNotifyPrivacyError::SensitiveField { field } if field == "circle_members"
    ));
}

#[test]
fn plaintext_visible_service_rejects_product_private_content_body() {
    let mut n = notification();
    n.extra.insert(
        "content".to_owned(),
        serde_json::json!({ "body": "secret message" }),
    );
    let err = n.validate_plaintext_visible_service().unwrap_err();
    assert!(matches!(
        err,
        PushNotifyPrivacyError::SensitiveField { field } if field == "content"
    ));
}

// ── Phase P2 (spec 37ce729) — Personal Agent event-kind parsing ─────

#[test]
fn agent_lifecycle_summary_is_pii_free() {
    // Each durable lifecycle kind renders an l10n key and no actor,
    // payload, or grant identifier. The host MUST be able to
    // surface the summary to a control-plane UI without leaking PII.
    for (kind, expected_suffix) in [
        ("ck.self.agent.pause", "pause"),
        ("ck.self.agent.resume", "resume"),
        ("ck.self.agent.deactivate", "deactivate"),
    ] {
        let summary = render_agent_lifecycle_summary(kind).expect("renders");
        assert_eq!(summary.event_kind, kind);
        assert_eq!(
            summary.l10n_key,
            format!("l10n_key:agent.lifecycle.{expected_suffix}")
        );
    }
    assert!(render_agent_lifecycle_summary("ck.agent.draft.propose").is_none());
    assert!(render_agent_lifecycle_summary("ck.message.create").is_none());
}

#[test]
fn agent_typed_id_in_extra_fails_closed() {
    // An agent / grant / backup / recovery typed-id appearing in
    // `extra` is a correlation leak — the wakeup wire never carries
    // these prefixes in a non-Agent slot. chime MUST reject the
    // frame.
    for prefix in PHASE_P2_AGENT_TYPED_ID_PREFIXES {
        let mut n = notification();
        n.extra.insert(
            "smuggled".to_owned(),
            Value::String(format!("{prefix}01HZK9Z000000000000000000")),
        );
        let err = n.validate_wire_model().unwrap_err();
        match err {
            PushNotifyPrivacyError::SensitiveField { field } => {
                assert_eq!(field, "smuggled");
            }
            other => panic!("expected SensitiveField for prefix `{prefix}`, got {other:?}"),
        }
    }
}

#[test]
fn round23_sensitive_fields_cover_agent_governance_set() {
    // Phase P2 added 10 agent / sidecar / recovery governance
    // identifiers to the `assert_no_sensitive_fields` tripwire.
    // Spot-check each one to lock in the wire-side reject.
    for field in [
        "accountability_grant_id",
        "controller_did",
        "agent_principal_id",
        "agent_session_id",
        "agent_key_id",
        "sidecar_circle_id",
        "agent_draft_id",
        "proposed_action",
        "action_payload_digest",
        "approval_nonce",
    ] {
        assert!(
            ROUND_R2_R3_SENSITIVE_FIELDS.contains(&field),
            "field `{field}` must be in ROUND_R2_R3_SENSITIVE_FIELDS"
        );
        let payload = serde_json::json!({
            "push_target_id": "ck:pseudonym:push:01HYZ8Z000000000000000",
            "wakeup_kind": "message",
            field: "leaked-value",
        });
        let outcome = std::panic::catch_unwind(|| assert_no_sensitive_fields(&payload));
        match outcome {
            Ok(Ok(())) => panic!("agent field `{field}` slipped through"),
            Ok(Err(path)) => assert!(
                path.contains(field),
                "returned path `{path}` should mention `{field}`"
            ),
            Err(_) => {
                // debug_assert! triggered — also a pass.
            }
        }
    }
}

#[test]
fn round23_sensitive_fields_cover_private_productivity_and_search_set() {
    for field in [
        "target_ref",
        "target_key",
        "collection_title",
        "collection_key",
        "reminder_note",
        "note",
        "message_payload",
        "message_payload_digest",
        "draft_slot",
        "origin_device_id",
        "realm_key",
        "blind_tokens",
        "shard_key",
    ] {
        assert!(
            ROUND_R2_R3_SENSITIVE_FIELDS.contains(&field),
            "field `{field}` must be in ROUND_R2_R3_SENSITIVE_FIELDS"
        );
        let payload = serde_json::json!({
            "push_target_id": "ck:pseudonym:push:01HYZ8Z000000000000000",
            "wakeup_kind": "reminder",
            field: "leaked-value",
        });
        let outcome = std::panic::catch_unwind(|| assert_no_sensitive_fields(&payload));
        match outcome {
            Ok(Ok(())) => panic!("private field `{field}` slipped through"),
            Ok(Err(path)) => assert!(
                path.contains(field),
                "returned path `{path}` should mention `{field}`"
            ),
            Err(_) => {}
        }
    }
}
