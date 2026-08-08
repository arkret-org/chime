use arkret::{DeviceId, EventId, PushCountIndicator, PushCounts, PushNotifyRequestReasonCode};

use super::*;
use crate::{PushRuleEventContext, ShouldNotify, WatchLevel, push_rule_reason_code};

const REALM_ROUTE_TOKEN: &str = "realm_route_token_000000001";
const ALICE_ROUTE_TOKEN: &str = "alice_route_token_000000001";
const BOB_ROUTE_TOKEN: &str = "bob_route_token_000000001";
const MALLORY_ROUTE_TOKEN: &str = "mallory_route_token_000000001";

fn device() -> PushDeviceRoute {
    PushDeviceRoute {
        device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000010").unwrap(),
        push_key: Some("fcm:very-secret-token".to_owned()),
        app_id: Some("app.example".to_owned()),
        target_route_token: None,
        platform: Some("android".to_owned()),
        visible_notification_opt_in: false,
    }
}

fn notification() -> PushNotificationEnvelope {
    PushNotificationEnvelope {
        push_target_id: Some("ak:pseudonym:push:01HYZ8Z000000000000000".to_owned()),
        wakeup_kind: Some("message".to_owned()),
        timing_profile_hint: Some(arkret::PushTimingProfileHint::Default),
        route_tokens: Some(PushRouteTokens {
            realm_route_token: Some(REALM_ROUTE_TOKEN.to_owned()),
            ..Default::default()
        }),
        push_hint: Some("new_message".to_owned()),
        counts: Some(PushCounts {
            badge: Some(PushCountIndicator::Bucket("2-5".to_owned())),
            ..Default::default()
        }),
        devices: vec![device()],
        ..Default::default()
    }
}

fn request() -> PushNotifyRequestBody {
    PushNotifyRequestBody {
        notification: notification(),
        event_kind: None,
        reason_code: None,
        audit_envelope: None,
    }
}

#[test]
fn sdk_owned_wire_model_validates_without_conversion() {
    request().validate_wire_model().unwrap();
}

#[test]
fn sdk_owned_wire_model_is_closed() {
    let error = serde_json::from_value::<PushNotifyRequestBody>(serde_json::json!({
        "notification": {
            "push_target_id": "ak:pseudonym:push:01HYZ8Z000000000000000",
            "wakeup_kind": "message",
            "timing_profile_hint": "default",
            "kind": "legacy-extra-field",
            "devices": [{
                "device_id": "ak:device:01904100-0000-7000-8000-000000000010"
            }]
        }
    }))
    .unwrap_err();
    assert!(error.to_string().contains("unknown field `kind`"));
}

#[test]
fn sdk_validator_rejects_invalid_target_and_wakeup_vocabulary() {
    let mut invalid_target = request();
    invalid_target.notification.push_target_id = Some("did:web:alice.example".to_owned());
    assert!(matches!(
        invalid_target.validate_wire_model(),
        Err(PushNotifyPrivacyError::InvalidFieldValue { field }) if field == "push_target_id"
    ));

    let mut invalid_wakeup = request();
    invalid_wakeup.notification.wakeup_kind = Some("custom_kind".to_owned());
    assert!(matches!(
        invalid_wakeup.validate_wire_model(),
        Err(PushNotifyPrivacyError::InvalidFieldValue { field }) if field == "wakeup_kind"
    ));
}

#[test]
fn blind_wakeup_rejects_visible_fields() {
    let mut request = request();
    request.notification.event_id =
        Some(EventId::new("ak:event:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h").unwrap());
    assert!(matches!(
        request.validate_blind_wakeup(),
        Err(PushNotifyPrivacyError::SensitiveField { field }) if field == "event_id"
    ));
}

#[test]
fn reason_code_is_validated_during_deserialization() {
    let mut request = request();
    request.reason_code = Some(PushNotifyRequestReasonCode::new("historical_only").unwrap());
    let encoded = serde_json::to_value(&request).unwrap();
    assert_eq!(encoded["reason_code"], "historical_only");
    request.validate_wire_model().unwrap();
}

#[test]
fn mention_redirect_gate_is_fail_closed() {
    let mut notification = notification();
    assert!(notification.decrypt_allowed_for_route_token(ALICE_ROUTE_TOKEN));
    assert!(!notification.has_mention_redirect_routing());

    notification
        .route_tokens
        .as_mut()
        .unwrap()
        .mention_redirect_target_route_tokens =
        vec![ALICE_ROUTE_TOKEN.to_owned(), BOB_ROUTE_TOKEN.to_owned()];
    assert!(notification.decrypt_allowed_for_route_token(ALICE_ROUTE_TOKEN));
    assert!(notification.decrypt_allowed_for_route_token(BOB_ROUTE_TOKEN));
    assert!(!notification.decrypt_allowed_for_route_token(MALLORY_ROUTE_TOKEN));
}

#[test]
fn late_recovery_reads_spec_audit_envelope() {
    let mut request = request();
    let event_id = EventId::new("ak:event:AU2FuZ5Cmuwsb0J0xuJwH47SCEL34D7oJWb4JivTH934").unwrap();
    request.audit_envelope = Some(arkret::PushAuditEnvelopeMetadata {
        access_kind: "e2ee_late_recovery".to_owned(),
        late_recovery_original_event_id: Some(event_id.clone()),
    });
    assert_eq!(late_recovery_event_id(&request), Some(&event_id));
}

#[test]
fn local_notification_expiry_invalidation_revokes_visible_preview() {
    let mut notification = notification();
    notification.wakeup_kind = Some("expiry_invalidation".to_owned());
    let decision = evaluate_local_notification(
        &notification,
        LocalNotificationState::visible_preview(),
        &LocalNotificationPolicy::default(),
    );
    assert_eq!(decision.action, LocalNotificationAction::RevokeExisting);
    assert_eq!(decision.reason_code, local_reason_code::EXPIRY_INVALIDATION);
}

#[test]
fn local_notification_respects_watch_policy() {
    let policy = LocalNotificationPolicy {
        watch_level: WatchLevel::All,
        event_context: PushRuleEventContext::default(),
        ..Default::default()
    };
    let decision =
        evaluate_local_notification(&notification(), LocalNotificationState::default(), &policy);
    assert_eq!(decision.action, LocalNotificationAction::Show);
    assert_eq!(decision.reason_code, push_rule_reason_code::WATCH_ALLOWS);
    assert_eq!(decision.push_rule_decision, Some(ShouldNotify::Notify));
}

#[test]
fn shared_vectors_follow_closed_sdk_shape() {
    for vector in shared_push_notify_privacy_vectors() {
        let result = serde_json::from_value::<PushNotifyRequestBody>(vector.payload)
            .map_err(|error| error.to_string())
            .and_then(|request| {
                request
                    .validate_privacy(vector.mode)
                    .map_err(|error| error.to_string())
            });
        assert_eq!(result.is_ok(), vector.should_accept, "{}", vector.name);
    }
}

#[test]
fn dedup_summary_remains_runtime_adapter() {
    let descriptor = crate::PushBridgeDescribeNotifyDescriptor {
        dedup_backend: Some("redis".to_owned()),
        dedup_ttl_seconds: Some(60),
        ..Default::default()
    };
    let summary = PushNotificationDedup::from_descriptor(&descriptor).unwrap();
    assert_eq!(summary.backend, "redis");
    assert_eq!(summary.window, std::time::Duration::from_secs(60));
    assert!(summary.has_window());
}
