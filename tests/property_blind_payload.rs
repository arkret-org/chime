//! Property tests for the SDK-owned closed push notify wire model.

#![cfg(feature = "notify")]

use chime::{PushNotifyEnvelopeExt, PushNotifyPolicyContext, PushNotifyRequestBody};
use proptest::prelude::*;
use serde_json::{Value, json};

const PROPTEST_CASES: u32 = 64;

fn request_value() -> Value {
    json!({
        "notification": {
            "push_target_id": "ak:pseudonym:push:01HYZ8Z000000000000000",
            "wakeup_kind": "message",
            "timing_profile_hint": "default",
            "devices": [{
                "device_id": "ak:device:01904100-0000-7000-8000-000000000010",
                "push_key": "fcm:token-aaaaaaaaaa",
                "app_id": "app.example"
            }]
        }
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(PROPTEST_CASES))]

    #[test]
    fn unknown_notification_fields_are_rejected_by_deserialization(
        key in "[a-z][a-z_]{2,24}",
        value in ".{0,32}",
    ) {
        let known = [
            "push_target_id", "wakeup_kind", "timing_profile_hint", "push_hint",
            "push_hint_l10n_key", "evaluation_locus_unresolved", "counts", "route_tokens",
            "devices", "event_id", "realm_id", "sender_actor_id", "strand_id", "message_id",
            "sender_actor_display_name", "strand_title", "realm_title", "user_is_target",
            "priority", "membership",
        ];
        prop_assume!(!known.contains(&key.as_str()));
        let mut frame = request_value();
        frame["notification"]
            .as_object_mut()
            .unwrap()
            .insert(key, Value::String(value));
        prop_assert!(serde_json::from_value::<PushNotifyRequestBody>(frame).is_err());
    }

    #[test]
    fn valid_typed_push_pseudonyms_round_trip(token in "[A-Za-z0-9_\\-]{22,64}") {
        let mut frame = request_value();
        let target = format!("ak:pseudonym:push:{token}");
        frame["notification"]["push_target_id"] = Value::String(target.clone());
        let request: PushNotifyRequestBody = serde_json::from_value(frame).unwrap();
        prop_assert!(request
            .assert_payload_safe(&PushNotifyPolicyContext::blind_wakeup_only(), None)
            .is_ok());
        prop_assert_eq!(request.notification.push_target_id.as_deref(), Some(target.as_str()));
    }
}
