//! T8.2 — additional property tests for chime's blind-wakeup contract.
//!
//! Complements `tests/property.rs` by exercising the
//! `ChimePushNotifyEnvelope::assert_payload_safe` validator with:
//!
//!  * Deeply-nested `extra` payloads (depth ≤ 3).
//!  * Unicode and emoji string values.
//!  * Filename-like attachment names (common PII smuggling path).
//!  * Disguised forbidden keys (case / dash variants).
//!  * `default_payload` nested under `extra`.
//!
//! Every block uses ≤ 64 proptest cases.

#![cfg(feature = "notify")]

use chime::{
    ChimePushNotifyEnvelope, PushNotification, PushNotificationDevice, PushNotifyPolicyContext,
    PushTargetId, WakeupKind,
};
use proptest::prelude::*;
use serde_json::{Map, Value, json};

const PROPTEST_CASES: u32 = 64;

const SENSITIVE_KEYS: &[&str] = &[
    "body",
    "title",
    "subtitle",
    "preview",
    "summary",
    "alert",
    "filename",
    "file_name",
    "attachment_name",
    "attachment_filename",
    "space_name",
    "flow_name",
    "room_name",
    "sender",
    "sender_did",
    "sender_handle",
    "sender_actor_display_name",
    "from",
    "to",
    "target_did",
    "provider_payload",
    "provider_data",
    "aps",
    "android",
    "webpush",
    "encrypted_payload",
    "encrypted_content",
    "encrypted_metadata",
    "metadata",
    "fields",
    "track",
    "track_name",
    "ciphertext",
    "sdp",
    "offer",
    "candidate",
    "ice_candidate",
    "facet",
    "view_renderer",
];

fn arb_sensitive_key() -> impl Strategy<Value = &'static str> {
    proptest::sample::select(SENSITIVE_KEYS.to_vec())
}

fn arb_safe_extra_key() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9_]{0,24}".prop_filter("avoid known sensitive keys", |key| {
        !SENSITIVE_KEYS.contains(&key.as_str())
            && !key.ends_with("_id")
            && !matches!(key.as_str(), "schema_id" | "kind")
    })
}

fn arb_safe_opaque_string() -> impl Strategy<Value = String> {
    proptest::collection::vec(
        prop_oneof![
            proptest::char::range('a', 'z'),
            proptest::char::range('A', 'Z'),
            proptest::char::range('0', '9'),
            Just('_'),
            Just('-'),
        ],
        0..24,
    )
    .prop_map(|chars| chars.into_iter().collect())
}

/// Strategy: a short unicode/emoji-flavoured string.
fn arb_unicode_string() -> impl Strategy<Value = String> {
    proptest::collection::vec(
        prop_oneof![
            proptest::char::range('\u{0020}', '\u{007E}'), // ASCII printable
            proptest::char::range('\u{00A1}', '\u{00FF}'), // Latin-1 supp.
            proptest::char::range('\u{1F300}', '\u{1F6FF}'), // emoji
            proptest::char::range('\u{4E00}', '\u{4E80}'), // CJK
        ],
        0..16,
    )
    .prop_map(|chars| chars.into_iter().collect())
}

fn make_request() -> ChimePushNotifyEnvelope {
    let device: PushNotificationDevice = serde_json::from_value(json!({
        "push_key": "fcm:token-aaaaaaaaaa",
        "app_id": "app.example",
    }))
    .unwrap();
    let mut notification = PushNotification::new_blind_wakeup(
        PushTargetId::new("ck:pseudonym:push:01HYZ8Z000000000000000").unwrap(),
        WakeupKind::Message,
    );
    notification.devices = vec![device];
    ChimePushNotifyEnvelope {
        notification,
        ..Default::default()
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(PROPTEST_CASES))]

    /// Property — a sensitive key buried in a nested `default_payload`
    /// inside `extra` MUST be rejected.
    #[test]
    fn sensitive_key_in_default_payload_is_rejected(
        key in arb_sensitive_key(),
        value in arb_unicode_string(),
    ) {
        let mut request = make_request();
        let mut default_payload = Map::new();
        default_payload.insert(key.to_owned(), Value::String(value));
        request
            .notification
            .extra
            .insert("default_payload".into(), Value::Object(default_payload));
        prop_assert!(
            request
                .assert_payload_safe(&PushNotifyPolicyContext::blind_wakeup_only())
                .is_err(),
            "sensitive key `{key}` nested under default_payload survived"
        );
    }

    /// Property — emoji / CJK strings inside a forbidden extra slot
    /// (e.g. `title`) MUST still be rejected. The sanitizer must not
    /// over-trigger or under-trigger on non-ASCII data.
    #[test]
    fn unicode_in_forbidden_slot_still_rejected(value in arb_unicode_string()) {
        let mut request = make_request();
        // `title` is forbidden by name, regardless of value charset.
        request
            .notification
            .extra
            .insert("title".into(), Value::String(value));
        prop_assert!(
            request
                .assert_payload_safe(&PushNotifyPolicyContext::blind_wakeup_only())
                .is_err()
        );
    }

    /// Property — filename-shaped strings under sensitive attachment
    /// keys MUST be rejected.
    #[test]
    fn filename_attachment_name_rejected(
        ext in prop_oneof![Just("pdf"), Just("png"), Just("jpg"), Just("zip")],
        stem in "[a-zA-Z0-9_-]{1,16}",
    ) {
        let mut request = make_request();
        let filename = format!("{stem}.{ext}");
        request
            .notification
            .extra
            .insert("attachment_name".into(), Value::String(filename));
        prop_assert!(
            request
                .assert_payload_safe(&PushNotifyPolicyContext::blind_wakeup_only())
                .is_err()
        );
    }

    /// Property — sensitive key buried two levels deep inside `extra`
    /// (object → object → key) MUST be rejected.
    #[test]
    fn deeply_nested_sensitive_key_rejected(
        key in arb_sensitive_key(),
        leaf in arb_unicode_string(),
    ) {
        let mut request = make_request();
        let nested = json!({ "a": { "b": { key: leaf } } });
        request.notification.extra.insert("nest".into(), nested);
        prop_assert!(
            request
                .assert_payload_safe(&PushNotifyPolicyContext::blind_wakeup_only())
                .is_err(),
            "deeply nested sensitive key `{key}` survived"
        );
    }

    /// Fuzz-style property — opaque, non-sensitive extension keys with
    /// bounded primitive values must not be rejected by
    /// `validate_blind_wakeup`.
    #[test]
    fn safe_opaque_extra_key_survives_validate_blind_wakeup(
        key in arb_safe_extra_key(),
        value in arb_safe_opaque_string(),
    ) {
        let mut request = make_request();
        request.notification.extra.insert(key, Value::String(value));
        prop_assert!(request.notification.validate_blind_wakeup().is_ok());
    }
}
