//! Property tests pinning chime's wire-shape and privacy contracts.
//!
//! Each test exercises an arbitrary value space and asserts an
//! invariant that should hold for *every* input — picked up by
//! `cargo test` like any other integration test, no extra runner.

use chime::{
    GatewayBinding, PushDeviceConfig, PushGatewayType, PushPlatform, PushPreferences,
    PushRegistrationError, build_register_device_request, build_unregister_device_request,
    hash_push_key,
};
use proptest::prelude::*;
#[cfg(feature = "notify")]
use serde_json::Value;

/// Strategy: ASCII tokens (alnum + `_-.`) of length 4..=96.
/// Keeps the search space small enough for proptest defaults while
/// still producing edge cases like "1", "aaa", "...".
fn ascii_token(min: usize, max: usize) -> impl Strategy<Value = String> {
    proptest::string::string_regex(&format!("[A-Za-z0-9_\\-.]{{{min},{max}}}"))
        .expect("regex compiles")
}

fn arb_platform() -> impl Strategy<Value = Option<PushPlatform>> {
    prop_oneof![
        Just(None),
        Just(Some(PushPlatform::Android)),
        Just(Some(PushPlatform::Ios)),
        Just(Some(PushPlatform::Web)),
        Just(Some(PushPlatform::Desktop)),
    ]
}

fn arb_gateway_type() -> impl Strategy<Value = PushGatewayType> {
    prop_oneof![
        Just(PushGatewayType::Standard),
        Just(PushGatewayType::Bugle),
        Just(PushGatewayType::Custom),
    ]
}

proptest! {
    /// `build_register_device_request` is total over the legal input
    /// space: any combination of well-formed device id, push token,
    /// platform, and HTTPS gateway URL produces either a valid request
    /// (where the platform / token / gateway round-trip exactly) or a
    /// declared `PushRegistrationError`. It must never panic.
    #[test]
    fn register_request_round_trips_or_fails_cleanly(
        device_id in ascii_token(4, 32),
        push_key in ascii_token(8, 96),
        app_id in ascii_token(4, 32),
        platform in arb_platform(),
        gateway in arb_gateway_type(),
    ) {
        let device_id_with_fragment = format!("did:web:alice.example#device-{device_id}");
        let prefs = PushPreferences {
            enabled: true,
            ..Default::default()
        };
        let binding = GatewayBinding::new(
            gateway,
            "https://push.example.com/api/v1/push/notify",
        );
        let config = PushDeviceConfig {
            principal_id: Some("did:web:alice.example"),
            device_id: &device_id_with_fragment,
            push_key: Some(&push_key),
            platform: platform.map(PushPlatform::as_str),
            app_id: Some(&app_id),
            domestic_app_id: None,
            registration_id: None,
            display_name: None,
            idempotency_key: None,
            request_id: None,
            proof: None,
        };

        match build_register_device_request(&config, &binding, &prefs) {
            Ok(request) => {
                prop_assert_eq!(request.device_id, device_id_with_fragment);
                prop_assert_eq!(request.push_key, push_key);
                if let Some(p) = platform {
                    prop_assert_eq!(request.platform.as_deref(), Some(p.as_str()));
                }
                // Gateway URL must round-trip exactly when prefs are HTTPS.
                prop_assert_eq!(request.push_gateway, binding.push_gateway);
            }
            Err(PushRegistrationError::InvalidPushGatewayUrl { .. })
            | Err(PushRegistrationError::MissingField(_))
            | Err(PushRegistrationError::InvalidPlatform(_)) => {
                // Declared failure modes are fine — we are pinning
                // "no panics, no surprise variants".
            }
            Err(other) => {
                prop_assert!(
                    false,
                    "unexpected error variant from build_register_device_request: {other:?}"
                );
            }
        }
    }

    /// `build_unregister_device_request` with a missing push_key MUST
    /// either produce a request that omits push_key entirely or reject
    /// before the wire — it must never echo random caller data into a
    /// field that would carry token material.
    #[test]
    fn unregister_request_never_echoes_random_into_push_key(
        device_id in ascii_token(4, 32),
        registration_id in ascii_token(4, 32),
    ) {
        let device_id_with_fragment = format!("did:web:bob.example#dev-{device_id}");
        let prefs = PushPreferences {
            enabled: true,
            ..Default::default()
        };
        let binding = GatewayBinding::new(
            PushGatewayType::Standard,
            "https://push.example.com/api/v1/push/notify",
        );
        let config = PushDeviceConfig {
            principal_id: Some("did:web:bob.example"),
            device_id: &device_id_with_fragment,
            push_key: None,
            platform: None,
            app_id: None,
            domestic_app_id: None,
            registration_id: Some(&registration_id),
            display_name: None,
            idempotency_key: None,
            request_id: None,
            proof: None,
        };

        if let Ok(request) = build_unregister_device_request(&config, &binding, &prefs) {
            prop_assert!(request.push_key.is_none());
            prop_assert_eq!(request.registration_id.as_deref(), Some(registration_id.as_str()));
        }
    }

    /// `hash_push_key` is deterministic, hex, and never leaks the
    /// input substring. Pinning these properties guards against a
    /// future refactor accidentally swapping in a transparent or
    /// reversible encoding.
    #[test]
    fn hash_push_key_is_deterministic_and_opaque(token in ascii_token(8, 96)) {
        let h1 = hash_push_key(&token);
        let h2 = hash_push_key(&token);
        prop_assert_eq!(&h1, &h2);

        prop_assert!(h1.starts_with("sha256:"));
        // sha256 hex is exactly 64 chars after the prefix.
        prop_assert_eq!(h1.len(), "sha256:".len() + 64);

        // Token must not appear in its hash. Tokens shorter than 6 chars
        // could coincidentally collide with hex pairs; skip those.
        if token.len() >= 6 {
            prop_assert!(!h1.contains(&token));
        }
    }
}

/// A separate proptest! block can use feature-gated APIs.
#[cfg(feature = "notify")]
mod notify_props {
    use chime::{
        PushNotification, PushNotificationDevice, PushNotifyPolicyContext, PushNotifyReqBody,
        PushTargetId, WakeupKind,
    };

    use super::*;

    proptest! {
        /// A blind-wakeup payload that includes a sensitive key
        /// anywhere in `extra` MUST be rejected. We try a fixed set of
        /// known-sensitive keys against a randomly-shaped value.
        #[test]
        fn blind_wakeup_rejects_known_sensitive_keys(
            sensitive_key in prop_oneof![
                Just("body"),
                Just("title"),
                Just("subtitle"),
                Just("preview"),
                Just("realm_name"),
                Just("sender_actor_display_name"),
                Just("provider_payload"),
                Just("aps"),
                Just("encrypted_payload"),
                Just("encrypted_content"),
                Just("encrypted_metadata"),
                Just("metadata"),
                Just("fields"),
                Just("track"),
                Just("track_name"),
                Just("ciphertext"),
            ],
            value_kind in 0u8..3u8,
        ) {
            let value: Value = match value_kind {
                0 => Value::String("anything".to_owned()),
                1 => Value::Number(serde_json::Number::from(42)),
                _ => Value::Object(serde_json::Map::new()),
            };

            let device: PushNotificationDevice = serde_json::from_value(serde_json::json!({
                "push_key": "fcm:token-aaaaaaaaaa",
                "app_id": "app.example",
            }))
            .unwrap();
            let mut notification = PushNotification::new_blind_wakeup(
                PushTargetId::new("ck:pseudonym:push:01HYZ8Z000000000000000").unwrap(),
                WakeupKind::Message,
            );
            notification.devices = vec![device];
            notification.extra.insert(sensitive_key.to_owned(), value);

            let request = PushNotifyReqBody {
                notification,
                ..Default::default()
            };

            prop_assert!(request.assert_payload_safe(
                &PushNotifyPolicyContext::blind_wakeup_only()
            ).is_err());
        }

        /// Round-trip property: any `PushTargetId` constructed via
        /// `PushTargetId::new` survives a JSON encode + decode without
        /// changing its byte form.
        #[test]
        fn target_id_serde_round_trip(
            // 22..=64 char base64url tokens are accepted.
            token in "[A-Za-z0-9_\\-]{22,64}",
        ) {
            let typed = format!("ck:pseudonym:push:{token}");
            let id = PushTargetId::new(&typed).unwrap();
            let json = serde_json::to_string(&id).unwrap();
            let back: PushTargetId = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(back.as_str(), typed.as_str());
        }
    }
}
