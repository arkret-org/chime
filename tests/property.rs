//! Property tests pinning chime's wire-shape and privacy contracts.
//!
//! Each test exercises an arbitrary value space and asserts an
//! invariant that should hold for *every* input — picked up by
//! `cargo test` like any other integration test, no extra runner.

use chime::{
    GatewayBinding, PushDeviceConfig, PushGatewayType, PushPlatform, PushPreferences,
    build_register_device_request, build_unregister_device_request,
};
use proptest::prelude::*;

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
    /// platform, and HTTPS gateway URL produces a valid request whose platform, token and gateway round-trip.
    #[test]
    fn legal_register_request_round_trips(
        device_suffix in proptest::string::string_regex("[0-9a-f]{12}").expect("regex compiles"),
        push_key in ascii_token(8, 96),
        app_id in ascii_token(4, 32),
        platform in arb_platform(),
        gateway in arb_gateway_type(),
    ) {
        let device_id = format!("ak:device:01904100-0000-7000-8000-{device_suffix}");
        let prefs = PushPreferences {
            enabled: true,
            ..Default::default()
        };
        let binding = GatewayBinding::new(
            gateway,
            "https://push.example.com/_arkret/edge/push/notify",
        );
        let config = PushDeviceConfig {
            account_id: Some(arkret_wire::AccountId::new(arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap(), arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap())),
            device_id: &device_id,
            push_key: Some(&push_key),
            platform: platform.map(PushPlatform::as_str),
            app_id: Some(&app_id),
            domestic_app_id: None,
            registration_id: None,
            display_name: None,
            visible_notification_opt_in: false,
            idempotency_key: None,
            request_id: None,
        };

        let request = build_register_device_request(&config, &binding, &prefs).expect("legal registration input");
        prop_assert_eq!(request.device_id, device_id);
        prop_assert_eq!(request.push_key, push_key);
        prop_assert_eq!(request.platform.as_deref(), platform.map(PushPlatform::as_str));
        prop_assert_eq!(request.push_gateway, binding.push_gateway);

    }

    /// `build_unregister_device_request` with a missing push_key MUST
    /// produce a request that omits push_key entirely and never echo caller data into a
    /// field that would carry token material.
    #[test]
    fn unregister_request_never_echoes_random_into_push_key(
        registration_id in ascii_token(4, 32),
    ) {
        let device_id =
            "ak:device:01904100-0000-7000-8000-000000000008".to_owned();
        let prefs = PushPreferences {
            enabled: true,
            ..Default::default()
        };
        let binding = GatewayBinding::new(
            PushGatewayType::Standard,
            "https://push.example.com/_arkret/edge/push/notify",
        );
        let config = PushDeviceConfig {
            account_id: Some(arkret_wire::AccountId::new(arkret_wire::DidCoreId::new("ak:did_core:web:bob.example").unwrap(), arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap())),
            device_id: &device_id,
            push_key: None,
            platform: None,
            app_id: None,
            domestic_app_id: None,
            registration_id: Some(&registration_id),
            display_name: None,
            visible_notification_opt_in: false,
            idempotency_key: None,
            request_id: None,
        };

        let request = build_unregister_device_request(&config, &binding, &prefs).expect("legal unregistration input");
        prop_assert!(request.push_key.is_none());
        prop_assert_eq!(request.registration_id.as_deref(), Some(registration_id.as_str()));
    }


}
