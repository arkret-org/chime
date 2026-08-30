//! Local chime <-> inkson-style push-registration smoke tests.
//!
//! Chime owns the wire DTO/client behavior; inkson owns platform token
//! acquisition. These tests exercise the chime side with the token shapes
//! inkson supplies in production.

use chime::{
    GatewayBinding, PushDeviceConfig, PushGatewayType, PushPreferences,
    build_register_device_request,
};

const PUSH_GATEWAY: &str = "https://push.example.com/_arkret/edge/push/notify";

#[test]
fn inkson_style_fcm_and_apns_tokens_build_chime_register_requests() {
    for (platform, token, app_id) in [
        (
            "android",
            "fcm:real-local-fcm-token-0123456789abcdef",
            "dev.arkret.inkson.android",
        ),
        (
            "ios",
            "apns:0123456789abcdef0123456789abcdef0123456789abcdef",
            "dev.arkret.inkson.ios",
        ),
    ] {
        let request = inkson_register_request(platform, token, app_id);

        assert_eq!(
            request.operation_id,
            arkret_wire::ServiceOperationId::EDGE_PUSH_COMMAND_REGISTER_DEVICE_V1
        );
        assert_eq!(request.push_gateway, PUSH_GATEWAY);
        assert_eq!(request.push_key, token);
        assert_eq!(request.platform.as_deref(), Some(platform));
        assert_eq!(request.app_id.as_deref(), Some(app_id));

        let debug = format!("{request:?}");
        assert!(
            !debug.contains(token),
            "ChimePushRegisterDeviceRequest::Debug must redact the platform token: {debug}"
        );
    }
}

#[cfg(feature = "http")]
#[tokio::test(flavor = "multi_thread")]
async fn chime_client_requires_session_grant_before_inkson_can_register() {
    let request = inkson_register_request(
        "android",
        "fcm:real-local-fcm-token-for-grant-check",
        "dev.arkret.inkson.android",
    );
    let error = chime::ArkretPushClient::new("https://principal.example")
        .register_device_with_request(&request, None, None)
        .await
        .expect_err("default chime registration must fail closed without a session grant");

    assert!(
        matches!(
            error,
            chime::PushRegistrationError::MissingField("session_grant")
        ),
        "unexpected error: {error:?}"
    );
}

fn inkson_register_request(
    platform: &'static str,
    token: &'static str,
    app_id: &'static str,
) -> chime::ChimePushRegisterDeviceRequest {
    let binding = GatewayBinding::new(PushGatewayType::Standard, PUSH_GATEWAY);
    let prefs = PushPreferences {
        enabled: true,
        ..Default::default()
    };
    let config = PushDeviceConfig {
        account_id: Some(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:inkson.local").unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        )),
        device_id: "ak:device:01904100-0000-7000-8000-000000000007",
        push_key: Some(token),
        platform: Some(platform),
        app_id: Some(app_id),
        domestic_app_id: None,
        registration_id: None,
        display_name: Some("inkson smoke device"),
        idempotency_key: Some("chime-inkson-smoke"),
        request_id: Some("ak:request:01904100-0000-7000-8000-000000000060"),
        proof: None,
    };

    build_register_device_request(&config, &binding, &prefs)
        .expect("inkson-style platform token should build a chime register request")
}
