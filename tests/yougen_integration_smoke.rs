//! Local chime <-> yougen-style push-registration smoke tests.
//!
//! Chime owns the wire DTO/client behavior; yougen owns platform token
//! acquisition. These tests exercise the chime side with the token shapes
//! yougen supplies in production.

use chime::{
    GatewayBinding, PushDeviceConfig, PushGatewayType, PushPreferences,
    build_register_device_request,
};

const PUSH_GATEWAY: &str = "https://push.example.com/_cokret/edge/push/notify";

#[test]
fn yougen_style_fcm_and_apns_tokens_build_chime_register_requests() {
    for (platform, token, app_id) in [
        (
            "android",
            "fcm:real-local-fcm-token-0123456789abcdef",
            "dev.cokret.yougen.android",
        ),
        (
            "ios",
            "apns:0123456789abcdef0123456789abcdef0123456789abcdef",
            "dev.cokret.yougen.ios",
        ),
    ] {
        let request = yougen_register_request(platform, token, app_id);

        assert_eq!(request.operation_id, chime::OPERATION_PUSH_REGISTER_DEVICE);
        assert_eq!(request.push_gateway, PUSH_GATEWAY);
        assert_eq!(request.push_key, token);
        assert_eq!(request.platform.as_deref(), Some(platform));
        assert_eq!(request.app_id.as_deref(), Some(app_id));

        let debug = format!("{request:?}");
        assert!(
            !debug.contains(token),
            "PushRegisterDeviceRequestBody::Debug must redact the platform token: {debug}"
        );
    }
}

#[cfg(feature = "http")]
#[tokio::test(flavor = "multi_thread")]
async fn chime_client_requires_session_grant_before_yougen_can_register() {
    let request = yougen_register_request(
        "android",
        "fcm:real-local-fcm-token-for-grant-check",
        "dev.cokret.yougen.android",
    );
    let error = chime::CokretPushClient::new("https://principal.example")
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

fn yougen_register_request(
    platform: &'static str,
    token: &'static str,
    app_id: &'static str,
) -> chime::PushRegisterDeviceRequestBody {
    let binding = GatewayBinding::new(PushGatewayType::Standard, PUSH_GATEWAY);
    let prefs = PushPreferences {
        enabled: true,
        ..Default::default()
    };
    let config = PushDeviceConfig {
        principal_id: Some("did:web:yougen.local"),
        device_id: "did:web:yougen.local#device-smoke",
        push_key: Some(token),
        platform: Some(platform),
        app_id: Some(app_id),
        domestic_app_id: None,
        registration_id: None,
        display_name: Some("yougen smoke device"),
        idempotency_key: Some("chime-yougen-smoke"),
        request_id: Some("ck:request:yougen-smoke"),
        proof: None,
    };

    build_register_device_request(&config, &binding, &prefs)
        .expect("yougen-style platform token should build a chime register request")
}
