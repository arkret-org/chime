//! Local chime <-> yougen push-registration smoke tests.
//!
//! This is intentionally a local cross-check against the sibling yougen
//! checkout. Chime owns the wire DTO/client behavior; yougen owns platform
//! token acquisition. The smoke keeps the integration honest without adding a
//! crate dependency cycle.

use std::fs;
use std::path::{Path, PathBuf};

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
            "RegisterDeviceRequest::Debug must redact the platform token: {debug}"
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

#[test]
fn sibling_yougen_wires_real_token_sources_into_chime_registration() {
    let Some(yougen_root) = sibling_yougen_root() else {
        eprintln!(
            "skip sibling_yougen_wires_real_token_sources_into_chime_registration: ../yougen unavailable"
        );
        return;
    };
    let push_rs = read_required(&yougen_root, "src/push.rs");
    let registration_rs = read_required(&yougen_root, "src/push_registration.rs");
    let todos = read_required(&yougen_root, "_yougen_todos.md");

    for needle in [
        "set_fcm_push_token",
        "set_apns_push_token",
        "YOUGEN_FCM_PUSH_TOKEN",
        "YOUGEN_APNS_PUSH_TOKEN",
        "FcmPushTokenProvider",
        "ApnsPushTokenProvider",
    ] {
        assert!(
            push_rs.contains(needle),
            "yougen src/push.rs no longer exposes token source `{needle}`"
        );
    }

    for needle in [
        "use chime::",
        "CokretPushClient",
        "build_register_device_request",
        "ensure_production_register_request",
        "with_session_grant",
        "register_device_with_request",
        "save_push_registration",
    ] {
        assert!(
            registration_rs.contains(needle),
            "yougen src/push_registration.rs no longer wires chime integration `{needle}`"
        );
    }

    assert!(
        todos.contains("Push tokens and chime session-grant proof wiring are closed"),
        "yougen todo file no longer records the closed local push-token/chime wiring"
    );
}

fn yougen_register_request(
    platform: &'static str,
    token: &'static str,
    app_id: &'static str,
) -> chime::RegisterDeviceRequest {
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

fn sibling_yougen_root() -> Option<PathBuf> {
    let chime_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    chime_root
        .parent()
        .map(|root| root.join("yougen"))
        .filter(|path| {
            path.join("src/push.rs").is_file() && path.join("src/push_registration.rs").is_file()
        })
}

fn read_required(root: &Path, rel: &str) -> String {
    fs::read_to_string(root.join(rel)).unwrap_or_else(|err| {
        panic!(
            "failed to read sibling yougen file {}: {err}",
            root.join(rel).display()
        )
    })
}
