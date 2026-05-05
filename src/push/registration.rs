//! Request body builders for register/unregister + their signing contexts.

use sha2::{Digest, Sha256};

use crate::PushPreferences;

use super::errors::PushRegistrationError;
use super::signing::{
    PushRequestSigningContext, PushRequestSigningOptions, build_signing_context,
};
use super::urls::{
    redact_push_key, require_non_empty, require_optional_non_empty, validate_push_gateway_url,
    validate_webpush_endpoint_allowlist,
};
use super::wire::{
    PushDeviceConfig, PushPlatform, RegisterDeviceRequest, UnregisterDeviceRequest,
};
use super::{REGISTER_DEVICE_PATH, UNREGISTER_DEVICE_PATH};

/// Build the Contrix register-device request body from app configuration and
/// stored push preferences.
///
/// ```rust
/// use chime::{PushDeviceConfig, PushPreferences, build_register_device_request};
///
/// let config = PushDeviceConfig {
///     principal_did: Some("did:web:alice.example"),
///     device_id: "did:web:alice.example#device-phone",
///     push_key: Some("fcm:token"),
///     platform: Some("android"),
///     app_id: Some("app.example.android"),
///     domestic_app_id: None,
///     registration_id: None,
///     display_name: Some("Alice Phone"),
///     idempotency_key: Some("register-phone-v1"),
///     request_id: None,
///     proof: None,
/// };
/// let prefs = PushPreferences {
///     enabled: true,
///     push_gateway: "https://push.example.com/api/v1/push/notify".to_owned(),
///     ..Default::default()
/// };
///
/// let request = build_register_device_request(&config, &prefs).unwrap();
/// assert_eq!(request.device_id, "did:web:alice.example#device-phone");
/// ```
pub fn build_register_device_request(
    config: &PushDeviceConfig<'_>,
    prefs: &PushPreferences,
) -> Result<RegisterDeviceRequest, PushRegistrationError> {
    require_non_empty("device_id", config.device_id)?;
    let push_key = require_optional_non_empty("push_key", config.push_key)?;
    validate_push_gateway_url(
        &prefs.push_gateway,
        prefs.allow_insecure_loopback_push_gateway,
    )?;

    let platform = parse_platform(config.platform)?;
    let app_id = prefs.app_id(platform, config.app_id, config.domestic_app_id);
    if platform == Some(PushPlatform::Web) {
        validate_webpush_endpoint_allowlist(push_key, &prefs.webpush_endpoint_allowlist)?;
    }

    Ok(RegisterDeviceRequest {
        operation_id: crate::OPERATION_PUSH_REGISTER_DEVICE.to_owned(),
        principal_did: config
            .principal_did
            .and_then(non_empty_str)
            .map(str::to_owned),
        device_id: config.device_id.to_owned(),
        push_gateway: prefs.push_gateway.clone(),
        push_key: push_key.to_owned(),
        platform: platform.map(|value| value.as_str().to_owned()),
        app_id: app_id.map(str::to_owned),
        display_name: config.display_name.map(str::to_owned),
        idempotency_key: config.idempotency_key.map(str::to_owned),
        request_id: config.request_id.map(str::to_owned),
        proof: config.proof.cloned(),
    })
}

/// Build the Contrix unregister-device request body from app configuration and
/// stored push preferences.
///
/// ```rust
/// use chime::{PushDeviceConfig, PushPreferences, build_unregister_device_request};
///
/// let config = PushDeviceConfig {
///     principal_did: Some("did:web:alice.example"),
///     device_id: "did:web:alice.example#device-phone",
///     push_key: None,
///     platform: Some("android"),
///     app_id: Some("app.example.android"),
///     domestic_app_id: None,
///     registration_id: Some("cx:pushreg:01JS0KE000000000000000000"),
///     display_name: None,
///     idempotency_key: Some("unregister-phone-v1"),
///     request_id: None,
///     proof: None,
/// };
/// let request = build_unregister_device_request(&config, &PushPreferences::default()).unwrap();
/// assert_eq!(request.registration_id.as_deref(), Some("cx:pushreg:01JS0KE000000000000000000"));
/// ```
pub fn build_unregister_device_request(
    config: &PushDeviceConfig<'_>,
    prefs: &PushPreferences,
) -> Result<UnregisterDeviceRequest, PushRegistrationError> {
    require_non_empty("device_id", config.device_id)?;
    if non_empty_str(&prefs.push_gateway).is_some() {
        validate_push_gateway_url(
            &prefs.push_gateway,
            prefs.allow_insecure_loopback_push_gateway,
        )?;
    }

    let platform = parse_platform(config.platform)?;
    let app_id = prefs.app_id(platform, config.app_id, config.domestic_app_id);
    let push_key = config.push_key.and_then(non_empty_str);

    Ok(UnregisterDeviceRequest {
        operation_id: crate::OPERATION_PUSH_UNREGISTER_DEVICE.to_owned(),
        principal_did: config
            .principal_did
            .and_then(non_empty_str)
            .map(str::to_owned),
        device_id: config.device_id.to_owned(),
        registration_id: non_empty_str(config.registration_id.unwrap_or_default())
            .map(str::to_owned),
        push_gateway: non_empty_str(&prefs.push_gateway).map(str::to_owned),
        push_key: push_key.map(str::to_owned),
        push_key_hash: push_key.map(hash_push_key_for_wire),
        push_key_preview: push_key.map(redact_push_key),
        app_id: app_id.map(str::to_owned),
        idempotency_key: config.idempotency_key.map(str::to_owned),
        request_id: config.request_id.map(str::to_owned),
        proof: config.proof.cloned(),
    })
}

/// Build the signing context for `cx.push.register_device`.
///
/// ```rust
/// use chime::{
///     PushDeviceConfig, PushPreferences, build_register_device_request,
///     build_register_signing_context,
/// };
///
/// let config = PushDeviceConfig {
///     principal_did: Some("did:web:alice.example"),
///     device_id: "did:web:alice.example#device-phone",
///     push_key: Some("fcm:token"),
///     platform: Some("android"),
///     app_id: Some("app.example.android"),
///     domestic_app_id: None,
///     registration_id: None,
///     display_name: None,
///     idempotency_key: None,
///     request_id: None,
///     proof: None,
/// };
/// let prefs = PushPreferences {
///     enabled: true,
///     push_gateway: "https://push.example.com/api/v1/push/notify".to_owned(),
///     ..Default::default()
/// };
/// let request = build_register_device_request(&config, &prefs).unwrap();
/// let context = build_register_signing_context(
///     "https://principal.example",
///     &request,
///     "2026-04-29T00:00:00Z",
///     "https://principal.example",
/// )
/// .unwrap();
/// assert_eq!(context.path, chime::REGISTER_DEVICE_PATH);
/// assert!(context.content_digest.starts_with("sha-256=:"));
/// ```
pub fn build_register_signing_context(
    service_base_url: &str,
    request: &RegisterDeviceRequest,
    created_at: impl Into<String>,
    audience: impl Into<String>,
) -> Result<PushRequestSigningContext, PushRegistrationError> {
    build_register_signing_context_with_options(
        service_base_url,
        request,
        PushRequestSigningOptions::new(created_at, audience),
    )
}

/// Build the signing context for `cx.push.register_device` with actor and
/// expiry metadata.
pub fn build_register_signing_context_with_options(
    service_base_url: &str,
    request: &RegisterDeviceRequest,
    options: PushRequestSigningOptions,
) -> Result<PushRequestSigningContext, PushRegistrationError> {
    build_signing_context(
        service_base_url,
        crate::OPERATION_PUSH_REGISTER_DEVICE,
        REGISTER_DEVICE_PATH,
        &request.device_id,
        request,
        options,
    )
}

/// Build the signing context for `cx.push.unregister_device`.
pub fn build_unregister_signing_context(
    service_base_url: &str,
    request: &UnregisterDeviceRequest,
    created_at: impl Into<String>,
    audience: impl Into<String>,
) -> Result<PushRequestSigningContext, PushRegistrationError> {
    build_unregister_signing_context_with_options(
        service_base_url,
        request,
        PushRequestSigningOptions::new(created_at, audience),
    )
}

/// Build the signing context for `cx.push.unregister_device` with actor and
/// expiry metadata.
pub fn build_unregister_signing_context_with_options(
    service_base_url: &str,
    request: &UnregisterDeviceRequest,
    options: PushRequestSigningOptions,
) -> Result<PushRequestSigningContext, PushRegistrationError> {
    build_signing_context(
        service_base_url,
        crate::OPERATION_PUSH_UNREGISTER_DEVICE,
        UNREGISTER_DEVICE_PATH,
        &request.device_id,
        request,
        options,
    )
}

fn parse_platform(value: Option<&str>) -> Result<Option<PushPlatform>, PushRegistrationError> {
    value.map(PushPlatform::try_from).transpose()
}

fn hash_push_key_for_wire(push_key: &str) -> String {
    let digest = Sha256::digest(push_key.as_bytes());
    let mut output = String::with_capacity("sha256:".len() + digest.len() * 2);
    output.push_str("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn non_empty_str(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::push::CONTRIX_ACTOR_DID_HEADER;
    use crate::push::CONTRIX_DESTINATION_SERVICE_DID_HEADER;
    use crate::push::CONTRIX_EXPIRES_AT_HEADER;
    use crate::push::CONTRIX_ORIGIN_SERVICE_DID_HEADER;
    use crate::push::CONTRIX_SESSION_GRANT_HEADER;
    use crate::push::SIGNATURE_HEADER;
    use crate::push::SIGNATURE_INPUT_HEADER;
    use crate::push::errors::PushErrorKind;
    use crate::{DEFAULT_BUGLE_PUSH_GATEWAY_URL, PushGatewayType};

    fn config<'a>(platform: Option<&'a str>) -> PushDeviceConfig<'a> {
        PushDeviceConfig {
            principal_did: Some("did:web:alice.example"),
            device_id: "did:web:alice.example#device-phone",
            push_key: Some("fcm:very-secret-token"),
            platform,
            app_id: Some("app.example.android"),
            domestic_app_id: Some("app.example.android.cn"),
            registration_id: Some("cx:pushreg:01JS0KE000000000000000000"),
            display_name: Some("Alice Phone"),
            idempotency_key: Some("idem-1"),
            request_id: Some("cx:req:01JS0KE000000000000000000"),
            proof: None,
        }
    }

    fn prefs(push_gateway: &str) -> PushPreferences {
        PushPreferences {
            enabled: true,
            push_gateway: push_gateway.to_owned(),
            ..Default::default()
        }
    }

    #[test]
    fn register_request_matches_contrix_schema() {
        let mut prefs = PushPreferences {
            enabled: true,
            gateway_type: PushGatewayType::Bugle,
            ..Default::default()
        };
        prefs.apply_gateway_type_defaults();

        let request = build_register_device_request(&config(Some("android")), &prefs).unwrap();

        assert_eq!(request.operation_id, crate::OPERATION_PUSH_REGISTER_DEVICE);
        assert_eq!(
            request.principal_did.as_deref(),
            Some("did:web:alice.example")
        );
        assert_eq!(request.device_id, "did:web:alice.example#device-phone");
        assert_eq!(request.push_gateway, DEFAULT_BUGLE_PUSH_GATEWAY_URL);
        assert_eq!(request.push_key, "fcm:very-secret-token");
        assert_eq!(request.platform.as_deref(), Some("android"));
        assert_eq!(request.app_id.as_deref(), Some("app.example.android.cn"));
        assert_eq!(request.display_name.as_deref(), Some("Alice Phone"));
        assert_eq!(request.idempotency_key.as_deref(), Some("idem-1"));
        assert_eq!(
            request.request_id.as_deref(),
            Some("cx:req:01JS0KE000000000000000000")
        );
    }

    #[test]
    fn unregister_request_supports_registration_id() {
        let request =
            build_unregister_device_request(&config(Some("ios")), &PushPreferences::default())
                .unwrap();

        assert_eq!(
            request.operation_id,
            crate::OPERATION_PUSH_UNREGISTER_DEVICE
        );
        assert_eq!(
            request.principal_did.as_deref(),
            Some("did:web:alice.example")
        );
        assert_eq!(request.device_id, "did:web:alice.example#device-phone");
        assert_eq!(
            request.registration_id.as_deref(),
            Some("cx:pushreg:01JS0KE000000000000000000")
        );
        assert_eq!(request.push_key.as_deref(), Some("fcm:very-secret-token"));
        assert!(
            request
                .push_key_hash
                .as_deref()
                .is_some_and(|value| value.starts_with("sha256:"))
        );
        assert_eq!(
            request.push_key_preview.as_deref(),
            Some("fcm:<redacted,len=17>")
        );
        assert_eq!(request.app_id.as_deref(), Some("app.example.android"));
        assert_eq!(request.idempotency_key.as_deref(), Some("idem-1"));
        assert_eq!(
            request.request_id.as_deref(),
            Some("cx:req:01JS0KE000000000000000000")
        );
    }

    #[test]
    fn requires_register_push_gateway() {
        let prefs = PushPreferences {
            push_gateway: " ".to_owned(),
            ..Default::default()
        };
        let err = build_register_device_request(&config(Some("android")), &prefs).unwrap_err();
        assert_eq!(err.kind(), PushErrorKind::MissingField);
    }

    #[test]
    fn requires_register_push_key() {
        let mut config = config(Some("android"));
        config.push_key = None;
        let err = build_register_device_request(
            &config,
            &prefs("https://push.example.com/api/v1/push/notify"),
        )
        .unwrap_err();
        assert_eq!(err.kind(), PushErrorKind::MissingField);
    }

    #[test]
    fn requires_device_id() {
        let mut config = config(Some("android"));
        config.device_id = " ";
        let err = build_register_device_request(
            &config,
            &prefs("https://push.example.com/api/v1/push/notify"),
        )
        .unwrap_err();
        assert_eq!(err.kind(), PushErrorKind::MissingField);
    }

    #[test]
    fn validates_webpush_endpoint_allowlist() {
        let mut web_config = config(Some("web"));
        web_config.push_key =
            Some("webpush:https://updates.push.services.mozilla.com/wpush/v2/token-secret");
        let prefs = PushPreferences {
            enabled: true,
            push_gateway: "https://push.example.com/api/v1/push/notify".to_owned(),
            webpush_endpoint_allowlist: vec![
                "https://updates.push.services.mozilla.com".to_owned(),
            ],
            ..Default::default()
        };

        build_register_device_request(&web_config, &prefs).unwrap();

        let mut blocked = prefs;
        blocked.webpush_endpoint_allowlist = vec!["https://fcm.googleapis.com".to_owned()];
        let err = build_register_device_request(&web_config, &blocked).unwrap_err();
        assert_eq!(err.kind(), PushErrorKind::WebPushEndpointNotAllowed);

        let debug = format!("{err:?}");
        assert!(!debug.contains("token-secret"));
        assert!(!debug.contains("wpush/v2"));
    }

    #[test]
    fn redacts_push_tokens_from_debug_output() {
        let request = build_register_device_request(
            &config(Some("android")),
            &prefs("https://push.example.com/api/v1/push/notify"),
        )
        .unwrap();
        let debug = format!("{request:?}");
        assert!(debug.contains("fcm:<redacted"));
        assert!(!debug.contains("very-secret-token"));

        let config_debug = format!("{:?}", config(Some("android")));
        assert!(config_debug.contains("fcm:<redacted"));
        assert!(!config_debug.contains("very-secret-token"));

        let unregister = build_unregister_device_request(
            &config(Some("android")),
            &prefs("https://push.example.com/api/v1/push/notify?debug=true"),
        )
        .unwrap();
        let unregister_debug = format!("{unregister:?}");
        assert!(!unregister_debug.contains("very-secret-token"));
        assert!(!unregister_debug.contains("debug=true"));
    }

    #[test]
    fn builds_register_signing_context() {
        let request = build_register_device_request(
            &config(Some("android")),
            &prefs("https://push.example.com/api/v1/push/notify"),
        )
        .unwrap();

        let context = build_register_signing_context(
            "https://principal.example",
            &request,
            "2026-04-29T00:00:00Z",
            "https://principal.example",
        )
        .unwrap();

        assert_eq!(context.operation_id, crate::OPERATION_PUSH_REGISTER_DEVICE);
        assert_eq!(context.method, "POST");
        assert_eq!(context.path, REGISTER_DEVICE_PATH);
        assert_eq!(
            context.target_uri,
            "https://principal.example/api/v1/push/register-device"
        );
        assert_eq!(context.device_id, "did:web:alice.example#device-phone");
        assert!(context.content_digest.starts_with("sha-256=:"));
        assert!(context.content_digest.ends_with(':'));
    }

    #[test]
    fn builds_signing_context_with_actor_expiry_and_signature_headers() {
        let request = build_register_device_request(
            &config(Some("android")),
            &prefs("https://push.example.com/api/v1/push/notify"),
        )
        .unwrap();

        let context = build_register_signing_context_with_options(
            "https://principal.example",
            &request,
            PushRequestSigningOptions::new("2026-04-29T00:00:00Z", "https://principal.example")
                .with_actor_did("did:web:alice.example")
                .with_expires_at("2026-04-29T00:05:00Z")
                .with_origin("https://app.example")
                .with_origin_service_did("did:web:sync.example.com")
                .with_destination_service_did("did:web:principal.example")
                .with_nonce("idem-1")
                .with_idempotency_key("idem-1")
                .with_session_grant("coauth-grant-secret"),
        )
        .unwrap();

        assert_eq!(context.actor_did.as_deref(), Some("did:web:alice.example"));
        assert_eq!(context.expires_at.as_deref(), Some("2026-04-29T00:05:00Z"));

        let proof_body = context.canonical_proof_body().unwrap();
        assert_eq!(
            proof_body["operation_id"],
            crate::OPERATION_PUSH_REGISTER_DEVICE
        );
        assert_eq!(proof_body["actor_did"], "did:web:alice.example");
        assert_eq!(proof_body["expires_at"], "2026-04-29T00:05:00Z");
        assert_eq!(proof_body["origin"], "https://app.example");
        assert_eq!(proof_body["nonce"], "idem-1");

        let metadata_headers = context.signed_metadata_headers();
        assert!(
            metadata_headers
                .contains(&(CONTRIX_ACTOR_DID_HEADER, "did:web:alice.example".to_owned()))
        );
        assert!(
            metadata_headers
                .contains(&(CONTRIX_EXPIRES_AT_HEADER, "2026-04-29T00:05:00Z".to_owned()))
        );
        assert!(metadata_headers.contains(&(
            CONTRIX_ORIGIN_SERVICE_DID_HEADER,
            "did:web:sync.example.com".to_owned()
        )));
        assert!(metadata_headers.contains(&(
            CONTRIX_DESTINATION_SERVICE_DID_HEADER,
            "did:web:principal.example".to_owned()
        )));
        assert!(metadata_headers.contains(&(
            CONTRIX_SESSION_GRANT_HEADER,
            "coauth-grant-secret".to_owned()
        )));

        let signature_input = context.http_message_signature_input("sig1").unwrap();
        assert!(signature_input.contains("\"x-contrix-actor-did\""));
        assert!(signature_input.contains("\"x-contrix-expires-at\""));
        assert!(signature_input.contains("\"x-contrix-origin-service-did\""));
        assert!(signature_input.contains("\"x-contrix-destination-service-did\""));
        assert!(signature_input.contains("\"x-contrix-session-grant\""));

        let debug = format!("{context:?}");
        assert!(debug.contains("session_grant"));
        assert!(!debug.contains("coauth-grant-secret"));

        let signature_headers = context
            .http_message_signature_headers("sig1", "YWJjZA==")
            .unwrap();
        assert!(signature_headers.contains(&(SIGNATURE_INPUT_HEADER, signature_input)));
        assert!(signature_headers.contains(&(SIGNATURE_HEADER, "sig1=:YWJjZA==:".to_owned())));
    }

    #[test]
    fn rejects_invalid_signature_header_inputs() {
        let request = build_register_device_request(
            &config(Some("android")),
            &prefs("https://push.example.com/api/v1/push/notify"),
        )
        .unwrap();
        let context = build_register_signing_context(
            "https://principal.example",
            &request,
            "2026-04-29T00:00:00Z",
            "https://principal.example",
        )
        .unwrap();

        assert_eq!(
            context
                .http_message_signature_input("bad label")
                .unwrap_err()
                .kind(),
            PushErrorKind::InvalidHeader
        );
        assert_eq!(
            PushRequestSigningContext::http_message_signature_header("sig1", "bad:sig")
                .unwrap_err()
                .kind(),
            PushErrorKind::InvalidHeader
        );
    }

    #[test]
    fn signing_context_rejects_url_tokens() {
        let request = build_register_device_request(
            &config(Some("android")),
            &prefs("https://push.example.com/api/v1/push/notify"),
        )
        .unwrap();

        let err = build_register_signing_context(
            "https://principal.example?access_token=secret",
            &request,
            "2026-04-29T00:00:00Z",
            "https://principal.example",
        )
        .unwrap_err();

        assert_eq!(err.kind(), PushErrorKind::ForbiddenPushGatewayQueryParam);
    }
}
