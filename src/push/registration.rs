//! Request body builders for register/unregister + their signing contexts.

use super::errors::PushRegistrationError;
use super::signing::{PushRequestSigningContext, PushRequestSigningOptions, build_signing_context};
use super::urls::{
    redact_push_key, require_non_empty, require_optional_non_empty, validate_push_gateway_url,
    validate_webpush_endpoint_allowlist,
};
use super::wire::{
    ChimePushRegisterDeviceRequest, ChimePushUnregisterDeviceRequest, PushDeviceConfig,
    PushPlatform,
};
use super::{REGISTER_DEVICE_PATH, UNREGISTER_DEVICE_PATH};
use crate::{GatewayBinding, PushPreferences, hash_push_key};

/// Build the Arkret register-device request body from app configuration,
/// the target gateway binding, and stored push preferences.
///
/// The `binding`'s `push_key` and `app_id` overrides take priority over
/// the matching fields in `config`. `prefs` carries policy fields only
/// (loopback opt-in, webpush allowlist, …).
///
/// ```rust
/// use chime::{
///     GatewayBinding, PushDeviceConfig, PushGatewayType, PushPreferences,
///     build_register_device_request,
/// };
///
/// let config = PushDeviceConfig {
///     principal_id: Some("did:web:alice.example"),
///     device_id: "ak:device:01904100-0000-7000-8000-000000000004",
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
/// let binding = GatewayBinding::new(
///     PushGatewayType::Standard,
///     "https://push.example.com/_arkret/edge/push/notify",
/// );
/// let prefs = PushPreferences {
///     enabled: true,
///     ..Default::default()
/// };
///
/// let request = build_register_device_request(&config, &binding, &prefs).unwrap();
/// assert_eq!(
///     request.device_id,
///     "ak:device:01904100-0000-7000-8000-000000000004"
/// );
/// ```
pub fn build_register_device_request(
    config: &PushDeviceConfig<'_>,
    binding: &GatewayBinding,
    prefs: &PushPreferences,
) -> Result<ChimePushRegisterDeviceRequest, PushRegistrationError> {
    require_non_empty("device_id", config.device_id)?;
    let push_key_value = binding.push_key.as_deref().or(config.push_key);
    let push_key = require_optional_non_empty("push_key", push_key_value)?;
    validate_push_gateway_url(
        &binding.push_gateway,
        prefs.allow_insecure_loopback_push_gateway,
    )?;

    let platform = parse_platform(config.platform)?;
    let app_id = binding.resolve_app_id(platform, config.app_id, config.domestic_app_id);
    if platform == Some(PushPlatform::Web) {
        validate_webpush_endpoint_allowlist(push_key, &prefs.webpush_endpoint_allowlist)?;
    }

    Ok(ChimePushRegisterDeviceRequest {
        operation_id: crate::OPERATION_PUSH_REGISTER_DEVICE.to_owned(),
        principal_id: config
            .principal_id
            .and_then(non_empty_str)
            .map(str::to_owned),
        device_id: config.device_id.to_owned(),
        push_gateway: binding.push_gateway.clone(),
        push_key: push_key.to_owned(),
        platform: platform.map(|value| value.as_str().to_owned()),
        app_id: app_id.map(str::to_owned),
        display_name: config.display_name.map(str::to_owned),
        idempotency_key: config.idempotency_key.map(str::to_owned),
        request_id: config.request_id.map(str::to_owned),
        proof: config.proof.cloned(),
        ..Default::default()
    })
}

/// Build the Arkret unregister-device request body from app configuration,
/// the target gateway binding, and stored push preferences.
///
/// ```rust
/// use chime::{
///     GatewayBinding, PushDeviceConfig, PushGatewayType, PushPreferences,
///     build_unregister_device_request,
/// };
///
/// let config = PushDeviceConfig {
///     principal_id: Some("did:web:alice.example"),
///     device_id: "ak:device:01904100-0000-7000-8000-000000000004",
///     push_key: None,
///     platform: Some("android"),
///     app_id: Some("app.example.android"),
///     domestic_app_id: None,
///     registration_id: Some("ak:pushreg:01JS0KE000000000000000000"),
///     display_name: None,
///     idempotency_key: Some("unregister-phone-v1"),
///     request_id: None,
///     proof: None,
/// };
/// let binding = GatewayBinding::new(
///     PushGatewayType::Standard,
///     "https://push.example.com/_arkret/edge/push/notify",
/// );
/// let request =
///     build_unregister_device_request(&config, &binding, &PushPreferences::default()).unwrap();
/// assert_eq!(
///     request.registration_id.as_deref(),
///     Some("ak:pushreg:01JS0KE000000000000000000")
/// );
/// ```
pub fn build_unregister_device_request(
    config: &PushDeviceConfig<'_>,
    binding: &GatewayBinding,
    prefs: &PushPreferences,
) -> Result<ChimePushUnregisterDeviceRequest, PushRegistrationError> {
    require_non_empty("device_id", config.device_id)?;
    if non_empty_str(&binding.push_gateway).is_some() {
        validate_push_gateway_url(
            &binding.push_gateway,
            prefs.allow_insecure_loopback_push_gateway,
        )?;
    }

    let platform = parse_platform(config.platform)?;
    let app_id = binding.resolve_app_id(platform, config.app_id, config.domestic_app_id);
    let push_key = binding
        .push_key
        .as_deref()
        .or(config.push_key)
        .and_then(non_empty_str);

    Ok(ChimePushUnregisterDeviceRequest {
        operation_id: crate::OPERATION_PUSH_UNREGISTER_DEVICE.to_owned(),
        principal_id: config
            .principal_id
            .and_then(non_empty_str)
            .map(str::to_owned),
        device_id: config.device_id.to_owned(),
        registration_id: non_empty_str(config.registration_id.unwrap_or_default())
            .map(str::to_owned),
        push_gateway: non_empty_str(&binding.push_gateway).map(str::to_owned),
        push_key: push_key.map(str::to_owned),
        push_key_hash: push_key.map(hash_push_key),
        push_key_preview: push_key.map(redact_push_key),
        app_id: app_id.map(str::to_owned),
        idempotency_key: config.idempotency_key.map(str::to_owned),
        request_id: config.request_id.map(str::to_owned),
        proof: config.proof.cloned(),
        ..Default::default()
    })
}

/// Build the signing context for `ak.edge.push.command.register_device`.
///
/// ```rust
/// use chime::{
///     GatewayBinding, PushDeviceConfig, PushGatewayType, PushPreferences,
///     build_register_device_request, build_register_signing_context,
/// };
///
/// let config = PushDeviceConfig {
///     principal_id: Some("did:web:alice.example"),
///     device_id: "ak:device:01904100-0000-7000-8000-000000000004",
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
/// let binding = GatewayBinding::new(
///     PushGatewayType::Standard,
///     "https://push.example.com/_arkret/edge/push/notify",
/// );
/// let prefs = PushPreferences {
///     enabled: true,
///     ..Default::default()
/// };
/// let request = build_register_device_request(&config, &binding, &prefs).unwrap();
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
    request: &ChimePushRegisterDeviceRequest,
    created_at: impl Into<String>,
    audience: impl Into<String>,
) -> Result<PushRequestSigningContext, PushRegistrationError> {
    build_register_signing_context_with_options(
        service_base_url,
        request,
        PushRequestSigningOptions::new(created_at, audience),
    )
}

/// Build the signing context for `ak.edge.push.command.register_device` with actor and
/// expiry metadata.
pub fn build_register_signing_context_with_options(
    service_base_url: &str,
    request: &ChimePushRegisterDeviceRequest,
    options: PushRequestSigningOptions,
) -> Result<PushRequestSigningContext, PushRegistrationError> {
    let sdk_request = request.to_sdk_request()?;
    build_signing_context(
        service_base_url,
        crate::OPERATION_PUSH_REGISTER_DEVICE,
        REGISTER_DEVICE_PATH,
        sdk_request.device_id.as_str(),
        &sdk_request,
        options,
    )
}

/// Build the signing context for `ak.edge.push.command.unregister_device`.
pub fn build_unregister_signing_context(
    service_base_url: &str,
    request: &ChimePushUnregisterDeviceRequest,
    created_at: impl Into<String>,
    audience: impl Into<String>,
) -> Result<PushRequestSigningContext, PushRegistrationError> {
    build_unregister_signing_context_with_options(
        service_base_url,
        request,
        PushRequestSigningOptions::new(created_at, audience),
    )
}

/// Build the signing context for `ak.edge.push.command.unregister_device` with actor and
/// expiry metadata.
pub fn build_unregister_signing_context_with_options(
    service_base_url: &str,
    request: &ChimePushUnregisterDeviceRequest,
    options: PushRequestSigningOptions,
) -> Result<PushRequestSigningContext, PushRegistrationError> {
    let sdk_request = request.to_sdk_request()?;
    build_signing_context(
        service_base_url,
        crate::OPERATION_PUSH_UNREGISTER_DEVICE,
        UNREGISTER_DEVICE_PATH,
        sdk_request.device_id.as_str(),
        &sdk_request,
        options,
    )
}

fn parse_platform(value: Option<&str>) -> Result<Option<PushPlatform>, PushRegistrationError> {
    value.map(PushPlatform::try_from).transpose()
}

fn non_empty_str(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::push::errors::PushErrorKind;
    use crate::push::{
        ARKRET_ACTOR_ID_HEADER, ARKRET_DESTINATION_SERVICE_ID_HEADER, ARKRET_EXPIRES_AT_HEADER,
        ARKRET_ORIGIN_SERVICE_ID_HEADER, ARKRET_SESSION_GRANT_HEADER, SIGNATURE_HEADER,
        SIGNATURE_INPUT_HEADER,
    };
    use crate::{DEFAULT_BUGLE_PUSH_GATEWAY_URL, PushGatewayType};

    fn config<'a>(platform: Option<&'a str>) -> PushDeviceConfig<'a> {
        PushDeviceConfig {
            principal_id: Some("did:web:alice.example"),
            device_id: "ak:device:01904100-0000-7000-8000-000000000004",
            push_key: Some("fcm:very-secret-token"),
            platform,
            app_id: Some("app.example.android"),
            domestic_app_id: Some("app.example.android.cn"),
            registration_id: Some("ak:pushreg:01JS0KE000000000000000000"),
            display_name: Some("Alice Phone"),
            idempotency_key: Some("idem-1"),
            request_id: Some("ak:request:01JS0KE000000000000000000"),
            proof: None,
        }
    }

    fn binding(gateway_type: PushGatewayType, push_gateway: &str) -> GatewayBinding {
        GatewayBinding::new(gateway_type, push_gateway)
    }

    fn enabled_prefs() -> PushPreferences {
        PushPreferences {
            enabled: true,
            ..Default::default()
        }
    }

    #[test]
    fn register_request_matches_arkret_schema() {
        let binding = binding(PushGatewayType::Bugle, DEFAULT_BUGLE_PUSH_GATEWAY_URL);
        let request =
            build_register_device_request(&config(Some("android")), &binding, &enabled_prefs())
                .unwrap();

        assert_eq!(request.operation_id, crate::OPERATION_PUSH_REGISTER_DEVICE);
        assert_eq!(
            request.principal_id.as_deref(),
            Some("did:web:alice.example")
        );
        assert_eq!(
            request.device_id,
            "ak:device:01904100-0000-7000-8000-000000000004"
        );
        assert_eq!(request.push_gateway, DEFAULT_BUGLE_PUSH_GATEWAY_URL);
        assert_eq!(request.push_key, "fcm:very-secret-token");
        assert_eq!(request.platform.as_deref(), Some("android"));
        assert_eq!(request.app_id.as_deref(), Some("app.example.android.cn"));
        assert_eq!(request.display_name.as_deref(), Some("Alice Phone"));
        assert_eq!(request.idempotency_key.as_deref(), Some("idem-1"));
        assert_eq!(
            request.request_id.as_deref(),
            Some("ak:request:01JS0KE000000000000000000")
        );
    }

    #[test]
    fn unregister_request_supports_registration_id() {
        let binding = binding(
            PushGatewayType::Standard,
            "https://push.example.com/_arkret/edge/push/notify",
        );
        let request = build_unregister_device_request(
            &config(Some("ios")),
            &binding,
            &PushPreferences::default(),
        )
        .unwrap();

        assert_eq!(
            request.operation_id,
            crate::OPERATION_PUSH_UNREGISTER_DEVICE
        );
        assert_eq!(
            request.principal_id.as_deref(),
            Some("did:web:alice.example")
        );
        assert_eq!(
            request.device_id,
            "ak:device:01904100-0000-7000-8000-000000000004"
        );
        assert_eq!(
            request.registration_id.as_deref(),
            Some("ak:pushreg:01JS0KE000000000000000000")
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
            Some("ak:request:01JS0KE000000000000000000")
        );
    }

    #[test]
    fn requires_register_push_gateway() {
        let binding = binding(PushGatewayType::Standard, " ");
        let err =
            build_register_device_request(&config(Some("android")), &binding, &enabled_prefs())
                .unwrap_err();
        assert_eq!(err.kind(), PushErrorKind::MissingField);
    }

    #[test]
    fn requires_register_push_key() {
        let mut config = config(Some("android"));
        config.push_key = None;
        let binding = binding(
            PushGatewayType::Standard,
            "https://push.example.com/_arkret/edge/push/notify",
        );
        let err = build_register_device_request(&config, &binding, &enabled_prefs()).unwrap_err();
        assert_eq!(err.kind(), PushErrorKind::MissingField);
    }

    #[test]
    fn requires_device_id() {
        let mut config = config(Some("android"));
        config.device_id = " ";
        let binding = binding(
            PushGatewayType::Standard,
            "https://push.example.com/_arkret/edge/push/notify",
        );
        let err = build_register_device_request(&config, &binding, &enabled_prefs()).unwrap_err();
        assert_eq!(err.kind(), PushErrorKind::MissingField);
    }

    #[test]
    fn validates_webpush_endpoint_allowlist() {
        let mut web_config = config(Some("web"));
        web_config.push_key =
            Some("webpush:https://updates.push.services.mozilla.com/wpush/v2/token-secret");
        let binding = binding(
            PushGatewayType::Standard,
            "https://push.example.com/_arkret/edge/push/notify",
        );
        let prefs = PushPreferences {
            enabled: true,
            webpush_endpoint_allowlist: vec![
                "https://updates.push.services.mozilla.com".to_owned(),
            ],
            ..Default::default()
        };

        build_register_device_request(&web_config, &binding, &prefs).unwrap();

        let mut blocked = prefs;
        blocked.webpush_endpoint_allowlist = vec!["https://fcm.googleapis.com".to_owned()];
        let err = build_register_device_request(&web_config, &binding, &blocked).unwrap_err();
        assert_eq!(err.kind(), PushErrorKind::WebPushEndpointNotAllowed);

        let debug = format!("{err:?}");
        assert!(!debug.contains("token-secret"));
        assert!(!debug.contains("wpush/v2"));
    }

    #[test]
    fn redacts_push_tokens_from_debug_output() {
        let plain_binding = binding(
            PushGatewayType::Standard,
            "https://push.example.com/_arkret/edge/push/notify",
        );
        let request = build_register_device_request(
            &config(Some("android")),
            &plain_binding,
            &enabled_prefs(),
        )
        .unwrap();
        let debug = format!("{request:?}");
        assert!(debug.contains("fcm:<redacted"));
        assert!(!debug.contains("very-secret-token"));

        let config_debug = format!("{:?}", config(Some("android")));
        assert!(config_debug.contains("fcm:<redacted"));
        assert!(!config_debug.contains("very-secret-token"));

        let debug_binding = binding(
            PushGatewayType::Standard,
            "https://push.example.com/_arkret/edge/push/notify?debug=true",
        );
        let unregister = build_unregister_device_request(
            &config(Some("android")),
            &debug_binding,
            &enabled_prefs(),
        )
        .unwrap();
        let unregister_debug = format!("{unregister:?}");
        assert!(!unregister_debug.contains("very-secret-token"));
        assert!(!unregister_debug.contains("debug=true"));
    }

    #[test]
    fn builds_register_signing_context() {
        let binding = binding(
            PushGatewayType::Standard,
            "https://push.example.com/_arkret/edge/push/notify",
        );
        let request =
            build_register_device_request(&config(Some("android")), &binding, &enabled_prefs())
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
            "https://principal.example/_arkret/edge/push/register-device"
        );
        assert_eq!(
            context.device_id,
            "ak:device:01904100-0000-7000-8000-000000000004"
        );
        assert!(context.content_digest.starts_with("sha-256=:"));
        assert!(context.content_digest.ends_with(':'));
    }

    #[test]
    fn builds_signing_context_with_actor_expiry_and_signature_headers() {
        let binding = binding(
            PushGatewayType::Standard,
            "https://push.example.com/_arkret/edge/push/notify",
        );
        let request =
            build_register_device_request(&config(Some("android")), &binding, &enabled_prefs())
                .unwrap();

        let context = build_register_signing_context_with_options(
            "https://principal.example",
            &request,
            PushRequestSigningOptions::new("2026-04-29T00:00:00Z", "https://principal.example")
                .with_actor_id("did:web:alice.example")
                .with_expires_at("2026-04-29T00:05:00Z")
                .with_origin("https://app.example")
                .with_origin_service_id("did:web:sync.example.com")
                .with_destination_service_id("did:web:principal.example")
                .with_nonce("idem-1")
                .with_idempotency_key("idem-1")
                .with_session_grant("coauth-grant-secret"),
        )
        .unwrap();

        assert_eq!(context.actor_id.as_deref(), Some("did:web:alice.example"));
        assert_eq!(context.expires_at.as_deref(), Some("2026-04-29T00:05:00Z"));

        let proof_body = context.canonical_proof_body().unwrap();
        assert_eq!(
            proof_body["operation_id"],
            crate::OPERATION_PUSH_REGISTER_DEVICE
        );
        assert_eq!(proof_body["actor_id"], "did:web:alice.example");
        assert_eq!(proof_body["expires_at"], "2026-04-29T00:05:00Z");
        assert_eq!(proof_body["origin"], "https://app.example");
        assert_eq!(proof_body["nonce"], "idem-1");

        let metadata_headers = context.signed_metadata_headers();
        assert!(
            metadata_headers
                .contains(&(ARKRET_ACTOR_ID_HEADER, "did:web:alice.example".to_owned()))
        );
        assert!(
            metadata_headers
                .contains(&(ARKRET_EXPIRES_AT_HEADER, "2026-04-29T00:05:00Z".to_owned()))
        );
        assert!(metadata_headers.contains(&(
            ARKRET_ORIGIN_SERVICE_ID_HEADER,
            "did:web:sync.example.com".to_owned()
        )));
        assert!(metadata_headers.contains(&(
            ARKRET_DESTINATION_SERVICE_ID_HEADER,
            "did:web:principal.example".to_owned()
        )));
        assert!(metadata_headers.contains(&(
            ARKRET_SESSION_GRANT_HEADER,
            "coauth-grant-secret".to_owned()
        )));

        let signature_input = context.http_message_signature_input("sig1").unwrap();
        assert!(signature_input.contains("\"x-arkret-actor-id\""));
        assert!(signature_input.contains("\"x-arkret-expires-at\""));
        assert!(signature_input.contains("\"x-arkret-origin-service-did\""));
        assert!(signature_input.contains("\"x-arkret-destination-service-did\""));
        assert!(signature_input.contains("\"x-arkret-session-grant\""));

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
        let binding = binding(
            PushGatewayType::Standard,
            "https://push.example.com/_arkret/edge/push/notify",
        );
        let request =
            build_register_device_request(&config(Some("android")), &binding, &enabled_prefs())
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
        let binding = binding(
            PushGatewayType::Standard,
            "https://push.example.com/_arkret/edge/push/notify",
        );
        let request =
            build_register_device_request(&config(Some("android")), &binding, &enabled_prefs())
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
