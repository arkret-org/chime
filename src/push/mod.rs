//! Contrix push device registration request types and HTTP helper.
//!
//! This module is split into:
//! - [`wire`]: register/unregister request/response DTOs + `ContrixError`
//! - [`bridge_describe`]: `bridge/describe` + `integration/describe` DTOs
//! - [`errors`]: `PushErrorKind` + `PushRegistrationError` + HTTP classification
//! - [`signing`]: signing context + options + content digest helpers
//! - [`urls`]: URL helpers, validation, redaction
//! - [`registration`]: request body + signing context builders
//! - [`client`]: async `ContrixPushClient` (feature = "http")
//! - [`route`]: actor-private `cx.device.push_route` state event wire model
//! - [`rule_core`]: T4.4 shared client-side push rule evaluator

mod bridge_describe;
#[cfg(feature = "http")]
mod client;
mod errors;
pub mod platform_app_id;
mod registration;
mod route;
mod rule_core;
mod signing;
mod urls;
mod wire;

pub use platform_app_id::{DefaultPlatformAppIdResolver, PlatformAppIdResolver};

// -- Path constants ---------------------------------------------------------

/// Contrix HTTP path for `cx.push.register_device`.
pub const REGISTER_DEVICE_PATH: &str = "/api/v1/push/register-device";

/// Contrix HTTP path for `cx.push.unregister_device`.
pub const UNREGISTER_DEVICE_PATH: &str = "/api/v1/push/unregister-device";

/// B.5 #8 — Contrix HTTP path for `cx.push.unsubscribe`. The body is a
/// [`PushUnsubscribeRequest`]; the URL also accepts an optional
/// `target_id` query parameter for callers that prefer to encode the
/// scope outside the JSON envelope (the wire body remains canonical).
pub const PUSH_UNSUBSCRIBE_PATH: &str = "/api/v1/push/unsubscribe";

/// Contrix HTTP path for discovering the active push gateway bridge contract.
pub const PUSH_BRIDGE_DESCRIBE_PATH: &str = "/api/v1/push/bridge/describe";

/// Contrix HTTP path for discovering the service-level push gateway integration manifest.
pub const PUSH_INTEGRATION_DESCRIBE_PATH: &str = "/api/v1/integration/describe";

// -- Header constants -------------------------------------------------------

/// Header used to correlate Contrix requests across clients and services.
pub const CONTRIX_REQUEST_ID_HEADER: &str = "X-Contrix-Request-Id";

/// RFC 9530 content digest header covered by request signatures.
pub const CONTENT_DIGEST_HEADER: &str = "Content-Digest";

/// Contrix operation id header covered by request signatures.
pub const CONTRIX_OPERATION_ID_HEADER: &str = "X-Contrix-Operation-Id";

/// Contrix device id header covered by request signatures.
pub const CONTRIX_DEVICE_ID_HEADER: &str = "X-Contrix-Device-Id";

/// Contrix request creation timestamp header covered by request signatures.
pub const CONTRIX_CREATED_AT_HEADER: &str = "X-Contrix-Created-At";

/// Contrix request audience header covered by request signatures.
pub const CONTRIX_AUDIENCE_HEADER: &str = "X-Contrix-Audience";

/// Contrix actor DID header covered by request signatures.
pub const CONTRIX_ACTOR_DID_HEADER: &str = "X-Contrix-Actor-Did";

/// Contrix request expiry timestamp header covered by request signatures.
pub const CONTRIX_EXPIRES_AT_HEADER: &str = "X-Contrix-Expires-At";

/// Contrix request origin URL header covered by request signatures.
pub const CONTRIX_ORIGIN_HEADER: &str = "X-Contrix-Origin";

/// Contrix origin service DID header covered by request signatures.
pub const CONTRIX_ORIGIN_SERVICE_DID_HEADER: &str = "X-Contrix-Origin-Service-Did";

/// Contrix destination service DID header covered by request signatures.
pub const CONTRIX_DESTINATION_SERVICE_DID_HEADER: &str = "X-Contrix-Destination-Service-Did";

/// Contrix nonce header covered by request signatures.
pub const CONTRIX_NONCE_HEADER: &str = "X-Contrix-Nonce";

/// Contrix idempotency key metadata header covered by request signatures.
pub const CONTRIX_IDEMPOTENCY_KEY_HEADER: &str = "X-Contrix-Idempotency-Key";

/// Header used to carry an externally supplied coauth/soland session grant.
pub const CONTRIX_SESSION_GRANT_HEADER: &str = "X-Contrix-Session-Grant";

/// HTTP Message Signatures input header.
pub const SIGNATURE_INPUT_HEADER: &str = "Signature-Input";

/// HTTP Message Signatures signature header.
pub const SIGNATURE_HEADER: &str = "Signature";

#[cfg(feature = "http")]
const SDK_USER_AGENT: &str = concat!("chime/", env!("CARGO_PKG_VERSION"));
#[cfg(feature = "http")]
const RETRY_AFTER_HEADER: &str = "Retry-After";

// -- Re-exports -------------------------------------------------------------

pub use bridge_describe::{
    EXPECTED_SPEC_VERSION, IntegrationView, PushBridgeDescribeGatewayDescriptor,
    PushBridgeDescribeNotifyDescriptor, PushBridgeDescribePrivacyDescriptor,
    PushBridgeDescribeResponse, PushGatewayIntegrationDependency,
    PushGatewayIntegrationDescribeResponse, PushGatewayIntegrationSurface,
};
pub use errors::{PushErrorKind, PushRegistrationError};
pub use registration::{
    build_register_device_request, build_register_signing_context,
    build_register_signing_context_with_options, build_unregister_device_request,
    build_unregister_signing_context, build_unregister_signing_context_with_options,
    build_unsubscribe_request,
};
pub use signing::{
    NonceReplayError, NonceTracker, PushRequestSigningContext, PushRequestSigningOptions,
    content_digest_sha256,
};
pub use urls::{
    contrix_api_url, push_bridge_describe_url, push_gateway_service_base_url,
    push_integration_describe_url, redact_push_key, validate_push_gateway_url,
    validate_webpush_endpoint_allowlist,
};
pub use wire::{
    ContrixError, ContrixErrorEnvelope, PushDeviceConfig, PushPlatform, PushUnsubscribeRequest,
    PushUnsubscribeResponse, RegisterDeviceRequest, RegisterDeviceResponse,
    UnregisterDeviceRequest, UnregisterDeviceResponse, compute_push_key_hmac,
    verify_push_key_binding,
};

#[cfg(feature = "http")]
pub use client::{ContrixPushClient, ContrixResponse, PushRetryPolicy};

pub use route::{
    PushRoute, PushRouteCapability, PushRouteError, PushRouteId, PushRouteValidationError,
    ServiceDid,
};
pub use rule_core::{
    EventContext as PushRuleEventContext, ShouldNotify, WatchLevel, evaluate_watch_level,
    reason_code as push_rule_reason_code,
};
