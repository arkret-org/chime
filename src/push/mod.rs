//! Cokret push device registration request types and HTTP helper.
//!
//! This module is split into:
//! - [`wire`]: register/unregister request/response DTOs + `CokretError`
//! - [`bridge_describe`]: floria `bridge/describe` + `integration/describe` DTOs
//! - [`errors`]: `PushErrorKind` + `PushRegistrationError` + HTTP classification
//! - [`signing`]: signing context + options + content digest helpers
//! - [`urls`]: URL helpers, validation, redaction
//! - [`registration`]: request body + signing context builders
//! - [`client`]: async `CokretPushClient` (feature = "http")
//! - [`route`]: actor-private `ck.device.push_route` state event wire model
//! - [`rule_core`]: T4.4 shared client-side push rule evaluator

mod bridge_describe;
#[cfg(feature = "http")]
mod client;
mod errors;
mod media_token;
pub mod platform_app_id;
mod registration;
mod route;
mod rule_core;
mod signing;
mod urls;
mod wire;

pub use platform_app_id::{DefaultPlatformAppIdResolver, PlatformAppIdResolver};

// -- Path constants ---------------------------------------------------------

/// Cokret HTTP path for `ck.edge.push.register_device`.
pub const REGISTER_DEVICE_PATH: &str = "/_cokret/edge/push/register-device";

/// Cokret HTTP path for `ck.edge.push.unregister_device`.
pub const UNREGISTER_DEVICE_PATH: &str = "/_cokret/edge/push/unregister-device";

/// Floria product path for discovering the active push gateway bridge contract.
pub const FLORIA_PUSH_BRIDGE_DESCRIBE_PATH: &str = "/_floria/push/bridge/describe";

/// Floria product path for discovering the service-level push gateway integration manifest.
pub const FLORIA_INTEGRATION_DESCRIBE_PATH: &str = "/_floria/integration/describe";

// -- Header constants -------------------------------------------------------

/// Header used to correlate Cokret requests across clients and services.
pub const COKRET_REQUEST_ID_HEADER: &str = "X-Cokret-Request-Id";

/// RFC 9530 content digest header covered by request signatures.
pub const CONTENT_DIGEST_HEADER: &str = "Content-Digest";

/// Cokret operation id header covered by request signatures.
pub const COKRET_OPERATION_ID_HEADER: &str = "X-Cokret-Operation-Id";

/// Cokret device id header covered by request signatures.
pub const COKRET_DEVICE_ID_HEADER: &str = "X-Cokret-Device-Id";

/// Cokret request creation timestamp header covered by request signatures.
pub const COKRET_CREATED_AT_HEADER: &str = "X-Cokret-Created-At";

/// Cokret request audience header covered by request signatures.
pub const COKRET_AUDIENCE_HEADER: &str = "X-Cokret-Audience";

/// Cokret actor ID header covered by request signatures.
pub const COKRET_ACTOR_ID_HEADER: &str = "X-Cokret-Actor-Id";

/// Cokret request expiry timestamp header covered by request signatures.
pub const COKRET_EXPIRES_AT_HEADER: &str = "X-Cokret-Expires-At";

/// Cokret request origin URL header covered by request signatures.
pub const COKRET_ORIGIN_HEADER: &str = "X-Cokret-Origin";

/// Cokret origin service DID header covered by request signatures.
pub const COKRET_ORIGIN_SERVICE_DID_HEADER: &str = "X-Cokret-Origin-Service-Did";

/// Cokret destination service DID header covered by request signatures.
pub const COKRET_DESTINATION_SERVICE_DID_HEADER: &str = "X-Cokret-Destination-Service-Did";

/// Cokret nonce header covered by request signatures.
pub const COKRET_NONCE_HEADER: &str = "X-Cokret-Nonce";

/// Cokret idempotency key metadata header covered by request signatures.
pub const COKRET_IDEMPOTENCY_KEY_HEADER: &str = "X-Cokret-Idempotency-Key";

/// Header used to carry an externally supplied coauth/soland session grant.
pub const COKRET_SESSION_GRANT_HEADER: &str = "X-Cokret-Session-Grant";

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
    PushBridgeDescribeNotifyDescriptor, PushBridgeDescribeOutcome,
    PushBridgeDescribePrivacyDescriptor, PushGatewayIntegrationDependency,
    PushGatewayIntegrationDescribeOutcome, PushGatewayIntegrationSurface,
};
#[cfg(feature = "http")]
pub use client::{CokretHttpOutcome, CokretPushClient, PushRetryPolicy};
pub use errors::{PushErrorKind, PushRegistrationError};
pub use media_token::{
    CallMediaParticipantBinding, CallMediaTokenExchangeOutcome, CallMediaTokenExchangeRequestBody,
    MediaBackendType, MediaTokenError, MediaTokenStructuralValidationContext,
    StructurallyValidatedMediaTokenOutcome, call_media_token_exchange, ensure_known_backend,
    structurally_validate_media_token_outcome,
};
pub use registration::{
    build_register_device_request, build_register_signing_context,
    build_register_signing_context_with_options, build_unregister_device_request,
    build_unregister_signing_context, build_unregister_signing_context_with_options,
};
pub use route::{
    PushRoute, PushRouteCapability, PushRouteError, PushRouteId, PushRouteValidationError,
    ServiceDid,
};
pub use rule_core::{
    EventContext as PushRuleEventContext, ShouldNotify, WatchLevel, evaluate_watch_level,
    reason_code as push_rule_reason_code,
};
pub use signing::{
    NonceReplayError, NonceTracker, PushRequestSigningContext, PushRequestSigningOptions,
    content_digest_sha256,
};
pub use urls::{
    cokret_api_url, push_bridge_describe_url, push_gateway_service_base_url,
    push_integration_describe_url, redact_push_key, validate_push_gateway_url,
    validate_webpush_endpoint_allowlist,
};
pub use wire::{
    CokretError, CokretErrorEnvelope, PushDeviceConfig, PushPlatform, PushRegisterDeviceOutcome,
    PushRegisterDeviceRequestBody, PushUnregisterDeviceOutcome, PushUnregisterDeviceRequestBody,
    compute_push_key_hmac, verify_push_key_binding,
};
