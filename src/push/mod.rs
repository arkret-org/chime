//! Arkret push device registration request types and HTTP helper.
//!
//! This module is split into:
//! - [`wire`]: register/unregister request/response DTOs + `CokretError`
//! - [`bridge_describe`]: floria `bridge/describe` + `integration/describe` DTOs
//! - [`errors`]: `PushErrorKind` + `PushRegistrationError` + HTTP classification
//! - [`signing`]: signing context + options + content digest helpers
//! - [`urls`]: URL helpers, validation, redaction
//! - [`registration`]: request body + signing context builders
//! - [`client`]: async `CokretPushClient` (feature = "http")
//! - [`route`]: actor-private `ak.device.push_route` state event wire model
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

/// Arkret HTTP path for `ak.edge.push.command.register_device`.
pub const REGISTER_DEVICE_PATH: &str = "/_arkret/edge/push/register-device";

/// Arkret HTTP path for `ak.edge.push.command.unregister_device`.
pub const UNREGISTER_DEVICE_PATH: &str = "/_arkret/edge/push/unregister-device";

/// Arkret HTTP path for `ak.edge.push.command.notify`.
pub const PUSH_NOTIFY_PATH: &str = "/_arkret/edge/push/notify";

/// Arkret HTTP path for `ak.server.query.describe`.
pub const SERVER_DESCRIBE_PATH: &str = "/_arkret/describe";

/// Floria product path for discovering the active push gateway bridge contract.
pub(crate) const FLORIA_PUSH_BRIDGE_DESCRIBE_PATH: &str = "/_floria/push/bridge/describe";

/// Floria product path for discovering the service-level push gateway integration manifest.
pub(crate) const FLORIA_INTEGRATION_DESCRIBE_PATH: &str = "/_floria/integration/describe";

// -- Header constants -------------------------------------------------------

/// Header used to correlate Arkret requests across clients and services.
pub const ARKRET_REQUEST_ID_HEADER: &str = "X-Arkret-Request-Id";

/// RFC 9530 content digest header covered by request signatures.
pub const CONTENT_DIGEST_HEADER: &str = "Content-Digest";

/// Arkret operation id header covered by request signatures.
pub const ARKRET_OPERATION_ID_HEADER: &str = "X-Arkret-Operation-Id";

/// Arkret device id header covered by request signatures.
pub const ARKRET_DEVICE_ID_HEADER: &str = "X-Arkret-Device-Id";

/// Arkret request creation timestamp header covered by request signatures.
pub const ARKRET_CREATED_AT_HEADER: &str = "X-Arkret-Created-At";

/// Arkret request audience header covered by request signatures.
pub const ARKRET_AUDIENCE_HEADER: &str = "X-Arkret-Audience";

/// Arkret actor ID header covered by request signatures.
pub const ARKRET_ACTOR_ID_HEADER: &str = "X-Arkret-Actor-Id";

/// Arkret request expiry timestamp header covered by request signatures.
pub const ARKRET_EXPIRES_AT_HEADER: &str = "X-Arkret-Expires-At";

/// Arkret request origin URL header covered by request signatures.
pub const ARKRET_ORIGIN_HEADER: &str = "X-Arkret-Origin";

/// Arkret origin service DID header covered by request signatures.
pub const ARKRET_ORIGIN_SERVICE_DID_HEADER: &str = "X-Arkret-Origin-Service-Did";

/// Arkret destination service DID header covered by request signatures.
pub const ARKRET_DESTINATION_SERVICE_DID_HEADER: &str = "X-Arkret-Destination-Service-Did";

/// Arkret nonce header covered by request signatures.
pub const ARKRET_NONCE_HEADER: &str = "X-Arkret-Nonce";

/// Arkret idempotency key metadata header covered by request signatures.
pub const ARKRET_IDEMPOTENCY_KEY_HEADER: &str = "X-Arkret-Idempotency-Key";

/// Header used to carry an externally supplied coauth/soland session grant.
pub const ARKRET_SESSION_GRANT_HEADER: &str = "X-Arkret-Session-Grant";

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
    PushGatewayIntegrationDescribeOutcome,
};
#[cfg(feature = "http")]
pub use client::{CokretHttpOutcome, CokretPushClient, PushRetryPolicy};
pub use arkret::{
    PushRegisterDeviceOutcome, PushRegisterDeviceRequestBody, PushUnregisterDeviceOutcome,
    PushUnregisterDeviceRequestBody, ServiceDescribe,
};
pub use errors::{PushErrorKind, PushRegistrationError};
pub use media_token::{
    CallMediaParticipantBinding, CallMediaTokenExchangeOutcome, CallMediaTokenExchangeRequestBody,
    CallMediaTokenVerification, MediaBackendType, MediaServiceAnchors, MediaTokenError,
    MediaTokenVerificationContext, VerifiedMediaTokenOutcome, call_media_token_exchange,
    ensure_known_backend, verify_media_token_outcome,
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
    arkret_api_url, floria_push_bridge_describe_url, floria_push_integration_describe_url,
    push_gateway_service_base_url, redact_push_key, validate_push_gateway_url,
    validate_webpush_endpoint_allowlist,
};
pub use wire::{
    ChimePushRegisterDeviceOutcome, ChimePushRegisterDeviceRequest,
    ChimePushUnregisterDeviceOutcome, ChimePushUnregisterDeviceRequest, CokretError,
    CokretErrorEnvelope, PushDeviceConfig, PushPlatform,
};
