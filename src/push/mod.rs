//! Arkret push device registration request types and HTTP helper.
//!
//! This module is split into:
//! - [`wire`]: register/unregister request builders and local configuration DTOs
//! - canonical push-gateway [`ServiceDescribe`] discovery
//! - [`errors`]: `PushErrorKind` + `PushRegistrationError` + HTTP classification
//! - [`urls`]: URL helpers, validation, redaction
//! - [`registration`]: request body builders
//! - [`client`]: async `ArkretPushClient` (feature = "http")

#[cfg(feature = "http")]
mod client;
mod errors;
mod registration;
mod urls;
mod wire;

// -- Path constants ---------------------------------------------------------

/// Arkret HTTP path for `ak.edge.push.command.register_device.v1`.
#[cfg(feature = "http")]
pub(crate) const REGISTER_DEVICE_PATH: &str = "/_arkret/edge/push/register-device";

/// Arkret HTTP path for `ak.edge.push.command.unregister_device.v1`.
#[cfg(feature = "http")]
pub(crate) const UNREGISTER_DEVICE_PATH: &str = "/_arkret/edge/push/unregister-device";

/// Canonical role-scoped service discovery path.
#[cfg(feature = "http")]
pub(crate) const SERVICE_DESCRIBE_PATH: &str = "/_arkret/describe";

// -- Header constants -------------------------------------------------------

/// Header used to correlate Arkret requests across clients and services.
#[cfg(feature = "http")]
pub(crate) const ARKRET_REQUEST_ID_HEADER: &str = "X-Arkret-Request-Id";

/// Header used to carry an externally supplied coauth/soland session grant.
#[cfg(feature = "http")]
pub(crate) const ARKRET_SESSION_GRANT_HEADER: &str = "X-Arkret-Session-Grant";

#[cfg(feature = "http")]
const SDK_USER_AGENT: &str = concat!("chime/", env!("CARGO_PKG_VERSION"));
#[cfg(feature = "http")]
const RETRY_AFTER_HEADER: &str = "Retry-After";

// -- Re-exports -------------------------------------------------------------

pub use arkret_models_discovery::ServiceDescribe;
#[cfg(feature = "http")]
pub use client::{ArkretHttpOutcome, ArkretPushClient, PushRetryPolicy};
pub use errors::{PushErrorKind, PushRegistrationError};
pub use registration::{build_register_device_request, build_unregister_device_request};
pub use urls::{redact_push_key, validate_push_gateway_url, validate_webpush_endpoint_allowlist};
pub use wire::{
    ChimePushRegisterDeviceRequest, ChimePushUnregisterDeviceRequest, PushDeviceConfig,
    PushPlatform,
};
