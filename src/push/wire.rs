//! Wire DTOs for `ck.edge.push.command.register_device` / `ck.edge.push.command.unregister_device`.
//!
//! ## Stability
//!
//! The local `1.0.0` wire shape evolves additively. The SDK leans on
//! `#[non_exhaustive]` + `#[derive(Default)]` for request/response types so
//! adding optional fields never breaks downstream construction. Use
//! `..Default::default()` when building these types in external crates.
//! Renames and removals require a major SemVer bump.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::errors::PushRegistrationError;
use super::urls::{redact_push_key, redact_url};

/// Supported Cokret push platform values.
///
/// Stability: `1.0`-stable. New variants are additive; renaming or
/// removing a variant requires a major SemVer bump.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PushPlatform {
    Android,
    Ios,
    Web,
    Desktop,
}

impl PushPlatform {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Android => "android",
            Self::Ios => "ios",
            Self::Web => "web",
            Self::Desktop => "desktop",
        }
    }
}

impl TryFrom<&str> for PushPlatform {
    type Error = PushRegistrationError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.to_ascii_lowercase().as_str() {
            "android" => Ok(Self::Android),
            "ios" => Ok(Self::Ios),
            "web" => Ok(Self::Web),
            "desktop" => Ok(Self::Desktop),
            other => Err(PushRegistrationError::InvalidPlatform(other.to_owned())),
        }
    }
}

/// Device configuration supplied by the host app.
///
/// Stability: `1.0`-stable. The struct is borrowed (every field is
/// `Option<&'a str>` or `&'a str`) so adding a new optional field is
/// always source-compatible. Renaming or removing fields requires a
/// major SemVer bump.
#[derive(Clone, Copy)]
pub struct PushDeviceConfig<'a> {
    /// Cokret principal ID that owns this device registration.
    pub principal_id: Option<&'a str>,
    /// Cokret device id, usually a DID fragment such as
    /// `did:web:alice.example#device-phone`.
    pub device_id: &'a str,
    /// Platform push token, e.g. `fcm:...`, `apns:...`, `webpush:...`.
    pub push_key: Option<&'a str>,
    /// Optional platform value: `android`, `ios`, `web`, or `desktop`.
    pub platform: Option<&'a str>,
    /// Application package name, bundle id, web app id, or desktop app id.
    pub app_id: Option<&'a str>,
    /// Domestic Android app id used when `PushGatewayType::Bugle` is selected.
    pub domestic_app_id: Option<&'a str>,
    /// Server-assigned registration id, when known.
    pub registration_id: Option<&'a str>,
    /// User-readable device name.
    pub display_name: Option<&'a str>,
    /// Idempotency key sent both as request metadata and, for services that
    /// persist it, as an optional request body field.
    pub idempotency_key: Option<&'a str>,
    /// Request id sent as `X-Cokret-Request-Id`.
    pub request_id: Option<&'a str>,
    /// Optional caller-supplied DID proof or canonical proof body.
    ///
    /// `chime` does not sign this proof; it only carries the already-built
    /// proof through the wire model.
    pub proof: Option<&'a Value>,
}

impl fmt::Debug for PushDeviceConfig<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PushDeviceConfig")
            .field("principal_id", &self.principal_id)
            .field("device_id", &self.device_id)
            .field("push_key", &self.push_key.map(redact_push_key))
            .field("platform", &self.platform)
            .field("app_id", &self.app_id)
            .field("domestic_app_id", &self.domestic_app_id)
            .field("registration_id", &self.registration_id)
            .field("display_name", &self.display_name)
            .field("idempotency_key", &self.idempotency_key)
            .field("request_id", &self.request_id)
            .field("proof", &self.proof.map(|_| "<present>"))
            .finish()
    }
}

/// Request body for `POST /_cokret/edge/push/register-device`.
///
/// Stability: 1.0-stable + `#[non_exhaustive]`. Build via
/// `ChimePushRegisterDeviceRequest { ..Default::default() }` from external crates so
/// future field additions stay source-compatible.
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ChimePushRegisterDeviceRequest {
    pub operation_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,
    pub device_id: String,
    pub push_gateway: String,
    pub push_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// SHA-256 fingerprint of the previously registered push token, set by
    /// token-rotation strands so the gateway can correlate the new registration
    /// with the old one and reclaim it server-side.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_token_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Value>,
}

impl fmt::Debug for ChimePushRegisterDeviceRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChimePushRegisterDeviceRequest")
            .field("operation_id", &self.operation_id)
            .field("principal_id", &self.principal_id)
            .field("device_id", &self.device_id)
            .field("push_gateway", &redact_url(&self.push_gateway))
            .field("push_key", &redact_push_key(&self.push_key))
            .field("platform", &self.platform)
            .field("app_id", &self.app_id)
            .field("display_name", &self.display_name)
            .field("idempotency_key", &self.idempotency_key)
            .field("request_id", &self.request_id)
            .field("previous_token_hash", &self.previous_token_hash)
            .field("proof", &self.proof.as_ref().map(|_| "<present>"))
            .finish()
    }
}

impl ChimePushRegisterDeviceRequest {
    pub fn to_sdk_request(
        &self,
    ) -> Result<cokret::PushRegisterDeviceRequestBody, PushRegistrationError> {
        Ok(cokret::PushRegisterDeviceRequestBody {
            device_id: cokret::DeviceId::new(self.device_id.clone()).map_err(|error| {
                PushRegistrationError::InvalidField {
                    field: "device_id",
                    reason: error.to_string(),
                }
            })?,
            push_gateway: self.push_gateway.clone(),
            push_key: self.push_key.clone(),
            platform: self.platform.clone(),
            app_id: self.app_id.clone(),
            display_name: self.display_name.clone(),
            recipient_service_did: None,
        })
    }
}

/// Response body for `POST /_cokret/edge/push/register-device`.
///
/// Stability: 1.0-stable. New optional fields may be added in a minor release.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ChimePushRegisterDeviceOutcome {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted_gateway: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_key_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_key_preview: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

impl From<cokret::PushRegisterDeviceOutcome> for ChimePushRegisterDeviceOutcome {
    fn from(value: cokret::PushRegisterDeviceOutcome) -> Self {
        Self {
            ok: value.ok,
            registration_id: value.registration_id,
            accepted_gateway: None,
            push_key_hash: None,
            push_key_preview: None,
            expires_at: value.expires_at.map(|expires_at| expires_at.to_rfc3339()),
            refresh_hint: None,
            warnings: Vec::new(),
            request_id: None,
        }
    }
}

/// Request body for `POST /_cokret/edge/push/unregister-device`.
///
/// Stability: 1.0-stable + `#[non_exhaustive]`. Build via
/// `ChimePushUnregisterDeviceRequest { ..Default::default() }` from external crates.
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ChimePushUnregisterDeviceRequest {
    pub operation_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,
    pub device_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_gateway: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_key_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_key_preview: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Value>,
}

impl fmt::Debug for ChimePushUnregisterDeviceRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChimePushUnregisterDeviceRequest")
            .field("operation_id", &self.operation_id)
            .field("principal_id", &self.principal_id)
            .field("device_id", &self.device_id)
            .field("registration_id", &self.registration_id)
            .field(
                "push_gateway",
                &self.push_gateway.as_deref().map(redact_url),
            )
            .field("push_key", &self.push_key.as_deref().map(redact_push_key))
            .field("push_key_hash", &self.push_key_hash)
            .field("push_key_preview", &self.push_key_preview)
            .field("app_id", &self.app_id)
            .field("idempotency_key", &self.idempotency_key)
            .field("request_id", &self.request_id)
            .field("proof", &self.proof.as_ref().map(|_| "<present>"))
            .finish()
    }
}

impl ChimePushUnregisterDeviceRequest {
    pub fn to_sdk_request(
        &self,
    ) -> Result<cokret::PushUnregisterDeviceRequestBody, PushRegistrationError> {
        Ok(cokret::PushUnregisterDeviceRequestBody {
            device_id: cokret::DeviceId::new(self.device_id.clone()).map_err(|error| {
                PushRegistrationError::InvalidField {
                    field: "device_id",
                    reason: error.to_string(),
                }
            })?,
            push_key: self.push_key.clone(),
            app_id: self.app_id.clone(),
        })
    }
}

/// Response body for `POST /_cokret/edge/push/unregister-device`.
///
/// Stability: 1.0-stable. New optional fields may be added in a minor release.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ChimePushUnregisterDeviceOutcome {
    pub ok: bool,
    #[serde(default)]
    pub already_removed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub removed_registration_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

impl From<cokret::PushUnregisterDeviceOutcome> for ChimePushUnregisterDeviceOutcome {
    fn from(value: cokret::PushUnregisterDeviceOutcome) -> Self {
        Self {
            ok: value.ok,
            already_removed: false,
            removed_registration_id: None,
            request_id: None,
        }
    }
}

/// Cokret standard error object.
///
/// Stability: 1.0-stable + `#[non_exhaustive]`. Server-controlled shape.
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CokretError {
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

impl fmt::Debug for CokretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CokretError")
            .field("code", &self.code)
            .field("message", &"<redacted>")
            .field("retry_after_ms", &self.retry_after_ms)
            .field("details_present", &self.details.is_some())
            .finish()
    }
}

/// Cokret standard error envelope.
///
/// Stability: 1.0-stable. Server-controlled response shape, so additional
/// fields may appear in a minor release.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CokretErrorEnvelope {
    pub ok: bool,
    pub error: CokretError,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

impl fmt::Debug for CokretErrorEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CokretErrorEnvelope")
            .field("ok", &self.ok)
            .field("error", &self.error)
            .field("request_id", &self.request_id)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::push::errors::PushErrorKind;

    #[test]
    fn rejects_unknown_platform() {
        let err = PushPlatform::try_from("wearable").unwrap_err();
        assert_eq!(err.kind(), PushErrorKind::InvalidPlatform);
    }

    #[test]
    fn supports_web_and_desktop_platforms() {
        assert_eq!(PushPlatform::try_from("web").unwrap(), PushPlatform::Web);
        assert_eq!(
            PushPlatform::try_from("desktop").unwrap(),
            PushPlatform::Desktop
        );
    }

    #[test]
    fn response_models_cover_frozen_wire_metadata() {
        let register: ChimePushRegisterDeviceOutcome = serde_json::from_value(serde_json::json!({
            "ok": true,
            "registration_id": "reg-1",
            "accepted_gateway": "https://push.example.com/_cokret/edge/push/notify",
            "push_key_hash": "sha256:abc",
            "push_key_preview": "fcm:<redacted,len=17>",
            "expires_at": "2026-05-02T00:00:00Z",
            "refresh_hint": "rotate_before_expiry",
            "warnings": ["duplicate-safe"],
            "request_id": "ck:request:123"
        }))
        .unwrap();

        assert!(register.ok);
        assert_eq!(
            register.accepted_gateway.as_deref(),
            Some("https://push.example.com/_cokret/edge/push/notify")
        );
        assert_eq!(register.push_key_hash.as_deref(), Some("sha256:abc"));
        assert_eq!(
            register.push_key_preview.as_deref(),
            Some("fcm:<redacted,len=17>")
        );
        assert_eq!(
            register.refresh_hint.as_deref(),
            Some("rotate_before_expiry")
        );
        assert_eq!(register.warnings, vec!["duplicate-safe"]);
        assert_eq!(register.request_id.as_deref(), Some("ck:request:123"));

        let unregister: ChimePushUnregisterDeviceOutcome =
            serde_json::from_value(serde_json::json!({
                "ok": true,
                "already_removed": true,
                "removed_registration_id": "reg-1",
                "request_id": "ck:request:456"
            }))
            .unwrap();

        assert!(unregister.ok);
        assert!(unregister.already_removed);
        assert_eq!(unregister.removed_registration_id.as_deref(), Some("reg-1"));
        assert_eq!(unregister.request_id.as_deref(), Some("ck:request:456"));
    }
}
