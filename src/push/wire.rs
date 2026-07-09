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

/// Supported Arkret push platform values.
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
    /// Arkret principal ID that owns this device registration.
    pub principal_id: Option<&'a str>,
    /// Arkret device id, usually a `ck:device:*` typed id.
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
    /// Request id sent as `X-Arkret-Request-Id`.
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

/// Internal builder/config for a `register-device` call.
///
/// **This is NOT a wire body.** The canonical `register-device` request
/// body is [`arkret::PushRegisterDeviceRequestBody`] and is the only thing
/// ever serialized onto the wire — chime derives it from this builder via
/// [`Self::to_sdk_request`]. The transport-only fields carried here
/// (`operation_id`, `principal_id`, `idempotency_key`, `request_id`,
/// `proof`, `previous_token_hash`) ride HTTP headers / the signing context
/// and the URL path, never the body (`push-operations.schema.json` sets
/// `additionalProperties:false` on the canonical body;
/// `service-http-binding.md:211-212`). The `Serialize`/`Deserialize`
/// derives exist only so local-state types such as
/// [`crate::PushTokenRotationPlan`] can persist a pending plan; the
/// resulting JSON is private SDK state, **never** a notify/register wire
/// body. Always route through [`Self::to_sdk_request`] before POSTing.
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
    ) -> Result<arkret::PushRegisterDeviceRequestBody, PushRegistrationError> {
        Ok(arkret::PushRegisterDeviceRequestBody {
            device_id: arkret::DeviceId::new(self.device_id.clone()).map_err(|error| {
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
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ChimePushRegisterDeviceOutcome {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

impl From<arkret::PushRegisterDeviceOutcome> for ChimePushRegisterDeviceOutcome {
    fn from(value: arkret::PushRegisterDeviceOutcome) -> Self {
        Self {
            ok: value.ok,
            registration_id: value.registration_id,
            expires_at: value.expires_at.map(|expires_at| expires_at.to_rfc3339()),
        }
    }
}

/// Internal builder/config for an `unregister-device` call.
///
/// **This is NOT a wire body.** The canonical `unregister-device` request
/// body is [`arkret::PushUnregisterDeviceRequestBody`] and is the only
/// thing serialized onto the wire — chime derives it from this builder via
/// [`Self::to_sdk_request`], which keeps only `{device_id, push_key?,
/// app_id?}`. The remaining fields here (`operation_id`, `principal_id`,
/// `registration_id`, `push_gateway`, `push_key_hash`, `push_key_preview`,
/// `idempotency_key`, `request_id`, `proof`) are correlation / transport
/// metadata that ride HTTP headers, the signing context, or local state —
/// never the body (`push-operations.schema.json` sets
/// `additionalProperties:false`; `service-http-binding.md:211-212`). The
/// `Serialize`/`Deserialize` derives exist only so local-state types such
/// as [`crate::PushTokenRotationPlan`] can persist a pending plan; the
/// resulting JSON is private SDK state, **never** an unregister wire body.
/// Always route through [`Self::to_sdk_request`] before POSTing.
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
    ) -> Result<arkret::PushUnregisterDeviceRequestBody, PushRegistrationError> {
        Ok(arkret::PushUnregisterDeviceRequestBody {
            device_id: arkret::DeviceId::new(self.device_id.clone()).map_err(|error| {
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

impl From<arkret::PushUnregisterDeviceOutcome> for ChimePushUnregisterDeviceOutcome {
    fn from(value: arkret::PushUnregisterDeviceOutcome) -> Self {
        Self {
            ok: value.ok,
            already_removed: false,
            removed_registration_id: None,
            request_id: None,
        }
    }
}

pub type CokretError = arkret::ErrorDetail;
pub type CokretErrorEnvelope = arkret::ErrorEnvelope;

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
            "expires_at": "2026-05-02T00:00:00Z"
        }))
        .unwrap();

        assert!(register.ok);
        assert_eq!(register.registration_id.as_deref(), Some("reg-1"));
        assert_eq!(register.expires_at.as_deref(), Some("2026-05-02T00:00:00Z"));

        serde_json::from_value::<ChimePushRegisterDeviceOutcome>(serde_json::json!({
            "ok": true,
            "registration_id": "reg-1",
            "request_id": "ak:request:123"
        }))
        .expect_err("register outcome must reject non-spec response fields");

        let unregister: ChimePushUnregisterDeviceOutcome =
            serde_json::from_value(serde_json::json!({
                "ok": true,
                "already_removed": true,
                "removed_registration_id": "reg-1",
                "request_id": "ak:request:456"
            }))
            .unwrap();

        assert!(unregister.ok);
        assert!(unregister.already_removed);
        assert_eq!(unregister.removed_registration_id.as_deref(), Some("reg-1"));
        assert_eq!(unregister.request_id.as_deref(), Some("ak:request:456"));
    }
}
