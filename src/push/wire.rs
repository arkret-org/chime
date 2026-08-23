//! Wire DTOs for `ak.edge.push.command.register_device` / `ak.edge.push.command.unregister_device`.
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
    /// Arkret device id, usually a `ak:device:*` typed id.
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
    ///
    /// This is an opaque push-gateway-local string constrained only by
    /// `push-operations.schema.json#/$defs/registration_id`
    /// (`^[A-Za-z0-9._:-]{1,128}$`). It is deliberately **not** a typed-ID:
    /// `pushreg` is not a registered `ak:<kind>`, so values must never be
    /// written with an `ak:` prefix.
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
/// body is [`arkret_models_integration::PushRegisterDeviceRequestBody`] and is the only thing
/// ever serialized onto the wire — chime derives it from this builder via
/// [`Self::to_sdk_request`]. The transport-only fields carried here
/// (`operation_id`, `principal_id`, `idempotency_key`, `request_id`,
/// `proof`) ride HTTP headers and the URL path, never the body
/// (`push-operations.schema.json` sets `additionalProperties:false` on the
/// canonical body; `service-http-binding.md:211-212`). The
/// `Serialize`/`Deserialize` derives exist only so hosts can persist a
/// pending request body; the resulting JSON is private SDK state, **never**
/// a notify/register wire body. Always route through
/// [`Self::to_sdk_request`] before POSTing.
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
            .field("proof", &self.proof.as_ref().map(|_| "<present>"))
            .finish()
    }
}

impl ChimePushRegisterDeviceRequest {
    pub fn to_sdk_request(
        &self,
    ) -> Result<arkret_models_integration::PushRegisterDeviceRequestBody, PushRegistrationError>
    {
        Ok(arkret_models_integration::PushRegisterDeviceRequestBody {
            device_id: arkret_wire::DeviceId::new(self.device_id.clone()).map_err(|error| {
                PushRegistrationError::InvalidField {
                    field: "device_id",
                    reason: error.to_string(),
                }
            })?,
            push_gateway: self.push_gateway.clone(),
            push_key: arkret_models_integration::PushKey::new(self.push_key.clone()).map_err(
                |error| PushRegistrationError::InvalidField {
                    field: "push_key",
                    reason: error.to_string(),
                },
            )?,
            platform: self.platform.clone(),
            app_id: self.app_id.clone(),
            display_name: self.display_name.clone(),
            recipient_service_id: None,
        })
    }
}

/// Canonical response body for `POST /_arkret/edge/push/register-device`.
pub type ChimePushRegisterDeviceOutcome = arkret_models_integration::PushRegisterDeviceOutcome;

/// Internal builder/config for an `unregister-device` call.
///
/// **This is NOT a wire body.** The canonical `unregister-device` request
/// body is [`arkret_models_integration::PushUnregisterDeviceRequestBody`] and is the only
/// thing serialized onto the wire — chime derives it from this builder via
/// [`Self::to_sdk_request`], which keeps only `{device_id, push_key?,
/// app_id?}`. The remaining fields here (`operation_id`, `principal_id`,
/// `registration_id`, `push_gateway`, `push_key_hash`, `push_key_preview`,
/// `idempotency_key`, `request_id`, `proof`) are correlation / transport
/// metadata that ride HTTP headers or local state — never the body
/// (`push-operations.schema.json` sets `additionalProperties:false`;
/// `service-http-binding.md:211-212`). The `Serialize`/`Deserialize`
/// derives exist only so hosts can persist a pending request body; the
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
    /// Opaque push-gateway-local registration id, not a typed-ID; see
    /// [`PushDeviceConfig::registration_id`].
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
    ) -> Result<arkret_models_integration::PushUnregisterDeviceRequestBody, PushRegistrationError>
    {
        Ok(arkret_models_integration::PushUnregisterDeviceRequestBody {
            device_id: arkret_wire::DeviceId::new(self.device_id.clone()).map_err(|error| {
                PushRegistrationError::InvalidField {
                    field: "device_id",
                    reason: error.to_string(),
                }
            })?,
            push_key: self
                .push_key
                .as_ref()
                .map(|push_key| {
                    arkret_models_integration::PushKey::new(push_key.clone()).map_err(|error| {
                        PushRegistrationError::InvalidField {
                            field: "push_key",
                            reason: error.to_string(),
                        }
                    })
                })
                .transpose()?,
            app_id: self.app_id.clone(),
        })
    }
}

/// Canonical response body for `POST /_arkret/edge/push/unregister-device`.
pub type ChimePushUnregisterDeviceOutcome = arkret_models_integration::PushUnregisterDeviceOutcome;

pub type ArkretError = arkret_wire::ErrorDetail;
pub type ArkretErrorEnvelope = arkret_wire::ErrorEnvelope;

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
            "push_target_id": "ak:pseudonym:push:ABCDEFGHIJKLMNOPQRSTUV",
            "registration_id": "reg-1",
            "expires_at": "2026-05-02T00:00:00.000Z"
        }))
        .unwrap();

        assert!(register.ok);
        assert_eq!(
            register.push_target_id,
            "ak:pseudonym:push:ABCDEFGHIJKLMNOPQRSTUV"
        );
        assert_eq!(register.registration_id.as_deref(), Some("reg-1"));
        assert_eq!(
            register
                .expires_at
                .map(arkret_canonical::format_timestamp_canonical),
            Some("2026-05-02T00:00:00.000Z".to_owned())
        );

        serde_json::from_value::<ChimePushRegisterDeviceOutcome>(serde_json::json!({
            "ok": true,
            "registration_id": "reg-1",
            "request_id": "ak:request:01904100-0000-7000-8000-000000000030"
        }))
        .expect_err("register outcome must reject non-spec response fields");

        serde_json::from_value::<ChimePushUnregisterDeviceOutcome>(serde_json::json!({
            "ok": true,
            "already_removed": true
        }))
        .expect_err("closed unregister outcome rejects product-local fields");
    }
}
