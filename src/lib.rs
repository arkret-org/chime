#![recursion_limit = "256"]

//! # chime
//!
//! Contrix push notification gateway types, preferences, and device
//! registration helpers.
//!
//! This crate provides the shared data types and logic used by Contrix
//! clients to register push-capable devices with a Contrix Principal Server,
//! Sync Service, or delegated Push Gateway.
//!
//! ## Gateway support
//!
//! | Gateway | Description |
//! |---------|-------------|
//! | **Standard** | Contrix Push Gateway using platform adapters such as FCM, APNs, Web Push, or desktop notification bridges. |
//! | **Bugle** | Contrix Push Gateway with domestic Chinese Android OEM provider support through JPush, Huawei, Xiaomi, OPPO, vivo, HONOR, and HarmonyOS routes. |
//! | **Custom** | User-provided gateway URL. |
//!
//! ## Features
//!
//! - `http` - enables `ContrixPushClient`, a small reqwest-based helper for
//!   `POST /api/v1/push/register-device` and
//!   `POST /api/v1/push/unregister-device`.

use serde::{Deserialize, Serialize};

#[cfg(feature = "notify")]
mod notify;
mod push;
mod state;

#[cfg(feature = "notify")]
pub use notify::{
    ProviderRetryHint, PushDeliveryReceipt, PushHint, PushNotification, PushNotificationDevice,
    PushNotifyPrivacyError, PushNotifyPrivacyMode, PushNotifyPrivacyVector, PushNotifyRequest,
    PushNotifyResponse, RejectedPushToken, shared_push_notify_privacy_vectors,
};

pub use push::{
    CONTENT_DIGEST_HEADER, CONTRIX_ACTOR_DID_HEADER, CONTRIX_AUDIENCE_HEADER,
    CONTRIX_CREATED_AT_HEADER, CONTRIX_DESTINATION_SERVICE_DID_HEADER, CONTRIX_DEVICE_ID_HEADER,
    CONTRIX_EXPIRES_AT_HEADER, CONTRIX_IDEMPOTENCY_KEY_HEADER, CONTRIX_NONCE_HEADER,
    CONTRIX_OPERATION_ID_HEADER, CONTRIX_ORIGIN_HEADER, CONTRIX_ORIGIN_SERVICE_DID_HEADER,
    CONTRIX_REQUEST_ID_HEADER, CONTRIX_SESSION_GRANT_HEADER, ContrixError, ContrixErrorEnvelope,
    IntegrationView, PUSH_BRIDGE_DESCRIBE_PATH, PUSH_INTEGRATION_DESCRIBE_PATH,
    PushBridgeDescribeGatewayDescriptor, PushBridgeDescribeNotifyDescriptor,
    PushBridgeDescribePrivacyDescriptor, PushBridgeDescribeResponse, PushDeviceConfig,
    PushErrorKind, PushGatewayIntegrationDependency, PushGatewayIntegrationDescribeResponse,
    PushGatewayIntegrationSurface, PushPlatform, PushRegistrationError, PushRequestSigningContext,
    PushRequestSigningOptions, REGISTER_DEVICE_PATH, RegisterDeviceRequest, RegisterDeviceResponse,
    SIGNATURE_HEADER, SIGNATURE_INPUT_HEADER, UNREGISTER_DEVICE_PATH, UnregisterDeviceRequest,
    UnregisterDeviceResponse, build_register_device_request, build_register_signing_context,
    build_register_signing_context_with_options, build_unregister_device_request,
    build_unregister_signing_context, build_unregister_signing_context_with_options,
    content_digest_sha256, contrix_api_url, push_bridge_describe_url,
    push_gateway_service_base_url, push_integration_describe_url, redact_push_key,
    validate_push_gateway_url, validate_webpush_endpoint_allowlist,
};
pub use state::{
    BridgeContractCache, BridgeContractDriftVerdict, PUSH_REGISTRATION_STATE_SCHEMA_VERSION,
    PushRegistrationLastError, PushRegistrationRepairPlan, PushRegistrationState,
    PushRegistrationStore, PushTokenRotationPlan, PushTokenRotationStrategy,
    build_registration_state, find_registration_by_token, find_registration_for_device,
    hash_push_key, merge_registration_state, plan_registration_repair, plan_token_rotation,
    plan_token_rotation_with_strategy, token_moved_to_different_device, token_rotation_required,
};

#[cfg(feature = "http")]
pub use push::{ContrixPushClient, ContrixResponse, PushRetryPolicy};

// -- Constants ---------------------------------------------------------------

/// Canonical Contrix operation id for push device registration.
pub const OPERATION_PUSH_REGISTER_DEVICE: &str = "cx.push.register_device";

/// Canonical Contrix operation id for push device unregistration.
pub const OPERATION_PUSH_UNREGISTER_DEVICE: &str = "cx.push.unregister_device";

/// Canonical Contrix operation id for push wakeup delivery.
pub const OPERATION_PUSH_NOTIFY: &str = "cx.push.notify";

/// Default standard Contrix push gateway URL.
///
/// Contrix does not define a single global push gateway. Consumers should set
/// this from service discovery or application configuration before registering.
pub const DEFAULT_CONTRIX_PUSH_GATEWAY_URL: &str = "";

/// Default Bugle push gateway URL using the Contrix push notify binding.
pub const DEFAULT_BUGLE_PUSH_GATEWAY_URL: &str = "https://push.palpo.im/api/v1/push/notify";

// -- PushGatewayType ---------------------------------------------------------

/// Which downstream push gateway to ask the Contrix service to use.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PushGatewayType {
    /// Standard Contrix push gateway using FCM, APNs, Web Push, or desktop
    /// notification adapters.
    #[default]
    Standard,
    /// Bugle push gateway with domestic Chinese Android OEM support.
    ///
    /// Routes through JPush `third_party_channel` to Huawei / Xiaomi / OPPO /
    /// vivo / HONOR / HarmonyOS providers.
    Bugle,
    /// User-provided gateway URL.
    Custom,
}

impl PushGatewayType {
    /// Default push gateway URL for this type.
    pub fn default_url(&self) -> &'static str {
        match self {
            Self::Standard => DEFAULT_CONTRIX_PUSH_GATEWAY_URL,
            Self::Bugle => DEFAULT_BUGLE_PUSH_GATEWAY_URL,
            Self::Custom => DEFAULT_CONTRIX_PUSH_GATEWAY_URL,
        }
    }

    /// Human-readable display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Standard => "Contrix Standard",
            Self::Bugle => "Bugle (China domestic)",
            Self::Custom => "Custom",
        }
    }

    /// Short description of this gateway type.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Standard => {
                "Standard Contrix push via platform adapters such as FCM, APNs, Web Push, or desktop bridges."
            }
            Self::Bugle => {
                "Domestic push for mainland China via JPush, Huawei, Xiaomi, OPPO, vivo, and HONOR providers."
            }
            Self::Custom => "Manually specify the push gateway URL.",
        }
    }

    /// Resolve the app id for a platform and gateway.
    ///
    /// For Android + Bugle, this returns `domestic_app_id` when provided;
    /// otherwise it returns `base_app_id`. Other platforms always use
    /// `base_app_id`.
    pub fn resolve_app_id<'a>(
        &self,
        platform: Option<PushPlatform>,
        base_app_id: Option<&'a str>,
        domestic_app_id: Option<&'a str>,
    ) -> Option<&'a str> {
        match (self, platform) {
            (Self::Bugle, Some(PushPlatform::Android)) => domestic_app_id.or(base_app_id),
            _ => base_app_id,
        }
    }
}

// -- PushPreferences ---------------------------------------------------------

/// Persisted Contrix push notification preferences.
///
/// Serializable to JSON. The file path and persistence strategy are left to
/// the consumer application.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PushPreferences {
    /// Whether push notifications are enabled.
    pub enabled: bool,
    /// The selected downstream push gateway type.
    pub gateway_type: PushGatewayType,
    /// The push gateway URL sent as `push_gateway` during Contrix registration.
    pub push_gateway: String,
    /// Allow non-HTTPS push gateways for loopback development URLs only.
    ///
    /// Production gateway URLs must use HTTPS.
    pub allow_insecure_loopback_push_gateway: bool,
    /// Whether a sender-provided, body-free `push_hint` may be used.
    ///
    /// Contrix push hints are blind wakeup metadata. They must not contain
    /// plaintext message bodies for E2EE Spaces.
    pub allow_push_hint: bool,
    /// Optional allowlist for WebPush endpoint origins.
    ///
    /// When non-empty and the platform is `web`, registration rejects WebPush
    /// endpoints whose origin is not present in this list. Entries may be full
    /// origins such as `https://fcm.googleapis.com` or host patterns such as
    /// `.push.apple.com` / `*.push.services.mozilla.com`.
    #[serde(default)]
    pub webpush_endpoint_allowlist: Vec<String>,
}

impl Default for PushPreferences {
    fn default() -> Self {
        Self {
            enabled: false,
            gateway_type: PushGatewayType::default(),
            push_gateway: DEFAULT_CONTRIX_PUSH_GATEWAY_URL.to_owned(),
            allow_insecure_loopback_push_gateway: false,
            allow_push_hint: true,
            webpush_endpoint_allowlist: Vec::new(),
        }
    }
}

impl PushPreferences {
    /// Resolve the app ID based on the current gateway type and platform.
    pub fn app_id<'a>(
        &self,
        platform: Option<PushPlatform>,
        base: Option<&'a str>,
        domestic: Option<&'a str>,
    ) -> Option<&'a str> {
        self.gateway_type.resolve_app_id(platform, base, domestic)
    }

    /// Update the push gateway URL to the default for the current gateway type,
    /// unless the gateway type is `Custom`.
    pub fn apply_gateway_type_defaults(&mut self) {
        if self.gateway_type != PushGatewayType::Custom {
            self.push_gateway = self.gateway_type.default_url().to_owned();
        }
    }
}

// -- JSON persistence helpers ------------------------------------------------

/// Serialize preferences to a JSON string.
pub fn to_json(prefs: &PushPreferences) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(prefs)
}

/// Deserialize preferences from a JSON string.
///
/// Strict: unknown fields (including legacy gateway-type aliases such as
/// `Sygnal`, legacy field names such as `gateway_url` /
/// `show_message_preview`) cause an error rather than a silent fallback.
/// Callers that want graceful recovery should match on the error and decide
/// what to do — there is no longer a permissive variant.
pub fn from_json(json: &str) -> Result<PushPreferences, serde_json::Error> {
    serde_json::from_str(json)
}

// -- Tests -------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_preferences() {
        let prefs = PushPreferences::default();
        assert!(!prefs.enabled);
        assert_eq!(prefs.gateway_type, PushGatewayType::Standard);
        assert!(prefs.push_gateway.is_empty());
        assert!(!prefs.allow_insecure_loopback_push_gateway);
        assert!(prefs.allow_push_hint);
    }

    #[test]
    fn resolve_app_id_standard() {
        let gw = PushGatewayType::Standard;
        assert_eq!(
            gw.resolve_app_id(
                Some(PushPlatform::Android),
                Some("app.example.android"),
                Some("app.example.android.cn")
            ),
            Some("app.example.android")
        );
    }

    #[test]
    fn resolve_app_id_bugle_android() {
        let gw = PushGatewayType::Bugle;
        assert_eq!(
            gw.resolve_app_id(
                Some(PushPlatform::Android),
                Some("app.example.android"),
                Some("app.example.android.cn")
            ),
            Some("app.example.android.cn")
        );
    }

    #[test]
    fn resolve_app_id_bugle_ios_uses_base() {
        let gw = PushGatewayType::Bugle;
        assert_eq!(
            gw.resolve_app_id(
                Some(PushPlatform::Ios),
                Some("app.example.ios"),
                Some("app.example.android.cn")
            ),
            Some("app.example.ios")
        );
    }

    #[test]
    fn apply_gateway_type_defaults_bugle() {
        let mut prefs = PushPreferences::default();
        prefs.gateway_type = PushGatewayType::Bugle;
        prefs.apply_gateway_type_defaults();
        assert_eq!(prefs.push_gateway, DEFAULT_BUGLE_PUSH_GATEWAY_URL);
    }

    #[test]
    fn apply_gateway_type_defaults_custom_keeps_url() {
        let mut prefs = PushPreferences {
            gateway_type: PushGatewayType::Custom,
            push_gateway: "https://custom.example.com/api/v1/push/notify".to_owned(),
            webpush_endpoint_allowlist: Vec::new(),
            ..Default::default()
        };
        prefs.apply_gateway_type_defaults();
        assert_eq!(
            prefs.push_gateway,
            "https://custom.example.com/api/v1/push/notify"
        );
    }

    #[test]
    fn json_roundtrip() {
        let prefs = PushPreferences {
            enabled: true,
            gateway_type: PushGatewayType::Bugle,
            push_gateway: "https://example.com/api/v1/push/notify".to_owned(),
            allow_insecure_loopback_push_gateway: false,
            allow_push_hint: false,
            webpush_endpoint_allowlist: vec!["https://fcm.googleapis.com".to_owned()],
        };
        let json = to_json(&prefs).unwrap();
        let loaded = from_json(&json).unwrap();
        assert_eq!(loaded.enabled, prefs.enabled);
        assert_eq!(loaded.gateway_type, prefs.gateway_type);
        assert_eq!(loaded.push_gateway, prefs.push_gateway);
        assert_eq!(loaded.allow_push_hint, prefs.allow_push_hint);
        assert_eq!(
            loaded.webpush_endpoint_allowlist,
            prefs.webpush_endpoint_allowlist
        );
    }

    #[test]
    fn from_json_partial_uses_field_defaults() {
        let loaded = from_json(r#"{"enabled":true}"#).unwrap();
        assert!(loaded.enabled);
        assert_eq!(loaded.gateway_type, PushGatewayType::Standard);
        assert!(loaded.push_gateway.is_empty());
        assert!(loaded.allow_push_hint);
    }

    #[test]
    fn from_json_rejects_invalid_payload() {
        assert!(from_json("not valid json").is_err());
    }

    #[test]
    fn from_json_rejects_legacy_aliases_strictly() {
        let loaded = from_json(
            r#"{
                "enabled": true,
                "gateway_type": "Sygnal",
                "gateway_url": "https://legacy.example/push/notify",
                "show_message_preview": false
            }"#,
        );
        assert!(
            loaded.is_err(),
            "legacy aliases must error, not silently default"
        );
    }
}
