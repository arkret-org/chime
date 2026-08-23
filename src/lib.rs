#![recursion_limit = "256"]

//! # chime
//!
//! Arkret push notification gateway types, preferences, and device
//! registration helpers.
//!
//! This crate provides the shared data types and logic used by Arkret
//! clients to register push-capable devices with a Arkret Principal Server,
//! Sync Service, or delegated Push Gateway.
//!
//! ## Gateway support
//!
//! | Gateway | Description |
//! |---------|-------------|
//! | **Standard** | Arkret Push Gateway using platform adapters such as FCM, APNs, Web Push, or desktop notification bridges. |
//! | **Bugle** | Arkret Push Gateway with domestic Chinese Android OEM provider support through JPush, Huawei, Xiaomi, OPPO, vivo, HONOR, and HarmonyOS routes. |
//! | **Custom** | User-provided gateway URL. |
//!
//! ## Features
//!
//! - `http` - enables `ArkretPushClient`, a small reqwest-based helper for `POST
//!   /_arkret/edge/push/register-device` and `POST /_arkret/edge/push/unregister-device`.

use serde::{Deserialize, Serialize};

/// Compile the README's rust code blocks as doc-tests so the public
/// quick-start examples cannot drift away from the actual API.
///
/// `rust,no_run` blocks are compile-checked but not executed (they would
/// require a live service). Plain `rust` blocks are compiled and run.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
mod readme_doctest {}

mod gateway_binding;
mod push;
mod rules;
mod state;

pub use arkret_models_integration::{
    DndPeriod, DndSchedule, DndSettings, PushCondition, PushRule, PushRulesConfig,
};
pub use gateway_binding::GatewayBinding;
#[cfg(feature = "http")]
pub use push::{ArkretHttpOutcome, ArkretPushClient, PushRetryPolicy};
pub use push::{
    ChimePushRegisterDeviceRequest, ChimePushUnregisterDeviceRequest,
    PushBridgeDescribeGatewayDescriptor, PushBridgeDescribeNotifyDescriptor,
    PushBridgeDescribeOutcome, PushBridgeDescribePrivacyDescriptor, PushDeviceConfig,
    PushErrorKind, PushPlatform, PushRegistrationError, build_register_device_request,
    build_unregister_device_request, redact_push_key, validate_push_gateway_url,
    validate_webpush_endpoint_allowlist,
};
pub use rules::{
    NotificationDecision, NotificationEvalContext, NotificationSound, PushRulesRejection,
    evaluate_notification, parse_dnd_settings, parse_push_rules,
};
pub use state::{
    BridgeContractCache, BridgeContractCacheError, BridgeContractDriftVerdict,
    PUSH_REGISTRATION_STATE_SCHEMA_VERSION, PushRegistrationLastError, PushRegistrationState,
    build_registration_state, hash_push_key,
};

// -- PushGatewayType ---------------------------------------------------------

/// Which downstream push gateway to ask the Arkret service to use.
///
/// Stability: `1.0`-stable. New variants are additive; renaming or
/// removing a variant requires a major SemVer bump.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PushGatewayType {
    /// Standard Arkret push gateway using FCM, APNs, Web Push, or desktop
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

/// Persisted Arkret push notification preferences.
///
/// Serializable to JSON. The file path and persistence strategy are left to
/// the consumer application.
///
/// Stability: `1.0`-stable. New optional fields are added with
/// `#[serde(default)]` so old persisted JSON keeps deserializing.
/// Renaming or removing a field requires a major SemVer bump.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PushPreferences {
    /// Whether push notifications are enabled.
    pub enabled: bool,
    /// Allow non-HTTPS push gateways for loopback development URLs only.
    ///
    /// Production gateway URLs must use HTTPS.
    pub allow_insecure_loopback_push_gateway: bool,
    /// Optional allowlist for WebPush endpoint origins.
    ///
    /// When non-empty and the platform is `web`, registration rejects WebPush
    /// endpoints whose origin is not present in this list. Entries may be full
    /// origins such as `https://fcm.googleapis.com` or host patterns such as
    /// `.push.apple.com` / `*.push.services.mozilla.com`.
    #[serde(default)]
    pub webpush_endpoint_allowlist: Vec<String>,
    /// Gateway bindings to register against.
    ///
    /// Each binding carries its own gateway type, URL, and optional
    /// per-binding `push_key` / `app_id` overrides. Every binding is
    /// exercised independently.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gateways: Vec<GatewayBinding>,
}

// -- Tests -------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn to_json(prefs: &PushPreferences) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(prefs)
    }

    fn from_json(json: &str) -> Result<PushPreferences, serde_json::Error> {
        serde_json::from_str(json)
    }

    #[test]
    fn default_preferences() {
        let prefs = PushPreferences::default();
        assert!(!prefs.enabled);
        assert!(prefs.gateways.is_empty());
        assert!(!prefs.allow_insecure_loopback_push_gateway);
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
    fn json_roundtrip() {
        let prefs = PushPreferences {
            enabled: true,
            allow_insecure_loopback_push_gateway: false,
            webpush_endpoint_allowlist: vec!["https://fcm.googleapis.com".to_owned()],
            gateways: vec![GatewayBinding::new(
                PushGatewayType::Bugle,
                "https://example.com/_arkret/edge/push/notify",
            )],
        };
        let json = to_json(&prefs).unwrap();
        let loaded = from_json(&json).unwrap();
        assert_eq!(loaded.enabled, prefs.enabled);
        assert_eq!(loaded.gateways, prefs.gateways);
        assert_eq!(
            loaded.webpush_endpoint_allowlist,
            prefs.webpush_endpoint_allowlist
        );
    }

    #[test]
    fn from_json_partial_uses_field_defaults() {
        let loaded = from_json(r#"{"enabled":true}"#).unwrap();
        assert!(loaded.enabled);
        assert!(loaded.gateways.is_empty());
    }

    #[test]
    fn from_json_rejects_invalid_payload() {
        assert!(from_json("not valid json").is_err());
    }

    #[test]
    fn gateways_round_trip_through_json() {
        let prefs = PushPreferences {
            enabled: true,
            gateways: vec![
                GatewayBinding::new(
                    PushGatewayType::Standard,
                    "https://push-a.example.com/_arkret/edge/push/notify",
                ),
                GatewayBinding::new(
                    PushGatewayType::Bugle,
                    "https://push.palpo.im/_arkret/edge/push/notify",
                )
                .with_push_key("vendor-token-cn-aaaaaaaaaa"),
            ],
            ..Default::default()
        };
        let json = to_json(&prefs).unwrap();
        let loaded = from_json(&json).unwrap();
        assert_eq!(loaded.gateways.len(), 2);
        assert_eq!(loaded.gateways, prefs.gateways);
    }

    #[test]
    fn from_json_rejects_removed_singular_and_aliases_strictly() {
        let loaded = from_json(
            r#"{
                "enabled": true,
                "gateway_type": "standard",
                "push_gateway": "https://old.example/push/notify",
                "show_message_preview": false
            }"#,
        );
        assert!(
            loaded.is_err(),
            "removed singular fields and aliases must error, not silently default"
        );
    }
}
