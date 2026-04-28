#![recursion_limit = "256"]

//! # chime
//!
//! Matrix push notification gateway types, preferences, and pusher registration.
//!
//! This crate provides the shared data types and logic used by Matrix clients
//! (such as Synpad and Robrix) to configure and register push notification
//! gateways with a Matrix homeserver.
//!
//! ## Gateway support
//!
//! | Gateway | Description |
//! |---------|-------------|
//! | **Sygnal** | Standard Matrix push gateway using FCM (Android) and APNs (iOS). |
//! | **Bugle** | Push gateway with domestic Chinese Android OEM provider support — routes through JPush `third_party_channel` to Huawei, Xiaomi, OPPO, vivo, HONOR, and HarmonyOS providers. Ideal for mainland China where FCM is unavailable. |
//! | **Custom** | User-provided gateway URL. |
//!
//! ## Features
//!
//! - `matrix` — enables `register_pusher` and `unregister_pusher` functions
//!   that use `matrix_sdk::Client` to talk to a Matrix homeserver.

use serde::{Deserialize, Serialize};

// ── Constants ────────────────────────────────────────────────────────────

/// Default Sygnal push gateway URL (official Matrix.org instance).
pub const DEFAULT_SYGNAL_GATEWAY_URL: &str = "https://matrix.org/_matrix/push/v1/notify";

/// Default Bugle push gateway URL (domestic China push).
pub const DEFAULT_BUGLE_GATEWAY_URL: &str = "https://push.palpo.im/_matrix/push/v1/notify";

// ── PushGatewayType ──────────────────────────────────────────────────────

/// Which push gateway to use.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PushGatewayType {
    /// Standard Matrix push gateway using FCM (Android) and APNs (iOS).
    #[default]
    Sygnal,
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
            Self::Sygnal => DEFAULT_SYGNAL_GATEWAY_URL,
            Self::Bugle => DEFAULT_BUGLE_GATEWAY_URL,
            Self::Custom => DEFAULT_SYGNAL_GATEWAY_URL,
        }
    }

    /// Human-readable display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Sygnal => "Sygnal (FCM / APNs)",
            Self::Bugle => "Bugle (China domestic)",
            Self::Custom => "Custom",
        }
    }

    /// Short description of this gateway type.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Sygnal => {
                "Standard push via Firebase Cloud Messaging (Android) and Apple Push Notification service (iOS)."
            }
            Self::Bugle => {
                "Domestic push for mainland China via JPush, Huawei, Xiaomi, OPPO, vivo, and HONOR providers."
            }
            Self::Custom => "Manually specify the push gateway URL.",
        }
    }

    /// Returns the domestic app ID when using Bugle, otherwise the base app ID.
    pub fn resolve_android_app_id<'a>(
        &self,
        base_app_id: &'a str,
        domestic_app_id: &'a str,
    ) -> &'a str {
        match self {
            Self::Bugle => domestic_app_id,
            Self::Sygnal | Self::Custom => base_app_id,
        }
    }
}

// ── PushPreferences ──────────────────────────────────────────────────────

/// Persisted push notification preferences.
///
/// Serializable to JSON.  The file path and persistence strategy are left
/// to the consumer application.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct PushPreferences {
    /// Whether push notifications are enabled.
    pub enabled: bool,
    /// The selected push gateway type.
    pub gateway_type: PushGatewayType,
    /// The push gateway URL.
    pub gateway_url: String,
    /// Whether to show message body in push notifications (privacy).
    pub show_message_preview: bool,
}

impl Default for PushPreferences {
    fn default() -> Self {
        Self {
            enabled: false,
            gateway_type: PushGatewayType::default(),
            gateway_url: DEFAULT_SYGNAL_GATEWAY_URL.to_owned(),
            show_message_preview: true,
        }
    }
}

impl PushPreferences {
    /// Resolve the Android app ID based on the current gateway type.
    pub fn android_app_id<'a>(&self, base: &'a str, domestic: &'a str) -> &'a str {
        self.gateway_type.resolve_android_app_id(base, domestic)
    }

    /// Update the gateway URL to the default for the current gateway type,
    /// unless the gateway type is `Custom`.
    pub fn apply_gateway_type_defaults(&mut self) {
        if self.gateway_type != PushGatewayType::Custom {
            self.gateway_url = self.gateway_type.default_url().to_owned();
        }
    }
}

// ── JSON persistence helpers ─────────────────────────────────────────────

/// Serialize preferences to a JSON string.
pub fn to_json(prefs: &PushPreferences) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(prefs)
}

/// Deserialize preferences from a JSON string, with fallback to defaults.
pub fn from_json(json: &str) -> PushPreferences {
    serde_json::from_str(json).unwrap_or_default()
}

// ── Pusher registration (requires `matrix` feature) ──────────────────────

#[cfg(feature = "matrix")]
mod pusher;
#[cfg(feature = "matrix")]
pub use pusher::{PusherConfig, PusherRegistrationError, register_pusher, unregister_pusher};

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_preferences() {
        let prefs = PushPreferences::default();
        assert!(!prefs.enabled);
        assert_eq!(prefs.gateway_type, PushGatewayType::Sygnal);
        assert_eq!(prefs.gateway_url, DEFAULT_SYGNAL_GATEWAY_URL);
        assert!(prefs.show_message_preview);
    }

    #[test]
    fn resolve_android_app_id_sygnal() {
        let gw = PushGatewayType::Sygnal;
        assert_eq!(gw.resolve_android_app_id("a.b", "a.b.cn"), "a.b");
    }

    #[test]
    fn resolve_android_app_id_bugle() {
        let gw = PushGatewayType::Bugle;
        assert_eq!(gw.resolve_android_app_id("a.b", "a.b.cn"), "a.b.cn");
    }

    #[test]
    fn apply_gateway_type_defaults_bugle() {
        let mut prefs = PushPreferences::default();
        prefs.gateway_type = PushGatewayType::Bugle;
        prefs.apply_gateway_type_defaults();
        assert_eq!(prefs.gateway_url, DEFAULT_BUGLE_GATEWAY_URL);
    }

    #[test]
    fn apply_gateway_type_defaults_custom_keeps_url() {
        let mut prefs = PushPreferences {
            gateway_type: PushGatewayType::Custom,
            gateway_url: "https://custom.example.com/push".to_owned(),
            ..Default::default()
        };
        prefs.apply_gateway_type_defaults();
        assert_eq!(prefs.gateway_url, "https://custom.example.com/push");
    }

    #[test]
    fn json_roundtrip() {
        let prefs = PushPreferences {
            enabled: true,
            gateway_type: PushGatewayType::Bugle,
            gateway_url: "https://example.com/push".to_owned(),
            show_message_preview: false,
        };
        let json = to_json(&prefs).unwrap();
        let loaded = from_json(&json);
        assert_eq!(loaded.enabled, prefs.enabled);
        assert_eq!(loaded.gateway_type, prefs.gateway_type);
        assert_eq!(loaded.gateway_url, prefs.gateway_url);
        assert_eq!(loaded.show_message_preview, prefs.show_message_preview);
    }

    #[test]
    fn from_json_invalid_returns_default() {
        let loaded = from_json("not valid json");
        assert_eq!(loaded.gateway_type, PushGatewayType::Sygnal);
    }

    #[test]
    fn from_json_partial_uses_field_defaults() {
        let loaded = from_json(r#"{"enabled":true}"#);
        assert!(loaded.enabled);
        assert_eq!(loaded.gateway_type, PushGatewayType::Sygnal);
        assert_eq!(loaded.gateway_url, DEFAULT_SYGNAL_GATEWAY_URL);
        assert!(loaded.show_message_preview);
    }
}
