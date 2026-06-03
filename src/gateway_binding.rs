//! Multi-gateway binding: one host application can target several push
//! gateways (Standard FCM/APNs + Bugle for China devices, for example)
//! by listing them as [`GatewayBinding`] entries in
//! [`PushPreferences::gateways`](crate::PushPreferences::gateways).
//!
//! Every binding is exercised independently (independent token,
//! independent app_id, independent register/unregister fault tolerance).

use serde::{Deserialize, Serialize};

use crate::{PushGatewayType, PushPlatform};

/// Binding of a single push gateway target.
///
/// Stability: `1.0`-stable. New optional fields are added with
/// `#[serde(default)]` so older persisted JSON keeps deserializing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayBinding {
    /// Which downstream push gateway type to ask the Cokret service
    /// to use for this binding.
    pub gateway_type: PushGatewayType,
    /// Push gateway URL sent as `push_gateway` during registration.
    /// Must be HTTPS unless the host application opts in to loopback
    /// dev URLs (see
    /// [`PushPreferences::allow_insecure_loopback_push_gateway`](crate::PushPreferences::allow_insecure_loopback_push_gateway)).
    pub push_gateway: String,
    /// Optional override for the platform push token bound to this
    /// gateway. Useful when one device exposes distinct tokens to
    /// different gateway types (e.g. FCM token to Standard, vendor
    /// token to Bugle). When `None`, the caller-supplied `push_key`
    /// from [`PushDeviceConfig`](crate::PushDeviceConfig) is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_key: Option<String>,
    /// Optional override for the application id. When `None`, the
    /// caller-supplied `app_id` (or `domestic_app_id` for Bugle on
    /// Android) from `PushDeviceConfig` is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
}

impl GatewayBinding {
    /// Construct a binding with default-empty overrides.
    pub fn new(gateway_type: PushGatewayType, push_gateway: impl Into<String>) -> Self {
        Self {
            gateway_type,
            push_gateway: push_gateway.into(),
            push_key: None,
            app_id: None,
        }
    }

    /// Attach a per-binding push token override.
    pub fn with_push_key(mut self, push_key: impl Into<String>) -> Self {
        self.push_key = Some(push_key.into());
        self
    }

    /// Attach a per-binding app id override.
    pub fn with_app_id(mut self, app_id: impl Into<String>) -> Self {
        self.app_id = Some(app_id.into());
        self
    }

    /// Resolve the app id for this binding, honouring per-binding override
    /// over the caller-supplied base / domestic pair.
    ///
    /// When `app_id` is set on the binding it wins; otherwise the
    /// gateway-type's resolution kicks in
    /// (Bugle + Android prefers `domestic_app_id`).
    pub fn resolve_app_id<'a>(
        &'a self,
        platform: Option<PushPlatform>,
        base_app_id: Option<&'a str>,
        domestic_app_id: Option<&'a str>,
    ) -> Option<&'a str> {
        if let Some(override_value) = self.app_id.as_deref() {
            return Some(override_value);
        }
        self.gateway_type
            .resolve_app_id(platform, base_app_id, domestic_app_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_round_trips_through_json_with_defaults_omitted() {
        let binding = GatewayBinding::new(
            PushGatewayType::Standard,
            "https://push.example.com/api/v1/push/notify",
        );
        let json = serde_json::to_string(&binding).unwrap();
        // Optional fields skip when None.
        assert!(!json.contains("push_key"));
        assert!(!json.contains("app_id"));
        let back: GatewayBinding = serde_json::from_str(&json).unwrap();
        assert_eq!(back, binding);
    }

    #[test]
    fn binding_with_overrides_serializes_overrides() {
        let binding = GatewayBinding::new(
            PushGatewayType::Bugle,
            "https://push.palpo.im/api/v1/push/notify",
        )
        .with_push_key("vendor-token-cn-aaaaaaaaaa")
        .with_app_id("app.example.android.cn");

        let json = serde_json::to_string(&binding).unwrap();
        assert!(json.contains("vendor-token-cn"));
        assert!(json.contains("app.example.android.cn"));
        let back: GatewayBinding = serde_json::from_str(&json).unwrap();
        assert_eq!(back, binding);
    }

    #[test]
    fn binding_rejects_unknown_fields() {
        let bad = serde_json::from_str::<GatewayBinding>(
            r#"{
                "gateway_type": "standard",
                "push_gateway": "https://x/api/v1/push/notify",
                "extra_typo": "oops"
            }"#,
        );
        assert!(bad.is_err());
    }

    #[test]
    fn resolve_app_id_prefers_binding_override() {
        let binding = GatewayBinding::new(
            PushGatewayType::Bugle,
            "https://push.palpo.im/api/v1/push/notify",
        )
        .with_app_id("app.binding.override");
        assert_eq!(
            binding.resolve_app_id(
                Some(PushPlatform::Android),
                Some("app.example.android"),
                Some("app.example.android.cn"),
            ),
            Some("app.binding.override")
        );
    }

    #[test]
    fn resolve_app_id_falls_back_to_gateway_resolution() {
        let binding = GatewayBinding::new(
            PushGatewayType::Bugle,
            "https://push.palpo.im/api/v1/push/notify",
        );
        assert_eq!(
            binding.resolve_app_id(
                Some(PushPlatform::Android),
                Some("app.example.android"),
                Some("app.example.android.cn"),
            ),
            Some("app.example.android.cn")
        );
    }
}
