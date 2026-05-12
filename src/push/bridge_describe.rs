//! Bridge describe + integration describe response DTOs.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

fn list_contains_ignore_ascii_case(haystack: &[String], needle: &str) -> bool {
    haystack
        .iter()
        .any(|entry| entry.eq_ignore_ascii_case(needle))
}

/// Response body for `GET /api/v1/push/bridge/describe`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushBridgeDescribeResponse {
    pub contract: String,
    pub version: String,
    pub api_base_path: String,
    pub gateway: PushBridgeDescribeGatewayDescriptor,
    pub notify: PushBridgeDescribeNotifyDescriptor,
    pub privacy: PushBridgeDescribePrivacyDescriptor,
    #[serde(default)]
    pub examples: PushBridgeDescribeExamples,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_capabilities_version: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provider_capabilities: Vec<ProviderCapabilityDescriptor>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub todos: Vec<String>,
}

impl PushBridgeDescribeResponse {
    /// Look up a per-app provider capability descriptor by configured app
    /// name (case-insensitive). Returns `None` when the bridge response
    /// did not carry the per-provider matrix or no entry matches.
    pub fn provider_capability(&self, name: &str) -> Option<&ProviderCapabilityDescriptor> {
        self.provider_capabilities
            .iter()
            .find(|cap| cap.name.eq_ignore_ascii_case(name))
    }

    /// Look up the first capability descriptor whose stable provider
    /// `kind` matches (case-insensitive). Useful when callers care
    /// about the upstream vendor (e.g. `"fcm"`) rather than the
    /// app-name registration.
    pub fn provider_capability_by_kind(&self, kind: &str) -> Option<&ProviderCapabilityDescriptor> {
        self.provider_capabilities
            .iter()
            .find(|cap| cap.kind.eq_ignore_ascii_case(kind))
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushBridgeDescribeGatewayDescriptor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_did: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_profiles: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_providers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub auth_modes: Vec<String>,
}

impl PushBridgeDescribeGatewayDescriptor {
    /// Whether this gateway advertises support for `name` as a push profile
    /// (case-insensitive). Profiles are wire-shape names like `"fcm"`,
    /// `"apns"`, `"webpush"`, `"jpush"`.
    pub fn supports_profile(&self, name: &str) -> bool {
        list_contains_ignore_ascii_case(&self.supported_profiles, name)
    }

    /// Whether this gateway advertises support for `name` as a downstream
    /// provider (case-insensitive). Providers are concrete vendors like
    /// `"huawei"`, `"xiaomi"`.
    pub fn supports_provider(&self, name: &str) -> bool {
        list_contains_ignore_ascii_case(&self.supported_providers, name)
    }

    /// Whether the gateway will accept the requested auth mode such as
    /// `"http-message-signature"` or `"bearer"`.
    pub fn supports_auth_mode(&self, name: &str) -> bool {
        list_contains_ignore_ascii_case(&self.auth_modes, name)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushBridgeDescribeNotifyDescriptor {
    pub notify_path: String,
    pub operation_id: String,
    pub request_id_header: String,
    pub idempotency_key_header: String,
    pub origin_service_did_header: String,
    pub destination_service_did_header: String,
    pub max_request_size_bytes: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dedup_backend: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dedup_ttl_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit_window_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rate_limit_scopes: Vec<String>,
}

impl PushBridgeDescribeNotifyDescriptor {
    /// Whether the gateway has any deduplication backend configured.
    pub fn supports_dedup(&self) -> bool {
        self.dedup_backend
            .as_deref()
            .is_some_and(|backend| !backend.trim().is_empty())
    }

    /// Deduplication retention window, when advertised.
    pub fn dedup_window(&self) -> Option<Duration> {
        self.dedup_ttl_seconds.map(Duration::from_secs)
    }

    /// Rate-limit window length, when advertised.
    pub fn rate_limit_window(&self) -> Option<Duration> {
        self.rate_limit_window_seconds.map(Duration::from_secs)
    }

    /// Whether the gateway advertises the named rate-limit scope (e.g.
    /// `"per-app"`, `"per-actor"`).
    pub fn rate_limits_by(&self, scope: &str) -> bool {
        list_contains_ignore_ascii_case(&self.rate_limit_scopes, scope)
    }

    /// Maximum request size in bytes, exposed as `usize` for convenience.
    pub fn max_request_size(&self) -> usize {
        self.max_request_size_bytes
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushBridgeDescribePrivacyDescriptor {
    pub default_mode: String,
    pub plaintext_visibility_class: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub active_reference_fields: Vec<String>,
}

/// Per-app frozen capability matrix entry, surfaced by the gateway via
/// `bridge/describe.provider_capabilities[]`.
///
/// Mirrors floria's `ProviderCapabilityDescriptor` wire shape (the
/// upstream serializes `ProviderCapabilities` flattened under a `name`
/// field). Contract version travels separately on
/// [`PushBridgeDescribeResponse::provider_capabilities_version`] and
/// matches `floria::pushkin::PROVIDER_CAPABILITIES_VERSION`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderCapabilityDescriptor {
    /// Configured app name as known to the gateway registry.
    pub name: String,
    /// Stable provider kind, e.g. `"apns"`, `"fcm"`, `"webpush"`.
    pub kind: String,
    /// Multi-recipient send shape: `"none"`, `"multicast"`, or `"topic"`.
    pub batch: String,
    /// Maximum TTL in seconds the upstream provider accepts, or `null`
    /// when the provider does not document a hard cap.
    #[serde(default)]
    pub ttl_seconds_max: Option<u64>,
    /// Whether the provider supports a collapse / replace key.
    #[serde(default)]
    pub supports_collapse: bool,
    /// Whether the provider has first-class badge / unread count support.
    #[serde(default)]
    pub supports_badge: bool,
    /// Default outbound payload shape — informs blind-wakeup vs.
    /// service-visible plaintext defaults.
    pub default_payload_shape: String,
    /// Credential material this provider expects.
    #[serde(default)]
    pub credential_kinds: Vec<String>,
    /// Documented credential rotation cadence for this provider kind.
    pub credential_rotation: String,
    /// Whether the provider can carry an encrypted body that the
    /// gateway must NOT inspect (controls plaintext-policy gating).
    #[serde(default)]
    pub blind_wakeup_required: bool,
}

impl ProviderCapabilityDescriptor {
    /// TTL cap exposed as `Duration`, when advertised.
    pub fn ttl_max(&self) -> Option<Duration> {
        self.ttl_seconds_max.map(Duration::from_secs)
    }

    /// Whether this provider accepts a multi-recipient batch shape
    /// (anything other than `"none"`).
    pub fn supports_batch(&self) -> bool {
        !self.batch.eq_ignore_ascii_case("none") && !self.batch.is_empty()
    }

    /// Whether the provider lists `kind` among its accepted credential
    /// material (case-insensitive).
    pub fn accepts_credential(&self, kind: &str) -> bool {
        list_contains_ignore_ascii_case(&self.credential_kinds, kind)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushBridgeDescribeExamples {
    #[serde(default)]
    pub notify_headers: Value,
    #[serde(default)]
    pub blind_wakeup_request: Value,
    #[serde(default)]
    pub plaintext_visible_service_request: Value,
}

/// Response body for `GET /api/v1/integration/describe`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushGatewayIntegrationDescribeResponse {
    pub contract: String,
    pub version: String,
    pub service: String,
    pub service_kind: String,
    pub api_base_path: String,
    pub describe_path: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<PushGatewayIntegrationDependency>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub surfaces: Vec<PushGatewayIntegrationSurface>,
    #[serde(default)]
    pub examples: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub todos: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushGatewayIntegrationDependency {
    pub service: String,
    pub purpose: String,
    pub required_contract: String,
    pub discovery_path: String,
    pub mode: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushGatewayIntegrationSurface {
    pub name: String,
    pub method: String,
    pub path: String,
    pub contract: String,
    pub stability: String,
    pub todo: String,
}

/// Combined view of a push gateway's high-level integration manifest plus its
/// active bridge contract.
///
/// `bridge/describe` is the active wire contract — request/response shapes,
/// privacy mode, rate limits — while `integration/describe` is the
/// service-level manifest (dependencies, surfaces, stability tiers).
/// Consumers usually want both: the manifest tells them which dependencies
/// they need (e.g. soland `register-device`) and the bridge describes how to
/// talk to the gateway today.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct IntegrationView {
    /// Service-level integration manifest (`/api/v1/integration/describe`).
    pub manifest: PushGatewayIntegrationDescribeResponse,
    /// Active bridge contract (`/api/v1/push/bridge/describe`).
    pub bridge: PushBridgeDescribeResponse,
}

impl IntegrationView {
    /// Construct an integration view from the two describe responses.
    pub fn new(
        manifest: PushGatewayIntegrationDescribeResponse,
        bridge: PushBridgeDescribeResponse,
    ) -> Self {
        Self { manifest, bridge }
    }

    /// Whether the manifest declares a dependency on the given service kind
    /// (e.g. `"soland"`) with the given purpose (e.g. `"register-device"`).
    pub fn requires(&self, service: &str, purpose: &str) -> bool {
        self.manifest
            .dependencies
            .iter()
            .any(|dep| dep.service == service && dep.purpose == purpose)
    }

    /// The active bridge contract digest, if any. Convenience for the common
    /// "did the contract drift?" comparison.
    pub fn contract_digest(&self) -> &str {
        &self.bridge.contract
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_descriptor_helpers_match_supported_lists() {
        let descriptor = PushBridgeDescribeGatewayDescriptor {
            service_did: Some("did:web:gateway.example".to_owned()),
            supported_profiles: vec!["fcm".to_owned(), "APNs".to_owned()],
            supported_providers: vec!["huawei".to_owned()],
            auth_modes: vec!["http-message-signature".to_owned()],
        };

        assert!(descriptor.supports_profile("FCM")); // case-insensitive
        assert!(descriptor.supports_profile("apns"));
        assert!(!descriptor.supports_profile("webpush"));
        assert!(descriptor.supports_provider("Huawei"));
        assert!(!descriptor.supports_provider("xiaomi"));
        assert!(descriptor.supports_auth_mode("HTTP-Message-Signature"));
    }

    #[test]
    fn notify_descriptor_exposes_dedup_and_rate_limit_windows() {
        let descriptor = PushBridgeDescribeNotifyDescriptor {
            notify_path: "/api/v1/push/notify".to_owned(),
            operation_id: "cx.push.notify".to_owned(),
            request_id_header: "X-Contrix-Request-Id".to_owned(),
            idempotency_key_header: "X-Contrix-Idempotency-Key".to_owned(),
            origin_service_did_header: "X-Contrix-Origin-Service-Did".to_owned(),
            destination_service_did_header: "X-Contrix-Destination-Service-Did".to_owned(),
            max_request_size_bytes: 16 * 1024,
            dedup_backend: Some("redis".to_owned()),
            dedup_ttl_seconds: Some(300),
            rate_limit_window_seconds: Some(60),
            rate_limit_scopes: vec!["per-app".to_owned()],
            ..Default::default()
        };

        assert!(descriptor.supports_dedup());
        assert_eq!(descriptor.dedup_window(), Some(Duration::from_secs(300)));
        assert_eq!(
            descriptor.rate_limit_window(),
            Some(Duration::from_secs(60))
        );
        assert!(descriptor.rate_limits_by("per-app"));
        assert!(!descriptor.rate_limits_by("per-actor"));
        assert_eq!(descriptor.max_request_size(), 16 * 1024);

        let empty = PushBridgeDescribeNotifyDescriptor::default();
        assert!(!empty.supports_dedup());
        assert!(empty.dedup_window().is_none());
        assert!(empty.rate_limit_window().is_none());
    }

    #[test]
    fn provider_capability_descriptor_roundtrips_floria_fcm_fixture() {
        // Mirrors floria's `fcm` entry from src/pushkin/mod.rs:189-199
        // wrapped in the per-app `ProviderCapabilityDescriptor` shape.
        let json = serde_json::json!({
            "name": "default-fcm-app",
            "kind": "fcm",
            "batch": "multicast",
            "ttl_seconds_max": 28u64 * 24 * 60 * 60,
            "supports_collapse": true,
            "supports_badge": true,
            "default_payload_shape": "data_only_blind_wakeup",
            "credential_kinds": ["service_account_v1"],
            "credential_rotation": "rotate_service_account_yearly_or_on_compromise",
            "blind_wakeup_required": true,
        });

        let cap: ProviderCapabilityDescriptor =
            serde_json::from_value(json.clone()).expect("deserialize fixture");
        assert_eq!(cap.name, "default-fcm-app");
        assert_eq!(cap.kind, "fcm");
        assert_eq!(cap.batch, "multicast");
        assert_eq!(cap.ttl_seconds_max, Some(28 * 24 * 60 * 60));
        assert_eq!(cap.ttl_max(), Some(Duration::from_secs(28 * 24 * 60 * 60)));
        assert!(cap.supports_collapse);
        assert!(cap.supports_badge);
        assert!(cap.supports_batch());
        assert!(cap.accepts_credential("service_account_v1"));
        assert!(!cap.accepts_credential("vapid_keypair"));
        assert!(cap.blind_wakeup_required);

        let reserialized = serde_json::to_value(&cap).expect("serialize fixture");
        assert_eq!(reserialized, json);
    }

    #[test]
    fn bridge_describe_response_carries_provider_capabilities_matrix() {
        let json = serde_json::json!({
            "contract": "cx.push.bridge.v1",
            "version": "1.0.0",
            "api_base_path": "/api/v1",
            "gateway": {},
            "notify": {
                "notify_path": "/api/v1/push/notify",
                "operation_id": "cx.push.notify",
                "request_id_header": "X-Contrix-Request-Id",
                "idempotency_key_header": "X-Contrix-Idempotency-Key",
                "origin_service_did_header": "X-Contrix-Origin-Service-Did",
                "destination_service_did_header": "X-Contrix-Destination-Service-Did",
                "max_request_size_bytes": 16384,
            },
            "privacy": {
                "default_mode": "blind_wakeup",
                "plaintext_visibility_class": "service-visible",
            },
            "provider_capabilities_version": "2026-05-07",
            "provider_capabilities": [
                {
                    "name": "default-fcm-app",
                    "kind": "fcm",
                    "batch": "multicast",
                    "ttl_seconds_max": 28u64 * 24 * 60 * 60,
                    "supports_collapse": true,
                    "supports_badge": true,
                    "default_payload_shape": "data_only_blind_wakeup",
                    "credential_kinds": ["service_account_v1"],
                    "credential_rotation": "rotate_service_account_yearly_or_on_compromise",
                    "blind_wakeup_required": true,
                },
                {
                    "name": "ios-app",
                    "kind": "apns",
                    "batch": "none",
                    "ttl_seconds_max": 28u64 * 24 * 60 * 60,
                    "supports_collapse": true,
                    "supports_badge": true,
                    "default_payload_shape": "encrypted_or_blind_wakeup",
                    "credential_kinds": ["jwt_p8", "cert_p12"],
                    "credential_rotation": "rotate_jwt_p8_yearly_cert_p12_per_apple_lifecycle",
                    "blind_wakeup_required": true,
                },
            ],
        });

        let response: PushBridgeDescribeResponse =
            serde_json::from_value(json).expect("deserialize bridge describe response");
        assert_eq!(
            response.provider_capabilities_version.as_deref(),
            Some("2026-05-07"),
        );
        assert_eq!(response.provider_capabilities.len(), 2);

        let fcm = response
            .provider_capability("default-fcm-app")
            .expect("fcm app present");
        assert_eq!(fcm.kind, "fcm");
        assert!(fcm.supports_batch());

        let apns = response
            .provider_capability_by_kind("apns")
            .expect("apns kind present");
        assert_eq!(apns.name, "ios-app");
        assert!(!apns.supports_batch());
        assert!(apns.accepts_credential("JWT_P8"));
    }

    #[test]
    fn bridge_describe_response_decodes_without_provider_capabilities() {
        // Provider capability fields are optional in the bridge contract.
        let json = serde_json::json!({
            "contract": "cx.push.bridge.v1",
            "version": "1.0.0",
            "api_base_path": "/api/v1",
            "gateway": {},
            "notify": {
                "notify_path": "/api/v1/push/notify",
                "operation_id": "cx.push.notify",
                "request_id_header": "X-Contrix-Request-Id",
                "idempotency_key_header": "X-Contrix-Idempotency-Key",
                "origin_service_did_header": "X-Contrix-Origin-Service-Did",
                "destination_service_did_header": "X-Contrix-Destination-Service-Did",
                "max_request_size_bytes": 16384,
            },
            "privacy": {
                "default_mode": "blind_wakeup",
                "plaintext_visibility_class": "service-visible",
            },
        });

        let response: PushBridgeDescribeResponse =
            serde_json::from_value(json).expect("decode response");
        assert!(response.provider_capabilities_version.is_none());
        assert!(response.provider_capabilities.is_empty());
        assert!(response.provider_capability("anything").is_none());

        // Re-serialize: empty optional capability fields stay omitted.
        let reserialized = serde_json::to_value(&response).expect("re-serialize");
        let obj = reserialized.as_object().expect("object");
        assert!(!obj.contains_key("provider_capabilities_version"));
        assert!(!obj.contains_key("provider_capabilities"));
    }

    #[test]
    fn integration_view_exposes_manifest_dependency_lookup() {
        let manifest = PushGatewayIntegrationDescribeResponse {
            contract: "cx.integration.push_gateway.v1".to_owned(),
            version: "1.0.0".to_owned(),
            service: "push-gateway".to_owned(),
            service_kind: "push-gateway".to_owned(),
            api_base_path: "/api/v1".to_owned(),
            describe_path: "/api/v1/integration/describe".to_owned(),
            dependencies: vec![PushGatewayIntegrationDependency {
                service: "soland".to_owned(),
                purpose: "register-device".to_owned(),
                required_contract: "cx.auth.bridge.v1".to_owned(),
                discovery_path: "/api/v1/auth/bridge/describe".to_owned(),
                mode: "required".to_owned(),
            }],
            surfaces: Vec::new(),
            examples: serde_json::Value::Null,
            todos: Vec::new(),
        };
        let bridge = PushBridgeDescribeResponse {
            contract: "cx.push.bridge.v1".to_owned(),
            ..Default::default()
        };

        let view = IntegrationView::new(manifest, bridge);
        assert!(view.requires("soland", "register-device"));
        assert!(!view.requires("soland", "unregister-device"));
        assert_eq!(view.contract_digest(), "cx.push.bridge.v1");
    }
}
