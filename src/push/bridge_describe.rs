//! Bridge describe + integration describe response DTOs.

use serde::{Deserialize, Serialize};
use serde_json::Value;

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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub todos: Vec<String>,
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

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushBridgeDescribeNotifyDescriptor {
    pub notify_path: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub legacy_notify_aliases: Vec<String>,
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

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushBridgeDescribePrivacyDescriptor {
    pub default_mode: String,
    pub plaintext_visibility_class: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub active_reference_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejected_legacy_fields: Vec<String>,
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
