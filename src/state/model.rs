//! Persistable push registration state types and helpers.

use arkret_models_integration::PushRegisterDeviceResponseBody;
use arkret_wire::{AccountId, OpaqueLocalId};
use serde::{Deserialize, Serialize};

use crate::{ChimePushRegisterDeviceRequest, GatewayBinding, redact_push_key};

/// Persistable local state for a successful push registration.
///
/// Stability: v1 development phase — the persisted shape may change
/// aggressively and old development blobs are not retained as a compatibility
/// surface.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushRegistrationState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<AccountId>,
    pub registration_id: Option<OpaqueLocalId>,
    pub device_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    pub app_id: Option<String>,
    pub push_gateway: String,
    pub push_key_hash: String,
    pub push_key_preview: String,
    pub registered_at: Option<String>,
    pub expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_success_at: Option<String>,
}

/// Return a stable SHA-256 fingerprint for local token comparison.
pub fn hash_push_key(push_key: &str) -> String {
    arkret_canonical::sha256_digest(push_key.as_bytes())
}

/// Build persistable registration state after a successful register response.
///
/// ```rust
/// use arkret_models_integration::PushRegisterDeviceResponseBody;
/// use chime::{
///     GatewayBinding, PushDeviceConfig, PushGatewayType, PushPreferences,
///     build_register_device_request, build_registration_state,
/// };
///
/// let config = PushDeviceConfig {
///     account_id: Some(arkret_wire::AccountId::new(
///         arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
///         arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
///     )),
///     device_id: "ak:device:01904100-0000-7000-8000-000000000004",
///     push_key: Some("fcm:token"),
///     platform: Some("android"),
///     app_id: Some("app.example.android"),
///     domestic_app_id: None,
///     registration_id: None,
///     display_name: None,
///     visible_notification_opt_in: false,
///     idempotency_key: None,
///     request_id: None,
///     proof: None,
/// };
/// let binding = GatewayBinding::new(
///     PushGatewayType::Standard,
///     "https://push.example.com/_arkret/edge/push/notify",
/// );
/// let prefs = PushPreferences {
///     enabled: true,
///     ..Default::default()
/// };
/// let request = build_register_device_request(&config, &binding, &prefs).unwrap();
/// let response = PushRegisterDeviceResponseBody {
///     push_target_id: arkret_wire::PushTargetId::new(
///         "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
///     )
///     .unwrap(),
///     registration_id: arkret_models_integration::PushRegistrationId::new(
///         "registration-test-00000001",
///     )
///     .unwrap(),
///     expires_at: None,
/// };
/// let state = build_registration_state(&binding, &request, &response, None);
/// assert_eq!(
///     state.registration_id.as_deref(),
///     Some("registration-test-00000001")
/// );
/// ```
pub fn build_registration_state(
    binding: &GatewayBinding,
    request: &ChimePushRegisterDeviceRequest,
    response: &PushRegisterDeviceResponseBody,
    registered_at: Option<&str>,
) -> PushRegistrationState {
    PushRegistrationState {
        account_id: request.account_id.clone(),
        registration_id: Some(response.registration_id.clone().into()),
        device_id: request.device_id.clone(),
        platform: request.platform.clone(),
        app_id: request.app_id.clone(),
        push_gateway: binding.push_gateway.clone(),
        push_key_hash: hash_push_key(&request.push_key),
        push_key_preview: redact_push_key(&request.push_key),
        registered_at: registered_at.map(str::to_owned),
        expires_at: response
            .expires_at
            .map(arkret_canonical::format_timestamp_canonical),
        last_success_at: registered_at.map(str::to_owned),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_register_device_request;
    use crate::state::test_fixtures::{binding, config, prefs};

    #[test]
    fn hashes_push_key_without_exposing_value() {
        let hash = hash_push_key("fcm:very-secret-token");
        assert!(hash.starts_with("sha256:"));
        assert_eq!(hash.len(), "sha256:".len() + 64);
        assert!(!hash.contains("very-secret-token"));
    }

    #[test]
    fn builds_registration_state_from_success() {
        let request =
            build_register_device_request(&config("fcm:new-token"), &binding(), &prefs()).unwrap();
        let response = PushRegisterDeviceResponseBody {
            // Server-derived pairwise pseudonym (required by the SDK wire
            // model); the registration-state builder does not read it.
            push_target_id: arkret_wire::PushTargetId::new(
                "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
            )
            .unwrap(),
            registration_id: arkret_models_integration::PushRegistrationId::new(
                "registration-test-new-00001",
            )
            .unwrap(),
            expires_at: Some("2026-04-29T00:00:00.000Z".parse().expect("valid timestamp")),
        };

        let state = build_registration_state(
            &binding(),
            &request,
            &response,
            Some("2026-04-29T00:00:00.000Z"),
        );

        assert_eq!(
            state
                .account_id
                .as_ref()
                .map(|account| account.principal_id.as_str()),
            Some("ak:did_core:web:alice.example")
        );
        assert_eq!(state.platform.as_deref(), Some("android"));
        assert_eq!(
            state.registration_id.as_deref(),
            Some("registration-test-new-00001")
        );
        assert_eq!(state.push_key_preview, "fcm:<redacted,len=9>");
        assert!(!state.push_key_hash.contains("new-token"));
        assert_eq!(
            state.last_success_at.as_deref(),
            Some("2026-04-29T00:00:00.000Z")
        );
    }

    #[test]
    fn same_principal_station_registrations_remain_distinct_and_private() {
        let request =
            build_register_device_request(&config("fcm:token"), &binding(), &prefs()).unwrap();
        let mut other = request.clone();
        other.account_id.as_mut().unwrap().station_id =
            arkret_wire::DidCoreId::new("ak:did_core:web:other-station.example").unwrap();
        assert_ne!(request.account_id, other.account_id);
        let wire = serde_json::to_value(request.to_sdk_request().unwrap()).unwrap();
        assert_eq!(
            wire,
            serde_json::to_value(other.to_sdk_request().unwrap()).unwrap()
        );
        assert!(wire.get("account_id").is_none());
        assert!(wire.get("principal_id").is_none());
        let mut persisted = serde_json::to_value(&request).unwrap();
        assert!(persisted["account_id"].is_object());
        persisted["principal_id"] = serde_json::json!("ak:did_core:web:alice.example");
        assert!(serde_json::from_value::<ChimePushRegisterDeviceRequest>(persisted).is_err());
    }
}
