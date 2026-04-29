//! Local push registration state helpers.

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    PushDeviceConfig, PushPreferences, PushRegistrationError, RegisterDeviceRequest,
    RegisterDeviceResponse, UnregisterDeviceRequest, build_register_device_request,
    build_unregister_device_request, redact_push_key,
};

/// Persistable local state for a successful push registration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushRegistrationState {
    pub registration_id: Option<String>,
    pub device_id: String,
    pub app_id: Option<String>,
    pub push_gateway: String,
    pub push_key_hash: String,
    pub push_key_preview: String,
    pub registered_at: Option<String>,
    pub expires_at: Option<String>,
}

/// Minimal storage abstraction for host applications.
///
/// The crate does not choose a database, keychain, or file format. Apps can
/// implement this trait over their own secure local storage.
pub trait PushRegistrationStore {
    type Error;

    fn load_push_registration(&self) -> Result<Option<PushRegistrationState>, Self::Error>;

    fn save_push_registration(&self, state: &PushRegistrationState) -> Result<(), Self::Error>;

    fn clear_push_registration(&self) -> Result<(), Self::Error>;
}

/// Request plan for replacing a platform push token.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct PushTokenRotationPlan {
    pub unregister_old: Option<UnregisterDeviceRequest>,
    pub register_new: Option<RegisterDeviceRequest>,
    pub token_changed: bool,
}

/// Return a stable SHA-256 fingerprint for local token comparison.
pub fn hash_push_key(push_key: &str) -> String {
    let digest = Sha256::digest(push_key.as_bytes());
    let mut output = String::with_capacity("sha256:".len() + digest.len() * 2);
    output.push_str("sha256:");
    for byte in digest {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

pub fn token_rotation_required(
    existing: Option<&PushRegistrationState>,
    new_push_key: &str,
) -> bool {
    let Some(existing) = existing else {
        return true;
    };

    existing.push_key_hash != hash_push_key(new_push_key)
}

/// Build persistable registration state after a successful register response.
///
/// ```rust
/// use chime::{
///     PushDeviceConfig, PushPreferences, RegisterDeviceResponse,
///     build_register_device_request, build_registration_state,
/// };
///
/// let config = PushDeviceConfig {
///     device_id: "did:web:alice.example#device-phone",
///     push_key: Some("fcm:token"),
///     platform: Some("android"),
///     app_id: Some("app.example.android"),
///     domestic_app_id: None,
///     registration_id: None,
///     display_name: None,
///     idempotency_key: None,
///     request_id: None,
///     proof: None,
/// };
/// let prefs = PushPreferences {
///     enabled: true,
///     push_gateway: "https://push.example.com/api/v1/push/notify".to_owned(),
///     ..Default::default()
/// };
/// let request = build_register_device_request(&config, &prefs).unwrap();
/// let response = RegisterDeviceResponse {
///     ok: true,
///     registration_id: Some("reg-1".to_owned()),
///     expires_at: None,
/// };
/// let state = build_registration_state(&config, &prefs, &request, &response, None);
/// assert_eq!(state.registration_id.as_deref(), Some("reg-1"));
/// ```
pub fn build_registration_state(
    config: &PushDeviceConfig<'_>,
    prefs: &PushPreferences,
    request: &RegisterDeviceRequest,
    response: &RegisterDeviceResponse,
    registered_at: Option<&str>,
) -> PushRegistrationState {
    PushRegistrationState {
        registration_id: response.registration_id.clone(),
        device_id: request.device_id.clone(),
        app_id: request.app_id.clone(),
        push_gateway: prefs.push_gateway.clone(),
        push_key_hash: hash_push_key(&request.push_key),
        push_key_preview: redact_push_key(&request.push_key),
        registered_at: registered_at.map(str::to_owned),
        expires_at: response.expires_at.clone(),
    }
    .with_registration_id_fallback(config.registration_id)
}

pub fn plan_token_rotation(
    existing: Option<&PushRegistrationState>,
    config: &PushDeviceConfig<'_>,
    prefs: &PushPreferences,
) -> Result<PushTokenRotationPlan, PushRegistrationError> {
    let new_push_key = config
        .push_key
        .ok_or(PushRegistrationError::MissingField("push_key"))?;

    if !token_rotation_required(existing, new_push_key) {
        return Ok(PushTokenRotationPlan {
            unregister_old: None,
            register_new: None,
            token_changed: false,
        });
    }

    let unregister_old = existing.map(|state| {
        let old_config = PushDeviceConfig {
            device_id: &state.device_id,
            push_key: None,
            platform: config.platform,
            app_id: state.app_id.as_deref(),
            domestic_app_id: None,
            registration_id: state.registration_id.as_deref(),
            display_name: None,
            idempotency_key: config.idempotency_key,
            request_id: config.request_id,
            proof: config.proof,
        };
        build_unregister_device_request(&old_config, prefs)
    });

    Ok(PushTokenRotationPlan {
        unregister_old: unregister_old.transpose()?,
        register_new: Some(build_register_device_request(config, prefs)?),
        token_changed: true,
    })
}

impl PushRegistrationState {
    fn with_registration_id_fallback(mut self, fallback: Option<&str>) -> Self {
        if self.registration_id.is_none() {
            self.registration_id = fallback.map(str::to_owned);
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefs() -> PushPreferences {
        PushPreferences {
            enabled: true,
            push_gateway: "https://push.example.com/api/v1/push/notify".to_owned(),
            ..Default::default()
        }
    }

    fn config<'a>(push_key: &'a str) -> PushDeviceConfig<'a> {
        PushDeviceConfig {
            device_id: "did:web:alice.example#device-phone",
            push_key: Some(push_key),
            platform: Some("android"),
            app_id: Some("app.example.android"),
            domestic_app_id: None,
            registration_id: Some("reg-old"),
            display_name: Some("Alice Phone"),
            idempotency_key: Some("idem-1"),
            request_id: None,
            proof: None,
        }
    }

    #[test]
    fn hashes_push_key_without_exposing_value() {
        let hash = hash_push_key("fcm:very-secret-token");
        assert!(hash.starts_with("sha256:"));
        assert_eq!(hash.len(), "sha256:".len() + 64);
        assert!(!hash.contains("very-secret-token"));
    }

    #[test]
    fn builds_registration_state_from_success() {
        let request = build_register_device_request(&config("fcm:new-token"), &prefs()).unwrap();
        let response = RegisterDeviceResponse {
            ok: true,
            registration_id: Some("reg-new".to_owned()),
            expires_at: Some("2026-04-29T00:00:00Z".to_owned()),
        };

        let state = build_registration_state(
            &config("fcm:new-token"),
            &prefs(),
            &request,
            &response,
            Some("2026-04-29T00:00:00Z"),
        );

        assert_eq!(state.registration_id.as_deref(), Some("reg-new"));
        assert_eq!(state.push_key_preview, "fcm:<redacted,len=9>");
        assert!(!state.push_key_hash.contains("new-token"));
    }

    #[test]
    fn rotation_plan_is_empty_when_token_unchanged() {
        let request = build_register_device_request(&config("fcm:same-token"), &prefs()).unwrap();
        let response = RegisterDeviceResponse {
            ok: true,
            registration_id: Some("reg-1".to_owned()),
            expires_at: None,
        };
        let state = build_registration_state(
            &config("fcm:same-token"),
            &prefs(),
            &request,
            &response,
            None,
        );

        let plan = plan_token_rotation(Some(&state), &config("fcm:same-token"), &prefs()).unwrap();

        assert!(!plan.token_changed);
        assert!(plan.unregister_old.is_none());
        assert!(plan.register_new.is_none());
    }

    #[test]
    fn rotation_plan_unregisters_old_and_registers_new_token() {
        let request = build_register_device_request(&config("fcm:old-token"), &prefs()).unwrap();
        let response = RegisterDeviceResponse {
            ok: true,
            registration_id: Some("reg-old".to_owned()),
            expires_at: None,
        };
        let state = build_registration_state(
            &config("fcm:old-token"),
            &prefs(),
            &request,
            &response,
            None,
        );

        let plan = plan_token_rotation(Some(&state), &config("fcm:new-token"), &prefs()).unwrap();

        assert!(plan.token_changed);
        assert_eq!(
            plan.unregister_old
                .as_ref()
                .and_then(|request| request.registration_id.as_deref()),
            Some("reg-old")
        );
        assert_eq!(
            plan.register_new
                .as_ref()
                .map(|request| request.push_key.as_str()),
            Some("fcm:new-token")
        );
    }
}
