//! Local push registration state helpers.

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    PushDeviceConfig, PushPlatform, PushPreferences, PushRegistrationError, RegisterDeviceRequest,
    RegisterDeviceResponse, UnregisterDeviceRequest, build_register_device_request,
    build_unregister_device_request, redact_push_key,
};

pub const PUSH_REGISTRATION_STATE_SCHEMA_VERSION: u16 = 1;

/// Persistable local state for a successful push registration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushRegistrationState {
    #[serde(default = "default_state_schema_version")]
    pub schema_version: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_did: Option<String>,
    pub registration_id: Option<String>,
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
    pub refresh_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_success_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<PushRegistrationLastError>,
}

/// Persistable non-secret summary of the last registration failure.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushRegistrationLastError {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub occurred_at: Option<String>,
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

    fn load_push_registrations(&self) -> Result<Vec<PushRegistrationState>, Self::Error> {
        Ok(self.load_push_registration()?.into_iter().collect())
    }

    fn save_push_registrations(&self, states: &[PushRegistrationState]) -> Result<(), Self::Error> {
        if let Some(state) = states.first() {
            self.save_push_registration(state)
        } else {
            self.clear_push_registration()
        }
    }

    fn delete_push_registration(&self, state: &PushRegistrationState) -> Result<(), Self::Error> {
        let _ = state;
        self.clear_push_registration()
    }
}

/// Request plan for replacing a platform push token.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct PushTokenRotationPlan {
    pub unregister_old: Option<UnregisterDeviceRequest>,
    pub register_new: Option<RegisterDeviceRequest>,
    pub token_changed: bool,
    pub strategy: PushTokenRotationStrategy,
}

/// State repair plan for stale local records, token moves, and partial
/// register/unregister failures.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct PushRegistrationRepairPlan {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_state: Option<PushRegistrationState>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stale_states: Vec<PushRegistrationState>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unregister_stale: Vec<UnregisterDeviceRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub register_current: Option<RegisterDeviceRequest>,
    #[serde(default)]
    pub stale_state_detected: bool,
    #[serde(default)]
    pub token_moved: bool,
}

/// Ordering strategy for token rotation plans.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PushTokenRotationStrategy {
    /// Unregister the old token before registering the new token.
    #[default]
    UnregisterOldFirst,
    /// Register the new token first, then unregister the old token once the
    /// replacement registration has succeeded.
    RegisterNewFirst,
}

fn default_state_schema_version() -> u16 {
    PUSH_REGISTRATION_STATE_SCHEMA_VERSION
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

pub fn find_registration_for_device<'a>(
    states: &'a [PushRegistrationState],
    principal_did: Option<&str>,
    device_id: &str,
    app_id: Option<&str>,
) -> Option<&'a PushRegistrationState> {
    states.iter().find(|state| {
        state.principal_did.as_deref() == principal_did
            && state.device_id == device_id
            && state.app_id.as_deref() == app_id
    })
}

pub fn find_registration_by_token<'a>(
    states: &'a [PushRegistrationState],
    push_key: &str,
) -> Option<&'a PushRegistrationState> {
    let push_key_hash = hash_push_key(push_key);
    states
        .iter()
        .find(|state| state.push_key_hash == push_key_hash)
}

pub fn token_moved_to_different_device(
    states: &[PushRegistrationState],
    principal_did: Option<&str>,
    device_id: &str,
    push_key: &str,
) -> bool {
    find_registration_by_token(states, push_key).is_some_and(|state| {
        state.principal_did.as_deref() == principal_did && state.device_id != device_id
    })
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
///     principal_did: Some("did:web:alice.example"),
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
///     accepted_gateway: None,
///     push_key_hash: None,
///     push_key_preview: None,
///     expires_at: None,
///     refresh_hint: None,
///     warnings: Vec::new(),
///     request_id: None,
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
        schema_version: PUSH_REGISTRATION_STATE_SCHEMA_VERSION,
        principal_did: request.principal_did.clone(),
        registration_id: response.registration_id.clone(),
        device_id: request.device_id.clone(),
        platform: request.platform.clone(),
        app_id: request.app_id.clone(),
        push_gateway: response
            .accepted_gateway
            .clone()
            .unwrap_or_else(|| prefs.push_gateway.clone()),
        push_key_hash: response
            .push_key_hash
            .clone()
            .unwrap_or_else(|| hash_push_key(&request.push_key)),
        push_key_preview: response
            .push_key_preview
            .clone()
            .unwrap_or_else(|| redact_push_key(&request.push_key)),
        registered_at: registered_at.map(str::to_owned),
        expires_at: response.expires_at.clone(),
        refresh_hint: response.refresh_hint.clone(),
        last_success_at: registered_at.map(str::to_owned),
        last_error: None,
    }
    .with_registration_id_fallback(config.registration_id)
}

pub fn plan_token_rotation(
    existing: Option<&PushRegistrationState>,
    config: &PushDeviceConfig<'_>,
    prefs: &PushPreferences,
) -> Result<PushTokenRotationPlan, PushRegistrationError> {
    plan_token_rotation_with_strategy(
        existing,
        config,
        prefs,
        PushTokenRotationStrategy::UnregisterOldFirst,
    )
}

pub fn plan_token_rotation_with_strategy(
    existing: Option<&PushRegistrationState>,
    config: &PushDeviceConfig<'_>,
    prefs: &PushPreferences,
    strategy: PushTokenRotationStrategy,
) -> Result<PushTokenRotationPlan, PushRegistrationError> {
    let new_push_key = config
        .push_key
        .ok_or(PushRegistrationError::MissingField("push_key"))?;

    if !token_rotation_required(existing, new_push_key) {
        return Ok(PushTokenRotationPlan {
            unregister_old: None,
            register_new: None,
            token_changed: false,
            strategy,
        });
    }

    let unregister_old = existing.map(|state| {
        let old_config = PushDeviceConfig {
            principal_did: config.principal_did,
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
        strategy,
    })
}

/// Merge a successful registration state into the locally persisted set.
///
/// The new state replaces any older entry for the same logical registration
/// and removes stale duplicates that still point at the same token hash from
/// another device/app record.
pub fn merge_registration_state(
    states: &[PushRegistrationState],
    new_state: PushRegistrationState,
) -> Vec<PushRegistrationState> {
    let mut merged = states
        .iter()
        .filter(|state| {
            !state.is_same_logical_registration(&new_state)
                && state.push_key_hash != new_state.push_key_hash
        })
        .cloned()
        .collect::<Vec<_>>();
    merged.push(new_state);
    merged
}

/// Build a repair plan for stale local registration state.
///
/// This helper covers common real-world recovery paths:
/// - `register-new-first` succeeded but `unregister-old` still needs cleanup.
/// - `unregister-old-first` ran, but local state still points at the old token.
/// - the same token was moved to another logical device/app registration.
pub fn plan_registration_repair(
    states: &[PushRegistrationState],
    config: &PushDeviceConfig<'_>,
    prefs: &PushPreferences,
) -> Result<PushRegistrationRepairPlan, PushRegistrationError> {
    let current_push_key = config.push_key.and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then_some(trimmed)
    });
    if prefs.enabled && current_push_key.is_none() {
        return Err(PushRegistrationError::MissingField("push_key"));
    }

    let current_push_key_hash = current_push_key.map(hash_push_key);
    let current_platform = config
        .platform
        .map(PushPlatform::try_from)
        .transpose()?
        .map(|platform| platform.as_str().to_owned());
    let current_app_id = prefs
        .app_id(
            current_platform
                .as_deref()
                .map(PushPlatform::try_from)
                .transpose()?,
            config.app_id,
            config.domestic_app_id,
        )
        .map(str::to_owned);

    let mut active_state = None::<PushRegistrationState>;
    let mut stale_states = Vec::new();
    let mut token_moved = false;

    for state in states {
        let same_logical = state.principal_did.as_deref() == config.principal_did
            && state.device_id == config.device_id
            && state.platform.as_deref() == current_platform.as_deref()
            && state.app_id.as_deref() == current_app_id.as_deref()
            && state.push_gateway == prefs.push_gateway;
        let same_token = current_push_key_hash
            .as_deref()
            .is_some_and(|hash| state.push_key_hash == hash);

        if same_logical && same_token {
            match &active_state {
                Some(current) if prefers_registration_state(state, current) => {
                    stale_states.push(current.clone());
                    active_state = Some(state.clone());
                }
                Some(_) => stale_states.push(state.clone()),
                None => active_state = Some(state.clone()),
            }
            continue;
        }

        if same_logical || same_token {
            token_moved |= same_token && !same_logical;
            stale_states.push(state.clone());
        }
    }

    let unregister_stale = stale_states
        .iter()
        .map(|state| build_unregister_request_for_state(state, config, prefs))
        .collect::<Result<Vec<_>, _>>()?;
    let register_current = if prefs.enabled && active_state.is_none() {
        Some(build_register_device_request(config, prefs)?)
    } else {
        None
    };

    Ok(PushRegistrationRepairPlan {
        active_state,
        stale_state_detected: !stale_states.is_empty(),
        stale_states,
        unregister_stale,
        register_current,
        token_moved,
    })
}

impl PushRegistrationState {
    /// Stable key for stores that support multiple registrations per device.
    pub fn storage_key(&self) -> String {
        [
            self.principal_did.as_deref().unwrap_or("_"),
            &self.device_id,
            self.platform.as_deref().unwrap_or("_"),
            self.app_id.as_deref().unwrap_or("_"),
            &self.push_gateway,
        ]
        .join("|")
    }

    pub fn is_same_logical_registration(&self, other: &Self) -> bool {
        self.principal_did == other.principal_did
            && self.device_id == other.device_id
            && self.platform == other.platform
            && self.app_id == other.app_id
            && self.push_gateway == other.push_gateway
    }

    pub fn token_matches(&self, push_key: &str) -> bool {
        self.push_key_hash == hash_push_key(push_key)
    }

    pub fn mark_last_error(
        mut self,
        kind: impl Into<String>,
        request_id: Option<&str>,
        retry_after: Option<&str>,
        occurred_at: Option<&str>,
    ) -> Self {
        self.last_error = Some(PushRegistrationLastError {
            kind: kind.into(),
            request_id: request_id.map(str::to_owned),
            retry_after: retry_after.map(str::to_owned),
            occurred_at: occurred_at.map(str::to_owned),
        });
        self
    }

    fn with_registration_id_fallback(mut self, fallback: Option<&str>) -> Self {
        if self.registration_id.is_none() {
            self.registration_id = fallback.map(str::to_owned);
        }
        self
    }
}

fn prefers_registration_state(
    candidate: &PushRegistrationState,
    current: &PushRegistrationState,
) -> bool {
    registration_state_rank(candidate) > registration_state_rank(current)
}

fn registration_state_rank(state: &PushRegistrationState) -> (u8, &str, &str, &str) {
    (
        u8::from(state.registration_id.is_some()),
        state.last_success_at.as_deref().unwrap_or(""),
        state.registered_at.as_deref().unwrap_or(""),
        state.expires_at.as_deref().unwrap_or(""),
    )
}

fn build_unregister_request_for_state(
    state: &PushRegistrationState,
    config: &PushDeviceConfig<'_>,
    prefs: &PushPreferences,
) -> Result<UnregisterDeviceRequest, PushRegistrationError> {
    let mut unregister_prefs = prefs.clone();
    unregister_prefs.push_gateway = state.push_gateway.clone();

    let unregister_config = PushDeviceConfig {
        principal_did: state.principal_did.as_deref().or(config.principal_did),
        device_id: &state.device_id,
        push_key: None,
        platform: state.platform.as_deref().or(config.platform),
        app_id: state.app_id.as_deref(),
        domestic_app_id: None,
        registration_id: state.registration_id.as_deref(),
        display_name: None,
        idempotency_key: config.idempotency_key,
        request_id: config.request_id,
        proof: config.proof,
    };

    build_unregister_device_request(&unregister_config, &unregister_prefs)
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
            principal_did: Some("did:web:alice.example"),
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

    fn state_for(
        device_id: &'static str,
        token: &'static str,
        registration_id: &'static str,
    ) -> PushRegistrationState {
        let mut device_config = config(token);
        device_config.device_id = device_id;
        device_config.registration_id = Some(registration_id);

        let request = build_register_device_request(&device_config, &prefs()).unwrap();
        let response = RegisterDeviceResponse {
            ok: true,
            registration_id: Some(registration_id.to_owned()),
            accepted_gateway: None,
            push_key_hash: None,
            push_key_preview: None,
            expires_at: Some("2026-05-03T00:00:00Z".to_owned()),
            refresh_hint: Some("rotate_before_expiry".to_owned()),
            warnings: Vec::new(),
            request_id: None,
        };

        build_registration_state(
            &device_config,
            &prefs(),
            &request,
            &response,
            Some("2026-05-03T00:00:00Z"),
        )
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
            accepted_gateway: None,
            push_key_hash: None,
            push_key_preview: None,
            expires_at: Some("2026-04-29T00:00:00Z".to_owned()),
            refresh_hint: None,
            warnings: Vec::new(),
            request_id: None,
        };

        let state = build_registration_state(
            &config("fcm:new-token"),
            &prefs(),
            &request,
            &response,
            Some("2026-04-29T00:00:00Z"),
        );

        assert_eq!(state.schema_version, PUSH_REGISTRATION_STATE_SCHEMA_VERSION);
        assert_eq!(
            state.principal_did.as_deref(),
            Some("did:web:alice.example")
        );
        assert_eq!(state.platform.as_deref(), Some("android"));
        assert_eq!(state.registration_id.as_deref(), Some("reg-new"));
        assert_eq!(state.push_key_preview, "fcm:<redacted,len=9>");
        assert!(!state.push_key_hash.contains("new-token"));
        assert_eq!(
            state.last_success_at.as_deref(),
            Some("2026-04-29T00:00:00Z")
        );
        assert!(state.storage_key().contains("did:web:alice.example"));
    }

    #[test]
    fn rotation_plan_is_empty_when_token_unchanged() {
        let request = build_register_device_request(&config("fcm:same-token"), &prefs()).unwrap();
        let response = RegisterDeviceResponse {
            ok: true,
            registration_id: Some("reg-1".to_owned()),
            accepted_gateway: None,
            push_key_hash: None,
            push_key_preview: None,
            expires_at: None,
            refresh_hint: None,
            warnings: Vec::new(),
            request_id: None,
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
        assert_eq!(plan.strategy, PushTokenRotationStrategy::UnregisterOldFirst);
    }

    #[test]
    fn rotation_plan_unregisters_old_and_registers_new_token() {
        let request = build_register_device_request(&config("fcm:old-token"), &prefs()).unwrap();
        let response = RegisterDeviceResponse {
            ok: true,
            registration_id: Some("reg-old".to_owned()),
            accepted_gateway: None,
            push_key_hash: None,
            push_key_preview: None,
            expires_at: None,
            refresh_hint: None,
            warnings: Vec::new(),
            request_id: None,
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

    #[test]
    fn rotation_plan_supports_register_new_first_strategy() {
        let request = build_register_device_request(&config("fcm:old-token"), &prefs()).unwrap();
        let response = RegisterDeviceResponse {
            ok: true,
            registration_id: Some("reg-old".to_owned()),
            accepted_gateway: None,
            push_key_hash: None,
            push_key_preview: None,
            expires_at: None,
            refresh_hint: None,
            warnings: Vec::new(),
            request_id: None,
        };
        let state = build_registration_state(
            &config("fcm:old-token"),
            &prefs(),
            &request,
            &response,
            None,
        );

        let plan = plan_token_rotation_with_strategy(
            Some(&state),
            &config("fcm:new-token"),
            &prefs(),
            PushTokenRotationStrategy::RegisterNewFirst,
        )
        .unwrap();

        assert!(plan.token_changed);
        assert_eq!(plan.strategy, PushTokenRotationStrategy::RegisterNewFirst);
        assert!(plan.unregister_old.is_some());
        assert!(plan.register_new.is_some());
    }

    #[test]
    fn multi_device_helpers_find_token_moves_without_exposing_token() {
        let request = build_register_device_request(&config("fcm:moved-token"), &prefs()).unwrap();
        let response = RegisterDeviceResponse {
            ok: true,
            registration_id: Some("reg-1".to_owned()),
            accepted_gateway: None,
            push_key_hash: None,
            push_key_preview: None,
            expires_at: None,
            refresh_hint: None,
            warnings: Vec::new(),
            request_id: None,
        };
        let state = build_registration_state(
            &config("fcm:moved-token"),
            &prefs(),
            &request,
            &response,
            None,
        );
        let states = vec![state.clone()];

        assert!(
            find_registration_for_device(
                &states,
                Some("did:web:alice.example"),
                "did:web:alice.example#device-phone",
                Some("app.example.android")
            )
            .is_some()
        );
        assert!(find_registration_by_token(&states, "fcm:moved-token").is_some());
        assert!(token_moved_to_different_device(
            &states,
            Some("did:web:alice.example"),
            "did:web:alice.example#device-tablet",
            "fcm:moved-token"
        ));

        let with_error = state.mark_last_error(
            "temporarily_unavailable",
            Some("cx:req:1"),
            Some("1"),
            Some("2026-05-02T00:00:00Z"),
        );
        assert_eq!(
            with_error
                .last_error
                .as_ref()
                .map(|error| error.kind.as_str()),
            Some("temporarily_unavailable")
        );
    }

    #[test]
    fn merge_registration_state_replaces_logical_duplicates_and_token_moves() {
        let old_phone = state_for(
            "did:web:alice.example#device-phone",
            "fcm:old-phone-token",
            "reg-old-phone",
        );
        let moved_token = state_for(
            "did:web:alice.example#device-tablet",
            "fcm:new-phone-token",
            "reg-tablet",
        );
        let merged = merge_registration_state(
            &[old_phone.clone(), moved_token],
            state_for(
                "did:web:alice.example#device-phone",
                "fcm:new-phone-token",
                "reg-new-phone",
            ),
        );

        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].registration_id.as_deref(), Some("reg-new-phone"));
        assert_eq!(merged[0].device_id, "did:web:alice.example#device-phone");
    }

    #[test]
    fn repair_plan_cleans_up_old_token_after_register_new_first_success() {
        let old_state = state_for(
            "did:web:alice.example#device-phone",
            "fcm:old-token",
            "reg-old",
        );
        let new_state = state_for(
            "did:web:alice.example#device-phone",
            "fcm:new-token",
            "reg-new",
        );
        let plan = plan_registration_repair(
            &[old_state.clone(), new_state.clone()],
            &config("fcm:new-token"),
            &prefs(),
        )
        .unwrap();

        assert_eq!(
            plan.active_state
                .as_ref()
                .and_then(|state| state.registration_id.as_deref()),
            Some("reg-new")
        );
        assert_eq!(plan.stale_states.len(), 1);
        assert_eq!(
            plan.unregister_stale[0].registration_id.as_deref(),
            Some("reg-old")
        );
        assert!(plan.register_current.is_none());
        assert!(plan.stale_state_detected);
    }

    #[test]
    fn repair_plan_recovers_stale_same_device_state_and_registers_current_token() {
        let stale_state = state_for(
            "did:web:alice.example#device-phone",
            "fcm:old-token",
            "reg-old",
        );
        let plan =
            plan_registration_repair(&[stale_state], &config("fcm:new-token"), &prefs()).unwrap();

        assert!(plan.active_state.is_none());
        assert_eq!(plan.stale_states.len(), 1);
        assert_eq!(
            plan.unregister_stale[0].registration_id.as_deref(),
            Some("reg-old")
        );
        assert_eq!(
            plan.register_current
                .as_ref()
                .map(|request| request.push_key.as_str()),
            Some("fcm:new-token")
        );
    }

    #[test]
    fn repair_plan_detects_token_moved_from_another_device() {
        let tablet_state = state_for(
            "did:web:alice.example#device-tablet",
            "fcm:moved-token",
            "reg-tablet",
        );
        let plan = plan_registration_repair(&[tablet_state], &config("fcm:moved-token"), &prefs())
            .unwrap();

        assert!(plan.token_moved);
        assert_eq!(plan.stale_states.len(), 1);
        assert_eq!(
            plan.unregister_stale[0].registration_id.as_deref(),
            Some("reg-tablet")
        );
        assert_eq!(
            plan.register_current
                .as_ref()
                .map(|request| request.push_key.as_str()),
            Some("fcm:moved-token")
        );
    }
}
