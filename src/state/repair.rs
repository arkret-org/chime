//! Local registration state repair planning.

use serde::{Deserialize, Serialize};

use crate::{
    PushDeviceConfig, PushPlatform, PushPreferences, PushRegistrationError, RegisterDeviceRequest,
    UnregisterDeviceRequest, build_register_device_request,
};

use super::model::{PushRegistrationState, build_unregister_request_for_state, hash_push_key};

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::test_fixtures::{config, prefs, state_for};

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
        let plan =
            plan_registration_repair(&[old_state, new_state], &config("fcm:new-token"), &prefs())
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
