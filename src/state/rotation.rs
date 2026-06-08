//! Token rotation planning.
// CH-3 evaluated 2026-05-18: kept local. See `repair.rs` for the full
// rationale; rotation here is a 5-line policy
// (`token_rotation_required` => one bool compare on `push_key_hash`)
// wrapped around `PushRegisterDeviceRequestBody` / `PushUnregisterDeviceRequestBody`
// builders, so a generic SDK shape would not reduce code in any
// current consumer.

use serde::{Deserialize, Serialize};

use super::model::{PushRegistrationState, token_rotation_required};
use crate::{
    GatewayBinding, PushDeviceConfig, PushGatewayType, PushPreferences,
    PushRegisterDeviceRequestBody, PushRegistrationError, PushUnregisterDeviceRequestBody,
    build_register_device_request, build_unregister_device_request,
};

/// Request plan for replacing a platform push token.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct PushTokenRotationPlan {
    pub unregister_old: Option<PushUnregisterDeviceRequestBody>,
    pub register_new: Option<PushRegisterDeviceRequestBody>,
    pub token_changed: bool,
    pub strategy: PushTokenRotationStrategy,
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

pub fn plan_token_rotation(
    existing: Option<&PushRegistrationState>,
    config: &PushDeviceConfig<'_>,
    binding: &GatewayBinding,
    prefs: &PushPreferences,
) -> Result<PushTokenRotationPlan, PushRegistrationError> {
    plan_token_rotation_with_strategy(
        existing,
        config,
        binding,
        prefs,
        PushTokenRotationStrategy::UnregisterOldFirst,
    )
}

pub fn plan_token_rotation_with_strategy(
    existing: Option<&PushRegistrationState>,
    config: &PushDeviceConfig<'_>,
    binding: &GatewayBinding,
    prefs: &PushPreferences,
    strategy: PushTokenRotationStrategy,
) -> Result<PushTokenRotationPlan, PushRegistrationError> {
    let new_push_key = binding
        .push_key
        .as_deref()
        .or(config.push_key)
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
            principal_id: config.principal_id,
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
        let old_binding =
            GatewayBinding::new(PushGatewayType::Standard, state.push_gateway.clone());
        build_unregister_device_request(&old_config, &old_binding, prefs)
    });

    let mut register_new = build_register_device_request(config, binding, prefs)?;
    if let Some(state) = existing {
        register_new.previous_token_hash = Some(state.push_key_hash.clone());
    }

    Ok(PushTokenRotationPlan {
        unregister_old: unregister_old.transpose()?,
        register_new: Some(register_new),
        token_changed: true,
        strategy,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PushRegisterDeviceOutcome;
    use crate::state::model::build_registration_state;
    use crate::state::test_fixtures::{binding, config, prefs};

    #[test]
    fn rotation_plan_is_empty_when_token_unchanged() {
        let request =
            build_register_device_request(&config("fcm:same-token"), &binding(), &prefs()).unwrap();
        let response = PushRegisterDeviceOutcome {
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
        let state = build_registration_state(&binding(), &request, &response, None);

        let plan = plan_token_rotation(
            Some(&state),
            &config("fcm:same-token"),
            &binding(),
            &prefs(),
        )
        .unwrap();

        assert!(!plan.token_changed);
        assert!(plan.unregister_old.is_none());
        assert!(plan.register_new.is_none());
        assert_eq!(plan.strategy, PushTokenRotationStrategy::UnregisterOldFirst);
    }

    #[test]
    fn rotation_plan_unregisters_old_and_registers_new_token() {
        let request =
            build_register_device_request(&config("fcm:old-token"), &binding(), &prefs()).unwrap();
        let response = PushRegisterDeviceOutcome {
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
        let state = build_registration_state(&binding(), &request, &response, None);

        let plan =
            plan_token_rotation(Some(&state), &config("fcm:new-token"), &binding(), &prefs())
                .unwrap();

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
    fn rotation_plan_attaches_previous_token_hash_to_register_request() {
        let request =
            build_register_device_request(&config("fcm:old-token"), &binding(), &prefs()).unwrap();
        let response = PushRegisterDeviceOutcome {
            ok: true,
            registration_id: Some("reg-old".to_owned()),
            ..Default::default()
        };
        let state = build_registration_state(&binding(), &request, &response, None);
        let old_hash = state.push_key_hash.clone();

        let plan =
            plan_token_rotation(Some(&state), &config("fcm:new-token"), &binding(), &prefs())
                .unwrap();

        let attached = plan
            .register_new
            .as_ref()
            .and_then(|request| request.previous_token_hash.clone());
        assert_eq!(attached.as_deref(), Some(old_hash.as_str()));
    }

    #[test]
    fn rotation_plan_omits_previous_token_hash_when_no_existing_state() {
        let plan =
            plan_token_rotation(None, &config("fcm:new-token"), &binding(), &prefs()).unwrap();
        assert!(plan.token_changed);
        assert!(
            plan.register_new
                .as_ref()
                .and_then(|request| request.previous_token_hash.as_ref())
                .is_none()
        );
    }

    #[test]
    fn rotation_plan_supports_register_new_first_strategy() {
        let request =
            build_register_device_request(&config("fcm:old-token"), &binding(), &prefs()).unwrap();
        let response = PushRegisterDeviceOutcome {
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
        let state = build_registration_state(&binding(), &request, &response, None);

        let plan = plan_token_rotation_with_strategy(
            Some(&state),
            &config("fcm:new-token"),
            &binding(),
            &prefs(),
            PushTokenRotationStrategy::RegisterNewFirst,
        )
        .unwrap();

        assert!(plan.token_changed);
        assert_eq!(plan.strategy, PushTokenRotationStrategy::RegisterNewFirst);
        assert!(plan.unregister_old.is_some());
        assert!(plan.register_new.is_some());
    }
}
