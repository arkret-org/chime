//! Local registration state repair planning.
// CH-3 evaluated 2026-05-18: coupling too tight to push-token state for
// clean SDK extraction; revisit if starid/teabay need similar logic.
//
// Every plan function here takes `PushRegistrationState` (which carries
// `push_gateway`, `push_key_hash`, `push_key_preview`, `platform`,
// `app_id`), `PushDeviceConfig`, a `GatewayBinding`, and
// `PushPreferences`, and emits `ChimePushRegisterDeviceRequest` /
// `ChimePushUnregisterDeviceRequest` wire bodies — all push-specific types. The
// pure "policy" logic (`registration_state_rank` and same-token /
// same-logical matching) is ~30 LoC and structurally specific to push:
// it ranks states by `registration_id`/`last_success_at` and equates
// records by the push tuple. Generifying every type parameter would
// produce an empty trait skeleton; inventing abstract registration
// types would force chime to translate on every call. A grep of
// starid/teabay confirms no existing registration-state-machine
// consumers (starid's "prerotation" is DID key prerotation, unrelated;
// teabay has no client-side device registration). Revisit if either
// service grows a per-device retry/repair lifecycle.

use serde::{Deserialize, Serialize};

use super::model::{PushRegistrationState, build_unregister_request_for_state, hash_push_key};
use crate::{
    GatewayBinding, PushDeviceConfig, PushPlatform, PushPreferences, ChimePushRegisterDeviceRequest,
    PushRegistrationError, ChimePushUnregisterDeviceRequest, build_register_device_request,
};

/// Aggregated repair plan across every binding in
/// [`PushPreferences::gateways`](crate::PushPreferences::gateways).
///
/// Each binding gets its own [`PushRegistrationRepairPlan`]; states whose
/// `push_gateway` does not match any binding are surfaced as orphans so
/// the host app can unregister them after a gateway has been removed
/// from `gateways`.
///
/// Stability: `1.0`-stable. New optional fields are added with
/// `#[serde(default)]`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct PushMultiGatewayRepairPlan {
    /// Per-binding repair plans, in the same order as
    /// [`PushPreferences::gateways`](crate::PushPreferences::gateways).
    #[serde(default)]
    pub per_binding: Vec<PushRegistrationRepairPlan>,
    /// Persisted states whose `push_gateway` does not match any current
    /// binding. Typically left over from a gateway that has since been
    /// removed from `prefs.gateways`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub orphan_states: Vec<PushRegistrationState>,
    /// Pre-built unregister requests for the orphan states.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unregister_orphans: Vec<ChimePushUnregisterDeviceRequest>,
}

impl PushMultiGatewayRepairPlan {
    /// Whether any binding or orphan list contains a stale entry.
    pub fn stale_state_detected(&self) -> bool {
        !self.orphan_states.is_empty()
            || self
                .per_binding
                .iter()
                .any(|plan| plan.stale_state_detected)
    }

    /// Whether any binding observed a token-moved-from-another-device.
    pub fn token_moved(&self) -> bool {
        self.per_binding.iter().any(|plan| plan.token_moved)
    }
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
    pub unregister_stale: Vec<ChimePushUnregisterDeviceRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub register_current: Option<ChimePushRegisterDeviceRequest>,
    #[serde(default)]
    pub stale_state_detected: bool,
    #[serde(default)]
    pub token_moved: bool,
}

/// Build a repair plan for stale local registration state, scoped to
/// a single gateway binding.
///
/// This helper covers common real-world recovery paths:
/// - `register-new-first` succeeded but `unregister-old` still needs cleanup.
/// - `unregister-old-first` ran, but local state still points at the old token.
/// - the same token was moved to another logical device/app registration.
pub fn plan_registration_repair(
    states: &[PushRegistrationState],
    config: &PushDeviceConfig<'_>,
    binding: &GatewayBinding,
    prefs: &PushPreferences,
) -> Result<PushRegistrationRepairPlan, PushRegistrationError> {
    let current_push_key = binding
        .push_key
        .as_deref()
        .or(config.push_key)
        .and_then(|value| {
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
    let current_app_id = binding
        .resolve_app_id(
            current_platform
                .as_deref()
                .map(PushPlatform::try_from)
                .transpose()?,
            config.app_id,
            config.domestic_app_id,
        )
        .map(str::to_owned);

    let mut active_state = None::<PushRegistrationState>;
    let mut stale_states: Vec<PushRegistrationState> = Vec::with_capacity(states.len());
    let mut token_moved = false;

    for state in states {
        let same_logical = state.principal_id.as_deref() == config.principal_id
            && state.device_id == config.device_id
            && state.platform.as_deref() == current_platform.as_deref()
            && state.app_id.as_deref() == current_app_id.as_deref()
            && state.push_gateway == binding.push_gateway;
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
        Some(build_register_device_request(config, binding, prefs)?)
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

/// Build a repair plan for every binding in
/// [`PushPreferences::gateways`](crate::PushPreferences::gateways).
///
/// Each binding is planned independently against the subset of
/// `states` whose `push_gateway` URL matches that binding. States whose
/// `push_gateway` does not match any binding are returned as
/// [`orphan_states`](PushMultiGatewayRepairPlan::orphan_states) so the
/// caller can unregister them after a gateway has been removed from
/// `prefs.gateways`.
///
/// Per-binding `push_key` and `app_id` overrides on the
/// [`GatewayBinding`](crate::GatewayBinding) take priority over the
/// values in `config` — mirroring
/// [`CokretPushClient::register_device_all`](crate::CokretPushClient::register_device_all)
/// (when the `http` feature is enabled).
///
/// When `prefs.gateways` is empty, the per-binding list is empty and
/// every persisted state is surfaced as an orphan.
pub fn plan_multi_gateway_repair(
    states: &[PushRegistrationState],
    config: &PushDeviceConfig<'_>,
    prefs: &PushPreferences,
) -> Result<PushMultiGatewayRepairPlan, PushRegistrationError> {
    let mut per_binding = Vec::with_capacity(prefs.gateways.len());
    let mut claimed = vec![false; states.len()];

    for binding in &prefs.gateways {
        let owned: Vec<PushRegistrationState> = states
            .iter()
            .enumerate()
            .filter_map(|(i, state)| {
                if state.push_gateway == binding.push_gateway {
                    claimed[i] = true;
                    Some(state.clone())
                } else {
                    None
                }
            })
            .collect();

        per_binding.push(plan_registration_repair(&owned, config, binding, prefs)?);
    }

    let orphan_states: Vec<PushRegistrationState> = states
        .iter()
        .enumerate()
        .filter(|(i, _)| !claimed[*i])
        .map(|(_, state)| state.clone())
        .collect();

    let unregister_orphans = orphan_states
        .iter()
        .map(|state| build_unregister_request_for_state(state, config, prefs))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(PushMultiGatewayRepairPlan {
        per_binding,
        orphan_states,
        unregister_orphans,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::test_fixtures::{
        binding, config, prefs, state_for, state_for_binding, state_for_gateway,
    };
    use crate::{GatewayBinding, PushGatewayType};

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
            &[old_state, new_state],
            &config("fcm:new-token"),
            &binding(),
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
        let plan = plan_registration_repair(
            &[stale_state],
            &config("fcm:new-token"),
            &binding(),
            &prefs(),
        )
        .unwrap();

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
        let plan = plan_registration_repair(
            &[tablet_state],
            &config("fcm:moved-token"),
            &binding(),
            &prefs(),
        )
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

    fn multi_gateway_prefs() -> PushPreferences {
        PushPreferences {
            enabled: true,
            gateways: vec![
                GatewayBinding::new(
                    PushGatewayType::Standard,
                    "https://gw-a.example.com/_cokret/edge/push/notify",
                ),
                GatewayBinding::new(
                    PushGatewayType::Bugle,
                    "https://gw-b.example.com/_cokret/edge/push/notify",
                )
                .with_push_key("vendor-token-cn-aaaaaaaaaa")
                .with_app_id("app.example.android.cn"),
            ],
            ..Default::default()
        }
    }

    #[test]
    fn multi_gateway_repair_filters_states_by_binding_gateway() {
        let prefs = multi_gateway_prefs();
        let state_a = state_for_gateway(
            "did:web:alice.example#device-phone",
            "fcm:current-token",
            "reg-a",
            "https://gw-a.example.com/_cokret/edge/push/notify".to_owned(),
        );
        // gw-b binding overrides push_key to vendor-token-cn-aaaaaaaaaa
        // and app_id to app.example.android.cn (Bugle on Android), so the
        // persisted state must match that binding's resolution to be claimed.
        let state_b = state_for_binding(
            "did:web:alice.example#device-phone",
            "vendor-token-cn-aaaaaaaaaa",
            "reg-b",
            "https://gw-b.example.com/_cokret/edge/push/notify".to_owned(),
            PushGatewayType::Bugle,
            Some("app.example.android.cn"),
        );
        let plan =
            plan_multi_gateway_repair(&[state_a, state_b], &config("fcm:current-token"), &prefs)
                .unwrap();

        assert_eq!(plan.per_binding.len(), 2);
        assert_eq!(
            plan.per_binding[0]
                .active_state
                .as_ref()
                .and_then(|state| state.registration_id.as_deref()),
            Some("reg-a")
        );
        assert_eq!(
            plan.per_binding[1]
                .active_state
                .as_ref()
                .and_then(|state| state.registration_id.as_deref()),
            Some("reg-b")
        );
        assert!(plan.orphan_states.is_empty());
        assert!(!plan.stale_state_detected());
    }

    #[test]
    fn multi_gateway_repair_surfaces_orphan_states_from_removed_gateway() {
        let prefs = multi_gateway_prefs();
        let orphan = state_for_gateway(
            "did:web:alice.example#device-phone",
            "fcm:current-token",
            "reg-orphan",
            "https://gw-removed.example.com/_cokret/edge/push/notify".to_owned(),
        );
        let plan =
            plan_multi_gateway_repair(&[orphan], &config("fcm:current-token"), &prefs).unwrap();

        // Each binding has nothing to claim → register_current is set.
        assert!(plan.per_binding[0].register_current.is_some());
        assert!(plan.per_binding[1].register_current.is_some());
        // The removed gateway's state is surfaced as an orphan.
        assert_eq!(plan.orphan_states.len(), 1);
        assert_eq!(plan.unregister_orphans.len(), 1);
        assert_eq!(
            plan.unregister_orphans[0].registration_id.as_deref(),
            Some("reg-orphan")
        );
        assert_eq!(
            plan.unregister_orphans[0].push_gateway.as_deref(),
            Some("https://gw-removed.example.com/_cokret/edge/push/notify")
        );
        assert!(plan.stale_state_detected());
    }

    #[test]
    fn multi_gateway_repair_does_not_cross_pollinate_token_moves() {
        // Same token registered legitimately with two different gateways.
        // The single-gateway plan would mark the gw-b state as a token-move
        // when planning gw-a; the multi-gateway plan must isolate per binding.
        let prefs = PushPreferences {
            enabled: true,
            gateways: vec![
                GatewayBinding::new(
                    PushGatewayType::Standard,
                    "https://gw-a.example.com/_cokret/edge/push/notify",
                ),
                GatewayBinding::new(
                    PushGatewayType::Standard,
                    "https://gw-b.example.com/_cokret/edge/push/notify",
                ),
            ],
            ..Default::default()
        };
        let state_a = state_for_gateway(
            "did:web:alice.example#device-phone",
            "fcm:shared-token",
            "reg-a",
            "https://gw-a.example.com/_cokret/edge/push/notify".to_owned(),
        );
        let state_b = state_for_gateway(
            "did:web:alice.example#device-phone",
            "fcm:shared-token",
            "reg-b",
            "https://gw-b.example.com/_cokret/edge/push/notify".to_owned(),
        );
        let plan =
            plan_multi_gateway_repair(&[state_a, state_b], &config("fcm:shared-token"), &prefs)
                .unwrap();

        for binding_plan in &plan.per_binding {
            assert!(binding_plan.active_state.is_some());
            assert!(binding_plan.stale_states.is_empty());
            assert!(!binding_plan.token_moved);
        }
        assert!(!plan.token_moved());
    }

    #[test]
    fn multi_gateway_repair_surfaces_every_state_as_orphan_when_gateways_empty() {
        let stale = state_for(
            "did:web:alice.example#device-phone",
            "fcm:old-token",
            "reg-old",
        );
        let plan = plan_multi_gateway_repair(&[stale], &config("fcm:new-token"), &prefs()).unwrap();

        assert!(plan.per_binding.is_empty());
        assert_eq!(plan.orphan_states.len(), 1);
        assert_eq!(plan.unregister_orphans.len(), 1);
    }
}
