//! Shared test fixtures for `state` sub-modules.
//!
//! Compiled only under `cfg(test)`.

use super::model::{PushRegistrationState, build_registration_state};
use crate::{
    ChimePushRegisterDeviceOutcome, GatewayBinding, PushDeviceConfig, PushGatewayType,
    PushPreferences, build_register_device_request,
};

pub(crate) const TEST_PUSH_GATEWAY: &str = "https://push.example.com/_cokret/edge/push/notify";

pub(crate) fn prefs() -> PushPreferences {
    PushPreferences {
        enabled: true,
        ..Default::default()
    }
}

pub(crate) fn binding() -> GatewayBinding {
    GatewayBinding::new(PushGatewayType::Standard, TEST_PUSH_GATEWAY)
}

pub(crate) fn config(push_key: &str) -> PushDeviceConfig<'_> {
    PushDeviceConfig {
        principal_id: Some("did:web:alice.example"),
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

pub(crate) fn state_for(
    device_id: &'static str,
    token: &'static str,
    registration_id: &'static str,
) -> PushRegistrationState {
    state_for_gateway(
        device_id,
        token,
        registration_id,
        TEST_PUSH_GATEWAY.to_owned(),
    )
}

pub(crate) fn state_for_gateway(
    device_id: &'static str,
    token: &'static str,
    registration_id: &'static str,
    push_gateway: String,
) -> PushRegistrationState {
    state_for_binding(
        device_id,
        token,
        registration_id,
        push_gateway,
        PushGatewayType::Standard,
        None,
    )
}

pub(crate) fn state_for_binding(
    device_id: &'static str,
    token: &'static str,
    registration_id: &'static str,
    push_gateway: String,
    gateway_type: PushGatewayType,
    app_id: Option<&'static str>,
) -> PushRegistrationState {
    let mut device_config = config(token);
    device_config.device_id = device_id;
    device_config.registration_id = Some(registration_id);
    if let Some(app_id) = app_id {
        device_config.app_id = Some(app_id);
    }

    let binding = GatewayBinding::new(gateway_type, push_gateway);

    let request = build_register_device_request(&device_config, &binding, &prefs()).unwrap();
    let response = ChimePushRegisterDeviceOutcome {
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

    build_registration_state(&binding, &request, &response, Some("2026-05-03T00:00:00Z"))
}
