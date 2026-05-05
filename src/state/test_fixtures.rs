//! Shared test fixtures for `state` sub-modules.
//!
//! Compiled only under `cfg(test)`.

use crate::{
    PushDeviceConfig, PushPreferences, RegisterDeviceResponse, build_register_device_request,
};

use super::model::{PushRegistrationState, build_registration_state};

pub(crate) fn prefs() -> PushPreferences {
    PushPreferences {
        enabled: true,
        push_gateway: "https://push.example.com/api/v1/push/notify".to_owned(),
        ..Default::default()
    }
}

pub(crate) fn config(push_key: &str) -> PushDeviceConfig<'_> {
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

pub(crate) fn state_for(
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
