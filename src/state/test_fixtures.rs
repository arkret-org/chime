//! Shared test fixtures for `state` sub-modules.
//!
//! Compiled only under `cfg(test)`.

use crate::{GatewayBinding, PushDeviceConfig, PushGatewayType, PushPreferences};

pub(crate) const TEST_PUSH_GATEWAY: &str = "https://push.example.com/_arkret/edge/push/notify";

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
        principal_id: Some(arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap()),
        device_id: "ak:device:01904100-0000-7000-8000-000000000004",
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
