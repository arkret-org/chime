//! E2E skeleton: push-registration deduplication.
//!
//! Round 2 (post-improve) — placeholder coverage for the
//! "same (device_id, push_key) registered twice MUST collapse to a
//! single gateway-side registration" invariant. The fixtures and
//! assertions sketch the shape the real test will take once the
//! `_helpers/floria_spawn.rs` harness exposes a way to seed an
//! initial registration row from outside the system-under-test.
//!
//! Gating: these tests are `#[ignore]` because they require a live
//! floria binary (CI sets `CHIME_INTEGRATION_REQUIRED=1` and supplies
//! `FLORIA_BIN`). Local developers should skip this file; the CI
//! floria-gated job runs the suite explicitly with
//! `cargo test --features http,notify -- --ignored e2e_registration_dedup`.

#![cfg(all(feature = "http", feature = "notify"))]

use chime::{
    GatewayBinding, OPERATION_PUSH_REGISTER_DEVICE, PushDeviceConfig, PushGatewayType,
    PushPreferences, RegisterDeviceRequest, build_register_device_request,
};

const GATEWAY_URL: &str = "https://push.gateway.example/api/v1/push/notify";

fn fixture_device_config<'a>(idempotency: &'a str) -> PushDeviceConfig<'a> {
    PushDeviceConfig {
        principal_did: Some("did:web:dedup.test"),
        device_id: "did:web:dedup.test#device-phone",
        push_key: Some("fcm:dedup-token-001"),
        platform: Some("android"),
        app_id: Some("test.dedup.app"),
        domestic_app_id: None,
        registration_id: None,
        display_name: Some("Dedup Test Phone"),
        idempotency_key: Some(idempotency),
        request_id: Some("cx:request:dedup-test-001"),
        proof: None,
    }
}

fn fixture_binding() -> GatewayBinding {
    GatewayBinding::new(PushGatewayType::Standard, GATEWAY_URL)
}

fn fixture_prefs() -> PushPreferences {
    PushPreferences {
        enabled: true,
        ..Default::default()
    }
}

fn fixture_register_request(idempotency: &str) -> RegisterDeviceRequest {
    build_register_device_request(
        &fixture_device_config(idempotency),
        &fixture_binding(),
        &fixture_prefs(),
    )
    .expect("fixture builds")
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "CI floria-gated: requires live floria + CHIME_INTEGRATION_REQUIRED=1"]
async fn duplicate_registration_idempotently_collapses() {
    // PLAN (round 3 fill-in):
    //   1. Spawn floria via `_helpers/floria_spawn::require_floria_or_skip`.
    //   2. POST `fixture_register_request("dedup-key-001")` and capture
    //      `registration_id`.
    //   3. POST the SAME body again with the SAME idempotency_key.
    //   4. Assert the second response carries the same registration_id
    //      and `warnings` contains a "duplicate-safe" marker.
    //   5. List registrations via the admin/describe endpoint and
    //      assert only ONE row exists for (device_id, push_key).
    let request = fixture_register_request("dedup-key-001");
    assert_eq!(request.operation_id, OPERATION_PUSH_REGISTER_DEVICE);
    assert_eq!(request.device_id, "did:web:dedup.test#device-phone");
    assert_eq!(request.idempotency_key.as_deref(), Some("dedup-key-001"));
    // Real assertion lands once floria_spawn supports describe.
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "CI floria-gated: requires live floria + CHIME_INTEGRATION_REQUIRED=1"]
async fn duplicate_registration_with_distinct_idempotency_keys_dedupes() {
    // PLAN: same (device_id, push_key) but a different idempotency
    // key MUST still dedupe at the gateway (idempotency_key is a
    // client-side retry hint, NOT a registration identity component).
    let a = fixture_register_request("dedup-key-A");
    let b = fixture_register_request("dedup-key-B");
    assert_eq!(a.device_id, b.device_id);
    assert_eq!(a.push_key, b.push_key);
    assert_ne!(a.idempotency_key, b.idempotency_key);
    // Real assertion lands once floria_spawn supports describe.
}
