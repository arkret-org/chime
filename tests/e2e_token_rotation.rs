//! E2E skeleton: push-token rotation.
//!
//! Round 2 (post-improve) — placeholder coverage for the
//! "device rotates its push token, server reclaims the old registration
//! and binds the new token" flow. Uses `previous_token_hash` (set by
//! the rotation path on `ChimePushRegisterDeviceRequest`) to correlate the new
//! registration with the old one.
//!
//! Gating: these tests are `#[ignore]` because they require a live
//! floria binary (CI sets `CHIME_INTEGRATION_REQUIRED=1` and supplies
//! `FLORIA_BIN`). Local developers should skip this file; the CI
//! floria-gated job runs the suite explicitly with
//! `cargo test --features http,notify -- --ignored e2e_token_rotation`.

#![cfg(all(feature = "http", feature = "notify"))]

use chime::{
    ChimePushRegisterDeviceRequest, GatewayBinding, PushDeviceConfig, PushGatewayType,
    PushPreferences, build_register_device_request,
};
use sha2::{Digest, Sha256};

const DEVICE_ID: &str = "did:web:rotation.test#device-phone";
const APP_ID: &str = "test.rotation.app";
const GATEWAY: &str = "https://push.gateway.example/_cokret/edge/push/notify";

fn config_for_token<'a>(token: &'a str, idempotency: &'a str) -> PushDeviceConfig<'a> {
    PushDeviceConfig {
        principal_id: Some("did:web:rotation.test"),
        device_id: DEVICE_ID,
        push_key: Some(token),
        platform: Some("android"),
        app_id: Some(APP_ID),
        domestic_app_id: None,
        registration_id: None,
        display_name: Some("Rotation Test Phone"),
        idempotency_key: Some(idempotency),
        request_id: Some("ck:request:rotation-test-001"),
        proof: None,
    }
}

fn fixture_binding() -> GatewayBinding {
    GatewayBinding::new(PushGatewayType::Standard, GATEWAY)
}

fn fixture_prefs() -> PushPreferences {
    PushPreferences {
        enabled: true,
        ..Default::default()
    }
}

fn sha256_hex(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    let mut out = String::with_capacity(digest.len() * 2);
    use std::fmt::Write as _;
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "CI floria-gated: requires live floria + CHIME_INTEGRATION_REQUIRED=1"]
async fn token_rotation_reclaims_old_registration() {
    // PLAN (round 3 fill-in):
    //   1. Spawn floria via `_helpers/floria_spawn::require_floria_or_skip`.
    //   2. Register the OLD token; capture `registration_id_old`.
    //   3. Build the NEW registration with `previous_token_hash = sha256_hex(old_token)`.
    //   4. POST the new registration; assert response carries `registration_id_new` AND a
    //      warning/marker indicating the old registration was reclaimed.
    //   5. List registrations and assert exactly ONE survives (the new one) for `device_id =
    //      DEVICE_ID`.
    let old_token = "fcm:rotation-token-OLD";
    let new_token = "fcm:rotation-token-NEW";
    let binding = fixture_binding();
    let prefs = fixture_prefs();

    let old_request: ChimePushRegisterDeviceRequest =
        build_register_device_request(&config_for_token(old_token, "rot-old"), &binding, &prefs)
            .expect("old token request builds");

    let mut new_request: ChimePushRegisterDeviceRequest =
        build_register_device_request(&config_for_token(new_token, "rot-new"), &binding, &prefs)
            .expect("new token request builds");
    new_request.previous_token_hash = Some(format!("sha256:{}", sha256_hex(old_token)));

    assert_eq!(old_request.device_id, new_request.device_id);
    assert_ne!(old_request.push_key, new_request.push_key);
    assert!(
        new_request.previous_token_hash.is_some(),
        "rotation MUST carry previous_token_hash",
    );
    // Real assertion lands once floria_spawn supports describe.
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "CI floria-gated: requires live floria + CHIME_INTEGRATION_REQUIRED=1"]
async fn token_rotation_rejects_mismatched_previous_hash() {
    // PLAN: when `previous_token_hash` does not match any known
    // registration, the gateway MUST refuse the rotation rather than
    // silently treating the request as a fresh registration. Caller
    // expects a 4xx with a stable failure code.
    let new_token = "fcm:rotation-token-NEW";
    let mut request: ChimePushRegisterDeviceRequest = build_register_device_request(
        &config_for_token(new_token, "rot-bad"),
        &fixture_binding(),
        &fixture_prefs(),
    )
    .expect("request builds");
    request.previous_token_hash = Some(format!("sha256:{}", sha256_hex("unknown-token")));

    assert!(request.previous_token_hash.is_some());
    // Real assertion lands once floria_spawn supports describe.
}
