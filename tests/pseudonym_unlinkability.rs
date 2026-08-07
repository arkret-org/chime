//! `push_target_id` unlinkability gate tests.

#![cfg(feature = "notify")]

use chime::{PushRoute, PushRouteCapability, PushRouteId, ServiceId};

#[test]
fn sdk_validator_rejects_principal_or_device_identifiers() {
    for value in [
        "did:web:alice.example",
        "did:web:alice.example#device-phone",
        "ak:device:01HYZ8Z000000000000000",
        "ak:realm:01HYZ8Z000000000000000",
        "fcm:eJx9k2-very-secret-token-aaa",
    ] {
        assert!(!arkret::blind_payload_sanitizer::is_valid_push_target_id(
            value
        ));
    }
}

#[test]
fn multiple_routes_keep_distinct_sdk_owned_pseudonyms() {
    let recipient = ServiceId::new("did:web:principal.example").unwrap();
    let main = PushRoute::active(
        recipient.clone(),
        PushRouteId::new("apns_main").unwrap(),
        "ak:pseudonym:push:01HYZ8Z000000000000ABC".to_owned(),
        "did:web:gateway.example",
    );
    let voip = {
        let mut route = PushRoute::active(
            recipient,
            PushRouteId::new("fcm_voip").unwrap(),
            "ak:pseudonym:push:01HYZ8Z000000000000XYZ".to_owned(),
            "did:web:gateway.example",
        );
        route.capabilities.push(PushRouteCapability::Voip);
        route
    };
    main.validate().unwrap();
    voip.validate().unwrap();
    assert_ne!(main.push_target_id, voip.push_target_id);
}

#[test]
fn wakeup_vocabulary_contains_no_identifying_material() {
    for kind in ["message", "mention", "reaction", "call_invite"] {
        assert!(arkret::blind_payload_sanitizer::is_valid_wakeup_kind(kind));
        assert!(!kind.contains("did:"));
        assert!(!kind.contains("ak:"));
    }
}
