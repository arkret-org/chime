//! `push_target_id` unlinkability gate tests.
//!
//! Spec: `arkret-spec/spec/v1/zh/crypto-media/device-lifecycle.md` §5a.3.
//! These tests lock the SDK side of the privacy contract: chime never
//! lets `device_id`, `push_key`, `principal_id`, `email`, or phone
//! number leak into a `PushTargetId`. The actual entropy / randomness
//! comes from the device's local secret store, which is out of scope
//! for this crate — we only assert that the SDK refuses to *help*
//! callers smuggle linkable data through the wire shape.

#![cfg(feature = "notify")]

use chime::{PushRoute, PushRouteCapability, PushRouteId, PushTargetId, ServiceId, WakeupKind};

/// `PushTargetId::new` must reject anything that looks like a DID, a
/// device handle, an email, or a phone number — regardless of how the
/// caller dressed it up.
#[test]
fn target_id_rejects_principal_or_device_identifiers() {
    let identifiers = [
        // DID forms
        "did:web:alice.example",
        "did:key:z6Mki...alice...000000",
        "DID:web:alice.example",
        // device DID URLs
        "did:web:alice.example#device-phone",
        // arkret typed ids
        "ak:device:01HYZ8Z000000000000000",
        "ak:realm:01HYZ8Z000000000000000",
        "ak:space:01HYZ8Z000000000000000",
    ];
    for value in identifiers {
        assert!(
            PushTargetId::new(value).is_err(),
            "expected {value:?} to be rejected as a push_target_id"
        );
    }
}

/// Two distinct base64url tokens for the same logical device must
/// remain typed-equal only if they are byte-for-byte identical. There
/// is no canonicalization that "merges" different randoms into the
/// same id — that's how the SDK promises unlinkability across
/// rotations.
#[test]
fn rotated_target_ids_compare_strictly_byte_equal() {
    let route_a = PushTargetId::new("ak:pseudonym:push:01HYZ8Z000000000000000").unwrap();
    let route_b = PushTargetId::new("ak:pseudonym:push:01HYZ8Z000000000000001").unwrap();
    let route_a_again = PushTargetId::new("ak:pseudonym:push:01HYZ8Z000000000000000").unwrap();

    assert_eq!(route_a, route_a_again);
    assert_ne!(
        route_a, route_b,
        "different randoms must hash and compare unequal"
    );

    // The SDK doesn't normalize case or strip the prefix —
    // anything different stays different.
    let raw_form = PushTargetId::new("01HYZ8Z000000000000000").unwrap();
    assert_ne!(route_a, raw_form);
}

/// The SDK never derives a `PushTargetId` from a `device_id` or
/// `push_key`. We can't statically prove "no derivation" but we *can*
/// pin the validator: anything that looks remotely token-shaped that
/// also embeds a device identifier or a push token MUST be rejected.
#[test]
fn target_id_rejects_strings_carrying_device_or_token_material() {
    let leaks = [
        // FCM token shapes
        "fcm:eJx9k2-very-secret-token-aaa",
        // APNs token shapes
        "apns:01abcdef01abcdef01abcdef01abcdef",
        // Random typed-id with device-like substring
        "ak:device:fcm:eJx9k2-aaaaaaaaaaaaa",
    ];
    for value in leaks {
        assert!(
            PushTargetId::new(value).is_err(),
            "expected {value:?} to be rejected"
        );
    }
}

/// A device may have several `(push_route, push_target_id)` pairs.
/// The SDK must allow them to coexist with distinct ids and reject any
/// route whose `push_target_id` was already used in a different route
/// only if the caller wires that check in. Here we lock the *positive*
/// behaviour: distinct routes serialize / deserialize without losing
/// pseudonyms.
#[test]
fn multiple_routes_per_device_keep_distinct_pseudonyms() {
    // T4.1: active routes are scoped to a recipient Principal Server
    // by their cell_subject quadruple, so the constructor now requires
    // a `recipient_service_id`. We use the same DID for both routes
    // because both belong to the same device on the same server.
    let recipient = ServiceId::new("did:web:principal.example").unwrap();
    let main = PushRoute::active(
        recipient.clone(),
        PushRouteId::new("apns_main").unwrap(),
        PushTargetId::new("ak:pseudonym:push:01HYZ8Z000000000000ABC").unwrap(),
        "did:web:gateway.example",
    );
    let voip = {
        let mut r = PushRoute::active(
            recipient,
            PushRouteId::new("fcm_voip").unwrap(),
            PushTargetId::new("ak:pseudonym:push:01HYZ8Z000000000000XYZ").unwrap(),
            "did:web:gateway.example",
        );
        r.capabilities.push(PushRouteCapability::Voip);
        r
    };

    assert_ne!(main.push_target_id, voip.push_target_id);

    let main_json = serde_json::to_string(&main).unwrap();
    let voip_json = serde_json::to_string(&voip).unwrap();
    assert!(!main_json.contains("XYZ"));
    assert!(!voip_json.contains("ABC"));

    let restored: PushRoute = serde_json::from_str(&main_json).unwrap();
    assert_eq!(restored, main);
}

/// `PushTargetId` must round-trip through serde without leaking into
/// either a panic or a normalization that could collide two distinct
/// devices' pseudonyms.
#[test]
fn target_id_serde_round_trip_preserves_byte_form() {
    let value = "ak:pseudonym:push:abc-DEF_ghi-JKL_mno-PQR_stu";
    let id = PushTargetId::new(value).unwrap();
    let json = serde_json::to_string(&id).unwrap();
    assert_eq!(json, format!("\"{value}\""));
    let back: PushTargetId = serde_json::from_str(&json).unwrap();
    assert_eq!(back.as_str(), value);
}

/// Sanity: `WakeupKind` carries no identifying material — it stringifies
/// to a small fixed vocabulary, never to a Space id or sender DID.
#[test]
fn wakeup_kind_serializes_to_opaque_vocabulary_only() {
    for kind in [
        WakeupKind::Message,
        WakeupKind::Mention,
        WakeupKind::Reaction,
        WakeupKind::CallInvite,
    ] {
        let json = serde_json::to_string(&kind).unwrap();
        assert!(!json.contains("did:"), "wakeup_kind leaked DID: {json}");
        assert!(!json.contains("ak:"), "wakeup_kind leaked typed id: {json}");
    }
}
