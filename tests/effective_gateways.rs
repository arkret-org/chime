//! Integration tests for [`PushPreferences::effective_gateways`].
//!
//! `effective_gateways()` is the canonical place callers learn which gateway
//! bindings to deliver to. It must give us the right list whether the caller
//! configured zero, one, or many bindings — single-gateway callers stay on the
//! legacy singular `gateway_type` / `push_gateway` fields, multi-gateway
//! callers populate `gateways`. These tests pin that fallback rule so the two
//! shapes cannot silently diverge.
//!
//! CH-2.

use chime::{GatewayBinding, PushGatewayType, PushPreferences};

/// When `gateways` is empty, the legacy singular `(gateway_type, push_gateway)`
/// pair must be synthesized into a one-element binding.
#[test]
fn empty_gateways_falls_back_to_singular_pair() {
    let prefs = PushPreferences {
        enabled: true,
        gateway_type: PushGatewayType::Standard,
        push_gateway: "https://push.example.com/api/v1/push/notify".to_owned(),
        ..Default::default()
    };

    let resolved = prefs.effective_gateways();

    assert_eq!(resolved.len(), 1, "fallback must produce exactly one binding");
    assert_eq!(resolved[0].gateway_type, PushGatewayType::Standard);
    assert_eq!(
        resolved[0].push_gateway,
        "https://push.example.com/api/v1/push/notify"
    );
    assert!(
        resolved[0].push_key.is_none(),
        "synthetic binding has no push key by construction"
    );
    assert!(
        resolved[0].app_id.is_none(),
        "synthetic binding has no app id by construction"
    );
}

/// A single explicit binding in `gateways` must be returned as-is. The
/// singular `push_gateway` field is ignored in this branch.
#[test]
fn single_explicit_gateway_takes_precedence_over_singular_field() {
    let prefs = PushPreferences {
        enabled: true,
        gateway_type: PushGatewayType::Standard,
        push_gateway: "https://ignored.example.com/api/v1/push/notify".to_owned(),
        gateways: vec![
            GatewayBinding::new(
                PushGatewayType::Bugle,
                "https://push.palpo.im/api/v1/push/notify",
            )
            .with_app_id("app.example.android.cn"),
        ],
        ..Default::default()
    };

    let resolved = prefs.effective_gateways();

    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].gateway_type, PushGatewayType::Bugle);
    assert_eq!(
        resolved[0].push_gateway,
        "https://push.palpo.im/api/v1/push/notify"
    );
    assert_eq!(
        resolved[0].app_id.as_deref(),
        Some("app.example.android.cn")
    );
    assert_ne!(
        resolved[0].push_gateway, "https://ignored.example.com/api/v1/push/notify",
        "singular push_gateway must NOT leak through when an explicit list is set"
    );
}

/// Multiple bindings must round-trip in original order with full metadata.
#[test]
fn multi_gateway_preserves_order_and_metadata() {
    let prefs = PushPreferences {
        enabled: true,
        gateway_type: PushGatewayType::Standard,
        push_gateway: "https://ignored.example.com/api/v1/push/notify".to_owned(),
        gateways: vec![
            GatewayBinding::new(
                PushGatewayType::Standard,
                "https://push-a.example.com/api/v1/push/notify",
            )
            .with_push_key("vendor-token-a"),
            GatewayBinding::new(
                PushGatewayType::Bugle,
                "https://push.palpo.im/api/v1/push/notify",
            )
            .with_app_id("app.example.android.cn")
            .with_push_key("vendor-token-cn"),
            GatewayBinding::new(
                PushGatewayType::Custom,
                "https://custom.example.com/api/v1/push/notify",
            ),
        ],
        ..Default::default()
    };

    let resolved = prefs.effective_gateways();

    assert_eq!(resolved.len(), 3);
    assert_eq!(resolved[0].gateway_type, PushGatewayType::Standard);
    assert_eq!(resolved[1].gateway_type, PushGatewayType::Bugle);
    assert_eq!(resolved[2].gateway_type, PushGatewayType::Custom);
    assert_eq!(resolved[0].push_key.as_deref(), Some("vendor-token-a"));
    assert_eq!(
        resolved[1].app_id.as_deref(),
        Some("app.example.android.cn")
    );
    assert_eq!(resolved[1].push_key.as_deref(), Some("vendor-token-cn"));
    assert!(resolved[2].push_key.is_none());
}

/// Default preferences have an empty singular `push_gateway` and no explicit
/// `gateways`. The fallback still produces a synthetic binding — callers can
/// then decide whether the empty URL is acceptable.
#[test]
fn default_preferences_fallback_to_empty_singular() {
    let prefs = PushPreferences::default();

    let resolved = prefs.effective_gateways();

    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].gateway_type, PushGatewayType::Standard);
    assert!(
        resolved[0].push_gateway.is_empty(),
        "default has empty push_gateway and we faithfully report it"
    );
}
