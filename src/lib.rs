#![recursion_limit = "256"]

//! # chime
//!
//! Cokret push notification gateway types, preferences, and device
//! registration helpers.
//!
//! This crate provides the shared data types and logic used by Cokret
//! clients to register push-capable devices with a Cokret Principal Server,
//! Sync Service, or delegated Push Gateway.
//!
//! ## Gateway support
//!
//! | Gateway | Description |
//! |---------|-------------|
//! | **Standard** | Cokret Push Gateway using platform adapters such as FCM, APNs, Web Push, or desktop notification bridges. |
//! | **Bugle** | Cokret Push Gateway with domestic Chinese Android OEM provider support through JPush, Huawei, Xiaomi, OPPO, vivo, HONOR, and HarmonyOS routes. |
//! | **Custom** | User-provided gateway URL. |
//!
//! ## Features
//!
//! - `http` - enables `CokretPushClient`, a small reqwest-based helper for `POST
//!   /_cokret/edge/push/register-device` and `POST /_cokret/edge/push/unregister-device`.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// Compile the README's rust code blocks as doc-tests so the public
/// quick-start examples cannot drift away from the actual API.
///
/// `rust,no_run` blocks are compile-checked but not executed (they would
/// require a live service); their live counterparts are exercised in
/// `tests/live_floria_integration.rs`. Plain `rust` blocks are compiled
/// and run.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
mod readme_doctest {}

pub mod bugle;
mod gateway_binding;
mod lifecycle;
#[cfg(feature = "notify")]
mod notify;
mod push;
mod state;

pub use bugle::BugleAppIdResolver;
// Round 4 (B5, spec a77b995) — re-export the SDK round-4 audit surfaces
// chime consumers (yougen, host apps) need for the late-key-recovery banner
// without having to depend on `cokret` directly.
#[cfg(feature = "notify")]
pub use cokret::{AccessKind, AuditPolicyAccessPayload};
pub use gateway_binding::GatewayBinding;
pub use lifecycle::{
    AccountDeactivationError, AccountDeactivationReceipt, AccountDeactivationSink,
    BackgroundFetchDriver, BackgroundFetchHint, BackgroundFetchOutcome,
    ClosureAccountDeactivationSink, DeactivationSource, DeviceSessionInvalidationReason,
    NoopAccountDeactivationSink, NoopBackgroundFetchDriver, on_account_deactivate,
};
#[cfg(feature = "notify")]
pub use notify::{
    AGENT_ACTOR_PRIVATE_KINDS, AGENT_LIFECYCLE_DURABLE_KINDS, AgentEventRouting,
    AgentLifecycleSummary, EncryptedEnvelope, EncryptedEnvelopeError, MentionRedirectRouting,
    PHASE_P2_AGENT_TYPED_ID_PREFIXES, PHASE_P2_LEGACY_FIELD_ALIASES, ProviderRetryHint,
    PushDeliveryReceipt, PushHint, PushNotification, PushNotificationDedup, PushNotificationDevice,
    PushNotifyPolicyContext, PushNotifyPrivacyError, PushNotifyPrivacyMode,
    PushNotifyPrivacyVector, PushNotifyReqBody, PushNotifyResBody, PushTargetId,
    ROUND_R2_R3_SENSITIVE_FIELDS, RejectedPushToken, WakeupKind, assert_no_sensitive_fields,
    classify_agent_event_kind, is_legacy_field_alias, is_phase_p2_agent_typed_id,
    render_agent_lifecycle_summary, shared_push_notify_privacy_vectors,
};
// R3 (CALL-1 / CALL-2, spec b47ff6ec) — media token exchange surface.
// Re-exported so chime consumers (yougen) call
// `chime::call_media_token_exchange` +
// `chime::structurally_validate_media_token_response` without depending on
// `cokret` directly. The validation marker is structure-only; hosts must
// perform Ed25519 signature verification before SFrame keying.
pub use push::{
    CONTENT_DIGEST_HEADER, COKRET_ACTOR_ID_HEADER, COKRET_AUDIENCE_HEADER,
    COKRET_CREATED_AT_HEADER, COKRET_DESTINATION_SERVICE_DID_HEADER, COKRET_DEVICE_ID_HEADER,
    COKRET_EXPIRES_AT_HEADER, COKRET_IDEMPOTENCY_KEY_HEADER, COKRET_NONCE_HEADER,
    COKRET_OPERATION_ID_HEADER, COKRET_ORIGIN_HEADER, COKRET_ORIGIN_SERVICE_DID_HEADER,
    COKRET_REQUEST_ID_HEADER, COKRET_SESSION_GRANT_HEADER, CokretError, CokretErrorEnvelope,
    EXPECTED_SPEC_VERSION, IntegrationView, NonceReplayError, NonceTracker,
    PUSH_BRIDGE_DESCRIBE_PATH, PUSH_INTEGRATION_DESCRIBE_PATH, PUSH_UNSUBSCRIBE_PATH,
    PushBridgeDescribeGatewayDescriptor, PushBridgeDescribeNotifyDescriptor,
    PushBridgeDescribePrivacyDescriptor, PushBridgeDescribeResponse, PushDeviceConfig,
    PushErrorKind, PushGatewayIntegrationDependency, PushGatewayIntegrationDescribeResponse,
    PushGatewayIntegrationSurface, PushPlatform, PushRegistrationError, PushRequestSigningContext,
    PushRequestSigningOptions, PushUnsubscribeRequest, PushUnsubscribeResponse,
    REGISTER_DEVICE_PATH, RegisterDeviceRequest, RegisterDeviceResponse, SIGNATURE_HEADER,
    SIGNATURE_INPUT_HEADER, UNREGISTER_DEVICE_PATH, UnregisterDeviceRequest,
    UnregisterDeviceResponse, build_register_device_request, build_register_signing_context,
    build_register_signing_context_with_options, build_unregister_device_request,
    build_unregister_signing_context, build_unregister_signing_context_with_options,
    build_unsubscribe_request, compute_push_key_hmac, content_digest_sha256, cokret_api_url,
    push_bridge_describe_url, push_gateway_service_base_url, push_integration_describe_url,
    redact_push_key, validate_push_gateway_url, validate_webpush_endpoint_allowlist,
    verify_push_key_binding,
};
#[cfg(feature = "http")]
pub use push::{CokretPushClient, CokretResponse, PushRetryPolicy};
pub use push::{
    DefaultPlatformAppIdResolver, MediaBackendType, MediaTokenError, MediaTokenExchangeRequest,
    MediaTokenResponse, MediaTokenStructuralValidationContext, ParticipantBinding,
    PlatformAppIdResolver, PushRoute, PushRouteCapability, PushRouteError, PushRouteId,
    PushRouteValidationError, PushRuleEventContext, ServiceDid, ShouldNotify,
    StructurallyValidatedMediaTokenResponse, WatchLevel, call_media_token_exchange,
    ensure_known_backend, evaluate_watch_level, push_rule_reason_code,
    structurally_validate_media_token_response,
};
pub use state::{
    BridgeContractCache, BridgeContractCacheError, BridgeContractDriftVerdict,
    MemoizingPushPreferencesStore, PUSH_PREFERENCES_CACHE_TTL,
    PUSH_REGISTRATION_STATE_SCHEMA_VERSION, PushMultiGatewayRepairPlan, PushPreferencesStore,
    PushRegistrationLastError, PushRegistrationRepairPlan, PushRegistrationState,
    PushRegistrationStore, PushTokenRotationPlan, PushTokenRotationStrategy,
    build_registration_state, find_registration_by_token, find_registration_for_device,
    hash_push_key, merge_registration_state, plan_multi_gateway_repair, plan_registration_repair,
    plan_token_rotation, plan_token_rotation_with_strategy, token_moved_to_different_device,
    token_rotation_required,
};

// -- Constants ---------------------------------------------------------------

/// Canonical Cokret operation id for push device registration.
pub const OPERATION_PUSH_REGISTER_DEVICE: &str = "ck.push.register_device";

/// Canonical Cokret operation id for push device unregistration.
pub const OPERATION_PUSH_UNREGISTER_DEVICE: &str = "ck.push.unregister_device";

/// Canonical Cokret operation id for push wakeup delivery.
pub const OPERATION_PUSH_NOTIFY: &str = "ck.push.notify";

/// B.5 #8 — Canonical Cokret operation id for the push unsubscribe
/// call. Sent as the `operation_id` field on
/// [`PushUnsubscribeRequest`].
pub const OPERATION_PUSH_UNSUBSCRIBE: &str = "cx.push.unsubscribe";

/// Default standard Cokret push gateway URL.
///
/// Cokret does not define a single global push gateway. Consumers should set
/// this from service discovery or application configuration before registering.
pub const DEFAULT_COKRET_PUSH_GATEWAY_URL: &str = "";

/// Default Bugle push gateway URL using the Cokret push notify binding.
pub const DEFAULT_BUGLE_PUSH_GATEWAY_URL: &str = "https://push.palpo.im/_cokret/edge/push/notify";

// -- PushGatewayType ---------------------------------------------------------

/// Which downstream push gateway to ask the Cokret service to use.
///
/// Stability: `1.0`-stable. New variants are additive; renaming or
/// removing a variant requires a major SemVer bump.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PushGatewayType {
    /// Standard Cokret push gateway using FCM, APNs, Web Push, or desktop
    /// notification adapters.
    #[default]
    Standard,
    /// Bugle push gateway with domestic Chinese Android OEM support.
    ///
    /// Routes through JPush `third_party_channel` to Huawei / Xiaomi / OPPO /
    /// vivo / HONOR / HarmonyOS providers.
    Bugle,
    /// User-provided gateway URL.
    Custom,
}

impl PushGatewayType {
    /// Default push gateway URL for this type.
    pub fn default_url(&self) -> &'static str {
        match self {
            Self::Standard => DEFAULT_COKRET_PUSH_GATEWAY_URL,
            Self::Bugle => DEFAULT_BUGLE_PUSH_GATEWAY_URL,
            Self::Custom => DEFAULT_COKRET_PUSH_GATEWAY_URL,
        }
    }

    /// Human-readable display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Standard => "Cokret Standard",
            Self::Bugle => "Bugle (China domestic)",
            Self::Custom => "Custom",
        }
    }

    /// Short description of this gateway type.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Standard => {
                "Standard Cokret push via platform adapters such as FCM, APNs, Web Push, or desktop bridges."
            }
            Self::Bugle => {
                "Domestic push for mainland China via JPush, Huawei, Xiaomi, OPPO, vivo, and HONOR providers."
            }
            Self::Custom => "Manually specify the push gateway URL.",
        }
    }

    /// Resolve the app id for a platform and gateway.
    ///
    /// For Android + Bugle, this returns `domestic_app_id` when provided;
    /// otherwise it returns `base_app_id`. Other platforms always use
    /// `base_app_id`.
    pub fn resolve_app_id<'a>(
        &self,
        platform: Option<PushPlatform>,
        base_app_id: Option<&'a str>,
        domestic_app_id: Option<&'a str>,
    ) -> Option<&'a str> {
        match (self, platform) {
            (Self::Bugle, Some(PushPlatform::Android)) => domestic_app_id.or(base_app_id),
            _ => base_app_id,
        }
    }
}

// -- PushPreferences ---------------------------------------------------------

/// Persisted Cokret push notification preferences.
///
/// Serializable to JSON. The file path and persistence strategy are left to
/// the consumer application — see [`PushPreferencesStore`] for a minimal
/// trait abstraction.
///
/// Stability: `1.0`-stable. New optional fields are added with
/// `#[serde(default)]` so old persisted JSON keeps deserializing.
/// Renaming or removing a field requires a major SemVer bump.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PushPreferences {
    /// Whether push notifications are enabled.
    pub enabled: bool,
    /// Allow non-HTTPS push gateways for loopback development URLs only.
    ///
    /// Production gateway URLs must use HTTPS.
    pub allow_insecure_loopback_push_gateway: bool,
    /// Whether a sender-provided, body-free `push_hint` may be used.
    ///
    /// Cokret push hints are blind wakeup metadata. They must not contain
    /// plaintext message bodies for E2EE Spaces.
    pub allow_push_hint: bool,
    /// Optional allowlist for WebPush endpoint origins.
    ///
    /// When non-empty and the platform is `web`, registration rejects WebPush
    /// endpoints whose origin is not present in this list. Entries may be full
    /// origins such as `https://fcm.googleapis.com` or host patterns such as
    /// `.push.apple.com` / `*.push.services.mozilla.com`.
    #[serde(default)]
    pub webpush_endpoint_allowlist: Vec<String>,
    /// Gateway bindings to register against.
    ///
    /// Each binding carries its own gateway type, URL, and optional
    /// per-binding `push_key` / `app_id` overrides. Every binding is
    /// exercised independently — see
    /// `CokretPushClient::register_device_all` (under the `http`
    /// feature) for the multi-gateway register helper.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gateways: Vec<GatewayBinding>,
    /// CXP-0007 (Circle primitive) — set of `ck:circle:` ids the user
    /// has muted on this device. Wakeups whose `circle_id` is in this
    /// set MUST NOT raise a UI surface; wire-level delivery is
    /// unchanged so floria can still account for the receipt.
    ///
    /// Stored as a `BTreeSet` so the persisted JSON is deterministic
    /// (essential for diff-based prefs sync).
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub muted_circle_ids: BTreeSet<String>,
    /// Set of `ck:realm:` ids the user has muted on this device. Same
    /// semantics as [`Self::muted_circle_ids`], scoped to the Realm
    /// (legacy Realm-scoped wakeups + any Circle-less Realm wakeups).
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub muted_realm_ids: BTreeSet<String>,
}

impl Default for PushPreferences {
    fn default() -> Self {
        Self {
            enabled: false,
            allow_insecure_loopback_push_gateway: false,
            allow_push_hint: true,
            webpush_endpoint_allowlist: Vec::new(),
            gateways: Vec::new(),
            muted_circle_ids: BTreeSet::new(),
            muted_realm_ids: BTreeSet::new(),
        }
    }
}

// -- JSON persistence helpers ------------------------------------------------

/// Serialize preferences to a JSON string.
pub fn to_json(prefs: &PushPreferences) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(prefs)
}

/// Deserialize preferences from a JSON string.
///
/// Strict: unknown fields (including the removed singular `gateway_type` /
/// `push_gateway` pair, removed gateway-type aliases such as `Sygnal`, and
/// removed field names such as `gateway_url` / `show_message_preview`)
/// cause an error rather than a silent fallback. Callers that want
/// graceful recovery should match on the error and decide what to do —
/// there is no longer a permissive variant.
pub fn from_json(json: &str) -> Result<PushPreferences, serde_json::Error> {
    serde_json::from_str(json)
}

// -- Tests -------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_preferences() {
        let prefs = PushPreferences::default();
        assert!(!prefs.enabled);
        assert!(prefs.gateways.is_empty());
        assert!(!prefs.allow_insecure_loopback_push_gateway);
        assert!(prefs.allow_push_hint);
    }

    #[test]
    fn resolve_app_id_standard() {
        let gw = PushGatewayType::Standard;
        assert_eq!(
            gw.resolve_app_id(
                Some(PushPlatform::Android),
                Some("app.example.android"),
                Some("app.example.android.cn")
            ),
            Some("app.example.android")
        );
    }

    #[test]
    fn resolve_app_id_bugle_android() {
        let gw = PushGatewayType::Bugle;
        assert_eq!(
            gw.resolve_app_id(
                Some(PushPlatform::Android),
                Some("app.example.android"),
                Some("app.example.android.cn")
            ),
            Some("app.example.android.cn")
        );
    }

    #[test]
    fn resolve_app_id_bugle_ios_uses_base() {
        let gw = PushGatewayType::Bugle;
        assert_eq!(
            gw.resolve_app_id(
                Some(PushPlatform::Ios),
                Some("app.example.ios"),
                Some("app.example.android.cn")
            ),
            Some("app.example.ios")
        );
    }

    #[test]
    fn json_roundtrip() {
        let prefs = PushPreferences {
            enabled: true,
            allow_insecure_loopback_push_gateway: false,
            allow_push_hint: false,
            webpush_endpoint_allowlist: vec!["https://fcm.googleapis.com".to_owned()],
            gateways: vec![GatewayBinding::new(
                PushGatewayType::Bugle,
                "https://example.com/_cokret/edge/push/notify",
            )],
            ..Default::default()
        };
        let json = to_json(&prefs).unwrap();
        let loaded = from_json(&json).unwrap();
        assert_eq!(loaded.enabled, prefs.enabled);
        assert_eq!(loaded.gateways, prefs.gateways);
        assert_eq!(loaded.allow_push_hint, prefs.allow_push_hint);
        assert_eq!(
            loaded.webpush_endpoint_allowlist,
            prefs.webpush_endpoint_allowlist
        );
    }

    #[test]
    fn from_json_partial_uses_field_defaults() {
        let loaded = from_json(r#"{"enabled":true}"#).unwrap();
        assert!(loaded.enabled);
        assert!(loaded.gateways.is_empty());
        assert!(loaded.allow_push_hint);
    }

    #[test]
    fn from_json_rejects_invalid_payload() {
        assert!(from_json("not valid json").is_err());
    }

    #[test]
    fn gateways_round_trip_through_json() {
        let prefs = PushPreferences {
            enabled: true,
            gateways: vec![
                GatewayBinding::new(
                    PushGatewayType::Standard,
                    "https://push-a.example.com/_cokret/edge/push/notify",
                ),
                GatewayBinding::new(
                    PushGatewayType::Bugle,
                    "https://push.palpo.im/_cokret/edge/push/notify",
                )
                .with_push_key("vendor-token-cn-aaaaaaaaaa"),
            ],
            ..Default::default()
        };
        let json = to_json(&prefs).unwrap();
        let loaded = from_json(&json).unwrap();
        assert_eq!(loaded.gateways.len(), 2);
        assert_eq!(loaded.gateways, prefs.gateways);
    }

    #[test]
    fn from_json_rejects_removed_singular_and_aliases_strictly() {
        let loaded = from_json(
            r#"{
                "enabled": true,
                "gateway_type": "standard",
                "push_gateway": "https://old.example/push/notify",
                "show_message_preview": false
            }"#,
        );
        assert!(
            loaded.is_err(),
            "removed singular fields and aliases must error, not silently default"
        );
    }

    #[test]
    fn muted_circle_and_realm_ids_round_trip() {
        let mut prefs = PushPreferences {
            enabled: true,
            ..Default::default()
        };
        prefs
            .muted_circle_ids
            .insert("ck:circle:01HZK9Z000000000000000001".to_owned());
        prefs
            .muted_circle_ids
            .insert("ck:circle:01HZK9Z000000000000000002".to_owned());
        prefs
            .muted_realm_ids
            .insert("ck:realm:01HZK9Z000000000000000003".to_owned());

        let json = to_json(&prefs).unwrap();
        assert!(json.contains("muted_circle_ids"));
        assert!(json.contains("muted_realm_ids"));
        let loaded = from_json(&json).unwrap();
        assert_eq!(loaded.muted_circle_ids, prefs.muted_circle_ids);
        assert_eq!(loaded.muted_realm_ids, prefs.muted_realm_ids);
    }

    #[test]
    fn default_preferences_have_empty_mutes() {
        let prefs = PushPreferences::default();
        assert!(prefs.muted_circle_ids.is_empty());
        assert!(prefs.muted_realm_ids.is_empty());
    }

    #[test]
    fn empty_mute_sets_are_omitted_from_serialised_form() {
        let prefs = PushPreferences::default();
        let json = to_json(&prefs).unwrap();
        // Defaults should not blow up the on-disk shape with empty
        // collections; the `skip_serializing_if` predicate keeps them out.
        assert!(!json.contains("muted_circle_ids"));
        assert!(!json.contains("muted_realm_ids"));
    }
}
