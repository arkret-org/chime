//! Optional `ck.push.notify` wire model for Push Gateway implementations.
//!
//! This module models the Cokret notify request/response payload and keeps
//! blind-wakeup validation conservative. It does not implement APNs, FCM, Web
//! Push, or OEM provider delivery.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose;
use cokret::blind_payload_sanitizer::{
    self as sdk_sanitizer, BlindPayloadError, BlindPayloadReasonCode, is_forbidden_payload_key,
};
// Round 4 (B5, spec a77b995) — pull typed audit surfaces from the SDK so
// chime stays byte-aligned with what soland/floria emit. The
// mention-redirect routing wrapper is local to chime until the SDK grows a
// stable public type for that exact wire object.
use cokret::{AccessKind, AuditPolicyAccessPayload, Did, EventId};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::redact_push_key;

/// Request body for `POST /_cokret/edge/push/notify`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushNotifyReqBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_service_did: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_service_did: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collapse_key: Option<String>,
    pub notification: PushNotification,
}

impl PushNotifyReqBody {
    pub fn validate_wire_model(&self) -> Result<(), PushNotifyPrivacyError> {
        if let Some(operation_id) = self.operation_id.as_deref()
            && operation_id != crate::OPERATION_PUSH_NOTIFY
        {
            return Err(PushNotifyPrivacyError::InvalidFieldValue {
                field: "operation_id".to_owned(),
            });
        }

        self.notification.validate_wire_model()
    }

    pub fn validate_blind_wakeup(&self) -> Result<(), PushNotifyPrivacyError> {
        self.validate_wire_model()?;
        self.notification.validate_blind_wakeup()
    }

    pub fn validate_blind_wakeup_strict(&self) -> Result<(), PushNotifyPrivacyError> {
        self.validate_wire_model()?;
        self.notification.validate_blind_wakeup_strict()?;

        // T1.1 — additionally route the serialised notification through
        // the SDK's strict sanitizer to reject *any* forbidden field
        // (including ones that would have passed the structured
        // `PushNotification` deserialiser because they're tucked
        // inside `extra`).
        let serialised = serde_json::to_value(&self.notification).map_err(|err| {
            PushNotifyPrivacyError::InvalidFieldValue {
                field: format!("notification (serialise failed: {err})"),
            }
        })?;
        sdk_sanitizer::sanitize_blind_payload_strict(&serialised)
            .map_err(PushNotifyPrivacyError::from)
    }

    pub fn validate_privacy(
        &self,
        mode: PushNotifyPrivacyMode,
    ) -> Result<(), PushNotifyPrivacyError> {
        match mode {
            PushNotifyPrivacyMode::E2eeBlindWakeup => self.validate_blind_wakeup(),
            PushNotifyPrivacyMode::PlaintextVisibleService => {
                self.validate_wire_model()?;
                self.notification.validate_plaintext_visible_service()
            }
        }
    }

    pub fn assert_payload_safe(
        &self,
        policy: &PushNotifyPolicyContext,
    ) -> Result<(), PushNotifyPrivacyError> {
        let mode = policy.mode_for(self.destination_service_did.as_deref());
        self.validate_privacy(mode)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PushNotifyPrivacyMode {
    E2eeBlindWakeup,
    PlaintextVisibleService,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PushNotifyPolicyContext {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub plaintext_visible_services: Vec<String>,
}

impl PushNotifyPolicyContext {
    pub fn blind_wakeup_only() -> Self {
        Self::default()
    }

    pub fn allows_plaintext_for(&self, destination_service_did: &str) -> bool {
        self.plaintext_visible_services
            .iter()
            .any(|service| service == destination_service_did)
    }

    pub fn mode_for(&self, destination_service_did: Option<&str>) -> PushNotifyPrivacyMode {
        match destination_service_did {
            Some(did) if self.allows_plaintext_for(did) => {
                PushNotifyPrivacyMode::PlaintextVisibleService
            }
            _ => PushNotifyPrivacyMode::E2eeBlindWakeup,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PushNotifyPrivacyVector {
    pub name: String,
    pub mode: PushNotifyPrivacyMode,
    pub payload: Value,
    pub should_accept: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_error_field: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct PushHint(String);

impl PushHint {
    pub fn new(value: impl Into<String>) -> Result<Self, PushNotifyPrivacyError> {
        let value = value.into();
        validate_push_hint_value(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for PushHint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::new(raw).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct PushTargetId(String);

impl PushTargetId {
    pub fn new(value: impl Into<String>) -> Result<Self, PushNotifyPrivacyError> {
        let value = value.into();
        validate_push_target_id(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for PushTargetId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::new(raw).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum WakeupKind {
    Message,
    Mention,
    Reaction,
    CallInvite,
}

impl WakeupKind {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Message => "message",
            Self::Mention => "mention",
            Self::Reaction => "reaction",
            Self::CallInvite => "call_invite",
        }
    }
}

impl Serialize for WakeupKind {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for WakeupKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Ok(match raw.as_str() {
            "message" => Self::Message,
            "mention" => Self::Mention,
            "reaction" => Self::Reaction,
            "call_invite" => Self::CallInvite,
            _ => {
                return Err(serde::de::Error::custom(
                    "wakeup_kind must be one of message, mention, reaction, call_invite",
                ));
            }
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
/// Wire notification descriptor for `ck.push.notify`.
///
/// This type intentionally carries unknown JSON fields in [`Self::extra`]
/// because `#[serde(flatten)]` cannot be combined with
/// `deny_unknown_fields`. Deserialization alone is therefore not a
/// safety boundary: callers that parse JSON into `PushNotification`
/// or [`PushNotifyReqBody`] MUST immediately run
/// [`PushNotifyReqBody::assert_payload_safe`],
/// [`PushNotifyReqBody::validate_blind_wakeup`], or
/// [`Self::validate_wire_model`] before reading fields or showing UI.
pub struct PushNotification {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_target_id: Option<PushTargetId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wakeup_kind: Option<WakeupKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    /// Security-boundary identifier. Still emitted on the blind-wakeup
    /// wire model only when allowed by the privacy descriptor; the SDK
    /// sanitizer treats scope identifiers as forbidden extra payload keys,
    /// so this typed wire field is validated separately below.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<String>,
    /// CXP-0007 (Circle primitive) — typed `ck:circle:` identifier of
    /// the Circle (intra-Realm encrypted sub-boundary) the wakeup is
    /// scoped to, when applicable. `None` for legacy Realm-scoped
    /// wakeups.
    ///
    /// Blind-wakeup mode: the typed string MAY appear on the wire as
    /// opaque routing metadata — see [`PushNotification::validate_blind_wakeup`]
    /// for the privacy validator that enforces the wire shape and the
    /// "no Circle member name leak" invariant.
    ///
    /// Plaintext-visible mode (whitelisted service DIDs only): MUST
    /// stay absent unless the destination service explicitly opts in
    /// via [`PushNotifyPolicyContext::plaintext_visible_services`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub circle_id: Option<String>,
    /// CXP-0007 (Circle primitive) — mirror of the event envelope's
    /// `effective_scope` field that floria stamps on the originating
    /// `ck.event.*` envelope. Lets the client side correlate a wakeup
    /// with the security boundary the event was authored against
    /// without having to round-trip back to floria.
    ///
    /// Shape: typed reference string (`ck:circle:...` or `ck:realm:...`).
    /// Validated by [`PushNotification::validate_wire_model`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_actor_display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_hint: Option<PushHint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<Value>,
    /// Round 4 (B5, spec a77b995) — plaintext routing fragment for
    /// mention-redirect scenarios. Only actor IDs in
    /// `mention_redirect_target_actor_ids` are permitted to decrypt the
    /// (otherwise encrypted) message body at the push layer. If the
    /// receiver's actor_id is NOT in the list, the body MUST stay
    /// encrypted and the wakeup is delivered as opaque routing
    /// metadata only — see [`PushNotification::decrypt_allowed_for_actor`].
    ///
    /// The field is intentionally typed (`MentionRedirectRouting`) rather
    /// than carried in `extra`, so consumers cannot accidentally bypass the
    /// fail-closed check by reading raw JSON.
    ///
    /// Wire shape (canonical, both modes):
    /// ```json
    /// "mention_redirect": {
    ///     "mention_redirect_target_actor_ids": ["did:web:alice.example", "did:webvh:bob.example"]
    /// }
    /// ```
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mention_redirect: Option<MentionRedirectRouting>,
    /// Round 4 (B5) — typed `ck.audit.policy_access` payload surfaced to
    /// consumers (e.g. yougen) so the late-key-recovery banner can read
    /// `late_recovery_original_event_id` directly off the wakeup. This
    /// is diagnostic context — push layer never decrypts on the
    /// strength of this field alone. The SDK validates the
    /// `(access_kind, late_recovery_original_event_id)` pairing via
    /// [`cokret::AuditPolicyAccessPayload::validate_minimal`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_access: Option<AuditPolicyAccessPayload>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<PushNotificationDevice>,
    /// Unknown extension fields captured from the wire.
    ///
    /// Because this field uses `#[serde(flatten)]`, serde cannot reject
    /// unknown fields during deserialization. Treat this map as
    /// untrusted until [`Self::validate_wire_model`] and the relevant
    /// privacy validator have accepted the payload.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MentionRedirectRouting {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mention_redirect_target_actor_ids: Vec<Did>,
}

impl PushNotification {
    /// Construct a minimal blind-wakeup `PushNotification`.
    ///
    /// Equivalent to `PushNotification::default()` plus the only two
    /// fields the SDK / floria treat as mandatory (`wakeup_kind`,
    /// `push_target_id`). Provided as a constructor so external
    /// consumers can build instances despite the `#[non_exhaustive]`
    /// attribute on the struct.
    pub fn new_blind_wakeup(push_target_id: PushTargetId, wakeup_kind: WakeupKind) -> Self {
        Self {
            push_target_id: Some(push_target_id),
            wakeup_kind: Some(wakeup_kind),
            ..Self::default()
        }
    }

    pub fn validate_wire_model(&self) -> Result<(), PushNotifyPrivacyError> {
        if self.wakeup_kind.is_none() {
            return Err(PushNotifyPrivacyError::MissingField {
                field: "wakeup_kind".to_owned(),
            });
        }

        validate_typed_id("event_id", self.event_id.as_deref(), "ck:event:")?;
        validate_typed_id("realm_id", self.realm_id.as_deref(), "ck:realm:")?;
        // CXP-0007 — Circle primitive typed-shape validation. We don't
        // require either to be present (legacy Realm-scoped wakeups
        // still set realm_id only), but when present they MUST be the
        // canonical typed-id shape so floria/yougen don't have to
        // re-parse arbitrary strings later.
        //
        // A.5 #1 — `circle_id` is the canonical opaque routing token in
        // blind-wakeup mode. Tighten its shape from the generic
        // `validate_typed_id` (which only checks the prefix) to a strict
        // regex equivalent of `^ck:circle:[a-z0-9]+$` so member-name /
        // display-label exfiltration via the tail is rejected at the
        // wire layer.
        validate_circle_id_opaque(self.circle_id.as_deref())?;
        validate_effective_scope(self.effective_scope.as_deref())?;
        validate_optional_non_empty("sender", self.sender.as_deref())?;

        if self.devices.is_empty() {
            return Err(PushNotifyPrivacyError::MissingField {
                field: "devices".to_owned(),
            });
        }
        for device in &self.devices {
            device.validate_wire_model()?;
        }
        for (key, value) in &self.extra {
            // Phase P2 (spec 37ce729) — legacy B-B field-naming aliases
            // fail closed at the wire layer. floria 6496235 mirrors the
            // same reject set on the gateway side; chime is the
            // client-side mirror so a legacy-pinned producer can't
            // sneak the old wire shape past us.
            if is_legacy_field_alias(key) {
                return Err(PushNotifyPrivacyError::RemovedField {
                    field: key.to_owned(),
                });
            }
            // Reject nested legacy aliases too (e.g. `media.size`).
            if let Err(path) = assert_no_legacy_aliases(value) {
                return Err(PushNotifyPrivacyError::RemovedField {
                    field: format!("{key}.{path}"),
                });
            }
            // Phase P2 — agent / sidecar / backup / recovery typed-id
            // prefixes are never expected to appear in a blind wakeup's
            // `extra` map. Reject any string value that starts with one
            // of the seven SDK typed-id prefixes so a caller can't
            // smuggle an agent_session / accountability_grant /
            // sidecar_circle id through.
            if let Some(raw) = value.as_str()
                && is_phase_p2_agent_typed_id(raw)
            {
                return Err(PushNotifyPrivacyError::SensitiveField {
                    field: key.to_owned(),
                });
            }
            validate_active_reference_extension(key, value)?;
        }

        Ok(())
    }

    pub fn validate_blind_wakeup_strict(&self) -> Result<(), PushNotifyPrivacyError> {
        if self.push_target_id.is_none() {
            return Err(PushNotifyPrivacyError::MissingField {
                field: "push_target_id".to_owned(),
            });
        }
        if self.wakeup_kind.is_none() {
            return Err(PushNotifyPrivacyError::MissingField {
                field: "wakeup_kind".to_owned(),
            });
        }
        self.validate_blind_wakeup()
    }

    pub fn validate_blind_wakeup(&self) -> Result<(), PushNotifyPrivacyError> {
        self.validate_wire_model()?;

        if self.sender_actor_display_name.is_some() {
            return Err(PushNotifyPrivacyError::SensitiveField {
                field: "sender_actor_display_name".to_owned(),
            });
        }
        if self.realm_name.is_some() {
            return Err(PushNotifyPrivacyError::SensitiveField {
                field: "realm_name".to_owned(),
            });
        }
        // CXP-0007 Circle metadata privacy invariant: even in blind
        // mode where `circle_id` may travel as opaque routing metadata,
        // the wakeup MUST NOT leak Circle membership/display fields.
        // The strict opaque validator in `validate_wire_model` already
        // rejects any `did:`/`:did` substring in the tail (it enforces
        // `^ck:circle:[a-z0-9]+$`), so we keep the belt-and-braces
        // SensitiveField mapping here for callers that bypass the
        // wire-model validator and call `validate_blind_wakeup` directly.
        if let Some(circle_id) = self.circle_id.as_deref()
            && (circle_id.to_ascii_lowercase().contains("did:") || circle_id.contains(":did"))
        {
            return Err(PushNotifyPrivacyError::SensitiveField {
                field: "circle_id".to_owned(),
            });
        }
        if let Some(counts) = &self.counts {
            validate_counts("counts", counts)?;
        }
        for (key, value) in &self.extra {
            if is_sensitive_payload_key(key) {
                return Err(PushNotifyPrivacyError::SensitiveField {
                    field: key.to_owned(),
                });
            }
            validate_extra_value(key, value)?;
        }

        // T1.1 — route every blind-wakeup payload through the shared
        // SDK sanitizer (single source of truth across chime + floria).
        // We feed it just the `extra` map so we don't double-flag the
        // wire-model fields we already validate above; the wire-model
        // owns its own allow-list and the SDK sanitizer owns the rule
        // that says "no forbidden field anywhere in the tree, no
        // sensitive did:/ck: literal anywhere".
        run_sdk_sanitizer_over_extra(&self.extra)?;

        Ok(())
    }

    pub fn validate_plaintext_visible_service(&self) -> Result<(), PushNotifyPrivacyError> {
        self.validate_wire_model()?;

        for (key, value) in &self.extra {
            if is_never_allowed_payload_key(key) {
                return Err(PushNotifyPrivacyError::SensitiveField {
                    field: key.to_owned(),
                });
            }
            validate_plaintext_extra_value(key, value)?;
        }

        Ok(())
    }

    /// Round 4 (B5) — `mention_redirect_target_actor_ids` fail-closed
    /// gate. Returns `true` iff the (encrypted) body MAY be decrypted
    /// at the push layer for `receiver_actor_id`.
    ///
    /// Semantics:
    /// - When [`Self::mention_redirect`] is `None`, this is NOT a mention-redirect scenario and the
    ///   call returns `true` (the normal recipient-set gate elsewhere applies).
    /// - When `mention_redirect` is `Some`, the receiver's actor ID MUST appear in
    ///   `mention_redirect_target_actor_ids` to be permitted. **Empty array means nobody is
    ///   permitted** — fail-closed by construction.
    ///
    /// This is the canonical accessor consumers (yougen, floria, host
    /// apps) should call before unwrapping the body. Direct reads of
    /// `self.mention_redirect.mention_redirect_target_actor_ids` are
    /// permitted for display but MUST NOT gate decryption — the
    /// fail-closed semantics live here, not at the call site.
    pub fn decrypt_allowed_for_actor(&self, receiver_actor_id: &Did) -> bool {
        let Some(routing) = &self.mention_redirect else {
            // Not a mention-redirect wakeup; gate is decided elsewhere.
            return true;
        };
        routing
            .mention_redirect_target_actor_ids
            .iter()
            .any(|allowed| allowed == receiver_actor_id)
    }

    /// Round 4 (B5) — return `true` when this wakeup carries
    /// mention-redirect plaintext routing (regardless of whether any
    /// actor is permitted). Consumers can branch on this to render
    /// "@-mention redirected to N actors" UI.
    pub fn has_mention_redirect_routing(&self) -> bool {
        self.mention_redirect.is_some()
    }

    /// B.5 #9 — build a [`crate::BackgroundFetchHint`] that mirrors the
    /// wakeup's opaque routing metadata. Host code passes the result
    /// into [`crate::BackgroundFetchDriver::dispatch_background_fetch`]
    /// to schedule the platform background-fetch job.
    ///
    /// Returns `None` when the wakeup is missing the two required
    /// fields (`push_target_id`, `wakeup_kind`). The wire-model
    /// validator rejects that shape upstream, so a `None` return at
    /// this point means an integrator constructed an out-of-spec
    /// notification manually — the safe default is "do not dispatch".
    pub fn background_fetch_hint(&self) -> Option<crate::BackgroundFetchHint<'_>> {
        let push_target_id = self.push_target_id.as_ref()?.as_str();
        let wakeup_kind = self.wakeup_kind.as_ref()?.as_str();
        let mut hint = crate::BackgroundFetchHint::new(push_target_id, wakeup_kind);
        if let Some(circle_id) = self.circle_id.as_deref() {
            hint = hint.with_circle_id(circle_id);
        }
        if let Some(realm_id) = self.realm_id.as_deref() {
            hint = hint.with_realm_id(realm_id);
        }
        Some(hint)
    }

    /// Round 4 (B5) — when the wakeup is a late-key-recovery audit
    /// surface (`ck.audit.policy_access.access_kind = e2ee_late_recovery`),
    /// return the `late_recovery_original_event_id` so the consumer can
    /// render a "the system recovered an old key for event X" banner.
    ///
    /// Returns `None` when:
    /// - `policy_access` is absent
    /// - `access_kind` is NOT `E2EELateRecovery` (any other kind has no banner contract)
    /// - `late_recovery_original_event_id` is absent (defensive — the SDK validator already rejects
    ///   this combination)
    pub fn late_recovery_event_id(&self) -> Option<&EventId> {
        let payload = self.policy_access.as_ref()?;
        match payload.access_kind {
            AccessKind::E2EELateRecovery => payload.late_recovery_original_event_id.as_ref(),
            _ => None,
        }
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushNotificationDevice {
    pub push_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_key_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
}

impl fmt::Debug for PushNotificationDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PushNotificationDevice")
            .field("push_key", &redact_push_key(&self.push_key))
            .field("app_id", &self.app_id)
            .field("registration_id", &self.registration_id)
            .field("push_key_hash", &self.push_key_hash)
            .field("platform", &self.platform)
            .finish()
    }
}

impl PushNotificationDevice {
    fn validate_wire_model(&self) -> Result<(), PushNotifyPrivacyError> {
        validate_required("devices[].push_key", &self.push_key)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct PushNotifyResBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(default)]
    pub accepted: usize,
    #[serde(default)]
    pub rejected: Vec<RejectedPushToken>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provider_retries: Vec<ProviderRetryHint>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delivery_receipts: Vec<PushDeliveryReceipt>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderRetryHint {
    pub provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushDeliveryReceipt {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_message_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_key_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectedPushToken {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_key_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl fmt::Debug for RejectedPushToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RejectedPushToken")
            .field("push_key", &self.push_key.as_deref().map(redact_push_key))
            .field("push_key_hash", &self.push_key_hash)
            .field("app_id", &self.app_id)
            .field("reason", &self.reason)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedEnvelope {
    pub recipient: String,
    pub algorithm: String,
    pub ciphertext: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aad: Option<String>,
}

impl EncryptedEnvelope {
    pub fn new(
        recipient: impl Into<String>,
        algorithm: impl Into<String>,
        ciphertext: impl Into<String>,
    ) -> Result<Self, EncryptedEnvelopeError> {
        let envelope = Self {
            recipient: recipient.into(),
            algorithm: algorithm.into(),
            ciphertext: ciphertext.into(),
            nonce: None,
            key_id: None,
            aad: None,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn with_nonce(mut self, nonce: impl Into<String>) -> Result<Self, EncryptedEnvelopeError> {
        let nonce = nonce.into();
        validate_base64_field("nonce", &nonce)?;
        self.nonce = Some(nonce);
        Ok(self)
    }

    pub fn with_key_id(mut self, key_id: impl Into<String>) -> Self {
        self.key_id = Some(key_id.into());
        self
    }

    pub fn with_aad(mut self, aad: impl Into<String>) -> Self {
        self.aad = Some(aad.into());
        self
    }

    pub fn validate(&self) -> Result<(), EncryptedEnvelopeError> {
        if self.recipient.trim().is_empty() {
            return Err(EncryptedEnvelopeError::MissingField { field: "recipient" });
        }
        // Round 4 (B5, spec a77b995) — DID regex sweep: route the
        // recipient through the SDK's tightened `Did::new` validator
        // (`^did:[a-z0-9]+:[^\s]+$`) instead of the previous
        // permissive `starts_with("did:")` shape. The pre-round-4 form
        // accepted method names with `.`/`-`/`_`/`:` which is now
        // wire-broken; reject them at the EncryptedEnvelope boundary
        // so chime can't be used to smuggle them past floria.
        if Did::new(self.recipient.clone()).is_err() {
            return Err(EncryptedEnvelopeError::InvalidRecipient {
                got: self.recipient.clone(),
            });
        }
        if self.algorithm.trim().is_empty() {
            return Err(EncryptedEnvelopeError::MissingField { field: "algorithm" });
        }
        if self.ciphertext.trim().is_empty() {
            return Err(EncryptedEnvelopeError::MissingField {
                field: "ciphertext",
            });
        }
        validate_base64_field("ciphertext", &self.ciphertext)?;
        if let Some(nonce) = self.nonce.as_deref() {
            validate_base64_field("nonce", nonce)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum EncryptedEnvelopeError {
    #[error("encrypted envelope is missing required field `{field}`")]
    MissingField { field: &'static str },
    #[error("encrypted envelope recipient must be a DID, got `{got}`")]
    InvalidRecipient { got: String },
    #[error("encrypted envelope field `{field}` is not base64")]
    InvalidBase64 { field: &'static str },
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PushNotifyPrivacyError {
    #[error("push notify payload is missing required field `{field}`")]
    MissingField { field: String },
    #[error("push notify payload field `{field}` has an invalid value")]
    InvalidFieldValue { field: String },
    #[error("push notify payload field `{field}` contains sensitive data")]
    SensitiveField { field: String },
    #[error("push notify payload field `{field}` has been removed from this contract")]
    RemovedField { field: String },
    #[error("push notify hint is sensitive")]
    SensitiveHint,
}

impl From<BlindPayloadError> for PushNotifyPrivacyError {
    fn from(err: BlindPayloadError) -> Self {
        match err.reason_code {
            BlindPayloadReasonCode::MissingRequiredField => Self::MissingField {
                field: err.field_path,
            },
            BlindPayloadReasonCode::InvalidFieldValue => Self::InvalidFieldValue {
                field: err.field_path,
            },
            BlindPayloadReasonCode::ForbiddenField | BlindPayloadReasonCode::SensitiveLiteral => {
                Self::SensitiveField {
                    field: err.field_path,
                }
            }
        }
    }
}

/// T1.1 — feed the `extra` map of a [`PushNotification`] through the SDK
/// sanitizer so the rule "no forbidden field anywhere, no `did:` / `ck:`
/// literal anywhere" stays unified across chime/floria.
///
/// We wrap the extras under a `notification` envelope so the SDK
/// sanitizer's wrapper-scan path runs (only forbidden-key + sensitive
/// literal checks, no allow-list — that lives in `validate_wire_model`).
fn run_sdk_sanitizer_over_extra(extra: &Map<String, Value>) -> Result<(), PushNotifyPrivacyError> {
    if extra.is_empty() {
        return Ok(());
    }
    // Empty `notification` so we hit the "scan wrapper for forbidden
    // keys + literals, ignore wrapper's own allow-list" branch.
    let envelope = serde_json::json!({
        "notification": {
            "push_target_id": "ck:pseudonym:push:0000000000000000000000",
            "wakeup_kind": "message",
        },
    });
    let mut envelope = envelope;
    if let Some(obj) = envelope.as_object_mut() {
        for (key, value) in extra {
            obj.insert(key.clone(), value.clone());
        }
    }
    sdk_sanitizer::sanitize_blind_payload(&envelope).map_err(PushNotifyPrivacyError::from)
}

/// B.5 #7 — client-facing summary of the push gateway's deduplication
/// configuration.
///
/// `bridge/describe` advertises a `dedup_backend` (e.g. `"redis"`,
/// `"in-memory"`) and a `dedup_ttl_seconds` field on the notify
/// descriptor. Host apps that want to mirror the gateway's dedup
/// behaviour locally (so they don't double-process a wakeup that the
/// gateway already short-circuited) need both values together — this
/// helper bundles them so callers don't have to reach into the bridge
/// descriptor at every consumption site.
///
/// Construct via [`PushNotificationDedup::from_descriptor`] from a
/// fetched [`crate::PushBridgeDescribeNotifyDescriptor`]; the factory
/// returns `None` when the gateway has no dedup backend advertised
/// (i.e. `dedup_backend` is `None` or empty), in which case the host
/// app should NOT assume any cross-request dedup at the gateway and
/// must apply its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PushNotificationDedup {
    /// Canonical backend identifier — copied verbatim from
    /// `bridge/describe.notify.dedup_backend` for downstream logs /
    /// metrics. Examples: `"redis"`, `"in-memory"`.
    pub backend: String,
    /// Retention window for the dedup record. When the gateway did not
    /// advertise a TTL, this is `Duration::ZERO`; callers should treat
    /// that as "fall back to your local default" rather than "no
    /// dedup".
    pub window: std::time::Duration,
}

impl PushNotificationDedup {
    /// Construct a [`PushNotificationDedup`] from a notify descriptor.
    ///
    /// Returns `None` when no `dedup_backend` is advertised, i.e. the
    /// gateway does NOT perform server-side dedup and the host app
    /// must handle it itself.
    pub fn from_descriptor(notify: &crate::PushBridgeDescribeNotifyDescriptor) -> Option<Self> {
        let backend = notify.dedup_backend.as_deref()?.trim();
        if backend.is_empty() {
            return None;
        }
        Some(Self {
            backend: backend.to_owned(),
            window: notify.dedup_window().unwrap_or(std::time::Duration::ZERO),
        })
    }

    /// `true` when the gateway advertised a positive retention window.
    pub fn has_window(&self) -> bool {
        !self.window.is_zero()
    }
}

pub fn shared_push_notify_privacy_vectors() -> Vec<PushNotifyPrivacyVector> {
    vec![
        PushNotifyPrivacyVector {
            name: "blind wakeup accepts opaque metadata".to_owned(),
            mode: PushNotifyPrivacyMode::E2eeBlindWakeup,
            payload: serde_json::json!({
                "operation_id": crate::OPERATION_PUSH_NOTIFY,
                "notification": {
                    "push_target_id": "ck:pseudonym:push:01HYZ8Z000000000000000",
                    "wakeup_kind": "message",
                    "push_hint": "new_message",
                    "counts": { "unread": 1 },
                    "devices": [{ "push_key": "fcm:opaque-token", "app_id": "app.example" }]
                }
            }),
            should_accept: true,
            expected_error_field: None,
        },
        PushNotifyPrivacyVector {
            name: "blind wakeup rejects title".to_owned(),
            mode: PushNotifyPrivacyMode::E2eeBlindWakeup,
            payload: serde_json::json!({
                "notification": {
                    "push_target_id": "ck:pseudonym:push:01HYZ8Z000000000000000",
                    "wakeup_kind": "message",
                    "title": "Secret",
                    "devices": [{ "push_key": "fcm:opaque-token", "app_id": "app.example" }]
                }
            }),
            should_accept: false,
            expected_error_field: Some("title".to_owned()),
        },
    ]
}

fn validate_push_hint_value(value: &str) -> Result<(), PushNotifyPrivacyError> {
    if value.to_ascii_lowercase().contains("did:") {
        return Err(PushNotifyPrivacyError::SensitiveField {
            field: "push_hint".to_owned(),
        });
    }

    if matches!(value, "new_message" | "incoming_call" | "mention_self") {
        return Ok(());
    }

    if let Some(token) = value.strip_prefix("l10n_key:")
        && !token.is_empty()
        && token.len() <= 64
        && token
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
    {
        return Ok(());
    }

    Err(PushNotifyPrivacyError::InvalidFieldValue {
        field: "push_hint".to_owned(),
    })
}

fn validate_push_target_id(value: &str) -> Result<(), PushNotifyPrivacyError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(PushNotifyPrivacyError::InvalidFieldValue {
            field: "push_target_id".to_owned(),
        });
    }

    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("did:") {
        return Err(PushNotifyPrivacyError::SensitiveField {
            field: "push_target_id".to_owned(),
        });
    }

    let token = if let Some(token) = trimmed.strip_prefix("ck:pseudonym:push:") {
        token
    } else if trimmed.starts_with("ck:") || trimmed.contains(':') {
        return Err(PushNotifyPrivacyError::InvalidFieldValue {
            field: "push_target_id".to_owned(),
        });
    } else {
        trimmed
    };

    if !(22..=128).contains(&token.len())
        || !token
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-'))
    {
        return Err(PushNotifyPrivacyError::InvalidFieldValue {
            field: "push_target_id".to_owned(),
        });
    }

    Ok(())
}

fn validate_required(field: &str, value: &str) -> Result<(), PushNotifyPrivacyError> {
    if value.trim().is_empty() {
        return Err(PushNotifyPrivacyError::MissingField {
            field: field.to_owned(),
        });
    }
    Ok(())
}

fn validate_optional_non_empty(
    field: &str,
    value: Option<&str>,
) -> Result<(), PushNotifyPrivacyError> {
    if value.is_some_and(|raw| raw.trim().is_empty()) {
        return Err(PushNotifyPrivacyError::InvalidFieldValue {
            field: field.to_owned(),
        });
    }
    Ok(())
}

fn validate_typed_id(
    field: &str,
    value: Option<&str>,
    prefix: &str,
) -> Result<(), PushNotifyPrivacyError> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.trim().is_empty() || !value.starts_with(prefix) {
        return Err(PushNotifyPrivacyError::InvalidFieldValue {
            field: field.to_owned(),
        });
    }
    Ok(())
}

/// A.5 #1 — strict shape validator for `circle_id`.
///
/// Enforces the canonical opaque routing-token regex
/// `^ck:circle:[a-z0-9]+$` (case-insensitive ASCII alphanumerics in the
/// tail — chime allows both lowercase `ck:circle:abc123` and ULID-style
/// uppercase `ck:circle:01HZK9Z...` because both are emitted today by
/// floria). The validator rejects:
///
/// - missing / empty tail,
/// - any non-alphanumeric byte in the tail (`:` / `-` / `_` / `.` etc.),
/// - `did:` / `:did` infix anywhere in the value (mapped to
///   [`PushNotifyPrivacyError::SensitiveField`] so the caller can tell "leaked DID literal" apart
///   from "bad shape" in its observability pipeline).
///
/// The wire-model validator runs this on the typed `circle_id` field so
/// member display labels, DID literals, or any other non-opaque content
/// cannot be smuggled through the Circle routing surface even in
/// blind-wakeup mode.
fn validate_circle_id_opaque(value: Option<&str>) -> Result<(), PushNotifyPrivacyError> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.trim().is_empty() {
        return Err(PushNotifyPrivacyError::InvalidFieldValue {
            field: "circle_id".to_owned(),
        });
    }
    // Reject `:did` infix (e.g. `ck:circle:did:web:alice...`) as a
    // sensitive field rather than a shape violation so the caller can
    // tell the difference between "bad shape" and "leaked DID literal"
    // in its observability pipeline.
    if value.to_ascii_lowercase().contains("did:") || value.contains(":did") {
        return Err(PushNotifyPrivacyError::SensitiveField {
            field: "circle_id".to_owned(),
        });
    }
    let Some(tail) = value.strip_prefix("ck:circle:") else {
        return Err(PushNotifyPrivacyError::InvalidFieldValue {
            field: "circle_id".to_owned(),
        });
    };
    if tail.is_empty() || !tail.chars().all(|ch| ch.is_ascii_alphanumeric()) {
        return Err(PushNotifyPrivacyError::InvalidFieldValue {
            field: "circle_id".to_owned(),
        });
    }
    Ok(())
}

/// CXP-0007 — `effective_scope` is a typed reference that floria stamps on
/// `ck.event.*` envelopes. The only two legal prefixes are `ck:circle:`
/// (intra-Realm encrypted sub-boundary) and `ck:realm:` (legacy
/// Realm-scoped). Anything else is wire-broken.
fn validate_effective_scope(value: Option<&str>) -> Result<(), PushNotifyPrivacyError> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.trim().is_empty()
        || !(value.starts_with("ck:circle:") || value.starts_with("ck:realm:"))
    {
        return Err(PushNotifyPrivacyError::InvalidFieldValue {
            field: "effective_scope".to_owned(),
        });
    }
    Ok(())
}

fn validate_active_reference_extension(
    key: &str,
    value: &Value,
) -> Result<(), PushNotifyPrivacyError> {
    if matches!(key, "schema_id" | "kind") {
        return Err(PushNotifyPrivacyError::RemovedField {
            field: key.to_owned(),
        });
    }

    match key {
        "flow_id" => validate_extra_typed_string(key, value, "ck:flow:"),
        "message_id" => validate_extra_typed_string(key, value, "ck:message:"),
        "notification_projection_id" => {
            validate_extra_typed_string(key, value, "ck:notification_projection:")
        }
        _ => Ok(()),
    }
}

fn validate_extra_typed_string(
    key: &str,
    value: &Value,
    prefix: &str,
) -> Result<(), PushNotifyPrivacyError> {
    match value.as_str() {
        Some(raw) if raw.starts_with(prefix) => Ok(()),
        _ => Err(PushNotifyPrivacyError::InvalidFieldValue {
            field: key.to_owned(),
        }),
    }
}

fn validate_counts(path: &str, value: &Value) -> Result<(), PushNotifyPrivacyError> {
    match value {
        Value::Number(_) => Ok(()),
        Value::Object(map) => {
            for (key, nested) in map {
                validate_counts(&format!("{path}.{key}"), nested)?;
            }
            Ok(())
        }
        _ => Err(PushNotifyPrivacyError::SensitiveField {
            field: path.to_owned(),
        }),
    }
}

fn validate_extra_value(path: &str, value: &Value) -> Result<(), PushNotifyPrivacyError> {
    match value {
        Value::String(raw) => {
            if raw.to_ascii_lowercase().contains("did:") {
                return Err(PushNotifyPrivacyError::SensitiveField {
                    field: path.to_owned(),
                });
            }
            Ok(())
        }
        Value::Array(values) => {
            for (index, nested) in values.iter().enumerate() {
                validate_extra_value(&format!("{path}[{index}]"), nested)?;
            }
            Ok(())
        }
        Value::Object(map) => {
            for (key, nested) in map {
                let nested_path = format!("{path}.{key}");
                if is_sensitive_payload_key(key) {
                    return Err(PushNotifyPrivacyError::SensitiveField { field: nested_path });
                }
                validate_extra_value(&nested_path, nested)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn validate_plaintext_extra_value(path: &str, value: &Value) -> Result<(), PushNotifyPrivacyError> {
    match value {
        Value::Array(values) => {
            for (index, nested) in values.iter().enumerate() {
                validate_plaintext_extra_value(&format!("{path}[{index}]"), nested)?;
            }
            Ok(())
        }
        Value::Object(map) => {
            for (key, nested) in map {
                let nested_path = format!("{path}.{key}");
                if is_never_allowed_payload_key(key) {
                    return Err(PushNotifyPrivacyError::SensitiveField { field: nested_path });
                }
                validate_plaintext_extra_value(&nested_path, nested)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn is_sensitive_payload_key(key: &str) -> bool {
    if is_forbidden_payload_key(key) {
        return true;
    }

    matches!(
        key,
        // Local policy extension: SDK blocks `space_name` / `flow_name` /
        // `room_name`; chime also treats the v1 security-boundary display
        // label as sensitive until all downstream services agree on a
        // generic `*_name` rule.
        "realm_name"
            | "sender_actor_display_name"
            // CXP-0007 — Circle display / membership surfaces. The typed
            // `circle_id` may travel; the human-readable label and any
            // member listing must not.
            | "circle_name"
            | "circle_display_name"
            | "circle_members"
            | "circle_member_dids"
            | "circle_member_actor_ids"
    )
}

fn is_never_allowed_payload_key(key: &str) -> bool {
    matches!(
        key,
        "provider_payload"
            | "aps"
            | "encrypted_payload"
            | "encrypted_content"
            | "encrypted_metadata"
            | "metadata"
            | "fields"
            | "track"
            | "track_name"
            | "ciphertext"
            | "sdp"
            | "candidate"
            | "ice"
            | "turn"
            | "call_setup"
            // CXP-0007 — Circle membership surfaces are never allowed
            // on any wakeup wire even for plaintext-visible service DIDs.
            | "circle_members"
            | "circle_member_dids"
            | "circle_member_actor_ids"
    )
}

/// Round R2/R3 sensitive fields that must NEVER appear in any blind push
/// payload — mirrors floria T07/T10/T06.
///
/// These fields belong to spec round 2+3 governance surfaces (moderation
/// appeals, attestation evidence, cross-signing reset, identity link
/// routing, realm/space terminal lifecycle). The SDK owns the generic
/// blind-payload forbidden-key list; this chime-only tripwire covers
/// governance identifiers that should never enter a device push wakeup.
///
/// Kept as a flat slice (rather than a `match`) so the array is itself
/// public API — tests in chime / floria / yougen can iterate it to
/// build negative-vector fixtures.
pub const ROUND_R2_R3_SENSITIVE_FIELDS: &[&str] = &[
    // T07 — moderation appeals
    "appeal_id",
    "appellant",
    "reviewer",
    "decision_ref",
    "modify_decision_ref",
    // T10 — attestation evidence
    "attestation_evidence",
    "audit_agent_principal_id",
    "audit_agent_did",
    "audit_purpose",
    "audit_policy_version_digest",
    "audit_policy_version_id",
    "attestation_chain",
    "attestation_key",
    "report_data",
    // T06 — cross-signing reset wire-break
    "trust_domain",
    "trust_domain_id",
    "reset_event_id",
    "previous_generation",
    "new_generation",
    // T11 — identity link cache + policy frontier
    "policy_frontier_digest",
    "pairwise_did",
    "identity_disclosure_profile",
    "minimal_metadata_mode",
    // T16 / T17 — realm/space terminal lifecycle
    "tombstone_event_id",
    "successor_realm_id",
    "erasure_receipt_id",
    // Phase P2 (spec 37ce729, CXP-0008 / CXP-0009) — Personal Agent /
    // Sidecar governance identifiers. None of these may appear on a push
    // wakeup wire: they identify the controller↔agent binding state and
    // the action-approval transcript. Leaking either correlates a user
    // device with their native agent runtime endpoint.
    "accountability_grant_id",
    "controller_did",
    "agent_principal_id",
    "agent_session_id",
    "agent_key_id",
    "sidecar_circle_id",
    "agent_draft_id",
    "proposed_action",
    "action_payload_digest",
    "approval_nonce",
];

/// Phase P2 (spec 37ce729, CXP-0008 / CXP-0009) — durable Personal Agent
/// lifecycle event kinds that floria silently consumes upstream
/// (`AGENT_LIFECYCLE_SILENT_KINDS` in floria 6496235). chime mirrors the
/// list so client-side notification recognizers can render a *minimal*
/// summary (no PII, no actor identity, no payload) when the host app
/// chooses to surface these events to a control plane UI. The default
/// behaviour for any caller that doesn't explicitly opt in is to drop
/// the wakeup — these kinds never raise an end-user notification.
pub const AGENT_LIFECYCLE_DURABLE_KINDS: &[&str] =
    &["ck.agent.pause", "ck.agent.resume", "ck.agent.deactivate"];

/// Phase P2 — actor-private Personal Agent event kinds. These never
/// reach end-user devices by default: they're controller-private state
/// transitions between the controller and its native agent runtime.
/// chime's recognizer enforces the **blind-wakeup sanitizer** for these
/// kinds unconditionally — no payload may surface to a UI unless the
/// destination service DID is on a [`PushNotifyPolicyContext::plaintext_visible_services`]
/// whitelist.
pub const AGENT_ACTOR_PRIVATE_KINDS: &[&str] = &[
    "ck.agent.draft.propose",
    "ck.agent.action_request",
    "ck.agent.action_approve",
    "ck.agent.action_reject",
];

/// Phase P2 — seven SDK typed-id prefixes mirrored from floria
/// 6496235's `PHASE_P2_AGENT_TYPED_ID_PREFIXES`. chime uses the list to
/// reject inbound payloads that route an agent/sidecar/backup/recovery
/// typed id into a slot reserved for a *different* typed-id prefix
/// (e.g. an `agent_session` id smuggled into a wakeup's `event_id`
/// slot). `agent_principal_id` is a DID-as-id, not a `ck:*` typed id.
pub const PHASE_P2_AGENT_TYPED_ID_PREFIXES: &[&str] = &[
    "ck:agent_session:",
    "ck:agent_key:",
    "ck:agent_draft:",
    "ck:accountability_grant:",
    "ck:sidecar_circle:",
    "ck:backup_series:",
    "ck:recovery_session:",
];

/// Classification of an inbound `event_kind` against chime's Phase P2
/// agent-routing table. Returned by [`classify_agent_event_kind`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentEventRouting {
    /// Durable lifecycle (`ck.agent.{pause,resume,deactivate}`). The
    /// host MAY render a minimal summary to a control-plane UI, but
    /// MUST NOT carry any payload onto an end-user surface.
    DurableLifecycle,
    /// Actor-private (`ck.agent.{draft.propose,action_request,
    /// action_approve,action_reject}`). MUST go through the
    /// blind-wakeup sanitizer; any plaintext payload is rejected
    /// unless the destination service DID is explicitly whitelisted.
    ActorPrivate,
}

/// Classify a top-level `event_kind` against chime's Phase P2 agent
/// routing table. Returns `None` for kinds chime does not route
/// specially (the historical default: fall through to the normal
/// notification surface).
pub fn classify_agent_event_kind(event_kind: &str) -> Option<AgentEventRouting> {
    if AGENT_LIFECYCLE_DURABLE_KINDS.contains(&event_kind) {
        return Some(AgentEventRouting::DurableLifecycle);
    }
    if AGENT_ACTOR_PRIVATE_KINDS.contains(&event_kind) {
        return Some(AgentEventRouting::ActorPrivate);
    }
    None
}

/// Return `true` if `value` starts with one of the seven SDK typed-id
/// prefixes mirrored in [`PHASE_P2_AGENT_TYPED_ID_PREFIXES`]. Used by
/// chime's wire-validation layer to fail closed when one of these typed
/// ids appears in a wakeup slot that should never carry an agent /
/// sidecar / backup / recovery identifier (e.g. `event_id`,
/// `circle_id`).
pub fn is_phase_p2_agent_typed_id(value: &str) -> bool {
    PHASE_P2_AGENT_TYPED_ID_PREFIXES
        .iter()
        .any(|prefix| value.starts_with(prefix))
}

/// Phase P2 — minimal, PII-free notification summary for a durable
/// agent lifecycle event. Returned by [`render_agent_lifecycle_summary`]
/// for callers that want to surface a control-plane breadcrumb without
/// reaching into the wire payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentLifecycleSummary {
    /// The matched event kind literal (`ck.agent.pause` /
    /// `ck.agent.resume` / `ck.agent.deactivate`). Stable wire string.
    pub event_kind: &'static str,
    /// Localisation key for the human-readable summary, e.g.
    /// `l10n_key:agent.lifecycle.pause`. Hosts SHOULD render this
    /// rather than the raw `event_kind` so end-users see translated
    /// copy. No actor identity, payload digest, or accountability
    /// grant id is embedded.
    pub l10n_key: &'static str,
}

/// Render a minimal lifecycle summary for one of the three durable
/// agent kinds. Returns `None` for any other kind. The returned summary
/// is PII-free by construction — no actor, no payload, no grant id.
pub fn render_agent_lifecycle_summary(event_kind: &str) -> Option<AgentLifecycleSummary> {
    let (kind, l10n_key) = match event_kind {
        "ck.agent.pause" => ("ck.agent.pause", "l10n_key:agent.lifecycle.pause"),
        "ck.agent.resume" => ("ck.agent.resume", "l10n_key:agent.lifecycle.resume"),
        "ck.agent.deactivate" => ("ck.agent.deactivate", "l10n_key:agent.lifecycle.deactivate"),
        _ => return None,
    };
    Some(AgentLifecycleSummary {
        event_kind: kind,
        l10n_key,
    })
}

/// Phase P2 — legacy B-B field-naming aliases that were renamed in the
/// candidate-stage breaking pass (spec 37ce729 / SDK 4d5a1af). chime
/// mirrors floria 6496235's wire-side reject list so inbound push frames
/// carrying any of these legacy keys fail closed at deserialisation
/// rather than getting silently translated. The hard reject is
/// belt-and-braces: the SDK's blind-payload sanitizer also rejects
/// `message_content` / similar leaves, but the *legacy* names need
/// their own pass so an old caller can't slip past by sending the
/// rename's old form (`size` / `flow_body` / `message_body` /
/// `body_only`).
pub const PHASE_P2_LEGACY_FIELD_ALIASES: &[&str] =
    &["size", "flow_body", "message_body", "body_only"];

/// Return `true` if `key` is one of the legacy B-B field-naming aliases
/// listed in [`PHASE_P2_LEGACY_FIELD_ALIASES`]. Used by chime's wire
/// recognizers to fail closed at deserialisation.
pub fn is_legacy_field_alias(key: &str) -> bool {
    PHASE_P2_LEGACY_FIELD_ALIASES.contains(&key)
}

/// Recursively walk a JSON value and return `Err(field_path)` if any
/// nested key matches a legacy B-B field-naming alias. Used by chime's
/// wire validators (`PushNotifyReqBody::validate_wire_model`) and by
/// the drift-gate to ensure no caller can smuggle a renamed-from name
/// past us.
fn assert_no_legacy_aliases(payload: &Value) -> Result<(), String> {
    fn walk(path: &str, value: &Value) -> Result<(), String> {
        match value {
            Value::Object(map) => {
                for (key, nested) in map {
                    let nested_path = if path.is_empty() {
                        key.clone()
                    } else {
                        format!("{path}.{key}")
                    };
                    if is_legacy_field_alias(key) {
                        return Err(nested_path);
                    }
                    walk(&nested_path, nested)?;
                }
                Ok(())
            }
            Value::Array(values) => {
                for (index, nested) in values.iter().enumerate() {
                    walk(&format!("{path}[{index}]"), nested)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
    walk("", payload)
}

/// Defense-in-depth: panic in debug if any of the round 2+3 sensitive
/// fields leak into a blind push payload.
///
/// chime is the **client-side** push receiver — it almost never needs
/// to parse the body of a blind wakeup, because the body should only
/// carry routing metadata (`push_target_id`, `wakeup_kind`, `counts`,
/// `push_hint`). But if a chime integrator ever passes the decoded
/// payload through their own pipeline (e.g. to drive an in-app inbox
/// projection), this helper acts as a cheap final tripwire to catch
/// the case where floria's sanitizer was bypassed, a wire schema
/// changed without chime catching up, or a test fixture accidentally
/// carries spec-round-2/3 governance state.
///
/// The check is recursive — nested objects and arrays inside `payload`
/// are walked, and any sensitive field name at any depth is flagged.
///
/// ## Behaviour
///
/// * In `debug_assertions` builds (typical for `cargo test` and dev builds) the function **panics**
///   with the offending field path. We want loud failures during development — a leaked governance
///   id is a privacy bug, not a recoverable user-input error.
/// * In release builds it returns `Err(field_path)` so production integrations can log and fail
///   closed without taking the process down. Returning the path (not just a bool) gives operators
///   something to grep for in incident response.
///
/// Returns `Ok(())` when the payload is clean.
//
pub fn assert_no_sensitive_fields(payload: &Value) -> Result<(), String> {
    fn walk(path: &str, value: &Value) -> Result<(), String> {
        match value {
            Value::Object(map) => {
                for (key, nested) in map {
                    let nested_path = if path.is_empty() {
                        key.clone()
                    } else {
                        format!("{path}.{key}")
                    };
                    if ROUND_R2_R3_SENSITIVE_FIELDS.contains(&key.as_str()) {
                        return Err(nested_path);
                    }
                    walk(&nested_path, nested)?;
                }
                Ok(())
            }
            Value::Array(values) => {
                for (index, nested) in values.iter().enumerate() {
                    let nested_path = format!("{path}[{index}]");
                    walk(&nested_path, nested)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    if let Err(field_path) = walk("", payload) {
        debug_assert!(
            false,
            "round 2+3 sensitive field `{field_path}` must never appear in a blind push payload"
        );
        return Err(field_path);
    }
    Ok(())
}

fn validate_base64_field(field: &'static str, value: &str) -> Result<(), EncryptedEnvelopeError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(EncryptedEnvelopeError::MissingField { field });
    }

    if general_purpose::STANDARD.decode(value).is_ok()
        || general_purpose::URL_SAFE.decode(value).is_ok()
        || general_purpose::URL_SAFE_NO_PAD.decode(value).is_ok()
    {
        Ok(())
    } else {
        Err(EncryptedEnvelopeError::InvalidBase64 { field })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device() -> PushNotificationDevice {
        PushNotificationDevice {
            push_key: "fcm:very-secret-token".to_owned(),
            app_id: Some("app.example".to_owned()),
            registration_id: None,
            push_key_hash: Some("sha256:abc".to_owned()),
            platform: Some("android".to_owned()),
        }
    }

    fn notification() -> PushNotification {
        // `PushNotification` is `#[non_exhaustive]`; build through
        // `Default` and field-update so adding a new optional field
        // does not require touching every test fixture.
        PushNotification {
            push_target_id: Some(
                PushTargetId::new("ck:pseudonym:push:01HYZ8Z000000000000000").unwrap(),
            ),
            wakeup_kind: Some(WakeupKind::Message),
            event_id: Some("ck:event:01JS0EV000000000000000000".to_owned()),
            realm_id: Some("ck:realm:01JS0SP000000000000000000".to_owned()),
            push_hint: Some(PushHint::new("new_message").unwrap()),
            counts: Some(serde_json::json!({ "unread": 1 })),
            devices: vec![device()],
            ..Default::default()
        }
    }

    #[test]
    fn push_hint_accepts_only_protocol_vocabulary() {
        PushHint::new("new_message").unwrap();
        PushHint::new("incoming_call").unwrap();
        PushHint::new("mention_self").unwrap();
        PushHint::new("l10n_key:message.new").unwrap();

        assert!(PushHint::new("New message").is_err());
        assert!(PushHint::new("title:secret").is_err());
    }

    #[test]
    fn wakeup_kind_rejects_unknown_values() {
        let value = "custom_kind";
        let error = serde_json::from_value::<WakeupKind>(Value::String(value.to_owned()))
            .expect_err("unknown wakeup kind must fail closed");
        assert!(
            error
                .to_string()
                .contains("message, mention, reaction, call_invite"),
            "unexpected error for {value}: {error}"
        );

        assert_eq!(
            serde_json::from_value::<WakeupKind>(Value::String("call_invite".to_owned())).unwrap(),
            WakeupKind::CallInvite
        );
    }

    #[test]
    fn blind_wakeup_rejects_plaintext_metadata() {
        let mut notification = notification();
        notification
            .extra
            .insert("title".to_owned(), Value::String("Secret".to_owned()));

        assert_eq!(
            notification.validate_blind_wakeup().unwrap_err(),
            PushNotifyPrivacyError::SensitiveField {
                field: "title".to_owned()
            }
        );
    }

    #[test]
    fn blind_wakeup_rejects_audience_mention_expansion_metadata() {
        let mut notification = notification();
        notification.extra.insert(
            "audience_mention_routing_hint".to_owned(),
            serde_json::json!({
                "audience": "flow_engaged",
                "recipient_count": 3,
            }),
        );

        assert_eq!(
            notification.validate_blind_wakeup().unwrap_err(),
            PushNotifyPrivacyError::SensitiveField {
                field: "audience_mention_routing_hint".to_owned()
            }
        );
    }

    #[test]
    fn deserialized_extra_fields_require_runtime_validation() {
        let loaded: PushNotification = serde_json::from_value(serde_json::json!({
            "push_target_id": "ck:pseudonym:push:01HYZ8Z000000000000000",
            "wakeup_kind": "message",
            "kind": "captured-extra-field",
            "devices": [{
                "push_key": "fcm:very-secret-token",
                "app_id": "app.example"
            }]
        }))
        .unwrap();

        assert!(loaded.extra.contains_key("kind"));
        assert!(matches!(
            loaded.validate_wire_model().unwrap_err(),
            PushNotifyPrivacyError::RemovedField { field } if field == "kind"
        ));
    }

    #[test]
    fn notify_request_validates_fixture_shape() {
        let request = PushNotifyReqBody {
            operation_id: Some(crate::OPERATION_PUSH_NOTIFY.to_owned()),
            notification: notification(),
            ..Default::default()
        };

        request.validate_blind_wakeup().unwrap();
    }

    #[test]
    fn push_target_id_accepts_typed_and_raw_tokens() {
        PushTargetId::new("ck:pseudonym:push:01HYZ8Z000000000000000").unwrap();
        PushTargetId::new("01HYZ8Z000000000000000").unwrap();

        assert!(PushTargetId::new("ck:device:01HYZ8Z000000000000000").is_err());
        assert!(PushTargetId::new("did:web:alice.example").is_err());
    }

    #[test]
    fn encrypted_envelope_validates_base64_payloads() {
        let envelope =
            EncryptedEnvelope::new("did:web:alice.example", "x25519", "Y2lwaGVydGV4dA==")
                .unwrap()
                .with_nonce("bm9uY2VfYWJj")
                .unwrap()
                .with_key_id("kid-1")
                .with_aad("ck.push.notify");

        envelope.validate().unwrap();
        assert!(EncryptedEnvelope::new("alice", "x25519", "Y2lwaGVydGV4dA==").is_err());
        assert!(EncryptedEnvelope::new("did:web:alice", "x25519", "not base64!").is_err());
    }

    #[test]
    fn debug_redacts_push_tokens() {
        let debug = format!("{:?}", device());
        assert!(debug.contains("fcm:<redacted"));
        assert!(!debug.contains("very-secret-token"));

        let rejected = RejectedPushToken {
            push_key: Some("fcm:very-secret-token".to_owned()),
            push_key_hash: Some("pkh_abc".to_owned()),
            app_id: Some("app.example".to_owned()),
            reason: Some("unregistered".to_owned()),
        };
        let debug = format!("{rejected:?}");
        assert!(debug.contains("fcm:<redacted"));
        assert!(!debug.contains("very-secret-token"));
    }

    #[test]
    fn assert_no_sensitive_fields_accepts_clean_payload() {
        let payload = serde_json::json!({
            "push_target_id": "ck:pseudonym:push:01HYZ8Z000000000000000",
            "wakeup_kind": "message",
            "counts": {"unread": 1},
        });
        assert_no_sensitive_fields(&payload).unwrap();
    }

    #[test]
    fn assert_no_sensitive_fields_rejects_round23_governance_fields() {
        for field in ROUND_R2_R3_SENSITIVE_FIELDS {
            let payload = serde_json::json!({
                "push_target_id": "ck:pseudonym:push:01HYZ8Z000000000000000",
                "wakeup_kind": "message",
                *field: "leaked-value",
            });
            // The release-build return value is what we lock in;
            // debug builds will panic in `walk` first, which is also
            // what we want, so we run the function with a catch_unwind
            // so the test verifies both paths.
            let outcome = std::panic::catch_unwind(|| assert_no_sensitive_fields(&payload));
            match outcome {
                Ok(Ok(())) => panic!("field `{field}` slipped through"),
                Ok(Err(path)) => assert!(
                    path.contains(field),
                    "returned path `{path}` should mention `{field}`"
                ),
                Err(_) => {
                    // debug_assert! triggered — also a pass.
                }
            }
        }
    }

    #[test]
    fn assert_no_sensitive_fields_walks_nested_objects() {
        let payload = serde_json::json!({
            "push_target_id": "ck:pseudonym:push:01HYZ8Z000000000000000",
            "metadata": {
                "deep": {
                    "appeal_id": "ck:appeal:01ABC"
                }
            }
        });
        let outcome = std::panic::catch_unwind(|| assert_no_sensitive_fields(&payload));
        match outcome {
            Ok(Ok(())) => panic!("nested appeal_id slipped through"),
            Ok(Err(path)) => assert!(path.contains("appeal_id")),
            Err(_) => {} // debug panic path
        }
    }

    #[test]
    fn assert_no_sensitive_fields_walks_arrays() {
        let payload = serde_json::json!({
            "items": [
                {"ok": 1},
                {"trust_domain": "ck:trust_domain:example.net"}
            ]
        });
        let outcome = std::panic::catch_unwind(|| assert_no_sensitive_fields(&payload));
        match outcome {
            Ok(Ok(())) => panic!("array trust_domain slipped through"),
            Ok(Err(path)) => assert!(path.contains("trust_domain")),
            Err(_) => {} // debug panic path
        }
    }

    // ── Round 4 (B5) — mention_redirect plaintext routing tests ───────

    #[test]
    fn decrypt_allowed_for_actor_no_routing_is_open() {
        // No `mention_redirect` field → not a mention-redirect wakeup,
        // gate decision lives elsewhere, return true.
        let notification = notification();
        let actor = Did::new("did:web:alice.example").unwrap();
        assert!(notification.decrypt_allowed_for_actor(&actor));
        assert!(!notification.has_mention_redirect_routing());
    }

    #[test]
    fn decrypt_allowed_for_actor_in_list_passes() {
        let mut notification = notification();
        let alice = Did::new("did:web:alice.example").unwrap();
        let bob = Did::new("did:webvh:bob.example").unwrap();
        notification.mention_redirect = Some(MentionRedirectRouting {
            mention_redirect_target_actor_ids: vec![alice.clone(), bob.clone()],
        });
        assert!(notification.has_mention_redirect_routing());
        assert!(notification.decrypt_allowed_for_actor(&alice));
        assert!(notification.decrypt_allowed_for_actor(&bob));
    }

    #[test]
    fn decrypt_allowed_for_actor_not_in_list_is_fail_closed() {
        let mut notification = notification();
        let alice = Did::new("did:web:alice.example").unwrap();
        let mallory = Did::new("did:web:mallory.example").unwrap();
        notification.mention_redirect = Some(MentionRedirectRouting {
            mention_redirect_target_actor_ids: vec![alice],
        });
        // Mallory is not in the list → fail-closed.
        assert!(!notification.decrypt_allowed_for_actor(&mallory));
    }

    #[test]
    fn decrypt_allowed_for_actor_empty_list_is_fail_closed() {
        // B5: an empty mention_redirect_target_actor_ids array means
        // *nobody* is allowed — explicit empty wakeups should not fall
        // back to "open". Fail closed by construction.
        let mut notification = notification();
        notification.mention_redirect = Some(MentionRedirectRouting::default());
        let anyone = Did::new("did:web:anyone.example").unwrap();
        assert!(notification.has_mention_redirect_routing());
        assert!(!notification.decrypt_allowed_for_actor(&anyone));
    }

    #[test]
    fn mention_redirect_round_trips_through_json() {
        let mut notification = notification();
        let alice = Did::new("did:web:alice.example").unwrap();
        notification.mention_redirect = Some(MentionRedirectRouting {
            mention_redirect_target_actor_ids: vec![alice.clone()],
        });
        let json = serde_json::to_string(&notification).unwrap();
        // Ensure the field is serialised under the canonical wire name.
        assert!(
            json.contains("mention_redirect_target_actor_ids"),
            "wire name must survive serde: {json}",
        );
        let loaded: PushNotification = serde_json::from_str(&json).unwrap();
        assert!(loaded.decrypt_allowed_for_actor(&alice));
    }

    // ── Round 4 (B5) — e2ee_late_recovery banner surface tests ────────

    #[test]
    fn late_recovery_event_id_is_some_for_e2ee_late_recovery() {
        // Parse the SDK shape via JSON so chime doesn't need to depend
        // on `chrono` directly to construct timestamps in tests.
        let payload: AuditPolicyAccessPayload = serde_json::from_value(serde_json::json!({
            "realm_id": "ck:realm:01904100-0000-7000-8000-000000000001",
            "actor": "did:web:alice.example",
            "access_kind": "e2_e_e_late_recovery",
            "late_recovery_original_event_id":
                "ck:event:01904100-0000-7000-8000-000000000002",
            "observed_at": "2026-05-20T00:00:00Z",
        }))
        .unwrap();
        // Sanity-check the SDK validator agrees.
        payload.validate_minimal().unwrap();

        let expected_event_id =
            EventId::new("ck:event:01904100-0000-7000-8000-000000000002").unwrap();
        let mut notification = notification();
        notification.policy_access = Some(payload);
        assert_eq!(
            notification.late_recovery_event_id(),
            Some(&expected_event_id)
        );
    }

    #[test]
    fn late_recovery_event_id_is_none_for_other_access_kinds() {
        let payload: AuditPolicyAccessPayload = serde_json::from_value(serde_json::json!({
            "realm_id": "ck:realm:01904100-0000-7000-8000-000000000001",
            "actor": "did:web:alice.example",
            "access_kind": "audit",
            "observed_at": "2026-05-20T00:00:00Z",
        }))
        .unwrap();
        let mut notification = notification();
        notification.policy_access = Some(payload);
        assert!(notification.late_recovery_event_id().is_none());
    }

    #[test]
    fn late_recovery_event_id_is_none_when_payload_absent() {
        let notification = notification();
        assert!(notification.late_recovery_event_id().is_none());
    }

    // ── CXP-0007 (Circle primitive) — circle_id / effective_scope ────────

    #[test]
    fn circle_id_and_effective_scope_round_trip_through_json() {
        let mut n = notification();
        n.circle_id = Some("ck:circle:01HZK9Z000000000000000000".to_owned());
        n.effective_scope = Some("ck:circle:01HZK9Z000000000000000000".to_owned());
        let json = serde_json::to_string(&n).unwrap();
        assert!(json.contains("circle_id"));
        assert!(json.contains("effective_scope"));
        let loaded: PushNotification = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.circle_id, n.circle_id);
        assert_eq!(loaded.effective_scope, n.effective_scope);
        // Wire shape validates.
        loaded.validate_wire_model().unwrap();
        // And it passes blind-wakeup privacy (typed circle_id is allowed
        // as opaque routing metadata).
        loaded.validate_blind_wakeup().unwrap();
    }

    #[test]
    fn circle_id_rejects_untyped_value() {
        let mut n = notification();
        n.circle_id = Some("not-a-typed-id".to_owned());
        assert!(matches!(
            n.validate_wire_model().unwrap_err(),
            PushNotifyPrivacyError::InvalidFieldValue { field } if field == "circle_id"
        ));
    }

    #[test]
    fn effective_scope_accepts_circle_or_realm_prefix() {
        let mut n = notification();
        n.effective_scope = Some("ck:realm:01HZK9Z000000000000000000".to_owned());
        n.validate_wire_model().unwrap();
        n.effective_scope = Some("ck:circle:01HZK9Z000000000000000000".to_owned());
        n.validate_wire_model().unwrap();
    }

    #[test]
    fn effective_scope_rejects_other_prefixes() {
        let mut n = notification();
        n.effective_scope = Some("ck:flow:01HZK9Z000000000000000000".to_owned());
        assert!(matches!(
            n.validate_wire_model().unwrap_err(),
            PushNotifyPrivacyError::InvalidFieldValue { field } if field == "effective_scope"
        ));
    }

    #[test]
    fn blind_wakeup_rejects_circle_id_carrying_did_literal() {
        let mut n = notification();
        // Force-bypass the typed-id check at construction by skipping
        // PushTargetId's constructor; the wire-model validator is what
        // we want to exercise here. We set a value that satisfies the
        // `ck:circle:` prefix but smuggles a did: literal in the tail.
        n.circle_id = Some("ck:circle:did:web:alice.example".to_owned());
        let err = n.validate_blind_wakeup().unwrap_err();
        assert!(matches!(
            err,
            PushNotifyPrivacyError::SensitiveField { field } if field == "circle_id"
        ));
    }

    #[test]
    fn blind_wakeup_rejects_circle_name_in_extra() {
        let mut n = notification();
        n.extra.insert(
            "circle_name".to_owned(),
            Value::String("Bridge Team".to_owned()),
        );
        let err = n.validate_blind_wakeup().unwrap_err();
        assert!(matches!(
            err,
            PushNotifyPrivacyError::SensitiveField { field } if field == "circle_name"
        ));
    }

    #[test]
    fn plaintext_visible_service_rejects_circle_members_array() {
        let mut n = notification();
        n.extra.insert(
            "circle_members".to_owned(),
            serde_json::json!(["did:web:alice.example"]),
        );
        let err = n.validate_plaintext_visible_service().unwrap_err();
        assert!(matches!(
            err,
            PushNotifyPrivacyError::SensitiveField { field } if field == "circle_members"
        ));
    }

    // ── Phase P2 (spec 37ce729) — Personal Agent event-kind parsing ─────

    #[test]
    fn agent_lifecycle_summary_is_pii_free() {
        // Each durable lifecycle kind renders an l10n key and no actor,
        // payload, or grant identifier. The host MUST be able to
        // surface the summary to a control-plane UI without leaking PII.
        for (kind, expected_suffix) in [
            ("ck.agent.pause", "pause"),
            ("ck.agent.resume", "resume"),
            ("ck.agent.deactivate", "deactivate"),
        ] {
            let summary = render_agent_lifecycle_summary(kind).expect("renders");
            assert_eq!(summary.event_kind, kind);
            assert_eq!(
                summary.l10n_key,
                format!("l10n_key:agent.lifecycle.{expected_suffix}")
            );
        }
        assert!(render_agent_lifecycle_summary("ck.agent.draft.propose").is_none());
        assert!(render_agent_lifecycle_summary("ck.message.create").is_none());
    }

    #[test]
    fn agent_typed_id_in_extra_fails_closed() {
        // An agent / sidecar / backup / recovery typed-id appearing in
        // `extra` is a correlation leak — the wakeup wire never carries
        // these prefixes in a non-Agent slot. chime MUST reject the
        // frame.
        for prefix in PHASE_P2_AGENT_TYPED_ID_PREFIXES {
            let mut n = notification();
            n.extra.insert(
                "smuggled".to_owned(),
                Value::String(format!("{prefix}01HZK9Z000000000000000000")),
            );
            let err = n.validate_wire_model().unwrap_err();
            match err {
                PushNotifyPrivacyError::SensitiveField { field } => {
                    assert_eq!(field, "smuggled");
                }
                other => panic!("expected SensitiveField for prefix `{prefix}`, got {other:?}"),
            }
        }
    }

    #[test]
    fn round23_sensitive_fields_cover_agent_governance_set() {
        // Phase P2 added 10 agent / sidecar / recovery governance
        // identifiers to the `assert_no_sensitive_fields` tripwire.
        // Spot-check each one to lock in the wire-side reject.
        for field in [
            "accountability_grant_id",
            "controller_did",
            "agent_principal_id",
            "agent_session_id",
            "agent_key_id",
            "sidecar_circle_id",
            "agent_draft_id",
            "proposed_action",
            "action_payload_digest",
            "approval_nonce",
        ] {
            assert!(
                ROUND_R2_R3_SENSITIVE_FIELDS.contains(&field),
                "field `{field}` must be in ROUND_R2_R3_SENSITIVE_FIELDS"
            );
            let payload = serde_json::json!({
                "push_target_id": "ck:pseudonym:push:01HYZ8Z000000000000000",
                "wakeup_kind": "message",
                field: "leaked-value",
            });
            let outcome = std::panic::catch_unwind(|| assert_no_sensitive_fields(&payload));
            match outcome {
                Ok(Ok(())) => panic!("agent field `{field}` slipped through"),
                Ok(Err(path)) => assert!(
                    path.contains(field),
                    "returned path `{path}` should mention `{field}`"
                ),
                Err(_) => {
                    // debug_assert! triggered — also a pass.
                }
            }
        }
    }
}
