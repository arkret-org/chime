use std::fmt;

// Round 4 (B5, spec a77b995) — pull typed audit surfaces from the SDK so
// chime stays byte-aligned with what soland/floria emit.
use cokret::{AccessKind, AuditPolicyAccessPayload, Did, EventId};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::agent_routing::{
    assert_no_forbidden_aliases, assert_no_sensitive_fields, is_forbidden_field_alias,
    is_phase_p2_agent_typed_id,
};
use super::errors::PushNotifyPrivacyError;
use super::validation::{
    is_never_allowed_payload_key, is_sensitive_payload_key, run_sdk_sanitizer_over_extra,
    validate_active_reference_extension, validate_circle_id_opaque, validate_counts,
    validate_effective_scope, validate_extra_value, validate_optional_non_empty,
    validate_plaintext_extra_value, validate_push_hint_value, validate_push_target_id,
    validate_required, validate_typed_id,
};
use crate::redact_push_key;

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
    Reminder,
    ScheduledSend,
    ExpiryInvalidation,
}

impl WakeupKind {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Message => "message",
            Self::Mention => "mention",
            Self::Reaction => "reaction",
            Self::CallInvite => "call_invite",
            Self::Reminder => "reminder",
            Self::ScheduledSend => "scheduled_send",
            Self::ExpiryInvalidation => "expiry_invalidation",
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
            "reminder" => Self::Reminder,
            "scheduled_send" => Self::ScheduledSend,
            "expiry_invalidation" => Self::ExpiryInvalidation,
            _ => {
                return Err(serde::de::Error::custom(
                    "wakeup_kind must be one of message, mention, reaction, call_invite, reminder, scheduled_send, expiry_invalidation",
                ));
            }
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
/// Wire notification descriptor for `ck.edge.push.command.notify`.
///
/// This type intentionally carries unknown JSON fields in [`Self::extra`]
/// because `#[serde(flatten)]` cannot be combined with
/// `deny_unknown_fields`. Deserialization alone is therefore not a
/// safety boundary: callers that parse JSON into `PushNotification`
/// or [`super::ChimePushNotifyEnvelope`] MUST immediately run
/// [`super::ChimePushNotifyEnvelope::assert_payload_safe`],
/// [`super::ChimePushNotifyEnvelope::validate_blind_wakeup`], or
/// [`Self::validate_wire_model`] before reading fields or showing UI.
pub struct PushNotification {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_target_id: Option<PushTargetId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wakeup_kind: Option<WakeupKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    /// SPEC-CR-016 (class B) — gateway-internal routing fragment
    /// (`realm_id` / `circle_id` / `effective_scope`). Stripped before any
    /// provider call; see [`RoutingMetadata`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routing_metadata: Option<RoutingMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_actor_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_actor_display_name: Option<String>,
    /// SPEC-CR-016 (class C) — profile-gated client-visible priority hint
    /// (e.g. `low`). Only meaningful under
    /// `ck.profile.push_gateway.visible_notification.v1`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_hint: Option<PushHint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_hint_l10n_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<Value>,
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

/// SPEC-CR-016 — gateway-internal routing fragment carried under
/// `notification.routing_metadata`. Every field here drives gateway-side
/// routing / dedup and MUST be stripped before any provider sees it.
///
/// NOTE: `routing_metadata.realm_id` is a distinct gateway-internal
/// routing path and is NOT a client-visible top-level `realm_id`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingMetadata {
    /// Security-boundary identifier (`ck:realm:...`). Gateway-internal
    /// routing; stripped before any provider call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<String>,
    /// CKP-0007 Circle (intra-Realm encrypted sub-boundary) typed id.
    /// Travels as opaque routing metadata; the "no Circle member name
    /// leak" invariant is enforced by [`validate_circle_id_opaque`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub circle_id: Option<String>,
    /// Round-4 gateway-internal scope Circle ID. Distinct from the
    /// legacy `circle_id` delivery hint: this identifies the scoped
    /// Circle boundary used by routing policy and is stripped before
    /// provider delivery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_circle_id: Option<String>,
    /// CKP-0007 — mirror of the event envelope's `effective_scope`
    /// (`ck:circle:...` or `ck:realm:...`). Lets the client correlate the
    /// wakeup with the authoring scope without a round-trip.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_scope: Option<String>,
    /// Round-4 mention-redirect routing allow-list. When present, only
    /// actor IDs in this list may decrypt the (otherwise encrypted) body at
    /// the push layer — see [`PushNotification::decrypt_allowed_for_actor`].
    /// Gateway-internal; stripped before any provider call.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mention_redirect_target_actor_ids: Vec<Did>,
    /// Receiver's accepted Realm delivery-binding frontier on a federation
    /// hop. Gateway-internal; stripped before any provider call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_binding_frontier: Option<String>,
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

    /// SPEC-CR-016 — gateway-internal routing `realm_id` (under
    /// `routing_metadata`).
    pub fn realm_id(&self) -> Option<&str> {
        self.routing_metadata
            .as_ref()
            .and_then(|routing| routing.realm_id.as_deref())
    }

    /// SPEC-CR-016 — gateway-internal routing `circle_id`.
    pub fn circle_id(&self) -> Option<&str> {
        self.routing_metadata
            .as_ref()
            .and_then(|routing| routing.circle_id.as_deref())
    }

    /// SPEC-CR-016 — gateway-internal routing `scope_circle_id`.
    pub fn scope_circle_id(&self) -> Option<&str> {
        self.routing_metadata
            .as_ref()
            .and_then(|routing| routing.scope_circle_id.as_deref())
    }

    /// SPEC-CR-016 — gateway-internal `effective_scope` mirror.
    pub fn effective_scope(&self) -> Option<&str> {
        self.routing_metadata
            .as_ref()
            .and_then(|routing| routing.effective_scope.as_deref())
    }

    /// SPEC-CR-016 — mention-redirect routing fragment (under
    /// `routing_metadata`).
    pub fn mention_redirect_target_actor_ids(&self) -> Option<&[Did]> {
        let ids = &self
            .routing_metadata
            .as_ref()?
            .mention_redirect_target_actor_ids;
        if ids.is_empty() {
            None
        } else {
            Some(ids.as_slice())
        }
    }

    pub fn validate_wire_model(&self) -> Result<(), PushNotifyPrivacyError> {
        if self.wakeup_kind.is_none() {
            return Err(PushNotifyPrivacyError::MissingField {
                field: "wakeup_kind".to_owned(),
            });
        }

        validate_typed_id("event_id", self.event_id.as_deref(), "ck:event:")?;
        validate_typed_id("realm_id", self.realm_id(), "ck:realm:")?;
        validate_typed_id("scope_circle_id", self.scope_circle_id(), "ck:circle:")?;
        // CKP-0007 — Circle primitive typed-shape validation. We don't
        // require either to be present (Realm-scoped wakeups can set
        // realm_id only), but when present they MUST be the
        // canonical typed-id shape so floria/yougen don't have to
        // re-parse arbitrary strings later.
        //
        // A.5 #1 — `circle_id` is the canonical opaque routing token in
        // blind-wakeup mode. Tighten its shape from the generic
        // `validate_typed_id` (which only checks the prefix) to a strict
        // regex equivalent of `^ck:circle:[a-z0-9]+$` so member-name /
        // display-label exfiltration via the tail is rejected at the
        // wire layer.
        validate_circle_id_opaque(self.circle_id())?;
        validate_effective_scope(self.effective_scope())?;
        validate_optional_non_empty("realm_title", self.realm_title.as_deref())?;
        if self
            .push_hint
            .as_ref()
            .is_some_and(|hint| hint.as_str() == "l10n_key")
        {
            validate_required(
                "push_hint_l10n_key",
                self.push_hint_l10n_key.as_deref().unwrap_or_default(),
            )?;
        } else if self.push_hint_l10n_key.is_some() {
            return Err(PushNotifyPrivacyError::InvalidFieldValue {
                field: "push_hint_l10n_key".to_owned(),
            });
        }

        if self.devices.is_empty() {
            return Err(PushNotifyPrivacyError::MissingField {
                field: "devices".to_owned(),
            });
        }
        for device in &self.devices {
            device.validate_wire_model()?;
        }
        if let Err(path) = assert_no_sensitive_fields(&Value::Object(self.extra.clone())) {
            return Err(PushNotifyPrivacyError::SensitiveField { field: path });
        }
        for (key, value) in &self.extra {
            // Phase P2 (spec 37ce729) — removed B-B field-naming aliases
            // fail closed at the wire layer. floria 6496235 mirrors the
            // same reject set on the gateway side; chime is the client-side
            // mirror.
            if is_forbidden_field_alias(key) {
                return Err(PushNotifyPrivacyError::RemovedField {
                    field: key.to_owned(),
                });
            }
            // Reject nested removed aliases too (e.g. `media.size`).
            if let Err(path) = assert_no_forbidden_aliases(value) {
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

        if self.event_id.is_some() {
            return Err(PushNotifyPrivacyError::SensitiveField {
                field: "event_id".to_owned(),
            });
        }
        if self.sender_actor_id.is_some() {
            return Err(PushNotifyPrivacyError::SensitiveField {
                field: "sender_actor_id".to_owned(),
            });
        }
        if self.sender_actor_display_name.is_some() {
            return Err(PushNotifyPrivacyError::SensitiveField {
                field: "sender_actor_display_name".to_owned(),
            });
        }
        if self.realm_title.is_some() {
            return Err(PushNotifyPrivacyError::SensitiveField {
                field: "realm_title".to_owned(),
            });
        }
        // CKP-0007 Circle metadata privacy invariant: even in blind
        // mode where `circle_id` may travel as opaque routing metadata,
        // the wakeup MUST NOT leak Circle membership/display fields.
        // The strict opaque validator in `validate_wire_model` already
        // rejects any `did:`/`:did` substring in the tail (it enforces
        // `^ck:circle:[a-z0-9]+$`), so we keep the belt-and-braces
        // SensitiveField mapping here for callers that bypass the
        // wire-model validator and call `validate_blind_wakeup` directly.
        if let Some(circle_id) = self.circle_id()
            && (circle_id.to_ascii_lowercase().contains("did:") || circle_id.contains(":did"))
        {
            return Err(PushNotifyPrivacyError::SensitiveField {
                field: "circle_id".to_owned(),
            });
        }
        if let Some(counts) = &self.counts {
            validate_counts("counts", None, counts)?;
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
    /// - When `mention_redirect_target_actor_ids` is empty, this is NOT a mention-redirect scenario
    ///   and the call returns `true` (the normal recipient-set gate elsewhere applies).
    /// - When it is non-empty, the receiver's actor ID MUST appear in the list to be permitted.
    ///
    /// This is the canonical accessor consumers (yougen, floria, host
    /// apps) should call before unwrapping the body. Direct reads of
    /// `mention_redirect_target_actor_ids` are permitted for display but
    /// MUST NOT gate decryption — the
    /// fail-closed semantics live here, not at the call site.
    pub fn decrypt_allowed_for_actor(&self, receiver_actor_id: &Did) -> bool {
        let Some(allowed_ids) = self.mention_redirect_target_actor_ids() else {
            // Not a mention-redirect wakeup; gate is decided elsewhere.
            return true;
        };
        allowed_ids
            .iter()
            .any(|allowed| allowed == receiver_actor_id)
    }

    /// Round 4 (B5) — return `true` when this wakeup carries
    /// mention-redirect plaintext routing (regardless of whether any
    /// actor is permitted). Consumers can branch on this to render
    /// "@-mention redirected to N actors" UI.
    pub fn has_mention_redirect_routing(&self) -> bool {
        self.mention_redirect_target_actor_ids().is_some()
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
        if let Some(circle_id) = self.circle_id() {
            hint = hint.with_circle_id(circle_id);
        }
        if let Some(realm_id) = self.realm_id() {
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
    pub device_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_actor_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
}

impl fmt::Debug for PushNotificationDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PushNotificationDevice")
            .field("device_id", &self.device_id)
            .field("push_key", &self.push_key.as_deref().map(redact_push_key))
            .field("app_id", &self.app_id)
            .field("target_actor_id", &self.target_actor_id)
            .field("platform", &self.platform)
            .finish()
    }
}

impl PushNotificationDevice {
    fn validate_wire_model(&self) -> Result<(), PushNotifyPrivacyError> {
        validate_required("devices[].device_id", &self.device_id)?;
        validate_optional_non_empty("devices[].push_key", self.push_key.as_deref())
    }
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
