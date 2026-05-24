//! Optional `cx.push.notify` wire model for Push Gateway implementations.
//!
//! This module models the Contrix notify request/response payload and keeps
//! blind-wakeup validation conservative. It does not implement APNs, FCM, Web
//! Push, or OEM provider delivery.

use std::fmt;

use base64::{Engine as _, engine::general_purpose};
use contrix::blind_payload_sanitizer::{
    self as sdk_sanitizer, BlindPayloadError, BlindPayloadReasonCode,
};
// Round 4 (B5, spec a77b995) — pull the typed shapes for
// `mention_redirect_target_actor_ids` plaintext routing and the
// `cx.audit.policy_access` late-key-recovery banner straight from the
// SDK so chime stays byte-aligned with what soland/floria emit. The
// SDK module is `contrix::model::round4::*`, re-exported via
// `contrix::model::*` and the crate root.
use contrix::{AccessKind, AuditPolicyAccessPayload, Did, EventId, MentionRedirectRouting};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::redact_push_key;

/// Request body for `POST /api/v1/push/notify`.
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
        if let Some(operation_id) = self.operation_id.as_deref() {
            if operation_id != crate::OPERATION_PUSH_NOTIFY {
                return Err(PushNotifyPrivacyError::InvalidFieldValue {
                    field: "operation_id".to_owned(),
                });
            }
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
    IncomingCall,
    Mention,
    Member,
    Presence,
    Custom(String),
}

impl WakeupKind {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Message => "message",
            Self::IncomingCall => "incoming_call",
            Self::Mention => "mention",
            Self::Member => "member",
            Self::Presence => "presence",
            Self::Custom(value) => value.as_str(),
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
            "incoming_call" => Self::IncomingCall,
            "mention" => Self::Mention,
            "member" => Self::Member,
            "presence" => Self::Presence,
            _ => {
                validate_custom_wakeup_kind(&raw).map_err(serde::de::Error::custom)?;
                Self::Custom(raw)
            }
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct PushNotification {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_target_id: Option<PushTargetId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wakeup_kind: Option<WakeupKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    /// Security-boundary identifier ("Realm" in the post-reversal
    /// protocol, formerly called Space). Still emitted on the
    /// blind-wakeup wire model only when allowed by the privacy
    /// descriptor; the SDK sanitizer treats `realm_id` (and the
    /// retained, now-container `space_id`) as forbidden top-level
    /// payload keys, so this field is also enumerated in
    /// [`PushNotification::validate_blind_wakeup`] below.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_hint: Option<PushHint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<Value>,
    /// Round 4 (B5, spec a77b995) — plaintext routing fragment for
    /// mention-redirect scenarios. Only actor DIDs in
    /// `mention_redirect_target_actor_ids` are permitted to decrypt the
    /// (otherwise encrypted) message body at the push layer. If the
    /// receiver's actor_id is NOT in the list, the body MUST stay
    /// encrypted and the wakeup is delivered as opaque routing
    /// metadata only — see [`PushNotification::decrypt_allowed_for_actor`].
    ///
    /// The field is intentionally typed (`MentionRedirectRouting`,
    /// re-exported from `contrix::model::round4`) rather than carried in
    /// `extra`, so consumers cannot accidentally bypass the fail-closed
    /// check by reading raw JSON.
    ///
    /// Wire shape (canonical, both modes):
    /// ```json
    /// "mention_redirect": {
    ///     "mention_redirect_target_actor_ids": ["did:web:alice.example", "did:webvh:bob.example"]
    /// }
    /// ```
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mention_redirect: Option<MentionRedirectRouting>,
    /// Round 4 (B5) — typed `cx.audit.policy_access` payload surfaced to
    /// consumers (e.g. yougen) so the late-key-recovery banner can read
    /// `late_recovery_original_event_id` directly off the wakeup. This
    /// is diagnostic context — push layer never decrypts on the
    /// strength of this field alone. The SDK validates the
    /// `(access_kind, late_recovery_original_event_id)` pairing via
    /// [`contrix::AuditPolicyAccessPayload::validate_minimal`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_access: Option<AuditPolicyAccessPayload>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<PushNotificationDevice>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl PushNotification {
    pub fn validate_wire_model(&self) -> Result<(), PushNotifyPrivacyError> {
        if self.wakeup_kind.is_none() {
            return Err(PushNotifyPrivacyError::MissingField {
                field: "wakeup_kind".to_owned(),
            });
        }

        validate_typed_id("event_id", self.event_id.as_deref(), "cx:event:")?;
        // Realm/Space reversal: the security-boundary id is now `realm_id`
        // (typed `cx:realm:`). The old container-level `place_id` becomes
        // the new `space_id`, which is NOT carried on the wire model — both
        // are blocked at the sanitizer forbidden-key list.
        validate_typed_id("realm_id", self.realm_id.as_deref(), "cx:realm:")?;
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

        if self.sender_display_name.is_some() {
            return Err(PushNotifyPrivacyError::SensitiveField {
                field: "sender_display_name".to_owned(),
            });
        }
        if self.realm_name.is_some() {
            return Err(PushNotifyPrivacyError::SensitiveField {
                field: "realm_name".to_owned(),
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
        // sensitive did:/cx: literal anywhere".
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
    /// - When [`Self::mention_redirect`] is `None`, this is NOT a
    ///   mention-redirect scenario and the call returns `true` (the
    ///   normal recipient-set gate elsewhere applies).
    /// - When `mention_redirect` is `Some`, the receiver's actor DID
    ///   MUST appear in `mention_redirect_target_actor_ids` to be
    ///   permitted. **Empty array means nobody is permitted** —
    ///   fail-closed by construction.
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

    /// Round 4 (B5) — when the wakeup is a late-key-recovery audit
    /// surface (`cx.audit.policy_access.access_kind = e2ee_late_recovery`),
    /// return the `late_recovery_original_event_id` so the consumer can
    /// render a "the system recovered an old key for event X" banner.
    ///
    /// Returns `None` when:
    /// - `policy_access` is absent
    /// - `access_kind` is NOT `E2EELateRecovery` (any other kind has no
    ///   banner contract)
    /// - `late_recovery_original_event_id` is absent (defensive — the
    ///   SDK validator already rejects this combination)
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
/// sanitizer so the rule "no forbidden field anywhere, no `did:` / `cx:`
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
            "push_target_id": "cx:pseudonym:push:0000000000000000000000",
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

pub fn shared_push_notify_privacy_vectors() -> Vec<PushNotifyPrivacyVector> {
    vec![
        PushNotifyPrivacyVector {
            name: "blind wakeup accepts opaque metadata".to_owned(),
            mode: PushNotifyPrivacyMode::E2eeBlindWakeup,
            payload: serde_json::json!({
                "operation_id": crate::OPERATION_PUSH_NOTIFY,
                "notification": {
                    "push_target_id": "cx:pseudonym:push:01HYZ8Z000000000000000",
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
                    "push_target_id": "cx:pseudonym:push:01HYZ8Z000000000000000",
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

    if let Some(token) = value.strip_prefix("l10n_key:") {
        if !token.is_empty()
            && token.len() <= 64
            && token
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
        {
            return Ok(());
        }
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

    let token = if let Some(token) = trimmed.strip_prefix("cx:pseudonym:push:") {
        token
    } else if trimmed.starts_with("cx:") || trimmed.contains(':') {
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

fn validate_custom_wakeup_kind(value: &str) -> Result<(), PushNotifyPrivacyError> {
    if value.is_empty()
        || value.len() > 32
        || value.to_ascii_lowercase().contains("did:")
        || value.contains("cx:")
        || !value
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
    {
        return Err(PushNotifyPrivacyError::InvalidFieldValue {
            field: "wakeup_kind".to_owned(),
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
        "flow_id" => validate_extra_typed_string(key, value, "cx:flow:"),
        "message_id" => validate_extra_typed_string(key, value, "cx:message:"),
        "notification_projection_id" => {
            validate_extra_typed_string(key, value, "cx:notification_projection:")
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
    matches!(
        key,
        "body"
            | "title"
            | "subtitle"
            | "preview"
            | "alert"
            | "provider_payload"
            | "aps"
            | "facets"
            | "entity_facet"
            | "view_renderer"
            | "rendered_view"
            | "encrypted_payload"
            | "ciphertext"
            | "sdp"
            | "candidate"
            | "ice"
            | "turn"
            | "call_setup"
            | "sender_display_name"
            | "realm_name"
            // TODO(realm-rework): the SDK's `is_forbidden_payload_key`
            // still references the legacy `space_id` token. Once the SDK
            // catches up, drop the explicit `realm_name` entry here and
            // route through the SDK list (it covers `*_name` semantics
            // via the sender / flow / room family already).
            | "space_name"
            | "flow_name"
            | "content"
    )
}

fn is_never_allowed_payload_key(key: &str) -> bool {
    matches!(
        key,
        "provider_payload"
            | "aps"
            | "encrypted_payload"
            | "ciphertext"
            | "sdp"
            | "candidate"
            | "ice"
            | "turn"
            | "call_setup"
    )
}

/// Round R2/R3 sensitive fields that must NEVER appear in any blind push
/// payload — mirrors floria T07/T10/T06.
///
/// These fields belong to spec round 2+3 governance surfaces (moderation
/// appeals, attestation evidence, cross-signing reset, identity link
/// routing, realm/space terminal lifecycle). They are deliberately *not*
/// part of the SDK's [`contrix::blind_payload_sanitizer::is_forbidden_payload_key`]
/// list yet — the SDK list is generic across services, and chime owns
/// the policy that says "if a R2/R3 governance identifier ever leaks
/// into a push wakeup, that's a programmer error worth panicking on in
/// debug builds." Production builds get the same field surfaced via
/// [`assert_no_sensitive_fields`] returning an `Err` instead.
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
];

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
/// * In `debug_assertions` builds (typical for `cargo test` and dev
///   builds) the function **panics** with the offending field path. We
///   want loud failures during development — a leaked governance id is
///   a privacy bug, not a recoverable user-input error.
/// * In release builds it returns `Err(field_path)` so production
///   integrations can log and fail closed without taking the process
///   down. Returning the path (not just a bool) gives operators
///   something to grep for in incident response.
///
/// Returns `Ok(())` when the payload is clean.
//
// TODO(round23-T07): once the SDK's `is_forbidden_payload_key` adopts
// the R2/R3 governance fields, fold this list into the SDK call and
// keep this helper as a thin wrapper that converts the SDK
// `BlindPayloadError` into chime's panic-in-debug ergonomic.
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
        PushNotification {
            push_target_id: Some(
                PushTargetId::new("cx:pseudonym:push:01HYZ8Z000000000000000").unwrap(),
            ),
            wakeup_kind: Some(WakeupKind::Message),
            event_id: Some("cx:event:01JS0EV000000000000000000".to_owned()),
            realm_id: Some("cx:realm:01JS0SP000000000000000000".to_owned()),
            sender: None,
            sender_display_name: None,
            realm_name: None,
            push_hint: Some(PushHint::new("new_message").unwrap()),
            counts: Some(serde_json::json!({ "unread": 1 })),
            mention_redirect: None,
            policy_access: None,
            devices: vec![device()],
            extra: Map::new(),
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
        PushTargetId::new("cx:pseudonym:push:01HYZ8Z000000000000000").unwrap();
        PushTargetId::new("01HYZ8Z000000000000000").unwrap();

        assert!(PushTargetId::new("cx:device:01HYZ8Z000000000000000").is_err());
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
                .with_aad("cx.push.notify");

        envelope.validate().unwrap();
        assert!(EncryptedEnvelope::new("alice", "x25519", "Y2lwaGVydGV4dA==").is_err());
        assert!(EncryptedEnvelope::new("did:web:alice", "x25519", "not base64!").is_err());
    }

    #[test]
    fn encrypted_envelope_rejects_pre_round4_permissive_did_methods() {
        // Round 4 (B5) DID regex sweep: method names with `.`, `-`,
        // `_`, or `:` are wire-broken; the tightened regex
        // `^did:[a-z0-9]+:[^\s]+$` forbids them. Each of these
        // pre-round-4 forms used to pass the permissive
        // `starts_with("did:")` check; they MUST now fail validation.
        // Negative test asserts round-4 regex rejects legacy method punctuation.
        for bad_did in [
            "did:web.acme:alice", // dot in method — ROUND4-ALLOW: negative test
            "did:web-acme:alice", // dash in method — ROUND4-ALLOW: negative test
            "did:web_acme:alice", // underscore in method — ROUND4-ALLOW: negative test
            "did:web:al ice",     // whitespace in method-specific-id
        ] {
            let envelope = EncryptedEnvelope {
                recipient: bad_did.to_owned(),
                algorithm: "x25519".to_owned(),
                ciphertext: "Y2lwaGVydGV4dA==".to_owned(),
                nonce: None,
                key_id: None,
                aad: None,
            };
            assert!(
                matches!(
                    envelope.validate(),
                    Err(EncryptedEnvelopeError::InvalidRecipient { .. })
                ),
                "pre-round-4 DID `{bad_did}` must be rejected post-round4",
            );
        }
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
            "push_target_id": "cx:pseudonym:push:01HYZ8Z000000000000000",
            "wakeup_kind": "message",
            "counts": {"unread": 1},
        });
        assert_no_sensitive_fields(&payload).unwrap();
    }

    #[test]
    fn assert_no_sensitive_fields_rejects_round23_governance_fields() {
        for field in ROUND_R2_R3_SENSITIVE_FIELDS {
            let payload = serde_json::json!({
                "push_target_id": "cx:pseudonym:push:01HYZ8Z000000000000000",
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
            "push_target_id": "cx:pseudonym:push:01HYZ8Z000000000000000",
            "metadata": {
                "deep": {
                    "appeal_id": "cx:appeal:01ABC"
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
                {"trust_domain": "cx:trust_domain:example.net"}
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
            "realm_id": "cx:realm:01904100-0000-7000-8000-000000000001",
            "actor": "did:web:alice.example",
            "access_kind": "e2_e_e_late_recovery",
            "late_recovery_original_event_id":
                "cx:event:01904100-0000-7000-8000-000000000002",
            "observed_at": "2026-05-20T00:00:00Z",
        }))
        .unwrap();
        // Sanity-check the SDK validator agrees.
        payload.validate_minimal().unwrap();

        let expected_event_id =
            EventId::new("cx:event:01904100-0000-7000-8000-000000000002").unwrap();
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
            "realm_id": "cx:realm:01904100-0000-7000-8000-000000000001",
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
}
