//! Optional `cx.push.notify` wire model for Push Gateway implementations.
//!
//! This module intentionally does not implement APNs, FCM, Web Push, or OEM
//! provider delivery. It only models the Contrix request/response payload and
//! provides a conservative E2EE blind-wakeup validator.
//!
//! Entity facets and view-renderer output are application routing/context hints
//! only when explicitly authorized. For blind wakeups, do not serialize
//! facet-derived title, body, display name, or space name into provider payloads.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::redact_push_key;

/// Request body for `POST /api/v1/push/notify`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushNotifyRequest {
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

impl PushNotifyRequest {
    /// Validate the active `cx.push.notify` wire model.
    pub fn validate_wire_model(&self) -> Result<(), PushNotifyPrivacyError> {
        if let Some(operation_id) = &self.operation_id
            && operation_id != crate::OPERATION_PUSH_NOTIFY
        {
            return Err(PushNotifyPrivacyError::InvalidFieldValue {
                field: "operation_id".to_owned(),
            });
        }

        self.notification.validate_wire_model()
    }

    /// Validate this notification as an E2EE blind wakeup payload.
    pub fn validate_blind_wakeup(&self) -> Result<(), PushNotifyPrivacyError> {
        self.validate_wire_model()?;
        self.notification.validate_blind_wakeup()
    }

    /// Validate this notification for an explicit privacy mode.
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

    /// Validate this notification against a policy context — the C1 release
    /// gate.
    ///
    /// The policy decides the mode: if `destination_service_did` is on the
    /// `plaintext_visible_services` allowlist, the request is checked under
    /// `PlaintextVisibleService`; otherwise (including the missing-DID case)
    /// it must satisfy `E2eeBlindWakeup`. Callers cannot override this from
    /// the request side — there is no `mode` field on the wire payload that
    /// can lift restrictions.
    pub fn assert_payload_safe(
        &self,
        policy: &PushNotifyPolicyContext,
    ) -> Result<(), PushNotifyPrivacyError> {
        let mode = policy.mode_for(self.destination_service_did.as_deref());
        self.validate_privacy(mode)
    }
}

/// Explicit privacy mode used by shared chime/floria validation vectors.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PushNotifyPrivacyMode {
    /// E2EE notifications must stay body-free and projection-only.
    E2eeBlindWakeup,
    /// A non-E2EE service has explicitly authorized plaintext notification
    /// metadata. Call setup credentials and encrypted payload bytes are still
    /// rejected.
    PlaintextVisibleService,
}

/// Policy context that drives privacy-mode selection per request.
///
/// The release-gate model: every notification is **blind wakeup by default**.
/// The application explicitly opts certain destination services into
/// plaintext-visible delivery by listing their service DIDs. Anything not on
/// the allowlist falls back to E2EE blind wakeup, even if the caller
/// requested otherwise. There is no global "trust me" toggle.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PushNotifyPolicyContext {
    /// Destination service DIDs that are explicitly allowed to receive
    /// plaintext-visible notifications (`PlaintextVisibleService` mode).
    /// Compared exactly — case-sensitive — against the request's
    /// `destination_service_did`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub plaintext_visible_services: Vec<String>,
}

impl PushNotifyPolicyContext {
    /// Construct an empty policy. Equivalent to "every request is treated as
    /// blind wakeup".
    pub fn blind_wakeup_only() -> Self {
        Self::default()
    }

    /// Whether `destination_service_did` is explicitly cleared for plaintext.
    pub fn allows_plaintext_for(&self, destination_service_did: &str) -> bool {
        self.plaintext_visible_services
            .iter()
            .any(|service| service == destination_service_did)
    }

    /// Resolve the privacy mode for a given destination DID.
    ///
    /// `None` (no destination provided) falls back to blind wakeup — the
    /// safest default.
    pub fn mode_for(&self, destination_service_did: Option<&str>) -> PushNotifyPrivacyMode {
        match destination_service_did {
            Some(did) if self.allows_plaintext_for(did) => {
                PushNotifyPrivacyMode::PlaintextVisibleService
            }
            _ => PushNotifyPrivacyMode::E2eeBlindWakeup,
        }
    }
}

/// Shared privacy validation vector for gateway and SDK tests.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PushNotifyPrivacyVector {
    pub name: String,
    pub mode: PushNotifyPrivacyMode,
    pub payload: Value,
    pub should_accept: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_error_field: Option<String>,
}

/// Strict opaque wakeup hint.
///
/// `PushHint` is a newtype wrapper over `String` that validates on
/// construction and on deserialization. The intent is "wakeup signal +
/// opaque token" — the hint must be non-empty, ≤64 chars, contain only
/// `[A-Za-z0-9_\-:.]`, never look like a DID, and never carry the
/// body / call-setup / preview markers documented in [`validate_hint`].
///
/// Replacing the prior free-text `Option<String>` makes it impossible to
/// thread a sentence like `"New message"` through the wire model — every
/// hint is forced to be opaque before the gateway sees it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct PushHint(String);

impl PushHint {
    /// Construct a hint, validating against the strict opaque-token rules.
    pub fn new(value: impl Into<String>) -> Result<Self, PushNotifyPrivacyError> {
        let value = value.into();
        validate_push_hint_value(&value)?;
        Ok(Self(value))
    }

    /// Borrow the underlying string.
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

/// Contrix push notification object.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct PushNotification {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_id: Option<String>,
    #[serde(rename = "type")]
    pub notification_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_name: Option<String>,
    /// Opaque wakeup hint. Validated as a [`PushHint`] on construction /
    /// deserialization — body-like, DID-like, or oversized values are
    /// rejected before the notification is ever serialized.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_hint: Option<PushHint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub counts: Option<Value>,
    pub devices: Vec<PushNotificationDevice>,
    /// Forward-compatible extension fields.
    ///
    /// `validate_blind_wakeup` rejects known sensitive keys in this map and
    /// `validate_wire_model` rejects DID-shaped string values anywhere in
    /// the extension tree (DIDs only belong in `sender`).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl PushNotification {
    /// Validate the active `cx.push.notify` notification contract.
    pub fn validate_wire_model(&self) -> Result<(), PushNotifyPrivacyError> {
        validate_required("type", &self.notification_type)?;
        validate_typed_id("event_id", self.event_id.as_deref(), "cx:event:")?;
        validate_typed_id("space_id", self.space_id.as_deref(), "cx:space:")?;

        if let Some(sender) = self.sender.as_deref()
            && carries_legacy_typed_id(sender)
        {
            return Err(PushNotifyPrivacyError::LegacyField {
                field: "sender".to_owned(),
            });
        }

        if self.devices.is_empty() {
            return Err(PushNotifyPrivacyError::MissingField {
                field: "devices".to_owned(),
            });
        }

        if is_legacy_notification_type(&self.notification_type) {
            return Err(PushNotifyPrivacyError::LegacyField {
                field: "type".to_owned(),
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

    /// Validate this notification as a minimized E2EE blind wakeup.
    ///
    /// The validator is intentionally conservative. It rejects explicit body,
    /// title, display-name, provider payload, facet/view-renderer, encrypted
    /// payload, SDP, ICE, and TURN fields in extension data. It also rejects
    /// push hints that look like call setup material or structured previews.
    pub fn validate_blind_wakeup(&self) -> Result<(), PushNotifyPrivacyError> {
        self.validate_wire_model()?;

        if self.sender_display_name.is_some() {
            return Err(PushNotifyPrivacyError::SensitiveField {
                field: "sender_display_name".to_owned(),
            });
        }

        if self.space_name.is_some() {
            return Err(PushNotifyPrivacyError::SensitiveField {
                field: "space_name".to_owned(),
            });
        }

        // `PushHint` enforces opaque-token shape on construction; nothing
        // extra to do for blind wakeups here.

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

        Ok(())
    }

    /// Validate a notification for an explicitly plaintext-visible service.
    ///
    /// This mode allows display metadata such as title/body in extension data
    /// only because the caller selected it explicitly. It still rejects
    /// encrypted payload bytes, provider wrappers, SDP/ICE/TURN credentials,
    /// and call setup material.
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
}

/// Target device entry for `cx.push.notify`.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushNotificationDevice {
    pub push_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
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

/// Response body for `POST /api/v1/push/notify`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct PushNotifyResponse {
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

/// Retry metadata for provider-side temporary failures.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderRetryHint {
    pub provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

/// Non-secret delivery receipt reference returned by a Push Gateway.
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

/// Rejected platform token summary.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct RejectedPushToken {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_key_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
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

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PushNotifyPrivacyError {
    #[error("push notification contains sensitive field `{field}`")]
    SensitiveField { field: String },
    #[error("push_hint appears to contain call setup or credential material")]
    SensitiveHint,
    #[error("push notification is missing required field `{field}`")]
    MissingField { field: String },
    #[error("push notification contains removed legacy field or alias `{field}`")]
    LegacyField { field: String },
    #[error("push notification field `{field}` contains an invalid value")]
    InvalidFieldValue { field: String },
}

// -- Encrypted envelope ------------------------------------------------------

/// DID-bound encrypted payload envelope mirroring the
/// `contrix-rust-sdk` shape.
///
/// `chime` does not encrypt or decrypt — it only carries the wire shape so
/// gateway and SDK code agree on field names, validation, and the rule that
/// **DID-bound payload bytes never travel as plaintext extension data**.
/// Callers that need to attach an encrypted payload to a notification must
/// build an `EncryptedEnvelope` (which fail-closes invalid recipients,
/// algorithms, or empty ciphertext) and serialize it through
/// `validate_wire_model`-clean transport.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct EncryptedEnvelope {
    /// Recipient DID. The only place chime accepts a DID in the encrypted-
    /// payload path; validated to start with `did:`.
    pub recipient: String,
    /// IANA-style algorithm identifier, e.g.
    /// `"x25519-xsalsa20-poly1305"`.
    pub algorithm: String,
    /// Base64-encoded ciphertext bytes. Must be non-empty, well-formed
    /// base64 (`A-Z a-z 0-9 + / =` only).
    pub ciphertext: String,
    /// Optional nonce / IV in the same base64 alphabet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Optional server-side key identifier (opaque to chime).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// Associated data (AAD) bound to the ciphertext during encryption — the
    /// gateway re-derives this on decrypt. Often `<operation_id>|<audience>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aad: Option<String>,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum EncryptedEnvelopeError {
    #[error("encrypted envelope recipient must be a DID, got `{got}`")]
    InvalidRecipient { got: String },
    #[error("encrypted envelope is missing required field `{field}`")]
    MissingField { field: &'static str },
    #[error("encrypted envelope `{field}` is not valid base64")]
    InvalidBase64 { field: &'static str },
}

impl EncryptedEnvelope {
    /// Build a validated envelope from the three required fields.
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

    /// Attach a base64-encoded nonce.
    pub fn with_nonce(mut self, nonce: impl Into<String>) -> Result<Self, EncryptedEnvelopeError> {
        let nonce = nonce.into();
        if !is_base64_token(&nonce) {
            return Err(EncryptedEnvelopeError::InvalidBase64 { field: "nonce" });
        }
        self.nonce = Some(nonce);
        Ok(self)
    }

    /// Attach an opaque `key_id`.
    pub fn with_key_id(mut self, key_id: impl Into<String>) -> Self {
        self.key_id = Some(key_id.into());
        self
    }

    /// Attach an AAD string.
    pub fn with_aad(mut self, aad: impl Into<String>) -> Self {
        self.aad = Some(aad.into());
        self
    }

    /// Run the full validator. Constructors call this internally; this
    /// public method lets callers re-validate a deserialized envelope (since
    /// `serde::Deserialize` skips the constructor).
    pub fn validate(&self) -> Result<(), EncryptedEnvelopeError> {
        if !self.recipient.starts_with("did:") {
            return Err(EncryptedEnvelopeError::InvalidRecipient {
                got: self.recipient.clone(),
            });
        }
        if self.algorithm.trim().is_empty() {
            return Err(EncryptedEnvelopeError::MissingField { field: "algorithm" });
        }
        if self.ciphertext.is_empty() {
            return Err(EncryptedEnvelopeError::MissingField {
                field: "ciphertext",
            });
        }
        if !is_base64_token(&self.ciphertext) {
            return Err(EncryptedEnvelopeError::InvalidBase64 {
                field: "ciphertext",
            });
        }
        if let Some(nonce) = &self.nonce
            && !is_base64_token(nonce)
        {
            return Err(EncryptedEnvelopeError::InvalidBase64 { field: "nonce" });
        }
        Ok(())
    }
}

fn is_base64_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '-' | '_'))
}

fn validate_required(field: &str, value: &str) -> Result<(), PushNotifyPrivacyError> {
    if value.trim().is_empty() {
        Err(PushNotifyPrivacyError::MissingField {
            field: field.to_owned(),
        })
    } else {
        Ok(())
    }
}

fn validate_typed_id(
    field: &str,
    value: Option<&str>,
    expected_prefix: &str,
) -> Result<(), PushNotifyPrivacyError> {
    let Some(value) = value else {
        return Ok(());
    };

    if value.trim().is_empty() || !value.starts_with(expected_prefix) {
        return Err(PushNotifyPrivacyError::InvalidFieldValue {
            field: field.to_owned(),
        });
    }

    Ok(())
}

fn validate_active_reference_extension(
    path: &str,
    value: &Value,
) -> Result<(), PushNotifyPrivacyError> {
    if is_legacy_contract_key(path) {
        return Err(PushNotifyPrivacyError::LegacyField {
            field: path.to_owned(),
        });
    }

    match (path, value) {
        ("flow_id", Value::String(value)) => validate_typed_id("flow_id", Some(value), "cx:flow:"),
        ("message_id", Value::String(value)) => {
            validate_typed_id("message_id", Some(value), "cx:message:")
        }
        ("notification_projection_id", Value::String(value)) => validate_typed_id(
            "notification_projection_id",
            Some(value),
            "cx:notification_projection:",
        ),
        (_, Value::String(value)) if carries_legacy_typed_id(value) => {
            Err(PushNotifyPrivacyError::LegacyField {
                field: path.to_owned(),
            })
        }
        // C1 release gate: DIDs only belong in the top-level `sender` field.
        // Anywhere in the extension tree is a privacy leak — fail closed.
        (_, Value::String(value)) if value_carries_did(value) => {
            Err(PushNotifyPrivacyError::SensitiveField {
                field: path.to_owned(),
            })
        }
        (_, Value::Object(map)) => {
            for (key, value) in map {
                let path = format!("{path}.{key}");
                validate_active_reference_extension(&path, value)?;
            }
            Ok(())
        }
        (_, Value::Array(values)) => {
            for (index, value) in values.iter().enumerate() {
                validate_active_reference_extension(&format!("{path}[{index}]"), value)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Whether a string value carries a DID (`did:method:identifier`) anywhere.
fn value_carries_did(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    normalized.starts_with("did:") || normalized.contains(" did:") || normalized.contains(":did:")
}

fn is_legacy_notification_type(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    normalized.starts_with("room.")
        || normalized.starts_with("card.")
        || normalized.starts_with("subject.")
        || normalized.starts_with("cx.room.")
        || normalized.starts_with("cx.card.")
        || normalized.starts_with("cx.subject.")
}

fn is_legacy_contract_key(path: &str) -> bool {
    let key = path.rsplit(['.', '[']).next().unwrap_or(path);
    matches!(
        key.to_ascii_lowercase().as_str(),
        "sender_service_did"
            | "room"
            | "room_id"
            | "room_ref"
            | "card"
            | "card_id"
            | "card_ref"
            | "subject"
            | "subject_id"
            | "subject_ref"
            | "event_kind"
            | "schema_id"
            | "projection_id"
    ) || path == "kind"
}

fn carries_legacy_typed_id(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    normalized.starts_with("cx:room:")
        || normalized.starts_with("cx:card:")
        || normalized.starts_with("cx:subject:")
}

/// Strict validator backing [`PushHint::new`] and the deserialization path.
///
/// Combined intent: the hint must be opaque enough that gateways and OS push
/// services see only a fixed-shape token, never a sentence or structured
/// document. The rules:
///
/// * 1..=64 chars (empty hints round-trip as `Option::None`, so empty is
///   never legal)
/// * `[A-Za-z0-9_\-:.]` only (rejects spaces, quotes, braces, newlines, ...)
/// * No `did:` substring (no DID leaks)
/// * No call-setup / body / preview marker sequences
fn validate_push_hint_value(value: &str) -> Result<(), PushNotifyPrivacyError> {
    if value.is_empty() || value.chars().count() > 64 {
        return Err(PushNotifyPrivacyError::InvalidFieldValue {
            field: "push_hint".to_owned(),
        });
    }

    let opaque_only = value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | ':' | '.'));
    if !opaque_only {
        return Err(PushNotifyPrivacyError::InvalidFieldValue {
            field: "push_hint".to_owned(),
        });
    }

    if value_carries_did(value) {
        return Err(PushNotifyPrivacyError::SensitiveField {
            field: "push_hint".to_owned(),
        });
    }

    let normalized = value.to_ascii_lowercase();
    let sensitive_markers = [
        "candidate:",
        "ice-ufrag",
        "ice-pwd",
        "a=crypto:",
        "turn:",
        "turns:",
        "sdp",
        "v=0",
        "title:",
        "body:",
        "message:",
        "preview:",
        "space_name:",
        "sender_display_name:",
    ];
    if sensitive_markers
        .iter()
        .any(|marker| normalized.contains(marker))
    {
        return Err(PushNotifyPrivacyError::SensitiveHint);
    }

    Ok(())
}

fn validate_counts(path: &str, value: &Value) -> Result<(), PushNotifyPrivacyError> {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                let path = format!("{path}.{key}");
                if is_sensitive_payload_key(key) {
                    return Err(PushNotifyPrivacyError::SensitiveField { field: path });
                }
                validate_counts(&path, value)?;
            }
            Ok(())
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                validate_counts(&format!("{path}[{index}]"), value)?;
            }
            Ok(())
        }
        Value::String(_) => Err(PushNotifyPrivacyError::SensitiveField {
            field: path.to_owned(),
        }),
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(()),
    }
}

fn validate_extra_value(path: &str, value: &Value) -> Result<(), PushNotifyPrivacyError> {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                let path = format!("{path}.{key}");
                if is_sensitive_payload_key(key) {
                    return Err(PushNotifyPrivacyError::SensitiveField { field: path });
                }
                validate_extra_value(&path, value)?;
            }
            Ok(())
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                validate_extra_value(&format!("{path}[{index}]"), value)?;
            }
            Ok(())
        }
        Value::String(value) => validate_extra_string(path, value),
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(()),
    }
}

fn validate_extra_string(path: &str, value: &str) -> Result<(), PushNotifyPrivacyError> {
    let normalized = value.to_ascii_lowercase();
    if normalized.contains("candidate:")
        || normalized.contains("ice-ufrag")
        || normalized.contains("ice-pwd")
        || normalized.contains("turn:")
        || normalized.contains("turns:")
        || normalized.contains("v=0\r")
        || normalized.contains("v=0\n")
    {
        Err(PushNotifyPrivacyError::SensitiveField {
            field: path.to_owned(),
        })
    } else {
        Ok(())
    }
}

fn validate_plaintext_extra_value(path: &str, value: &Value) -> Result<(), PushNotifyPrivacyError> {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                let path = format!("{path}.{key}");
                if is_never_allowed_payload_key(key) {
                    return Err(PushNotifyPrivacyError::SensitiveField { field: path });
                }
                validate_plaintext_extra_value(&path, value)?;
            }
            Ok(())
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                validate_plaintext_extra_value(&format!("{path}[{index}]"), value)?;
            }
            Ok(())
        }
        Value::String(value) => validate_extra_string(path, value),
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(()),
    }
}

fn is_sensitive_payload_key(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "body"
            | "message_body"
            | "formatted_body"
            | "notification_body"
            | "message"
            | "message_text"
            | "text"
            | "plaintext"
            | "content"
            | "title"
            | "subtitle"
            | "notification_title"
            | "alert"
            | "preview"
            | "summary"
            | "filename"
            | "file_name"
            | "attachment_name"
            | "attachment_filename"
            | "attachment_preview"
            | "space_name"
            | "room_name"
            | "room_display_name"
            | "sender_name"
            | "sender_display_name"
            | "provider_payload"
            | "provider_data"
            | "notification_payload"
            | "payload"
            | "aps"
            | "android"
            | "webpush"
            | "facet"
            | "facets"
            | "entity_facet"
            | "entity_facets"
            | "view_renderer"
            | "view_renderers"
            | "rendered_view"
            | "renderer"
            | "template"
            | "template_vars"
            | "encrypted_payload"
            | "ciphertext"
            | "sdp"
            | "ice_candidate"
            | "ice_candidates"
            | "turn_credential"
            | "turn_credentials"
    )
}

fn is_never_allowed_payload_key(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "provider_payload"
            | "provider_data"
            | "notification_payload"
            | "payload"
            | "aps"
            | "android"
            | "webpush"
            | "encrypted_payload"
            | "ciphertext"
            | "sdp"
            | "ice_candidate"
            | "ice_candidates"
            | "turn_credential"
            | "turn_credentials"
    )
}

/// Return shared validation vectors for `chime` and Push Gateway tests.
pub fn shared_push_notify_privacy_vectors() -> Vec<PushNotifyPrivacyVector> {
    vec![
        PushNotifyPrivacyVector {
            name: "e2ee-minimized-wakeup".to_owned(),
            mode: PushNotifyPrivacyMode::E2eeBlindWakeup,
            payload: serde_json::json!({
                "operation_id": "cx.push.notify",
                "notification": {
                    "event_id": "cx:event:01JS0EV000000000000000000",
                    "space_id": "cx:space:01JS0SP000000000000000000",
                    "type": "cx.message.create",
                    "push_hint": "wakeup-msg-1",
                    "counts": { "unread": 1 },
                    "devices": [{
                        "push_key": "fcm:very-secret-token",
                        "push_key_hash": "sha256:abc",
                        "app_id": "app.example.android"
                    }]
                }
            }),
            should_accept: true,
            expected_error_field: None,
        },
        PushNotifyPrivacyVector {
            name: "e2ee-rejects-body".to_owned(),
            mode: PushNotifyPrivacyMode::E2eeBlindWakeup,
            payload: serde_json::json!({
                "notification": {
                    "event_id": "cx:event:01JS0EV000000000000000000",
                    "space_id": "cx:space:01JS0SP000000000000000000",
                    "type": "cx.message.create",
                    "body": "secret message",
                    "devices": [{ "push_key": "fcm:very-secret-token" }]
                }
            }),
            should_accept: false,
            expected_error_field: Some("body".to_owned()),
        },
        PushNotifyPrivacyVector {
            name: "e2ee-rejects-call-credentials".to_owned(),
            mode: PushNotifyPrivacyMode::E2eeBlindWakeup,
            payload: serde_json::json!({
                "notification": {
                    "event_id": "cx:event:01JS0EV000000000000000000",
                    "space_id": "cx:space:01JS0SP000000000000000000",
                    "type": "cx.call.invite",
                    "sdp": "v=0\r\na=ice-ufrag:secret",
                    "devices": [{ "push_key": "fcm:very-secret-token" }]
                }
            }),
            should_accept: false,
            expected_error_field: Some("sdp".to_owned()),
        },
        PushNotifyPrivacyVector {
            name: "e2ee-rejects-legacy-room-reference".to_owned(),
            mode: PushNotifyPrivacyMode::E2eeBlindWakeup,
            payload: serde_json::json!({
                "notification": {
                    "event_id": "cx:event:01JS0EV000000000000000000",
                    "space_id": "cx:space:01JS0SP000000000000000000",
                    "type": "cx.message.create",
                    "room_id": "cx:room:legacy-room",
                    "devices": [{ "push_key": "fcm:very-secret-token" }]
                }
            }),
            should_accept: false,
            expected_error_field: Some("room_id".to_owned()),
        },
        PushNotifyPrivacyVector {
            name: "e2ee-rejects-legacy-schema-id".to_owned(),
            mode: PushNotifyPrivacyMode::E2eeBlindWakeup,
            payload: serde_json::json!({
                "notification": {
                    "event_id": "cx:event:01JS0EV000000000000000000",
                    "space_id": "cx:space:01JS0SP000000000000000000",
                    "type": "cx.message.create",
                    "schema_id": "legacy.room.schema",
                    "devices": [{ "push_key": "fcm:very-secret-token" }]
                }
            }),
            should_accept: false,
            expected_error_field: Some("schema_id".to_owned()),
        },
        PushNotifyPrivacyVector {
            name: "plaintext-visible-service-allows-title-body".to_owned(),
            mode: PushNotifyPrivacyMode::PlaintextVisibleService,
            payload: serde_json::json!({
                "notification": {
                    "event_id": "cx:event:01JS0EV000000000000000000",
                    "space_id": "cx:space:public",
                    "type": "cx.message.create",
                    "title": "Public room",
                    "body": "Visible announcement",
                    "devices": [{ "push_key": "fcm:very-secret-token" }]
                }
            }),
            should_accept: true,
            expected_error_field: None,
        },
        PushNotifyPrivacyVector {
            name: "plaintext-visible-service-still-rejects-provider-payload".to_owned(),
            mode: PushNotifyPrivacyMode::PlaintextVisibleService,
            payload: serde_json::json!({
                "notification": {
                    "event_id": "cx:event:01JS0EV000000000000000000",
                    "space_id": "cx:space:public",
                    "type": "cx.message.create",
                    "provider_payload": { "aps": { "alert": "raw" } },
                    "devices": [{ "push_key": "fcm:very-secret-token" }]
                }
            }),
            should_accept: false,
            expected_error_field: Some("provider_payload".to_owned()),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn notification() -> PushNotification {
        PushNotification {
            event_id: Some("cx:event:01JS0EV000000000000000000".to_owned()),
            space_id: Some("cx:space:01JS0SP000000000000000000".to_owned()),
            notification_type: "cx.message.create".to_owned(),
            sender: Some("did:web:bob.example".to_owned()),
            sender_display_name: None,
            space_name: None,
            push_hint: Some(PushHint::new("wakeup-msg-01").expect("opaque hint")),
            counts: Some(serde_json::json!({ "unread": 5 })),
            devices: vec![PushNotificationDevice {
                push_key: "fcm:very-secret-token".to_owned(),
                app_id: Some("app.example.android".to_owned()),
                registration_id: Some("cx:pushreg:01JS0KE000000000000000000".to_owned()),
                push_key_hash: Some("sha256:abc".to_owned()),
                platform: Some("android".to_owned()),
            }],
            extra: Map::new(),
        }
    }

    #[test]
    fn policy_context_blind_wakeup_only_by_default() {
        let policy = PushNotifyPolicyContext::default();
        assert_eq!(
            policy.mode_for(Some("did:web:gateway.example")),
            PushNotifyPrivacyMode::E2eeBlindWakeup
        );
        assert_eq!(
            policy.mode_for(None),
            PushNotifyPrivacyMode::E2eeBlindWakeup
        );
    }

    #[test]
    fn policy_context_picks_plaintext_only_for_allowlisted_service() {
        let policy = PushNotifyPolicyContext {
            plaintext_visible_services: vec!["did:web:public.example".to_owned()],
        };
        assert_eq!(
            policy.mode_for(Some("did:web:public.example")),
            PushNotifyPrivacyMode::PlaintextVisibleService
        );
        // Different DID still falls back to blind wakeup.
        assert_eq!(
            policy.mode_for(Some("did:web:other.example")),
            PushNotifyPrivacyMode::E2eeBlindWakeup
        );
        // Missing DID always falls back to blind wakeup.
        assert_eq!(
            policy.mode_for(None),
            PushNotifyPrivacyMode::E2eeBlindWakeup
        );
    }

    #[test]
    fn assert_payload_safe_routes_through_policy() {
        // Request with a body field violates blind wakeup but passes
        // plaintext-visible mode.
        let request = PushNotifyRequest {
            destination_service_did: Some("did:web:public.example".to_owned()),
            notification: {
                let mut n = notification();
                n.extra
                    .insert("title".to_owned(), Value::String("Public".to_owned()));
                n
            },
            ..Default::default()
        };

        // Empty policy → blind wakeup → rejected because of `title`.
        let strict = PushNotifyPolicyContext::blind_wakeup_only();
        assert!(matches!(
            request.assert_payload_safe(&strict),
            Err(PushNotifyPrivacyError::SensitiveField { .. })
        ));

        // Allowlisted destination → plaintext-visible → still rejects
        // provider-payload keys but accepts a plain `title`.
        let permissive = PushNotifyPolicyContext {
            plaintext_visible_services: vec!["did:web:public.example".to_owned()],
        };
        request.assert_payload_safe(&permissive).unwrap();
    }

    #[test]
    fn assert_payload_safe_blind_wakeup_when_destination_missing() {
        // No destination DID + allowlist → falls back to blind wakeup, even
        // if the allowlist is non-empty. Cannot be lifted by the caller.
        let request = PushNotifyRequest {
            notification: {
                let mut n = notification();
                n.extra
                    .insert("title".to_owned(), Value::String("Public".to_owned()));
                n
            },
            ..Default::default()
        };
        let permissive = PushNotifyPolicyContext {
            plaintext_visible_services: vec!["did:web:public.example".to_owned()],
        };
        assert!(request.assert_payload_safe(&permissive).is_err());
    }

    #[test]
    fn rejects_legacy_typed_id_in_sender_field() {
        let mut notification = notification();
        notification.sender = Some("cx:room:legacy-room".to_owned());
        let result = notification.validate_wire_model();
        match result {
            Err(PushNotifyPrivacyError::LegacyField { field }) => assert_eq!(field, "sender"),
            other => panic!("expected LegacyField for sender, got {other:?}"),
        }
    }

    #[test]
    fn validates_minimized_notification() {
        PushNotifyRequest {
            operation_id: Some(crate::OPERATION_PUSH_NOTIFY.to_owned()),
            idempotency_key: Some("notify-1".to_owned()),
            origin_service_did: Some("did:web:sync.example.com".to_owned()),
            destination_service_did: Some("did:web:push.example.com".to_owned()),
            app_id: Some("app.example.android".to_owned()),
            priority: Some("high".to_owned()),
            ttl_seconds: Some(900),
            collapse_key: Some("cx:space:01JS0SP000000000000000000".to_owned()),
            notification: notification(),
        }
        .validate_blind_wakeup()
        .unwrap();
    }

    #[test]
    fn shared_privacy_vectors_match_validator_outcomes() {
        for vector in shared_push_notify_privacy_vectors() {
            let request: PushNotifyRequest = serde_json::from_value(vector.payload.clone())
                .unwrap_or_else(|error| panic!("{} failed to decode: {error}", vector.name));
            let result = request.validate_privacy(vector.mode);

            assert_eq!(
                result.is_ok(),
                vector.should_accept,
                "{} returned {result:?}",
                vector.name
            );

            if let Some(expected_field) = vector.expected_error_field {
                match result {
                    Err(PushNotifyPrivacyError::SensitiveField { ref field })
                    | Err(PushNotifyPrivacyError::LegacyField { ref field }) => {
                        assert_eq!(field, &expected_field, "{}", vector.name);
                    }
                    other => panic!(
                        "{} expected error field `{expected_field}`, got {other:?}",
                        vector.name
                    ),
                }
            }
        }
    }

    #[test]
    fn plaintext_visible_service_explicitly_allows_display_metadata() {
        let mut notification = notification();
        notification
            .extra
            .insert("title".to_owned(), Value::String("Public room".to_owned()));
        notification.extra.insert(
            "body".to_owned(),
            Value::String("Visible announcement".to_owned()),
        );

        notification
            .validate_plaintext_visible_service()
            .expect("plaintext-visible service should allow title/body");
        assert!(matches!(
            notification.validate_blind_wakeup().unwrap_err(),
            PushNotifyPrivacyError::SensitiveField { field }
                if field == "title" || field == "body"
        ));
    }

    #[test]
    fn notify_wire_model_roundtrips_contract_metadata() {
        let request: PushNotifyRequest = serde_json::from_value(serde_json::json!({
            "operation_id": "cx.push.notify",
            "idempotency_key": "notify-1",
            "origin_service_did": "did:web:sync.example.com",
            "destination_service_did": "did:web:push.example.com",
            "app_id": "app.example.android",
            "priority": "high",
            "ttl_seconds": 900,
            "collapse_key": "space-1",
            "notification": {
                "event_id": "cx:event:01JS0EV000000000000000000",
                "space_id": "cx:space:01JS0SP000000000000000000",
                "type": "cx.message.create",
                "devices": [{
                    "push_key": "fcm:very-secret-token",
                    "push_key_hash": "sha256:abc",
                    "registration_id": "reg-1",
                    "platform": "android",
                    "app_id": "app.example.android"
                }]
            }
        }))
        .unwrap();

        assert_eq!(
            request.operation_id.as_deref(),
            Some(crate::OPERATION_PUSH_NOTIFY)
        );
        assert_eq!(
            request.origin_service_did.as_deref(),
            Some("did:web:sync.example.com")
        );
        assert_eq!(request.priority.as_deref(), Some("high"));
        assert_eq!(request.ttl_seconds, Some(900));
        assert_eq!(
            request.notification.devices[0].registration_id.as_deref(),
            Some("reg-1")
        );

        let response = PushNotifyResponse {
            request_id: Some("cx:req:123".to_owned()),
            accepted: 1,
            rejected: vec![RejectedPushToken {
                push_key: None,
                push_key_hash: Some("pkh_abc".to_owned()),
                app_id: Some("app.example.android".to_owned()),
                reason: Some("unregistered".to_owned()),
            }],
            provider_retries: vec![ProviderRetryHint {
                provider: "fcm".to_owned(),
                retry_after_ms: Some(1000),
            }],
            delivery_receipts: vec![PushDeliveryReceipt {
                provider: Some("fcm".to_owned()),
                provider_message_id: Some("projects/example/messages/1".to_owned()),
                push_key_hash: Some("pkh_abc".to_owned()),
                status: Some("accepted".to_owned()),
                retry_after_ms: None,
                timestamp: Some("2026-05-02T00:00:00Z".to_owned()),
                request_id: Some("cx:req:123".to_owned()),
            }],
        };
        let encoded = serde_json::to_value(response).unwrap();
        assert_eq!(encoded["accepted"], 1);
        assert_eq!(encoded["rejected"][0]["push_key_hash"], "pkh_abc");
        assert_eq!(encoded["delivery_receipts"][0]["provider"], "fcm");
    }

    #[test]
    fn rejects_legacy_sender_service_alias_during_decode() {
        let request = serde_json::from_value::<PushNotifyRequest>(serde_json::json!({
            "operation_id": "cx.push.notify",
            "sender_service_did": "did:web:sync.example.com",
            "notification": {
                "event_id": "cx:event:01JS0EV000000000000000000",
                "space_id": "cx:space:01JS0SP000000000000000000",
                "type": "cx.message.create",
                "devices": [{ "push_key": "fcm:very-secret-token" }]
            }
        }));

        assert!(request.is_err());
    }

    #[test]
    fn accepts_active_flow_message_and_projection_references() {
        let mut notification = notification();
        notification.extra.insert(
            "flow_id".to_owned(),
            Value::String("cx:flow:01JS0FL000000000000000000".to_owned()),
        );
        notification.extra.insert(
            "message_id".to_owned(),
            Value::String("cx:message:01JS0MS000000000000000000".to_owned()),
        );
        notification.extra.insert(
            "notification_projection_id".to_owned(),
            Value::String("cx:notification_projection:01JS0NP000000000000000000".to_owned()),
        );

        notification.validate_blind_wakeup().unwrap();
    }

    #[test]
    fn rejects_legacy_contract_fields_and_types() {
        let mut with_room = notification();
        with_room.extra.insert(
            "room_id".to_owned(),
            Value::String("cx:room:legacy-room".to_owned()),
        );
        assert_eq!(
            with_room.validate_blind_wakeup().unwrap_err(),
            PushNotifyPrivacyError::LegacyField {
                field: "room_id".to_owned()
            }
        );

        let mut with_card = notification();
        with_card.extra.insert(
            "card_id".to_owned(),
            Value::String("cx:card:legacy-card".to_owned()),
        );
        assert_eq!(
            with_card.validate_blind_wakeup().unwrap_err(),
            PushNotifyPrivacyError::LegacyField {
                field: "card_id".to_owned()
            }
        );

        let mut with_subject = notification();
        with_subject.extra.insert(
            "subject_id".to_owned(),
            Value::String("cx:subject:legacy-subject".to_owned()),
        );
        assert_eq!(
            with_subject.validate_blind_wakeup().unwrap_err(),
            PushNotifyPrivacyError::LegacyField {
                field: "subject_id".to_owned()
            }
        );

        let mut with_flow_id = notification();
        with_flow_id.extra.insert(
            "flow_id".to_owned(),
            Value::String("cx:card:legacy-card".to_owned()),
        );
        assert_eq!(
            with_flow_id.validate_blind_wakeup().unwrap_err(),
            PushNotifyPrivacyError::InvalidFieldValue {
                field: "flow_id".to_owned()
            }
        );

        let mut with_schema = notification();
        with_schema.extra.insert(
            "schema_id".to_owned(),
            Value::String("legacy.room.schema".to_owned()),
        );
        assert_eq!(
            with_schema.validate_blind_wakeup().unwrap_err(),
            PushNotifyPrivacyError::LegacyField {
                field: "schema_id".to_owned()
            }
        );

        let mut with_kind = notification();
        with_kind.notification_type = "cx.room.message".to_owned();
        assert_eq!(
            with_kind.validate_blind_wakeup().unwrap_err(),
            PushNotifyPrivacyError::LegacyField {
                field: "type".to_owned()
            }
        );
    }

    #[test]
    fn rejects_message_body_extension() {
        let mut notification = notification();
        notification
            .extra
            .insert("body".to_owned(), Value::String("secret".to_owned()));

        let err = notification.validate_blind_wakeup().unwrap_err();
        assert_eq!(
            err,
            PushNotifyPrivacyError::SensitiveField {
                field: "body".to_owned()
            }
        );
    }

    #[test]
    fn rejects_display_name_metadata_in_blind_wakeup() {
        let mut with_space_name = notification();
        with_space_name.space_name = Some("Secret Project".to_owned());

        assert_eq!(
            with_space_name.validate_blind_wakeup().unwrap_err(),
            PushNotifyPrivacyError::SensitiveField {
                field: "space_name".to_owned()
            }
        );

        let mut with_sender_name = notification();
        with_sender_name.sender_display_name = Some("Bob".to_owned());

        assert_eq!(
            with_sender_name.validate_blind_wakeup().unwrap_err(),
            PushNotifyPrivacyError::SensitiveField {
                field: "sender_display_name".to_owned()
            }
        );
    }

    #[test]
    fn rejects_provider_payload_preview_smuggling() {
        let mut notification = notification();
        notification.extra.insert(
            "provider_payload".to_owned(),
            serde_json::json!({
                "aps": {
                    "alert": {
                        "title": "Secret Project",
                        "body": "message body"
                    }
                }
            }),
        );

        assert_eq!(
            notification.validate_blind_wakeup().unwrap_err(),
            PushNotifyPrivacyError::SensitiveField {
                field: "provider_payload".to_owned()
            }
        );
    }

    #[test]
    fn rejects_facet_and_view_renderer_metadata() {
        for key in ["facets", "entity_facet", "view_renderer", "rendered_view"] {
            let mut notification = notification();
            notification.extra.insert(
                key.to_owned(),
                serde_json::json!({ "title": "Secret Project" }),
            );

            assert_eq!(
                notification.validate_blind_wakeup().unwrap_err(),
                PushNotifyPrivacyError::SensitiveField {
                    field: key.to_owned()
                }
            );
        }
    }

    #[test]
    fn rejects_sensitive_keys_nested_in_allowed_extension() {
        let mut notification = notification();
        notification.extra.insert(
            "routing".to_owned(),
            serde_json::json!({
                "authorized": true,
                "view": {
                    "title": "Secret Project"
                }
            }),
        );

        assert_eq!(
            notification.validate_blind_wakeup().unwrap_err(),
            PushNotifyPrivacyError::SensitiveField {
                field: "routing.view.title".to_owned()
            }
        );
    }

    #[test]
    fn rejects_counts_string_metadata() {
        let mut notification = notification();
        notification.counts = Some(serde_json::json!({ "unread": "five" }));

        assert_eq!(
            notification.validate_blind_wakeup().unwrap_err(),
            PushNotifyPrivacyError::SensitiveField {
                field: "counts.unread".to_owned()
            }
        );
    }

    #[test]
    fn push_hint_rejects_sensitive_markers_within_allowed_charset() {
        // Now caught at construction (and on JSON deserialize), not at
        // validate_blind_wakeup. The marker substrings below are all valid
        // under the opaque-token charset but still get rejected.
        for marker_value in [
            "title:secret",
            "body:hidden",
            "preview:abc",
            "candidate:host",
            "turn:relay",
        ] {
            assert_eq!(
                PushHint::new(marker_value).unwrap_err(),
                PushNotifyPrivacyError::SensitiveHint,
                "expected SensitiveHint for `{marker_value}`"
            );
        }

        // SDP/control-byte values still fail — they hit the charset check
        // first, which is also fail-closed.
        assert!(matches!(
            PushHint::new("v=0\r\n"),
            Err(PushNotifyPrivacyError::InvalidFieldValue { .. })
        ));
    }

    #[test]
    fn push_hint_rejects_structured_or_freeform_value() {
        // Both braces and spaces violate the opaque-token character class.
        assert!(matches!(
            PushHint::new(r#"{"title":"Secret"}"#),
            Err(PushNotifyPrivacyError::InvalidFieldValue { .. })
        ));
        assert!(matches!(
            PushHint::new("New message"),
            Err(PushNotifyPrivacyError::InvalidFieldValue { .. })
        ));
    }

    #[test]
    fn push_hint_rejects_did_substrings() {
        let err = PushHint::new("did:web:alice.example").unwrap_err();
        assert!(matches!(err, PushNotifyPrivacyError::SensitiveField { .. }));
    }

    #[test]
    fn push_hint_rejects_oversized_token() {
        let too_long = "a".repeat(65);
        assert!(matches!(
            PushHint::new(too_long),
            Err(PushNotifyPrivacyError::InvalidFieldValue { .. })
        ));
    }

    #[test]
    fn push_hint_accepts_opaque_tokens() {
        PushHint::new("wakeup-2026-05-06").unwrap();
        PushHint::new("v1.session-abc.idem-42").unwrap();
        PushHint::new("token:opaque").unwrap();
    }

    #[test]
    fn push_hint_deserialize_validates() {
        let bad = serde_json::from_str::<PushHint>("\"New message\"");
        assert!(bad.is_err(), "bad hints must error on deserialize");
        let good = serde_json::from_str::<PushHint>("\"wakeup-1\"").unwrap();
        assert_eq!(good.as_str(), "wakeup-1");
    }

    #[test]
    fn encrypted_envelope_accepts_did_recipient_and_base64() {
        let envelope = EncryptedEnvelope::new(
            "did:web:alice.example",
            "x25519-xsalsa20-poly1305",
            "Y2lwaGVydGV4dA==",
        )
        .unwrap()
        .with_nonce("bm9uY2VfYWJj")
        .unwrap()
        .with_key_id("kid-1")
        .with_aad("cx.push.notify|did:web:gateway.example");

        envelope.validate().unwrap();
        let json = serde_json::to_string(&envelope).unwrap();
        let loaded: EncryptedEnvelope = serde_json::from_str(&json).unwrap();
        loaded.validate().unwrap();
        assert_eq!(loaded, envelope);
    }

    #[test]
    fn encrypted_envelope_rejects_non_did_recipient() {
        let err = EncryptedEnvelope::new("alice", "x25519", "Y2lwaGVydGV4dA==").unwrap_err();
        match err {
            EncryptedEnvelopeError::InvalidRecipient { got } => assert_eq!(got, "alice"),
            other => panic!("expected InvalidRecipient, got {other:?}"),
        }
    }

    #[test]
    fn encrypted_envelope_rejects_empty_algorithm_or_ciphertext() {
        assert!(matches!(
            EncryptedEnvelope::new("did:web:alice", " ", "Y2lwaGVydGV4dA=="),
            Err(EncryptedEnvelopeError::MissingField { field: "algorithm" })
        ));
        assert!(matches!(
            EncryptedEnvelope::new("did:web:alice", "x25519", ""),
            Err(EncryptedEnvelopeError::MissingField {
                field: "ciphertext"
            })
        ));
    }

    #[test]
    fn encrypted_envelope_rejects_non_base64_payload() {
        let err = EncryptedEnvelope::new("did:web:alice", "x25519", "not base64!").unwrap_err();
        assert!(matches!(
            err,
            EncryptedEnvelopeError::InvalidBase64 {
                field: "ciphertext"
            }
        ));
    }

    #[test]
    fn encrypted_envelope_deserialize_then_validate_catches_drift() {
        // Synthesize a JSON payload that bypasses the constructor — e.g. a
        // gateway response with a tampered recipient — and confirm the
        // re-validate catches it.
        let raw = r#"{
            "recipient": "alice@example",
            "algorithm": "x25519",
            "ciphertext": "Y2lwaGVydGV4dA=="
        }"#;
        let envelope: EncryptedEnvelope = serde_json::from_str(raw).unwrap();
        let err = envelope.validate().unwrap_err();
        assert!(matches!(
            err,
            EncryptedEnvelopeError::InvalidRecipient { .. }
        ));
    }

    #[test]
    fn redacts_notify_device_debug() {
        let debug = format!("{:?}", notification().devices[0]);
        assert!(debug.contains("fcm:<redacted"));
        assert!(!debug.contains("very-secret-token"));

        let rejected = RejectedPushToken {
            push_key: Some("fcm:very-secret-token".to_owned()),
            push_key_hash: Some("pkh_abc".to_owned()),
            app_id: Some("app.example.android".to_owned()),
            reason: Some("unregistered".to_owned()),
        };
        let debug = format!("{rejected:?}");
        assert!(debug.contains("fcm:<redacted"));
        assert!(!debug.contains("very-secret-token"));
    }
}
