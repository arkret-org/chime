//! Optional `cx.push.notify` wire model for Push Gateway implementations.
//!
//! This module models the Contrix notify request/response payload and keeps
//! blind-wakeup validation conservative. It does not implement APNs, FCM, Web
//! Push, or OEM provider delivery.

use std::fmt;

use base64::{Engine as _, engine::general_purpose};
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
        self.notification.validate_blind_wakeup_strict()
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_hint: Option<PushHint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<Value>,
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
        validate_typed_id("space_id", self.space_id.as_deref(), "cx:space:")?;
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
        if self.space_name.is_some() {
            return Err(PushNotifyPrivacyError::SensitiveField {
                field: "space_name".to_owned(),
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
        if !self.recipient.starts_with("did:") {
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
            space_id: Some("cx:space:01JS0SP000000000000000000".to_owned()),
            sender: None,
            sender_display_name: None,
            space_name: None,
            push_hint: Some(PushHint::new("new_message").unwrap()),
            counts: Some(serde_json::json!({ "unread": 1 })),
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
        let request = PushNotifyRequest {
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
}
