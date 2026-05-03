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
        if let Some(operation_id) = &self.operation_id {
            if operation_id != crate::OPERATION_PUSH_NOTIFY {
                return Err(PushNotifyPrivacyError::InvalidFieldValue {
                    field: "operation_id".to_owned(),
                });
            }
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_hint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub counts: Option<Value>,
    pub devices: Vec<PushNotificationDevice>,
    /// Forward-compatible extension fields.
    ///
    /// `validate_blind_wakeup` rejects known sensitive keys in this map.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl PushNotification {
    /// Validate the active `cx.push.notify` notification contract.
    pub fn validate_wire_model(&self) -> Result<(), PushNotifyPrivacyError> {
        validate_required("type", &self.notification_type)?;
        validate_typed_id("event_id", self.event_id.as_deref(), "cx:event:")?;
        validate_typed_id("space_id", self.space_id.as_deref(), "cx:space:")?;

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

        if let Some(push_hint) = &self.push_hint {
            validate_hint(push_hint)?;
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

    /// Validate a notification for an explicitly plaintext-visible service.
    ///
    /// This mode allows display metadata such as title/body in extension data
    /// only because the caller selected it explicitly. It still rejects
    /// encrypted payload bytes, provider wrappers, SDP/ICE/TURN credentials,
    /// and call setup material.
    pub fn validate_plaintext_visible_service(&self) -> Result<(), PushNotifyPrivacyError> {
        self.validate_wire_model()?;

        if let Some(push_hint) = &self.push_hint {
            validate_hint(push_hint)?;
        }

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

fn validate_hint(push_hint: &str) -> Result<(), PushNotifyPrivacyError> {
    let normalized = push_hint.to_ascii_lowercase();
    let sensitive_markers = [
        "candidate:",
        "ice-ufrag",
        "ice-pwd",
        "a=crypto:",
        "turn:",
        "turns:",
        "sdp",
        "v=0\r",
        "v=0\n",
        "title:",
        "body:",
        "space_name:",
        "space name:",
        "sender_display_name:",
        "\"title\"",
        "\"body\"",
        "\"space_name\"",
    ];

    if sensitive_markers
        .iter()
        .any(|marker| normalized.contains(marker))
    {
        Err(PushNotifyPrivacyError::SensitiveHint)
    } else {
        Ok(())
    }
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
                    "push_hint": "New message",
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
            push_hint: Some("New message".to_owned()),
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
    fn rejects_sdp_like_hint() {
        let mut notification = notification();
        notification.push_hint = Some("v=0\r\na=ice-ufrag:secret".to_owned());

        assert_eq!(
            notification.validate_blind_wakeup().unwrap_err(),
            PushNotifyPrivacyError::SensitiveHint
        );
    }

    #[test]
    fn rejects_structured_preview_hint() {
        let mut notification = notification();
        notification.push_hint = Some(r#"{"title":"Secret Project"}"#.to_owned());

        assert_eq!(
            notification.validate_blind_wakeup().unwrap_err(),
            PushNotifyPrivacyError::SensitiveHint
        );
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
