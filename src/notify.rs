//! Optional `cx.push.notify` wire model for Push Gateway implementations.
//!
//! This module intentionally does not implement APNs, FCM, Web Push, or OEM
//! provider delivery. It only models the Contrix request/response payload and
//! provides a conservative E2EE blind-wakeup validator.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::redact_push_key;

/// Request body for `POST /api/v1/push/notify`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct PushNotifyRequest {
    pub notification: PushNotification,
}

impl PushNotifyRequest {
    /// Validate this notification as an E2EE blind wakeup payload.
    pub fn validate_blind_wakeup(&self) -> Result<(), PushNotifyPrivacyError> {
        self.notification.validate_blind_wakeup()
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
    /// Validate this notification as a minimized E2EE blind wakeup.
    ///
    /// The validator is intentionally conservative. It rejects explicit body,
    /// encrypted payload, SDP, ICE, and TURN fields in extension data, and it
    /// rejects push hints that look like call setup material.
    pub fn validate_blind_wakeup(&self) -> Result<(), PushNotifyPrivacyError> {
        if let Some(push_hint) = &self.push_hint {
            validate_hint(push_hint)?;
        }

        for key in self.extra.keys() {
            if is_sensitive_payload_key(key) {
                return Err(PushNotifyPrivacyError::SensitiveField {
                    field: key.to_owned(),
                });
            }
        }

        Ok(())
    }
}

/// Target device entry for `cx.push.notify`.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct PushNotificationDevice {
    pub push_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
}

impl fmt::Debug for PushNotificationDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PushNotificationDevice")
            .field("push_key", &redact_push_key(&self.push_key))
            .field("app_id", &self.app_id)
            .finish()
    }
}

/// Response body for `POST /api/v1/push/notify`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct PushNotifyResponse {
    pub rejected: Vec<RejectedPushToken>,
}

/// Rejected platform token summary.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct RejectedPushToken {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl fmt::Debug for RejectedPushToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RejectedPushToken")
            .field("push_key", &self.push_key.as_deref().map(redact_push_key))
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

fn is_sensitive_payload_key(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "body"
            | "message_body"
            | "formatted_body"
            | "encrypted_payload"
            | "ciphertext"
            | "sdp"
            | "ice_candidate"
            | "ice_candidates"
            | "turn_credential"
            | "turn_credentials"
    )
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
            }],
            extra: Map::new(),
        }
    }

    #[test]
    fn validates_minimized_notification() {
        PushNotifyRequest {
            notification: notification(),
        }
        .validate_blind_wakeup()
        .unwrap();
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
    fn rejects_sdp_like_hint() {
        let mut notification = notification();
        notification.push_hint = Some("v=0\r\na=ice-ufrag:secret".to_owned());

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
    }
}
