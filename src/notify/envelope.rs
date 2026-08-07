pub use arkret::PushNotifyRequestBody;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::errors::PushNotifyPrivacyError;
use super::notification::{PushNotificationExt, validate_sdk_request};
/// Chime behavior layered over the SDK-owned push notify request body.
pub trait PushNotifyEnvelopeExt {
    fn validate_wire_model(&self) -> Result<(), PushNotifyPrivacyError>;
    fn validate_blind_wakeup(&self) -> Result<(), PushNotifyPrivacyError>;
    fn validate_blind_wakeup_strict(&self) -> Result<(), PushNotifyPrivacyError>;
    fn validate_privacy(&self, mode: PushNotifyPrivacyMode) -> Result<(), PushNotifyPrivacyError>;
    fn assert_payload_safe(
        &self,
        policy: &PushNotifyPolicyContext,
        destination_service_id: Option<&str>,
    ) -> Result<(), PushNotifyPrivacyError>;
}

impl PushNotifyEnvelopeExt for PushNotifyRequestBody {
    fn validate_wire_model(&self) -> Result<(), PushNotifyPrivacyError> {
        validate_sdk_request(self)
    }

    fn validate_blind_wakeup(&self) -> Result<(), PushNotifyPrivacyError> {
        self.validate_wire_model()?;
        self.notification.validate_blind_wakeup()
    }

    fn validate_blind_wakeup_strict(&self) -> Result<(), PushNotifyPrivacyError> {
        self.validate_wire_model()?;
        self.notification.validate_blind_wakeup_strict()
    }

    fn validate_privacy(&self, mode: PushNotifyPrivacyMode) -> Result<(), PushNotifyPrivacyError> {
        match mode {
            PushNotifyPrivacyMode::E2eeBlindWakeup => self.validate_blind_wakeup(),
            PushNotifyPrivacyMode::PlaintextVisibleService => {
                self.validate_wire_model()?;
                self.notification.validate_plaintext_visible_service()
            }
        }
    }

    fn assert_payload_safe(
        &self,
        policy: &PushNotifyPolicyContext,
        destination_service_id: Option<&str>,
    ) -> Result<(), PushNotifyPrivacyError> {
        self.validate_privacy(policy.mode_for(destination_service_id))
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

    pub fn allows_plaintext_for(&self, destination_service_id: &str) -> bool {
        self.plaintext_visible_services
            .iter()
            .any(|service| service == destination_service_id)
    }

    pub fn mode_for(&self, destination_service_id: Option<&str>) -> PushNotifyPrivacyMode {
        match destination_service_id {
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

pub fn shared_push_notify_privacy_vectors() -> Vec<PushNotifyPrivacyVector> {
    vec![
        PushNotifyPrivacyVector {
            name: "blind wakeup accepts opaque metadata".to_owned(),
            mode: PushNotifyPrivacyMode::E2eeBlindWakeup,
            payload: serde_json::json!({
                "notification": {
                    "push_target_id": "ak:pseudonym:push:01HYZ8Z000000000000000",
                    "wakeup_kind": "message",
                    "timing_profile_hint": "default",
                    "push_hint": "new_message",
                    "counts": { "badge": "2-5" },
                    "devices": [{
                        "device_id": "ak:device:01904100-0000-7000-8000-000000000010",
                        "push_key": "fcm:opaque-token",
                        "app_id": "app.example"
                    }]
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
                    "push_target_id": "ak:pseudonym:push:01HYZ8Z000000000000000",
                    "wakeup_kind": "message",
                    "timing_profile_hint": "default",
                    "title": "Secret",
                    "devices": [{
                        "device_id": "ak:device:01904100-0000-7000-8000-000000000010",
                        "push_key": "fcm:opaque-token",
                        "app_id": "app.example"
                    }]
                }
            }),
            should_accept: false,
            expected_error_field: Some("title".to_owned()),
        },
    ]
}
