use cokret::blind_payload_sanitizer as sdk_sanitizer;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::errors::PushNotifyPrivacyError;
use super::notification::PushNotification;

/// Request body for `POST /_cokret/edge/push/notify`.
///
/// SPEC-CR-016: the canonical `push_notify_request_body` is
/// `{notification, event_kind?, reason_code?, audit_envelope?}` with
/// `additionalProperties:false`. The former envelope-level transport
/// fields (`operation_id` / `idempotency_key` / `origin_service_did` /
/// `destination_service_did`) ride HTTP headers
/// (`Idempotency-Key` / `Source-Service-DID` / `Destination-Service-DID`)
/// or are determined by the URL path (`operationId`) and are no longer
/// body fields. The provider-collapse hints (`app_id` / `ttl_seconds` /
/// `collapse_key`) and `priority` were never part of the canonical body;
/// `priority` is now a visible_notification field on `PushNotification`,
/// the collapse hints are gateway/provider concerns (push-notifications.md
/// §2.4) carried out of band, not on the notify request body.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChimePushNotifyEnvelope {
    pub notification: PushNotification,
    /// SPEC-CR-016 (class D) — originating Event kind used by the gateway
    /// to route Phase-P2 `ck.agent.*` kinds. Coarse routing selector.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_kind: Option<String>,
    /// SPEC-CR-016 (class D) — caller-supplied wire-safe reason code
    /// (e.g. `historical_only` for a diagnostic replay no-op).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    /// SPEC-CR-016 (class D) — `ck.audit.policy_access` envelope routing
    /// fragment. When present the request is an audit-pipeline event, not a
    /// push notify.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_envelope: Option<AuditEnvelopeMetadata>,
}

/// SPEC-CR-016 — top-level `ck.audit.policy_access` envelope routing
/// fragment (mirror of floria's `AuditEnvelopeMetadata` /
/// `cokret::AuditPolicyAccessPayload` wire fields).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEnvelopeMetadata {
    pub access_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub late_recovery_original_event_id: Option<String>,
}

impl ChimePushNotifyEnvelope {
    pub fn validate_wire_model(&self) -> Result<(), PushNotifyPrivacyError> {
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

    /// SPEC-CR-016: the destination service DID rides the
    /// `Destination-Service-DID` HTTP header, not the body, so callers pass
    /// it in explicitly (the value they put on / read from the header) to
    /// select the privacy mode.
    pub fn assert_payload_safe(
        &self,
        policy: &PushNotifyPolicyContext,
        destination_service_did: Option<&str>,
    ) -> Result<(), PushNotifyPrivacyError> {
        let mode = policy.mode_for(destination_service_did);
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

pub fn shared_push_notify_privacy_vectors() -> Vec<PushNotifyPrivacyVector> {
    vec![
        PushNotifyPrivacyVector {
            name: "blind wakeup accepts opaque metadata".to_owned(),
            mode: PushNotifyPrivacyMode::E2eeBlindWakeup,
            // SPEC-CR-016: the notify request body top level is strictly
            // `{notification, event_kind?, reason_code?, audit_envelope?}`
            // (`deny_unknown_fields`). Transport fields such as
            // `operation_id` are determined by the URL path / HTTP headers
            // and MUST NOT appear in the body, so this accept-vector payload
            // carries no `operation_id` (see `service-http-binding.md:213`).
            payload: serde_json::json!({
                "notification": {
                    "push_target_id": "ck:pseudonym:push:01HYZ8Z000000000000000",
                    "wakeup_kind": "message",
                    "push_hint": "new_message",
                    "counts": { "badge": "2-5" },
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
