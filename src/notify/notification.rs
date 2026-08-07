use arkret::{AgentSidecarAccessReadiness, EventId};
pub use arkret::{PushDeviceRoute, PushNotificationEnvelope, PushRouteTokens};

use super::agent_routing::AgentFanoutGate;
use super::errors::PushNotifyPrivacyError;

/// Construct the minimal SDK-owned blind-wakeup notification shape.
pub fn new_blind_wakeup(
    push_target_id: impl Into<String>,
    wakeup_kind: impl Into<String>,
) -> PushNotificationEnvelope {
    PushNotificationEnvelope {
        push_target_id: Some(push_target_id.into()),
        wakeup_kind: Some(wakeup_kind.into()),
        timing_profile_hint: Some(arkret::PushTimingProfileHint::Default),
        ..Default::default()
    }
}

/// Chime behavior layered over the SDK-owned push notification wire type.
pub trait PushNotificationExt {
    fn realm_route_token(&self) -> Option<&str>;
    fn scope_route_token(&self) -> Option<&str>;
    fn delivery_binding_frontier_token(&self) -> Option<&str>;
    fn mention_redirect_target_route_tokens(&self) -> Option<&[String]>;
    fn validate_wire_model(&self) -> Result<(), PushNotifyPrivacyError>;
    fn validate_blind_wakeup_strict(&self) -> Result<(), PushNotifyPrivacyError>;
    fn validate_blind_wakeup(&self) -> Result<(), PushNotifyPrivacyError>;
    fn validate_plaintext_visible_service(&self) -> Result<(), PushNotifyPrivacyError>;
    fn decrypt_allowed_for_route_token(&self, receiver_route_token: &str) -> bool;
    fn has_mention_redirect_routing(&self) -> bool;
    fn eligible_agent_fanout_devices<F>(
        &self,
        gate: &AgentFanoutGate<'_>,
        readiness_for: F,
    ) -> Vec<&PushDeviceRoute>
    where
        F: FnMut(&arkret::DeviceId) -> Option<AgentSidecarAccessReadiness>;
    fn background_fetch_hint(&self) -> Option<crate::BackgroundFetchHint<'_>>;
}

impl PushNotificationExt for PushNotificationEnvelope {
    fn realm_route_token(&self) -> Option<&str> {
        self.route_tokens
            .as_ref()
            .and_then(|routing| routing.realm_route_token.as_deref())
    }

    fn scope_route_token(&self) -> Option<&str> {
        self.route_tokens
            .as_ref()
            .and_then(|routing| routing.scope_route_token.as_deref())
    }

    fn delivery_binding_frontier_token(&self) -> Option<&str> {
        self.route_tokens
            .as_ref()
            .and_then(|routing| routing.delivery_binding_frontier_token.as_deref())
    }

    fn mention_redirect_target_route_tokens(&self) -> Option<&[String]> {
        let tokens = &self
            .route_tokens
            .as_ref()?
            .mention_redirect_target_route_tokens;
        (!tokens.is_empty()).then_some(tokens.as_slice())
    }

    fn validate_wire_model(&self) -> Result<(), PushNotifyPrivacyError> {
        validate_sdk_request(&arkret::PushNotifyRequestBody {
            notification: self.clone(),
            event_kind: None,
            reason_code: None,
            audit_envelope: None,
        })
    }

    fn validate_blind_wakeup_strict(&self) -> Result<(), PushNotifyPrivacyError> {
        self.validate_blind_wakeup()
    }

    fn validate_blind_wakeup(&self) -> Result<(), PushNotifyPrivacyError> {
        self.validate_wire_model()?;

        for (field, present) in [
            ("event_id", self.event_id.is_some()),
            ("realm_id", self.realm_id.is_some()),
            ("sender_actor_id", self.sender_actor_id.is_some()),
            ("strand_id", self.strand_id.is_some()),
            ("message_id", self.message_id.is_some()),
            (
                "sender_actor_display_name",
                self.sender_actor_display_name.is_some(),
            ),
            ("strand_title", self.strand_title.is_some()),
            ("realm_title", self.realm_title.is_some()),
            ("user_is_target", self.user_is_target.is_some()),
            ("priority", self.priority.is_some()),
            ("membership", self.membership.is_some()),
        ] {
            if present {
                return Err(PushNotifyPrivacyError::SensitiveField {
                    field: field.to_owned(),
                });
            }
        }

        if let Some(push_hint) = self.push_hint.as_deref()
            && !arkret::blind_payload_sanitizer::is_valid_push_hint(push_hint)
        {
            return Err(PushNotifyPrivacyError::InvalidFieldValue {
                field: "push_hint".to_owned(),
            });
        }
        if self.push_hint.as_deref() == Some("l10n_key") {
            if self.push_hint_l10n_key.as_deref().is_none_or(str::is_empty) {
                return Err(PushNotifyPrivacyError::MissingField {
                    field: "push_hint_l10n_key".to_owned(),
                });
            }
        } else if self.push_hint_l10n_key.is_some() {
            return Err(PushNotifyPrivacyError::InvalidFieldValue {
                field: "push_hint_l10n_key".to_owned(),
            });
        }

        Ok(())
    }

    fn validate_plaintext_visible_service(&self) -> Result<(), PushNotifyPrivacyError> {
        self.validate_wire_model()
    }

    fn decrypt_allowed_for_route_token(&self, receiver_route_token: &str) -> bool {
        let Some(allowed_tokens) = self.mention_redirect_target_route_tokens() else {
            return true;
        };
        let receiver_route_token = receiver_route_token.trim();
        allowed_tokens
            .iter()
            .any(|allowed| allowed.trim() == receiver_route_token)
    }

    fn has_mention_redirect_routing(&self) -> bool {
        self.mention_redirect_target_route_tokens().is_some()
    }

    fn eligible_agent_fanout_devices<F>(
        &self,
        gate: &AgentFanoutGate<'_>,
        mut readiness_for: F,
    ) -> Vec<&PushDeviceRoute>
    where
        F: FnMut(&arkret::DeviceId) -> Option<AgentSidecarAccessReadiness>,
    {
        self.devices
            .iter()
            .filter(|device| {
                gate.evaluate_target(readiness_for(&device.device_id))
                    .is_ok()
            })
            .collect()
    }

    fn background_fetch_hint(&self) -> Option<crate::BackgroundFetchHint<'_>> {
        Some(crate::BackgroundFetchHint::new(
            self.push_target_id.as_deref()?,
            self.wakeup_kind.as_deref()?,
        ))
    }
}

pub(super) fn validate_sdk_request(
    request: &arkret::PushNotifyRequestBody,
) -> Result<(), PushNotifyPrivacyError> {
    arkret::validate_push_notify_contract_shape(request).map_err(push_notify_contract_error)
}

fn push_notify_contract_error(message: String) -> PushNotifyPrivacyError {
    let field = [
        "notification.push_target_id",
        "notification.wakeup_kind",
        "notification.timing_profile_hint",
        "notification.devices",
        "notification.route_tokens.realm_route_token",
        "notification.route_tokens.scope_route_token",
        "notification.route_tokens.delivery_binding_frontier_token",
        "notification.route_tokens.mention_redirect_target_route_tokens",
    ]
    .into_iter()
    .find(|field| message.contains(field))
    .map(|field| {
        field
            .strip_prefix("notification.")
            .unwrap_or(field)
            .to_owned()
    })
    .unwrap_or_else(|| message.clone());

    if message.contains("is required") || message.contains("must contain at least one") {
        PushNotifyPrivacyError::MissingField { field }
    } else if message.contains("forbidden") {
        PushNotifyPrivacyError::SensitiveField { field }
    } else {
        PushNotifyPrivacyError::InvalidFieldValue { field }
    }
}

/// Client-facing summary of the push gateway's deduplication configuration.
///
/// This is Chime runtime state, not an Arkret wire model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PushNotificationDedup {
    pub backend: String,
    pub window: std::time::Duration,
}

impl PushNotificationDedup {
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

    pub fn has_window(&self) -> bool {
        !self.window.is_zero()
    }
}

pub fn late_recovery_event_id(request: &arkret::PushNotifyRequestBody) -> Option<&EventId> {
    let audit = request.audit_envelope.as_ref()?;
    (audit.access_kind == "e2ee_late_recovery")
        .then_some(audit.late_recovery_original_event_id.as_ref())
        .flatten()
}
