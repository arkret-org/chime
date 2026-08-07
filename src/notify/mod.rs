//! Optional `ak.edge.push.command.notify` wire model for Push Gateway implementations.
//!
//! This module models the Arkret notify request/response payload and keeps
//! blind-wakeup validation conservative. It does not implement APNs, FCM, Web
//! Push, or OEM provider delivery.

mod agent_routing;
mod envelope;
mod errors;
mod local;
mod notification;

#[cfg(test)]
mod tests;

pub use agent_routing::{
    AGENT_ACTOR_PRIVATE_KINDS, AGENT_LIFECYCLE_DURABLE_KINDS, AgentEventRouting, AgentFanoutAction,
    AgentFanoutDenied, AgentFanoutGate, AgentLifecycleSummary, PHASE_P2_AGENT_TYPED_ID_PREFIXES,
    PHASE_P2_FORBIDDEN_FIELD_ALIASES, ROUND_R2_R3_SENSITIVE_FIELDS, assert_no_sensitive_fields,
    classify_agent_event_kind, is_forbidden_field_alias, is_phase_p2_agent_typed_id,
    render_agent_lifecycle_summary,
};
pub use envelope::{
    PushNotifyEnvelopeExt, PushNotifyPolicyContext, PushNotifyPrivacyMode, PushNotifyPrivacyVector,
    PushNotifyRequestBody, shared_push_notify_privacy_vectors,
};
pub use errors::PushNotifyPrivacyError;
pub use local::{
    ExpiryInvalidationBehavior, LocalNotificationAction, LocalNotificationDecision,
    LocalNotificationPolicy, LocalNotificationState, evaluate_local_notification,
    local_reason_code,
};
pub use notification::{
    PushDeviceRoute, PushNotificationDedup, PushNotificationEnvelope, PushNotificationExt,
    PushRouteTokens, late_recovery_event_id, new_blind_wakeup,
};
