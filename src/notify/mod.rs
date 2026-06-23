//! Optional `ck.edge.push.command.notify` wire model for Push Gateway implementations.
//!
//! This module models the Cokret notify request/response payload and keeps
//! blind-wakeup validation conservative. It does not implement APNs, FCM, Web
//! Push, or OEM provider delivery.

mod agent_routing;
mod envelope;
mod errors;
mod local;
mod notification;
mod outcome;
mod validation;

#[cfg(test)]
mod tests;

pub use agent_routing::{
    AGENT_ACTOR_PRIVATE_KINDS, AGENT_LIFECYCLE_DURABLE_KINDS, AgentEventRouting,
    AgentLifecycleSummary, PHASE_P2_AGENT_TYPED_ID_PREFIXES, PHASE_P2_FORBIDDEN_FIELD_ALIASES,
    ROUND_R2_R3_SENSITIVE_FIELDS, assert_no_sensitive_fields, classify_agent_event_kind,
    is_forbidden_field_alias, is_phase_p2_agent_typed_id, render_agent_lifecycle_summary,
};
// `AuditEnvelopeMetadata` and `RouteTokens` are `pub` field types of
// the public envelope/notification structs but are not consumed by name in
// any non-test in-crate code path; re-exporting them keeps the types
// publicly nameable through this module exactly as in the pre-split
// single-file form. The `#[allow]` mirrors that the original `pub struct`
// definitions produced no unused warning.
#[allow(unused_imports)]
pub use envelope::AuditEnvelopeMetadata;
pub use envelope::{
    ChimePushNotifyEnvelope, PushNotifyPolicyContext, PushNotifyPrivacyMode,
    PushNotifyPrivacyVector, shared_push_notify_privacy_vectors,
};
pub use errors::PushNotifyPrivacyError;
pub use local::{
    ExpiryInvalidationBehavior, LocalNotificationAction, LocalNotificationDecision,
    LocalNotificationPolicy, LocalNotificationState, evaluate_local_notification,
    local_reason_code,
};
#[allow(unused_imports)]
pub use notification::{
    PushHint, PushNotification, PushNotificationDedup, PushNotificationDevice, PushTargetId,
    RouteTokens, WakeupKind,
};
pub use outcome::{
    ChimePushNotifyOutcome, EncryptedEnvelope, EncryptedEnvelopeError, ProviderRetryHint,
    PushDeliveryReceipt, RejectedPushToken, SUPPORTED_ENCRYPTED_ENVELOPE_ALGORITHMS,
};
