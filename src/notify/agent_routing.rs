use serde_json::Value;
use thiserror::Error;

use arkret::{
    AgentAuthorizationAdmission, AgentAuthorizationStatus, AgentSignerEvidence, Did, Hash,
    protocol_journey::{
        DeploymentCeilingSignedHead, ParticipationBits, ParticipationReplaceReceipt,
        ParticipationReplacementBatch, ParticipationScope, ParticipationScopeEvidence,
        ProtocolOpaqueId, SidecarAccessReadiness,
    },
};
use chrono::{DateTime, Utc};

/// Round R2/R3 sensitive fields that must NEVER appear in any blind push
/// payload — mirrors floria T07/T10/T06.
///
/// These fields belong to spec round 2+3 governance surfaces (moderation
/// appeals, attestation evidence, cross-signing reset, identity link
/// routing, realm/space terminal lifecycle). The SDK owns the generic
/// blind-payload forbidden-key list; this chime-only tripwire covers
/// governance identifiers that should never enter a device push wakeup.
///
/// Kept as a flat slice (rather than a `match`) so the array is itself
/// public API — tests in chime / floria / inkson can iterate it to
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
    "audit_agent_principal_id",
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
    // Phase P2 (spec 37ce729, AKP-0008 / AKP-0009) — Personal Agent /
    // Sidecar governance identifiers. None of these may appear on a push
    // wakeup wire: they identify the controller↔agent binding state and
    // the action-approval transcript. Leaking either correlates a user
    // device with their native agent runtime endpoint.
    "accountability_grant_id",
    "controller_did",
    "controller_principal_id",
    "agent_principal_id",
    "controller_id",
    "agent_id",
    "agent_session_id",
    "agent_key_id",
    "sidecar_circle_id",
    "agent_draft_id",
    "proposed_action",
    "action_payload_digest",
    "approval_nonce",
    // Personal productivity / private search state. These are either
    // holder-private account-data plaintext or encrypted search-index
    // internals and must never be mirrored into provider-visible push
    // payloads.
    "target_ref",
    "target_key",
    "collection_title",
    "collection_key",
    "reminder_note",
    "note",
    "message_payload",
    "message_payload_digest",
    "draft_slot",
    "origin_device_id",
    "realm_key",
    "blind_tokens",
    "shard_key",
];

pub use arkret::{
    AGENT_ACTOR_PRIVATE_KINDS, AGENT_LIFECYCLE_SILENT_KINDS as AGENT_LIFECYCLE_DURABLE_KINDS,
    AgentEventRouting, PHASE_P2_AGENT_TYPED_ID_PREFIXES,
};

/// The five protocol actions controlled by `ak.profile.agent_participation_policy.v1`.
///
/// This is an evaluation selector, not a wire model. The policy bits and all
/// evidence remain the canonical SDK types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentFanoutAction {
    ReplyMessage,
    ReactionAdd,
    ReactionRemove,
    ThirdPartyMention,
    ActOnBehalf,
}

/// Why a newly-derived Agent notification or push target was denied.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum AgentFanoutDenied {
    #[error("required Agent fanout evidence is unresolved")]
    EvidenceUnresolved,
    #[error("Agent participation evidence is malformed")]
    InvalidParticipationEvidence,
    #[error("Agent participation evidence does not bind the exact target")]
    ScopeEvidenceMismatch,
    #[error("Agent participation receipt does not bind the accepted batch")]
    ReceiptMismatch,
    #[error("the current deployment ceiling is invalid, stale, or for another service")]
    DeploymentCeilingInvalid,
    #[error("the controller selection exceeds an effective participation ceiling")]
    SelectionExceedsCeiling,
    #[error("the requested Agent action is disabled by effective participation")]
    ActionDisabled,
    #[error("the Agent authorization is not currently admitted")]
    CurrentAdmissionInvalid,
    #[error("the target device/Sidecar intersection is not ready")]
    TargetNotReady,
}

/// Borrowed inputs for the fail-closed Agent notification/fanout gate.
///
/// This type is deliberately not serializable: it is an in-process evaluator
/// over SDK-owned protocol objects, so it cannot become a second wire contract.
/// Signature verification of the supplied SDK objects must have succeeded at
/// the trust boundary before this structural/current-state gate is invoked.
pub struct AgentFanoutGate<'a> {
    pub action: AgentFanoutAction,
    pub batch: Option<&'a ParticipationReplacementBatch>,
    pub receipt: Option<&'a ParticipationReplaceReceipt>,
    pub immutable_provision_ceiling: Option<ParticipationBits>,
    pub deployment_ceiling: Option<&'a DeploymentCeilingSignedHead>,
    pub realm_ceiling: Option<ParticipationBits>,
    /// Required for Circle and Strand targets; absent for a Realm target.
    pub scoped_ceiling: Option<ParticipationBits>,
    pub current_admission: Option<&'a AgentAuthorizationAdmission>,
    pub current_signer_evidence: Option<&'a AgentSignerEvidence>,
    pub target_service_id: &'a Did,
    pub verifier_id: &'a Did,
    pub audience: &'a ProtocolOpaqueId,
    pub now: DateTime<Utc>,
}

impl AgentFanoutGate<'_> {
    /// Evaluate one concrete target/device intersection.
    ///
    /// Call this at message-event fanout time. A later participation change
    /// must not retroactively create or remove an already-derived notification.
    pub fn evaluate_target(
        &self,
        readiness: Option<SidecarAccessReadiness>,
    ) -> Result<(), AgentFanoutDenied> {
        let batch = self.batch.ok_or(AgentFanoutDenied::EvidenceUnresolved)?;
        let receipt = self.receipt.ok_or(AgentFanoutDenied::EvidenceUnresolved)?;
        let immutable_ceiling = self
            .immutable_provision_ceiling
            .ok_or(AgentFanoutDenied::EvidenceUnresolved)?;
        let deployment = self
            .deployment_ceiling
            .ok_or(AgentFanoutDenied::EvidenceUnresolved)?;
        let realm_ceiling = self
            .realm_ceiling
            .ok_or(AgentFanoutDenied::EvidenceUnresolved)?;
        let admission = self
            .current_admission
            .ok_or(AgentFanoutDenied::EvidenceUnresolved)?;
        let signer_evidence = self
            .current_signer_evidence
            .ok_or(AgentFanoutDenied::EvidenceUnresolved)?;

        batch
            .validate()
            .map_err(|_| AgentFanoutDenied::InvalidParticipationEvidence)?;
        receipt
            .validate()
            .map_err(|_| AgentFanoutDenied::ReceiptMismatch)?;
        deployment
            .validate()
            .map_err(|_| AgentFanoutDenied::DeploymentCeilingInvalid)?;

        self.validate_scope_evidence(batch)?;
        self.validate_receipt(batch, receipt, deployment)?;
        self.validate_current_admission(batch, admission, signer_evidence)?;

        let selection = batch.selection;
        if !selection.is_subset_of(immutable_ceiling)
            || !selection.is_subset_of(deployment.core.ceiling)
            || !selection.is_subset_of(realm_ceiling)
        {
            return Err(AgentFanoutDenied::SelectionExceedsCeiling);
        }
        if !matches!(batch.target_scope, ParticipationScope::Realm { .. }) {
            let scoped_ceiling = self
                .scoped_ceiling
                .ok_or(AgentFanoutDenied::EvidenceUnresolved)?;
            if !selection.is_subset_of(scoped_ceiling) {
                return Err(AgentFanoutDenied::SelectionExceedsCeiling);
            }
        }
        if !action_enabled(selection, self.action) {
            return Err(AgentFanoutDenied::ActionDisabled);
        }
        if readiness != Some(SidecarAccessReadiness::Ready) {
            return Err(AgentFanoutDenied::TargetNotReady);
        }
        Ok(())
    }

    fn validate_scope_evidence(
        &self,
        batch: &ParticipationReplacementBatch,
    ) -> Result<(), AgentFanoutDenied> {
        let (
            agent_id,
            target_scope,
            target_service_id,
            verifier_id,
            audience,
            issued_at,
            expires_at,
        ) = match &batch.scope_evidence {
            ParticipationScopeEvidence::InlineEncrypted { challenge, .. } => (
                &challenge.agent_id,
                &challenge.target_scope,
                &challenge.target_service_id,
                &challenge.verifier_id,
                &challenge.audience,
                challenge.issued_at,
                challenge.expires_at,
            ),
            ParticipationScopeEvidence::AcceptedTargetReceipt {
                agent_id,
                target_scope,
                target_service_id,
                verifier_id,
                audience,
                issued_at,
                expires_at,
                ..
            } => (
                agent_id,
                target_scope,
                target_service_id,
                verifier_id,
                audience,
                *issued_at,
                *expires_at,
            ),
        };
        if agent_id != &batch.agent_id
            || target_scope != &batch.target_scope
            || target_service_id != self.target_service_id
            || verifier_id != self.verifier_id
            || audience != self.audience
            || issued_at > self.now
            || expires_at <= self.now
        {
            return Err(AgentFanoutDenied::ScopeEvidenceMismatch);
        }
        Ok(())
    }

    fn validate_receipt(
        &self,
        batch: &ParticipationReplacementBatch,
        receipt: &ParticipationReplaceReceipt,
        deployment: &DeploymentCeilingSignedHead,
    ) -> Result<(), AgentFanoutDenied> {
        let batch_digest =
            canonical_digest(batch).map_err(|_| AgentFanoutDenied::InvalidParticipationEvidence)?;
        let evidence_digest = canonical_digest(&batch.scope_evidence)
            .map_err(|_| AgentFanoutDenied::InvalidParticipationEvidence)?;
        let accepted_version = batch
            .expected_version
            .checked_add(1)
            .ok_or(AgentFanoutDenied::ReceiptMismatch)?;
        if receipt.batch_digest != batch_digest
            || receipt.scope_evidence_digest != evidence_digest
            || receipt.target_service_id != *self.target_service_id
            || receipt.accepted_version != accepted_version
            || receipt.accepted_at > self.now
            || receipt.deployment_ceiling_digest != deployment.head_digest
            || receipt.deployment_ceiling_version != deployment.core.version
        {
            return Err(AgentFanoutDenied::ReceiptMismatch);
        }
        if deployment.core.target_service_id != *self.target_service_id
            || deployment.core.issuer != *self.target_service_id
            || deployment.core.issued_at > receipt.accepted_at
            || deployment.core.expires_at <= self.now
            || receipt.signature.verification_method != deployment.core.issuer_verification_method
        {
            return Err(AgentFanoutDenied::DeploymentCeilingInvalid);
        }
        Ok(())
    }

    fn validate_current_admission(
        &self,
        batch: &ParticipationReplacementBatch,
        admission: &AgentAuthorizationAdmission,
        signer_evidence: &AgentSignerEvidence,
    ) -> Result<(), AgentFanoutDenied> {
        let binding = &signer_evidence.signing_key_binding;
        let authorization = &signer_evidence.authorization;
        let witness = &signer_evidence.state_witness;
        let freshness = &signer_evidence.freshness_attestation;
        if admission.agent_id != batch.agent_id
            || binding.agent_id != batch.agent_id
            || admission.verification_method != binding.verification_method
            || authorization.status != AgentAuthorizationStatus::Active
            || admission.authorization_event_id != authorization.authorized_event_id
            || binding.agent_key_authorize_event_id != authorization.authorized_event_id
            || admission.accepted_frontier != authorization.accepted_frontier
            || admission.accepted_at != authorization.accepted_at
            || witness.agent_id != batch.agent_id
            || witness.authorization_event_id != authorization.authorized_event_id
            || witness.accepted_frontier != authorization.accepted_frontier
            || admission.accepted_at > self.now
            || authorization.not_before > self.now
            || binding.issued_at > self.now
            || binding
                .expires_at
                .is_some_and(|expires_at| expires_at <= self.now)
            || authorization
                .expires_at
                .is_some_and(|expires_at| expires_at <= self.now)
            || authorization.valid_until_frontier.is_some()
            || authorization.transition_event_id.is_some()
            || freshness.issued_at > self.now
            || freshness.issued_at >= freshness.expires_at
            || freshness.expires_at <= self.now
        {
            return Err(AgentFanoutDenied::CurrentAdmissionInvalid);
        }
        Ok(())
    }
}

fn action_enabled(bits: ParticipationBits, action: AgentFanoutAction) -> bool {
    match action {
        AgentFanoutAction::ReplyMessage => bits.reply_message,
        AgentFanoutAction::ReactionAdd => bits.reaction_add,
        AgentFanoutAction::ReactionRemove => bits.reaction_remove,
        AgentFanoutAction::ThirdPartyMention => bits.accept_third_party_mention,
        AgentFanoutAction::ActOnBehalf => bits.act_on_behalf,
    }
}

fn canonical_digest<T: serde::Serialize>(value: &T) -> arkret_wire::Result<Hash> {
    let bytes = arkret_canonical::canonical_json_bytes(value)?;
    Hash::new(arkret_canonical::canonical::sha256_digest(bytes))
        .map_err(|error| arkret_wire::Error::Protocol(error.to_string()))
}

/// Classify a top-level `event_kind` against chime's Phase P2 agent
/// routing table. Returns `None` for kinds chime does not route
/// specially (the historical default: fall through to the normal
/// notification surface).
pub fn classify_agent_event_kind(event_kind: &str) -> Option<AgentEventRouting> {
    arkret::classify_agent_event_kind(event_kind)
}

/// Return `true` if `value` starts with one of the registered typed-id
/// prefixes listed in [`PHASE_P2_AGENT_TYPED_ID_PREFIXES`]. Used by
/// chime's wire-validation layer to fail closed when one of these typed
/// ids appears in a wakeup slot that should never carry an agent,
/// grant, backup, or recovery identifier (e.g. `event_id`, `circle_id`).
pub fn is_phase_p2_agent_typed_id(value: &str) -> bool {
    arkret::is_phase_p2_agent_typed_id(value)
}

/// Phase P2 — minimal, PII-free notification summary for a durable
/// agent lifecycle event. Returned by [`render_agent_lifecycle_summary`]
/// for callers that want to surface a control-plane breadcrumb without
/// reaching into the wire payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentLifecycleSummary {
    /// The matched event kind literal (`ak.self.agent.pause` /
    /// `ak.self.agent.resume` / `ak.self.agent.deactivate`). Stable wire string.
    pub event_kind: &'static str,
    /// Localisation key for the human-readable summary, e.g.
    /// `l10n_key:agent.lifecycle.pause`. Hosts SHOULD render this
    /// rather than the raw `event_kind` so end-users see translated
    /// copy. No actor identity, payload digest, or accountability
    /// grant id is embedded.
    pub l10n_key: &'static str,
}

/// Render a minimal lifecycle summary for one of the three durable
/// agent kinds. Returns `None` for any other kind. The returned summary
/// is PII-free by construction — no actor, no payload, no grant id.
pub fn render_agent_lifecycle_summary(event_kind: &str) -> Option<AgentLifecycleSummary> {
    let (kind, l10n_key) = match event_kind {
        "ak.self.agent.pause" => ("ak.self.agent.pause", "l10n_key:agent.lifecycle.pause"),
        "ak.self.agent.resume" => ("ak.self.agent.resume", "l10n_key:agent.lifecycle.resume"),
        "ak.self.agent.deactivate" => (
            "ak.self.agent.deactivate",
            "l10n_key:agent.lifecycle.deactivate",
        ),
        _ => return None,
    };
    Some(AgentLifecycleSummary {
        event_kind: kind,
        l10n_key,
    })
}

/// Phase P2 — B-B field-naming aliases removed in the candidate-stage
/// breaking pass (spec 37ce729 / SDK 4d5a1af). chime mirrors floria
/// 6496235's wire-side reject list so inbound push frames carrying any
/// of these keys fail closed at deserialisation.
pub const PHASE_P2_FORBIDDEN_FIELD_ALIASES: &[&str] =
    &["size", "strand_body", "message_body", "body_only"];

/// Return `true` if `key` is one of the forbidden B-B field-naming aliases
/// listed in [`PHASE_P2_FORBIDDEN_FIELD_ALIASES`]. Used by chime's wire
/// recognizers to fail closed at deserialisation.
pub fn is_forbidden_field_alias(key: &str) -> bool {
    PHASE_P2_FORBIDDEN_FIELD_ALIASES.contains(&key)
}

/// Recursively walk a JSON value and return `Err(field_path)` if any
/// nested key matches a forbidden B-B field-naming alias. Used by chime's
/// wire validators (`ChimePushNotifyEnvelope::validate_wire_model`) so no
/// caller can smuggle a renamed-from name past us.
pub(super) fn assert_no_forbidden_aliases(payload: &Value) -> Result<(), String> {
    fn walk(path: &str, value: &Value) -> Result<(), String> {
        match value {
            Value::Object(map) => {
                for (key, nested) in map {
                    let nested_path = if path.is_empty() {
                        key.clone()
                    } else {
                        format!("{path}.{key}")
                    };
                    if is_forbidden_field_alias(key) {
                        return Err(nested_path);
                    }
                    walk(&nested_path, nested)?;
                }
                Ok(())
            }
            Value::Array(values) => {
                for (index, nested) in values.iter().enumerate() {
                    walk(&format!("{path}[{index}]"), nested)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
    walk("", payload)
}

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
/// * In `debug_assertions` builds (typical for `cargo test` and dev builds) the function **panics**
///   with the offending field path. We want loud failures during development — a leaked governance
///   id is a privacy bug, not a recoverable user-input error.
/// * In release builds it returns `Err(field_path)` so production integrations can log and fail
///   closed without taking the process down. Returning the path (not just a bool) gives operators
///   something to grep for in incident response.
///
/// Returns `Ok(())` when the payload is clean.
//
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

#[cfg(test)]
mod fanout_tests {
    use super::*;

    const ACTIONS: [AgentFanoutAction; 5] = [
        AgentFanoutAction::ReplyMessage,
        AgentFanoutAction::ReactionAdd,
        AgentFanoutAction::ReactionRemove,
        AgentFanoutAction::ThirdPartyMention,
        AgentFanoutAction::ActOnBehalf,
    ];

    #[test]
    fn fanout_action_selector_uses_all_five_sdk_bits() {
        let all = ParticipationBits {
            reply_message: true,
            reaction_add: true,
            reaction_remove: true,
            accept_third_party_mention: true,
            act_on_behalf: true,
        };
        for action in ACTIONS {
            assert!(action_enabled(all, action));
        }
    }

    #[test]
    fn third_party_mention_is_not_inferred_from_reply_or_reaction_bits() {
        let without_mention = ParticipationBits {
            reply_message: true,
            reaction_add: true,
            reaction_remove: true,
            accept_third_party_mention: false,
            act_on_behalf: true,
        };
        assert!(!action_enabled(
            without_mention,
            AgentFanoutAction::ThirdPartyMention
        ));
    }

    #[test]
    fn unresolved_policy_evidence_denies_even_a_ready_target() {
        let target_service_id = serde_json::from_str("\"did:web:target.example\"").unwrap();
        let verifier_id = serde_json::from_str("\"did:web:verifier.example\"").unwrap();
        let audience = serde_json::from_str("\"push-fanout\"").unwrap();
        let gate = AgentFanoutGate {
            action: AgentFanoutAction::ThirdPartyMention,
            batch: None,
            receipt: None,
            immutable_provision_ceiling: None,
            deployment_ceiling: None,
            realm_ceiling: None,
            scoped_ceiling: None,
            current_admission: None,
            current_signer_evidence: None,
            target_service_id: &target_service_id,
            verifier_id: &verifier_id,
            audience: &audience,
            now: Utc::now(),
        };

        assert_eq!(
            gate.evaluate_target(Some(SidecarAccessReadiness::Ready)),
            Err(AgentFanoutDenied::EvidenceUnresolved)
        );
    }
}
