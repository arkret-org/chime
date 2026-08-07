use arkret::{
    AgentAuthorizationStatus, AgentLifecycleStatus, AgentParticipationEntry,
    AgentSidecarAccessReadiness, AgentSignerEvidence, ControllerAccountEligibility,
    ControllerAccountStatus, Did, Hash, NonEmptyString, ParticipationBits, ParticipationScope,
    ProtocolOperationId,
};
use chrono::{DateTime, Utc};
use serde_json::Value;
use thiserror::Error;

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
/// This is an evaluation selector, not a wire model. The selection and current
/// target policy remain canonical SDK types.
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
    #[error("required Agent fanout state is unresolved")]
    EvidenceUnresolved,
    #[error("the current participation entry does not bind the exact target scope")]
    ScopeMismatch,
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
    pub agent_id: &'a Did,
    pub target_scope: &'a ParticipationScope,
    pub participation: Option<&'a AgentParticipationEntry>,
    /// Effective current target policy after the deployment/Realm/scope policy
    /// chain has been resolved by the authority.
    pub current_target_policy: Option<ParticipationBits>,
    pub current_signer_evidence: Option<&'a AgentSignerEvidence>,
    /// Exact operation whose request is being admitted for fanout.
    pub operation_id: &'a ProtocolOperationId,
    /// Digest of the exact request currently being admitted.
    pub request_digest: &'a Hash,
    pub verifier_id: &'a Did,
    pub audience: &'a Did,
    /// One-time verifier challenge issued for this admission.
    pub challenge: &'a NonEmptyString,
    pub now: DateTime<Utc>,
}

impl AgentFanoutGate<'_> {
    /// Evaluate one concrete target/device intersection.
    ///
    /// Call this at message-event fanout time. A later participation change
    /// must not retroactively create or remove an already-derived notification.
    pub fn evaluate_target(
        &self,
        readiness: Option<AgentSidecarAccessReadiness>,
    ) -> Result<(), AgentFanoutDenied> {
        let participation = self
            .participation
            .ok_or(AgentFanoutDenied::EvidenceUnresolved)?;
        let current_target_policy = self
            .current_target_policy
            .ok_or(AgentFanoutDenied::EvidenceUnresolved)?;
        let signer_evidence = self
            .current_signer_evidence
            .ok_or(AgentFanoutDenied::EvidenceUnresolved)?;

        if participation.version == 0 || &participation.scope != self.target_scope {
            return Err(AgentFanoutDenied::ScopeMismatch);
        }
        self.validate_current_admission(self.agent_id, signer_evidence)?;

        let effective = participation.selection.intersect(current_target_policy);
        if !action_enabled(effective, self.action) {
            return Err(AgentFanoutDenied::ActionDisabled);
        }
        if readiness != Some(AgentSidecarAccessReadiness::Ready) {
            return Err(AgentFanoutDenied::TargetNotReady);
        }
        Ok(())
    }

    fn validate_current_admission(
        &self,
        agent_id: &Did,
        signer_evidence: &AgentSignerEvidence,
    ) -> Result<(), AgentFanoutDenied> {
        let AgentSignerEvidence::CurrentAdmission {
            schema,
            admission_evidence,
            current_observation,
            outer_attestation,
            ..
        } = signer_evidence
        else {
            // A historical destination receipt proves an earlier admission; it
            // can never authorize a new fanout operation.
            return Err(AgentFanoutDenied::CurrentAdmissionInvalid);
        };

        let snapshot = &admission_evidence.agent_authority_snapshot;
        let core = &snapshot.core;
        let binding = &core.signing_key_binding;
        let authorization = &core.authorization;
        let key_witness = &core.key_state_witness;
        let lifecycle = &core.agent_lifecycle_witness;
        let account_gate = &admission_evidence.controller_account_gate_attestation;

        let snapshot_digest = canonical_digest(&snapshot.core)
            .map_err(|_| AgentFanoutDenied::CurrentAdmissionInvalid)?;
        let account_gate_digest = canonical_digest(account_gate)
            .map_err(|_| AgentFanoutDenied::CurrentAdmissionInvalid)?;
        let admission_evidence_digest = canonical_digest(&serde_json::json!({
            "agent_authority_snapshot": snapshot,
            "controller_account_gate_attestation": account_gate,
        }))
        .map_err(|_| AgentFanoutDenied::CurrentAdmissionInvalid)?;
        let outer_core_digest = evidence_core_digest(signer_evidence)
            .map_err(|_| AgentFanoutDenied::CurrentAdmissionInvalid)?;

        if schema.as_str() != "ak.schema.agent_signer_evidence.v1"
            || admission_evidence.admission_evidence_digest != admission_evidence_digest
            || snapshot.snapshot_digest != snapshot_digest
            || snapshot.lease.snapshot_digest != snapshot.snapshot_digest
            || snapshot.lease.authority_service_id != core.authority_service_id
            || snapshot.lease.authority_kind.as_str() != "agent_authority"
            || outer_attestation.domain.as_str() != "ak.agent-signer-evidence.v1"
            || outer_attestation.core_digest != outer_core_digest
            || outer_attestation.source_service_id != core.authority_service_id
            || binding.agent_id != *agent_id
            || binding.agent_key_authorize_event_id != authorization.authorized_event_id
            || authorization.status != AgentAuthorizationStatus::Active
            || authorization.transition_event_id.is_some()
            || authorization.transition_seal_id.is_some()
            || key_witness.component.as_str() != "ak.component.agent.key.v1"
            || key_witness.agent_id != *agent_id
            || key_witness.authorization_event_id != authorization.authorized_event_id
            || key_witness.seal_id != authorization.accepted_seal_id
            || lifecycle.component.as_str() != "ak.component.agent.status.v1"
            || lifecycle.agent_id != *agent_id
            || lifecycle.controller_id != binding.controller_id
            || lifecycle.status != AgentLifecycleStatus::Active
            || lifecycle.cell_value != AgentLifecycleStatus::Active
            || account_gate.schema.as_str() != "ak.schema.controller_account_gate_attestation.v1"
            || account_gate.principal_id != binding.controller_id
            || account_gate.eligibility != ControllerAccountEligibility::Active
            || account_gate.status != ControllerAccountStatus::Active
            || current_observation.operation_id != *self.operation_id
            || current_observation.request_digest != *self.request_digest
            || current_observation.verifier_id != *self.verifier_id
            || current_observation.audience != *self.audience
            || current_observation.challenge != *self.challenge
            || !(16..=512).contains(&current_observation.challenge.as_str().chars().count())
            || current_observation.agent_snapshot_digest != snapshot.snapshot_digest
            || current_observation.agent_key_seal_id != key_witness.seal_id
            || current_observation.agent_status_seal_id != lifecycle.seal_id
            || current_observation.controller_gate_attestation_digest != account_gate_digest
            || authorization.accepted_at > self.now
            || authorization.not_before > self.now
            || authorization
                .expires_at
                .is_some_and(|expires_at| expires_at <= self.now)
            || binding.issued_at > self.now
            || binding
                .expires_at
                .is_some_and(|expires_at| expires_at <= self.now)
            || snapshot.lease.issued_at > self.now
            || snapshot.lease.expires_at <= self.now
            || account_gate.issued_at > self.now
            || account_gate.expires_at <= self.now
            || current_observation.evaluated_at > self.now
            || current_observation.expires_at <= self.now
            || outer_attestation.issued_at > self.now
            || outer_attestation.expires_at <= self.now
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

/// Digest the complete tagged evidence object with only
/// `outer_attestation` omitted, as required by the Spec transcript.
fn evidence_core_digest(evidence: &AgentSignerEvidence) -> arkret_wire::Result<Hash> {
    let mut value = serde_json::to_value(evidence)
        .map_err(|error| arkret_wire::Error::Protocol(error.to_string()))?;
    let object = value.as_object_mut().ok_or_else(|| {
        arkret_wire::Error::Protocol("Agent signer evidence must serialize as an object".to_owned())
    })?;
    object.remove("outer_attestation").ok_or_else(|| {
        arkret_wire::Error::Protocol("Agent signer evidence lacks outer_attestation".to_owned())
    })?;
    canonical_digest(&value)
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
        let agent_id = serde_json::from_str("\"did:web:agent.example\"").unwrap();
        let realm_id =
            serde_json::from_str("\"ak:realm:AR5_BcY29XYrMbX0Y8Qiz4KDnt-NvwrXmij2C3-4UD2c\"")
                .unwrap();
        let target_scope = ParticipationScope::Realm { realm_id };
        let verifier_id = serde_json::from_str("\"did:web:verifier.example\"").unwrap();
        let audience = serde_json::from_str("\"did:web:push-audience.example\"").unwrap();
        let operation_id =
            serde_json::from_str("\"ak:operation:edge.push.command.notify\"").unwrap();
        let request_digest = serde_json::from_str(
            "\"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"",
        )
        .unwrap();
        let challenge = serde_json::from_str("\"0123456789abcdef\"").unwrap();
        let gate = AgentFanoutGate {
            action: AgentFanoutAction::ThirdPartyMention,
            agent_id: &agent_id,
            target_scope: &target_scope,
            participation: None,
            current_target_policy: None,
            current_signer_evidence: None,
            operation_id: &operation_id,
            request_digest: &request_digest,
            verifier_id: &verifier_id,
            audience: &audience,
            challenge: &challenge,
            now: Utc::now(),
        };

        assert_eq!(
            gate.evaluate_target(Some(AgentSidecarAccessReadiness::Ready)),
            Err(AgentFanoutDenied::EvidenceUnresolved)
        );
    }
}
