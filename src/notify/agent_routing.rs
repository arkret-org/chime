use serde_json::Value;

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
    // Phase P2 (spec 37ce729, CKP-0008 / CKP-0009) — Personal Agent /
    // Sidecar governance identifiers. None of these may appear on a push
    // wakeup wire: they identify the controller↔agent binding state and
    // the action-approval transcript. Leaking either correlates a user
    // device with their native agent runtime endpoint.
    "accountability_grant_id",
    "controller_did",
    "agent_principal_id",
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
    /// The matched event kind literal (`ck.self.agent.pause` /
    /// `ck.self.agent.resume` / `ck.self.agent.deactivate`). Stable wire string.
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
        "ak.self.agent.pause" => ("ck.self.agent.pause", "l10n_key:agent.lifecycle.pause"),
        "ak.self.agent.resume" => ("ck.self.agent.resume", "l10n_key:agent.lifecycle.resume"),
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
