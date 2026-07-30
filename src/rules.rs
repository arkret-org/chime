//! Client-side evaluation of actor-private push rules and DND schedules.

use arkret_models_integration::{DndSettings, PushCondition, PushRule, PushRulesConfig};
use arkret_push_policy::push_rule_core::{
    self, EventContext as PushRuleEventContext, ShouldNotify as PushRuleDecision, WatchLevel,
};
use serde_json::Value;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NotificationEvalContext {
    pub event_kind: String,
    pub notification_kind: String,
    pub realm_id: String,
    pub strand_id: Option<String>,
    pub strand_track: Option<String>,
    pub sender: Option<String>,
    pub body: Option<String>,
    pub is_e2ee: bool,
    pub local_decrypted: bool,
    pub mentions_actor: Option<bool>,
    pub assigned_to_actor: bool,
    pub schedule_target: bool,
    pub reply_to_self: bool,
    pub participating_thread_update: bool,
    pub is_direct_message: bool,
    pub member_count: Option<u32>,
    pub priority: Option<String>,
    pub priority_override: bool,
    pub watch_level: Option<WatchLevel>,
    pub realm_watch_level: Option<WatchLevel>,
    pub now_minutes: Option<u16>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum NotificationSound {
    #[default]
    None,
    Default,
    Critical,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotificationDecision {
    pub should_notify: bool,
    pub highlight: bool,
    pub sound: NotificationSound,
    pub matched_rule_id: Option<String>,
    pub actions: Vec<String>,
    pub muted_short_circuit: bool,
    pub watch_suppressed: bool,
    pub dnd_suppressed: bool,
    pub unresolved_client_evaluation: bool,
    pub blind_wakeup_required: bool,
    pub reason: String,
}

impl NotificationDecision {
    fn dont_notify(reason: impl Into<String>) -> Self {
        Self {
            should_notify: false,
            highlight: false,
            sound: NotificationSound::None,
            matched_rule_id: None,
            actions: Vec::new(),
            muted_short_circuit: false,
            watch_suppressed: false,
            dnd_suppressed: false,
            unresolved_client_evaluation: false,
            blind_wakeup_required: false,
            reason: reason.into(),
        }
    }
}

/// Why a stored `ak.push_rules` document was not accepted.
///
/// v1 defines client-side evaluation only. A document asking the server to
/// evaluate rule conditions is a registered `unsupported_feature`, which is a
/// different operational fact from a malformed document: the former means a
/// producer wrote a v-next shape, the latter means the account data is corrupt.
/// Collapsing both into `None` hid the distinction and let a rejected rule set
/// look like "no rules configured".
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PushRulesRejection {
    /// `evaluation_locus` is not `client`. Maps to wire `unsupported_feature`.
    UnsupportedFeature { reason: String },
    /// The document does not parse as an `ak.push_rules` config.
    Malformed { reason: String },
}

impl PushRulesRejection {
    /// The canonical wire error code for this rejection.
    pub fn wire_code(&self) -> &'static str {
        match self {
            Self::UnsupportedFeature { .. } => "unsupported_feature",
            Self::Malformed { .. } => "schema_violation",
        }
    }
}

/// Parse an actor-private `ak.push_rules` document.
///
/// The non-client locus check is performed on the raw document rather than by
/// inspecting the SDK deserializer's error text, so the classification does not
/// depend on an error message staying stable.
pub fn parse_push_rules(value: &Value) -> Result<PushRulesConfig, PushRulesRejection> {
    if let Some(rules) = value.get("rules").and_then(Value::as_array) {
        for rule in rules {
            let locus = rule.get("evaluation_locus").and_then(Value::as_str);
            if let Some(locus) = locus
                && locus != "client"
            {
                let rule_id = rule
                    .get("rule_id")
                    .and_then(Value::as_str)
                    .unwrap_or("<unnamed>");
                return Err(PushRulesRejection::UnsupportedFeature {
                    reason: format!(
                        "rule {rule_id} requests evaluation_locus={locus}; \
                         v1 push rules are client-evaluated only"
                    ),
                });
            }
        }
    }
    serde_json::from_value(value.clone()).map_err(|error| PushRulesRejection::Malformed {
        reason: error.to_string(),
    })
}

pub fn parse_dnd_settings(value: &Value) -> Option<DndSettings> {
    let body = value.get("dnd").cloned().unwrap_or_else(|| value.clone());
    serde_json::from_value(body).ok()
}

pub fn evaluate_notification(
    rules: Option<&PushRulesConfig>,
    dnd: Option<&DndSettings>,
    ctx: &NotificationEvalContext,
) -> NotificationDecision {
    if let Some(decision) = evaluate_watch_gate(ctx) {
        return decision;
    }

    let decision = match rules {
        Some(config) if !config.rules.is_empty() => evaluate_rule_chain(config, ctx),
        _ => default_decision(ctx),
    };
    apply_dnd(decision, dnd, ctx)
}

fn evaluate_rule_chain(
    config: &PushRulesConfig,
    ctx: &NotificationEvalContext,
) -> NotificationDecision {
    for rule in config.rules.iter().filter(|rule| rule.enabled) {
        match rule_matches(rule, ctx) {
            RuleMatch::Matched => {
                return decision_from_actions(
                    rule.actions.clone(),
                    Some(rule.rule_id.clone()),
                    "matched push rule",
                );
            }
            RuleMatch::UnresolvedClient => {
                let mut decision = NotificationDecision::dont_notify(
                    "client-side rule unresolved in E2EE context",
                );
                decision.matched_rule_id = Some(rule.rule_id.clone());
                decision.unresolved_client_evaluation = true;
                decision.blind_wakeup_required = true;
                return decision;
            }
            RuleMatch::NoMatch => {}
        }
    }
    NotificationDecision::dont_notify("no push rule matched")
}

fn default_decision(ctx: &NotificationEvalContext) -> NotificationDecision {
    let mut actions = vec!["notify".to_owned()];
    if directed_event(ctx) {
        actions.push("highlight".to_owned());
    }
    decision_from_actions(actions, None, "default notification policy")
}

fn decision_from_actions(
    actions: Vec<String>,
    matched_rule_id: Option<String>,
    reason: impl Into<String>,
) -> NotificationDecision {
    let dont_notify = actions.iter().any(|action| action == "dont_notify");
    let notify = actions.iter().any(|action| action == "notify") && !dont_notify;
    let sound = if !notify {
        NotificationSound::None
    } else if actions.iter().any(|action| action == "sound_critical") {
        NotificationSound::Critical
    } else if actions.iter().any(|action| action == "sound_default") {
        NotificationSound::Default
    } else {
        NotificationSound::None
    };
    NotificationDecision {
        should_notify: notify,
        highlight: notify && actions.iter().any(|action| action == "highlight"),
        sound,
        matched_rule_id,
        actions,
        muted_short_circuit: false,
        watch_suppressed: false,
        dnd_suppressed: false,
        unresolved_client_evaluation: false,
        blind_wakeup_required: false,
        reason: reason.into(),
    }
}

fn apply_dnd(
    mut decision: NotificationDecision,
    dnd: Option<&DndSettings>,
    ctx: &NotificationEvalContext,
) -> NotificationDecision {
    if !decision.should_notify {
        return decision;
    }
    let Some(dnd) = dnd else {
        return decision;
    };
    if !dnd.enabled || !dnd_active(dnd, ctx.now_minutes.unwrap_or_else(current_local_minute)) {
        return decision;
    }
    if ctx.priority_override
        || ctx
            .priority
            .as_deref()
            .is_some_and(|priority| matches!(priority, "critical" | "high" | "urgent"))
    {
        return decision;
    }
    if decision
        .matched_rule_id
        .as_ref()
        .is_some_and(|rule_id| dnd.exceptions.iter().any(|exception| exception == rule_id))
    {
        return decision;
    }
    decision.should_notify = false;
    decision.sound = NotificationSound::None;
    decision.dnd_suppressed = true;
    decision.reason = "suppressed by dnd schedule".to_owned();
    decision
}

fn effective_watch_level(ctx: &NotificationEvalContext) -> Option<WatchLevel> {
    ctx.watch_level.or(ctx.realm_watch_level)
}

fn evaluate_watch_gate(ctx: &NotificationEvalContext) -> Option<NotificationDecision> {
    let level = effective_watch_level(ctx)?;
    let core_ctx = PushRuleEventContext {
        mentions_actor: ctx.mentions_actor.unwrap_or(false),
        assigned_to_actor: ctx.assigned_to_actor || ctx.schedule_target,
        reply_to_self: ctx.reply_to_self,
        participating_thread_update: ctx.participating_thread_update,
        is_e2ee: ctx.is_e2ee,
        local_decrypted: ctx.local_decrypted,
    };
    let (decision, reason) = push_rule_core::evaluate_watch_level(level, &core_ctx);
    match decision {
        PushRuleDecision::Notify => None,
        PushRuleDecision::DontNotify => {
            let mut decision = if reason == push_rule_core::reason_code::MUTED {
                NotificationDecision::dont_notify("watch muted")
            } else {
                NotificationDecision::dont_notify("watch level suppressed event")
            };
            decision.watch_suppressed = true;
            decision.muted_short_circuit = reason == push_rule_core::reason_code::MUTED;
            Some(decision)
        }
        PushRuleDecision::BlindWakeup => {
            let mut decision = NotificationDecision::dont_notify(
                "client-side watch evaluation unresolved in E2EE context",
            );
            decision.unresolved_client_evaluation = true;
            decision.blind_wakeup_required = true;
            Some(decision)
        }
    }
}

fn directed_event(ctx: &NotificationEvalContext) -> bool {
    ctx.mentions_actor.unwrap_or(false) || ctx.assigned_to_actor || ctx.schedule_target
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuleMatch {
    Matched,
    NoMatch,
    UnresolvedClient,
}

fn rule_matches(rule: &PushRule, ctx: &NotificationEvalContext) -> RuleMatch {
    // `parse_push_rules` rejects every non-client locus, so `client` is the only
    // reachable value here. Keep the branch closed rather than implicitly
    // accepting an unknown locus: a rule the actor did not ask to be evaluated
    // locally must never be applied to local state.
    if rule.evaluation_locus != "client" {
        return RuleMatch::NoMatch;
    }
    if ctx.is_e2ee && !ctx.local_decrypted {
        return RuleMatch::UnresolvedClient;
    }
    let mut unresolved = false;
    for condition in &rule.conditions {
        match condition_matches(condition, ctx) {
            ConditionResult::Matched => {}
            ConditionResult::NoMatch => return RuleMatch::NoMatch,
            ConditionResult::UnresolvedClient => unresolved = true,
        }
    }
    if unresolved {
        RuleMatch::UnresolvedClient
    } else {
        RuleMatch::Matched
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConditionResult {
    Matched,
    NoMatch,
    UnresolvedClient,
}

fn condition_matches(condition: &PushCondition, ctx: &NotificationEvalContext) -> ConditionResult {
    match condition.kind.as_str() {
        "field_match" => {
            let Some(field) = condition.field.as_deref() else {
                return ConditionResult::NoMatch;
            };
            let Some(value) = context_field(ctx, field) else {
                return ConditionResult::NoMatch;
            };
            bool_result(pattern_matches(condition.pattern.as_ref(), value))
        }
        "contains_keyword" => {
            if ctx.is_e2ee && !ctx.local_decrypted {
                return ConditionResult::UnresolvedClient;
            }
            bool_result(
                ctx.body
                    .as_deref()
                    .is_some_and(|body| keyword_matches(condition.pattern.as_ref(), body)),
            )
        }
        "mentions_actor" => match ctx.mentions_actor {
            Some(value) => bool_result(value),
            None if ctx.is_e2ee && !ctx.local_decrypted => ConditionResult::UnresolvedClient,
            None => ConditionResult::NoMatch,
        },
        "is_direct_message" => bool_result(ctx.is_direct_message),
        "member_count" => member_count_matches(condition, ctx),
        "strand_track" => bool_result(
            ctx.strand_track
                .as_deref()
                .is_some_and(|track| pattern_matches(condition.pattern.as_ref(), track)),
        ),
        "watch_state" => bool_result(pattern_matches(
            condition.pattern.as_ref(),
            effective_watch_level(ctx).unwrap_or_default().as_wire(),
        )),
        _ => ConditionResult::NoMatch,
    }
}

fn bool_result(value: bool) -> ConditionResult {
    if value {
        ConditionResult::Matched
    } else {
        ConditionResult::NoMatch
    }
}

fn member_count_matches(
    condition: &PushCondition,
    ctx: &NotificationEvalContext,
) -> ConditionResult {
    let (Some(actual), Some(expected)) = (ctx.member_count.map(i64::from), condition.value) else {
        return ConditionResult::NoMatch;
    };
    bool_result(match condition.op.as_deref().unwrap_or("eq") {
        "lt" | "<" => actual < expected,
        "lte" | "<=" => actual <= expected,
        "gt" | ">" => actual > expected,
        "gte" | ">=" => actual >= expected,
        "neq" | "!=" => actual != expected,
        _ => actual == expected,
    })
}

fn context_field<'a>(ctx: &'a NotificationEvalContext, field: &str) -> Option<&'a str> {
    match field {
        "realm_id" => Some(ctx.realm_id.as_str()),
        "kind" | "event_kind" => Some(ctx.event_kind.as_str()),
        "notification_kind" => Some(ctx.notification_kind.as_str()),
        "strand_id" => ctx.strand_id.as_deref(),
        "actor_id" | "sender_actor_id" => ctx.sender.as_deref(),
        "strand_track" | "track_name" => ctx.strand_track.as_deref(),
        "priority" | "notification_priority" => ctx.priority.as_deref(),
        "watch_state" => effective_watch_level(ctx).map(WatchLevel::as_wire),
        _ => None,
    }
}

fn pattern_matches(pattern: Option<&Value>, value: &str) -> bool {
    match pattern {
        Some(Value::String(pattern)) => glob_match(pattern, value),
        Some(Value::Array(patterns)) => patterns.iter().any(|pattern| {
            pattern
                .as_str()
                .is_some_and(|pattern| glob_match(pattern, value))
        }),
        Some(Value::Bool(expected)) => value.parse::<bool>().ok() == Some(*expected),
        Some(Value::Number(expected)) => expected.to_string() == value,
        None => true,
        _ => false,
    }
}

fn keyword_matches(pattern: Option<&Value>, body: &str) -> bool {
    let body = body.to_lowercase();
    match pattern {
        Some(Value::String(pattern)) => pattern
            .split('|')
            .map(str::trim)
            .filter(|term| !term.is_empty())
            .any(|term| body.contains(&term.to_lowercase())),
        Some(Value::Array(patterns)) => patterns.iter().any(|pattern| {
            pattern
                .as_str()
                .is_some_and(|term| body.contains(&term.to_lowercase()))
        }),
        _ => false,
    }
}

fn glob_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') {
        return pattern == value;
    }
    let mut remainder = value;
    let anchored_start = !pattern.starts_with('*');
    let anchored_end = !pattern.ends_with('*');
    let parts = pattern
        .split('*')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if parts.is_empty() {
        return true;
    }
    if anchored_start {
        let Some(stripped) = remainder.strip_prefix(parts[0]) else {
            return false;
        };
        remainder = stripped;
    }
    for part in parts.iter().skip(usize::from(anchored_start)) {
        let Some(index) = remainder.find(part) else {
            return false;
        };
        remainder = &remainder[index + part.len()..];
    }
    !anchored_end || remainder.is_empty()
}

fn dnd_active(dnd: &DndSettings, minute: u16) -> bool {
    dnd.schedule.periods.iter().any(|period| {
        let (Some(start), Some(end)) = (parse_hhmm(&period.start), parse_hhmm(&period.end)) else {
            return false;
        };
        start != end
            && if start < end {
                (start..end).contains(&minute)
            } else {
                minute >= start || minute < end
            }
    })
}

fn parse_hhmm(value: &str) -> Option<u16> {
    let (hour, minute) = value.split_once(':')?;
    let (hour, minute) = (hour.parse::<u16>().ok()?, minute.parse::<u16>().ok()?);
    (hour < 24 && minute < 60).then_some(hour * 60 + minute)
}

fn current_local_minute() -> u16 {
    use chrono::Timelike;

    let now = chrono::Local::now();
    (now.hour() as u16) * 60 + now.minute() as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_matching_rule_wins() {
        let rules = parse_push_rules(&serde_json::json!({
            "rules": [
                {
                    "rule_id": "override.mute",
                    "kind": "override",
                    "enabled": true,
                    "evaluation_locus": "client",
                    "conditions": [{"kind": "field_match", "field": "realm_id", "pattern": "r1"}],
                    "actions": ["dont_notify"]
                },
                {
                    "rule_id": "underride.all",
                    "kind": "underride",
                    "enabled": true,
                    "evaluation_locus": "client",
                    "conditions": [],
                    "actions": ["notify"]
                }
            ]
        }))
        .expect("rules");
        let decision = evaluate_notification(
            Some(&rules),
            None,
            &NotificationEvalContext {
                realm_id: "r1".to_owned(),
                ..Default::default()
            },
        );
        assert!(!decision.should_notify);
        assert_eq!(decision.matched_rule_id.as_deref(), Some("override.mute"));
    }

    #[test]
    fn unresolved_e2ee_client_rule_requires_blind_wakeup() {
        let rules = parse_push_rules(&serde_json::json!({
            "rules": [{
                "rule_id": "mention",
                "kind": "underride",
                "enabled": true,
                "evaluation_locus": "client",
                "conditions": [{"kind": "mentions_actor"}],
                "actions": ["notify"]
            }]
        }))
        .expect("rules");
        let decision = evaluate_notification(
            Some(&rules),
            None,
            &NotificationEvalContext {
                is_e2ee: true,
                ..Default::default()
            },
        );
        assert!(decision.blind_wakeup_required);
        assert!(!decision.should_notify);
    }

    #[test]
    fn server_locus_user_rule_is_rejected_as_unsupported_feature() {
        let rejection = parse_push_rules(&serde_json::json!({
            "rules": [{
                "rule_id": "override.mute",
                "kind": "override",
                "enabled": true,
                "evaluation_locus": "server",
                "conditions": [{"kind": "field_match", "field": "realm_id", "pattern": "r1"}],
                "actions": ["dont_notify"]
            }]
        }))
        .expect_err("v1 must not accept a server-evaluated user push rule");
        assert_eq!(rejection.wire_code(), "unsupported_feature");
        assert!(
            matches!(rejection, PushRulesRejection::UnsupportedFeature { .. }),
            "a v-next locus is unsupported_feature, not a malformed document"
        );
    }

    #[test]
    fn malformed_rules_are_not_reported_as_unsupported_feature() {
        let rejection = parse_push_rules(&serde_json::json!({ "rules": "not-an-array" }))
            .expect_err("a non-array rules member does not parse");
        assert_eq!(rejection.wire_code(), "schema_violation");
    }

    /// The coarse server-side watch gate and user rule evaluation are separate
    /// truths. When a rule set is rejected, its outcome must not be attributed
    /// to a user rule: `matched_rule_id` stays `None` and the decision reports
    /// the built-in policy, so an operator cannot read a suppression as "the
    /// actor's rule fired".
    #[test]
    fn rejected_rules_do_not_borrow_authority_from_the_coarse_watch_gate() {
        let document = serde_json::json!({
            "rules": [{
                "rule_id": "override.mute",
                "kind": "override",
                "enabled": true,
                "evaluation_locus": "server",
                "conditions": [],
                "actions": ["dont_notify"]
            }]
        });
        assert!(parse_push_rules(&document).is_err());

        // With no accepted rule set, evaluation falls back to the built-in
        // policy rather than silently honouring the rejected server rule.
        let decision = evaluate_notification(
            None,
            None,
            &NotificationEvalContext {
                realm_id: "r1".to_owned(),
                ..Default::default()
            },
        );
        assert!(decision.should_notify, "built-in default notifies");
        assert_eq!(decision.matched_rule_id, None);
        assert_eq!(decision.reason, "default notification policy");

        // The coarse watch gate still applies on its own authority, and its
        // suppression is likewise not attributed to a user rule.
        let muted = evaluate_notification(
            None,
            None,
            &NotificationEvalContext {
                realm_id: "r1".to_owned(),
                watch_level: Some(WatchLevel::Muted),
                ..Default::default()
            },
        );
        assert!(!muted.should_notify);
        assert_eq!(muted.matched_rule_id, None);
    }
}
