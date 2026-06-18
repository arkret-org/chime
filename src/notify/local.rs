use super::notification::{PushNotification, WakeupKind};
use crate::push::{
    PushRuleEventContext, ShouldNotify, WatchLevel, evaluate_watch_level, push_rule_reason_code,
};

pub mod local_reason_code {
    pub const DND: &str = "dnd";
    pub const SNOOZED: &str = "snoozed";
    pub const EXPIRY_INVALIDATION: &str = "expiry_invalidation";
    pub const NO_VISIBLE_PREVIEW: &str = "no_visible_preview";
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ExpiryInvalidationBehavior {
    #[default]
    Revoke,
    ReplaceWithExpiredStub,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LocalNotificationState {
    pub visible: bool,
    pub contains_preview: bool,
}

impl LocalNotificationState {
    pub fn visible_preview() -> Self {
        Self {
            visible: true,
            contains_preview: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalNotificationPolicy {
    pub watch_level: WatchLevel,
    pub event_context: PushRuleEventContext,
    pub dnd_active: bool,
    pub snoozed: bool,
    pub expiry_invalidation_behavior: ExpiryInvalidationBehavior,
}

impl Default for LocalNotificationPolicy {
    fn default() -> Self {
        Self {
            watch_level: WatchLevel::default(),
            event_context: PushRuleEventContext::default(),
            dnd_active: false,
            snoozed: false,
            expiry_invalidation_behavior: ExpiryInvalidationBehavior::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalNotificationAction {
    Show,
    Suppress,
    BackgroundFetch,
    RevokeExisting,
    ReplaceWithExpiredStub,
    Noop,
}

impl LocalNotificationAction {
    pub fn visible(self) -> bool {
        matches!(self, Self::Show | Self::ReplaceWithExpiredStub)
    }

    pub fn mutates_existing(self) -> bool {
        matches!(self, Self::RevokeExisting | Self::ReplaceWithExpiredStub)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalNotificationDecision {
    pub action: LocalNotificationAction,
    pub reason_code: &'static str,
    pub push_rule_decision: Option<ShouldNotify>,
}

pub fn evaluate_local_notification(
    notification: &PushNotification,
    existing: LocalNotificationState,
    policy: &LocalNotificationPolicy,
) -> LocalNotificationDecision {
    if matches!(
        notification.wakeup_kind.as_ref(),
        Some(WakeupKind::ExpiryInvalidation)
    ) {
        return evaluate_expiry_invalidation(existing, policy.expiry_invalidation_behavior);
    }

    let (push_rule_decision, reason_code) =
        evaluate_watch_level(policy.watch_level, &policy.event_context);
    match push_rule_decision {
        ShouldNotify::DontNotify => LocalNotificationDecision {
            action: LocalNotificationAction::Suppress,
            reason_code,
            push_rule_decision: Some(push_rule_decision),
        },
        ShouldNotify::BlindWakeup => LocalNotificationDecision {
            action: LocalNotificationAction::BackgroundFetch,
            reason_code,
            push_rule_decision: Some(push_rule_decision),
        },
        ShouldNotify::Notify if policy.dnd_active => LocalNotificationDecision {
            action: LocalNotificationAction::Suppress,
            reason_code: local_reason_code::DND,
            push_rule_decision: Some(push_rule_decision),
        },
        ShouldNotify::Notify if policy.snoozed => LocalNotificationDecision {
            action: LocalNotificationAction::Suppress,
            reason_code: local_reason_code::SNOOZED,
            push_rule_decision: Some(push_rule_decision),
        },
        ShouldNotify::Notify => LocalNotificationDecision {
            action: LocalNotificationAction::Show,
            reason_code: push_rule_reason_code::WATCH_ALLOWS,
            push_rule_decision: Some(push_rule_decision),
        },
    }
}

fn evaluate_expiry_invalidation(
    existing: LocalNotificationState,
    behavior: ExpiryInvalidationBehavior,
) -> LocalNotificationDecision {
    if !existing.visible || !existing.contains_preview {
        return LocalNotificationDecision {
            action: LocalNotificationAction::Noop,
            reason_code: local_reason_code::NO_VISIBLE_PREVIEW,
            push_rule_decision: None,
        };
    }

    let action = match behavior {
        ExpiryInvalidationBehavior::Revoke => LocalNotificationAction::RevokeExisting,
        ExpiryInvalidationBehavior::ReplaceWithExpiredStub => {
            LocalNotificationAction::ReplaceWithExpiredStub
        }
    };
    LocalNotificationDecision {
        action,
        reason_code: local_reason_code::EXPIRY_INVALIDATION,
        push_rule_decision: None,
    }
}
