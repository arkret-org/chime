//! T4.4 — Push rule core v1.
//!
//! Shared client-side evaluator for the v1 core push rules. Exposes the
//! receiver-level watch-state decision (muted / mentions_only /
//! participating / all) plus a `blind_wakeup` decision used by E2EE
//! contexts where the client cannot evaluate full payloads until after
//! decryption.
//!
//! Scope (v1 core):
//! - `muted` short-circuits to `dont_notify` (pre-engine deny rule).
//! - `mentions_only` requires `mentions_actor=true`.
//! - `participating` requires the receiver to be a participant
//!   (mentions, assignment, reply-to-self, or a participating thread
//!   update).
//! - `all` always passes the watch-level gate.
//!
//! Advanced rules (`mentions_actor` keyword matching, `flow_track`
//! filters, DND, etc.) are deferred to extensions — yougen retains a
//! richer evaluator on top of `cx.push_rules` account_data.
//!
//! This module is consumer-facing: clients call
//! [`evaluate_watch_level`] when they're offline (e.g. an iOS NSE
//! extension that already has a cached watch level + event metadata)
//! so they get the same decision a Sync Service would have made.

use serde::{Deserialize, Serialize};

/// Receiver-level watch state. Mirrors `cx.flow.watch.set`'s `level`
/// field wire encoding (snake_case JSON).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchLevel {
    /// Pre-engine deny rule. Never deliver, even for direct mentions.
    Muted,
    /// Only deliver when the receiver is explicitly mentioned.
    #[default]
    MentionsOnly,
    /// Deliver when the receiver participated in the surrounding
    /// flow / thread (mentions, assignment, reply-to-self, or a
    /// participating thread update).
    Participating,
    /// Deliver every event in the watched scope.
    All,
}

impl WatchLevel {
    /// Parse the wire form (`muted` / `mentions_only` / `participating`
    /// / `all`). Returns `None` for unknown variants so callers can
    /// fall back to their own defaults rather than silently widening.
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "muted" => Some(Self::Muted),
            "mentions_only" => Some(Self::MentionsOnly),
            "participating" => Some(Self::Participating),
            "all" => Some(Self::All),
            _ => None,
        }
    }

    /// Canonical wire string for this level.
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::Muted => "muted",
            Self::MentionsOnly => "mentions_only",
            Self::Participating => "participating",
            Self::All => "all",
        }
    }
}

/// Minimal event metadata required to make a v1-core decision. Callers
/// build this from the inbound notification payload (sync stream, push
/// hint, or local model).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EventContext {
    /// Whether the event explicitly mentions the receiver.
    pub mentions_actor: bool,
    /// Whether the event is addressed/assigned to the receiver.
    pub assigned_to_actor: bool,
    /// Whether this event replies to a thread the receiver authored.
    pub reply_to_self: bool,
    /// Whether the receiver has already participated in the
    /// surrounding flow / thread.
    pub participating_thread_update: bool,
    /// Whether the receiver should be treated as a participant (any of
    /// the per-event flags above can imply this for v1 core).
    pub is_e2ee: bool,
    /// True when the local device already decrypted the event and can
    /// make the full decision without a blind wakeup.
    pub local_decrypted: bool,
}

impl EventContext {
    pub fn directed(&self) -> bool {
        self.mentions_actor || self.assigned_to_actor
    }

    /// Did the receiver participate in any way?
    pub fn participated(&self) -> bool {
        self.directed() || self.reply_to_self || self.participating_thread_update
    }
}

/// Decision returned by [`evaluate_watch_level`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShouldNotify {
    /// Deliver a visible notification.
    Notify,
    /// Skip delivery entirely (muted / watch-level suppressed).
    DontNotify,
    /// E2EE event: client must request a blind wakeup so it can
    /// decrypt and re-evaluate locally.
    BlindWakeup,
}

impl ShouldNotify {
    pub fn delivers(self) -> bool {
        matches!(self, Self::Notify | Self::BlindWakeup)
    }

    /// True when the decision should produce a visible UI banner.
    pub fn visible(self) -> bool {
        matches!(self, Self::Notify)
    }
}

/// Stable wire reason codes returned alongside [`ShouldNotify`]. These
/// are safe to send across a Sync Service / Push Gateway boundary —
/// they describe *why the receiver does/doesn't get the message*
/// without leaking internal state (see the soland `internal_reason`
/// channel for diagnostics).
pub mod reason_code {
    /// Receiver explicitly muted the flow.
    pub const MUTED: &str = "muted";
    /// Receiver's watch level is `mentions_only` and this event is not
    /// a direct mention.
    pub const NOT_MENTIONED: &str = "not_mentioned";
    /// Receiver's watch level is `participating` and the receiver has
    /// not participated in the surrounding thread.
    pub const NOT_PARTICIPATING: &str = "not_participating";
    /// Watch level allows delivery.
    pub const WATCH_ALLOWS: &str = "watch_allows";
    /// E2EE event: client must re-evaluate after decrypting.
    pub const BLIND_WAKEUP_REQUIRED: &str = "blind_wakeup_required";
}

/// Evaluate the receiver's watch level against an event. This is the
/// v1-core decision shared by chime (client-side), soland (server-side
/// dispatch), and yougen (notification-list UI hints).
///
/// Returns the wire-safe reason code alongside the decision so callers
/// can surface a UX-friendly explanation (e.g. yougen's
/// "you're not getting notifications for this discussion" hint).
pub fn evaluate_watch_level(level: WatchLevel, ctx: &EventContext) -> (ShouldNotify, &'static str) {
    // 1) Muted is the pre-engine deny rule — short-circuits everything.
    if matches!(level, WatchLevel::Muted) {
        return (ShouldNotify::DontNotify, reason_code::MUTED);
    }

    // 2) E2EE events that can't be locally decrypted always need a
    //    blind wakeup so the client can decrypt + re-run this
    //    evaluation with the real `mentions_actor` flag.
    if ctx.is_e2ee && !ctx.local_decrypted {
        return (ShouldNotify::BlindWakeup, reason_code::BLIND_WAKEUP_REQUIRED);
    }

    // 3) Plaintext / locally-decrypted: apply watch-level filter.
    match level {
        WatchLevel::Muted => unreachable!("handled above"),
        WatchLevel::All => (ShouldNotify::Notify, reason_code::WATCH_ALLOWS),
        WatchLevel::MentionsOnly => {
            if ctx.directed() {
                (ShouldNotify::Notify, reason_code::WATCH_ALLOWS)
            } else {
                (ShouldNotify::DontNotify, reason_code::NOT_MENTIONED)
            }
        }
        WatchLevel::Participating => {
            if ctx.participated() {
                (ShouldNotify::Notify, reason_code::WATCH_ALLOWS)
            } else {
                (ShouldNotify::DontNotify, reason_code::NOT_PARTICIPATING)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> EventContext {
        EventContext::default()
    }

    #[test]
    fn watch_level_wire_roundtrip() {
        for level in [
            WatchLevel::Muted,
            WatchLevel::MentionsOnly,
            WatchLevel::Participating,
            WatchLevel::All,
        ] {
            assert_eq!(WatchLevel::from_wire(level.as_wire()), Some(level));
        }
        assert!(WatchLevel::from_wire("nope").is_none());
    }

    #[test]
    fn muted_short_circuit() {
        let (decision, reason) = evaluate_watch_level(WatchLevel::Muted, &ctx());
        assert_eq!(decision, ShouldNotify::DontNotify);
        assert_eq!(reason, reason_code::MUTED);

        // Even a direct mention is suppressed by mute.
        let mut c = ctx();
        c.mentions_actor = true;
        let (decision, reason) = evaluate_watch_level(WatchLevel::Muted, &c);
        assert_eq!(decision, ShouldNotify::DontNotify);
        assert_eq!(reason, reason_code::MUTED);
    }

    #[test]
    fn mentions_only_filters_non_mentions() {
        let (decision, reason) = evaluate_watch_level(WatchLevel::MentionsOnly, &ctx());
        assert_eq!(decision, ShouldNotify::DontNotify);
        assert_eq!(reason, reason_code::NOT_MENTIONED);

        let mut c = ctx();
        c.mentions_actor = true;
        let (decision, reason) = evaluate_watch_level(WatchLevel::MentionsOnly, &c);
        assert_eq!(decision, ShouldNotify::Notify);
        assert_eq!(reason, reason_code::WATCH_ALLOWS);

        // Assigned-to counts as directed.
        let mut c = ctx();
        c.assigned_to_actor = true;
        let (decision, _) = evaluate_watch_level(WatchLevel::MentionsOnly, &c);
        assert_eq!(decision, ShouldNotify::Notify);
    }

    #[test]
    fn participating_filters_non_participants() {
        let (decision, reason) = evaluate_watch_level(WatchLevel::Participating, &ctx());
        assert_eq!(decision, ShouldNotify::DontNotify);
        assert_eq!(reason, reason_code::NOT_PARTICIPATING);

        let mut c = ctx();
        c.reply_to_self = true;
        let (decision, reason) = evaluate_watch_level(WatchLevel::Participating, &c);
        assert_eq!(decision, ShouldNotify::Notify);
        assert_eq!(reason, reason_code::WATCH_ALLOWS);

        let mut c = ctx();
        c.participating_thread_update = true;
        let (decision, _) = evaluate_watch_level(WatchLevel::Participating, &c);
        assert_eq!(decision, ShouldNotify::Notify);
    }

    #[test]
    fn all_passes_all() {
        let (decision, reason) = evaluate_watch_level(WatchLevel::All, &ctx());
        assert_eq!(decision, ShouldNotify::Notify);
        assert_eq!(reason, reason_code::WATCH_ALLOWS);
    }

    #[test]
    fn e2ee_requires_blind_wakeup_until_decrypted() {
        let mut c = ctx();
        c.is_e2ee = true;
        c.local_decrypted = false;
        let (decision, reason) = evaluate_watch_level(WatchLevel::MentionsOnly, &c);
        assert_eq!(decision, ShouldNotify::BlindWakeup);
        assert_eq!(reason, reason_code::BLIND_WAKEUP_REQUIRED);
        assert!(decision.delivers());
        assert!(!decision.visible());

        // Once decrypted the normal filter kicks in.
        c.local_decrypted = true;
        c.mentions_actor = false;
        let (decision, _) = evaluate_watch_level(WatchLevel::MentionsOnly, &c);
        assert_eq!(decision, ShouldNotify::DontNotify);
    }

    #[test]
    fn e2ee_muted_still_short_circuits() {
        // Mute is pre-engine — never burn a wakeup for a muted flow.
        let mut c = ctx();
        c.is_e2ee = true;
        c.local_decrypted = false;
        let (decision, reason) = evaluate_watch_level(WatchLevel::Muted, &c);
        assert_eq!(decision, ShouldNotify::DontNotify);
        assert_eq!(reason, reason_code::MUTED);
    }
}
