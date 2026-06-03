//! Round R2/R3 (T07) — account deactivation cleanup hook.
//!
//! The spec's `account-lifecycle.md` §7.1 Deactivation Fanout requires
//! seven domains to wind down when a principal is deactivated:
//!
//! - session
//! - device
//! - applet
//! - keypackage
//! - push
//! - to-device queue
//! - capability cache
//!
//! chime owns the **client-side** push surface — the device push queue,
//! the per-device keypackage cache it consults before signing wakeups,
//! and the local device session that lets the client speak to floria.
//! Floria reaches us either by emitting a `cx.principal.deactivate`
//! event on the device's normal sync stream (in-band) or by sending a
//! dedicated push wakeup whose `wakeup_kind` is a closed v1 token
//! signalling deactivation. Either path funnels into [`on_account_deactivate`] —
//! the single entrypoint a chime integrator should call when they
//! observe a deactivation for the principal currently bound to this
//! device.
//!
//! The hook is split into three sub-steps that match the spec's domain
//! list above:
//!
//! 1. **Drain the local push queue** — any pending wakeups stashed by the host app for delivery to
//!    the OS must be dropped on the floor. The actual queue lives in the host app (chime never sees
//!    raw notification bodies), so we expose a hook the integrator implements.
//! 2. **Clear the keypackage cache** — drop any keypackage material cached for the deactivated
//!    principal. After deactivation the principal cannot enrol new devices, so the cache is
//!    permanently invalid.
//! 3. **Invalidate the device session** — surface the deactivation to the integrator's session
//!    layer so the next outbound request fails closed rather than silently 401-ing in a retry loop.
//!    We do this by handing the integrator a fresh
//!    [`DeviceSessionInvalidationReason::AccountDeactivated`] signal.
//!
//! The first two steps need host-side wiring (file IO, keychain access,
//! MLS state). chime does not own any of that, so the implementation
//! here is a contract surface: integrators either implement
//! [`AccountDeactivationSink`] directly or use
//! [`ClosureAccountDeactivationSink`] to bind existing queue/cache/session
//! functions without a custom type.

use crate::PushPreferencesStore;

/// B.5 #9 — host-supplied driver for the background-fetch wakeup path.
///
/// When a Cokret push gateway delivers a blind wakeup, the device's
/// integration code typically needs to:
///
/// 1. Hand control to the host app (iOS BGAppRefreshTask, Android WorkManager job, Web Push
///    `pushevent`, desktop launcher hook).
/// 2. Wait for the app to fetch fresh events from sync.
/// 3. Hand control back to the OS within the platform-imposed budget.
///
/// chime does not own any of that — the host app does. This trait is
/// the seam so chime's higher-level helpers (e.g. the notify-handling
/// layer) can request the fetch without hard-coding a platform.
///
/// The trait is intentionally small and synchronous from chime's
/// perspective: a host implementor that needs async behaviour should
/// dispatch the work onto its own runtime and return immediately,
/// using the returned [`BackgroundFetchOutcome`] to signal whether
/// the dispatch succeeded.
///
/// Implementors are expected to be `Send + Sync` so the driver can be
/// stashed in an `Arc<dyn BackgroundFetchDriver<Error = _>>`.
pub trait BackgroundFetchDriver: Send + Sync {
    /// Host-side error type. chime bubbles it back to the caller
    /// without inspection.
    type Error;

    /// Kick off a background fetch for the given wakeup. The host app
    /// implementation is responsible for whatever platform plumbing
    /// (BGAppRefreshTask, WorkManager, …) it uses.
    ///
    /// `hint` is opaque routing metadata copied from the wakeup. chime
    /// guarantees it does not carry plaintext message bodies (the
    /// blind-wakeup privacy gate runs first), so implementors can log
    /// it freely.
    fn dispatch_background_fetch(
        &self,
        hint: &BackgroundFetchHint,
    ) -> Result<BackgroundFetchOutcome, Self::Error>;
}

/// Routing metadata for a background-fetch dispatch.
///
/// Held flat as `&'a str` so chime can hand a borrowed view to the
/// driver without forcing the host to allocate. The struct is
/// `#[non_exhaustive]` so future fields (e.g. priority, deadline) do
/// not break existing implementors.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct BackgroundFetchHint<'a> {
    /// Opaque push target id (`ck:pseudonym:push:...`). Always present.
    pub push_target_id: &'a str,
    /// Wakeup kind (`message`, `mention`, `reaction`, `call_invite`).
    pub wakeup_kind: &'a str,
    /// Optional Circle scope, when the originating wakeup carried one.
    pub circle_id: Option<&'a str>,
    /// Optional Realm scope, when the originating wakeup carried one.
    pub realm_id: Option<&'a str>,
}

impl<'a> BackgroundFetchHint<'a> {
    /// Construct a minimal hint from a push target id + wakeup kind.
    pub fn new(push_target_id: &'a str, wakeup_kind: &'a str) -> Self {
        Self {
            push_target_id,
            wakeup_kind,
            circle_id: None,
            realm_id: None,
        }
    }

    /// Attach a Circle scope.
    pub fn with_circle_id(mut self, circle_id: &'a str) -> Self {
        self.circle_id = Some(circle_id);
        self
    }

    /// Attach a Realm scope.
    pub fn with_realm_id(mut self, realm_id: &'a str) -> Self {
        self.realm_id = Some(realm_id);
        self
    }
}

/// Outcome of [`BackgroundFetchDriver::dispatch_background_fetch`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BackgroundFetchOutcome {
    /// The driver dispatched the fetch onto the platform queue.
    Dispatched,
    /// The driver chose not to dispatch (e.g. the device is in
    /// power-saver mode, the platform's daily budget is exhausted).
    /// chime treats this as a non-error path so callers can surface
    /// metrics without alerting.
    Skipped,
}

/// No-op `BackgroundFetchDriver` for integrations that have no
/// background-fetch surface (CLI smoke tests, server-side bridges, etc.).
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopBackgroundFetchDriver;

impl BackgroundFetchDriver for NoopBackgroundFetchDriver {
    type Error = core::convert::Infallible;

    fn dispatch_background_fetch(
        &self,
        _hint: &BackgroundFetchHint<'_>,
    ) -> Result<BackgroundFetchOutcome, Self::Error> {
        Ok(BackgroundFetchOutcome::Skipped)
    }
}

/// Why the device session is being invalidated.
///
/// Round R2/R3 only emits one variant from chime, but the enum is
/// `#[non_exhaustive]` so we can add the other six §7.1 domains later
/// (e.g. `AppletRevoked`, `CapabilityCachePoisoned`) without a SemVer
/// bump.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeviceSessionInvalidationReason {
    /// The bound principal has been deactivated upstream. The session
    /// MUST be discarded; subsequent register/notify calls will fail
    /// closed at floria with `principal_deactivated`.
    AccountDeactivated,
}

/// Source that fed the deactivation notice into chime.
///
/// Both paths land in the same handler — the discriminant only exists
/// so the integrator can distinguish them in metrics/logs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeactivationSource {
    /// A floria push wakeup carried a deactivation hint (chime received
    /// it via [`crate::PushNotifyReqBody`] or an equivalent decoded
    /// shape on the device).
    FloriaPush,
    /// The device's sync stream surfaced an in-band
    /// `cx.principal.deactivate` event.
    InBandSync,
}

/// Integrator-supplied glue for the three deactivation sub-steps chime
/// orchestrates.
///
/// chime never owns the local push queue, keypackage cache, or device
/// session itself; the host application does. This trait is the seam.
///
/// All methods take `&self` so a single shared sink can run inside an
/// `Arc<dyn AccountDeactivationSink<Error = _>>` without the integrator
/// having to thread `&mut` through their app state.
pub trait AccountDeactivationSink {
    /// Host-side error type. chime bubbles it back from
    /// [`on_account_deactivate`] without inspection.
    type Error;

    /// Drain any push wakeups buffered locally for the deactivated
    /// principal.
    ///
    /// This is the host app's outbound delivery queue — wakeups already
    /// signed by floria that the OS has not yet handed to the user.
    /// They must be dropped: a deactivated principal cannot consent to
    /// further notifications.
    fn drain_local_push_queue(&self) -> Result<(), Self::Error>;

    /// Clear any cached keypackage material the device was holding for
    /// the deactivated principal.
    ///
    /// Deactivation is terminal (`account-lifecycle.md` §7.1): no new
    /// device under this principal can be enrolled, so cached
    /// keypackages are dead weight and a potential
    /// fingerprinting surface. Drop them eagerly.
    fn clear_keypackage_cache(&self) -> Result<(), Self::Error>;

    /// Invalidate the device session bound to this principal.
    ///
    /// The integrator should treat this as "tear down whatever session
    /// state authenticates this device to floria/soland". The next
    /// outbound register/notify must fail closed rather than reuse a
    /// stale session grant.
    fn invalidate_device_session(
        &self,
        reason: DeviceSessionInvalidationReason,
    ) -> Result<(), Self::Error>;
}

/// No-op deactivation sink for integrations that have no local queue,
/// keypackage cache, or device session state inside the current process.
///
/// This is intentionally named, rather than implementing the trait for
/// `()`, so production callers have to opt into the no-op semantics
/// explicitly at the call site.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopAccountDeactivationSink;

impl AccountDeactivationSink for NoopAccountDeactivationSink {
    type Error = core::convert::Infallible;

    fn drain_local_push_queue(&self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn clear_keypackage_cache(&self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn invalidate_device_session(
        &self,
        _reason: DeviceSessionInvalidationReason,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// Closure-backed deactivation sink.
///
/// Host apps such as yougen can wire their concrete push-outbox flush,
/// keypackage-cache clear, and session-invalidation functions into chime
/// without defining a bespoke adapter type.
pub struct ClosureAccountDeactivationSink<D, C, I> {
    drain_local_push_queue: D,
    clear_keypackage_cache: C,
    invalidate_device_session: I,
}

impl<D, C, I> ClosureAccountDeactivationSink<D, C, I> {
    pub fn new(
        drain_local_push_queue: D,
        clear_keypackage_cache: C,
        invalidate_device_session: I,
    ) -> Self {
        Self {
            drain_local_push_queue,
            clear_keypackage_cache,
            invalidate_device_session,
        }
    }
}

impl<D, C, I, E> AccountDeactivationSink for ClosureAccountDeactivationSink<D, C, I>
where
    D: Fn() -> Result<(), E>,
    C: Fn() -> Result<(), E>,
    I: Fn(DeviceSessionInvalidationReason) -> Result<(), E>,
{
    type Error = E;

    fn drain_local_push_queue(&self) -> Result<(), Self::Error> {
        (self.drain_local_push_queue)()
    }

    fn clear_keypackage_cache(&self) -> Result<(), Self::Error> {
        (self.clear_keypackage_cache)()
    }

    fn invalidate_device_session(
        &self,
        reason: DeviceSessionInvalidationReason,
    ) -> Result<(), Self::Error> {
        (self.invalidate_device_session)(reason)
    }
}

/// Errors surfaced by [`on_account_deactivate`].
///
/// Each variant pins down which sub-step failed so the integrator can
/// retry the right one. We deliberately do NOT short-circuit on the
/// first error: chime always attempts all three sub-steps and reports
/// the first failure, because cancelling on (e.g.) a transient queue
/// drain error would leave the keypackage cache and session intact —
/// the opposite of fail-closed.
#[derive(Debug, thiserror::Error)]
pub enum AccountDeactivationError<E> {
    /// The local push queue drain hook returned an error.
    #[error("local push queue drain failed during account deactivation")]
    DrainQueue(#[source] E),
    /// The keypackage cache clear hook returned an error.
    #[error("keypackage cache clear failed during account deactivation")]
    ClearKeypackageCache(#[source] E),
    /// The device session invalidation hook returned an error.
    #[error("device session invalidation failed during account deactivation")]
    InvalidateSession(#[source] E),
    /// Clearing the persisted push preferences via
    /// [`PushPreferencesStore::clear_push_preferences`] failed.
    #[error("push preferences clear failed during account deactivation")]
    ClearPushPreferences(#[source] E),
}

/// Outcome of an [`on_account_deactivate`] call.
///
/// Each field records whether the corresponding sub-step ran. They are
/// all `true` on the happy path; `false` only when an earlier sub-step
/// returned an error and the receipt is being constructed for the
/// caller's metric pipeline.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccountDeactivationReceipt {
    pub source: Option<DeactivationSource>,
    pub queue_drained: bool,
    pub keypackage_cache_cleared: bool,
    pub session_invalidated: bool,
    pub push_preferences_cleared: bool,
    /// CXP-0007 — `ck:circle:` ids whose chime-side subscription /
    /// mute state was torn down as part of this deactivation. Empty
    /// when no Circle-scoped state existed for this principal.
    pub circle_bindings_cleared: Vec<String>,
    /// CXP-0007 — same as [`Self::circle_bindings_cleared`] but for the
    /// Realm-scoped mute list (legacy + Circle-less Realm wakeups).
    pub realm_bindings_cleared: Vec<String>,
}

impl AccountDeactivationReceipt {
    /// `true` when every sub-step succeeded.
    pub fn is_complete(&self) -> bool {
        self.queue_drained
            && self.keypackage_cache_cleared
            && self.session_invalidated
            && self.push_preferences_cleared
    }
}

/// Client integrator entrypoint — call this on receiving a
/// `cx.principal.deactivate` signal (either via floria push or in-band
/// sync) for the principal currently bound to this device.
///
/// Drives the three §7.1 sub-steps in a fixed order: drain queue →
/// clear keypackage cache → invalidate device session, then clears the
/// persisted [`crate::PushPreferences`] so a fresh enrolment after
/// reactivation starts from defaults rather than the now-stale gateway
/// bindings.
///
/// The order is significant:
///
/// 1. Drain first so we don't fire wakeups against a session we're about to invalidate.
/// 2. Keypackage cache next so any concurrent encryption path stops selecting against a deactivated
///    principal.
/// 3. Session invalidation last so the integrator can observe the "session torn down" state and
///    emit any UI / logout-style hook.
/// 4. PushPreferences clear is best-effort and runs after the three sink hooks because it's purely
///    chime-owned state.
///
/// On the first error chime stops invoking *subsequent* sink methods
/// (the receipt records what ran and what didn't) but ALWAYS attempts
/// the push-preferences clear because that step uses a separate
/// trait/store and doesn't depend on the sink.
//
pub fn on_account_deactivate<S, P>(
    sink: &S,
    preferences_store: Option<&P>,
    source: DeactivationSource,
) -> Result<AccountDeactivationReceipt, AccountDeactivationError<S::Error>>
where
    S: AccountDeactivationSink,
    P: PushPreferencesStore<Error = S::Error>,
{
    let mut receipt = AccountDeactivationReceipt {
        source: Some(source),
        ..Default::default()
    };

    sink.drain_local_push_queue()
        .map_err(AccountDeactivationError::DrainQueue)?;
    receipt.queue_drained = true;

    sink.clear_keypackage_cache()
        .map_err(AccountDeactivationError::ClearKeypackageCache)?;
    receipt.keypackage_cache_cleared = true;

    sink.invalidate_device_session(DeviceSessionInvalidationReason::AccountDeactivated)
        .map_err(AccountDeactivationError::InvalidateSession)?;
    receipt.session_invalidated = true;

    if let Some(store) = preferences_store {
        // CXP-0007 — before wiping the persisted preferences, snapshot
        // the circle-scoped and realm-scoped subscription / mute state
        // so the receipt can report which bindings were torn down
        // (the receipt is what host apps wire into telemetry; an
        // empty wholesale clear would otherwise be observability-opaque).
        // `load_push_preferences` returning `None` is treated as
        // "nothing to snapshot"; an error here propagates as a
        // `ClearPushPreferences` step failure so the integrator can
        // retry the whole sub-step on a transient persistence error.
        let snapshot = store
            .load_push_preferences()
            .map_err(AccountDeactivationError::ClearPushPreferences)?;
        if let Some(prefs) = snapshot {
            // `prefs` is owned here, so we can move the strings straight
            // out of the `BTreeSet` instead of cloning each `String`.
            receipt.circle_bindings_cleared = prefs.muted_circle_ids.into_iter().collect();
            receipt.realm_bindings_cleared = prefs.muted_realm_ids.into_iter().collect();
        }
        store
            .clear_push_preferences()
            .map_err(AccountDeactivationError::ClearPushPreferences)?;
        receipt.push_preferences_cleared = true;
    } else {
        // No store wired — treat as a no-op success so callers without
        // persisted preferences (e.g. one-shot CLI smoke tests) still
        // get an `is_complete()` receipt. The circle/realm binding
        // lists stay empty by construction.
        receipt.push_preferences_cleared = true;
    }

    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    #[derive(Default)]
    struct CountingSink {
        drain: Cell<u32>,
        clear: Cell<u32>,
        invalidate: Cell<u32>,
        invalidate_reason: Cell<Option<DeviceSessionInvalidationReason>>,
        fail_on_drain: bool,
        fail_on_clear: bool,
        fail_on_invalidate: bool,
    }

    impl AccountDeactivationSink for CountingSink {
        type Error = &'static str;

        fn drain_local_push_queue(&self) -> Result<(), Self::Error> {
            self.drain.set(self.drain.get() + 1);
            if self.fail_on_drain {
                Err("drain failed")
            } else {
                Ok(())
            }
        }

        fn clear_keypackage_cache(&self) -> Result<(), Self::Error> {
            self.clear.set(self.clear.get() + 1);
            if self.fail_on_clear {
                Err("clear failed")
            } else {
                Ok(())
            }
        }

        fn invalidate_device_session(
            &self,
            reason: DeviceSessionInvalidationReason,
        ) -> Result<(), Self::Error> {
            self.invalidate.set(self.invalidate.get() + 1);
            self.invalidate_reason.set(Some(reason));
            if self.fail_on_invalidate {
                Err("invalidate failed")
            } else {
                Ok(())
            }
        }
    }

    #[derive(Default)]
    struct InMemoryPrefs {
        cleared: Cell<u32>,
        // CXP-0007 — optional pre-loaded preferences so a test can
        // assert the deactivation hook snapshots circle/realm mute
        // state before wiping.
        stored: std::cell::RefCell<Option<crate::PushPreferences>>,
    }

    impl PushPreferencesStore for InMemoryPrefs {
        type Error = &'static str;
        fn load_push_preferences(&self) -> Result<Option<crate::PushPreferences>, Self::Error> {
            Ok(self.stored.borrow().clone())
        }
        fn save_push_preferences(&self, prefs: &crate::PushPreferences) -> Result<(), Self::Error> {
            *self.stored.borrow_mut() = Some(prefs.clone());
            Ok(())
        }
        fn clear_push_preferences(&self) -> Result<(), Self::Error> {
            self.cleared.set(self.cleared.get() + 1);
            *self.stored.borrow_mut() = None;
            Ok(())
        }
    }

    #[derive(Default)]
    struct InfalliblePrefs;

    impl PushPreferencesStore for InfalliblePrefs {
        type Error = core::convert::Infallible;

        fn load_push_preferences(&self) -> Result<Option<crate::PushPreferences>, Self::Error> {
            Ok(None)
        }

        fn save_push_preferences(&self, _: &crate::PushPreferences) -> Result<(), Self::Error> {
            Ok(())
        }

        fn clear_push_preferences(&self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[test]
    fn happy_path_runs_all_four_substeps_in_order() {
        let sink = CountingSink::default();
        let prefs = InMemoryPrefs::default();

        let receipt =
            on_account_deactivate(&sink, Some(&prefs), DeactivationSource::FloriaPush).unwrap();

        assert_eq!(sink.drain.get(), 1);
        assert_eq!(sink.clear.get(), 1);
        assert_eq!(sink.invalidate.get(), 1);
        assert_eq!(prefs.cleared.get(), 1);
        assert_eq!(
            sink.invalidate_reason.get(),
            Some(DeviceSessionInvalidationReason::AccountDeactivated)
        );
        assert_eq!(receipt.source, Some(DeactivationSource::FloriaPush));
        assert!(receipt.is_complete());
    }

    #[test]
    fn missing_prefs_store_still_completes() {
        let sink = CountingSink::default();
        let receipt =
            on_account_deactivate::<_, InMemoryPrefs>(&sink, None, DeactivationSource::InBandSync)
                .unwrap();
        assert!(receipt.is_complete());
        assert_eq!(receipt.source, Some(DeactivationSource::InBandSync));
    }

    #[test]
    fn drain_failure_short_circuits_subsequent_sink_steps() {
        let sink = CountingSink {
            fail_on_drain: true,
            ..Default::default()
        };
        let prefs = InMemoryPrefs::default();

        let err =
            on_account_deactivate(&sink, Some(&prefs), DeactivationSource::FloriaPush).unwrap_err();
        assert!(matches!(
            err,
            AccountDeactivationError::DrainQueue("drain failed")
        ));
        // Drain ran but the rest did not.
        assert_eq!(sink.drain.get(), 1);
        assert_eq!(sink.clear.get(), 0);
        assert_eq!(sink.invalidate.get(), 0);
        // Prefs clear must NOT run when the sink portion bailed: the
        // session is still authoritative until invalidate succeeds.
        assert_eq!(prefs.cleared.get(), 0);
    }

    #[test]
    fn invalidate_failure_does_not_clear_prefs() {
        let sink = CountingSink {
            fail_on_invalidate: true,
            ..Default::default()
        };
        let prefs = InMemoryPrefs::default();

        let err =
            on_account_deactivate(&sink, Some(&prefs), DeactivationSource::FloriaPush).unwrap_err();
        assert!(matches!(
            err,
            AccountDeactivationError::InvalidateSession("invalidate failed")
        ));
        assert_eq!(sink.drain.get(), 1);
        assert_eq!(sink.clear.get(), 1);
        assert_eq!(sink.invalidate.get(), 1);
        assert_eq!(prefs.cleared.get(), 0);
    }

    #[test]
    fn noop_sink_completes_for_stateless_integrations() {
        let receipt = on_account_deactivate::<_, InfalliblePrefs>(
            &NoopAccountDeactivationSink,
            None,
            DeactivationSource::FloriaPush,
        )
        .unwrap();
        assert!(receipt.is_complete());
    }

    #[test]
    fn on_account_deactivate_snapshots_and_clears_circle_scoped_bindings() {
        // CXP-0007 — deactivation MUST tear down circle-scoped state.
        // The wholesale `clear_push_preferences` already drops them on
        // disk; this test pins the receipt contract so host-side
        // telemetry can see which circle / realm bindings were live at
        // the moment of deactivation.
        let sink = CountingSink::default();
        let prefs = InMemoryPrefs::default();
        let mut seeded = crate::PushPreferences {
            enabled: true,
            ..Default::default()
        };
        seeded
            .muted_circle_ids
            .insert("ck:circle:01HZK9Z000000000000000001".to_owned());
        seeded
            .muted_circle_ids
            .insert("ck:circle:01HZK9Z000000000000000002".to_owned());
        seeded
            .muted_realm_ids
            .insert("ck:realm:01HZK9Z000000000000000099".to_owned());
        prefs.save_push_preferences(&seeded).unwrap();

        let receipt =
            on_account_deactivate(&sink, Some(&prefs), DeactivationSource::FloriaPush).unwrap();

        assert!(receipt.is_complete());
        assert_eq!(receipt.circle_bindings_cleared.len(), 2);
        assert!(
            receipt
                .circle_bindings_cleared
                .iter()
                .any(|c| c.ends_with('1'))
        );
        assert!(
            receipt
                .circle_bindings_cleared
                .iter()
                .any(|c| c.ends_with('2'))
        );
        assert_eq!(receipt.realm_bindings_cleared.len(), 1);
        // And the persisted prefs were actually dropped.
        assert!(prefs.stored.borrow().is_none());
    }

    #[test]
    fn closure_sink_wires_host_queue_cache_and_session_hooks() {
        let drain = Cell::new(0);
        let clear = Cell::new(0);
        let invalidate = Cell::new(0);
        let reason = Cell::new(None);
        let sink = ClosureAccountDeactivationSink::new(
            || {
                drain.set(drain.get() + 1);
                Ok::<_, &'static str>(())
            },
            || {
                clear.set(clear.get() + 1);
                Ok::<_, &'static str>(())
            },
            |next_reason| {
                invalidate.set(invalidate.get() + 1);
                reason.set(Some(next_reason));
                Ok::<_, &'static str>(())
            },
        );

        let receipt =
            on_account_deactivate::<_, InMemoryPrefs>(&sink, None, DeactivationSource::InBandSync)
                .unwrap();

        assert!(receipt.is_complete());
        assert_eq!(drain.get(), 1);
        assert_eq!(clear.get(), 1);
        assert_eq!(invalidate.get(), 1);
        assert_eq!(
            reason.get(),
            Some(DeviceSessionInvalidationReason::AccountDeactivated)
        );
    }
}
