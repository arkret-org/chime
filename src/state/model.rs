//! Persistable push registration state types and lifecycle helpers.

use std::fmt::Write as _;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    GatewayBinding, PushDeviceConfig, PushPreferences, RegisterDeviceRequest,
    RegisterDeviceResponse, UnregisterDeviceRequest, redact_push_key,
};

use super::PUSH_REGISTRATION_STATE_SCHEMA_VERSION;

/// Persistable local state for a successful push registration.
///
/// Stability: `1.0`-stable. The struct is versioned with
/// `schema_version`; new fields are added with `#[serde(default)]` so
/// older persisted blobs continue to deserialize. Renaming or
/// removing a field bumps `schema_version` and requires a major
/// SemVer bump.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushRegistrationState {
    #[serde(default = "default_state_schema_version")]
    pub schema_version: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,
    pub registration_id: Option<String>,
    pub device_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    pub app_id: Option<String>,
    pub push_gateway: String,
    pub push_key_hash: String,
    pub push_key_preview: String,
    pub registered_at: Option<String>,
    pub expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_success_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<PushRegistrationLastError>,
}

/// Persistable non-secret summary of the last registration failure.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushRegistrationLastError {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub occurred_at: Option<String>,
}

/// Minimal storage abstraction for host application push preferences.
///
/// `PushPreferences` is a small JSON-serializable struct (gateway type,
/// gateway URL, allowlists, dnd flags, …) that callers will typically
/// keep next to their other application settings — a config file, a
/// keychain entry, an encrypted blob in the host app's database, etc.
/// Defining it as a trait lets `chime` consumers (yougen, soland test
/// harnesses, …) reuse the same lifecycle helpers without re-rolling
/// the file IO each time.
///
/// The default implementations are intentionally minimal: `clear` is
/// expressed as `save(PushPreferences::default())` so backends only
/// need to implement `load` + `save`. Backends that can do better
/// (true delete, atomic replace) should override.
pub trait PushPreferencesStore {
    type Error;

    /// Load the persisted preferences, or `None` when the host app has
    /// not yet stored any.
    fn load_push_preferences(&self) -> Result<Option<crate::PushPreferences>, Self::Error>;

    /// Persist the preferences, replacing any prior value.
    fn save_push_preferences(&self, prefs: &crate::PushPreferences) -> Result<(), Self::Error>;

    /// Clear the persisted preferences. Default impl writes the
    /// `PushPreferences::default()` value, which on most backends is
    /// equivalent to "disabled, no gateway URL". Backends that support
    /// true deletion should override.
    fn clear_push_preferences(&self) -> Result<(), Self::Error> {
        self.save_push_preferences(&crate::PushPreferences::default())
    }
}

/// Default TTL for [`MemoizingPushPreferencesStore`] — short enough that
/// out-of-band edits (a user toggling the setting in another app
/// instance, a sync push from soland) catch up within a minute, long
/// enough that the hot path (push-notification fan-out) does not hit
/// the inner store on every event.
pub const PUSH_PREFERENCES_CACHE_TTL: Duration = Duration::from_secs(60);

/// Snapshot of the last `load_push_preferences()` call. `value` is the
/// loaded preferences (or `None` if the store reported "not set yet");
/// `loaded_at` is the monotonic instant the snapshot was taken.
#[derive(Default)]
struct PushPreferencesCache {
    value: Option<crate::PushPreferences>,
    loaded_at: Option<Instant>,
}

/// Decorator that adds TTL-bounded in-memory memoization to any
/// [`PushPreferencesStore`].
///
/// Push fan-out hot paths can call `load_push_preferences()` once per
/// inbound event — the underlying stores are typically file IO or a
/// keychain query, both of which are slow enough to matter under load.
/// This decorator caches the last loaded value for
/// [`PUSH_PREFERENCES_CACHE_TTL`] and serves subsequent reads from a
/// `RwLock` read guard. Any `save_push_preferences` /
/// `clear_push_preferences` call invalidates the cache so the next read
/// goes through to the inner store.
///
/// The cache is intentionally process-local — it is NOT a coherence
/// layer across host-app processes. Callers that need cross-process
/// invalidation must drive it themselves (e.g. on a sync push).
pub struct MemoizingPushPreferencesStore<S> {
    inner: S,
    ttl: Duration,
    cache: RwLock<PushPreferencesCache>,
}

impl<S> MemoizingPushPreferencesStore<S> {
    /// Wrap `inner` with the default 60s TTL.
    pub fn new(inner: S) -> Self {
        Self::with_ttl(inner, PUSH_PREFERENCES_CACHE_TTL)
    }

    /// Wrap `inner` with a custom TTL. A zero TTL effectively disables
    /// memoization (every read goes through).
    pub fn with_ttl(inner: S, ttl: Duration) -> Self {
        Self {
            inner,
            ttl,
            cache: RwLock::new(PushPreferencesCache::default()),
        }
    }

    /// Drop the cached snapshot. Safe to call from any thread.
    pub fn invalidate(&self) {
        let mut guard = self.cache.write().expect("preferences cache poisoned");
        guard.value = None;
        guard.loaded_at = None;
    }

    fn fresh(snapshot: &PushPreferencesCache, ttl: Duration) -> bool {
        match snapshot.loaded_at {
            Some(at) => at.elapsed() < ttl,
            None => false,
        }
    }
}

impl<S> PushPreferencesStore for MemoizingPushPreferencesStore<S>
where
    S: PushPreferencesStore,
{
    type Error = S::Error;

    fn load_push_preferences(&self) -> Result<Option<crate::PushPreferences>, Self::Error> {
        // Fast path: read-lock and serve from cache if still fresh.
        {
            let guard = self.cache.read().expect("preferences cache poisoned");
            if Self::fresh(&guard, self.ttl) {
                return Ok(guard.value.clone());
            }
        }

        // Slow path: upgrade to write lock. We re-check freshness
        // under the write lock to absorb the race where two readers
        // simultaneously found the cache stale.
        let mut guard = self.cache.write().expect("preferences cache poisoned");
        if Self::fresh(&guard, self.ttl) {
            return Ok(guard.value.clone());
        }
        let loaded = self.inner.load_push_preferences()?;
        guard.value = loaded.clone();
        guard.loaded_at = Some(Instant::now());
        Ok(loaded)
    }

    fn save_push_preferences(&self, prefs: &crate::PushPreferences) -> Result<(), Self::Error> {
        self.inner.save_push_preferences(prefs)?;
        // Write-through: refresh the cache so the immediately-following
        // read returns the value we just wrote, without round-tripping
        // through the inner store.
        let mut guard = self.cache.write().expect("preferences cache poisoned");
        guard.value = Some(prefs.clone());
        guard.loaded_at = Some(Instant::now());
        Ok(())
    }

    fn clear_push_preferences(&self) -> Result<(), Self::Error> {
        self.inner.clear_push_preferences()?;
        self.invalidate();
        Ok(())
    }
}

/// Minimal storage abstraction for host applications.
///
/// The crate does not choose a database, keychain, or file format. Apps can
/// implement this trait over their own secure local storage.
pub trait PushRegistrationStore {
    type Error;

    fn load_push_registration(&self) -> Result<Option<PushRegistrationState>, Self::Error>;

    fn save_push_registration(&self, state: &PushRegistrationState) -> Result<(), Self::Error>;

    fn clear_push_registration(&self) -> Result<(), Self::Error>;

    fn load_push_registrations(&self) -> Result<Vec<PushRegistrationState>, Self::Error> {
        Ok(self.load_push_registration()?.into_iter().collect())
    }

    fn save_push_registrations(&self, states: &[PushRegistrationState]) -> Result<(), Self::Error> {
        if let Some(state) = states.first() {
            self.save_push_registration(state)
        } else {
            self.clear_push_registration()
        }
    }

    fn delete_push_registration(&self, state: &PushRegistrationState) -> Result<(), Self::Error> {
        let _ = state;
        self.clear_push_registration()
    }
}

fn default_state_schema_version() -> u16 {
    PUSH_REGISTRATION_STATE_SCHEMA_VERSION
}

/// Return a stable SHA-256 fingerprint for local token comparison.
pub fn hash_push_key(push_key: &str) -> String {
    let digest = Sha256::digest(push_key.as_bytes());
    let mut output = String::with_capacity("sha256:".len() + digest.len() * 2);
    output.push_str("sha256:");
    for byte in digest {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

pub fn token_rotation_required(
    existing: Option<&PushRegistrationState>,
    new_push_key: &str,
) -> bool {
    let Some(existing) = existing else {
        return true;
    };

    existing.push_key_hash != hash_push_key(new_push_key)
}

pub fn find_registration_for_device<'a>(
    states: &'a [PushRegistrationState],
    principal_id: Option<&str>,
    device_id: &str,
    app_id: Option<&str>,
) -> Option<&'a PushRegistrationState> {
    states.iter().find(|state| {
        state.principal_id.as_deref() == principal_id
            && state.device_id == device_id
            && state.app_id.as_deref() == app_id
    })
}

pub fn find_registration_by_token<'a>(
    states: &'a [PushRegistrationState],
    push_key: &str,
) -> Option<&'a PushRegistrationState> {
    let push_key_hash = hash_push_key(push_key);
    states
        .iter()
        .find(|state| state.push_key_hash == push_key_hash)
}

pub fn token_moved_to_different_device(
    states: &[PushRegistrationState],
    principal_id: Option<&str>,
    device_id: &str,
    push_key: &str,
) -> bool {
    find_registration_by_token(states, push_key).is_some_and(|state| {
        state.principal_id.as_deref() == principal_id && state.device_id != device_id
    })
}

/// Build persistable registration state after a successful register response.
///
/// ```rust
/// use chime::{
///     GatewayBinding, PushDeviceConfig, PushGatewayType, PushPreferences,
///     RegisterDeviceResponse, build_register_device_request,
///     build_registration_state,
/// };
///
/// let config = PushDeviceConfig {
///     principal_id: Some("did:web:alice.example"),
///     device_id: "did:web:alice.example#device-phone",
///     push_key: Some("fcm:token"),
///     platform: Some("android"),
///     app_id: Some("app.example.android"),
///     domestic_app_id: None,
///     registration_id: None,
///     display_name: None,
///     idempotency_key: None,
///     request_id: None,
///     proof: None,
/// };
/// let binding = GatewayBinding::new(
///     PushGatewayType::Standard,
///     "https://push.example.com/api/v1/push/notify",
/// );
/// let prefs = PushPreferences {
///     enabled: true,
///     ..Default::default()
/// };
/// let request = build_register_device_request(&config, &binding, &prefs).unwrap();
/// let mut response = RegisterDeviceResponse::default();
/// response.ok = true;
/// response.registration_id = Some("reg-1".to_owned());
/// let state = build_registration_state(&binding, &request, &response, None);
/// assert_eq!(state.registration_id.as_deref(), Some("reg-1"));
/// ```
pub fn build_registration_state(
    binding: &GatewayBinding,
    request: &RegisterDeviceRequest,
    response: &RegisterDeviceResponse,
    registered_at: Option<&str>,
) -> PushRegistrationState {
    PushRegistrationState {
        schema_version: PUSH_REGISTRATION_STATE_SCHEMA_VERSION,
        principal_id: request.principal_id.clone(),
        registration_id: response.registration_id.clone(),
        device_id: request.device_id.clone(),
        platform: request.platform.clone(),
        app_id: request.app_id.clone(),
        push_gateway: response
            .accepted_gateway
            .clone()
            .unwrap_or_else(|| binding.push_gateway.clone()),
        push_key_hash: response
            .push_key_hash
            .clone()
            .unwrap_or_else(|| hash_push_key(&request.push_key)),
        push_key_preview: response
            .push_key_preview
            .clone()
            .unwrap_or_else(|| redact_push_key(&request.push_key)),
        registered_at: registered_at.map(str::to_owned),
        expires_at: response.expires_at.clone(),
        refresh_hint: response.refresh_hint.clone(),
        last_success_at: registered_at.map(str::to_owned),
        last_error: None,
    }
}

/// Merge a successful registration state into the locally persisted set.
///
/// The new state replaces any older entry for the same logical registration
/// and removes stale duplicates that still point at the same token hash from
/// another device/app record.
pub fn merge_registration_state(
    states: &[PushRegistrationState],
    new_state: PushRegistrationState,
) -> Vec<PushRegistrationState> {
    let mut merged = states
        .iter()
        .filter(|state| {
            !state.is_same_logical_registration(&new_state)
                && state.push_key_hash != new_state.push_key_hash
        })
        .cloned()
        .collect::<Vec<_>>();
    merged.push(new_state);
    merged
}

impl PushRegistrationState {
    /// Stable key for stores that support multiple registrations per device.
    pub fn storage_key(&self) -> String {
        [
            self.principal_id.as_deref().unwrap_or("_"),
            &self.device_id,
            self.platform.as_deref().unwrap_or("_"),
            self.app_id.as_deref().unwrap_or("_"),
            &self.push_gateway,
        ]
        .join("|")
    }

    pub fn is_same_logical_registration(&self, other: &Self) -> bool {
        self.principal_id == other.principal_id
            && self.device_id == other.device_id
            && self.platform == other.platform
            && self.app_id == other.app_id
            && self.push_gateway == other.push_gateway
    }

    pub fn token_matches(&self, push_key: &str) -> bool {
        self.push_key_hash == hash_push_key(push_key)
    }

    pub fn mark_last_error(
        mut self,
        kind: impl Into<String>,
        request_id: Option<&str>,
        retry_after: Option<&str>,
        occurred_at: Option<&str>,
    ) -> Self {
        self.last_error = Some(PushRegistrationLastError {
            kind: kind.into(),
            request_id: request_id.map(str::to_owned),
            retry_after: retry_after.map(str::to_owned),
            occurred_at: occurred_at.map(str::to_owned),
        });
        self
    }
}

/// Builds an unregister request body that matches a stored registration state.
///
/// Used by repair flows to clean up state-side records that no longer match
/// the current device/token. The synthetic binding uses
/// [`PushGatewayType::Standard`](crate::PushGatewayType::Standard) as a
/// placeholder — `gateway_type` is not echoed on the wire and unregister
/// resolves `app_id` straight from the persisted state, so the choice has
/// no observable effect.
pub(super) fn build_unregister_request_for_state(
    state: &PushRegistrationState,
    config: &PushDeviceConfig<'_>,
    prefs: &PushPreferences,
) -> Result<UnregisterDeviceRequest, crate::PushRegistrationError> {
    let binding = GatewayBinding::new(crate::PushGatewayType::Standard, state.push_gateway.clone());

    let unregister_config = PushDeviceConfig {
        principal_id: state.principal_id.as_deref().or(config.principal_id),
        device_id: &state.device_id,
        push_key: None,
        platform: state.platform.as_deref().or(config.platform),
        app_id: state.app_id.as_deref(),
        domestic_app_id: None,
        registration_id: state.registration_id.as_deref(),
        display_name: None,
        idempotency_key: config.idempotency_key,
        request_id: config.request_id,
        proof: config.proof,
    };

    crate::build_unregister_device_request(&unregister_config, &binding, prefs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_register_device_request;
    use crate::state::test_fixtures::{binding, config, prefs, state_for};

    #[test]
    fn hashes_push_key_without_exposing_value() {
        let hash = hash_push_key("fcm:very-secret-token");
        assert!(hash.starts_with("sha256:"));
        assert_eq!(hash.len(), "sha256:".len() + 64);
        assert!(!hash.contains("very-secret-token"));
    }

    #[test]
    fn builds_registration_state_from_success() {
        let request =
            build_register_device_request(&config("fcm:new-token"), &binding(), &prefs()).unwrap();
        let response = RegisterDeviceResponse {
            ok: true,
            registration_id: Some("reg-new".to_owned()),
            accepted_gateway: None,
            push_key_hash: None,
            push_key_preview: None,
            expires_at: Some("2026-04-29T00:00:00Z".to_owned()),
            refresh_hint: None,
            warnings: Vec::new(),
            request_id: None,
        };

        let state = build_registration_state(
            &binding(),
            &request,
            &response,
            Some("2026-04-29T00:00:00Z"),
        );

        assert_eq!(state.schema_version, PUSH_REGISTRATION_STATE_SCHEMA_VERSION);
        assert_eq!(state.principal_id.as_deref(), Some("did:web:alice.example"));
        assert_eq!(state.platform.as_deref(), Some("android"));
        assert_eq!(state.registration_id.as_deref(), Some("reg-new"));
        assert_eq!(state.push_key_preview, "fcm:<redacted,len=9>");
        assert!(!state.push_key_hash.contains("new-token"));
        assert_eq!(
            state.last_success_at.as_deref(),
            Some("2026-04-29T00:00:00Z")
        );
        assert!(state.storage_key().contains("did:web:alice.example"));
    }

    #[test]
    fn multi_device_helpers_find_token_moves_without_exposing_token() {
        let state = state_for(
            "did:web:alice.example#device-phone",
            "fcm:moved-token",
            "reg-1",
        );
        let states = vec![state.clone()];

        assert!(
            find_registration_for_device(
                &states,
                Some("did:web:alice.example"),
                "did:web:alice.example#device-phone",
                Some("app.example.android")
            )
            .is_some()
        );
        assert!(find_registration_by_token(&states, "fcm:moved-token").is_some());
        assert!(token_moved_to_different_device(
            &states,
            Some("did:web:alice.example"),
            "did:web:alice.example#device-tablet",
            "fcm:moved-token"
        ));

        let with_error = state.mark_last_error(
            "temporarily_unavailable",
            Some("cx:request:1"),
            Some("1"),
            Some("2026-05-02T00:00:00Z"),
        );
        assert_eq!(
            with_error
                .last_error
                .as_ref()
                .map(|error| error.kind.as_str()),
            Some("temporarily_unavailable")
        );
    }

    #[test]
    fn merge_registration_state_replaces_logical_duplicates_and_token_moves() {
        let old_phone = state_for(
            "did:web:alice.example#device-phone",
            "fcm:old-phone-token",
            "reg-old-phone",
        );
        let moved_token = state_for(
            "did:web:alice.example#device-tablet",
            "fcm:new-phone-token",
            "reg-tablet",
        );
        let merged = merge_registration_state(
            &[old_phone, moved_token],
            state_for(
                "did:web:alice.example#device-phone",
                "fcm:new-phone-token",
                "reg-new-phone",
            ),
        );

        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].registration_id.as_deref(), Some("reg-new-phone"));
        assert_eq!(merged[0].device_id, "did:web:alice.example#device-phone");
    }

    /// Tiny in-memory `PushPreferencesStore` so we can lock the trait
    /// surface without bringing in test-only crates.
    struct InMemoryPrefsStore {
        inner: std::sync::Mutex<Option<crate::PushPreferences>>,
    }

    impl PushPreferencesStore for InMemoryPrefsStore {
        type Error = std::convert::Infallible;

        fn load_push_preferences(&self) -> Result<Option<crate::PushPreferences>, Self::Error> {
            Ok(self.inner.lock().unwrap().clone())
        }

        fn save_push_preferences(&self, prefs: &crate::PushPreferences) -> Result<(), Self::Error> {
            *self.inner.lock().unwrap() = Some(prefs.clone());
            Ok(())
        }
    }

    #[test]
    fn push_preferences_store_default_clear_resets_to_default() {
        let store = InMemoryPrefsStore {
            inner: std::sync::Mutex::new(None),
        };
        assert!(store.load_push_preferences().unwrap().is_none());

        let prefs = crate::PushPreferences {
            enabled: true,
            gateways: vec![crate::GatewayBinding::new(
                crate::PushGatewayType::Bugle,
                "https://push.palpo.im/api/v1/push/notify",
            )],
            ..crate::PushPreferences::default()
        };
        store.save_push_preferences(&prefs).unwrap();
        assert_eq!(
            store
                .load_push_preferences()
                .unwrap()
                .unwrap()
                .gateways
                .len(),
            1
        );

        // Default `clear` writes back the default preferences.
        store.clear_push_preferences().unwrap();
        let cleared = store.load_push_preferences().unwrap().unwrap();
        assert!(!cleared.enabled);
        assert!(cleared.gateways.is_empty());
    }

    // ── MemoizingPushPreferencesStore TTL coverage ──────────────────

    /// Counting store so we can assert how many times the inner
    /// `load_push_preferences` was actually invoked.
    struct CountingStore {
        loads: std::sync::atomic::AtomicUsize,
        inner: std::sync::Mutex<Option<crate::PushPreferences>>,
    }

    impl CountingStore {
        fn new(initial: Option<crate::PushPreferences>) -> Self {
            Self {
                loads: std::sync::atomic::AtomicUsize::new(0),
                inner: std::sync::Mutex::new(initial),
            }
        }

        fn load_count(&self) -> usize {
            self.loads.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl PushPreferencesStore for CountingStore {
        type Error = std::convert::Infallible;
        fn load_push_preferences(&self) -> Result<Option<crate::PushPreferences>, Self::Error> {
            self.loads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(self.inner.lock().unwrap().clone())
        }
        fn save_push_preferences(&self, prefs: &crate::PushPreferences) -> Result<(), Self::Error> {
            *self.inner.lock().unwrap() = Some(prefs.clone());
            Ok(())
        }
    }

    fn sample_prefs() -> crate::PushPreferences {
        crate::PushPreferences {
            enabled: true,
            gateways: vec![crate::GatewayBinding::new(
                crate::PushGatewayType::Bugle,
                "https://push.palpo.im/api/v1/push/notify",
            )],
            ..crate::PushPreferences::default()
        }
    }

    /// Within the TTL window, repeated loads must hit the cache and
    /// NOT round-trip to the inner store.
    #[test]
    fn memoizing_store_serves_cached_value_within_ttl() {
        let inner = CountingStore::new(Some(sample_prefs()));
        let memo = MemoizingPushPreferencesStore::with_ttl(inner, Duration::from_secs(60));

        let first = memo.load_push_preferences().unwrap();
        assert!(first.unwrap().enabled);
        // Three more reads in quick succession — all served from cache.
        for _ in 0..3 {
            memo.load_push_preferences().unwrap();
        }
        assert_eq!(memo.inner.load_count(), 1);

        // save_push_preferences refreshes the cache; the immediately
        // following load still does not hit the inner store.
        let mut next = sample_prefs();
        next.enabled = false;
        memo.save_push_preferences(&next).unwrap();
        let after_save = memo.load_push_preferences().unwrap().unwrap();
        assert!(!after_save.enabled);
        assert_eq!(
            memo.inner.load_count(),
            1,
            "save must write-through, not re-load"
        );
    }

    /// A zero TTL effectively disables memoization: every load goes
    /// through to the inner store. (We use this to assert the
    /// stale-cache code path is hit deterministically without sleeping.)
    #[test]
    fn memoizing_store_zero_ttl_disables_caching() {
        let inner = CountingStore::new(Some(sample_prefs()));
        let memo = MemoizingPushPreferencesStore::with_ttl(inner, Duration::from_secs(0));

        memo.load_push_preferences().unwrap();
        memo.load_push_preferences().unwrap();
        memo.load_push_preferences().unwrap();
        // Loaded at least 3 times — every read past TTL re-acquires.
        assert!(
            memo.inner.load_count() >= 3,
            "got {}",
            memo.inner.load_count()
        );
    }

    /// `clear_push_preferences` invalidates the cache so the next read
    /// reflects the cleared inner store.
    #[test]
    fn memoizing_store_clear_invalidates_cache_and_picks_up_external_writes() {
        let inner = CountingStore::new(Some(sample_prefs()));
        let memo = MemoizingPushPreferencesStore::new(inner);

        // Prime the cache.
        assert!(memo.load_push_preferences().unwrap().is_some());
        let baseline = memo.inner.load_count();
        assert_eq!(baseline, 1);

        // Clear → the inner store gets reset AND the cache is dropped.
        memo.clear_push_preferences().unwrap();
        let after_clear = memo.load_push_preferences().unwrap();
        // Default prefs round-trip through the inner store: enabled=false.
        assert!(!after_clear.unwrap().enabled);
        assert!(memo.inner.load_count() > baseline);

        // Bypass the decorator and tamper with the inner store directly;
        // the memoized read must still serve the cached value until the
        // cache is explicitly invalidated.
        let baseline2 = memo.inner.load_count();
        *memo.inner.inner.lock().unwrap() = Some(sample_prefs());
        let still_cached = memo.load_push_preferences().unwrap().unwrap();
        assert!(!still_cached.enabled, "cached value must win within TTL");
        assert_eq!(memo.inner.load_count(), baseline2);

        // After explicit invalidate, the tampered value is observed.
        memo.invalidate();
        let after_invalidate = memo.load_push_preferences().unwrap().unwrap();
        assert!(after_invalidate.enabled);
        assert_eq!(memo.inner.load_count(), baseline2 + 1);
    }
}
