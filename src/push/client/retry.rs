use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use arkret_retry::RetryPolicy;

/// Retry configuration for `ArkretPushClient`.
///
/// Stays `Copy` + `const`-constructible so callers can stash it in static
/// config. The curve itself is [`arkret_retry::RetryPolicy`] — the push client
/// does not own a second ladder. The `disabled_kinds_mask` is a bitmask indexed
/// by [`super::super::PushErrorKind`] discriminant ordinal — see
/// [`PushRetryPolicy::with_disabled_kinds`] for ergonomic builder access.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PushRetryPolicy {
    /// Backoff curve and retry budget.
    pub retry: RetryPolicy,
    /// Bitmask of `PushErrorKind` ordinals that should *not* be
    /// retried even when `is_retryable()` would say yes. Useful when
    /// the host application wants to bypass retries for `RateLimited`
    /// to surface 429 immediately, etc.
    pub disabled_kinds_mask: u64,
}

impl PushRetryPolicy {
    pub const fn disabled() -> Self {
        Self {
            retry: RetryPolicy::none(),
            disabled_kinds_mask: 0,
        }
    }

    /// The `sync/api-conventions.md` §9 curve with a small retry budget.
    ///
    /// The delays are normative, not a client-side tuning knob: the previous
    /// 200 ms / 3 s pair breached both the 1,000 ms first-wait floor and the
    /// 60,000 ms ceiling that §9 requires.
    pub const fn conservative() -> Self {
        Self {
            retry: RetryPolicy::arkret_default().with_max_retries(2),
            disabled_kinds_mask: 0,
        }
    }

    /// Disable retries for the listed error kinds. Returns a new
    /// policy; the input slice is OR-folded into the existing mask so
    /// callers can layer this on top of `conservative()`.
    pub const fn with_disabled_kinds(mut self, kinds: &[super::super::PushErrorKind]) -> Self {
        let mut i = 0;
        while i < kinds.len() {
            self.disabled_kinds_mask |= 1u64 << kinds[i].ordinal();
            i += 1;
        }
        self
    }

    /// Whether retries are explicitly disabled for `kind`.
    pub const fn retries_disabled_for(&self, kind: super::super::PushErrorKind) -> bool {
        self.disabled_kinds_mask & (1u64 << kind.ordinal()) != 0
    }
}

impl Default for PushRetryPolicy {
    fn default() -> Self {
        Self::disabled()
    }
}

pub(super) fn retry_jitter_seed() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_nanos().min(u64::MAX as u128) as u64)
        .unwrap_or(0xC0DE_CAFE)
}

/// Per-target async sleep used by the retry/backoff loop.
///
/// Native targets dispatch to `tokio::time::sleep` (the `http` feature
/// pulls in tokio with the `time` driver). The wasm32 build has no
/// tokio runtime on the browser main thread so it dispatches through
/// `gloo_timers::future::sleep`, which is a thin wrapper over
/// `setTimeout` and works inside the wasm-bindgen-futures executor that
/// `wasm_bindgen_futures::spawn_local` provides.
#[cfg(not(target_arch = "wasm32"))]
pub(super) async fn sleep_for(delay: Duration) {
    tokio::time::sleep(delay).await;
}

#[cfg(target_arch = "wasm32")]
pub(super) async fn sleep_for(delay: Duration) {
    gloo_timers::future::sleep(delay).await;
}

/// Generate a per-request idempotency key from process-monotonic state.
///
/// Used as a fallback when the caller does not provide
/// `PushDeviceConfig::idempotency_key` and the client has no
/// `default_idempotency_key` configured. The same key is reused across retries
/// of the same logical request so the gateway can deduplicate.
pub(super) fn generate_idempotency_key() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    // This is a client-local hash-domain separator, not an Arkret protocol
    // identifier. Keep it out of the reserved `ak.*` registry namespace.
    let digest = arkret_canonical::sha256_hex_from_slices(&[
        b"org.arkret.chime.idempotency.v1",
        &nanos.to_le_bytes(),
        &counter.to_le_bytes(),
    ]);

    // Idempotency-Key is opaque to the server. The product prefix is useful
    // for diagnostics but must not look like a registered Arkret identifier.
    let mut output = String::with_capacity("chime-sdk-".len() + 32);
    output.push_str("chime-sdk-");
    output.push_str(&digest[..32]);
    output
}
