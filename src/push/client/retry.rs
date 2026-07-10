use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use sha2::{Digest, Sha256};

/// Retry configuration for `ArkretPushClient`.
///
/// Stability: `1.0`-stable. Stays `Copy` + `const`-constructible so
/// callers can stash it in static config. The `disabled_kinds_mask`
/// is a bitmask indexed by [`super::super::PushErrorKind`] discriminant ordinal —
/// see [`PushRetryPolicy::with_disabled_kinds`] for ergonomic builder
/// access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PushRetryPolicy {
    pub max_retries: u32,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    pub jitter: Duration,
    /// Bitmask of `PushErrorKind` ordinals that should *not* be
    /// retried even when `is_retryable()` would say yes. Useful when
    /// the host application wants to bypass retries for `RateLimited`
    /// to surface 429 immediately, etc.
    pub disabled_kinds_mask: u64,
}

impl PushRetryPolicy {
    pub const fn disabled() -> Self {
        Self {
            max_retries: 0,
            initial_backoff: Duration::from_millis(0),
            max_backoff: Duration::from_millis(0),
            jitter: Duration::from_millis(0),
            disabled_kinds_mask: 0,
        }
    }

    pub const fn conservative() -> Self {
        Self {
            max_retries: 2,
            initial_backoff: Duration::from_millis(200),
            max_backoff: Duration::from_secs(3),
            jitter: Duration::from_millis(100),
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
    let mut hasher = Sha256::new();
    hasher.update(b"ak.idempotency-v1");
    hasher.update(nanos.to_le_bytes());
    hasher.update(counter.to_le_bytes());
    let digest = hasher.finalize();

    use std::fmt::Write as _;
    let mut output = String::with_capacity("ak.sdk-".len() + 32);
    output.push_str("ak.sdk-");
    for byte in &digest[..16] {
        let _ = write!(output, "{byte:02x}");
    }
    output
}
