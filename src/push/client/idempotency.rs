use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

/// Generate a per-request idempotency key from process-monotonic state.
///
/// Used as a fallback when the caller does not provide
/// `PushDeviceConfig::idempotency_key`. Hosts that retry a logical request must retain and reuse
/// its key.
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
