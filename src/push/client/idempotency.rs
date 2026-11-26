/// Mint an opaque key when the caller has not supplied one. Retries of the
/// same logical request must retain the original key.
pub(super) fn generate_idempotency_key() -> String {
    let unix_ms = u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or_default();
    format!("chime-sdk-{}", arkret_wire::uuid_v7_at(unix_ms).simple())
}
