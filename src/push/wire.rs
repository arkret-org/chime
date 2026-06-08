//! Wire DTOs for `ck.edge.push.register_device` / `ck.edge.push.unregister_device`.
//!
//! ## Stability
//!
//! The local `1.0.0` wire shape evolves additively. The SDK leans on
//! `#[non_exhaustive]` + `#[derive(Default)]` for request/response types so
//! adding optional fields never breaks downstream construction. Use
//! `..Default::default()` when building these types in external crates.
//! Renames and removals require a major SemVer bump.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::errors::PushRegistrationError;
use super::urls::{redact_push_key, redact_url};

/// A.5 #5 — HMAC-SHA256 over the push token, keyed by the device id.
///
/// The output is hex-encoded so it travels through `serde_json` as a
/// plain ASCII string without base64 alphabet ambiguity. This binding is
/// stamped into [`PushRegisterDeviceRequestBody::push_key_hmac`] so the floria /
/// soland verifier can reject a tampered payload where an attacker swapped
/// the `push_key` field for one of their own tokens but left the rest of
/// the signed envelope intact.
///
/// We deliberately implement HMAC-SHA256 inline rather than pulling in
/// the `hmac` crate: the algorithm is one page of code, and chime's
/// transitive dep graph is already on `sha2 = 0.10`. Constants follow
/// RFC 2104 — `ipad = 0x36`, `opad = 0x5C`, block size 64 bytes for
/// SHA-256.
pub fn compute_push_key_hmac(push_key: &str, device_id: &str) -> String {
    let mac = hmac_sha256(device_id.as_bytes(), push_key.as_bytes());
    let mut out = String::with_capacity(mac.len() * 2);
    use std::fmt::Write as _;
    for byte in mac {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// A.5 #5 — verify the encryption binding between a push token and a
/// device id.
///
/// Returns `true` only when [`compute_push_key_hmac`] over `push_key` and
/// `device_id` matches `expected` byte-for-byte. The comparison is
/// constant-time so a timing side-channel doesn't leak which bytes
/// matched.
///
/// Callers should treat a `false` result as fatal — it means the
/// persisted state has been tampered with, the registration request has
/// been man-in-the-middled, or the verifier is reading state across an
/// incompatible device id boundary. Either way the registration MUST be
/// rebuilt from scratch rather than retried with the old material.
pub fn verify_push_key_binding(push_key: &str, device_id: &str, expected: &str) -> bool {
    let expected = expected.as_bytes();
    let computed = compute_push_key_hmac(push_key, device_id);
    let computed = computed.as_bytes();
    if expected.len() != computed.len() {
        return false;
    }
    // Constant-time byte comparison.
    let mut diff: u8 = 0;
    for (a, b) in expected.iter().zip(computed.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;
    const IPAD: u8 = 0x36;
    const OPAD: u8 = 0x5c;

    // Normalise the key to BLOCK_SIZE bytes.
    let mut block_key = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let digest = Sha256::digest(key);
        block_key[..32].copy_from_slice(&digest);
    } else {
        block_key[..key.len()].copy_from_slice(key);
    }

    let mut inner_key = [0u8; BLOCK_SIZE];
    let mut outer_key = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        inner_key[i] = block_key[i] ^ IPAD;
        outer_key[i] = block_key[i] ^ OPAD;
    }

    // Inner hash: SHA256(inner_key || message)
    let mut inner = Sha256::new();
    inner.update(inner_key);
    inner.update(message);
    let inner_digest = inner.finalize();

    // Outer hash: SHA256(outer_key || inner_digest)
    let mut outer = Sha256::new();
    outer.update(outer_key);
    outer.update(inner_digest);
    outer.finalize().into()
}

/// Supported Cokret push platform values.
///
/// Stability: `1.0`-stable. New variants are additive; renaming or
/// removing a variant requires a major SemVer bump.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PushPlatform {
    Android,
    Ios,
    Web,
    Desktop,
}

impl PushPlatform {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Android => "android",
            Self::Ios => "ios",
            Self::Web => "web",
            Self::Desktop => "desktop",
        }
    }
}

impl TryFrom<&str> for PushPlatform {
    type Error = PushRegistrationError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.to_ascii_lowercase().as_str() {
            "android" => Ok(Self::Android),
            "ios" => Ok(Self::Ios),
            "web" => Ok(Self::Web),
            "desktop" => Ok(Self::Desktop),
            other => Err(PushRegistrationError::InvalidPlatform(other.to_owned())),
        }
    }
}

/// Device configuration supplied by the host app.
///
/// Stability: `1.0`-stable. The struct is borrowed (every field is
/// `Option<&'a str>` or `&'a str`) so adding a new optional field is
/// always source-compatible. Renaming or removing fields requires a
/// major SemVer bump.
#[derive(Clone, Copy)]
pub struct PushDeviceConfig<'a> {
    /// Cokret principal ID that owns this device registration.
    pub principal_id: Option<&'a str>,
    /// Cokret device id, usually a DID fragment such as
    /// `did:web:alice.example#device-phone`.
    pub device_id: &'a str,
    /// Platform push token, e.g. `fcm:...`, `apns:...`, `webpush:...`.
    pub push_key: Option<&'a str>,
    /// Optional platform value: `android`, `ios`, `web`, or `desktop`.
    pub platform: Option<&'a str>,
    /// Application package name, bundle id, web app id, or desktop app id.
    pub app_id: Option<&'a str>,
    /// Domestic Android app id used when `PushGatewayType::Bugle` is selected.
    pub domestic_app_id: Option<&'a str>,
    /// Server-assigned registration id, when known.
    pub registration_id: Option<&'a str>,
    /// User-readable device name.
    pub display_name: Option<&'a str>,
    /// Idempotency key sent both as request metadata and, for services that
    /// persist it, as an optional request body field.
    pub idempotency_key: Option<&'a str>,
    /// Request id sent as `X-Cokret-Request-Id`.
    pub request_id: Option<&'a str>,
    /// Optional caller-supplied DID proof or canonical proof body.
    ///
    /// `chime` does not sign this proof; it only carries the already-built
    /// proof through the wire model.
    pub proof: Option<&'a Value>,
}

impl fmt::Debug for PushDeviceConfig<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PushDeviceConfig")
            .field("principal_id", &self.principal_id)
            .field("device_id", &self.device_id)
            .field("push_key", &self.push_key.map(redact_push_key))
            .field("platform", &self.platform)
            .field("app_id", &self.app_id)
            .field("domestic_app_id", &self.domestic_app_id)
            .field("registration_id", &self.registration_id)
            .field("display_name", &self.display_name)
            .field("idempotency_key", &self.idempotency_key)
            .field("request_id", &self.request_id)
            .field("proof", &self.proof.map(|_| "<present>"))
            .finish()
    }
}

/// Request body for `POST /_cokret/edge/push/register-device`.
///
/// Stability: 1.0-stable + `#[non_exhaustive]`. Build via
/// `PushRegisterDeviceRequestBody { ..Default::default() }` from external crates so
/// future field additions stay source-compatible.
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PushRegisterDeviceRequestBody {
    pub operation_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,
    pub device_id: String,
    pub push_gateway: String,
    pub push_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// SHA-256 fingerprint of the previously registered push token, set by
    /// token-rotation flows so the gateway can correlate the new registration
    /// with the old one and reclaim it server-side.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_token_hash: Option<String>,
    /// A.5 #5 — HMAC-SHA256(`push_key`, key=`device_id`), hex-encoded.
    ///
    /// Binds the push token to the device id so an attacker that
    /// intercepts the wire envelope cannot swap the `push_key` field
    /// for one of their own tokens. Floria/soland verifiers
    /// recompute the HMAC from the signed payload's `push_key` +
    /// `device_id` and reject mismatches. See
    /// [`compute_push_key_hmac`] for the production helper and
    /// [`verify_push_key_binding`] for the verifier-side check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_key_hmac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Value>,
}

impl fmt::Debug for PushRegisterDeviceRequestBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PushRegisterDeviceRequestBody")
            .field("operation_id", &self.operation_id)
            .field("principal_id", &self.principal_id)
            .field("device_id", &self.device_id)
            .field("push_gateway", &redact_url(&self.push_gateway))
            .field("push_key", &redact_push_key(&self.push_key))
            .field("platform", &self.platform)
            .field("app_id", &self.app_id)
            .field("display_name", &self.display_name)
            .field("idempotency_key", &self.idempotency_key)
            .field("request_id", &self.request_id)
            .field("previous_token_hash", &self.previous_token_hash)
            .field("push_key_hmac", &self.push_key_hmac)
            .field("proof", &self.proof.as_ref().map(|_| "<present>"))
            .finish()
    }
}

/// Response body for `POST /_cokret/edge/push/register-device`.
///
/// Stability: 1.0-stable. New optional fields may be added in a minor release.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PushRegisterDeviceOutcome {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted_gateway: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_key_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_key_preview: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

/// Request body for `POST /_cokret/edge/push/unregister-device`.
///
/// Stability: 1.0-stable + `#[non_exhaustive]`. Build via
/// `PushUnregisterDeviceRequestBody { ..Default::default() }` from external crates.
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PushUnregisterDeviceRequestBody {
    pub operation_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,
    pub device_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_gateway: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_key_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_key_preview: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Value>,
}

impl fmt::Debug for PushUnregisterDeviceRequestBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PushUnregisterDeviceRequestBody")
            .field("operation_id", &self.operation_id)
            .field("principal_id", &self.principal_id)
            .field("device_id", &self.device_id)
            .field("registration_id", &self.registration_id)
            .field(
                "push_gateway",
                &self.push_gateway.as_deref().map(redact_url),
            )
            .field("push_key", &self.push_key.as_deref().map(redact_push_key))
            .field("push_key_hash", &self.push_key_hash)
            .field("push_key_preview", &self.push_key_preview)
            .field("app_id", &self.app_id)
            .field("idempotency_key", &self.idempotency_key)
            .field("request_id", &self.request_id)
            .field("proof", &self.proof.as_ref().map(|_| "<present>"))
            .finish()
    }
}

/// Response body for `POST /_cokret/edge/push/unregister-device`.
///
/// Stability: 1.0-stable. New optional fields may be added in a minor release.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PushUnregisterDeviceOutcome {
    pub ok: bool,
    #[serde(default)]
    pub already_removed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub removed_registration_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

/// B.5 #8 — request body for `POST /_cokret/edge/push/unsubscribe`.
///
/// Mutes a Circle / Realm / Flow at the gateway so chime does NOT have
/// to receive (and silently drop) wakeups for it. The previous design
/// kept the mute list purely client-side in
/// [`crate::PushPreferences::muted_circle_ids`] and
/// [`crate::PushPreferences::muted_realm_ids`], which meant every muted
/// scope still woke the device. The unsubscribe API tells the gateway
/// to stop emitting wakeups for the target altogether.
///
/// Stability: 1.0-stable + `#[non_exhaustive]`. Use
/// [`Self::for_circle`], [`Self::for_realm`], [`Self::for_flow`] to
/// build canonical requests; future scopes (e.g. per-app) will be
/// added as new constructors without bumping SemVer.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PushUnsubscribeRequestBody {
    pub operation_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,
    pub device_id: String,
    /// Typed reference to the scope being unsubscribed from
    /// (`ck:circle:...`, `ck:realm:...`, or `ck:flow:...`). The
    /// gateway echoes this back in the `target_id` of the response and
    /// matches it against the registration set when picking who to
    /// remove.
    pub target_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

impl PushUnsubscribeRequestBody {
    /// Construct an unsubscribe request for a Circle.
    pub fn for_circle(
        device_id: impl Into<String>,
        circle_id: impl Into<String>,
    ) -> Result<Self, PushRegistrationError> {
        Self::new(device_id, "ck:circle:", circle_id)
    }

    /// Construct an unsubscribe request for a Realm.
    pub fn for_realm(
        device_id: impl Into<String>,
        realm_id: impl Into<String>,
    ) -> Result<Self, PushRegistrationError> {
        Self::new(device_id, "ck:realm:", realm_id)
    }

    /// Construct an unsubscribe request for a Flow.
    pub fn for_flow(
        device_id: impl Into<String>,
        flow_id: impl Into<String>,
    ) -> Result<Self, PushRegistrationError> {
        Self::new(device_id, "ck:flow:", flow_id)
    }

    fn new(
        device_id: impl Into<String>,
        prefix: &str,
        target_id: impl Into<String>,
    ) -> Result<Self, PushRegistrationError> {
        let device_id = device_id.into();
        let target_id = target_id.into();
        if device_id.trim().is_empty() {
            return Err(PushRegistrationError::MissingField("device_id"));
        }
        if !target_id.starts_with(prefix) {
            return Err(PushRegistrationError::MissingField("target_id"));
        }
        Ok(Self {
            operation_id: crate::OPERATION_PUSH_UNSUBSCRIBE.to_owned(),
            principal_id: None,
            device_id,
            target_id,
            idempotency_key: None,
            request_id: None,
        })
    }

    /// Attach a principal ID. The gateway uses this to scope the
    /// unsubscribe to a specific actor when a device hosts multiple
    /// principals (e.g. shared family device).
    pub fn with_principal_id(mut self, principal_id: impl Into<String>) -> Self {
        self.principal_id = Some(principal_id.into());
        self
    }

    /// Attach an explicit idempotency key.
    pub fn with_idempotency_key(mut self, idempotency_key: impl Into<String>) -> Self {
        self.idempotency_key = Some(idempotency_key.into());
        self
    }

    /// Attach an explicit request id.
    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }
}

/// Response body for `POST /_cokret/edge/push/unsubscribe`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PushUnsubscribeOutcome {
    pub ok: bool,
    #[serde(default)]
    pub already_unsubscribed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

/// Cokret standard error object.
///
/// Stability: 1.0-stable + `#[non_exhaustive]`. Server-controlled shape.
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CokretError {
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

impl fmt::Debug for CokretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CokretError")
            .field("code", &self.code)
            .field("message", &"<redacted>")
            .field("retry_after_ms", &self.retry_after_ms)
            .field("details_present", &self.details.is_some())
            .finish()
    }
}

/// Cokret standard error envelope.
///
/// Stability: 1.0-stable. Server-controlled response shape, so additional
/// fields may appear in a minor release.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CokretErrorEnvelope {
    pub ok: bool,
    pub error: CokretError,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

impl fmt::Debug for CokretErrorEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CokretErrorEnvelope")
            .field("ok", &self.ok)
            .field("error", &self.error)
            .field("request_id", &self.request_id)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::push::errors::PushErrorKind;

    #[test]
    fn rejects_unknown_platform() {
        let err = PushPlatform::try_from("wearable").unwrap_err();
        assert_eq!(err.kind(), PushErrorKind::InvalidPlatform);
    }

    #[test]
    fn supports_web_and_desktop_platforms() {
        assert_eq!(PushPlatform::try_from("web").unwrap(), PushPlatform::Web);
        assert_eq!(
            PushPlatform::try_from("desktop").unwrap(),
            PushPlatform::Desktop
        );
    }

    #[test]
    fn push_key_hmac_is_stable_and_device_bound() {
        // A.5 #5 — same `(push_key, device_id)` always produces the
        // same digest; swapping either input changes the digest. This
        // is the property the floria verifier relies on.
        let hmac_a = compute_push_key_hmac("fcm:token-a", "did:web:alice.example#device-phone");
        let hmac_a_again =
            compute_push_key_hmac("fcm:token-a", "did:web:alice.example#device-phone");
        assert_eq!(hmac_a, hmac_a_again);

        let hmac_other_key =
            compute_push_key_hmac("fcm:token-b", "did:web:alice.example#device-phone");
        assert_ne!(
            hmac_a, hmac_other_key,
            "different push_key MUST move the HMAC"
        );

        let hmac_other_device =
            compute_push_key_hmac("fcm:token-a", "did:web:alice.example#device-tablet");
        assert_ne!(
            hmac_a, hmac_other_device,
            "different device_id MUST move the HMAC"
        );

        // 32 raw bytes -> 64 hex chars.
        assert_eq!(hmac_a.len(), 64);
        assert!(hmac_a.chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    #[test]
    fn verify_push_key_binding_round_trip_and_rejects_tamper() {
        let expected = compute_push_key_hmac("fcm:token-a", "did:web:alice.example#device-phone");

        assert!(verify_push_key_binding(
            "fcm:token-a",
            "did:web:alice.example#device-phone",
            &expected,
        ));
        // Tampered push_key.
        assert!(!verify_push_key_binding(
            "fcm:swapped-by-attacker",
            "did:web:alice.example#device-phone",
            &expected,
        ));
        // Tampered device_id.
        assert!(!verify_push_key_binding(
            "fcm:token-a",
            "did:web:mallory.example#device-phone",
            &expected,
        ));
        // Tampered HMAC (single-byte flip in the hex string).
        let mut flipped = expected;
        let last = flipped.pop().unwrap();
        // Swap the last hex digit to something else so the comparison
        // is *just barely* wrong.
        flipped.push(if last == '0' { '1' } else { '0' });
        assert!(!verify_push_key_binding(
            "fcm:token-a",
            "did:web:alice.example#device-phone",
            &flipped,
        ));
    }

    #[test]
    fn response_models_cover_frozen_wire_metadata() {
        let register: PushRegisterDeviceOutcome = serde_json::from_value(serde_json::json!({
            "ok": true,
            "registration_id": "reg-1",
            "accepted_gateway": "https://push.example.com/_cokret/edge/push/notify",
            "push_key_hash": "sha256:abc",
            "push_key_preview": "fcm:<redacted,len=17>",
            "expires_at": "2026-05-02T00:00:00Z",
            "refresh_hint": "rotate_before_expiry",
            "warnings": ["duplicate-safe"],
            "request_id": "ck:request:123"
        }))
        .unwrap();

        assert!(register.ok);
        assert_eq!(
            register.accepted_gateway.as_deref(),
            Some("https://push.example.com/_cokret/edge/push/notify")
        );
        assert_eq!(register.push_key_hash.as_deref(), Some("sha256:abc"));
        assert_eq!(
            register.push_key_preview.as_deref(),
            Some("fcm:<redacted,len=17>")
        );
        assert_eq!(
            register.refresh_hint.as_deref(),
            Some("rotate_before_expiry")
        );
        assert_eq!(register.warnings, vec!["duplicate-safe"]);
        assert_eq!(register.request_id.as_deref(), Some("ck:request:123"));

        let unregister: PushUnregisterDeviceOutcome = serde_json::from_value(serde_json::json!({
            "ok": true,
            "already_removed": true,
            "removed_registration_id": "reg-1",
            "request_id": "ck:request:456"
        }))
        .unwrap();

        assert!(unregister.ok);
        assert!(unregister.already_removed);
        assert_eq!(unregister.removed_registration_id.as_deref(), Some("reg-1"));
        assert_eq!(unregister.request_id.as_deref(), Some("ck:request:456"));
    }
}
