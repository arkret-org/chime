//! HTTP Message Signature / DID-proof signing context construction.
//!
//! ## CH-1 (SDK-3 migration)
//!
//! Wire-level primitives (RFC 9530 `Content-Digest` computation, the
//! base64 alphabet used for the `Signature` value, the covered-component
//! lookup keys) are now sourced from
//! [`cokret::http_signature`](cokret::http_signature) so chime, floria
//! and soland share a single canonicalization implementation. The
//! `PushRequestSigningContext` type itself stays in chime because:
//!
//! 1. chime's covered-component set differs from floria's notify set — it covers
//!    `x-cokret-operation-id`, `x-cokretice-id`, `x-cokret-created-at`, `x-cokret-audience`
//!    (the device- registration flow), not the two service-DID headers floria's `/notify` verifier
//!    requires.
//! 2. chime never owned a private key; it only canonicalizes context so an external signer (the
//!    host application's DID proof or HSM) can attach a pre-computed `Signature` header. The SDK's
//!    `sign_message` helper is therefore not called here — callers that have a `SigningKey` should
//!    call it directly with the canonical message built from chime's `PushRequestSigningContext`.

use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, SystemTime, SystemTimeError};

use cokret::http_signature::{
    Component, ContentDigest, ContentDigestAlgorithm, format_signature_header,
    format_signature_input_component_list,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use super::errors::PushRegistrationError;
use super::urls::{
    redact_url, require_optional_owned_non_empty, require_owned_non_empty, try_cokret_api_url,
};
use super::{
    CONTENT_DIGEST_HEADER, COKRET_ACTOR_ID_HEADER, COKRET_AUDIENCE_HEADER,
    COKRET_CREATED_AT_HEADER, COKRET_DESTINATION_SERVICE_DID_HEADER, COKRET_DEVICE_ID_HEADER,
    COKRET_EXPIRES_AT_HEADER, COKRET_IDEMPOTENCY_KEY_HEADER, COKRET_NONCE_HEADER,
    COKRET_OPERATION_ID_HEADER, COKRET_ORIGIN_HEADER, COKRET_ORIGIN_SERVICE_DID_HEADER,
    COKRET_SESSION_GRANT_HEADER, SIGNATURE_HEADER, SIGNATURE_INPUT_HEADER,
};

/// Canonical data that callers can bind into DID proofs or HTTP Message Signatures.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushRequestSigningContext {
    pub operation_id: String,
    pub method: String,
    pub path: String,
    pub target_uri: String,
    pub content_digest: String,
    pub device_id: String,
    pub created_at: String,
    pub audience: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin_service_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_service_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_grant: Option<String>,
}

impl fmt::Debug for PushRequestSigningContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PushRequestSigningContext")
            .field("operation_id", &self.operation_id)
            .field("method", &self.method)
            .field("path", &self.path)
            .field("target_uri", &redact_url(&self.target_uri))
            .field("content_digest", &self.content_digest)
            .field("device_id", &self.device_id)
            .field("created_at", &self.created_at)
            .field("audience", &self.audience)
            .field("actor_id", &self.actor_id)
            .field("expires_at", &self.expires_at)
            .field("origin", &self.origin)
            .field("origin_service_did", &self.origin_service_did)
            .field("destination_service_did", &self.destination_service_did)
            .field("nonce", &self.nonce)
            .field("idempotency_key", &self.idempotency_key)
            .field(
                "session_grant",
                &self.session_grant.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl PushRequestSigningContext {
    /// Return the canonical JSON value callers can sign as a DID proof body.
    pub fn canonical_proof_body(&self) -> Result<Value, PushRegistrationError> {
        Ok(serde_json::to_value(self)?)
    }

    /// Return deterministic metadata headers that should be present on the
    /// HTTP request and covered by HTTP Message Signatures.
    pub fn signed_metadata_headers(&self) -> Vec<(&'static str, String)> {
        // Pre-allocate the worst-case header count so we avoid up to four
        // small grows as the optional headers are appended below.
        let mut headers: Vec<(&'static str, String)> = Vec::with_capacity(13);
        headers.push((CONTENT_DIGEST_HEADER, self.content_digest.clone()));
        headers.push((COKRET_OPERATION_ID_HEADER, self.operation_id.clone()));
        headers.push((COKRET_DEVICE_ID_HEADER, self.device_id.clone()));
        headers.push((COKRET_CREATED_AT_HEADER, self.created_at.clone()));
        headers.push((COKRET_AUDIENCE_HEADER, self.audience.clone()));

        if let Some(actor_id) = &self.actor_id {
            headers.push((COKRET_ACTOR_ID_HEADER, actor_id.clone()));
        }
        if let Some(expires_at) = &self.expires_at {
            headers.push((COKRET_EXPIRES_AT_HEADER, expires_at.clone()));
        }
        if let Some(origin) = &self.origin {
            headers.push((COKRET_ORIGIN_HEADER, origin.clone()));
        }
        if let Some(origin_service_did) = &self.origin_service_did {
            headers.push((
                COKRET_ORIGIN_SERVICE_DID_HEADER,
                origin_service_did.clone(),
            ));
        }
        if let Some(destination_service_did) = &self.destination_service_did {
            headers.push((
                COKRET_DESTINATION_SERVICE_DID_HEADER,
                destination_service_did.clone(),
            ));
        }
        if let Some(nonce) = &self.nonce {
            headers.push((COKRET_NONCE_HEADER, nonce.clone()));
        }
        if let Some(idempotency_key) = &self.idempotency_key {
            headers.push((COKRET_IDEMPOTENCY_KEY_HEADER, idempotency_key.clone()));
        }
        if let Some(session_grant) = &self.session_grant {
            headers.push((COKRET_SESSION_GRANT_HEADER, session_grant.clone()));
        }

        headers
    }

    /// Build the `Signature-Input` header value for this request context.
    pub fn http_message_signature_input(
        &self,
        label: &str,
    ) -> Result<String, PushRegistrationError> {
        // Pre-allocate the worst-case component count (7 mandatory + 8 optional).
        let mut components: Vec<Component> = Vec::with_capacity(15);
        components.push(Component::Method);
        components.push(Component::TargetUri);
        components.push(Component::Header("content-digest".to_owned()));
        components.push(Component::Header("x-cokret-operation-id".to_owned()));
        components.push(Component::Header("x-cokretice-id".to_owned()));
        components.push(Component::Header("x-cokret-created-at".to_owned()));
        components.push(Component::Header("x-cokret-audience".to_owned()));

        if self.actor_id.is_some() {
            components.push(Component::Header("x-cokret-actor-id".to_owned()));
        }
        if self.expires_at.is_some() {
            components.push(Component::Header("x-cokret-expires-at".to_owned()));
        }
        if self.origin.is_some() {
            components.push(Component::Header("x-cokret-origin".to_owned()));
        }
        if self.origin_service_did.is_some() {
            components.push(Component::Header("x-cokret-origin-service-did".to_owned()));
        }
        if self.destination_service_did.is_some() {
            components.push(Component::Header(
                "x-cokret-destination-service-did".to_owned(),
            ));
        }
        if self.nonce.is_some() {
            components.push(Component::Header("x-cokret-nonce".to_owned()));
        }
        if self.idempotency_key.is_some() {
            components.push(Component::Header("x-cokret-idempotency-key".to_owned()));
        }
        if self.session_grant.is_some() {
            components.push(Component::Header("x-cokret-session-grant".to_owned()));
        }

        format_signature_input_component_list(label, &components).map_err(|_| {
            PushRegistrationError::InvalidHeader {
                name: SIGNATURE_INPUT_HEADER.to_owned(),
            }
        })
    }

    /// Build the `Signature` header value from a precomputed base64 signature.
    pub fn http_message_signature_header(
        label: &str,
        signature: &str,
    ) -> Result<String, PushRegistrationError> {
        format_signature_header(label, signature).map_err(|_| {
            PushRegistrationError::InvalidHeader {
                name: SIGNATURE_HEADER.to_owned(),
            }
        })
    }

    /// Return the metadata, `Signature-Input`, and `Signature` headers needed
    /// to attach a precomputed HTTP Message Signature to the request.
    pub fn http_message_signature_headers(
        &self,
        label: &str,
        signature: &str,
    ) -> Result<Vec<(&'static str, String)>, PushRegistrationError> {
        let mut headers = self.signed_metadata_headers();
        headers.push((
            SIGNATURE_INPUT_HEADER,
            self.http_message_signature_input(label)?,
        ));
        headers.push((
            SIGNATURE_HEADER,
            Self::http_message_signature_header(label, signature)?,
        ));
        Ok(headers)
    }
}

/// Inputs used to build a request signing context.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushRequestSigningOptions {
    pub created_at: String,
    pub audience: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin_service_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_service_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_grant: Option<String>,
}

impl PushRequestSigningOptions {
    pub fn new(created_at: impl Into<String>, audience: impl Into<String>) -> Self {
        Self {
            created_at: created_at.into(),
            audience: audience.into(),
            actor_id: None,
            expires_at: None,
            origin: None,
            origin_service_did: None,
            destination_service_did: None,
            nonce: None,
            idempotency_key: None,
            session_grant: None,
        }
    }

    pub fn with_actor_id(mut self, actor_id: impl Into<String>) -> Self {
        self.actor_id = Some(actor_id.into());
        self
    }

    pub fn with_expires_at(mut self, expires_at: impl Into<String>) -> Self {
        self.expires_at = Some(expires_at.into());
        self
    }

    pub fn with_origin(mut self, origin: impl Into<String>) -> Self {
        self.origin = Some(origin.into());
        self
    }

    pub fn with_origin_service_did(mut self, origin_service_did: impl Into<String>) -> Self {
        self.origin_service_did = Some(origin_service_did.into());
        self
    }

    pub fn with_destination_service_did(
        mut self,
        destination_service_did: impl Into<String>,
    ) -> Self {
        self.destination_service_did = Some(destination_service_did.into());
        self
    }

    pub fn with_nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    pub fn with_idempotency_key(mut self, idempotency_key: impl Into<String>) -> Self {
        self.idempotency_key = Some(idempotency_key.into());
        self
    }

    /// Attach an externally supplied coauth/soland session grant.
    ///
    /// `chime` only carries this value into the signing context and metadata
    /// headers; it never owns private keys or attempts to mint grants.
    pub fn with_session_grant(mut self, session_grant: impl Into<String>) -> Self {
        self.session_grant = Some(session_grant.into());
        self
    }
}

/// Return an RFC 9530-style `Content-Digest` value for the serialized JSON body.
///
/// The body is serialized with `serde_json`. The current helper is intended for
/// SDK request signing and HTTP Message Signature transcript construction; it
/// does not claim to replace the protocol's canonical JSON encoder.
///
/// ## CH-1 wire shape
///
/// The output is produced by [`cokret::http_signature::ContentDigest::compute`]
/// with [`ContentDigestAlgorithm::Sha256`]. That guarantees byte-equivalent
/// wire output (same `sha-256=:BASE64STANDARD_32B:` form, same base64
/// alphabet) with floria's verifier and soland's fanout signer, which
/// also delegate to the SDK.
pub fn content_digest_sha256<T>(body: &T) -> Result<String, PushRegistrationError>
where
    T: Serialize + ?Sized,
{
    let json = serde_json::to_vec(body)?;
    Ok(ContentDigest::compute(&json, ContentDigestAlgorithm::Sha256).wire_value)
}

pub(super) fn build_signing_context<T>(
    service_base_url: &str,
    operation_id: &str,
    path: &str,
    device_id: &str,
    body: &T,
    options: PushRequestSigningOptions,
) -> Result<PushRequestSigningContext, PushRegistrationError>
where
    T: Serialize + ?Sized,
{
    let created_at = require_owned_non_empty("created_at", options.created_at)?;
    let audience = require_owned_non_empty("audience", options.audience)?;
    let actor_id = require_optional_owned_non_empty("actor_id", options.actor_id)?;
    let expires_at = require_optional_owned_non_empty("expires_at", options.expires_at)?;
    let origin = require_optional_owned_non_empty("origin", options.origin)?;
    let origin_service_did =
        require_optional_owned_non_empty("origin_service_did", options.origin_service_did)?;
    let destination_service_did = require_optional_owned_non_empty(
        "destination_service_did",
        options.destination_service_did,
    )?;
    let nonce = require_optional_owned_non_empty("nonce", options.nonce)?;
    let idempotency_key =
        require_optional_owned_non_empty("idempotency_key", options.idempotency_key)?;
    let session_grant = require_optional_owned_non_empty("session_grant", options.session_grant)?;

    Ok(PushRequestSigningContext {
        operation_id: operation_id.to_owned(),
        method: "POST".to_owned(),
        path: path.to_owned(),
        target_uri: try_cokret_api_url(service_base_url, path)?,
        content_digest: content_digest_sha256(body)?,
        device_id: device_id.to_owned(),
        created_at,
        audience,
        actor_id,
        expires_at,
        origin,
        origin_service_did,
        destination_service_did,
        nonce,
        idempotency_key,
        session_grant,
    })
}

/// A.5 #4 — per-`(device_id, nonce)` replay-window tracker.
///
/// The chime push device registration / unregistration flow stamps a
/// random `X-Cokret-Nonce` value on every signed request so floria's
/// verifier can reject replays. The signed transcript would otherwise
/// stay valid forever, which means an attacker who recorded one
/// `register-device` request can resubmit it from any vantage point
/// until the soland session grant expires.
///
/// `NonceTracker` is the client-side counterpart of that defence — it
/// short-circuits the *same* `(device_id, nonce)` pair before the
/// signing context is ever built so chime can't accidentally hand
/// floria a replay-able payload. It is also useful in server-side
/// integrations that delegate signing to chime but need to remember
/// which nonces they have already accepted on the inbound leg.
///
/// ## Semantics
///
/// - Entries expire after [`NonceTracker::window`] seconds. The tracker prunes lazily on insert;
///   long-running processes that never insert do not see growth from this tracker alone.
/// - The store is in-memory and per-`NonceTracker` instance. Hosts that want restart-surviving or
///   cross-process coverage MUST layer Redis, an encrypted local key-value store, or another
///   durable backend on top — the unit of correctness here is the local SDK boundary.
/// - `observe` returns `Err(NonceReplayError::DuplicateNonce)` on replay so the caller fail-closes
///   rather than silently dropping the second request.
///
/// The tracker is intentionally lockless internally (single
/// `HashMap`); callers that share it across threads should wrap it in
/// a `Mutex`/`RwLock` themselves to keep dependencies minimal.
#[derive(Debug)]
pub struct NonceTracker {
    window: Duration,
    /// (device_id, nonce) → observed-at SystemTime
    seen: HashMap<NonceKey, SystemTime>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct NonceKey {
    device_id: String,
    nonce: String,
}

/// Error returned by [`NonceTracker::observe`] on replay or clock skew.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum NonceReplayError {
    /// The supplied `(device_id, nonce)` pair was already observed
    /// within the active replay window. The request MUST NOT be
    /// signed/submitted again — fail-closed.
    #[error("duplicate nonce `{nonce}` for device `{device_id}` within replay window")]
    DuplicateNonce { device_id: String, nonce: String },
}

impl From<SystemTimeError> for NonceReplayError {
    fn from(_: SystemTimeError) -> Self {
        // Clock skew is treated as duplicate-equivalent: returning
        // anything else would let a backward clock jump silently
        // re-accept old nonces.
        Self::DuplicateNonce {
            device_id: String::new(),
            nonce: String::new(),
        }
    }
}

impl NonceTracker {
    /// Construct a tracker that retains `(device_id, nonce)` pairs for
    /// `window`. A typical value is 5 minutes.
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            seen: HashMap::new(),
        }
    }

    /// Active replay-window duration.
    pub fn window(&self) -> Duration {
        self.window
    }

    /// Record a `(device_id, nonce)` pair. Returns
    /// `Err(NonceReplayError::DuplicateNonce)` if the same pair has
    /// already been recorded within the active window.
    ///
    /// Use the value of [`crate::COKRET_NONCE_HEADER`] for `nonce`.
    pub fn observe(&mut self, device_id: &str, nonce: &str) -> Result<(), NonceReplayError> {
        self.observe_at(device_id, nonce, SystemTime::now())
    }

    /// Test-friendly variant of [`Self::observe`] that takes the
    /// observation timestamp explicitly. Production callers should use
    /// [`Self::observe`].
    pub fn observe_at(
        &mut self,
        device_id: &str,
        nonce: &str,
        now: SystemTime,
    ) -> Result<(), NonceReplayError> {
        // Drop entries older than the active window. We do this on
        // every insert so the tracker stays bounded in size for
        // long-running processes.
        self.prune(now);

        let key = NonceKey {
            device_id: device_id.to_owned(),
            nonce: nonce.to_owned(),
        };
        if self.seen.contains_key(&key) {
            return Err(NonceReplayError::DuplicateNonce {
                device_id: key.device_id,
                nonce: key.nonce,
            });
        }
        self.seen.insert(key, now);
        Ok(())
    }

    /// Number of unexpired `(device_id, nonce)` pairs currently tracked.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// `true` when the tracker holds no unexpired entries.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    fn prune(&mut self, now: SystemTime) {
        let window = self.window;
        self.seen.retain(|_, observed_at| {
            now.duration_since(*observed_at)
                .map(|elapsed| elapsed < window)
                .unwrap_or(true)
        });
    }
}

#[cfg(test)]
mod tests {
    //! CH-1 wire-equivalence tests for the SDK-routed `content_digest_sha256`.
    //!
    //! The whole point of routing through `cokret::http_signature::ContentDigest`
    //! is that chime, floria's verifier, and soland's fanout signer all
    //! agree on the wire bytes. These tests pin that agreement so a
    //! future SDK bump can't silently change the wire shape without
    //! also tripping chime's CI.

    use cokret::http_signature::{ContentDigest, ContentDigestAlgorithm, verify_content_digest};

    use super::*;

    /// chime's `content_digest_sha256` for a fixed body must be
    /// byte-identical to the SDK's `ContentDigest::compute` output
    /// (same algorithm tag, same base64 alphabet, same surrounding
    /// `:...:` wrap). This is the contract floria's verifier relies on.
    #[test]
    fn ch1_content_digest_matches_sdk_byte_for_byte() {
        let body = serde_json::json!({
            "operation_id": "ck.push.register_device",
            "device_id": "ck:device:01HYZ8Z000000000000000",
        });
        let chime_value = content_digest_sha256(&body).expect("chime digest computes");

        let json = serde_json::to_vec(&body).expect("body serializes");
        let sdk_value = ContentDigest::compute(&json, ContentDigestAlgorithm::Sha256).wire_value;

        assert_eq!(chime_value, sdk_value, "chime/SDK wire bytes must match");
        assert!(chime_value.starts_with("sha-256=:"));
        assert!(chime_value.ends_with(':'));
    }

    /// A `Content-Digest` value chime emits must parse cleanly with
    /// the SDK and re-verify against the same body bytes. This is the
    /// chime → floria interop check at the digest layer.
    ///
    /// Note: chime's `content_digest_sha256<T>` always serializes `T`
    /// through `serde_json::to_vec`, so the bytes that get hashed are
    /// the serde-emitted JSON, NOT the input as-is. For a Rust byte
    /// slice that means hashing the JSON ARRAY representation of the
    /// bytes — which is fine wire-wise (callers always pass the same
    /// serializable struct on both sides), but the test fixture has
    /// to mirror that.
    #[test]
    fn ch1_chime_emitted_digest_round_trips_through_sdk_parser() {
        let body = serde_json::json!({"hello": "world"});
        let wire = content_digest_sha256(&body).expect("chime digest computes");

        let parsed = ContentDigest::parse(&wire).expect("SDK parses chime's digest");
        assert_eq!(parsed.algorithm, ContentDigestAlgorithm::Sha256);
        assert_eq!(parsed.digest.len(), 32);

        // floria's verifier hashes the raw HTTP body bytes — for chime
        // the raw body is exactly `serde_json::to_vec(&body)`, so feed
        // the same byte sequence to the SDK verifier.
        let body_bytes = serde_json::to_vec(&body).expect("body serializes");
        verify_content_digest(&parsed, &body_bytes).expect("SDK verifies chime's digest");

        // Tampering the body must trip the SDK verifier — the same
        // protection floria's `verified_content_digest` relies on.
        let err = verify_content_digest(&parsed, b"different body").unwrap_err();
        assert!(matches!(
            err,
            cokret::http_signature::SignatureError::ContentDigestMismatch
        ));
    }

    // ─── A.5 #4 NonceTracker replay-window tests ───────────────────────

    #[test]
    fn nonce_tracker_accepts_distinct_nonces() {
        let mut tracker = NonceTracker::new(Duration::from_secs(300));
        tracker
            .observe("did:web:alice.example#device-phone", "nonce-a")
            .expect("fresh nonce accepted");
        tracker
            .observe("did:web:alice.example#device-phone", "nonce-b")
            .expect("distinct nonce accepted");
        assert_eq!(tracker.len(), 2);
    }

    #[test]
    fn nonce_tracker_rejects_duplicate_within_window() {
        let mut tracker = NonceTracker::new(Duration::from_secs(300));
        tracker
            .observe("did:web:alice.example#device-phone", "nonce-a")
            .expect("first observation accepted");
        let err = tracker
            .observe("did:web:alice.example#device-phone", "nonce-a")
            .unwrap_err();
        assert!(matches!(
            err,
            NonceReplayError::DuplicateNonce { ref device_id, ref nonce }
                if device_id == "did:web:alice.example#device-phone"
                    && nonce == "nonce-a"
        ));
    }

    #[test]
    fn nonce_tracker_scopes_by_device_id() {
        // The same nonce string from two different devices is fine —
        // the replay primitive is `(device_id, nonce)`, not nonce
        // alone.
        let mut tracker = NonceTracker::new(Duration::from_secs(300));
        tracker
            .observe("did:web:alice.example#device-phone", "shared-nonce")
            .unwrap();
        tracker
            .observe("did:web:alice.example#device-tablet", "shared-nonce")
            .expect("same nonce on different device is not a replay");
    }

    #[test]
    fn nonce_tracker_prunes_entries_past_window() {
        let mut tracker = NonceTracker::new(Duration::from_secs(60));
        let base = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        tracker
            .observe_at("did:web:alice.example#device-phone", "nonce-a", base)
            .unwrap();
        assert_eq!(tracker.len(), 1);

        // Insert past the window: the old entry must be evicted, and
        // re-observing the same nonce must now succeed because it has
        // aged out.
        let later = base + Duration::from_secs(120);
        tracker
            .observe_at("did:web:alice.example#device-phone", "nonce-b", later)
            .unwrap();
        // After the prune the only surviving entry is `nonce-b`.
        assert_eq!(tracker.len(), 1);

        tracker
            .observe_at("did:web:alice.example#device-phone", "nonce-a", later)
            .expect("aged-out nonce can be re-observed");
        assert_eq!(tracker.len(), 2);
    }
}
