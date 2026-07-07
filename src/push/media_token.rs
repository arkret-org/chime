//! R3 (CALL-1, spec b47ff6ec) — client-side helper for
//! `ck.self.call.media.exchange.issue_token` (`POST /rtc/token`).
//!
//! This module is intentionally transport-agnostic: it builds the
//! request body via the SDK's [`call_media_token_exchange`] helper and
//! exposes [`verify_media_token_outcome`] that performs the checks chime
//! owes its consumer (yougen):
//!
//! - `participant_binding.issuer_kid` matches the realm's current
//!   `ck.realm.media_service.service_id` anchors supplied by the host and ties together the call-id
//!   / focus-id / actor-id / device-id tuple that the caller asked for,
//! - the token TTL is within the spec ceiling
//!   ([`MEDIA_TOKEN_TTL_MAX_SECS`](cokret::MEDIA_TOKEN_TTL_MAX_SECS)) via the SDK's
//!   [`validate_token_ttl`],
//! - `service_signature` and `participant_binding.sig` verify through the SDK's media-service
//!   verifier before the returned marker can be used for SFrame keying.
//!
//! The companion [`ensure_known_backend`] helper rejects unsupported
//! media focus backend labels before the host forwards a focus into
//! the wire layer.
//!
//! When validation fails this helper returns a typed [`MediaTokenError`]
//! whose [`MediaTokenError::kind`] aligns one-to-one with the CKP-0010
//! variants surfaced through [`PushErrorKind`] (CALL-2). HTTP transport
//! is the caller's responsibility — the rationale is that chime's
//! `CokretPushClient` is push-registration scoped and may live on
//! wasm32 without a tokio runtime, while the RTC token exchange is
//! typically driven by the in-app call surface (yougen).
use std::fmt;

use chrono::{DateTime, Utc};
// Re-export the SDK types so chime consumers can pull the full media
// token surface through `chime::` without a second `cokret` dep.
pub use cokret::{
    CallMediaParticipantBinding, CallMediaServiceSignature, CallMediaTokenExchangeOutcome,
    CallMediaTokenExchangeRequestBody, CallMediaTokenVerification, MediaBackendType,
    MediaServiceAnchors, call_media_token_exchange,
};

use super::errors::PushErrorKind;

/// Chime-side error raised when a media-token exchange response fails
/// CALL-1 / CALL-2 validation.
///
/// Each variant maps to a CKP-0010 error code on the wire; the
/// [`Self::kind`] accessor returns the matching [`PushErrorKind`] so
/// host applications can branch on a single classifier surface.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MediaTokenError {
    /// CALL-2 — `participant_binding.issuer_kid` is not anchored to
    /// the realm's current
    /// `ck.realm.media_service.service_id`.
    TokenIssuerUnauthorised {
        observed_kid: String,
        expected_service_id: String,
    },
    /// CALL-2 — focus backend type is not recognised; receivers MUST
    /// fail closed instead of forwarding to the wire layer.
    UnknownFocusType,
    /// CALL-2 — `participant_binding` tuple does not match the call
    /// state the caller committed to (focus / call / actor / device).
    ParticipantBindingInvalid { reason: String },
    /// CALL-2 — the focus id in `participant_binding` does not match
    /// either the requested focus id or the already-committed
    /// `ck.call.state.session_focus`.
    FocusMismatch {
        requested_focus_id: String,
        binding_focus_id: String,
        committed_focus_id: Option<String>,
    },
}

impl MediaTokenError {
    /// Map to the chime-wide [`PushErrorKind`] classifier. Lets callers
    /// share a single match arm with the HTTP transport's failure
    /// classifier when surfacing media-token errors through a generic
    /// error toast.
    pub const fn kind(&self) -> PushErrorKind {
        match self {
            Self::TokenIssuerUnauthorised { .. } => PushErrorKind::TokenIssuerUnauthorised,
            Self::UnknownFocusType => PushErrorKind::UnknownFocusType,
            Self::ParticipantBindingInvalid { .. } => PushErrorKind::ParticipantBindingInvalid,
            Self::FocusMismatch { .. } => PushErrorKind::FocusMismatch,
        }
    }
}

impl fmt::Display for MediaTokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TokenIssuerUnauthorised {
                observed_kid,
                expected_service_id,
            } => write!(
                f,
                "token_issuer_unauthorised: participant_binding.issuer_kid `{observed_kid}` is not anchored to current media_service.service_id `{expected_service_id}`"
            ),
            Self::UnknownFocusType => f.write_str(
                "unknown_focus_type: media focus backend label not recognised by this SDK",
            ),
            Self::ParticipantBindingInvalid { reason } => {
                write!(f, "participant_binding_invalid: {reason}")
            }
            Self::FocusMismatch {
                requested_focus_id,
                binding_focus_id,
                committed_focus_id,
            } => {
                if let Some(committed_focus_id) = committed_focus_id {
                    write!(
                        f,
                        "focus_mismatch: participant_binding.focus_id `{binding_focus_id}` does not match committed session_focus `{committed_focus_id}` (requested `{requested_focus_id}`)"
                    )
                } else {
                    write!(
                        f,
                        "focus_mismatch: requested focus `{requested_focus_id}` does not match participant_binding.focus_id `{binding_focus_id}`"
                    )
                }
            }
        }
    }
}

impl std::error::Error for MediaTokenError {}

/// Inputs to the CALL-1 verification pipeline.
#[derive(Clone, Debug)]
pub struct MediaTokenVerificationContext<'a> {
    /// Original request body produced by [`call_media_token_exchange`].
    /// The SDK verifier compares the response binding against this exact
    /// tuple.
    pub request: &'a CallMediaTokenExchangeRequestBody,
    /// Current `ck.realm.media_service.service_id` anchors plus the
    /// resolved Ed25519 verifying keys keyed by full `kid`.
    pub media_service_anchors: &'a MediaServiceAnchors,
    /// `ck.call.state.session_focus` committed in the call state — used
    /// to fail-closed on `focus_mismatch`. Pass `None` when the call
    /// has no committed focus yet (the SDK does not currently model
    /// "no commit yet" as an error — it accepts the response and lets
    /// the caller commit the focus next).
    pub committed_session_focus: Option<&'a str>,
    /// Wall-clock used for TTL validation (typically `Utc::now()` at
    /// the call site; injected for determinism in tests).
    pub now: DateTime<Utc>,
}

/// Marker returned after a [`CallMediaTokenExchangeOutcome`] has passed
/// chime's structure checks and the SDK's Ed25519 media-service signature
/// verification.
#[derive(Clone, Debug)]
pub struct VerifiedMediaTokenOutcome<'a> {
    response: &'a CallMediaTokenExchangeOutcome,
    verification: CallMediaTokenVerification,
}

impl<'a> VerifiedMediaTokenOutcome<'a> {
    /// Borrow the original response after all checks have passed.
    pub fn response(&self) -> &'a CallMediaTokenExchangeOutcome {
        self.response
    }

    /// Borrow the participant binding whose tuple/TTL/issuer anchor and
    /// signatures have been checked.
    pub fn participant_binding(&self) -> &'a CallMediaParticipantBinding {
        &self.response.participant_binding
    }

    /// SDK verification summary proving the anchored issuer DID and
    /// participant identity.
    pub fn verification(&self) -> &CallMediaTokenVerification {
        &self.verification
    }

    /// Typed `{kid, sig}` service signature material that has already passed
    /// SDK Ed25519 verification.
    pub fn service_signature(&self) -> &'a CallMediaServiceSignature {
        &self.response.service_signature
    }

    /// Participant-binding signature material that has already passed SDK
    /// Ed25519 verification.
    pub fn participant_binding_signature(&self) -> &'a str {
        &self.response.participant_binding.sig
    }
}

/// Verify a [`CallMediaTokenExchangeOutcome`] against the original request,
/// current media-service anchors, committed call focus, TTL, and both
/// media-service signatures.
pub fn verify_media_token_outcome<'response>(
    response: &'response CallMediaTokenExchangeOutcome,
    ctx: &MediaTokenVerificationContext<'_>,
) -> Result<VerifiedMediaTokenOutcome<'response>, MediaTokenError> {
    ensure_known_backend_label(&response.backend_type)?;

    // Focus mismatch: the response focus_id and binding focus_id MUST equal the
    // committed session_focus (when present) and the focus the caller
    // requested. The checks distinguish a server-side
    // incorrect routing (binding != committed) from a client-side focus
    // selection bug (requested != binding).
    if response.focus_id != ctx.request.focus_id {
        return Err(MediaTokenError::FocusMismatch {
            requested_focus_id: ctx.request.focus_id.clone(),
            binding_focus_id: response.focus_id.clone(),
            committed_focus_id: None,
        });
    }
    if response.participant_binding.focus_id != ctx.request.focus_id {
        return Err(MediaTokenError::FocusMismatch {
            requested_focus_id: ctx.request.focus_id.clone(),
            binding_focus_id: response.participant_binding.focus_id.clone(),
            committed_focus_id: None,
        });
    }
    if let Some(committed) = ctx.committed_session_focus
        && response.participant_binding.focus_id != committed
    {
        return Err(MediaTokenError::FocusMismatch {
            requested_focus_id: ctx.request.focus_id.clone(),
            binding_focus_id: response.participant_binding.focus_id.clone(),
            committed_focus_id: Some(committed.to_owned()),
        });
    }

    let binding = &response.participant_binding;
    // Binding expires_at and response expires_at must agree — if the
    // service-side signed binding outlives the surrounding response
    // metadata the client cannot rely on either.
    if binding.expires_at != response.expires_at {
        return Err(MediaTokenError::ParticipantBindingInvalid {
            reason: format!(
                "expires_at mismatch: binding `{}` vs response `{}`",
                binding.expires_at, response.expires_at
            ),
        });
    }

    let verification = cokret::verify_call_media_token_outcome(
        ctx.request,
        response,
        ctx.media_service_anchors,
        ctx.now,
    )
    .map_err(|err| map_sdk_media_error(err, response))?;

    Ok(VerifiedMediaTokenOutcome {
        response,
        verification,
    })
}

/// Reject the focus when the SDK does not recognise the backend
/// label. Surfaces as CALL-2 [`MediaTokenError::UnknownFocusType`].
///
/// Wraps the SDK's [`MediaBackendType::ensure_known`] so chime
/// consumers can perform the check without depending on `cokret`
/// directly.
pub fn ensure_known_backend(backend: &MediaBackendType) -> Result<(), MediaTokenError> {
    backend
        .ensure_known()
        .map_err(|_| MediaTokenError::UnknownFocusType)
}

fn ensure_known_backend_label(label: &str) -> Result<(), MediaTokenError> {
    let backend: MediaBackendType =
        serde_json::from_value(serde_json::Value::String(label.to_owned())).map_err(|err| {
            MediaTokenError::ParticipantBindingInvalid {
                reason: format!("backend_type decode failed: {err}"),
            }
        })?;
    ensure_known_backend(&backend)
}

fn map_sdk_media_error(
    err: cokret::Error,
    response: &CallMediaTokenExchangeOutcome,
) -> MediaTokenError {
    match sdk_media_reason(err) {
        SdkMediaReason::TokenIssuerUnauthorised => {
            let observed_kid = if response.participant_binding.issuer_kid.trim().is_empty() {
                response.service_signature.kid.clone()
            } else {
                response.participant_binding.issuer_kid.clone()
            };
            MediaTokenError::TokenIssuerUnauthorised {
                observed_kid,
                expected_service_id: "realm media-service anchors".to_owned(),
            }
        }
        SdkMediaReason::UnknownFocusType => MediaTokenError::UnknownFocusType,
        SdkMediaReason::Other(reason) => MediaTokenError::ParticipantBindingInvalid { reason },
    }
}

enum SdkMediaReason {
    TokenIssuerUnauthorised,
    UnknownFocusType,
    Other(String),
}

fn sdk_media_reason(err: cokret::Error) -> SdkMediaReason {
    match err {
        cokret::Error::Protocol(message) => {
            let reason_code = message
                .split_once(':')
                .map_or(message.as_str(), |(code, _)| code)
                .trim();
            match reason_code {
                cokret::REASON_TOKEN_ISSUER_UNAUTHORISED => SdkMediaReason::TokenIssuerUnauthorised,
                cokret::REASON_UNKNOWN_FOCUS_TYPE => SdkMediaReason::UnknownFocusType,
                _ => SdkMediaReason::Other(message),
            }
        }
        other => SdkMediaReason::Other(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use chrono::Duration;
    use cokret::{CallId, DeviceId, Did, RealmId};
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    const ISSUER_KID: &str = "did:web:media.example:media#kid-1";

    fn realm() -> RealmId {
        RealmId::new("ck:realm:01904100-0000-7000-8000-000000000001".to_owned()).unwrap()
    }
    fn call() -> CallId {
        CallId::new("ck:call:01904100-0000-7000-8000-000000000002".to_owned()).unwrap()
    }
    fn actor() -> Did {
        Did::new("did:web:alice.example".to_owned()).unwrap()
    }
    fn device() -> DeviceId {
        DeviceId::new("ck:device:01904100-0000-7000-8000-000000000004".to_owned()).unwrap()
    }
    fn issuer_did() -> Did {
        Did::new("did:web:media.example:media".to_owned()).unwrap()
    }
    fn issuer_key() -> SigningKey {
        SigningKey::from_bytes(&[11_u8; 32])
    }
    fn anchors_with_issuer_key(key: &SigningKey) -> MediaServiceAnchors {
        MediaServiceAnchors::new([issuer_did()])
            .with_keys([(ISSUER_KID.to_owned(), key.verifying_key())])
    }
    fn token_request() -> CallMediaTokenExchangeRequestBody {
        call_media_token_exchange(realm(), call(), actor(), device(), "ck:focus:01".to_owned())
    }

    fn unsigned_response(expires_at: DateTime<Utc>) -> CallMediaTokenExchangeOutcome {
        CallMediaTokenExchangeOutcome {
            focus_id: "ck:focus:01".to_owned(),
            backend_type: "livekit".to_owned(),
            connect_url: "wss://media.example/livekit".to_owned(),
            backend_token: "livekit-jwt-token".to_owned(),
            participant_identity: "ck:rtc_participant:01904100-0000-7000-8000-000000000003"
                .to_owned(),
            participant_binding: CallMediaParticipantBinding {
                scheme: CallMediaParticipantBinding::SCHEME.to_owned(),
                sig: String::new(),
                issuer_kid: ISSUER_KID.to_owned(),
                realm_id: realm(),
                call_id: call(),
                focus_id: "ck:focus:01".to_owned(),
                actor_id: actor(),
                device_id: device(),
                participant_identity: "ck:rtc_participant:01904100-0000-7000-8000-000000000003"
                    .to_owned(),
                issued_at: expires_at - Duration::minutes(5),
                expires_at,
            },
            expires_at,
            service_signature: CallMediaServiceSignature {
                kid: ISSUER_KID.to_owned(),
                sig: String::new(),
            },
        }
    }

    fn sign_response(response: &mut CallMediaTokenExchangeOutcome, key: &SigningKey) {
        let input = cokret::participant_binding_signing_input(&response.participant_binding)
            .expect("participant binding signing input builds");
        let sig = URL_SAFE_NO_PAD.encode(key.sign(&input).to_bytes());
        response.participant_binding.sig = sig.clone();
        response.service_signature.sig = sig;
    }

    fn good_response(now: DateTime<Utc>, key: &SigningKey) -> CallMediaTokenExchangeOutcome {
        let mut response = unsigned_response(now + Duration::seconds(300));
        sign_response(&mut response, key);
        response
    }

    fn good_ctx<'a>(
        now: DateTime<Utc>,
        request: &'a CallMediaTokenExchangeRequestBody,
        anchors: &'a MediaServiceAnchors,
    ) -> MediaTokenVerificationContext<'a> {
        MediaTokenVerificationContext {
            request,
            media_service_anchors: anchors,
            committed_session_focus: Some("ck:focus:01"),
            now,
        }
    }

    #[test]
    fn happy_path_passes() {
        let now = Utc::now();
        let request = token_request();
        let key = issuer_key();
        let anchors = anchors_with_issuer_key(&key);
        let response = good_response(now, &key);
        let ctx = good_ctx(now, &request, &anchors);
        let verified = verify_media_token_outcome(&response, &ctx).unwrap();
        assert_eq!(
            verified.response().participant_identity,
            response.participant_identity
        );
        assert_eq!(
            verified.verification().participant_identity,
            response.participant_identity
        );
        assert_eq!(verified.verification().issuer_did, issuer_did());
        assert!(!verified.participant_binding_signature().is_empty());
    }

    #[test]
    fn rejects_token_issuer_unauthorised_via_binding_kid() {
        let now = Utc::now();
        let request = token_request();
        let key = issuer_key();
        let anchors =
            MediaServiceAnchors::new([Did::new("did:web:other.example:media".to_owned()).unwrap()])
                .with_keys([(ISSUER_KID.to_owned(), key.verifying_key())]);
        let response = good_response(now, &key);
        let ctx = good_ctx(now, &request, &anchors);
        let err = verify_media_token_outcome(&response, &ctx).unwrap_err();
        assert_eq!(err.kind(), PushErrorKind::TokenIssuerUnauthorised);
    }

    #[test]
    fn sdk_protocol_reason_constants_map_to_media_error_kinds() {
        let now = Utc::now();
        let key = issuer_key();
        let response = good_response(now, &key);

        let err = map_sdk_media_error(
            cokret::Error::Protocol(format!(
                "{}: wording after the reason code may change",
                cokret::REASON_TOKEN_ISSUER_UNAUTHORISED
            )),
            &response,
        );
        assert_eq!(err.kind(), PushErrorKind::TokenIssuerUnauthorised);

        let err = map_sdk_media_error(
            cokret::Error::Protocol(format!(
                "{}: wording after the reason code may change",
                cokret::REASON_UNKNOWN_FOCUS_TYPE
            )),
            &response,
        );
        assert_eq!(err.kind(), PushErrorKind::UnknownFocusType);
    }

    #[test]
    fn rejects_tampered_media_token_signature() {
        let now = Utc::now();
        let request = token_request();
        let key = issuer_key();
        let anchors = anchors_with_issuer_key(&key);
        let mut response = good_response(now, &key);
        response.service_signature.sig = "tampered".to_owned();
        let ctx = good_ctx(now, &request, &anchors);
        let err = verify_media_token_outcome(&response, &ctx).unwrap_err();
        assert_eq!(err.kind(), PushErrorKind::TokenIssuerUnauthorised);
    }

    #[test]
    fn rejects_focus_mismatch() {
        let now = Utc::now();
        let key = issuer_key();
        let anchors = anchors_with_issuer_key(&key);
        let response = good_response(now, &key);
        let request =
            call_media_token_exchange(realm(), call(), actor(), device(), "ck:focus:02".to_owned());
        let ctx = good_ctx(now, &request, &anchors);
        let err = verify_media_token_outcome(&response, &ctx).unwrap_err();
        assert_eq!(err.kind(), PushErrorKind::FocusMismatch);
        assert!(matches!(
            err,
            MediaTokenError::FocusMismatch {
                requested_focus_id,
                binding_focus_id,
                committed_focus_id: None,
            } if requested_focus_id == "ck:focus:02" && binding_focus_id == "ck:focus:01"
        ));
    }

    #[test]
    fn rejects_committed_focus_mismatch_with_explicit_fields() {
        let now = Utc::now();
        let request = token_request();
        let key = issuer_key();
        let anchors = anchors_with_issuer_key(&key);
        let response = good_response(now, &key);
        let mut ctx = good_ctx(now, &request, &anchors);
        ctx.committed_session_focus = Some("ck:focus:committed-other");
        let err = verify_media_token_outcome(&response, &ctx).unwrap_err();
        assert!(matches!(
            err,
            MediaTokenError::FocusMismatch {
                requested_focus_id,
                binding_focus_id,
                committed_focus_id: Some(committed_focus_id),
            } if requested_focus_id == "ck:focus:01"
                && binding_focus_id == "ck:focus:01"
                && committed_focus_id == "ck:focus:committed-other"
        ));
    }

    #[test]
    fn rejects_participant_binding_tuple_mismatch() {
        let now = Utc::now();
        let request = token_request();
        let key = issuer_key();
        let anchors = anchors_with_issuer_key(&key);
        let mut response = unsigned_response(now + Duration::seconds(300));
        response.participant_binding.device_id =
            DeviceId::new("ck:device:01904100-0000-7000-8000-000000000099".to_owned()).unwrap();
        sign_response(&mut response, &key);
        let ctx = good_ctx(now, &request, &anchors);
        let err = verify_media_token_outcome(&response, &ctx).unwrap_err();
        assert_eq!(err.kind(), PushErrorKind::ParticipantBindingInvalid);
    }

    #[test]
    fn rejects_expired_ttl() {
        let now = Utc::now();
        let request = token_request();
        let key = issuer_key();
        let anchors = anchors_with_issuer_key(&key);
        let mut response = unsigned_response(now - Duration::seconds(600));
        sign_response(&mut response, &key);
        let ctx = good_ctx(now, &request, &anchors);
        let err = verify_media_token_outcome(&response, &ctx).unwrap_err();
        assert_eq!(err.kind(), PushErrorKind::ParticipantBindingInvalid);
    }

    #[test]
    fn rejects_ttl_above_ceiling() {
        let now = Utc::now();
        let request = token_request();
        let key = issuer_key();
        let anchors = anchors_with_issuer_key(&key);
        let mut response = unsigned_response(now + Duration::seconds(700));
        sign_response(&mut response, &key);
        let ctx = good_ctx(now, &request, &anchors);
        let err = verify_media_token_outcome(&response, &ctx).unwrap_err();
        assert_eq!(err.kind(), PushErrorKind::ParticipantBindingInvalid);
    }

    #[test]
    fn rejects_unknown_backend_label() {
        let now = Utc::now();
        let request = token_request();
        let key = issuer_key();
        let anchors = anchors_with_issuer_key(&key);
        let mut response = good_response(now, &key);
        response.backend_type = "unknown_sfu".to_owned();
        let ctx = good_ctx(now, &request, &anchors);
        let err = verify_media_token_outcome(&response, &ctx).unwrap_err();
        assert_eq!(err.kind(), PushErrorKind::UnknownFocusType);
    }

    #[test]
    fn ensure_known_backend_rejects_unknown() {
        let err = ensure_known_backend(&MediaBackendType::Unknown).unwrap_err();
        assert_eq!(err.kind(), PushErrorKind::UnknownFocusType);
        assert!(ensure_known_backend(&MediaBackendType::Livekit).is_ok());
        assert!(ensure_known_backend(&MediaBackendType::CokretNative).is_ok());
    }

    #[test]
    fn helper_builds_request_with_provided_focus_id() {
        // CALL-1: chime exposes the SDK request-builder so consumers
        // don't need their own `cokret` dep.
        let req =
            call_media_token_exchange(realm(), call(), actor(), device(), "ck:focus:01".to_owned());
        assert_eq!(req.focus_id, "ck:focus:01");
        assert_eq!(req.realm_id, realm());
    }

    #[test]
    fn media_token_error_kind_matches_push_error_kind() {
        let err = MediaTokenError::TokenIssuerUnauthorised {
            observed_kid: "k".to_owned(),
            expected_service_id: "s".to_owned(),
        };
        assert!(err.kind().is_media_token_rejection());
        assert!(
            MediaTokenError::UnknownFocusType
                .kind()
                .is_media_token_rejection()
        );
        assert!(
            MediaTokenError::FocusMismatch {
                requested_focus_id: "a".to_owned(),
                binding_focus_id: "b".to_owned(),
                committed_focus_id: None,
            }
            .kind()
            .is_media_token_rejection()
        );
        assert!(
            MediaTokenError::ParticipantBindingInvalid {
                reason: String::new(),
            }
            .kind()
            .is_media_token_rejection()
        );
    }
}
