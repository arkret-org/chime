//! R3 (CALL-1, spec b47ff6ec) — client-side helper for
//! `ck.self.call.media.exchange.issue_token` (`POST /rtc/token`).
//!
//! This module is intentionally transport-agnostic: it builds the
//! request body via the SDK's [`call_media_token_exchange`] helper and
//! exposes [`structurally_validate_media_token_outcome`] that performs
//! the structure-level checks chime owes its consumer (yougen):
//!
//! - `participant_binding.issuer_kid` matches the realm's current
//!   `ck.realm.media_service.service_id` and ties together the call-id / focus-id / actor-id /
//!   device-id tuple that the caller asked for,
//! - the token TTL is within the spec ceiling
//!   ([`MEDIA_TOKEN_TTL_MAX_SECS`](cokret::MEDIA_TOKEN_TTL_MAX_SECS)) via the SDK's
//!   [`validate_token_ttl`].
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
//!
//! ## Cryptography
//!
//! The signature-verification path is currently stubbed out
//! (`TODO(R3.1)`): we structurally validate the binding tuple and TTL
//! but defer the Ed25519 signature check to the host application's
//! keystore until the SDK's `verify_service_signature` lands. The
//! issuer anchor check DOES run today — it is a pure equality check
//! against the caller-supplied current service id. A returned
//! [`StructurallyValidatedMediaTokenOutcome`] is not proof that
//! `service_signature` or `participant_binding.sig` has been
//! cryptographically verified.

use std::fmt;

use chrono::{DateTime, Utc};
// Re-export the SDK types so chime consumers can pull the full media
// token surface through `chime::` without a second `cokret` dep.
pub use cokret::{
    CallMediaParticipantBinding, CallMediaTokenExchangeOutcome, CallMediaTokenExchangeRequestBody,
    MediaBackendType, call_media_token_exchange,
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

/// Inputs to the CALL-1 structure-validation pipeline. Bundled in a
/// struct so the call site stays readable when chime grows additional
/// anchor dimensions (e.g. epoch number) in R3.1+.
#[derive(Clone, Debug)]
pub struct MediaTokenStructuralValidationContext<'a> {
    /// The current `ck.realm.media_service.service_id` resolved by the
    /// caller (yougen) from realm state at the moment of the exchange.
    pub current_media_service_id: &'a str,
    /// `ck.call.state.session_focus` committed in the call state — used
    /// to fail-closed on `focus_mismatch`. Pass `None` when the call
    /// has no committed focus yet (the SDK does not currently model
    /// "no commit yet" as an error — it accepts the response and lets
    /// the caller commit the focus next).
    pub committed_session_focus: Option<&'a str>,
    /// Focus id the caller passed to [`call_media_token_exchange`].
    pub requested_focus_id: &'a str,
    /// Realm id the request was built with — must match
    /// `participant_binding.realm_id`.
    pub realm_id: &'a cokret::RealmId,
    /// Call id the request was built with — must match
    /// `participant_binding.call_id`.
    pub call_id: &'a cokret::CallId,
    /// Actor ID the request was built with — must match
    /// `participant_binding.actor_id`.
    pub actor_id: &'a cokret::Did,
    /// Device id the request was built with — must match
    /// `participant_binding.device_id`.
    pub device_id: &'a cokret::DeviceId,
    /// Wall-clock used for TTL validation (typically `Utc::now()` at
    /// the call site; injected for determinism in tests).
    pub now: DateTime<Utc>,
}

/// Marker returned after a [`CallMediaTokenExchangeOutcome`] has passed chime's
/// structure-level media-token checks.
///
/// This type deliberately means "structurally validated", not
/// "cryptographically verified". Host applications MUST verify
/// `service_signature` and `participant_binding.sig` with the realm
/// media-service key before using the token response for SFrame
/// keying.
#[derive(Clone, Copy, Debug)]
pub struct StructurallyValidatedMediaTokenOutcome<'a> {
    response: &'a CallMediaTokenExchangeOutcome,
}

impl<'a> StructurallyValidatedMediaTokenOutcome<'a> {
    /// Borrow the original response after structure-level checks have
    /// passed.
    pub fn response(&self) -> &'a CallMediaTokenExchangeOutcome {
        self.response
    }

    /// Borrow the participant binding whose tuple/TTL/issuer anchor
    /// has been structurally checked.
    pub fn participant_binding(&self) -> &'a CallMediaParticipantBinding {
        &self.response.participant_binding
    }

    /// Detached service signature material that still requires host-side
    /// Ed25519 verification.
    pub fn service_signature(&self) -> &'a str {
        &self.response.service_signature
    }

    /// Participant-binding signature material that still requires
    /// host-side Ed25519 verification.
    pub fn participant_binding_signature(&self) -> &'a str {
        &self.response.participant_binding.sig
    }
}

/// Structurally validate a [`CallMediaTokenExchangeOutcome`] against the realm's
/// current media service anchor and the call state the caller committed
/// to.
///
/// On success, returns a [`StructurallyValidatedMediaTokenOutcome`]
/// marker around the borrowed response. On failure, returns a typed
/// [`MediaTokenError`] whose
/// [`MediaTokenError::kind`] matches one of the five CKP-0010
/// rejection codes the chime SDK guarantees to surface (CALL-2).
///
/// This helper structurally validates the binding tuple, TTL, and
/// service-id anchor. Cryptographic verification of
/// `service_signature` and `participant_binding.sig` is deferred to a
/// follow-up (`TODO(R3.1)`) once the SDK's
/// `verify_service_signature` lands. Until then, callers MUST treat
/// the returned value as structure-only evidence and gate any SFrame
/// keying on the host application's own signature check.
pub fn structurally_validate_media_token_outcome<'response>(
    response: &'response CallMediaTokenExchangeOutcome,
    ctx: &MediaTokenStructuralValidationContext<'_>,
) -> Result<StructurallyValidatedMediaTokenOutcome<'response>, MediaTokenError> {
    // ── 1. Anchor: `participant_binding.issuer_kid` MUST resolve to
    // the realm's current `ck.realm.media_service.service_id`. We
    // accept either a plain service id ("did:web:host:media") or a
    // `did#kid` form — the fragment may rotate across epochs so we
    // only require the DID portion to match the anchor. The opaque
    // `service_signature` blob is treated as cryptographic material;
    // chime does not parse the (implementation-defined) wire format
    // here. The signature verification itself is deferred to R3.1.
    let binding_issuer_did = strip_kid_fragment(&response.participant_binding.issuer_kid);
    if binding_issuer_did != ctx.current_media_service_id {
        return Err(MediaTokenError::TokenIssuerUnauthorised {
            observed_kid: response.participant_binding.issuer_kid.clone(),
            expected_service_id: ctx.current_media_service_id.to_owned(),
        });
    }

    // ── 2. Focus mismatch: the binding's focus_id MUST equal the
    // committed session_focus (when present) and the focus the caller
    // requested. The two-step check distinguishes a server-side
    // incorrect routing (binding != committed) from a client-side focus
    // selection bug (requested != binding).
    if response.participant_binding.focus_id != ctx.requested_focus_id {
        return Err(MediaTokenError::FocusMismatch {
            requested_focus_id: ctx.requested_focus_id.to_owned(),
            binding_focus_id: response.participant_binding.focus_id.clone(),
            committed_focus_id: None,
        });
    }
    if let Some(committed) = ctx.committed_session_focus
        && response.participant_binding.focus_id != committed
    {
        return Err(MediaTokenError::FocusMismatch {
            requested_focus_id: ctx.requested_focus_id.to_owned(),
            binding_focus_id: response.participant_binding.focus_id.clone(),
            committed_focus_id: Some(committed.to_owned()),
        });
    }

    // ── 3. Participant binding tuple match (realm/call/actor/device).
    let binding = &response.participant_binding;
    if &binding.realm_id != ctx.realm_id {
        return Err(MediaTokenError::ParticipantBindingInvalid {
            reason: format!(
                "realm_id mismatch: binding `{}` vs request `{}`",
                binding.realm_id, ctx.realm_id
            ),
        });
    }
    if &binding.call_id != ctx.call_id {
        return Err(MediaTokenError::ParticipantBindingInvalid {
            reason: format!(
                "call_id mismatch: binding `{}` vs request `{}`",
                binding.call_id, ctx.call_id
            ),
        });
    }
    if &binding.actor_id != ctx.actor_id {
        return Err(MediaTokenError::ParticipantBindingInvalid {
            reason: format!(
                "actor_id mismatch: binding `{}` vs request `{}`",
                binding.actor_id, ctx.actor_id
            ),
        });
    }
    if &binding.device_id != ctx.device_id {
        return Err(MediaTokenError::ParticipantBindingInvalid {
            reason: format!(
                "device_id mismatch: binding `{}` vs request `{}`",
                binding.device_id, ctx.device_id
            ),
        });
    }
    if binding.scheme != CallMediaParticipantBinding::SCHEME {
        return Err(MediaTokenError::ParticipantBindingInvalid {
            reason: format!(
                "scheme mismatch: expected `{}`, got `{}`",
                CallMediaParticipantBinding::SCHEME,
                binding.scheme
            ),
        });
    }

    // ── 4. TTL within the spec ceiling. The SDK helper enforces
    // `0 < remaining <= MEDIA_TOKEN_TTL_MAX_SECS`.
    if let Err(err) = cokret::validate_token_ttl(ctx.now, response.expires_at) {
        return Err(MediaTokenError::ParticipantBindingInvalid {
            reason: format!("{err}"),
        });
    }
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

    // ── 5. TODO(R3.1): once the SDK exposes a service-key
    // verification helper, validate `response.service_signature` and
    // `binding.sig` against the resolved media-service public key.
    // Until then we only return a structure-validation marker. Host
    // applications must perform Ed25519 verification before SFrame
    // keying.

    Ok(StructurallyValidatedMediaTokenOutcome { response })
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

fn strip_kid_fragment(kid: &str) -> &str {
    // `did:web:host:media#kid-2026-05` → `did:web:host:media`. The
    // fragment is the key identifier within the DID document; the
    // anchor check operates on the DID itself.
    kid.split_once('#').map(|(did, _)| did).unwrap_or(kid)
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use cokret::{CallId, DeviceId, Did, RealmId};

    use super::*;

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

    fn good_response(now: DateTime<Utc>) -> CallMediaTokenExchangeOutcome {
        let expires_at = now + Duration::seconds(300);
        CallMediaTokenExchangeOutcome {
            focus_id: "ck:focus:01".to_owned(),
            backend_type: "livekit".to_owned(),
            connect_url: "wss://media.example/livekit".to_owned(),
            backend_token: "livekit-jwt-token".to_owned(),
            participant_identity: "ck:rtc_participant:01904100-0000-7000-8000-000000000003"
                .to_owned(),
            participant_binding: CallMediaParticipantBinding {
                scheme: CallMediaParticipantBinding::SCHEME.to_owned(),
                sig: "stub-sig".to_owned(),
                issuer_kid: "did:web:media.example:media#kid-1".to_owned(),
                realm_id: realm(),
                call_id: call(),
                focus_id: "ck:focus:01".to_owned(),
                actor_id: actor(),
                device_id: device(),
                participant_identity: "ck:rtc_participant:01904100-0000-7000-8000-000000000003"
                    .to_owned(),
                expires_at,
            },
            expires_at,
            service_signature: "did:web:media.example:media#kid-1:detached-sig".to_owned(),
        }
    }

    fn good_ctx<'a>(
        now: DateTime<Utc>,
        realm_id: &'a RealmId,
        call_id: &'a CallId,
        actor_id: &'a Did,
        device_id: &'a DeviceId,
    ) -> MediaTokenStructuralValidationContext<'a> {
        MediaTokenStructuralValidationContext {
            current_media_service_id: "did:web:media.example:media",
            committed_session_focus: Some("ck:focus:01"),
            requested_focus_id: "ck:focus:01",
            realm_id,
            call_id,
            actor_id,
            device_id,
            now,
        }
    }

    #[test]
    fn happy_path_passes() {
        let now = Utc::now();
        let response = good_response(now);
        let realm_id = realm();
        let call_id = call();
        let actor_id = actor();
        let device_id = device();
        let ctx = good_ctx(now, &realm_id, &call_id, &actor_id, &device_id);
        let structurally_validated =
            structurally_validate_media_token_outcome(&response, &ctx).unwrap();
        assert_eq!(
            structurally_validated.response().participant_identity,
            response.participant_identity
        );
        assert_eq!(
            structurally_validated.participant_binding_signature(),
            "stub-sig"
        );
    }

    #[test]
    fn rejects_token_issuer_unauthorised_via_binding_kid() {
        let now = Utc::now();
        let mut response = good_response(now);
        response.participant_binding.issuer_kid = "did:web:rogue.example:media#k".to_owned();
        let realm_id = realm();
        let call_id = call();
        let actor_id = actor();
        let device_id = device();
        let ctx = good_ctx(now, &realm_id, &call_id, &actor_id, &device_id);
        let err = structurally_validate_media_token_outcome(&response, &ctx).unwrap_err();
        assert_eq!(err.kind(), PushErrorKind::TokenIssuerUnauthorised);
    }

    #[test]
    fn rejects_focus_mismatch() {
        let now = Utc::now();
        let response = good_response(now);
        let realm_id = realm();
        let call_id = call();
        let actor_id = actor();
        let device_id = device();
        let mut ctx = good_ctx(now, &realm_id, &call_id, &actor_id, &device_id);
        ctx.requested_focus_id = "ck:focus:02";
        let err = structurally_validate_media_token_outcome(&response, &ctx).unwrap_err();
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
        let response = good_response(now);
        let realm_id = realm();
        let call_id = call();
        let actor_id = actor();
        let device_id = device();
        let mut ctx = good_ctx(now, &realm_id, &call_id, &actor_id, &device_id);
        ctx.committed_session_focus = Some("ck:focus:committed-other");
        let err = structurally_validate_media_token_outcome(&response, &ctx).unwrap_err();
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
        let mut response = good_response(now);
        response.participant_binding.device_id =
            DeviceId::new("ck:device:01904100-0000-7000-8000-000000000099".to_owned()).unwrap();
        let realm_id = realm();
        let call_id = call();
        let actor_id = actor();
        let device_id = device();
        let ctx = good_ctx(now, &realm_id, &call_id, &actor_id, &device_id);
        let err = structurally_validate_media_token_outcome(&response, &ctx).unwrap_err();
        assert_eq!(err.kind(), PushErrorKind::ParticipantBindingInvalid);
    }

    #[test]
    fn rejects_expired_ttl() {
        let now = Utc::now();
        let mut response = good_response(now);
        // 10 minutes in the past — already expired.
        response.expires_at = now - Duration::seconds(600);
        response.participant_binding.expires_at = response.expires_at;
        let realm_id = realm();
        let call_id = call();
        let actor_id = actor();
        let device_id = device();
        let ctx = good_ctx(now, &realm_id, &call_id, &actor_id, &device_id);
        let err = structurally_validate_media_token_outcome(&response, &ctx).unwrap_err();
        assert_eq!(err.kind(), PushErrorKind::ParticipantBindingInvalid);
    }

    #[test]
    fn rejects_ttl_above_ceiling() {
        let now = Utc::now();
        let mut response = good_response(now);
        // > 600s ceiling.
        response.expires_at = now + Duration::seconds(700);
        response.participant_binding.expires_at = response.expires_at;
        let realm_id = realm();
        let call_id = call();
        let actor_id = actor();
        let device_id = device();
        let ctx = good_ctx(now, &realm_id, &call_id, &actor_id, &device_id);
        let err = structurally_validate_media_token_outcome(&response, &ctx).unwrap_err();
        assert_eq!(err.kind(), PushErrorKind::ParticipantBindingInvalid);
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
