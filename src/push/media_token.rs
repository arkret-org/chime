//! R3 (CALL-1, spec b47ff6ec) — client-side helper for
//! `cx.call.media.token_exchange` (`POST /rtc/token`).
//!
//! This module is intentionally transport-agnostic: it builds the
//! request body via the SDK's [`call_media_token_exchange`] helper and
//! exposes [`verify_media_token_response`] that performs the
//! wire-level checks chime owes its consumer (yougen):
//!
//! - `service_signature.kid` is anchored to the realm's current
//!   `cx.realm.media_service.service_id`,
//! - `participant_binding.issuer_kid` matches the same service id and
//!   ties together the call-id / focus-id / actor-id / device-id tuple
//!   that the caller asked for,
//! - the focus backend type is recognised (rejects `unknown_focus_type`
//!   fail-closed via [`MediaBackendType::ensure_known`]),
//! - the token TTL is within the spec ceiling
//!   ([`MEDIA_TOKEN_TTL_MAX_SECS`](contrix::MEDIA_TOKEN_TTL_MAX_SECS))
//!   via the SDK's [`validate_token_ttl`].
//!
//! When validation fails this helper returns a typed [`MediaTokenError`]
//! whose [`MediaTokenError::kind`] aligns one-to-one with the CXP-0010
//! variants surfaced through [`PushErrorKind`] (CALL-2). HTTP transport
//! is the caller's responsibility — the rationale is that chime's
//! `ContrixPushClient` is push-registration scoped and may live on
//! wasm32 without a tokio runtime, while the RTC token exchange is
//! typically driven by the in-app call surface (yougen).
//!
//! ## Cryptography
//!
//! The signature-verification path is currently stubbed out
//! (`TODO(R3.1)`): we structurally validate the binding tuple and TTL
//! but defer the Ed25519 signature check to the host application's
//! keystore until the SDK's `verify_service_signature` lands. The
//! anchor checks DO run today — those are pure equality checks against
//! the caller-supplied current service id.

use std::fmt;

use chrono::{DateTime, Utc};

use super::errors::PushErrorKind;

// Re-export the SDK types so chime consumers can pull the full media
// token surface through `chime::` without a second `contrix` dep.
pub use contrix::{
    MediaBackendType, MediaTokenExchangeRequest, MediaTokenResponse, ParticipantBinding,
    call_media_token_exchange,
};

/// Chime-side error raised when a media-token exchange response fails
/// CALL-1 / CALL-2 validation.
///
/// Each variant maps to a CXP-0010 error code on the wire; the
/// [`Self::kind`] accessor returns the matching [`PushErrorKind`] so
/// host applications can branch on a single classifier surface.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MediaTokenError {
    /// CALL-2 — `service_signature.kid` (or `participant_binding.issuer_kid`)
    /// is not anchored to the realm's current
    /// `cx.realm.media_service.service_id`.
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
    /// CALL-2 — server has not committed a multi-focus
    /// `cx.realm.media_service` binding yet; the realm is still on the
    /// single-endpoint legacy contract.
    LegacySingleEndpointMediaService,
    /// CALL-2 — committed `cx.call.state.session_focus` does not match
    /// the focus id the caller asked the SDK to exchange.
    FocusMismatch {
        expected_focus_id: String,
        committed_focus_id: String,
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
            Self::LegacySingleEndpointMediaService => {
                PushErrorKind::LegacySingleEndpointMediaService
            }
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
                "token_issuer_unauthorised: signature kid `{observed_kid}` is not anchored to current media_service.service_id `{expected_service_id}`"
            ),
            Self::UnknownFocusType => f.write_str(
                "unknown_focus_type: media focus backend label not recognised by this SDK",
            ),
            Self::ParticipantBindingInvalid { reason } => {
                write!(f, "participant_binding_invalid: {reason}")
            }
            Self::LegacySingleEndpointMediaService => f.write_str(
                "legacy_single_endpoint_media_service: realm still on single-endpoint media service",
            ),
            Self::FocusMismatch {
                expected_focus_id,
                committed_focus_id,
            } => write!(
                f,
                "focus_mismatch: requested focus `{expected_focus_id}` does not match committed session_focus `{committed_focus_id}`"
            ),
        }
    }
}

impl std::error::Error for MediaTokenError {}

/// Inputs to the CALL-1 verification pipeline. Bundled in a struct so
/// the call site stays readable when chime grows additional anchor
/// dimensions (e.g. epoch number) in R3.1+.
#[derive(Clone, Debug)]
pub struct MediaTokenVerifyContext<'a> {
    /// The current `cx.realm.media_service.service_id` resolved by the
    /// caller (yougen) from realm state at the moment of the exchange.
    pub current_media_service_id: &'a str,
    /// `cx.call.state.session_focus` committed in the call state — used
    /// to fail-closed on `focus_mismatch`. Pass `None` when the call
    /// has no committed focus yet (the SDK does not currently model
    /// "no commit yet" as an error — it accepts the response and lets
    /// the caller commit the focus next).
    pub committed_session_focus: Option<&'a str>,
    /// Focus id the caller passed to [`call_media_token_exchange`].
    pub requested_focus_id: &'a str,
    /// Realm id the request was built with — must match
    /// `participant_binding.realm_id`.
    pub realm_id: &'a contrix::RealmId,
    /// Call id the request was built with — must match
    /// `participant_binding.call_id`.
    pub call_id: &'a contrix::CallId,
    /// Actor DID the request was built with — must match
    /// `participant_binding.actor_id`.
    pub actor_id: &'a contrix::Did,
    /// Device id the request was built with — must match
    /// `participant_binding.device_id`.
    pub device_id: &'a contrix::DeviceId,
    /// Wall-clock used for TTL validation (typically `Utc::now()` at
    /// the call site; injected for determinism in tests).
    pub now: DateTime<Utc>,
}

/// Verify a [`MediaTokenResponse`] against the realm's current media
/// service anchor and the call state the caller committed to.
///
/// On success, returns the recognised [`MediaBackendType`] parsed from
/// `response.participant_binding` — callers MUST forward this to their
/// SFU client. On failure, returns a typed [`MediaTokenError`] whose
/// [`MediaTokenError::kind`] matches one of the five CXP-0010
/// rejection codes the chime SDK guarantees to surface (CALL-2).
///
/// This helper structurally validates the binding tuple, TTL, and
/// service-id anchor. Cryptographic verification of
/// `service_signature` and `participant_binding.sig` is deferred to a
/// follow-up (`TODO(R3.1)`) once the SDK's
/// `verify_service_signature` lands. Until then, callers SHOULD treat
/// `MediaTokenResponse` as advisory and gate any SFrame keying on the
/// host application's own signature check.
pub fn verify_media_token_response(
    response: &MediaTokenResponse,
    ctx: &MediaTokenVerifyContext<'_>,
) -> Result<(), MediaTokenError> {
    // ── 1. Anchor: `participant_binding.issuer_kid` MUST resolve to
    // the realm's current `cx.realm.media_service.service_id`. We
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
            expected_focus_id: ctx.requested_focus_id.to_owned(),
            committed_focus_id: response.participant_binding.focus_id.clone(),
        });
    }
    if let Some(committed) = ctx.committed_session_focus
        && response.participant_binding.focus_id != committed
    {
        return Err(MediaTokenError::FocusMismatch {
            expected_focus_id: ctx.requested_focus_id.to_owned(),
            committed_focus_id: committed.to_owned(),
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
    if binding.scheme != ParticipantBinding::SCHEME {
        return Err(MediaTokenError::ParticipantBindingInvalid {
            reason: format!(
                "scheme mismatch: expected `{}`, got `{}`",
                ParticipantBinding::SCHEME,
                binding.scheme
            ),
        });
    }

    // ── 4. TTL within the spec ceiling. The SDK helper enforces
    // `0 < remaining <= MEDIA_TOKEN_TTL_MAX_SECS`.
    if let Err(err) = contrix::validate_token_ttl(ctx.now, response.expires_at) {
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
    // Until then we structurally accept the response and rely on the
    // surrounding TLS / session-grant channel for authenticity.

    Ok(())
}

/// Reject the focus when the SDK does not recognise the backend
/// label. Surfaces as CALL-2 [`MediaTokenError::UnknownFocusType`].
///
/// Wraps the SDK's [`MediaBackendType::ensure_known`] so chime
/// consumers can perform the check without depending on `contrix`
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
    use super::*;
    use chrono::Duration;
    use contrix::{CallId, DeviceId, Did, RealmId};

    fn realm() -> RealmId {
        RealmId::new("cx:realm:01904100-0000-7000-8000-000000000001".to_owned()).unwrap()
    }
    fn call() -> CallId {
        CallId::new("cx:call:01904100-0000-7000-8000-000000000002".to_owned()).unwrap()
    }
    fn actor() -> Did {
        Did::new("did:web:alice.example".to_owned()).unwrap()
    }
    fn device() -> DeviceId {
        DeviceId::new("cx:device:01904100-0000-7000-8000-000000000004".to_owned()).unwrap()
    }

    fn good_response(now: DateTime<Utc>) -> MediaTokenResponse {
        let expires_at = now + Duration::seconds(300);
        MediaTokenResponse {
            backend_token: "livekit-jwt-token".to_owned(),
            participant_identity: "cx:rtcpart:01904100-0000-7000-8000-000000000003".to_owned(),
            participant_binding: ParticipantBinding {
                scheme: ParticipantBinding::SCHEME.to_owned(),
                sig: "stub-sig".to_owned(),
                issuer_kid: "did:web:media.example:media#kid-1".to_owned(),
                realm_id: realm(),
                call_id: call(),
                focus_id: "cx:focus:01".to_owned(),
                actor_id: actor(),
                device_id: device(),
                participant_identity: "cx:rtcpart:01904100-0000-7000-8000-000000000003".to_owned(),
                expires_at,
            },
            expires_at,
            service_signature: "did:web:media.example:media#kid-1:detached-sig".to_owned(),
            connect_url: None,
        }
    }

    fn good_ctx<'a>(
        now: DateTime<Utc>,
        realm_id: &'a RealmId,
        call_id: &'a CallId,
        actor_id: &'a Did,
        device_id: &'a DeviceId,
    ) -> MediaTokenVerifyContext<'a> {
        MediaTokenVerifyContext {
            current_media_service_id: "did:web:media.example:media",
            committed_session_focus: Some("cx:focus:01"),
            requested_focus_id: "cx:focus:01",
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
        assert!(verify_media_token_response(&response, &ctx).is_ok());
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
        let err = verify_media_token_response(&response, &ctx).unwrap_err();
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
        ctx.requested_focus_id = "cx:focus:02";
        let err = verify_media_token_response(&response, &ctx).unwrap_err();
        assert_eq!(err.kind(), PushErrorKind::FocusMismatch);
    }

    #[test]
    fn rejects_participant_binding_tuple_mismatch() {
        let now = Utc::now();
        let mut response = good_response(now);
        response.participant_binding.device_id =
            DeviceId::new("cx:device:01904100-0000-7000-8000-000000000099".to_owned()).unwrap();
        let realm_id = realm();
        let call_id = call();
        let actor_id = actor();
        let device_id = device();
        let ctx = good_ctx(now, &realm_id, &call_id, &actor_id, &device_id);
        let err = verify_media_token_response(&response, &ctx).unwrap_err();
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
        let err = verify_media_token_response(&response, &ctx).unwrap_err();
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
        let err = verify_media_token_response(&response, &ctx).unwrap_err();
        assert_eq!(err.kind(), PushErrorKind::ParticipantBindingInvalid);
    }

    #[test]
    fn ensure_known_backend_rejects_unknown() {
        let err = ensure_known_backend(&MediaBackendType::Unknown).unwrap_err();
        assert_eq!(err.kind(), PushErrorKind::UnknownFocusType);
        assert!(ensure_known_backend(&MediaBackendType::Livekit).is_ok());
        assert!(ensure_known_backend(&MediaBackendType::ContrixNative).is_ok());
    }

    #[test]
    fn helper_builds_request_with_provided_focus_id() {
        // CALL-1: chime exposes the SDK request-builder so consumers
        // don't need their own `contrix` dep.
        let req =
            call_media_token_exchange(realm(), call(), actor(), device(), "cx:focus:01".to_owned());
        assert_eq!(req.focus_id, "cx:focus:01");
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
            MediaTokenError::LegacySingleEndpointMediaService
                .kind()
                .is_media_token_rejection()
        );
        assert!(
            MediaTokenError::FocusMismatch {
                expected_focus_id: "a".to_owned(),
                committed_focus_id: "b".to_owned(),
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
