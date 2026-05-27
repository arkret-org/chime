//! Push registration error types and HTTP status classification.

use std::fmt;
use std::time::{Duration, SystemTime};

use thiserror::Error;

use super::urls::{redact_url, redact_webpush_endpoint};
use super::wire::ContrixErrorEnvelope;

/// Stable high-level category for push registration failures.
///
/// Stability: `1.0`-stable. New variants are additive; matching against
/// the enum should always include a wildcard arm to forward-compat
/// against future error categories. Renaming or removing a variant
/// requires a major SemVer bump.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PushErrorKind {
    MissingField,
    InvalidPlatform,
    InvalidPushGatewayUrl,
    InvalidWebPushEndpoint,
    WebPushEndpointNotAllowed,
    ForbiddenPushGatewayQueryParam,
    InvalidHeader,
    Unauthenticated,
    CapabilityDenied,
    RateLimited,
    TemporarilyUnavailable,
    DuplicateConflict,
    NotFound,
    /// HTTP 410 Gone — the push token (or registration) has been retired and
    /// callers should drop it locally rather than retry.
    Gone,
    SchemaViolation,
    NetworkTimeout,
    Network,
    InvalidResponse,
    HttpStatus,
    /// Round 4 (spec a77b995) — federation sender used an obsolete member
    /// delivery binding frontier. The response carries
    /// `new_recipient_service_did` + `handover_frontier`; chime
    /// consumers MUST resolve the current binding and retry against the
    /// new recipient rather than re-issuing the same wakeup.
    DeliveryBindingStale,
    /// Round 4 — sender continued using a previous `recipient_service_did`
    /// after the handover grace window expired. Sender MUST resolve the
    /// current binding and retry there. Treat as terminal for the old
    /// recipient.
    DeliveryBindingHandedOver,
    /// Round 4 — idempotency cache replay served only as a historical
    /// diagnostic after key or binding state changed. Receivers MUST NOT
    /// perform new reducer side effects; in particular chime consumers
    /// MUST NOT trigger another push fanout from a `historical_only`
    /// response.
    HistoricalOnly,
    // ── R3 (CXP-0010 media binding + agent lifecycle, spec b47ff6ec) ─────
    // The variants below mirror the 20 new error codes added in the SDK
    // (see `contrix_core::error`). Chime mirrors the media-binding,
    // agent-lifecycle, and handle-homograph subsets because those are
    // the codes a push-SDK consumer can plausibly observe — either while
    // calling `cx.call.media.token_exchange` directly (`Media*`) or
    // while the user's agent/principal pair is in an inactive state
    // (`Agent*`) or while a handle homograph slips through wire-level
    // validation (`HandleHomographForbidden`).
    /// CXP-0010 — focus referenced by client does not match the
    /// committed `cx.call.state.session_focus`.
    FocusMismatch,
    /// CXP-0010 — media focus backend label not recognised by the SDK.
    /// Receivers MUST fail closed instead of forwarding the focus.
    UnknownFocusType,
    /// CXP-0010 — token issuer DID is not anchored to the current
    /// `cx.realm.media_service.service_id` epoch.
    TokenIssuerUnauthorised,
    /// CXP-0010 — `participant_binding` signature, tuple, or TTL does
    /// not validate against the realm media-service binding.
    ParticipantBindingInvalid,
    /// CXP-0010 — `participant_identity` returned by the focus does not
    /// match any entry in `cx.call.state.participants[]`.
    ParticipantIdentityUnrecognised,
    /// CXP-0010 — `cx.call.state.session_focus` is write-once; a
    /// concurrent commit attempt collided with the existing value.
    SessionFocusAlreadyCommitted,
    /// CXP-0010 — backend cloud attempted to supply the SFrame key
    /// material; MLS-Exporter is the only authorised source.
    E2eeKeySourceUnauthorised,
    /// CXP-0010 — recording artifact bypassed the Contrix blob upload
    /// pipeline (e.g. LiveKit Egress direct-to-S3).
    RecordingArtifactPipelineBypassed,
    /// CXP-0010 — realm's `cx.realm.media_service` is still configured
    /// as a single-endpoint legacy service; multi-focus binding is
    /// required for the requested operation.
    LegacySingleEndpointMediaService,
    /// CXP-0010 — chosen focus is unavailable to this client (e.g. the
    /// focus has been retired or the client is on an unsupported
    /// platform); callers MUST surface this rather than silently
    /// downgrading the media path.
    FocusUnavailableForClient,
    /// Agent lifecycle — pairing request expired before completion.
    PairingRequestExpired,
    /// Agent lifecycle — supplied proof signature did not validate.
    ProofInvalid,
    /// Agent lifecycle — verification method does not match the
    /// asserted principal.
    VerificationMethodPrincipalMismatch,
    /// Agent lifecycle — agent principal is currently paused.
    AgentPaused,
    /// Agent lifecycle — agent principal has been deactivated
    /// (terminal; no resume path).
    AgentDeactivated,
    /// Agent lifecycle — approval token already consumed.
    ApprovalAlreadyConsumed,
    /// Agent lifecycle — sidecar thread creation was denied by policy.
    SidecarCreateDenied,
    /// Agent lifecycle — actor kind is reducer-managed and cannot be
    /// mutated through the requested surface.
    ActorKindReducerManaged,
    /// Recovery — recovery witness revoke lagged behind the policy
    /// timeline; receivers should retry after the witness catches up.
    RecoveryWitnessRevokeLagging,
    /// Handle — wire-level NFC + UTS#39 confusable-skeleton + script-mix
    /// rejection. The handle MUST NOT be created or resolved.
    HandleHomographForbidden,
}

impl PushErrorKind {
    /// Stable bit position used by retry-policy bitmasks. Hand-assigned
    /// so `#[non_exhaustive]` additions never silently reorder existing
    /// callers' masks.
    pub const fn ordinal(self) -> u8 {
        match self {
            Self::MissingField => 0,
            Self::InvalidPlatform => 1,
            Self::InvalidPushGatewayUrl => 2,
            Self::InvalidWebPushEndpoint => 3,
            Self::WebPushEndpointNotAllowed => 4,
            Self::ForbiddenPushGatewayQueryParam => 5,
            Self::InvalidHeader => 6,
            Self::Unauthenticated => 7,
            Self::CapabilityDenied => 8,
            Self::RateLimited => 9,
            Self::TemporarilyUnavailable => 10,
            Self::DuplicateConflict => 11,
            Self::NotFound => 12,
            Self::Gone => 13,
            Self::SchemaViolation => 14,
            Self::NetworkTimeout => 15,
            Self::Network => 16,
            Self::InvalidResponse => 17,
            Self::HttpStatus => 18,
            // Round 4 (spec a77b995) — additions are bit-position
            // appended; never reorder existing ones.
            Self::DeliveryBindingStale => 19,
            Self::DeliveryBindingHandedOver => 20,
            Self::HistoricalOnly => 21,
            // R3 (spec b47ff6ec) — bit positions appended; never reorder.
            // (CALL-2 + ERR-1) Codes ordered to keep media-binding /
            // agent-lifecycle / handle subgroups contiguous.
            Self::FocusMismatch => 22,
            Self::UnknownFocusType => 23,
            Self::TokenIssuerUnauthorised => 24,
            Self::ParticipantBindingInvalid => 25,
            Self::ParticipantIdentityUnrecognised => 26,
            Self::SessionFocusAlreadyCommitted => 27,
            Self::E2eeKeySourceUnauthorised => 28,
            Self::RecordingArtifactPipelineBypassed => 29,
            Self::LegacySingleEndpointMediaService => 30,
            Self::FocusUnavailableForClient => 31,
            // R3 ordinals ≥ 32 spill outside the u32 retry mask. The
            // codes below are not retry candidates anyway — they are
            // terminal classifications surfaced through the `kind()`
            // path. We saturate at 31 so the existing `with_disabled_kinds`
            // call sites keep compiling without panicking on shift
            // overflow; callers MUST NOT add them to the retry mask.
            Self::PairingRequestExpired
            | Self::ProofInvalid
            | Self::VerificationMethodPrincipalMismatch
            | Self::AgentPaused
            | Self::AgentDeactivated
            | Self::ApprovalAlreadyConsumed
            | Self::SidecarCreateDenied
            | Self::ActorKindReducerManaged
            | Self::RecoveryWitnessRevokeLagging
            | Self::HandleHomographForbidden => 31,
        }
    }

    /// R3 (CALL-2) — the five CXP-0010 codes the chime SDK guarantees
    /// will be surfaced as typed `PushErrorKind` variants when the
    /// underlying transport returns a media-token error. Consumers can
    /// use this helper to branch the call UI without listing every
    /// variant by hand.
    pub const fn is_media_token_rejection(self) -> bool {
        matches!(
            self,
            Self::UnknownFocusType
                | Self::TokenIssuerUnauthorised
                | Self::ParticipantBindingInvalid
                | Self::FocusMismatch
                | Self::LegacySingleEndpointMediaService
        )
    }

    /// R3 — full set of CXP-0010 media-binding error codes (the
    /// rejection subset above plus the additional codes that may be
    /// raised by the server but are not flagged in CALL-2). Useful for
    /// telemetry that wants to label the wider media-binding bucket.
    pub const fn is_media_binding_code(self) -> bool {
        matches!(
            self,
            Self::UnknownFocusType
                | Self::TokenIssuerUnauthorised
                | Self::ParticipantBindingInvalid
                | Self::FocusMismatch
                | Self::LegacySingleEndpointMediaService
                | Self::ParticipantIdentityUnrecognised
                | Self::SessionFocusAlreadyCommitted
                | Self::E2eeKeySourceUnauthorised
                | Self::RecordingArtifactPipelineBypassed
                | Self::FocusUnavailableForClient
        )
    }

    /// R3 — agent-lifecycle subset of the mirrored error codes.
    pub const fn is_agent_lifecycle_code(self) -> bool {
        matches!(
            self,
            Self::PairingRequestExpired
                | Self::ProofInvalid
                | Self::VerificationMethodPrincipalMismatch
                | Self::AgentPaused
                | Self::AgentDeactivated
                | Self::ApprovalAlreadyConsumed
                | Self::SidecarCreateDenied
                | Self::ActorKindReducerManaged
        )
    }

    /// Round 4 — `historical_only` is a diagnostic surface: the server
    /// served a cached response after key/binding state changed and the
    /// receiver MUST NOT take any new action on it (no push refanout,
    /// no retry, no state mutation). Callers can branch on this when
    /// they need to suppress side effects rather than treat it as an
    /// error.
    pub const fn is_diagnostic_only(self) -> bool {
        matches!(self, Self::HistoricalOnly)
    }

    /// Round 4 — `delivery_binding_stale` and `delivery_binding_handed_over`
    /// both signal "stop talking to this recipient and resolve the
    /// current binding". Consumers SHOULD use this helper rather than
    /// matching the two variants by hand so future additions stay
    /// covered.
    pub const fn is_delivery_binding_signal(self) -> bool {
        matches!(
            self,
            Self::DeliveryBindingStale | Self::DeliveryBindingHandedOver
        )
    }

    /// Map a Contrix `bridge/describe.failure_codes` string to a stable kind.
    ///
    /// Returns `None` when the code is not part of the contract, so callers can
    /// decide between treating it as `HttpStatus` or surfacing the raw code.
    pub fn from_failure_code(code: &str) -> Option<Self> {
        // Round 4 — pull the three new wire codes from the SDK's
        // canonical constants so chime's classification stays
        // byte-aligned with what soland/floria emit.
        if code == contrix::ERROR_CODE_DELIVERY_BINDING_STALE {
            return Some(Self::DeliveryBindingStale);
        }
        if code == contrix::ERROR_CODE_DELIVERY_BINDING_HANDED_OVER {
            return Some(Self::DeliveryBindingHandedOver);
        }
        if code == contrix::ERROR_CODE_HISTORICAL_ONLY {
            return Some(Self::HistoricalOnly);
        }
        // R3 (spec b47ff6ec) — CXP-0010 media-binding + agent-lifecycle
        // + handle homograph codes. Sourced from the SDK constants
        // (in the `contrix::error` module — the R3 codes are not
        // glob-reexported at the crate root yet) so chime stays
        // byte-aligned with soland/floria emission.
        if code == contrix::error::ERROR_CODE_FOCUS_MISMATCH {
            return Some(Self::FocusMismatch);
        }
        if code == contrix::error::ERROR_CODE_UNKNOWN_FOCUS_TYPE {
            return Some(Self::UnknownFocusType);
        }
        if code == contrix::error::ERROR_CODE_TOKEN_ISSUER_UNAUTHORISED {
            return Some(Self::TokenIssuerUnauthorised);
        }
        if code == contrix::error::ERROR_CODE_PARTICIPANT_BINDING_INVALID {
            return Some(Self::ParticipantBindingInvalid);
        }
        if code == contrix::error::ERROR_CODE_PARTICIPANT_IDENTITY_UNRECOGNISED {
            return Some(Self::ParticipantIdentityUnrecognised);
        }
        if code == contrix::error::ERROR_CODE_SESSION_FOCUS_ALREADY_COMMITTED {
            return Some(Self::SessionFocusAlreadyCommitted);
        }
        if code == contrix::error::ERROR_CODE_E2EE_KEY_SOURCE_UNAUTHORISED {
            return Some(Self::E2eeKeySourceUnauthorised);
        }
        if code == contrix::error::ERROR_CODE_RECORDING_ARTIFACT_PIPELINE_BYPASSED {
            return Some(Self::RecordingArtifactPipelineBypassed);
        }
        if code == contrix::error::ERROR_CODE_LEGACY_SINGLE_ENDPOINT_MEDIA_SERVICE {
            return Some(Self::LegacySingleEndpointMediaService);
        }
        if code == contrix::error::ERROR_CODE_FOCUS_UNAVAILABLE_FOR_CLIENT {
            return Some(Self::FocusUnavailableForClient);
        }
        if code == contrix::error::ERROR_CODE_PAIRING_REQUEST_EXPIRED {
            return Some(Self::PairingRequestExpired);
        }
        if code == contrix::error::ERROR_CODE_PROOF_INVALID {
            return Some(Self::ProofInvalid);
        }
        if code == contrix::error::ERROR_CODE_VERIFICATION_METHOD_PRINCIPAL_MISMATCH {
            return Some(Self::VerificationMethodPrincipalMismatch);
        }
        if code == contrix::error::ERROR_CODE_AGENT_PAUSED {
            return Some(Self::AgentPaused);
        }
        if code == contrix::error::ERROR_CODE_AGENT_DEACTIVATED {
            return Some(Self::AgentDeactivated);
        }
        if code == contrix::error::ERROR_CODE_APPROVAL_ALREADY_CONSUMED {
            return Some(Self::ApprovalAlreadyConsumed);
        }
        if code == contrix::error::ERROR_CODE_SIDECAR_CREATE_DENIED {
            return Some(Self::SidecarCreateDenied);
        }
        if code == contrix::error::ERROR_CODE_ACTOR_KIND_REDUCER_MANAGED {
            return Some(Self::ActorKindReducerManaged);
        }
        if code == contrix::error::ERROR_CODE_RECOVERY_WITNESS_REVOKE_LAGGING {
            return Some(Self::RecoveryWitnessRevokeLagging);
        }
        if code == contrix::error::ERROR_CODE_HANDLE_HOMOGRAPH_FORBIDDEN {
            return Some(Self::HandleHomographForbidden);
        }
        Some(match code {
            "unauthenticated" | "auth_expired" | "soft_logged_out" => Self::Unauthenticated,
            "capability_denied" => Self::CapabilityDenied,
            "rate_limited" => Self::RateLimited,
            "temporarily_unavailable" => Self::TemporarilyUnavailable,
            "duplicate_conflict" => Self::DuplicateConflict,
            "not_found" => Self::NotFound,
            "gone" | "registration_gone" | "push_token_gone" => Self::Gone,
            "schema_violation" | "bad_json" | "bad_query" | "missing_param" | "invalid_param" => {
                Self::SchemaViolation
            }
            _ => return None,
        })
    }
}

#[derive(Error)]
pub enum PushRegistrationError {
    #[error("missing required Contrix push field: {0}")]
    MissingField(&'static str),
    #[error("unsupported push platform: {0}")]
    InvalidPlatform(String),
    #[error("invalid push gateway URL: {reason}")]
    InvalidPushGatewayUrl { url: String, reason: String },
    #[error("invalid WebPush endpoint: {reason}")]
    InvalidWebPushEndpoint { endpoint: String, reason: String },
    #[error("WebPush endpoint origin is not allowed: {origin}")]
    WebPushEndpointNotAllowed { endpoint: String, origin: String },
    #[error("push gateway URL contains forbidden query parameter: {param}")]
    ForbiddenPushGatewayQueryParam { param: String },
    #[error("invalid HTTP header `{name}`")]
    InvalidHeader { name: String },
    #[error("Contrix service returned HTTP {status}")]
    HttpStatus {
        status: u16,
        kind: PushErrorKind,
        error: Option<Box<ContrixErrorEnvelope>>,
        body: String,
        retry_after: Option<String>,
        request_id: Option<String>,
    },
    #[cfg(feature = "http")]
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

impl fmt::Debug for PushRegistrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingField(field) => f.debug_tuple("MissingField").field(field).finish(),
            Self::InvalidPlatform(platform) => {
                f.debug_tuple("InvalidPlatform").field(platform).finish()
            }
            Self::InvalidPushGatewayUrl { url, reason } => f
                .debug_struct("InvalidPushGatewayUrl")
                .field("url", &redact_url(url))
                .field("reason", reason)
                .finish(),
            Self::InvalidWebPushEndpoint { endpoint, reason } => f
                .debug_struct("InvalidWebPushEndpoint")
                .field("endpoint", &redact_webpush_endpoint(endpoint))
                .field("reason", reason)
                .finish(),
            Self::WebPushEndpointNotAllowed { endpoint, origin } => f
                .debug_struct("WebPushEndpointNotAllowed")
                .field("endpoint", &redact_webpush_endpoint(endpoint))
                .field("origin", origin)
                .finish(),
            Self::ForbiddenPushGatewayQueryParam { param } => f
                .debug_struct("ForbiddenPushGatewayQueryParam")
                .field("param", param)
                .finish(),
            Self::InvalidHeader { name } => {
                f.debug_struct("InvalidHeader").field("name", name).finish()
            }
            Self::HttpStatus {
                status,
                kind,
                error,
                body,
                retry_after,
                request_id,
            } => f
                .debug_struct("HttpStatus")
                .field("status", status)
                .field("kind", kind)
                .field("error", error)
                .field("body_len", &body.len())
                .field("retry_after", retry_after)
                .field("request_id", request_id)
                .finish(),
            #[cfg(feature = "http")]
            Self::Http(error) => f.debug_tuple("Http").field(error).finish(),
            Self::Json(error) => f.debug_tuple("Json").field(error).finish(),
        }
    }
}

impl PushRegistrationError {
    pub fn kind(&self) -> PushErrorKind {
        match self {
            Self::MissingField(_) => PushErrorKind::MissingField,
            Self::InvalidPlatform(_) => PushErrorKind::InvalidPlatform,
            Self::InvalidPushGatewayUrl { .. } => PushErrorKind::InvalidPushGatewayUrl,
            Self::InvalidWebPushEndpoint { .. } => PushErrorKind::InvalidWebPushEndpoint,
            Self::WebPushEndpointNotAllowed { .. } => PushErrorKind::WebPushEndpointNotAllowed,
            Self::ForbiddenPushGatewayQueryParam { .. } => {
                PushErrorKind::ForbiddenPushGatewayQueryParam
            }
            Self::InvalidHeader { .. } => PushErrorKind::InvalidHeader,
            Self::HttpStatus { kind, .. } => *kind,
            #[cfg(feature = "http")]
            Self::Http(error) if error.is_timeout() => PushErrorKind::NetworkTimeout,
            #[cfg(feature = "http")]
            Self::Http(_) => PushErrorKind::Network,
            Self::Json(_) => PushErrorKind::InvalidResponse,
        }
    }

    pub fn status(&self) -> Option<u16> {
        match self {
            Self::HttpStatus { status, .. } => Some(*status),
            _ => None,
        }
    }

    pub fn contrix_error(&self) -> Option<&ContrixErrorEnvelope> {
        match self {
            Self::HttpStatus { error, .. } => error.as_deref(),
            _ => None,
        }
    }

    pub fn retry_after(&self) -> Option<&str> {
        match self {
            Self::HttpStatus { retry_after, .. } => retry_after.as_deref(),
            _ => None,
        }
    }

    pub fn retry_after_duration(&self) -> Option<Duration> {
        let value = self.retry_after()?;
        parse_retry_after(value)
    }

    pub fn request_id(&self) -> Option<&str> {
        match self {
            Self::HttpStatus {
                request_id, error, ..
            } => request_id.as_deref().or_else(|| {
                error
                    .as_deref()
                    .and_then(|envelope| envelope.request_id.as_deref())
            }),
            _ => None,
        }
    }

    #[cfg(feature = "http")]
    pub(super) fn is_retryable(&self) -> bool {
        matches!(
            self.kind(),
            PushErrorKind::RateLimited
                | PushErrorKind::TemporarilyUnavailable
                | PushErrorKind::NetworkTimeout
        )
    }
}

#[cfg(any(test, feature = "http"))]
pub(super) fn classify_http_error(
    status: u16,
    error: Option<&ContrixErrorEnvelope>,
) -> PushErrorKind {
    if let Some(code) = error.map(|envelope| envelope.error.code.as_str())
        && let Some(kind) = PushErrorKind::from_failure_code(code)
    {
        return kind;
    }

    match status {
        401 => PushErrorKind::Unauthenticated,
        403 => PushErrorKind::CapabilityDenied,
        404 => PushErrorKind::NotFound,
        409 => PushErrorKind::DuplicateConflict,
        410 => PushErrorKind::Gone,
        400 | 422 => PushErrorKind::SchemaViolation,
        429 => PushErrorKind::RateLimited,
        503 => PushErrorKind::TemporarilyUnavailable,
        _ => PushErrorKind::HttpStatus,
    }
}

pub(super) fn parse_retry_after(value: &str) -> Option<Duration> {
    if let Ok(seconds) = value.trim().parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }

    let retry_at = httpdate::parse_http_date(value).ok()?;
    let now = SystemTime::now();
    retry_at.duration_since(now).ok().or(Some(Duration::ZERO))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::push::wire::ContrixError;

    #[test]
    fn classifies_contrix_error_codes() {
        let envelope = ContrixErrorEnvelope {
            ok: false,
            error: ContrixError {
                code: "capability_denied".to_owned(),
                message: "denied".to_owned(),
                retry_after_ms: None,
                details: None,
            },
            request_id: Some("cx:request:test".to_owned()),
        };

        assert_eq!(
            classify_http_error(403, Some(&envelope)),
            PushErrorKind::CapabilityDenied
        );
    }

    #[test]
    fn maps_410_gone_status() {
        assert_eq!(classify_http_error(410, None), PushErrorKind::Gone);
    }

    #[test]
    fn from_failure_code_covers_contract() {
        assert_eq!(
            PushErrorKind::from_failure_code("rate_limited"),
            Some(PushErrorKind::RateLimited)
        );
        assert_eq!(
            PushErrorKind::from_failure_code("registration_gone"),
            Some(PushErrorKind::Gone)
        );
        assert_eq!(PushErrorKind::from_failure_code("unknown_code"), None);
    }

    #[test]
    fn round4_failure_codes_classify() {
        // B5: chime must recognise the three round-4 wire codes that
        // floria/soland forward so consumers can branch on them.
        assert_eq!(
            PushErrorKind::from_failure_code(contrix::ERROR_CODE_DELIVERY_BINDING_STALE),
            Some(PushErrorKind::DeliveryBindingStale)
        );
        assert_eq!(
            PushErrorKind::from_failure_code(contrix::ERROR_CODE_DELIVERY_BINDING_HANDED_OVER),
            Some(PushErrorKind::DeliveryBindingHandedOver)
        );
        assert_eq!(
            PushErrorKind::from_failure_code(contrix::ERROR_CODE_HISTORICAL_ONLY),
            Some(PushErrorKind::HistoricalOnly)
        );
    }

    #[test]
    fn historical_only_is_diagnostic_only() {
        // B5: `historical_only` MUST be treated as diagnostic — no
        // re-action, no fanout. Callers branch on this helper rather
        // than matching the variant by hand.
        assert!(PushErrorKind::HistoricalOnly.is_diagnostic_only());
        assert!(!PushErrorKind::DeliveryBindingStale.is_diagnostic_only());
        assert!(!PushErrorKind::DeliveryBindingHandedOver.is_diagnostic_only());
    }

    #[test]
    fn delivery_binding_signals_grouped() {
        assert!(PushErrorKind::DeliveryBindingStale.is_delivery_binding_signal());
        assert!(PushErrorKind::DeliveryBindingHandedOver.is_delivery_binding_signal());
        assert!(!PushErrorKind::HistoricalOnly.is_delivery_binding_signal());
        assert!(!PushErrorKind::RateLimited.is_delivery_binding_signal());
    }

    #[test]
    fn round4_codes_classify_against_409_and_200_statuses() {
        // Spec status mapping: stale/handed_over → 409, historical_only → 200.
        let envelope = ContrixErrorEnvelope {
            ok: false,
            error: ContrixError {
                code: contrix::ERROR_CODE_DELIVERY_BINDING_STALE.to_owned(),
                message: "stale".to_owned(),
                retry_after_ms: None,
                details: None,
            },
            request_id: None,
        };
        assert_eq!(
            classify_http_error(409, Some(&envelope)),
            PushErrorKind::DeliveryBindingStale
        );

        let envelope = ContrixErrorEnvelope {
            ok: false,
            error: ContrixError {
                code: contrix::ERROR_CODE_HISTORICAL_ONLY.to_owned(),
                message: "diagnostic".to_owned(),
                retry_after_ms: None,
                details: None,
            },
            request_id: None,
        };
        assert_eq!(
            classify_http_error(200, Some(&envelope)),
            PushErrorKind::HistoricalOnly
        );
    }
}
