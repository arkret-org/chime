//! Push registration error types and HTTP status classification.

use std::fmt;
use std::time::{Duration, SystemTime};

use thiserror::Error;

use super::urls::{redact_url, redact_webpush_endpoint};
use super::wire::ArkretErrorEnvelope;

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
    /// `new_recipient_service_id` + `handover_frontier`; chime
    /// consumers MUST resolve the current binding and retry against the
    /// new recipient rather than re-issuing the same wakeup.
    DeliveryBindingStale,
    /// Round 4 — sender continued using a previous `recipient_service_id`
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
    // ── R3 (AKP-0010 media binding + agent lifecycle, spec b47ff6ec) ─────
    // The variants below mirror the 20 new error codes added in the SDK
    // (see `arkret::error`). Chime mirrors the media-binding,
    // agent-lifecycle, and handle-homograph subsets because those are
    // the codes a push-SDK consumer can plausibly observe — either while
    // calling `ak.self.call.media.exchange.issue_token` directly (`Media*`) or
    // while the user's agent/principal pair is in an inactive state
    // (`Agent*`) or while a handle homograph slips through wire-level
    // validation (`HandleHomographForbidden`).
    /// AKP-0010 — focus referenced by client does not match the
    /// committed `ak.call.state.session_focus`.
    FocusMismatch,
    /// AKP-0010 — media focus backend label not recognised by the SDK.
    /// Receivers MUST fail closed instead of forwarding the focus.
    UnknownFocusType,
    /// AKP-0010 — token issuer DID is not anchored to the current
    /// `ak.realm.media_service.service_id` epoch.
    TokenIssuerUnauthorised,
    /// AKP-0010 — `participant_binding` signature, tuple, or TTL does
    /// not validate against the realm media-service binding. Chime's
    /// current structure-only media-token helper emits this for tuple
    /// and TTL failures; host-side Ed25519 verification remains
    /// responsible for signature failures until the SDK verifier lands.
    ParticipantBindingInvalid,
    /// AKP-0010 — `participant_identity` returned by the focus does not
    /// match any entry in `ak.call.state.participants[]`.
    ParticipantIdentityUnrecognised,
    /// AKP-0010 — `ak.call.state.session_focus` is write-once; a
    /// concurrent commit attempt collided with the existing value.
    SessionFocusAlreadyCommitted,
    /// AKP-0010 — backend cloud attempted to supply the SFrame key
    /// material; MLS-Exporter is the only authorised source.
    E2eeKeySourceUnauthorised,
    /// AKP-0010 — recording artifact bypassed the Arkret blob upload
    /// pipeline (e.g. LiveKit Egress direct-to-S3).
    RecordingArtifactPipelineBypassed,
    /// AKP-0010 — chosen focus is unavailable to this client (e.g. the
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
            Self::FocusUnavailableForClient => 30,
            Self::PairingRequestExpired => 31,
            Self::ProofInvalid => 32,
            Self::VerificationMethodPrincipalMismatch => 33,
            Self::AgentPaused => 34,
            Self::AgentDeactivated => 35,
            Self::ApprovalAlreadyConsumed => 36,
            Self::SidecarCreateDenied => 37,
            Self::ActorKindReducerManaged => 38,
            Self::RecoveryWitnessRevokeLagging => 39,
            Self::HandleHomographForbidden => 40,
        }
    }

    /// R3 (CALL-2) — the five AKP-0010 codes the chime SDK guarantees
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
        )
    }

    /// R3 — full set of AKP-0010 media-binding error codes (the
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

    /// Map a Arkret `bridge/describe.failure_codes` string to a stable kind.
    ///
    /// Returns `None` when the code is not part of the contract, so callers can
    /// decide between treating it as `HttpStatus` or surfacing the raw code.
    pub fn from_failure_code(code: &str) -> Option<Self> {
        // Canonical wire codes sourced from the SDK constants so chime's
        // classification stays byte-aligned with what soland/floria emit.
        // Top-level error codes are glob-reexported at the crate root;
        // reason-code classifications use SDK `arkret::error::REASON_*`
        // constants when the SDK exposes them.
        const CODE_MAP: &[(&str, PushErrorKind)] = &[
            (
                arkret::ErrorCode::UNAUTHENTICATED,
                PushErrorKind::Unauthenticated,
            ),
            (
                arkret::ErrorCode::AUTH_EXPIRED,
                PushErrorKind::Unauthenticated,
            ),
            (
                arkret::ErrorCode::SOFT_LOGGED_OUT,
                PushErrorKind::Unauthenticated,
            ),
            (
                arkret::ErrorCode::CAPABILITY_DENIED,
                PushErrorKind::CapabilityDenied,
            ),
            (arkret::ErrorCode::RATE_LIMITED, PushErrorKind::RateLimited),
            (
                arkret::ErrorCode::TEMPORARILY_UNAVAILABLE,
                PushErrorKind::TemporarilyUnavailable,
            ),
            (
                arkret::ErrorCode::DUPLICATE_CONFLICT,
                PushErrorKind::DuplicateConflict,
            ),
            (arkret::ErrorCode::NOT_FOUND, PushErrorKind::NotFound),
            (
                arkret::ErrorCode::SCHEMA_VIOLATION,
                PushErrorKind::SchemaViolation,
            ),
            (arkret::ErrorCode::BAD_JSON, PushErrorKind::SchemaViolation),
            (arkret::ErrorCode::BAD_QUERY, PushErrorKind::SchemaViolation),
            (
                arkret::ErrorCode::MISSING_PARAM,
                PushErrorKind::SchemaViolation,
            ),
            (
                arkret::ErrorCode::INVALID_PARAM,
                PushErrorKind::SchemaViolation,
            ),
            (
                arkret::ErrorCode::DELIVERY_BINDING_STALE,
                PushErrorKind::DeliveryBindingStale,
            ),
            (
                arkret::ErrorCode::DELIVERY_BINDING_HANDED_OVER,
                PushErrorKind::DeliveryBindingHandedOver,
            ),
            (
                arkret::ErrorCode::HISTORICAL_ONLY,
                PushErrorKind::HistoricalOnly,
            ),
            (
                arkret::error::ReasonCode::TOKEN_ISSUER_UNAUTHORISED,
                PushErrorKind::TokenIssuerUnauthorised,
            ),
            (
                arkret::error::ReasonCode::E2EE_KEY_SOURCE_UNAUTHORISED,
                PushErrorKind::E2eeKeySourceUnauthorised,
            ),
            (
                arkret::error::ReasonCode::RECORDING_ARTIFACT_PIPELINE_BYPASSED,
                PushErrorKind::RecordingArtifactPipelineBypassed,
            ),
        ];
        if let Some(&(_, kind)) = CODE_MAP.iter().find(|(c, _)| *c == code) {
            return Some(kind);
        }
        None
    }
}

#[derive(Error)]
pub enum PushRegistrationError {
    #[error("missing required Arkret push field: {0}")]
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
    #[error("invalid Arkret push field `{field}`: {reason}")]
    InvalidField { field: &'static str, reason: String },
    #[error("Arkret service returned HTTP {status}")]
    HttpStatus {
        status: u16,
        kind: PushErrorKind,
        error: Option<Box<ArkretErrorEnvelope>>,
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
            Self::InvalidField { field, reason } => f
                .debug_struct("InvalidField")
                .field("field", field)
                .field("reason", reason)
                .finish(),
            Self::HttpStatus {
                status,
                kind,
                error,
                body,
                retry_after,
                request_id,
            } => {
                let redacted_error = error.as_deref().map(RedactedArkretErrorEnvelope);
                f.debug_struct("HttpStatus")
                    .field("status", status)
                    .field("kind", kind)
                    .field("error", &redacted_error)
                    .field("body_len", &body.len())
                    .field("retry_after", retry_after)
                    .field("request_id", request_id)
                    .finish()
            }
            #[cfg(feature = "http")]
            Self::Http(error) => f.debug_tuple("Http").field(error).finish(),
            Self::Json(error) => f.debug_tuple("Json").field(error).finish(),
        }
    }
}

struct RedactedArkretErrorEnvelope<'a>(&'a ArkretErrorEnvelope);

impl fmt::Debug for RedactedArkretErrorEnvelope<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArkretErrorEnvelope")
            .field("ok", &self.0.ok)
            .field("code", &self.0.error.code)
            .field("message_present", &(!self.0.error.message.is_empty()))
            .field("retry_after_ms", &self.0.error.retry_after_ms)
            .field("details_present", &(!self.0.error.details.is_empty()))
            .field("request_id", &self.0.request_id)
            .finish()
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
            Self::InvalidField { .. } => PushErrorKind::SchemaViolation,
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

    pub fn arkret_error(&self) -> Option<&ArkretErrorEnvelope> {
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
                    .map(|envelope| envelope.request_id.as_str())
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
    error: Option<&ArkretErrorEnvelope>,
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
    use std::collections::BTreeMap;

    use super::*;
    use crate::push::wire::ArkretError;

    #[test]
    fn classifies_arkret_error_codes() {
        let envelope = ArkretErrorEnvelope {
            ok: false,
            error: ArkretError {
                code: arkret::ErrorCode::CAPABILITY_DENIED.to_owned(),
                message: "denied".to_owned(),
                retry_after_ms: None,
                details: BTreeMap::new(),
            },
            request_id: "ak:request:test".to_owned(),
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
            PushErrorKind::from_failure_code(arkret::ErrorCode::RATE_LIMITED),
            Some(PushErrorKind::RateLimited)
        );
        assert_eq!(PushErrorKind::from_failure_code("registration_gone"), None);
        assert_eq!(PushErrorKind::from_failure_code("unknown_code"), None);
    }

    #[test]
    fn round4_failure_codes_classify() {
        // B5: chime must recognise the three round-4 wire codes that
        // floria/soland forward so consumers can branch on them.
        assert_eq!(
            PushErrorKind::from_failure_code(arkret::ErrorCode::DELIVERY_BINDING_STALE),
            Some(PushErrorKind::DeliveryBindingStale)
        );
        assert_eq!(
            PushErrorKind::from_failure_code(arkret::ErrorCode::DELIVERY_BINDING_HANDED_OVER),
            Some(PushErrorKind::DeliveryBindingHandedOver)
        );
        assert_eq!(
            PushErrorKind::from_failure_code(arkret::ErrorCode::HISTORICAL_ONLY),
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
    fn ordinals_are_unique_and_fit_retry_mask() {
        let kinds = [
            PushErrorKind::MissingField,
            PushErrorKind::InvalidPlatform,
            PushErrorKind::InvalidPushGatewayUrl,
            PushErrorKind::InvalidWebPushEndpoint,
            PushErrorKind::WebPushEndpointNotAllowed,
            PushErrorKind::ForbiddenPushGatewayQueryParam,
            PushErrorKind::InvalidHeader,
            PushErrorKind::Unauthenticated,
            PushErrorKind::CapabilityDenied,
            PushErrorKind::RateLimited,
            PushErrorKind::TemporarilyUnavailable,
            PushErrorKind::DuplicateConflict,
            PushErrorKind::NotFound,
            PushErrorKind::Gone,
            PushErrorKind::SchemaViolation,
            PushErrorKind::NetworkTimeout,
            PushErrorKind::Network,
            PushErrorKind::InvalidResponse,
            PushErrorKind::HttpStatus,
            PushErrorKind::DeliveryBindingStale,
            PushErrorKind::DeliveryBindingHandedOver,
            PushErrorKind::HistoricalOnly,
            PushErrorKind::FocusMismatch,
            PushErrorKind::UnknownFocusType,
            PushErrorKind::TokenIssuerUnauthorised,
            PushErrorKind::ParticipantBindingInvalid,
            PushErrorKind::ParticipantIdentityUnrecognised,
            PushErrorKind::SessionFocusAlreadyCommitted,
            PushErrorKind::E2eeKeySourceUnauthorised,
            PushErrorKind::RecordingArtifactPipelineBypassed,
            PushErrorKind::FocusUnavailableForClient,
            PushErrorKind::PairingRequestExpired,
            PushErrorKind::ProofInvalid,
            PushErrorKind::VerificationMethodPrincipalMismatch,
            PushErrorKind::AgentPaused,
            PushErrorKind::AgentDeactivated,
            PushErrorKind::ApprovalAlreadyConsumed,
            PushErrorKind::SidecarCreateDenied,
            PushErrorKind::ActorKindReducerManaged,
            PushErrorKind::RecoveryWitnessRevokeLagging,
            PushErrorKind::HandleHomographForbidden,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for kind in kinds {
            let ordinal = kind.ordinal();
            assert!(ordinal < 64, "{kind:?} ordinal must fit u64 mask");
            assert!(seen.insert(ordinal), "{kind:?} reuses ordinal {ordinal}");
        }
    }

    #[test]
    fn round4_codes_classify_against_409_and_200_statuses() {
        // Spec status mapping: stale/handed_over → 409, historical_only → 200.
        let envelope = ArkretErrorEnvelope {
            ok: false,
            error: ArkretError {
                code: arkret::ErrorCode::DELIVERY_BINDING_STALE.to_owned(),
                message: "stale".to_owned(),
                retry_after_ms: None,
                details: BTreeMap::new(),
            },
            request_id: "ak:request:test".to_owned(),
        };
        assert_eq!(
            classify_http_error(409, Some(&envelope)),
            PushErrorKind::DeliveryBindingStale
        );

        let envelope = ArkretErrorEnvelope {
            ok: false,
            error: ArkretError {
                code: arkret::ErrorCode::HISTORICAL_ONLY.to_owned(),
                message: "diagnostic".to_owned(),
                retry_after_ms: None,
                details: BTreeMap::new(),
            },
            request_id: "ak:request:test".to_owned(),
        };
        assert_eq!(
            classify_http_error(200, Some(&envelope)),
            PushErrorKind::HistoricalOnly
        );
    }
}
