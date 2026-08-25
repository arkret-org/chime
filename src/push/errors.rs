//! Push registration error types and HTTP status classification.

use std::fmt;
use std::time::{Duration, SystemTime};

use arkret_wire::ErrorEnvelope;
use thiserror::Error;

use super::urls::{redact_url, redact_webpush_endpoint};

/// High-level category for push registration failures.
///
/// Stability: v1 development phase — variants may be renamed or removed
/// without a compatibility window. Matching against the enum should
/// include a wildcard arm (the enum is `#[non_exhaustive]`).
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
    ResponseInvalid,
    HttpStatus,
    /// Federation sender used an obsolete member
    /// delivery binding frontier. The response carries
    /// `new_recipient_service_id` + `handover_frontier`; chime
    /// consumers MUST resolve the current binding and retry against the
    /// new recipient rather than re-issuing the same wakeup.
    DeliveryBindingStale,
    /// Sender continued using a previous `recipient_service_id`
    /// after the handover grace window expired. Sender MUST resolve the
    /// current binding and retry there. Treat as terminal for the old
    /// recipient.
    DeliveryBindingHandedOver,
    /// Idempotency cache replay served only as a historical
    /// diagnostic after key or binding state changed. Receivers MUST NOT
    /// perform new reducer side effects; in particular chime consumers
    /// MUST NOT trigger another push fanout from a `historical_only`
    /// response.
    HistoricalOnly,
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
            Self::ResponseInvalid => 17,
            Self::HttpStatus => 18,
            // Delivery-binding additions are bit-position appended;
            // never reorder existing ones.
            Self::DeliveryBindingStale => 19,
            Self::DeliveryBindingHandedOver => 20,
            Self::HistoricalOnly => 21,
        }
    }

    /// Map a Arkret `bridge/describe.failure_reason_codes` string to a stable kind.
    ///
    /// Returns `None` when the code is not part of the contract, so callers can
    /// decide between treating it as `HttpStatus` or surfacing the raw code.
    pub fn from_failure_reason_code(code: &str) -> Option<Self> {
        // Canonical wire codes sourced from the SDK constants so chime's
        // classification stays byte-aligned with what soland/floria emit.
        const CODE_MAP: &[(&str, PushErrorKind)] = &[
            (
                arkret_wire::ErrorCode::UNAUTHENTICATED,
                PushErrorKind::Unauthenticated,
            ),
            (
                arkret_wire::ErrorCode::AUTH_EXPIRED,
                PushErrorKind::Unauthenticated,
            ),
            (
                arkret_wire::ErrorCode::SOFT_LOGGED_OUT,
                PushErrorKind::Unauthenticated,
            ),
            (
                arkret_wire::ErrorCode::CAPABILITY_DENIED,
                PushErrorKind::CapabilityDenied,
            ),
            (
                arkret_wire::ErrorCode::RATE_LIMITED,
                PushErrorKind::RateLimited,
            ),
            (
                arkret_wire::ErrorCode::TEMPORARILY_UNAVAILABLE,
                PushErrorKind::TemporarilyUnavailable,
            ),
            (
                arkret_wire::ErrorCode::DUPLICATE_CONFLICT,
                PushErrorKind::DuplicateConflict,
            ),
            (arkret_wire::ErrorCode::NOT_FOUND, PushErrorKind::NotFound),
            (
                arkret_wire::ErrorCode::SCHEMA_VIOLATION,
                PushErrorKind::SchemaViolation,
            ),
            (
                arkret_wire::ErrorCode::JSON_INVALID,
                PushErrorKind::SchemaViolation,
            ),
            (
                arkret_wire::ErrorCode::QUERY_INVALID,
                PushErrorKind::SchemaViolation,
            ),
            (
                arkret_wire::ErrorCode::PARAM_MISSING,
                PushErrorKind::SchemaViolation,
            ),
            (
                arkret_wire::ErrorCode::PARAM_INVALID,
                PushErrorKind::SchemaViolation,
            ),
            (
                arkret_wire::ErrorCode::DELIVERY_BINDING_STALE,
                PushErrorKind::DeliveryBindingStale,
            ),
            (
                arkret_wire::ErrorCode::DELIVERY_BINDING_HANDED_OVER,
                PushErrorKind::DeliveryBindingHandedOver,
            ),
            (
                arkret_wire::ErrorCode::HISTORICAL_ONLY,
                PushErrorKind::HistoricalOnly,
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
    #[error("Arkret service response body is too large: {actual} bytes exceeds {limit} byte limit")]
    ResponseTooLarge { limit: usize, actual: usize },
    #[error("Arkret service returned HTTP {status}")]
    HttpStatus {
        status: u16,
        kind: PushErrorKind,
        error: Option<Box<ErrorEnvelope>>,
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
            Self::ResponseTooLarge { limit, actual } => f
                .debug_struct("ResponseTooLarge")
                .field("limit", limit)
                .field("actual", actual)
                .finish(),
            Self::HttpStatus {
                status,
                kind,
                error,
                body,
                retry_after,
                request_id,
            } => {
                let redacted_error = error.as_deref().map(RedactedErrorEnvelope);
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

struct RedactedErrorEnvelope<'a>(&'a ErrorEnvelope);

impl fmt::Debug for RedactedErrorEnvelope<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ErrorEnvelope")
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
            Self::ResponseTooLarge { .. } => PushErrorKind::ResponseInvalid,
            Self::HttpStatus { kind, .. } => *kind,
            #[cfg(feature = "http")]
            Self::Http(error) if error.is_timeout() => PushErrorKind::NetworkTimeout,
            #[cfg(feature = "http")]
            Self::Http(_) => PushErrorKind::Network,
            Self::Json(_) => PushErrorKind::ResponseInvalid,
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
pub(super) fn classify_http_error(status: u16, error: Option<&ErrorEnvelope>) -> PushErrorKind {
    if let Some(code) = error.map(|envelope| envelope.error.code.as_str())
        && let Some(kind) = PushErrorKind::from_failure_reason_code(code)
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

    use arkret_wire::ErrorDetail;

    use super::*;

    #[test]
    fn classifies_error_codes() {
        let envelope = ErrorEnvelope {
            ok: false,
            error: ErrorDetail {
                code: arkret_wire::ErrorCode::CAPABILITY_DENIED.to_owned(),
                message: "denied".to_owned(),
                retry_after_ms: None,
                details: BTreeMap::new(),
            },
            request_id: "ak:request:01904100-0000-7000-8000-000000000010".to_owned(),
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
    fn from_failure_reason_code_covers_contract() {
        assert_eq!(
            PushErrorKind::from_failure_reason_code(arkret_wire::ErrorCode::RATE_LIMITED),
            Some(PushErrorKind::RateLimited)
        );
        assert_eq!(
            PushErrorKind::from_failure_reason_code("registration_gone"),
            None
        );
        assert_eq!(
            PushErrorKind::from_failure_reason_code("unknown_code"),
            None
        );
    }

    #[test]
    fn delivery_binding_and_historical_only_codes_classify() {
        // chime must recognise the delivery-binding and historical-only wire
        // codes that floria/soland forward so consumers can branch on them.
        assert_eq!(
            PushErrorKind::from_failure_reason_code(arkret_wire::ErrorCode::DELIVERY_BINDING_STALE),
            Some(PushErrorKind::DeliveryBindingStale)
        );
        assert_eq!(
            PushErrorKind::from_failure_reason_code(
                arkret_wire::ErrorCode::DELIVERY_BINDING_HANDED_OVER
            ),
            Some(PushErrorKind::DeliveryBindingHandedOver)
        );
        assert_eq!(
            PushErrorKind::from_failure_reason_code(arkret_wire::ErrorCode::HISTORICAL_ONLY),
            Some(PushErrorKind::HistoricalOnly)
        );
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
            PushErrorKind::ResponseInvalid,
            PushErrorKind::HttpStatus,
            PushErrorKind::DeliveryBindingStale,
            PushErrorKind::DeliveryBindingHandedOver,
            PushErrorKind::HistoricalOnly,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for kind in kinds {
            let ordinal = kind.ordinal();
            assert!(ordinal < 64, "{kind:?} ordinal must fit u64 mask");
            assert!(seen.insert(ordinal), "{kind:?} reuses ordinal {ordinal}");
        }
    }

    #[test]
    fn delivery_binding_stale_maps_409_and_historical_only_maps_200() {
        // Spec status mapping: stale/handed_over → 409, historical_only → 200.
        let envelope = ErrorEnvelope {
            ok: false,
            error: ErrorDetail {
                code: arkret_wire::ErrorCode::DELIVERY_BINDING_STALE.to_owned(),
                message: "stale".to_owned(),
                retry_after_ms: None,
                details: BTreeMap::new(),
            },
            request_id: "ak:request:01904100-0000-7000-8000-000000000011".to_owned(),
        };
        assert_eq!(
            classify_http_error(409, Some(&envelope)),
            PushErrorKind::DeliveryBindingStale
        );

        let envelope = ErrorEnvelope {
            ok: false,
            error: ErrorDetail {
                code: arkret_wire::ErrorCode::HISTORICAL_ONLY.to_owned(),
                message: "diagnostic".to_owned(),
                retry_after_ms: None,
                details: BTreeMap::new(),
            },
            request_id: "ak:request:01904100-0000-7000-8000-000000000012".to_owned(),
        };
        assert_eq!(
            classify_http_error(200, Some(&envelope)),
            PushErrorKind::HistoricalOnly
        );
    }
}
